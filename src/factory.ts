import type {
  CreateSandboxOptions,
  Sandbox,
  SandboxPlugin,
  CircuitBreakerState,
  CircuitBreakerConfig,
  DegradationChain,
} from './types.js';
import { SandboxPermissionError, SandboxCrashError } from './types.js';

// ---------------------------------------------------------------------------
// Sandbox creation limits (§10)
// ---------------------------------------------------------------------------

const MAX_CONCURRENT_SANDBOXES = 50;
const MAX_CREATION_RATE = 10; // per second
const RATE_WINDOW_MS = 1000;

/** Track active sandbox count. */
let activeSandboxCount = 0;

/** Sliding window of creation timestamps for rate limiting. */
const creationTimestamps: number[] = [];

function checkCreationLimits(): void {
  if (activeSandboxCount >= MAX_CONCURRENT_SANDBOXES) {
    throw new SandboxPermissionError(
      `Max concurrent sandboxes (${MAX_CONCURRENT_SANDBOXES}) reached`,
    );
  }
  const now = Date.now();
  const windowStart = now - RATE_WINDOW_MS;
  // Prune old timestamps
  while (creationTimestamps.length > 0 && creationTimestamps[0] <= windowStart) {
    creationTimestamps.shift();
  }
  if (creationTimestamps.length >= MAX_CREATION_RATE) {
    throw new SandboxPermissionError(
      `Sandbox creation rate limit (${MAX_CREATION_RATE}/sec) exceeded`,
    );
  }
}

function trackCreation(): void {
  activeSandboxCount++;
  creationTimestamps.push(Date.now());
}

function trackDestruction(): void {
  activeSandboxCount = Math.max(0, activeSandboxCount - 1);
}

/**
 * Wrap a sandbox to track its lifecycle for creation limits.
 * Uses explicit delegation — no prototype chain.
 */
function wrapSandbox(sandbox: Sandbox): Sandbox {
  const originalDestroy = sandbox.destroy.bind(sandbox);
  return {
    execute: sandbox.execute.bind(sandbox),
    executeStream: sandbox.executeStream.bind(sandbox),
    fs: sandbox.fs,
    git: sandbox.git,
    ready: sandbox.ready.bind(sandbox),
    destroy: async () => {
      try {
        await originalDestroy();
      } finally {
        trackDestruction();
      }
    },
  };
}

/** Default circuit breaker config. */
const DEFAULT_CB: CircuitBreakerConfig = {
  failureThreshold: 3,
  cooldownMs: 30000,
};

/** Per-plugin circuit breaker state. */
interface CircuitBreaker {
  state: CircuitBreakerState;
  failures: number;
  lastFailure: number;
  config: CircuitBreakerConfig;
  /** True while a half-open probe is in flight — blocks concurrent probes. */
  probing: boolean;
}

/** Global circuit breaker map (keyed by plugin name). */
const breakers = new Map<string, CircuitBreaker>();

/** Get or create a circuit breaker for a plugin. */
function getBreaker(name: string, config?: Partial<CircuitBreakerConfig>): CircuitBreaker {
  let cb = breakers.get(name);
  if (!cb) {
    cb = {
      state: 'closed',
      failures: 0,
      lastFailure: 0,
      config: { ...DEFAULT_CB, ...config },
      probing: false,
    };
    breakers.set(name, cb);
  }
  return cb;
}

/** Check if the circuit breaker allows a request. */
function canAttempt(cb: CircuitBreaker): boolean {
  if (cb.state === 'closed') return true;
  if (cb.state === 'open') {
    const elapsed = Date.now() - cb.lastFailure;
    if (elapsed >= cb.config.cooldownMs) {
      // Only allow one probe at a time — block concurrent half-open attempts
      if (cb.probing) return false;
      cb.state = 'half-open';
      cb.probing = true;
      return true;
    }
    return false;
  }
  // half-open: only one probe allowed at a time
  if (cb.probing) return false;
  cb.probing = true;
  return true;
}

/** Record a success on the circuit breaker. */
function recordSuccess(cb: CircuitBreaker): void {
  cb.state = 'closed';
  cb.failures = 0;
  cb.probing = false;
}

/** Record a failure on the circuit breaker. */
function recordFailure(cb: CircuitBreaker): void {
  cb.failures++;
  cb.lastFailure = Date.now();
  cb.probing = false;
  if (cb.failures >= cb.config.failureThreshold || cb.state === 'half-open') {
    cb.state = 'open';
  }
}

/** Plugin registry — single source of truth in plugins/registry.ts. */
// Re-export type to keep the import path short for consumers.
import { PLUGINS as PLUGIN_REGISTRY } from './plugins/registry.js';

/** Resolve a plugin by name from the registry. */
async function resolvePlugin(name: string): Promise<SandboxPlugin> {
  const loader = PLUGIN_REGISTRY[name];
  if (!loader) {
    throw new SandboxPermissionError(`Unknown plugin: "${name}". Available: ${Object.keys(PLUGIN_REGISTRY).join(', ')}`);
  }
  const mod = await loader();
  return mod.default;
}

/**
 * Create a sandbox instance using the specified plugin and configuration.
 *
 * This is the main entry point for the sandbox system. It resolves the
 * plugin (by name or direct reference), validates version compatibility,
 * manages the circuit breaker, and handles graceful degradation.
 *
 * @param options - Plugin, config, and optional circuit breaker settings.
 * @returns A ready-to-use sandbox instance.
 * @throws {SandboxPermissionError} If the plugin is incompatible.
 * @throws {SandboxCrashError} If all plugins in the degradation chain fail.
 */
export async function createSandbox(options: CreateSandboxOptions): Promise<Sandbox> {
  const { config, circuitBreaker: cbConfig } = options;

  // Validate limits
  if (config.limits.memoryMB <= 0) {
    throw new SandboxPermissionError('memoryMB must be positive');
  }
  if (config.limits.timeoutMs <= 0) {
    throw new SandboxPermissionError('timeoutMs must be positive');
  }
  if (config.limits.cpuMs <= 0) {
    throw new SandboxPermissionError('cpuMs must be positive');
  }

  // Freeze host functions to prevent modification after creation
  if (config.hostFunctions) {
    Object.freeze(config.hostFunctions);
  }

  // Enforce creation limits (§10)
  checkCreationLimits();

  // Resolve plugin
  let plugin: SandboxPlugin;
  if (typeof options.plugin === 'string') {
    plugin = await resolvePlugin(options.plugin);
  } else {
    plugin = options.plugin;
  }

  // Circuit breaker check
  const cb = getBreaker(plugin.name, cbConfig);
  if (!canAttempt(cb)) {
    throw new SandboxCrashError(`Circuit breaker open for plugin "${plugin.name}" — in cooldown`);
  }

  try {
    const sandbox = await plugin.create(config);
    recordSuccess(cb);
    trackCreation();
    return wrapSandbox(sandbox);
  } catch (err) {
    recordFailure(cb);
    throw err;
  }
}

/**
 * Default degradation chain.
 * Docker Sandboxes (T3) → E2B (T3) → Landlock (T2) → Anthropic SR (T2) → isolated-vm (T1)
 *
 * OpenShell is NOT in the default chain — it requires explicit opt-in via
 * `experimental.openshell: true` in config. Use
 * OPENSHELL_DEGRADATION_CHAIN for openshell-first degradation.
 */
const DEFAULT_DEGRADATION_CHAIN: DegradationChain = [
  'docker', 'e2b', 'landlock', 'anthropic-sr', 'isolated-vm',
];

/**
 * Degradation chain with OpenShell at the head.
 * Only used when `experimental.openshell` is enabled in config.
 * Falls back to Docker → E2B → ... if OpenShell fails.
 */
export const OPENSHELL_DEGRADATION_CHAIN: DegradationChain = [
  'openshell', 'docker', 'e2b', 'landlock', 'anthropic-sr', 'isolated-vm',
];

/** Tier mapping for MCP enforcement. */
const PLUGIN_TIERS: Record<string, number> = {
  'mock': 1, 'isolated-vm': 1,
  'anthropic-sr': 2, 'landlock': 2, 'firejail': 2, 'docker-pi': 2,
  'docker': 3, 'microsandbox': 3, 'e2b': 3, 'openshell': 3,
};

// BREAKING: `onWarning` removed — mcpMinTier is now a hard floor that
// rejects plugins below the tier instead of warning. See §10.
/**
 * Shadow mode result emitted when comparing experimental vs primary sandbox.
 */
export interface ShadowModeResult {
  experimental: string;
  primary: string;
  diverged: boolean;
  experimentalError?: string;
  latencyDeltaMs: number;
}

export interface DegradationOptions {
  /** The degradation chain to follow. Defaults to built-in chain. */
  chain?: DegradationChain;
  /** Sandbox config to use. */
  config: import('./types.js').SandboxConfig;
  /** Minimum tier for MCP enforcement. Plugins below this tier are skipped entirely. */
  mcpMinTier?: number;
  /** Circuit breaker config. */
  circuitBreaker?: Partial<CircuitBreakerConfig>;
  /**
   * Shadow mode: run an experimental plugin alongside the primary.
   * The primary plugin's sandbox is always returned to the caller.
   * The experimental plugin runs in parallel and results are compared
   * via the `onShadowResult` callback. Use this to evaluate alpha
   * plugins (e.g., OpenShell) against stable ones (e.g., Docker)
   * before graduating them to production.
   */
  shadowMode?: {
    /** Experimental plugin to test (e.g., 'openshell'). */
    experimentalPlugin: string;
    /** Called with comparison results after both sandboxes execute. */
    onShadowResult?: (result: ShadowModeResult) => void;
  };
}

/**
 * Create a sandbox with graceful degradation.
 *
 * Tries each plugin in the degradation chain until one succeeds.
 * Plugins below `mcpMinTier` are skipped entirely (hard floor — §10).
 * Throws `SandboxCrashError` if all plugins fail.
 */
export async function createSandboxWithDegradation(options: DegradationOptions): Promise<Sandbox> {
  const chain = options.chain ?? DEFAULT_DEGRADATION_CHAIN;
  const errors: Array<{ plugin: string; error: unknown }> = [];

  for (const pluginName of chain) {
    // mcpMinTier is a hard floor — skip plugins below it entirely
    const tier = PLUGIN_TIERS[pluginName] ?? 1;
    if (options.mcpMinTier && tier < options.mcpMinTier) {
      errors.push({
        plugin: pluginName,
        error: new SandboxPermissionError(
          `Plugin "${pluginName}" is Tier ${tier}, below mcpMinTier ${options.mcpMinTier}`,
        ),
      });
      continue;
    }

    try {
      const sandbox = await createSandbox({
        plugin: pluginName,
        config: options.config,
        circuitBreaker: options.circuitBreaker,
      });

      // Shadow mode: also create experimental sandbox in background
      if (options.shadowMode) {
        const { experimentalPlugin, onShadowResult } = options.shadowMode;
        // Fire-and-forget — experimental sandbox creation runs in background.
        // Failures are captured and reported, never thrown.
        createSandbox({
          plugin: experimentalPlugin,
          config: options.config,
          circuitBreaker: options.circuitBreaker,
        }).then((experimentalSandbox) => {
          // Wrap the primary sandbox's execute to also run on experimental
          const originalExecute = sandbox.execute.bind(sandbox);
          sandbox.execute = async (code, execOptions) => {
            const primaryStart = Date.now();
            const primaryResult = await originalExecute(code, execOptions);
            const primaryMs = Date.now() - primaryStart;

            // Run experimental in background — never block the caller
            const expStart = Date.now();
            experimentalSandbox.execute(code, execOptions).then((expResult) => {
              const expMs = Date.now() - expStart;
              const diverged = primaryResult.success !== expResult.success
                || JSON.stringify(primaryResult.result) !== JSON.stringify(expResult.result);
              onShadowResult?.({
                experimental: experimentalPlugin,
                primary: pluginName,
                diverged,
                latencyDeltaMs: expMs - primaryMs,
              });
            }).catch((err) => {
              onShadowResult?.({
                experimental: experimentalPlugin,
                primary: pluginName,
                diverged: true,
                experimentalError: err instanceof Error ? err.message : String(err),
                latencyDeltaMs: Date.now() - expStart,
              });
            });

            return primaryResult;
          };

          // Ensure experimental sandbox is destroyed when primary is
          const originalDestroy = sandbox.destroy.bind(sandbox);
          sandbox.destroy = async () => {
            await originalDestroy();
            await experimentalSandbox.destroy().catch(() => {});
          };
        }).catch(() => {
          // Experimental creation failed — shadow mode silently disabled.
          // Primary sandbox is unaffected.
        });
      }

      return sandbox;
    } catch (err) {
      errors.push({ plugin: pluginName, error: err });
    }
  }

  throw new SandboxCrashError(
    `All plugins in degradation chain failed: ${errors.map(e => `${e.plugin}: ${e.error instanceof Error ? e.error.message : String(e.error)}`).join('; ')}`,
  );
}

/** Reset all circuit breakers and creation limits (for testing). */
export function resetCircuitBreakers(): void {
  breakers.clear();
  activeSandboxCount = 0;
  creationTimestamps.length = 0;
}

/** Get circuit breaker state for a plugin (for testing). */
export function getCircuitBreakerState(pluginName: string): CircuitBreakerState | undefined {
  return breakers.get(pluginName)?.state;
}

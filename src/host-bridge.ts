import type { HostFunction, HostFunctionDef, RateLimitConfig } from './types.js';
import { InstructionPrivilege, createMessage, type OperatorPolicy } from './instruction-hierarchy.js';
import { applySpotlight, type SpotlightConfig } from './spotlighting.js';
import type { DefensePipeline } from './defense-pipeline.js';

/** Max return value size in bytes (1MB). */
const MAX_RETURN_SIZE_BYTES = 1_048_576;

/** Default host function timeout in ms (30s). */
const DEFAULT_HOST_FUNCTION_TIMEOUT_MS = 30_000;

/**
 * Frozen, validated host function bridge.
 *
 * Created at sandbox initialization from the allowlist in `SandboxConfig.hostFunctions`.
 * The bridge validates arguments against Zod schemas, enforces rate limits,
 * and prevents SSRF to internal endpoints (169.254.x.x).
 *
 * The returned object is `Object.freeze()`'d — no functions can be added
 * or removed after creation.
 */
export interface HostBridge {
  /**
   * Call a host function by name.
   *
   * @param name - The function name from the allowlist.
   * @param args - Arguments to pass (validated against schema if defined).
   * @returns The function's return value. **Note:** when spotlighting is enabled
   *   (via `HostBridgeDefenseOptions.spotlightConfig`), ALL non-null/undefined
   *   return values are converted to boundary-marked strings regardless of the
   *   handler's original return type. This is intentional — spotlighted content
   *   is destined for LLM prompt context, not programmatic consumption.
   * @throws If the function is not in the allowlist, args fail schema validation, or rate limit is exceeded.
   */
  call(name: string, args: unknown): Promise<unknown>;

  /** List of available host function names (for debugging). */
  readonly availableFunctions: readonly string[];
}

/** Internal rate limiter state per function. */
interface RateLimiterState {
  config: RateLimitConfig;
  calls: number[];
}

/** RFC 1918 + link-local + loopback patterns for SSRF prevention. */
const BLOCKED_IP_PATTERNS = [
  /^169\.254\./,           // link-local / cloud metadata
  /^127\./,                // loopback
  /^10\./,                 // RFC 1918 Class A
  /^172\.(1[6-9]|2\d|3[01])\./, // RFC 1918 Class B
  /^192\.168\./,           // RFC 1918 Class C
  /^0\./,                  // current network
  /^localhost$/i,
  /^\[?::1\]?$/,           // IPv6 loopback
];

/**
 * Normalize a HostFunction (bare function or full def) into a HostFunctionDef.
 */
function normalizeDef(fn: HostFunction): HostFunctionDef {
  if (typeof fn === 'function') {
    return { handler: fn };
  }
  return fn;
}

/**
 * Check if a URL string targets a blocked internal address.
 */
function isBlockedUrl(urlStr: string): boolean {
  // Only check strings that look like URLs (have a scheme)
  if (!/^https?:\/\//i.test(urlStr)) return false;
  try {
    const url = new URL(urlStr);
    const hostname = url.hostname;
    return BLOCKED_IP_PATTERNS.some(pattern => pattern.test(hostname));
  } catch {
    // Malformed URL with http(s) scheme — block as potentially dangerous.
    // A malformed URL string could still be interpreted by a more lenient
    // HTTP library downstream.
    return true;
  }
}

/**
 * Deep-scan args for URL-like strings that target internal addresses.
 */
function containsBlockedUrl(args: unknown): boolean {
  if (typeof args === 'string') {
    return isBlockedUrl(args);
  }
  if (args !== null && typeof args === 'object') {
    for (const val of Object.values(args as Record<string, unknown>)) {
      if (typeof val === 'string' && isBlockedUrl(val)) return true;
      if (typeof val === 'object' && val !== null && containsBlockedUrl(val)) return true;
    }
  }
  return false;
}

/**
 * Validate network allowlist format (§7). Each peer must be `host:port`.
 */
export function validateNetworkAllowlist(peers: string[]): void {
  for (const peer of peers) {
    const parts = peer.split(':');
    if (parts.length < 2 || !parts[parts.length - 1].match(/^\d+$/)) {
      throw new Error(
        `Invalid network peer "${peer}": must be host:port (e.g. "api.openai.com:443")`,
      );
    }
  }
}

/** Options for defense pipeline integration in the host bridge. */
export interface HostBridgeDefenseOptions {
  /** Defense pipeline for guardrail evaluation. */
  pipeline?: DefensePipeline;

  /** Sandbox ID for audit trail. */
  sandboxId?: string;

  /** Optional tenant ID for multi-tenant isolation (§5). */
  tenantId?: string;

  /** Spotlighting config for return values. */
  spotlightConfig?: SpotlightConfig;

  /** Operator policy for allowed host functions. */
  operatorPolicy?: OperatorPolicy;
}

/**
 * Create a frozen host function bridge from an allowlist.
 *
 * @param hostFunctions - The allowlist from `SandboxConfig.hostFunctions`.
 * @param defenseOptions - Optional V2 defense pipeline integration.
 * @returns A frozen bridge that validates and rate-limits all calls.
 */
export function createHostBridge(
  hostFunctions: Record<string, HostFunction>,
  defenseOptions?: HostBridgeDefenseOptions,
): HostBridge {
  const names = Object.keys(hostFunctions);
  if (names.length === 0) {
    throw new Error('Host function allowlist must not be empty');
  }

  const defs = new Map<string, HostFunctionDef>();
  const rateLimiters = new Map<string, RateLimiterState>();

  for (const [name, fn] of Object.entries(hostFunctions)) {
    const def = normalizeDef(fn);
    defs.set(name, def);
    if (def.rateLimit) {
      rateLimiters.set(name, { config: def.rateLimit, calls: [] });
    }
  }

  const bridge: HostBridge = Object.freeze({
    availableFunctions: Object.freeze(names),

    async call(name: string, args: unknown): Promise<unknown> {
      if (!name) {
        throw new Error('Host function name must not be empty');
      }

      const def = defs.get(name);
      if (!def) {
        throw new Error(`Host function "${name}" is not available`);
      }

      // V2: Operator policy — check if this function is allowed (§14.5)
      if (defenseOptions?.operatorPolicy?.allowedHostFunctions) {
        if (!defenseOptions.operatorPolicy.allowedHostFunctions.includes(name)) {
          throw new Error(`Host function "${name}" is not in operator allowlist`);
        }
      }

      // V2: Defense pipeline — evaluate tool call (§14.14)
      if (defenseOptions?.pipeline) {
        const msg = createMessage(
          JSON.stringify({ tool: name, args }),
          InstructionPrivilege.AGENT,
          defenseOptions.sandboxId ?? 'unknown',
          { sandboxId: defenseOptions.sandboxId },
        );
        const result = await defenseOptions.pipeline.processToolCall(name, args as Record<string, unknown>, msg);
        if (result.action === 'block') {
          throw new Error(`Host function "${name}" blocked by defense pipeline: ${result.guardrail.reason ?? 'policy violation'}`);
        }
      }

      // SSRF prevention: scan args for blocked URLs
      if (containsBlockedUrl(args)) {
        throw new Error('SSRF blocked: request targets an internal/metadata endpoint');
      }

      // Schema validation
      if (def.schema) {
        const result = def.schema.safeParse(args);
        if (!result.success) {
          const issues = result.error.issues.map(
            (i: { path: (string | number)[]; message: string }) => `${i.path.join('.')}: ${i.message}`,
          ).join('; ');
          throw new Error(`Schema validation failed for "${name}": ${issues}`);
        }
      }

      // Rate limiting
      const limiter = rateLimiters.get(name);
      if (limiter) {
        const now = Date.now();
        const windowStart = now - limiter.config.windowMs;
        limiter.calls = limiter.calls.filter(t => t > windowStart);
        if (limiter.calls.length >= limiter.config.maxCalls) {
          throw new Error(`Rate limit exceeded for "${name}": ${limiter.config.maxCalls} calls per ${limiter.config.windowMs}ms`);
        }
        limiter.calls.push(now);
      }

      // Call the handler with independent timeout (§3).
      // Timer is cleared on resolution to avoid leaking setTimeout handles.
      const timeoutMs = def.timeoutMs ?? DEFAULT_HOST_FUNCTION_TIMEOUT_MS;
      let timer: ReturnType<typeof setTimeout>;
      const result = await Promise.race([
        def.handler(args),
        new Promise<never>((_, reject) => {
          timer = setTimeout(
            () => reject(new Error(`Host function "${name}" timed out after ${timeoutMs}ms`)),
            timeoutMs,
          );
        }),
      ]).finally(() => clearTimeout(timer));

      // Return value size cap (§3).
      // Serialize once, return the parsed result (avoids double-stringify).
      const serialized = JSON.stringify(result);
      if (serialized !== undefined && serialized.length > MAX_RETURN_SIZE_BYTES) {
        throw new Error(
          `Host function "${name}" return value exceeds size cap (${serialized.length} bytes > ${MAX_RETURN_SIZE_BYTES} bytes)`,
        );
      }

      // V2: Spotlighting — mark return values with boundary tokens (§14.6)
      // Applies to ALL return types: strings pass through directly,
      // non-strings (objects, arrays, numbers) are JSON-serialized first.
      if (defenseOptions?.spotlightConfig && result !== undefined && result !== null) {
        const stringified = typeof result === 'string' ? result : JSON.stringify(result);
        const msg = createMessage(
          stringified,
          InstructionPrivilege.TOOL_OUTPUT,
          `hostbridge:${name}`,
          { sandboxId: defenseOptions.sandboxId },
        );
        const spotted = applySpotlight(msg, defenseOptions.spotlightConfig);
        return spotted.content;
      }

      return result;
    },
  });

  return bridge;
}

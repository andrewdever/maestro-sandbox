import type { ZodSchema } from 'zod';

// ---------------------------------------------------------------------------
// Sandbox Plugin
// ---------------------------------------------------------------------------

/**
 * A sandbox plugin provides a specific isolation strategy.
 *
 * Each plugin implements the same interface, enabling drop-in replacement
 * across tiers: V8 isolates (Tier 1), OS-level restriction (Tier 2),
 * or infrastructure isolation (Tier 3).
 *
 * Plugins are loaded dynamically via the registry — only the plugin
 * specified in configuration is imported at runtime.
 */
export interface SandboxPlugin {
  /** Unique plugin identifier, e.g. `'isolated-vm'`, `'landlock'`, `'mock'`. */
  readonly name: string;

  /** Semver version string, e.g. `'1.0.0'`. */
  readonly version: string;

  /** Required core version range, e.g. `'>=1.0.0 <2.0.0'`. */
  readonly requiredCoreVersion: string;

  /** The kind of isolation this plugin provides. */
  readonly isolationLevel: IsolationLevel;

  /**
   * Create a new sandbox instance with the given configuration.
   *
   * @param config - Sandbox limits, permissions, secrets, and host functions.
   * @returns A ready-to-use sandbox, or throws a {@link SandboxError}.
   */
  create(config: SandboxConfig): Promise<Sandbox>;
}

/** The isolation strategy a plugin implements. */
export type IsolationLevel = 'isolate' | 'process' | 'container' | 'microvm';

// ---------------------------------------------------------------------------
// Sandbox Configuration
// ---------------------------------------------------------------------------

/**
 * Configuration for creating a sandbox instance.
 *
 * Passed to {@link SandboxPlugin.create}. Defines resource limits,
 * permissions, secrets, and the host callback bridge.
 */
export interface SandboxConfig {
  /** Resource limits enforced by the sandbox. */
  limits: SandboxLimits;

  /** Optional list of named permissions (plugin-specific). */
  permissions?: string[];

  /**
   * Secrets injected into the sandbox at creation time.
   * Never written to disk. Scoped per sandbox instance.
   * Values are redacted from {@link SandboxResult.logs}.
   */
  secrets?: Record<string, string>;

  /** Network policy for Tier 2+ sandboxes. */
  network?: NetworkConfig;

  /**
   * Host functions the sandbox is allowed to call.
   *
   * This is the security boundary: the allowlist is declared at creation
   * time and frozen with `Object.freeze()`. The sandbox cannot register
   * new host functions or discover functions not in this list.
   *
   * Each function can have a Zod schema for argument validation and
   * an optional rate limit to prevent abuse.
   */
  hostFunctions?: Record<string, HostFunction>;
}

/** Resource limits enforced by the sandbox runtime. */
export interface SandboxLimits {
  /** Maximum memory in megabytes. */
  memoryMB: number;

  /** Maximum CPU time in milliseconds. */
  cpuMs: number;

  /** Maximum wall-clock time in milliseconds before termination. */
  timeoutMs: number;

  /** Whether outbound network access is allowed. Default: `false`. */
  networkAccess: boolean;

  /** Filesystem access level inside the sandbox. */
  filesystemAccess: 'none' | 'readonly' | 'tmpfs';
}

/** Network configuration for sandboxes with network access. */
export interface NetworkConfig {
  /** Allowlisted peers, e.g. `['api.openai.com:443', '10.0.0.5:5432']`. */
  allowedPeers?: string[];

  /** Enable mutual TLS between sandboxes (V2). */
  mTLS?: boolean;
}

// ---------------------------------------------------------------------------
// Host Callback Bridge
// ---------------------------------------------------------------------------

/**
 * Definition for a host function that sandboxed code can call.
 *
 * Host functions bridge the gap between the isolated sandbox and the
 * outside world. They are the ONLY way sandboxed code can perform
 * async I/O (fetch, database queries, etc.).
 *
 * @example
 * ```typescript
 * hostFunctions: {
 *   fetch: {
 *     handler: async (args) => {
 *       const { url, method } = args as { url: string; method: string };
 *       if (!isAllowedUrl(url)) throw new Error('URL not in allowlist');
 *       const res = await fetch(url, { method });
 *       return { status: res.status, body: await res.text() };
 *     },
 *     schema: z.object({ url: z.string().url(), method: z.enum(['GET', 'POST']) }),
 *     rateLimit: { maxCalls: 100, windowMs: 60000 },
 *   },
 * }
 * ```
 */
export interface HostFunctionDef {
  /** The function the host executes when the sandbox calls it. */
  handler: (args: unknown) => Promise<unknown>;

  /** Zod schema for argument validation. Rejects malformed args before the handler runs. */
  schema?: ZodSchema;

  /** Rate limit to prevent sandbox from spamming host functions. */
  rateLimit?: RateLimitConfig;

  /** Timeout in ms for this host function, independent of sandbox timeout. Default: 30000. */
  timeoutMs?: number;
}

/** Shorthand: a bare function (no schema, no rate limit) or a full definition. */
export type HostFunction = HostFunctionDef | ((args: unknown) => Promise<unknown>);

/** Rate limit configuration for a host function. */
export interface RateLimitConfig {
  /** Maximum number of calls allowed per window. */
  maxCalls: number;

  /** Window duration in milliseconds. */
  windowMs: number;
}

// ---------------------------------------------------------------------------
// Sandbox Instance
// ---------------------------------------------------------------------------

/**
 * A running sandbox instance.
 *
 * Created by {@link SandboxPlugin.create}. Provides code execution,
 * file access, and git operations within the isolated environment.
 *
 * Always call {@link destroy} when done — in a `finally` block.
 */
export interface Sandbox {
  /**
   * Execute code inside the sandbox.
   *
   * @param code - JavaScript code string (Tier 1) or shell command (Tier 2+ with `shell: true`).
   * @param options - Execution options: injected context variables, shell mode.
   * @returns Execution result with output, logs, and metrics.
   */
  execute(code: string, options?: ExecuteOptions): Promise<SandboxResult>;

  /**
   * Execute code and stream output chunks.
   *
   * For long-running LLM agents that produce incremental output.
   * Basic stdout/stderr piping in V1.
   */
  executeStream(code: string, options?: ExecuteOptions): AsyncIterable<SandboxChunk>;

  /** File access within the sandbox's tmpdir. */
  fs: SandboxFileAccess;

  /** Git operations: inject code in, export patches out. */
  git: SandboxGitAccess;

  /**
   * Health check. Returns `true` when the sandbox is ready to execute code.
   * Especially important for Tier 3 (VM boot time).
   */
  ready(): Promise<boolean>;

  /**
   * Destroy the sandbox and release all resources.
   *
   * Always call this in a `finally` block. If `destroy()` fails,
   * the runtime force-kills the sandbox. No leaked tmpdirs,
   * child processes, or Docker containers.
   */
  destroy(): Promise<void>;
}

/** Options for {@link Sandbox.execute} and {@link Sandbox.executeStream}. */
export interface ExecuteOptions {
  /** Variables injected into the sandbox's execution scope. */
  context?: Record<string, unknown>;

  /**
   * If `true`, run as an OS command instead of JavaScript.
   * Only supported in Tier 2+ sandboxes (not V8 isolates).
   *
   * @example
   * ```typescript
   * await sandbox.execute('python3 script.py', { shell: true });
   * ```
   */
  shell?: boolean;
}

// ---------------------------------------------------------------------------
// Sandbox Result & Streaming
// ---------------------------------------------------------------------------

/**
 * Result of a sandbox execution.
 *
 * Every execution returns a result — even failures. The sandbox must
 * never crash the host process. Errors are captured and returned.
 */
export interface SandboxResult {
  /** Whether the execution completed without error. */
  success: boolean;

  /** The return value of the executed code, if any. */
  result?: unknown;

  /** Error information if `success` is `false`. */
  error?: SandboxError | string;

  /** Captured log output (console.log, stdout, stderr). */
  logs: string[];

  /** Resource usage metrics for this execution. */
  metrics: SandboxMetrics;
}

/** A chunk of streaming output from {@link Sandbox.executeStream}. */
export interface SandboxChunk {
  /** The stream this chunk came from. */
  stream: 'stdout' | 'stderr';

  /** The chunk data. */
  data: string;

  /** Timestamp of when this chunk was produced. */
  timestamp: number;
}

/** Resource usage metrics collected after execution. */
export interface SandboxMetrics {
  /** CPU time consumed in milliseconds. */
  cpuMs: number;

  /** Peak memory usage in megabytes. */
  memoryMB: number;

  /** Wall-clock time in milliseconds. */
  wallMs: number;
}

// ---------------------------------------------------------------------------
// File Access
// ---------------------------------------------------------------------------

/**
 * File access within a sandbox's isolated filesystem.
 *
 * V1: tmpdir-based read/write. Files exist only for the sandbox's lifetime.
 * V2: cross-VM gateway with overlay filesystem.
 */
export interface SandboxFileAccess {
  /** Read a file from the sandbox's tmpdir. */
  read(path: string): Promise<string>;

  /** Write a file to the sandbox's tmpdir. */
  write(path: string, content: string): Promise<void>;

  /** List files in a directory within the sandbox's tmpdir. */
  list(dir: string): Promise<string[]>;
}

// ---------------------------------------------------------------------------
// Git Access
// ---------------------------------------------------------------------------

/**
 * Git operations for code injection and patch export.
 *
 * V1: inject code in, export patches out. Sandboxes never see the full repo.
 * V2: live clone/pull from other VMs.
 *
 * @example
 * ```typescript
 * // Host injects pruned repo
 * await sandbox.git.inject(tarball);
 *
 * // Agent works inside sandbox...
 * await sandbox.execute('...');
 *
 * // Host extracts changes as patch
 * const patch = await sandbox.git.exportPatch();
 * // Host validates and applies: git apply patch
 * ```
 */
export interface SandboxGitAccess {
  /** Inject a tarball or git bundle into the sandbox. */
  inject(source: string | Buffer): Promise<void>;

  /** Export all changes as a git diff patch string. */
  exportPatch(): Promise<string>;

  /** Export specific files as a tarball. */
  exportFiles(paths: string[]): Promise<Buffer>;
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/** Union of all typed sandbox errors. */
export type SandboxError =
  | SandboxTimeoutError
  | SandboxOOMError
  | SandboxPermissionError
  | SandboxCrashError;

/** The sandbox execution exceeded its wall-clock time limit. */
export class SandboxTimeoutError extends Error {
  readonly code = 'SANDBOX_TIMEOUT' as const;
  constructor(message = 'Sandbox execution timed out') {
    super(message);
    this.name = 'SandboxTimeoutError';
  }
}

/** The sandbox exceeded its memory limit. */
export class SandboxOOMError extends Error {
  readonly code = 'SANDBOX_OOM' as const;
  constructor(message = 'Sandbox exceeded memory limit') {
    super(message);
    this.name = 'SandboxOOMError';
  }
}

/** The sandbox attempted an operation it does not have permission for. */
export class SandboxPermissionError extends Error {
  readonly code = 'SANDBOX_PERMISSION' as const;
  constructor(message = 'Sandbox permission denied') {
    super(message);
    this.name = 'SandboxPermissionError';
  }
}

/** The sandbox process crashed unexpectedly. */
export class SandboxCrashError extends Error {
  readonly code = 'SANDBOX_CRASH' as const;
  constructor(message = 'Sandbox process crashed') {
    super(message);
    this.name = 'SandboxCrashError';
  }
}

/** All possible sandbox error codes. */
export type SandboxErrorCode =
  | 'SANDBOX_TIMEOUT'
  | 'SANDBOX_OOM'
  | 'SANDBOX_PERMISSION'
  | 'SANDBOX_CRASH';

// ---------------------------------------------------------------------------
// Circuit Breaker
// ---------------------------------------------------------------------------

/** State of a per-plugin circuit breaker. */
export type CircuitBreakerState = 'closed' | 'open' | 'half-open';

/**
 * Circuit breaker configuration for plugin failure handling.
 *
 * 3 consecutive failures → breaker trips (open) → 30s cooldown →
 * half-open retry → success closes breaker, failure re-opens.
 */
export interface CircuitBreakerConfig {
  /** Number of consecutive failures before the breaker trips. Default: 3. */
  failureThreshold: number;

  /** Cooldown period in milliseconds before a half-open retry. Default: 30000. */
  cooldownMs: number;
}

// ---------------------------------------------------------------------------
// Patch Validator
// ---------------------------------------------------------------------------

/** Result of validating a git patch. */
export interface PatchValidationResult {
  /** Whether the patch passed all validation rules. */
  valid: boolean;

  /** List of validation errors, if any. */
  errors: PatchValidationError[];
}

/** A specific validation failure in a git patch. */
export interface PatchValidationError {
  /** Which rule was violated. */
  rule: PatchValidationRule;

  /** Human-readable error message. */
  message: string;

  /** The offending path, if applicable. */
  path?: string;
}

/**
 * The 7 patch validation rules.
 *
 * Before applying any agent-produced patch, the host MUST:
 * 1. Parse the patch structurally (not just `git apply` blindly)
 * 2. Normalize all paths — reject `../` traversal
 * 3. Reject symlink creation
 * 4. Reject binary blobs by default
 * 5. Confine all paths to the workspace root
 * 6. Reject modifications to `.git/` internals
 * 7. Log the full patch for audit
 */
export type PatchValidationRule =
  | 'structural-parse'
  | 'path-traversal'
  | 'symlink-rejection'
  | 'binary-rejection'
  | 'workspace-confinement'
  | 'git-internals'
  | 'audit-log';

// ---------------------------------------------------------------------------
// Plugin Registry
// ---------------------------------------------------------------------------

/** Map of plugin names to their dynamic import functions. */
export type PluginRegistry = Record<string, () => Promise<{ default: SandboxPlugin }>>;

/**
 * Options for the sandbox factory.
 *
 * Used by `createSandbox()` to resolve the correct plugin and
 * configure the sandbox instance.
 */
export interface CreateSandboxOptions {
  /** The plugin to use, or its name for registry lookup. */
  plugin: SandboxPlugin | string;

  /** Sandbox configuration (limits, permissions, host functions). */
  config: SandboxConfig;

  /** Circuit breaker configuration. Uses defaults if not provided. */
  circuitBreaker?: Partial<CircuitBreakerConfig>;
}

// ---------------------------------------------------------------------------
// Degradation Chain
// ---------------------------------------------------------------------------

/**
 * The graceful degradation chain.
 *
 * When a higher-tier plugin is unavailable, the system falls back to
 * the next available tier. Warns loudly if an MCP server falls back
 * below `mcpMinTier`.
 *
 * Default chain:
 * Docker Sandboxes (T3) → E2B (T3) → Landlock (T2) → Anthropic SR (T2) → isolated-vm (T1)
 */
export type DegradationChain = string[];

import ivm from 'isolated-vm';
import type {
  SandboxPlugin,
  SandboxConfig,
  Sandbox,
  SandboxResult,
  SandboxChunk,
  ExecuteOptions,
  SandboxMetrics,
} from '../types.js';
import { SandboxTimeoutError, SandboxOOMError } from '../types.js';
import { createFileAccess } from '../file-access.js';
import { createGitAccess } from '../git-access.js';
import { createHostBridge, type HostBridge } from '../host-bridge.js';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/**
 * Bootstrap code injected into each fresh V8 context.
 *
 * Sets up:
 * - `console.log/error/warn` → host log capture via `_log` Callback
 * - `setTimeout(fn, ms)` → host timer via `_setTimeoutRef` Reference
 *
 * V8 isolates have no built-in timer or console APIs. These bridge
 * to the host event loop via isolated-vm's cross-isolate primitives.
 */
const BOOTSTRAP = `
  const console = {
    log:   (...args) => _log(args.map(a => typeof a === 'string' ? a : JSON.stringify(a) ?? String(a)).join(' ')),
    error: (...args) => _log(args.map(a => typeof a === 'string' ? a : JSON.stringify(a) ?? String(a)).join(' ')),
    warn:  (...args) => _log(args.map(a => typeof a === 'string' ? a : JSON.stringify(a) ?? String(a)).join(' ')),
  };
  let _nextTimerId = 1;
  function setTimeout(fn, ms) {
    const id = _nextTimerId++;
    _setTimeoutRef.applySyncPromise(undefined, [ms || 0]);
    try { if (typeof fn === 'function') fn(); } catch (_) {}
    return id;
  }
`;

/**
 * Host call bridge bootstrap (when hostFunctions are configured).
 *
 * Uses `Reference.applySyncPromise()` — the isolate yields to the host
 * event loop while the async host function runs, then resumes with
 * the JSON-serialized result. Errors are caught host-side and returned
 * as data to avoid unhandled rejections.
 *
 * NOTE: The JSON round-trip is lossy for non-JSON-safe types (Date → string,
 * Map/Set/BigInt/Buffer lost). This is an inherent trade-off of cross-isolate
 * communication. Host functions should return JSON-safe values. The mock
 * plugin does NOT have this limitation since it runs in the host process.
 */
const BOOTSTRAP_HOST_CALL = `
  function hostCall(name, args) {
    const resultJson = _hostCallRef.applySyncPromise(
      undefined, [name, JSON.stringify(args)]
    );
    const parsed = JSON.parse(resultJson);
    if (!parsed.ok) throw new Error(parsed.error);
    return parsed.value;
  }
`;

const BOOTSTRAP_NO_HOST_CALL = `
  function hostCall() { throw new Error('No host functions configured'); }
`;

/**
 * Tier 1: V8 isolate sandbox plugin.
 *
 * Uses the `isolated-vm` npm package to create separate V8 isolates
 * with their own heap, no access to host filesystem/network/globals.
 * Sub-millisecond startup. Cross-platform.
 *
 * Each `execute()` call creates a fresh Context within the Isolate,
 * ensuring context variables don't leak between executions. The Isolate
 * itself persists for the sandbox's lifetime (reusing compiled code caches).
 *
 * Resource limits:
 * - `memoryMB` → enforced by isolated-vm's `memoryLimit` (V8 heap cap)
 * - `timeoutMs` → enforced by V8-level `timeout` (sync loops) + host-side
 *   `Promise.race` (async never-resolving promises)
 * - `cpuMs` → reported via `isolate.cpuTime` but NOT enforced. Wall-time
 *   timeout is the enforced limit. True CPU-time enforcement would require
 *   polling `cpuTime` from a separate thread, which is deferred to V2.
 */
const isolatedVmPlugin: SandboxPlugin = {
  name: 'isolated-vm',
  version: '0.0.1',
  requiredCoreVersion: '>=0.0.1',
  isolationLevel: 'isolate',

  async create(config: SandboxConfig): Promise<Sandbox> {
    const tmpDir = await mkdtemp(join(tmpdir(), 'maestro-ivm-'));
    const workDir = join(tmpDir, 'work');

    const isolate = new ivm.Isolate({ memoryLimit: config.limits.memoryMB });
    let destroyed = false;
    let executing = false;

    // Track host-side timers for cleanup on destroy
    const activeTimers = new Set<ReturnType<typeof setTimeout>>();

    // Build host bridge if host functions provided
    let bridge: HostBridge | undefined;
    if (config.hostFunctions && Object.keys(config.hostFunctions).length > 0) {
      bridge = createHostBridge(config.hostFunctions);
    }

    const sandbox: Sandbox = {
      async execute(code: string, options?: ExecuteOptions): Promise<SandboxResult> {
        if (destroyed || isolate.isDisposed) {
          return {
            success: false,
            error: 'Sandbox has been destroyed',
            logs: [],
            metrics: { cpuMs: 0, memoryMB: 0, wallMs: 0 },
          };
        }

        // Prevent concurrent executions — shared isolate.cpuTime would
        // produce inaccurate metrics, and overlapping contexts on the
        // same isolate are not a supported use case.
        if (executing) {
          return {
            success: false,
            error: 'Concurrent execution not supported — wait for the previous call to complete',
            logs: [],
            metrics: { cpuMs: 0, memoryMB: 0, wallMs: 0 },
          };
        }
        executing = true;

        const startWall = Date.now();
        const startCpu = isolate.cpuTime;
        const logs: string[] = [];

        // Snapshot heap before execution for delta measurement
        let heapBefore = 0;
        try {
          heapBefore = isolate.getHeapStatisticsSync().used_heap_size;
        } catch { /* isolate may be disposed */ }

        // Fresh context per execution — prevents context variable leaking
        const context = await isolate.createContext();

        try {
          const jail = context.global;

          // --- Console log capture ---
          // Callback receives a single pre-formatted string from the isolate.
          // Uses default (sync) mode so logs are captured before eval resolves.
          await jail.set('_log', new ivm.Callback(
            (msg: string) => { logs.push(msg); },
          ));

          // --- setTimeout polyfill ---
          // Bridges to host event loop. Capped to sandbox timeout to prevent
          // a rogue `setTimeout(fn, Infinity)` from tying up the isolate
          // thread past the declared timeout. Timer IDs tracked for cleanup.
          const maxMs = config.limits.timeoutMs;
          await jail.set('_setTimeoutRef', new ivm.Reference(
            (ms: number) => {
              const capped = Math.min(Math.max(0, ms || 0), maxMs);
              return new Promise<void>((resolve) => {
                const id = globalThis.setTimeout(() => {
                  activeTimers.delete(id);
                  resolve();
                }, capped);
                activeTimers.add(id);
              });
            },
          ));

          await context.eval(BOOTSTRAP);

          // --- Host callback bridge ---
          if (bridge) {
            // Use Reference + applySyncPromise pattern for async host calls.
            // The isolate blocks (yields to host event loop) while the host
            // Promise resolves, then resumes with the result.
            const hostCallFn = async (name: string, argsJson: string) => {
              try {
                const args = JSON.parse(argsJson);
                const result = await bridge!.call(name, args);
                return JSON.stringify({ ok: true, value: result });
              } catch (err) {
                const msg = err instanceof Error ? err.message : String(err);
                return JSON.stringify({ ok: false, error: msg });
              }
            };
            await jail.set('_hostCallRef', new ivm.Reference(hostCallFn));
            await context.eval(BOOTSTRAP_HOST_CALL);
          } else {
            await context.eval(BOOTSTRAP_NO_HOST_CALL);
          }

          // --- Context variable injection ---
          if (options?.context) {
            for (const [key, value] of Object.entries(options.context)) {
              await jail.set(
                key,
                new ivm.ExternalCopy(value).copyInto(),
              );
            }
          }

          // --- Execute user code ---
          // Wrap in async IIFE so `return` and `await` work.
          // Two layers of timeout protection:
          //   1. V8-level `timeout` catches infinite synchronous loops
          //   2. Host-side `Promise.race` catches never-resolving promises
          const timeoutMs = config.limits.timeoutMs;
          const timer = createTimer(timeoutMs);

          try {
            const execPromise = context.eval(
              `(async () => { ${code} })()`,
              { timeout: timeoutMs, promise: true, copy: true },
            );

            const result = await Promise.race([execPromise, timer.promise]);
            const metrics = collectMetrics(isolate, startCpu, startWall, heapBefore);
            return { success: true, result, logs, metrics };
          } catch (err) {
            const metrics = collectMetrics(isolate, startCpu, startWall, heapBefore);

            if (isTimeoutError(err)) {
              return { success: false, error: new SandboxTimeoutError(), logs, metrics };
            }
            if (isOOMError(err)) {
              return { success: false, error: new SandboxOOMError(), logs, metrics };
            }

            const message = err instanceof Error ? err.message : String(err);
            return { success: false, error: message, logs, metrics };
          } finally {
            timer.clear();
          }
        } finally {
          // Guard against race with destroy() — isolate may be disposed
          try { context.release(); } catch { /* already disposed */ }
          executing = false;
        }
      },

      async *executeStream(
        code: string,
        options?: ExecuteOptions,
      ): AsyncIterable<SandboxChunk> {
        const result = await sandbox.execute(code, options);
        for (const log of result.logs) {
          yield { stream: 'stdout', data: log, timestamp: Date.now() };
        }
        if (!result.success && result.error) {
          const msg =
            typeof result.error === 'string'
              ? result.error
              : result.error.message;
          yield { stream: 'stderr', data: msg, timestamp: Date.now() };
        }
      },

      fs: createFileAccess(tmpDir),
      git: createGitAccess(workDir),

      async ready(): Promise<boolean> {
        return !destroyed && !isolate.isDisposed;
      },

      async destroy(): Promise<void> {
        if (destroyed) return;
        destroyed = true;

        // Cancel all pending host-side timers (setTimeout polyfill)
        for (const id of activeTimers) globalThis.clearTimeout(id);
        activeTimers.clear();

        if (!isolate.isDisposed) {
          isolate.dispose();
        }
        await rm(tmpDir, { recursive: true, force: true });
      },
    };

    return sandbox;
  },
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Collect CPU, memory (delta), and wall-clock metrics from the isolate.
 *
 * Memory is measured as the delta between heap usage before and after
 * execution, matching the mock plugin's behavior. Falls back gracefully
 * if the isolate is disposed (e.g., after OOM).
 */
function collectMetrics(
  isolate: ivm.Isolate,
  startCpu: bigint,
  startWall: number,
  heapBefore: number,
): SandboxMetrics {
  const wallMs = Date.now() - startWall;
  try {
    // cpuTime is bigint nanoseconds. Number() is safe up to ~104 days of CPU.
    const cpuNs = isolate.cpuTime - startCpu;
    const cpuMs = Number(cpuNs) / 1_000_000;

    let memoryMB = 0;
    try {
      const heapAfter = isolate.getHeapStatisticsSync().used_heap_size;
      memoryMB = Math.max(0, (heapAfter - heapBefore)) / (1024 * 1024);
    } catch {
      // Isolate may be disposed after OOM
    }

    return { cpuMs, memoryMB, wallMs };
  } catch {
    // Isolate disposed — return wall time only
    return { cpuMs: 0, memoryMB: 0, wallMs };
  }
}

/** Detect V8 timeout errors thrown by isolated-vm. */
function isTimeoutError(err: unknown): boolean {
  if (!(err instanceof Error)) return false;
  const msg = err.message.toLowerCase();
  return (
    msg.includes('script execution timed out') ||
    msg.includes('execution timed out') ||
    msg.includes('execution timeout')
  );
}

/** Detect V8 out-of-memory errors thrown by isolated-vm. */
function isOOMError(err: unknown): boolean {
  if (!(err instanceof Error)) return false;
  const msg = err.message.toLowerCase();
  return (
    msg.includes('memory limit') ||
    msg.includes('out of memory') ||
    (msg.includes('allocation') && msg.includes('failed'))
  );
}

/** Creates a clearable timeout that rejects with SandboxTimeoutError. */
function createTimer(ms: number): { promise: Promise<never>; clear: () => void } {
  let timerId: ReturnType<typeof setTimeout>;
  const promise = new Promise<never>((_, reject) => {
    timerId = globalThis.setTimeout(() => reject(new SandboxTimeoutError()), ms);
  });
  return { promise, clear: () => globalThis.clearTimeout(timerId) };
}

export default isolatedVmPlugin;

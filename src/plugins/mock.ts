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
 * Mock sandbox plugin for testing.
 *
 * Validates config exactly as real plugins. Executes code in the host
 * process WITHOUT isolation. Records lifecycle events for test assertions.
 * Enforces timeouts/memory via Node.js APIs.
 */
const mockPlugin: SandboxPlugin = {
  name: 'mock',
  version: '0.0.1',
  requiredCoreVersion: '>=0.0.1',
  isolationLevel: 'isolate',

  async create(config: SandboxConfig): Promise<Sandbox> {
    const tmpDir = await mkdtemp(join(tmpdir(), 'maestro-mock-'));
    const workDir = join(tmpDir, 'work');
    let destroyed = false;

    // Build host bridge if host functions provided
    let bridge: HostBridge | undefined;
    if (config.hostFunctions && Object.keys(config.hostFunctions).length > 0) {
      bridge = createHostBridge(config.hostFunctions);
    }

    const sandbox: Sandbox = {
      async execute(code: string, options?: ExecuteOptions): Promise<SandboxResult> {
        if (destroyed) {
          return {
            success: false,
            error: 'Sandbox has been destroyed',
            logs: [],
            metrics: { cpuMs: 0, memoryMB: 0, wallMs: 0 },
          };
        }

        const startTime = Date.now();
        const logs: string[] = [];
        const memBefore = process.memoryUsage().heapUsed;

        const timer = createTimeout(config.limits.timeoutMs);
        try {
          const result = await Promise.race([
            executeCode(code, options, logs, bridge, config),
            timer.promise,
          ]);

          const wallMs = Date.now() - startTime;
          const memAfter = process.memoryUsage().heapUsed;
          const metrics: SandboxMetrics = {
            cpuMs: wallMs, // approximate in mock
            memoryMB: Math.max(0, (memAfter - memBefore) / 1024 / 1024),
            wallMs,
          };

          return { success: true, result, logs, metrics };
        } catch (err) {
          const wallMs = Date.now() - startTime;
          const metrics: SandboxMetrics = {
            cpuMs: wallMs,
            memoryMB: 0,
            wallMs,
          };

          if (err instanceof SandboxTimeoutError || err instanceof SandboxOOMError) {
            return { success: false, error: err, logs, metrics };
          }

          return {
            success: false,
            error: err instanceof Error ? err.message : String(err),
            logs,
            metrics,
          };
        } finally {
          timer.clear();
        }
      },

      async *executeStream(code: string, options?: ExecuteOptions): AsyncIterable<SandboxChunk> {
        const result = await sandbox.execute(code, options);
        for (const log of result.logs) {
          yield { stream: 'stdout', data: log, timestamp: Date.now() };
        }
        if (!result.success && result.error) {
          const msg = typeof result.error === 'string' ? result.error : result.error.message;
          yield { stream: 'stderr', data: msg, timestamp: Date.now() };
        }
      },

      fs: createFileAccess(tmpDir),
      git: createGitAccess(workDir),

      async ready(): Promise<boolean> {
        return !destroyed;
      },

      async destroy(): Promise<void> {
        if (destroyed) return;
        destroyed = true;
        await rm(tmpDir, { recursive: true, force: true });
      },
    };

    return sandbox;
  },
};

/**
 * Execute code in the host process (no isolation).
 * Supports context injection and hostCall via the bridge.
 */
async function executeCode(
  code: string,
  options: ExecuteOptions | undefined,
  logs: string[],
  bridge: HostBridge | undefined,
  config: SandboxConfig,
): Promise<unknown> {
  // Build the execution context
  const context: Record<string, unknown> = { ...(options?.context ?? {}) };

  // Inject secrets as env-like access
  if (config.secrets) {
    context.__secrets = { ...config.secrets };
  }

  // hostCall function for sandbox code
  const hostCall = async (name: string, args: unknown): Promise<unknown> => {
    if (!bridge) throw new Error('No host functions configured');
    return bridge.call(name, args);
  };

  // Custom console.log that captures to logs array
  const consoleMock = {
    log: (...args: unknown[]) => {
      logs.push(args.map(a => typeof a === 'string' ? a : JSON.stringify(a)).join(' '));
    },
    error: (...args: unknown[]) => {
      logs.push(args.map(a => typeof a === 'string' ? a : JSON.stringify(a)).join(' '));
    },
    warn: (...args: unknown[]) => {
      logs.push(args.map(a => typeof a === 'string' ? a : JSON.stringify(a)).join(' '));
    },
  };

  // Build the function body with context variables
  const contextKeys = Object.keys(context);
  const contextValues = Object.values(context);

  // Construct function that has access to context, hostCall, and console
  const fn = new Function(
    'console', 'hostCall', ...contextKeys,
    `return (async () => { ${code} })();`,
  );

  return await fn(consoleMock, hostCall, ...contextValues);
}

/** Creates a clearable timeout that rejects after the given duration. */
function createTimeout(ms: number): { promise: Promise<never>; clear: () => void } {
  let timerId: ReturnType<typeof setTimeout>;
  const promise = new Promise<never>((_, reject) => {
    timerId = setTimeout(() => reject(new SandboxTimeoutError()), ms);
  });
  return {
    promise,
    clear: () => clearTimeout(timerId),
  };
}

export default mockPlugin;

import type {
  SandboxPlugin,
  SandboxConfig,
  Sandbox,
  SandboxResult,
  SandboxChunk,
  ExecuteOptions,
  SandboxMetrics,
} from '../types.js';
import { SandboxTimeoutError, SandboxOOMError, SandboxCrashError } from '../types.js';
import { createFileAccess } from '../file-access.js';
import { createGitAccess } from '../git-access.js';
import { createHostBridge, type HostBridge } from '../host-bridge.js';
import { buildScript, parseScriptOutput, parseExecError } from '../build-script.js';
import { SandboxManager } from '@anthropic-ai/sandbox-runtime';
import type { SandboxRuntimeConfig } from '@anthropic-ai/sandbox-runtime';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

/** Track whether SandboxManager has been initialized globally. */
let managerInitialized = false;

/**
 * Tier 2: Anthropic Sandbox Runtime plugin.
 *
 * Wraps `@anthropic-ai/sandbox-runtime` — Anthropic's OS-level restriction
 * system. Uses Seatbelt (macOS) or Landlock+seccomp (Linux) under the hood.
 *
 * Code executes in a child Node.js process wrapped by the Anthropic sandbox
 * runtime, which restricts filesystem, network, and syscall access.
 */
const anthropicSrPlugin: SandboxPlugin = {
  name: 'anthropic-sr',
  version: '0.0.1',
  requiredCoreVersion: '>=0.0.1',
  isolationLevel: 'process',

  async create(config: SandboxConfig): Promise<Sandbox> {
    const tmpDir = await mkdtemp(join(tmpdir(), 'maestro-asr-'));
    const workDir = join(tmpDir, 'work');
    let destroyed = false;

    // Check platform support
    if (!SandboxManager.isSupportedPlatform()) {
      throw new SandboxCrashError(
        'Anthropic Sandbox Runtime is not supported on this platform',
      );
    }

    // Check dependencies — fail fast if sandbox runtime can't work
    const deps = SandboxManager.checkDependencies();
    if (deps.errors.length > 0) {
      throw new SandboxCrashError(
        `Anthropic Sandbox Runtime dependencies missing: ${deps.errors.join('; ')}`,
      );
    }

    // Build Anthropic SR config from our SandboxConfig
    const srConfig: SandboxRuntimeConfig = {
      network: {
        allowedDomains: config.limits.networkAccess
          ? (config.network?.allowedPeers?.map(p => p.split(':')[0]) ?? [])
          : [],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: [],
        allowWrite: [tmpDir],
        denyWrite: [],
      },
    };

    // Initialize the sandbox manager once globally (singleton pattern).
    // WARNING: SandboxManager is a process-global singleton. Calling updateConfig()
    // changes the config for ALL active sandboxes. If sandboxes need different
    // network policies, they must use separate plugins or be created sequentially.
    // This is an Anthropic SDK limitation — tracked for V2 resolution.
    if (!managerInitialized) {
      await SandboxManager.initialize(srConfig);
      managerInitialized = true;
    } else {
      SandboxManager.updateConfig(srConfig);
    }

    // Host functions require IPC bridge — not available in process-level sandbox V1
    if (config.hostFunctions && Object.keys(config.hostFunctions).length > 0) {
      throw new SandboxCrashError(
        'Anthropic SR plugin does not support hostFunctions in V1. Use isolated-vm for host callbacks.',
      );
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

        try {
          // Write the code to a temp file (avoids shell injection via -e)
          const scriptPath = join(tmpDir, `exec-${Date.now()}.mjs`);
          const wrappedCode = buildScript(code, options);
          await writeFile(scriptPath, wrappedCode, 'utf-8');

          // Wrap the node command with sandbox restrictions
          // Use execFile with argument array to avoid sh -c injection
          const wrappedCmd = await SandboxManager.wrapWithSandbox(
            `${process.execPath} --max-old-space-size=${Number(config.limits.memoryMB)} ${scriptPath}`,
          );

          // Execute with timeout — restricted env (no process.env spread)
          const { stdout, stderr } = await execFileAsync('sh', ['-c', wrappedCmd], {
            cwd: tmpDir,
            timeout: config.limits.timeoutMs,
            maxBuffer: 10 * 1024 * 1024,
            env: {
              PATH: process.env.PATH,
              HOME: tmpDir,
              TMPDIR: tmpDir,
              NODE_PATH: process.env.NODE_PATH,
              ...(config.secrets ?? {}),
            },
          });

          const wallMs = Date.now() - startTime;
          // V1: cpuMs is wall-clock time (no per-process CPU accounting). memoryMB is 0 (no /proc stat).
          const metrics: SandboxMetrics = { cpuMs: wallMs, memoryMB: 0, wallMs };

          const parsed = parseScriptOutput(stdout);
          if (parsed) {
            logs.push(...parsed.logs);
            if (parsed.error) {
              return { success: false, error: parsed.error, logs, metrics };
            }
            return { success: true, result: parsed.result, logs, metrics };
          }

          if (stdout.trim()) logs.push(stdout.trim());
          if (stderr.trim()) logs.push(stderr.trim());
          return { success: true, result: undefined, logs, metrics };
        } catch (err: unknown) {
          const wallMs = Date.now() - startTime;
          const metrics: SandboxMetrics = { cpuMs: wallMs, memoryMB: 0, wallMs };

          if (err && typeof err === 'object' && 'killed' in err && err.killed) {
            return { success: false, error: new SandboxTimeoutError(), logs, metrics };
          }

          // Try to parse structured output from the failed process
          const parsedErr = parseExecError(err);
          if (parsedErr) {
            logs.push(...parsedErr.logs);
            if (parsedErr.error) {
              return { success: false, error: parsedErr.error, logs, metrics };
            }
          }

          const msg = err instanceof Error ? err.message : String(err);

          if (msg.includes('ETIMEDOUT') || msg.includes('timed out')) {
            return { success: false, error: new SandboxTimeoutError(), logs, metrics };
          }

          // OOM detection: check exit code 137 directly, not as substring
          const exitCode = err && typeof err === 'object' && 'code' in err ? (err as { code: unknown }).code : undefined;
          if (msg.includes('OOM') || msg.includes('out of memory') || exitCode === 137) {
            return { success: false, error: new SandboxOOMError(), logs, metrics };
          }

          return { success: false, error: msg, logs, metrics };
        }
      },

      /**
       * V1 limitation: executes fully via execute(), then yields logs as chunks.
       * Not true streaming — all output is buffered until execution completes.
       */
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
        return !destroyed && SandboxManager.isSandboxingEnabled();
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

export default anthropicSrPlugin;

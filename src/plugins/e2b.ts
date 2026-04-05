import type {
  SandboxPlugin,
  SandboxConfig,
  Sandbox,
  SandboxResult,
  SandboxChunk,
  ExecuteOptions,
  SandboxMetrics,
  SandboxFileAccess,
  SandboxGitAccess,
} from '../types.js';
import { SandboxTimeoutError, SandboxOOMError, SandboxCrashError } from '../types.js';
import { buildScript, parseScriptOutput, confinePath, shellEscape } from '../build-script.js';
import { randomUUID } from 'node:crypto';
import { Sandbox as E2BSandbox } from 'e2b';

/**
 * Tier 3: E2B cloud sandbox plugin.
 *
 * Cloud-hosted sandboxes via the E2B SDK. Each sandbox runs in its own
 * microVM with full isolation. Requires E2B_API_KEY environment variable.
 *
 * Best for: SOC2/HIPAA, multi-tenant SaaS, untrusted models.
 * Trade-off: network latency, data leaves local infrastructure.
 */
const e2bPlugin: SandboxPlugin = {
  name: 'e2b',
  version: '0.0.1',
  requiredCoreVersion: '>=0.0.1',
  isolationLevel: 'microvm',

  async create(config: SandboxConfig): Promise<Sandbox> {
    // Host functions require IPC bridge — not available in microVM sandbox V1.
    // Check BEFORE creating the E2B sandbox to avoid leaking a cloud VM.
    if (config.hostFunctions && Object.keys(config.hostFunctions).length > 0) {
      throw new SandboxCrashError(
        'E2B plugin does not support hostFunctions in V1. Use isolated-vm for host callbacks.',
      );
    }

    const apiKey = config.secrets?.E2B_API_KEY ?? process.env.E2B_API_KEY;
    if (!apiKey) {
      throw new SandboxCrashError(
        'E2B_API_KEY is required. Set it in config.secrets or environment.',
      );
    }

    let e2bSandbox: E2BSandbox;
    try {
      // Sandbox lifetime is separate from execution timeout — keep the VM alive
      // for the session. Use a generous lifetime (5min minimum).
      const lifetimeMs = Math.max(config.limits.timeoutMs * 5, 300000);
      e2bSandbox = await E2BSandbox.create({
        apiKey,
        timeoutMs: lifetimeMs,
      });
    } catch (err) {
      throw new SandboxCrashError(
        `Failed to create E2B sandbox: ${err instanceof Error ? err.message : String(err)}`,
      );
    }

    let destroyed = false;

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
          // Write script to the sandbox filesystem
          const scriptPath = `/sandbox/exec-${randomUUID()}.mjs`;
          const wrappedCode = buildScript(code, options);
          await e2bSandbox.files.write(scriptPath, wrappedCode);

          // Execute with timeout
          const result = await e2bSandbox.commands.run(
            `node --max-old-space-size=${Number(config.limits.memoryMB)} ${shellEscape(scriptPath)}`,
            { timeoutMs: config.limits.timeoutMs },
          );

          const wallMs = Date.now() - startTime;
          const metrics: SandboxMetrics = { cpuMs: wallMs, memoryMB: 0, wallMs };

          const stdout = result.stdout.trim();
          const stderr = result.stderr.trim();

          // Parse structured output first, then fall back to raw
          const parsed = parseScriptOutput(stdout);
          if (parsed) {
            logs.push(...parsed.logs);
            if (stderr) logs.push(stderr);
            if (parsed.error) {
              return { success: false, error: parsed.error, logs, metrics };
            }
            return { success: true, result: parsed.result, logs, metrics };
          }

          if (stdout) logs.push(stdout);
          if (stderr) logs.push(stderr);

          if (result.exitCode !== 0) {
            return { success: false, error: `Process exited with code ${result.exitCode}`, logs, metrics };
          }

          return { success: true, result: undefined, logs, metrics };
        } catch (err: unknown) {
          const wallMs = Date.now() - startTime;
          const metrics: SandboxMetrics = { cpuMs: wallMs, memoryMB: 0, wallMs };

          const msg = err instanceof Error ? err.message : String(err);
          if (msg.includes('timeout') || msg.includes('Timeout')) {
            return { success: false, error: new SandboxTimeoutError(), logs, metrics };
          }

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

      fs: createE2BFileAccess(e2bSandbox),
      git: createE2BGitAccess(e2bSandbox),

      async ready(): Promise<boolean> {
        if (destroyed) return false;
        try {
          return await e2bSandbox.isRunning();
        } catch {
          return false;
        }
      },

      async destroy(): Promise<void> {
        if (destroyed) return;
        destroyed = true;
        try {
          await e2bSandbox.kill();
        } catch {
          // Sandbox may already be killed
        }
      },
    };

    return sandbox;
  },
};

const SANDBOX_BASE = '/sandbox';

/**
 * E2B-based file access with path confinement.
 */
function createE2BFileAccess(e2bSandbox: E2BSandbox): SandboxFileAccess {
  return {
    async read(path: string): Promise<string> {
      const safePath = confinePath(SANDBOX_BASE, path);
      return await e2bSandbox.files.read(safePath);
    },

    async write(path: string, content: string): Promise<void> {
      const safePath = confinePath(SANDBOX_BASE, path);
      await e2bSandbox.files.write(safePath, content);
    },

    async list(dir: string): Promise<string[]> {
      const safePath = confinePath(SANDBOX_BASE, dir);
      const result = await e2bSandbox.commands.run(`ls ${shellEscape(safePath)}`);
      return result.stdout.trim().split('\n').filter(Boolean);
    },
  };
}

/**
 * E2B-based git access with path confinement.
 */
function createE2BGitAccess(e2bSandbox: E2BSandbox): SandboxGitAccess {
  const workDir = '/sandbox/work';
  let initialized = false;

  async function run(cmd: string): Promise<string> {
    const result = await e2bSandbox.commands.run(cmd, { timeoutMs: 10000 });
    return result.stdout;
  }

  async function ensureGit(): Promise<void> {
    if (initialized) return;
    await run(`mkdir -p ${shellEscape(workDir)}`);
    await run(`cd ${shellEscape(workDir)} && git init`);
    await run(`cd ${shellEscape(workDir)} && git config user.email sandbox@maestro.dev`);
    await run(`cd ${shellEscape(workDir)} && git config user.name "Maestro Sandbox"`);
    await run(`cd ${shellEscape(workDir)} && git add -A && git commit -m initial --allow-empty`);
    initialized = true;
  }

  return {
    async inject(source: string | Buffer): Promise<void> {
      await ensureGit();
      if (typeof source === 'string') {
        // Upload tarball and extract
        const fs = await import('node:fs/promises');
        const content = await fs.readFile(source);
        const ab = content.buffer.slice(content.byteOffset, content.byteOffset + content.byteLength) as ArrayBuffer;
        await e2bSandbox.files.write(`${workDir}/.inject.tar`, ab);
        await run(`cd ${shellEscape(workDir)} && tar xf .inject.tar && rm .inject.tar`);
      } else {
        const ab = source.buffer.slice(source.byteOffset, source.byteOffset + source.byteLength) as ArrayBuffer;
        await e2bSandbox.files.write(`${workDir}/.inject.tar`, ab);
        await run(`cd ${shellEscape(workDir)} && tar xf .inject.tar && rm .inject.tar`);
      }
      await run(`cd ${shellEscape(workDir)} && git add -A && git commit -m injected --allow-empty`);
    },

    async exportPatch(): Promise<string> {
      await ensureGit();
      return await run(`cd ${shellEscape(workDir)} && git diff HEAD`);
    },

    async exportFiles(paths: string[]): Promise<Buffer> {
      await ensureGit();
      // Validate each path is confined to workDir
      for (const p of paths) {
        confinePath(workDir, p);
      }
      const escapedPaths = paths.map(p => shellEscape(p));
      const tarName = '.maestro-export.tar';
      await run(`cd ${shellEscape(workDir)} && tar cf ${shellEscape(tarName)} ${escapedPaths.join(' ')}`);
      const content = await e2bSandbox.files.read(`${workDir}/${tarName}`, { format: 'bytes' });
      await run(`rm ${shellEscape(workDir + '/' + tarName)}`);
      return Buffer.from(content);
    },
  };
}

export default e2bPlugin;

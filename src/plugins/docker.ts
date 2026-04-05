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
import type { SandboxFileAccess, SandboxGitAccess } from '../types.js';
import { buildScript, parseScriptOutput, parseExecError, confinePath, shellEscape } from '../build-script.js';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomUUID } from 'node:crypto';
import { writeFile, rm, chmod } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const execFileAsync = promisify(execFile);

/**
 * Tier 3: Docker Sandboxes plugin.
 *
 * Runs code in ephemeral Docker containers. Requires Docker to be installed
 * and running. Each sandbox gets its own container with restricted resources.
 *
 * Uses `docker run` with resource limits (--memory, --cpus), network isolation
 * (--network=none), and a readonly root filesystem with a tmpfs for writes.
 */
const dockerPlugin: SandboxPlugin = {
  name: 'docker',
  version: '0.0.1',
  requiredCoreVersion: '>=0.0.1',
  isolationLevel: 'container',

  async create(config: SandboxConfig): Promise<Sandbox> {
    // Verify Docker is available
    try {
      await execFileAsync('docker', ['info'], { timeout: 5000 });
    } catch {
      throw new SandboxCrashError(
        'Docker is not available. Install Docker Desktop or use degradation chain.',
      );
    }

    const containerId = `maestro-sandbox-${randomUUID()}`;
    const workDir = '/sandbox/work';
    let destroyed = false;
    let containerStarted = false;

    // Host functions require IPC bridge — not available in container sandbox V1
    if (config.hostFunctions && Object.keys(config.hostFunctions).length > 0) {
      throw new SandboxCrashError(
        'Docker plugin does not support hostFunctions in V1. Use isolated-vm for host callbacks.',
      );
    }

    // Start a persistent container
    const { args: dockerArgs, envFilePath } = await buildDockerRunArgs(containerId, config);
    try {
      await execFileAsync('docker', dockerArgs, { timeout: 30000 });
      containerStarted = true;
    } catch (err) {
      throw new SandboxCrashError(
        `Failed to start Docker container: ${err instanceof Error ? err.message : String(err)}`,
      );
    } finally {
      // Always clean up the env file — secrets must not persist on disk
      if (envFilePath) {
        await rm(envFilePath, { force: true }).catch(() => {});
      }
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
          // Write script to file inside container (avoids shell injection via node -e)
          const scriptName = `exec-${randomUUID()}.mjs`;
          const scriptPath = `/sandbox/${scriptName}`;
          const wrappedCode = buildScript(code, options);

          // Use docker exec sh -c with stdin to write the file safely.
          // `as never`: execFile options accept `input` at runtime but @types/node omits it.
          await execFileAsync(
            'docker',
            ['exec', '-i', containerId, 'sh', '-c', `cat > ${shellEscape(scriptPath)}`],
            { timeout: 5000, input: wrappedCode } as never,
          );

          // Execute the script file
          const result = await execFileAsync(
            'docker',
            ['exec', containerId, 'node', `--max-old-space-size=${Number(config.limits.memoryMB)}`, scriptPath],
            {
              timeout: config.limits.timeoutMs + 1000, // buffer for docker overhead
              maxBuffer: 10 * 1024 * 1024,
            },
          );

          const wallMs = Date.now() - startTime;
          const metrics: SandboxMetrics = { cpuMs: wallMs, memoryMB: 0, wallMs };

          const parsed = parseScriptOutput(result.stdout);
          if (parsed) {
            logs.push(...parsed.logs);
            if (parsed.error) {
              return { success: false, error: parsed.error, logs, metrics };
            }
            return { success: true, result: parsed.result, logs, metrics };
          }

          if (result.stdout.trim()) logs.push(result.stdout.trim());
          if (result.stderr.trim()) logs.push(result.stderr.trim());
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

          // Check exit code 137 (SIGKILL from OOM killer) via the error object,
          // not substring — avoids false positives on IPs like 10.0.137.1
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

      fs: createDockerFileAccess(containerId),
      git: createDockerGitAccess(containerId, workDir),

      async ready(): Promise<boolean> {
        if (destroyed || !containerStarted) return false;
        try {
          const { stdout } = await execFileAsync(
            'docker',
            ['inspect', '-f', '{{.State.Running}}', containerId],
            { timeout: 5000 },
          );
          return stdout.trim() === 'true';
        } catch {
          return false;
        }
      },

      async destroy(): Promise<void> {
        if (destroyed) return;
        destroyed = true;
        if (containerStarted) {
          try {
            await execFileAsync('docker', ['rm', '-f', containerId], { timeout: 10000 });
          } catch {
            // Container may already be gone
          }
        }
      },
    };

    return sandbox;
  },
};

/**
 * Build docker run args for creating a persistent container.
 *
 * Secrets are written to a temp env-file (chmod 600) and passed via --env-file
 * to avoid leaking values in process listings. The caller MUST delete the
 * returned envFilePath after docker run completes.
 */
async function buildDockerRunArgs(
  name: string,
  config: SandboxConfig,
): Promise<{ args: string[]; envFilePath?: string }> {
  const args = [
    'run', '-d',
    '--name', name,
    '--memory', `${config.limits.memoryMB}m`,
    '--memory-swap', `${config.limits.memoryMB}m`, // no swap
    '--pids-limit', '64',
    '--read-only',
    '--tmpfs', '/sandbox:rw,nosuid,size=256m',
    '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m',
  ];

  // Network isolation
  if (!config.limits.networkAccess) {
    args.push('--network', 'none');
  }

  // Security: drop all capabilities, no new privileges
  args.push('--cap-drop', 'ALL');
  args.push('--security-opt', 'no-new-privileges');

  // Inject secrets via --env-file (avoids leaking in ps/cmdline)
  let envFilePath: string | undefined;
  if (config.secrets && Object.keys(config.secrets).length > 0) {
    envFilePath = join(tmpdir(), `maestro-env-${randomUUID()}`);
    const lines = Object.entries(config.secrets)
      .map(([k, v]) => `${k}=${v}`)
      .join('\n');
    await writeFile(envFilePath, lines, { mode: 0o600 });
    args.push('--env-file', envFilePath);
  }

  // Use node:22-slim image, keep container alive with tail -f /dev/null
  args.push('node:22-slim', 'tail', '-f', '/dev/null');

  return { args, envFilePath };
}

const SANDBOX_BASE = '/sandbox';

/**
 * Docker-based file access — uses docker exec with path confinement.
 */
function createDockerFileAccess(containerId: string): SandboxFileAccess {
  return {
    async read(path: string): Promise<string> {
      const safePath = confinePath(SANDBOX_BASE, path);
      const { stdout } = await execFileAsync(
        'docker', ['exec', containerId, 'cat', safePath],
        { timeout: 5000 },
      );
      return stdout;
    },

    async write(path: string, content: string): Promise<void> {
      const safePath = confinePath(SANDBOX_BASE, path);
      const dir = safePath.split('/').slice(0, -1).join('/');
      await execFileAsync(
        'docker', ['exec', containerId, 'mkdir', '-p', dir],
        { timeout: 5000 },
      );
      await execFileAsync(
        'docker', ['exec', '-i', containerId, 'sh', '-c', `cat > ${shellEscape(safePath)}`],
        { timeout: 5000, input: content } as never,
      );
    },

    async list(dir: string): Promise<string[]> {
      const safePath = confinePath(SANDBOX_BASE, dir);
      const { stdout } = await execFileAsync(
        'docker', ['exec', containerId, 'ls', safePath],
        { timeout: 5000 },
      );
      return stdout.trim().split('\n').filter(Boolean);
    },
  };
}

/**
 * Docker-based git access with path confinement.
 */
function createDockerGitAccess(containerId: string, workDir: string): SandboxGitAccess {
  let initialized = false;

  async function dockerExec(args: string[]): Promise<string> {
    const { stdout } = await execFileAsync(
      'docker', ['exec', containerId, ...args],
      { timeout: 10000 },
    );
    return stdout;
  }

  async function ensureGit(): Promise<void> {
    if (initialized) return;
    await dockerExec(['mkdir', '-p', workDir]);
    await dockerExec(['git', '-C', workDir, 'init']);
    await dockerExec(['git', '-C', workDir, 'config', 'user.email', 'sandbox@maestro.dev']);
    await dockerExec(['git', '-C', workDir, 'config', 'user.name', 'Maestro Sandbox']);
    await dockerExec(['git', '-C', workDir, 'add', '-A']);
    await dockerExec(['git', '-C', workDir, 'commit', '-m', 'initial', '--allow-empty']);
    initialized = true;
  }

  return {
    async inject(source: string | Buffer): Promise<void> {
      await ensureGit();
      if (typeof source === 'string') {
        // Copy tarball into container and extract
        await execFileAsync('docker', ['cp', source, `${containerId}:${workDir}/`], { timeout: 10000 });
        const filename = source.split('/').pop()!;
        await dockerExec(['tar', 'xf', `${workDir}/${filename}`, '-C', workDir]);
        await dockerExec(['rm', `${workDir}/${filename}`]);
      } else {
        throw new Error('Buffer injection not yet supported in Docker plugin — use file path');
      }
      await dockerExec(['git', '-C', workDir, 'add', '-A']);
      await dockerExec(['git', '-C', workDir, 'commit', '-m', 'injected', '--allow-empty']);
    },

    async exportPatch(): Promise<string> {
      await ensureGit();
      return await dockerExec(['git', '-C', workDir, 'diff', 'HEAD']);
    },

    async exportFiles(paths: string[]): Promise<Buffer> {
      await ensureGit();
      // Validate each path is confined to workDir
      for (const p of paths) {
        confinePath(workDir, p);
      }
      const tarName = '.maestro-export.tar';
      await dockerExec(['tar', 'cf', `${workDir}/${tarName}`, '-C', workDir, ...paths]);
      const { stdout } = await execFileAsync(
        'docker', ['exec', containerId, 'cat', `${workDir}/${tarName}`],
        { timeout: 10000, encoding: 'buffer' as never },
      );
      await dockerExec(['rm', `${workDir}/${tarName}`]);
      return Buffer.from(stdout);
    },
  };
}

export default dockerPlugin;

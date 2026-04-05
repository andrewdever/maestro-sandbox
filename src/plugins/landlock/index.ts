import type {
  SandboxPlugin,
  SandboxConfig,
  Sandbox,
  SandboxResult,
  SandboxChunk,
  ExecuteOptions,
  SandboxMetrics,
} from '../../types.js';
import { SandboxTimeoutError, SandboxOOMError, SandboxCrashError } from '../../types.js';
import { createFileAccess } from '../../file-access.js';
import { createGitAccess } from '../../git-access.js';
import { buildScript, parseScriptOutput, parseExecError } from '../../build-script.js';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir, platform } from 'node:os';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

/**
 * Tier 2: Maestro's own OS-level sandbox plugin.
 *
 * - **macOS**: Seatbelt profile + `sandbox-exec` via child_process.
 * - **Linux**: Not yet implemented — refuses to create (V1.1 requires Rust NAPI-RS).
 * - **Windows**: Not supported — falls back via degradation chain.
 *
 * No vendor lock-in. Drop-in replacement for Anthropic SR.
 */
const landlockPlugin: SandboxPlugin = {
  name: 'landlock',
  version: '0.0.1',
  requiredCoreVersion: '>=0.0.1',
  isolationLevel: 'process',

  async create(config: SandboxConfig): Promise<Sandbox> {
    const os = platform();

    if (os === 'linux') {
      // Linux Landlock+seccomp requires Rust NAPI-RS bindings (V1.1).
      // Refuse to create rather than silently running without isolation.
      throw new SandboxCrashError(
        'Landlock plugin on Linux requires Rust NAPI-RS bindings (V1.1). Use degradation chain to fall back to Anthropic SR or isolated-vm.',
      );
    }

    if (os !== 'darwin') {
      throw new SandboxCrashError(
        `Landlock plugin is not supported on ${os}. Use degradation chain to fall back.`,
      );
    }

    const tmpDir = await mkdtemp(join(tmpdir(), 'maestro-landlock-'));
    const workDir = join(tmpDir, 'work');
    let destroyed = false;

    // Host functions require IPC bridge — not available in process-level sandbox V1
    if (config.hostFunctions && Object.keys(config.hostFunctions).length > 0) {
      throw new SandboxCrashError(
        'Landlock plugin does not support hostFunctions in V1. Use isolated-vm for host callbacks.',
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
          const scriptPath = join(tmpDir, `exec-${Date.now()}.mjs`);
          const wrappedCode = buildScript(code, options);
          await writeFile(scriptPath, wrappedCode, 'utf-8');

          const nodeArgs = [`--max-old-space-size=${Number(config.limits.memoryMB)}`, scriptPath];

          // macOS: use sandbox-exec with Seatbelt profile
          const nodeRootDir = process.execPath.split('/').slice(0, -2).join('/');
          const profile = buildSeatbeltProfile(tmpDir, config, nodeRootDir);
          const profilePath = join(tmpDir, '.seatbelt.sb');
          await writeFile(profilePath, profile, 'utf-8');

          const result = await execFileAsync(
            'sandbox-exec',
            ['-f', profilePath, process.execPath, ...nodeArgs],
            {
              cwd: tmpDir,
              timeout: config.limits.timeoutMs,
              maxBuffer: 10 * 1024 * 1024,
              env: {
                PATH: process.env.PATH,
                HOME: tmpDir,
                TMPDIR: tmpDir,
                ...(config.secrets ?? {}),
              },
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

          // OOM detection: exit code 137 = SIGKILL (OOM killer).
          // Check exit code directly — substring '137' false-positives on IPs.
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
        if (destroyed) return false;
        try {
          await execFileAsync('which', ['sandbox-exec']);
          return true;
        } catch {
          return false;
        }
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
 * Build a macOS Seatbelt profile that restricts the sandboxed process.
 *
 * Strategy: allow-default with deny rules for network and filesystem writes.
 * Node.js requires many mach ports, IOKit, and system services that are
 * impractical to enumerate in a deny-default profile.
 *
 * Denies:
 * - Network access (unless config allows)
 * - Filesystem writes outside tmpdir
 * - Filesystem writes to sensitive system paths
 * - Filesystem reads of sensitive credentials
 * - Process spawning of system binaries
 */
/** Sanitize a path for safe interpolation into a Seatbelt profile. */
function sanitizeSeatbeltPath(p: string): string {
  // Reject characters that could break out of a (subpath "...") / (literal "...") form.
  // Only double-quotes and backslashes are dangerous inside the quoted string.
  if (/["\\\x00-\x1f]/.test(p)) {
    throw new Error(`Unsafe characters in path for Seatbelt profile: ${p}`);
  }
  return p;
}

function buildSeatbeltProfile(tmpDir: string, config: SandboxConfig, nodePath?: string): string {
  const safeTmpDir = sanitizeSeatbeltPath(tmpDir);
  const safeNodePath = nodePath ? sanitizeSeatbeltPath(nodePath) : undefined;

  const networkRule = config.limits.networkAccess
    ? '(allow network*)'
    : '(deny network*)';

  return `
(version 1)
(allow default)

;; Deny network access unless explicitly allowed
${networkRule}

;; Deny writing to all user and system paths (protect host filesystem)
(deny file-write* (subpath "/Users"))
(deny file-write* (subpath "/home"))
(deny file-write* (subpath "/etc"))
(deny file-write* (subpath "/var/root"))
(deny file-write* (subpath "/opt"))
(deny file-write* (subpath "/usr/local"))
(deny file-write* (subpath "/Library"))

;; Allow writing to sandbox tmpdir (must come after deny rules)
(allow file-write* (subpath "${safeTmpDir}"))

;; Deny reading sensitive credential files
(deny file-read-data (literal "/etc/shadow"))
(deny file-read-data (subpath "/Users/*/.*ssh"))
(deny file-read-data (subpath "/Users/*/.gnupg"))
(deny file-read-data (subpath "/Users/*/.aws"))
(deny file-read-data (literal "/Users/*/.env"))
(deny file-read-data (literal "/Users/*/.env.local"))

;; Deny spawning system binaries (limit to node itself)
(deny process-exec (subpath "/usr/bin") (with no-report))
(deny process-exec (subpath "/usr/sbin") (with no-report))
(deny process-exec (subpath "/bin") (with no-report))
(deny process-exec (subpath "/sbin") (with no-report))
(allow process-exec (literal "/usr/bin/env"))
${safeNodePath ? `(allow process-exec (subpath "${safeNodePath}"))` : ''}
`.trim();
}

export default landlockPlugin;

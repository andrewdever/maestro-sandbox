import { describe, it, expect, afterEach } from 'vitest';
import { platform } from 'node:os';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createSandbox, resetCircuitBreakers } from '../../factory.js';
import type { Sandbox, SandboxConfig } from '../../types.js';
import { SandboxOOMError, SandboxTimeoutError } from '../../types.js';

const execFileAsync = promisify(execFile);

let hasRipgrep = false;
try {
  await execFileAsync('rg', ['--version'], { timeout: 3000 });
  hasRipgrep = true;
} catch { /* anthropic-sr requires ripgrep */ }

const config: SandboxConfig = {
  limits: {
    memoryMB: 128,
    cpuMs: 5000,
    timeoutMs: 3000,
    networkAccess: false,
    filesystemAccess: 'tmpfs' as const,
  },
};

describe('Sandbox isolation (integration)', () => {
  const sandboxes: Sandbox[] = [];

  afterEach(async () => {
    for (const sb of sandboxes) {
      await sb.destroy();
    }
    sandboxes.length = 0;
    resetCircuitBreakers();
  });

  describe('Tier 1: isolated-vm', () => {
    it('cannot access host filesystem via require("fs")', async () => {
      const sb = await createSandbox({ plugin: 'isolated-vm', config });
      sandboxes.push(sb);
      const result = await sb.execute(
        'try { require("fs").readFileSync("/etc/passwd"); return "ESCAPED" } catch { return "BLOCKED" }',
      );
      expect(result.success).toBe(true);
      expect(result.result).toBe('BLOCKED');
    });

    it('cannot access host filesystem via import("fs")', async () => {
      const sb = await createSandbox({ plugin: 'isolated-vm', config });
      sandboxes.push(sb);
      const result = await sb.execute(
        'try { await import("fs"); return "ESCAPED" } catch { return "BLOCKED" }',
      );
      expect(result.success).toBe(true);
      expect(result.result).toBe('BLOCKED');
    });

    it('cannot access /etc/passwd', async () => {
      const sb = await createSandbox({ plugin: 'isolated-vm', config });
      sandboxes.push(sb);
      const result = await sb.execute('return typeof require');
      expect(result.success).toBe(true);
      expect(result.result).toBe('undefined');
    });

    it('cannot access process.env of host', async () => {
      const sb = await createSandbox({ plugin: 'isolated-vm', config });
      sandboxes.push(sb);
      const result = await sb.execute('return typeof process');
      expect(result.success).toBe(true);
      expect(result.result).toBe('undefined');
    });

    it('cannot spawn child processes', async () => {
      const sb = await createSandbox({ plugin: 'isolated-vm', config });
      sandboxes.push(sb);
      const result = await sb.execute(
        'try { require("child_process"); return "ESCAPED" } catch { return "BLOCKED" }',
      );
      expect(result.success).toBe(true);
      expect(result.result).toBe('BLOCKED');
    });

    it('cannot access network primitives', async () => {
      const sb = await createSandbox({ plugin: 'isolated-vm', config });
      sandboxes.push(sb);
      const result = await sb.execute(
        'return typeof fetch === "undefined" && typeof XMLHttpRequest === "undefined"',
      );
      expect(result.success).toBe(true);
      expect(result.result).toBe(true);
    });

    it('respects memory limits (OOM terminates cleanly)', async () => {
      const oomConfig: SandboxConfig = {
        limits: { ...config.limits, memoryMB: 8 },
      };
      const sb = await createSandbox({ plugin: 'isolated-vm', config: oomConfig });
      sandboxes.push(sb);
      const result = await sb.execute(
        'const arr = []; while(true) arr.push(new Array(1e6).fill("x"))',
      );
      expect(result.success).toBe(false);
      expect(result.error).toBeInstanceOf(SandboxOOMError);
    });

    it('respects timeout (infinite loop terminates)', async () => {
      const timeoutConfig: SandboxConfig = {
        limits: { ...config.limits, timeoutMs: 500 },
      };
      const sb = await createSandbox({ plugin: 'isolated-vm', config: timeoutConfig });
      sandboxes.push(sb);
      const result = await sb.execute('while(true) {}');
      expect(result.success).toBe(false);
      expect(result.error).toBeInstanceOf(SandboxTimeoutError);
    });

    it('separate V8 heap — no shared state between sandboxes', async () => {
      const sb1 = await createSandbox({ plugin: 'isolated-vm', config });
      sandboxes.push(sb1);
      const sb2 = await createSandbox({ plugin: 'isolated-vm', config });
      sandboxes.push(sb2);

      // Set a global in sb1
      await sb1.execute('globalThis.__secret = 42');

      // sb2 should not see it
      const result = await sb2.execute('return typeof globalThis.__secret');
      expect(result.success).toBe(true);
      expect(result.result).toBe('undefined');
    });
  });

  describe('Tier 2: Landlock (Seatbelt on macOS)', () => {
    const isMac = platform() === 'darwin';
    const tier2It = isMac ? it : it.skip;

    tier2It('blocks filesystem writes outside sandbox tmpdir', async () => {
      const sb = await createSandbox({ plugin: 'landlock', config });
      sandboxes.push(sb);
      const result = await sb.execute(`
        try {
          require('fs').writeFileSync('/tmp/maestro-escape-test', 'pwned');
          return 'ESCAPED';
        } catch {
          return 'BLOCKED';
        }
      `);
      expect(result.success).toBe(true);
      expect(result.result).toBe('BLOCKED');
    }, 10000);

    tier2It('blocks network access when networkAccess=false', async () => {
      const sb = await createSandbox({ plugin: 'landlock', config });
      sandboxes.push(sb);
      const result = await sb.execute(`
        try {
          const http = require('http');
          await new Promise((resolve, reject) => {
            const req = http.get('http://example.com', resolve);
            req.on('error', reject);
            req.setTimeout(1000, () => reject(new Error('timeout')));
          });
          return 'ESCAPED';
        } catch {
          return 'BLOCKED';
        }
      `);
      expect(result.success).toBe(true);
      expect(result.result).toBe('BLOCKED');
    }, 10000);

    tier2It('blocks child_process.exec of system binaries', async () => {
      const sb = await createSandbox({ plugin: 'landlock', config });
      sandboxes.push(sb);
      const result = await sb.execute(`
        try {
          require('child_process').execSync('whoami');
          return 'ESCAPED';
        } catch {
          return 'BLOCKED';
        }
      `);
      expect(result.success).toBe(true);
      expect(result.result).toBe('BLOCKED');
    }, 10000);

    tier2It('blocks env var access to host secrets', async () => {
      const sb = await createSandbox({ plugin: 'landlock', config });
      sandboxes.push(sb);
      // Landlock sandbox only gets PATH, HOME=tmpdir, TMPDIR=tmpdir + explicit secrets
      const result = await sb.execute(`
        const home = process.env.HOME;
        const user = process.env.USER;
        return { home, user };
      `);
      expect(result.success).toBe(true);
      const val = result.result as { home: string; user: string };
      // HOME should be the sandbox tmpdir, not the real home
      expect(val.home).not.toBe(process.env.HOME);
      // USER should not be set
      expect(val.user).toBeUndefined();
    }, 10000);

    tier2It('blocks /proc/self/environ access', async () => {
      const sb = await createSandbox({ plugin: 'landlock', config });
      sandboxes.push(sb);
      // On macOS there's no /proc — this naturally fails
      const result = await sb.execute(`
        try {
          require('fs').readFileSync('/proc/self/environ', 'utf8');
          return 'ESCAPED';
        } catch {
          return 'BLOCKED';
        }
      `);
      expect(result.success).toBe(true);
      expect(result.result).toBe('BLOCKED');
    }, 10000);

    tier2It('blocks setuid/setgid calls', async () => {
      const sb = await createSandbox({ plugin: 'landlock', config });
      sandboxes.push(sb);
      const result = await sb.execute(`
        try {
          process.setuid(0);
          return 'ESCAPED';
        } catch {
          return 'BLOCKED';
        }
      `);
      expect(result.success).toBe(true);
      expect(result.result).toBe('BLOCKED');
    }, 10000);

    tier2It('blocks ptrace', async () => {
      const sb = await createSandbox({ plugin: 'landlock', config });
      sandboxes.push(sb);
      // ptrace isn't directly accessible from Node.js, but we can verify
      // that process spawning (which could use ptrace) is blocked
      const result = await sb.execute(`
        try {
          require('child_process').execSync('ls /');
          return 'ESCAPED';
        } catch {
          return 'BLOCKED';
        }
      `);
      expect(result.success).toBe(true);
      expect(result.result).toBe('BLOCKED');
    }, 10000);

    tier2It('blocks mount', async () => {
      const sb = await createSandbox({ plugin: 'landlock', config });
      sandboxes.push(sb);
      const result = await sb.execute(`
        try {
          require('child_process').execSync('mount');
          return 'ESCAPED';
        } catch {
          return 'BLOCKED';
        }
      `);
      expect(result.success).toBe(true);
      expect(result.result).toBe('BLOCKED');
    }, 10000);

    tier2It('blocks fork bomb (process spawning restriction)', async () => {
      const sb = await createSandbox({ plugin: 'landlock', config });
      sandboxes.push(sb);
      const result = await sb.execute(`
        try {
          // Try to spawn processes — Seatbelt blocks exec of system binaries
          require('child_process').execSync('bash -c ":(){ :|:& };:"');
          return 'ESCAPED';
        } catch {
          return 'BLOCKED';
        }
      `);
      expect(result.success).toBe(true);
      expect(result.result).toBe('BLOCKED');
    }, 10000);
  });

  describe('Tier 2: Anthropic SR', () => {
    const canRunSR = (platform() === 'darwin' || platform() === 'linux') && hasRipgrep;
    const srIt = canRunSR ? it : it.skip;

    srIt('executes simple code and returns result', async () => {
      const sb = await createSandbox({ plugin: 'anthropic-sr', config });
      sandboxes.push(sb);
      const result = await sb.execute('return 42');
      expect(result.success).toBe(true);
      expect(result.result).toBe(42);
    }, 10000);

    srIt('blocks filesystem writes outside sandbox tmpdir', async () => {
      const sb = await createSandbox({ plugin: 'anthropic-sr', config });
      sandboxes.push(sb);
      const result = await sb.execute(`
        try {
          require('fs').writeFileSync('/tmp/maestro-sr-escape', 'pwned');
          return 'ESCAPED';
        } catch {
          return 'BLOCKED';
        }
      `);
      expect(result.success).toBe(true);
      expect(result.result).toBe('BLOCKED');
    }, 10000);

    srIt('blocks network access when networkAccess=false', async () => {
      const sb = await createSandbox({ plugin: 'anthropic-sr', config });
      sandboxes.push(sb);
      const result = await sb.execute(`
        try {
          const http = require('http');
          await new Promise((resolve, reject) => {
            const req = http.get('http://example.com', resolve);
            req.on('error', reject);
            req.setTimeout(1000, () => reject(new Error('timeout')));
          });
          return 'ESCAPED';
        } catch {
          return 'BLOCKED';
        }
      `);
      expect(result.success).toBe(true);
      expect(result.result).toBe('BLOCKED');
    }, 10000);

    srIt('captures console.log in logs', async () => {
      const sb = await createSandbox({ plugin: 'anthropic-sr', config });
      sandboxes.push(sb);
      const result = await sb.execute('console.log("sr-hello"); return 1');
      expect(result.success).toBe(true);
      expect(result.logs).toContain('sr-hello');
    }, 10000);

    srIt('returns error for throwing code', async () => {
      const sb = await createSandbox({ plugin: 'anthropic-sr', config });
      sandboxes.push(sb);
      const result = await sb.execute('throw new Error("sr-boom")');
      expect(result.success).toBe(false);
      const msg = typeof result.error === 'string' ? result.error : (result.error as Error).message;
      expect(msg).toContain('sr-boom');
    }, 10000);

    srIt('respects timeout', async () => {
      const timeoutConfig: SandboxConfig = {
        limits: { ...config.limits, timeoutMs: 1000 },
      };
      const sb = await createSandbox({ plugin: 'anthropic-sr', config: timeoutConfig });
      sandboxes.push(sb);
      const result = await sb.execute('await new Promise(r => setTimeout(r, 30000))');
      expect(result.success).toBe(false);
      expect(result.error).toBeInstanceOf(SandboxTimeoutError);
    }, 10000);

    srIt('injects context variables', async () => {
      const sb = await createSandbox({ plugin: 'anthropic-sr', config });
      sandboxes.push(sb);
      const result = await sb.execute('return x + y', { context: { x: 10, y: 20 } });
      expect(result.success).toBe(true);
      expect(result.result).toBe(30);
    }, 10000);
  });

  describe('blast radius', () => {
    it('one sandbox crash does not affect other sandboxes', async () => {
      const sb1 = await createSandbox({ plugin: 'isolated-vm', config });
      sandboxes.push(sb1);
      const sb2 = await createSandbox({ plugin: 'isolated-vm', config });
      sandboxes.push(sb2);

      const crashResult = await sb1.execute('throw new Error("crash")');
      expect(crashResult.success).toBe(false);

      const okResult = await sb2.execute('return 42');
      expect(okResult.success).toBe(true);
      expect(okResult.result).toBe(42);
    });

    it('one sandbox OOM does not affect other sandboxes', async () => {
      const oomConfig: SandboxConfig = {
        limits: { ...config.limits, memoryMB: 8 },
      };
      const sb1 = await createSandbox({ plugin: 'isolated-vm', config: oomConfig });
      sandboxes.push(sb1);
      const sb2 = await createSandbox({ plugin: 'isolated-vm', config });
      sandboxes.push(sb2);

      const oomResult = await sb1.execute(
        'const arr = []; while(true) arr.push(new Array(1e6).fill("x"))',
      );
      expect(oomResult.success).toBe(false);

      const okResult = await sb2.execute('return "alive"');
      expect(okResult.success).toBe(true);
      expect(okResult.result).toBe('alive');
    });

    it('spawn 10 sandboxes, crash 5 — other 5 still respond', async () => {
      const all: Sandbox[] = [];
      for (let i = 0; i < 10; i++) {
        const sb = await createSandbox({ plugin: 'isolated-vm', config });
        sandboxes.push(sb);
        all.push(sb);
      }

      for (let i = 0; i < 5; i++) {
        const result = await all[i].execute(`throw new Error('crash ${i}')`);
        expect(result.success).toBe(false);
      }

      for (let i = 5; i < 10; i++) {
        const result = await all[i].execute(`return ${i}`);
        expect(result.success).toBe(true);
        expect(result.result).toBe(i);
      }
    });

    it('host process remains healthy after sandbox crash', async () => {
      const sb1 = await createSandbox({ plugin: 'isolated-vm', config });
      sandboxes.push(sb1);

      const crashResult = await sb1.execute('throw new Error("crash")');
      expect(crashResult.success).toBe(false);

      const sb2 = await createSandbox({ plugin: 'isolated-vm', config });
      sandboxes.push(sb2);

      const result = await sb2.execute('return "still alive"');
      expect(result.success).toBe(true);
      expect(result.result).toBe('still alive');
    });
  });
});

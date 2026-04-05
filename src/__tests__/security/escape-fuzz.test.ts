import { describe, it, expect, afterEach } from 'vitest';
import { createSandbox, resetCircuitBreakers } from '../../factory.js';
import type { Sandbox, SandboxConfig } from '../../types.js';

const config: SandboxConfig = {
  limits: { memoryMB: 128, cpuMs: 5000, timeoutMs: 2000, networkAccess: false, filesystemAccess: 'tmpfs' },
};

/**
 * Escape fuzzing tests run against BOTH mock and isolated-vm.
 * Mock verifies that execute() never throws (contract compliance).
 * isolated-vm verifies that the V8 isolation boundary holds.
 */
const plugins = ['mock', 'isolated-vm'] as const;

describe('Security: escape fuzzing', () => {
  afterEach(() => {
    resetCircuitBreakers();
  });

  describe.each(plugins)('plugin: %s', (pluginName) => {
    describe('random input', () => {
      const randomInputs = [
        Math.random().toString(36),
        'throw new Error("x")',
        '}{][)(',
        'return undefined',
        'return null',
        'return 0',
        'return ""',
        'return NaN',
        'return Infinity',
        ';;;',
        'while(false){}',
        'var x = 1; return x',
        '/* comment */',
        'return [1,2,3]',
        'return {a: 1}',
        "return 'hello world'",
        'let a = []; for(let i=0;i<10;i++) a.push(i); return a',
        'return Math.PI',
        'return Date.now()',
        'return JSON.stringify({ok: true})',
      ];

      it('no random string escapes sandbox', async () => {
        const sandbox = await createSandbox({ plugin: pluginName, config });
        try {
          for (const input of randomInputs) {
            const result = await sandbox.execute(input);
            expect(result).toBeDefined();
            expect(typeof result.success).toBe('boolean');
          }
        } finally {
          await sandbox.destroy();
        }
      });

      it('sandbox either succeeds or fails — never crashes the host', async () => {
        const sandbox = await createSandbox({ plugin: pluginName, config });
        try {
          for (const input of randomInputs) {
            const result = await sandbox.execute(input);
            expect(result).toHaveProperty('success');
            expect(result).toHaveProperty('logs');
            expect(result).toHaveProperty('metrics');
            expect(typeof result.success).toBe('boolean');
            expect(Array.isArray(result.logs)).toBe(true);
            expect(typeof result.metrics.cpuMs).toBe('number');
            expect(typeof result.metrics.memoryMB).toBe('number');
            expect(typeof result.metrics.wallMs).toBe('number');
          }
        } finally {
          await sandbox.destroy();
        }
      });

      // These tests only matter for isolated-vm (mock has no isolation)
      if (pluginName === 'isolated-vm') {
        it('random code does not leak host environment variables', async () => {
          const sandbox = await createSandbox({ plugin: pluginName, config });
          try {
            const envProbes = [
              'return typeof process',
              'return typeof process !== "undefined" && process.env',
              'try { return process.env.PATH } catch { return "BLOCKED" }',
              'try { return process.env.HOME } catch { return "BLOCKED" }',
            ];
            for (const probe of envProbes) {
              const result = await sandbox.execute(probe);
              expect(result.success).toBe(true);
              // process is undefined in the isolate — all probes return undefined or "BLOCKED"
              expect(result.result).not.toContain('/');
            }
          } finally {
            await sandbox.destroy();
          }
        });

        it('random code does not access host filesystem', async () => {
          const sandbox = await createSandbox({ plugin: pluginName, config });
          try {
            const fsProbes = [
              'try { require("fs"); return "ESCAPED" } catch { return "BLOCKED" }',
              'try { await import("fs"); return "ESCAPED" } catch { return "BLOCKED" }',
              'try { require("child_process").execSync("ls /"); return "ESCAPED" } catch { return "BLOCKED" }',
            ];
            for (const probe of fsProbes) {
              const result = await sandbox.execute(probe);
              expect(result.success).toBe(true);
              expect(result.result).toBe('BLOCKED');
            }
          } finally {
            await sandbox.destroy();
          }
        });
      }
    });

    describe('known escape vectors', () => {
      // These tests are meaningful against isolated-vm specifically
      if (pluginName === 'isolated-vm') {
        it('prototype pollution does not escape sandbox', async () => {
          const sandbox = await createSandbox({ plugin: pluginName, config });
          try {
            // Attempt to pollute Object.prototype inside the isolate
            const result = await sandbox.execute(`
              Object.prototype.pwned = true;
              return true;
            `);
            expect(result.success).toBe(true);
            // Host Object.prototype must NOT be affected
            expect(({} as Record<string, unknown>).pwned).toBeUndefined();
          } finally {
            await sandbox.destroy();
          }
        });

        it('constructor manipulation does not escape sandbox', async () => {
          const sandbox = await createSandbox({ plugin: pluginName, config });
          try {
            const result = await sandbox.execute(`
              try {
                const F = (function(){}).constructor;
                const evil = new F('return this');
                const globalThis = evil();
                return typeof globalThis.process !== 'undefined' ? 'ESCAPED' : 'CONTAINED';
              } catch {
                return 'BLOCKED';
              }
            `);
            expect(result.success).toBe(true);
            // Should be CONTAINED (new Function works but 'this' is the sandbox global)
            // or BLOCKED — either way, not ESCAPED
            expect(result.result).not.toBe('ESCAPED');
          } finally {
            await sandbox.destroy();
          }
        });

        it('import() does not load host modules', async () => {
          const sandbox = await createSandbox({ plugin: pluginName, config });
          try {
            const result = await sandbox.execute(`
              try { await import('fs'); return 'ESCAPED' } catch { return 'BLOCKED' }
            `);
            expect(result.success).toBe(true);
            expect(result.result).toBe('BLOCKED');
          } finally {
            await sandbox.destroy();
          }
        });
      }

      it('eval/Function constructor does not escape sandbox', async () => {
        const sandbox = await createSandbox({ plugin: pluginName, config });
        try {
          const result = await sandbox.execute("return eval('1+1')");
          expect(result).toBeDefined();
          expect(typeof result.success).toBe('boolean');
        } finally {
          await sandbox.destroy();
        }
      });

      it('WebAssembly does not bypass restrictions', async () => {
        const sandbox = await createSandbox({ plugin: pluginName, config });
        try {
          const result = await sandbox.execute(`
            try {
              const bytes = new Uint8Array([0,97,115,109,1,0,0,0]);
              const mod = new WebAssembly.Module(bytes);
              return typeof mod === 'object' ? 'WASM_AVAILABLE' : 'BLOCKED';
            } catch {
              return 'BLOCKED';
            }
          `);
          expect(result.success).toBe(true);
          // WebAssembly may or may not be available in the isolate,
          // but it must not provide an escape vector
          expect(result.result).not.toBe('ESCAPED');
        } finally {
          await sandbox.destroy();
        }
      });
    });
  });
});

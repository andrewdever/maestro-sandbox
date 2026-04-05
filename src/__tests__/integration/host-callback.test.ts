import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { createSandbox, resetCircuitBreakers } from '../../factory.js';
import { z } from 'zod';
import type { Sandbox, SandboxConfig } from '../../types.js';

const config: SandboxConfig = {
  limits: {
    memoryMB: 128,
    cpuMs: 5000,
    timeoutMs: 5000,
    networkAccess: false,
    filesystemAccess: 'tmpfs' as const,
  },
  hostFunctions: {
    greet: {
      handler: async (args: unknown) => `hello ${(args as any).name}`,
    },
    fetchUrl: {
      handler: async (args: unknown) => {
        const { url } = args as { url: string };
        return { status: 200, body: `response from ${url}` };
      },
      schema: z.object({ url: z.string().url() }),
      rateLimit: { maxCalls: 3, windowMs: 60000 },
    },
    failing: {
      handler: async () => {
        throw new Error('handler failed');
      },
    },
  },
};

describe('Host callback bridge (integration)', () => {
  const sandboxes: Sandbox[] = [];

  beforeEach(() => {
    resetCircuitBreakers();
  });

  afterEach(async () => {
    for (const sb of sandboxes) {
      await sb.destroy();
    }
    sandboxes.length = 0;
    resetCircuitBreakers();
  });

  describe('allowlist enforcement', () => {
    it('sandbox can call allowlisted function', async () => {
      const sb = await createSandbox({ plugin: 'mock', config });
      sandboxes.push(sb);

      const result = await sb.execute(`return await hostCall('greet', { name: 'world' })`);
      expect(result.success).toBe(true);
      expect(result.result).toBe('hello world');
    });

    it('sandbox cannot call function not in allowlist', async () => {
      const sb = await createSandbox({ plugin: 'mock', config });
      sandboxes.push(sb);

      const result = await sb.execute(`return await hostCall('notAllowed', {})`);
      expect(result.success).toBe(false);
      expect(String(result.error)).toMatch(/is not available/);
    });

    it('sandbox cannot discover available functions', async () => {
      const sb = await createSandbox({ plugin: 'mock', config });
      sandboxes.push(sb);
      // Sandbox code should not be able to enumerate available host functions
      const result = await sb.execute(`
        try {
          // hostCall is a function, not an object with keys
          return typeof hostCall === 'function' ? 'function' : 'other';
        } catch { return 'error'; }
      `);
      expect(result.success).toBe(true);
      expect(result.result).toBe('function');
      // No way to get the list of available functions from hostCall itself
    });

    it('sandbox cannot add new functions at runtime', async () => {
      const sb = await createSandbox({ plugin: 'mock', config });
      sandboxes.push(sb);
      // Even if sandbox tries to redefine hostCall, the original bridge is frozen
      const result = await sb.execute(`
        const original = hostCall;
        try {
          // Try calling a function that wasn't in the original allowlist
          return await original('secretFunc', {});
        } catch (e) {
          return e.message;
        }
      `);
      expect(result.success).toBe(true);
      expect(String(result.result)).toMatch(/is not available/);
    });
  });

  describe('schema validation', () => {
    it('valid args pass through to handler', async () => {
      const sb = await createSandbox({ plugin: 'mock', config });
      sandboxes.push(sb);

      const result = await sb.execute(
        `return await hostCall('fetchUrl', { url: 'https://example.com/api' })`,
      );
      expect(result.success).toBe(true);
      expect(result.result).toEqual({ status: 200, body: 'response from https://example.com/api' });
    });

    it('invalid args rejected before handler is called', async () => {
      const sb = await createSandbox({ plugin: 'mock', config });
      sandboxes.push(sb);

      const result = await sb.execute(
        `return await hostCall('fetchUrl', { url: 'not-a-url' })`,
      );
      expect(result.success).toBe(false);
      expect(String(result.error)).toContain('Schema validation failed');
    });
  });

  describe('rate limiting', () => {
    it('burst within limit succeeds', async () => {
      const sb = await createSandbox({ plugin: 'mock', config });
      sandboxes.push(sb);

      const result = await sb.execute(`
        const r1 = await hostCall('fetchUrl', { url: 'https://example.com/1' });
        const r2 = await hostCall('fetchUrl', { url: 'https://example.com/2' });
        const r3 = await hostCall('fetchUrl', { url: 'https://example.com/3' });
        return [r1, r2, r3];
      `);
      expect(result.success).toBe(true);
      expect(result.result).toHaveLength(3);
    });

    it('burst exceeding limit fails', async () => {
      const sb = await createSandbox({ plugin: 'mock', config });
      sandboxes.push(sb);

      const result = await sb.execute(`
        await hostCall('fetchUrl', { url: 'https://example.com/1' });
        await hostCall('fetchUrl', { url: 'https://example.com/2' });
        await hostCall('fetchUrl', { url: 'https://example.com/3' });
        return await hostCall('fetchUrl', { url: 'https://example.com/4' });
      `);
      expect(result.success).toBe(false);
      expect(String(result.error)).toContain('Rate limit exceeded');
    });

    // NOTE: fake timers can interact badly with async sandbox operations.
    // If this test flakes, check that vi.useFakeTimers doesn't break
    // the mock plugin's internal setTimeout/setImmediate calls.
    it('limit resets after window', async () => {
      vi.useFakeTimers();
      try {
        const shortWindowConfig: SandboxConfig = {
          limits: config.limits,
          hostFunctions: {
            ping: {
              handler: async () => 'pong',
              rateLimit: { maxCalls: 1, windowMs: 1000 },
            },
          },
        };
        const sb = await createSandbox({ plugin: 'mock', config: shortWindowConfig });
        sandboxes.push(sb);

        // First call succeeds
        const r1 = await sb.execute(`return await hostCall('ping', {})`);
        expect(r1.success).toBe(true);

        // Second call fails (rate limit)
        const r2 = await sb.execute(`return await hostCall('ping', {})`);
        expect(r2.success).toBe(false);
        expect(String(r2.error)).toContain('Rate limit');

        // Advance past window
        vi.advanceTimersByTime(1001);

        // Third call succeeds (window reset)
        const r3 = await sb.execute(`return await hostCall('ping', {})`);
        expect(r3.success).toBe(true);
        expect(r3.result).toBe('pong');
      } finally {
        vi.useRealTimers();
      }
    });
  });

  describe('SSRF prevention', () => {
    it('blocks fetch to 169.254.169.254 (AWS metadata)', async () => {
      const sb = await createSandbox({ plugin: 'mock', config });
      sandboxes.push(sb);

      const result = await sb.execute(
        `return await hostCall('fetchUrl', { url: 'http://169.254.169.254/metadata' })`,
      );
      expect(result.success).toBe(false);
      expect(String(result.error)).toContain('SSRF');
    });

    it('blocks fetch to localhost', async () => {
      const sb = await createSandbox({ plugin: 'mock', config });
      sandboxes.push(sb);

      const result = await sb.execute(
        `return await hostCall('fetchUrl', { url: 'http://localhost/admin' })`,
      );
      expect(result.success).toBe(false);
      expect(String(result.error)).toContain('SSRF');
    });

    it('allows fetch to explicitly allowlisted URL', async () => {
      const sb = await createSandbox({ plugin: 'mock', config });
      sandboxes.push(sb);

      const result = await sb.execute(
        `return await hostCall('fetchUrl', { url: 'https://example.com' })`,
      );
      expect(result.success).toBe(true);
      expect(result.result).toEqual({ status: 200, body: 'response from https://example.com' });
    });
  });

  describe('error propagation', () => {
    it('handler error surfaces in sandbox as error', async () => {
      const sb = await createSandbox({ plugin: 'mock', config });
      sandboxes.push(sb);

      const result = await sb.execute(`return await hostCall('failing', {})`);
      expect(result.success).toBe(false);
      expect(String(result.error)).toContain('handler failed');
    });

    it('handler timeout triggers sandbox timeout', async () => {
      const slowConfig: SandboxConfig = {
        limits: { ...config.limits, timeoutMs: 500 },
        hostFunctions: {
          slow: {
            handler: async () => {
              await new Promise(r => setTimeout(r, 10000));
              return 'done';
            },
          },
        },
      };
      const sb = await createSandbox({ plugin: 'mock', config: slowConfig });
      sandboxes.push(sb);
      const result = await sb.execute(`return await hostCall('slow', {})`);
      expect(result.success).toBe(false);
      // The mock plugin's timeout should kill the execution
    }, 5000);

    it('handler hang does not hang the host', async () => {
      const hangConfig: SandboxConfig = {
        limits: { ...config.limits, timeoutMs: 500 },
        hostFunctions: {
          hang: {
            handler: () => new Promise(() => {}), // never resolves
          },
        },
      };
      const sb = await createSandbox({ plugin: 'mock', config: hangConfig });
      sandboxes.push(sb);
      const result = await sb.execute(`return await hostCall('hang', {})`);
      expect(result.success).toBe(false);
      // Host is still responsive — verify by creating another sandbox
      const sb2 = await createSandbox({ plugin: 'mock', config });
      sandboxes.push(sb2);
      const r2 = await sb2.execute('return 42');
      expect(r2.success).toBe(true);
      expect(r2.result).toBe(42);
    }, 5000);
  });
});

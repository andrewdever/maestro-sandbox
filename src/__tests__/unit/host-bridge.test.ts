import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { z } from 'zod';
import { createHostBridge } from '../../host-bridge.js';
import type { HostBridgeDefenseOptions } from '../../host-bridge.js';

describe('HostBridge', () => {
  describe('creation', () => {
    it('creates a frozen bridge from an allowlist', () => {
      const bridge = createHostBridge({
        greet: async () => 'hello',
      });
      expect(Object.isFrozen(bridge)).toBe(true);
    });

    it('freezes the bridge — no functions can be added after creation', () => {
      const bridge = createHostBridge({
        greet: async () => 'hello',
      });
      expect(() => {
        (bridge as any).newProp = 'nope';
      }).toThrow();
    });

    it('lists available function names', () => {
      const bridge = createHostBridge({
        alpha: async () => 'a',
        beta: async () => 'b',
      });
      expect(bridge.availableFunctions).toEqual(['alpha', 'beta']);
      expect(Object.isFrozen(bridge.availableFunctions)).toBe(true);
    });

    it('throws if allowlist is empty', () => {
      expect(() => createHostBridge({})).toThrow('Host function allowlist must not be empty');
    });
  });

  describe('call', () => {
    it('calls the handler with provided args', async () => {
      const handler = vi.fn(async (args) => args);
      const bridge = createHostBridge({ echo: handler });
      await bridge.call('echo', { msg: 'hi' });
      expect(handler).toHaveBeenCalledWith({ msg: 'hi' });
    });

    it('returns the handler result', async () => {
      const bridge = createHostBridge({
        double: async (args) => (args as number) * 2,
      });
      const result = await bridge.call('double', 5);
      expect(result).toBe(10);
    });

    it('throws if function name is not in allowlist', async () => {
      const bridge = createHostBridge({
        greet: async () => 'hello',
      });
      try {
        await bridge.call('missing', {});
        expect.unreachable('should have thrown');
      } catch (e) {
        expect((e as Error).message).toContain('is not available');
        // Must NOT leak the allowlist (§3)
        expect((e as Error).message).not.toContain('greet');
      }
    });

    it('throws if function name is empty string', async () => {
      const bridge = createHostBridge({
        greet: async () => 'hello',
      });
      await expect(bridge.call('', {})).rejects.toThrow('must not be empty');
    });
  });

  describe('schema validation', () => {
    it('validates args against Zod schema before calling handler', async () => {
      const handler = vi.fn(async (args) => args);
      const bridge = createHostBridge({
        fetch: {
          handler,
          schema: z.object({ url: z.string().url() }),
        },
      });
      await bridge.call('fetch', { url: 'https://example.com' });
      expect(handler).toHaveBeenCalledWith({ url: 'https://example.com' });
    });

    it('rejects args that fail schema validation', async () => {
      const bridge = createHostBridge({
        fetch: {
          handler: async () => null,
          schema: z.object({ url: z.string().url() }),
        },
      });
      await expect(bridge.call('fetch', { url: 'not-a-url' })).rejects.toThrow('Schema validation failed');
    });

    it('passes args through if no schema is defined', async () => {
      const handler = vi.fn(async (args) => args);
      const bridge = createHostBridge({ echo: handler });
      await bridge.call('echo', { anything: true });
      expect(handler).toHaveBeenCalledWith({ anything: true });
    });

    it('provides descriptive error message on validation failure', async () => {
      const bridge = createHostBridge({
        create: {
          handler: async () => null,
          schema: z.object({ name: z.string(), age: z.number() }),
        },
      });
      await expect(bridge.call('create', { name: 123, age: 'old' })).rejects.toThrow(/Schema validation failed for "create"/);
    });
  });

  describe('rate limiting', () => {
    beforeEach(() => {
      vi.useFakeTimers();
    });

    it('allows calls within rate limit', async () => {
      const bridge = createHostBridge({
        ping: {
          handler: async () => 'pong',
          rateLimit: { maxCalls: 3, windowMs: 1000 },
        },
      });
      await expect(bridge.call('ping', null)).resolves.toBe('pong');
      await expect(bridge.call('ping', null)).resolves.toBe('pong');
      await expect(bridge.call('ping', null)).resolves.toBe('pong');
    });

    it('rejects calls that exceed rate limit', async () => {
      const bridge = createHostBridge({
        ping: {
          handler: async () => 'pong',
          rateLimit: { maxCalls: 2, windowMs: 1000 },
        },
      });
      await bridge.call('ping', null);
      await bridge.call('ping', null);
      await expect(bridge.call('ping', null)).rejects.toThrow('Rate limit exceeded');
    });

    it('resets rate limit after window expires', async () => {
      const bridge = createHostBridge({
        ping: {
          handler: async () => 'pong',
          rateLimit: { maxCalls: 1, windowMs: 1000 },
        },
      });
      await bridge.call('ping', null);
      await expect(bridge.call('ping', null)).rejects.toThrow('Rate limit exceeded');

      vi.advanceTimersByTime(1001);

      await expect(bridge.call('ping', null)).resolves.toBe('pong');
    });

    it('tracks rate limits per function independently', async () => {
      const bridge = createHostBridge({
        alpha: {
          handler: async () => 'a',
          rateLimit: { maxCalls: 1, windowMs: 1000 },
        },
        beta: {
          handler: async () => 'b',
          rateLimit: { maxCalls: 1, windowMs: 1000 },
        },
      });
      await bridge.call('alpha', null);
      await expect(bridge.call('alpha', null)).rejects.toThrow('Rate limit exceeded');
      // beta should still be fine
      await expect(bridge.call('beta', null)).resolves.toBe('b');
    });

    it('allows unlimited calls if no rate limit is defined', async () => {
      const bridge = createHostBridge({
        ping: async () => 'pong',
      });
      for (let i = 0; i < 100; i++) {
        await expect(bridge.call('ping', null)).resolves.toBe('pong');
      }
    });

    afterEach(() => {
      vi.useRealTimers();
    });
  });

  describe('SSRF prevention', () => {
    const makeTrackedBridge = () => {
      const handler = vi.fn(async (args: unknown) => args);
      const bridge = createHostBridge({ fetch: { handler } });
      return { bridge, handler };
    };

    it('blocks calls to 169.254.x.x metadata endpoints', async () => {
      const { bridge, handler } = makeTrackedBridge();
      await expect(
        bridge.call('fetch', { url: 'http://169.254.169.254/metadata' }),
      ).rejects.toThrow('SSRF blocked');
      expect(handler).not.toHaveBeenCalled();
    });

    it('blocks calls to localhost/127.0.0.1', async () => {
      const { bridge, handler } = makeTrackedBridge();
      await expect(
        bridge.call('fetch', { url: 'http://127.0.0.1:8080/secret' }),
      ).rejects.toThrow('SSRF blocked');
      await expect(
        bridge.call('fetch', { url: 'http://localhost/admin' }),
      ).rejects.toThrow('SSRF blocked');
      expect(handler).not.toHaveBeenCalled();
    });

    it('blocks calls to internal network ranges (10.x, 172.16-31.x, 192.168.x)', async () => {
      const { bridge, handler } = makeTrackedBridge();
      await expect(
        bridge.call('fetch', { url: 'http://10.0.0.1/api' }),
      ).rejects.toThrow('SSRF blocked');
      await expect(
        bridge.call('fetch', { url: 'http://172.16.0.1/api' }),
      ).rejects.toThrow('SSRF blocked');
      await expect(
        bridge.call('fetch', { url: 'http://192.168.1.1/api' }),
      ).rejects.toThrow('SSRF blocked');
      expect(handler).not.toHaveBeenCalled();
    });

    it('allows calls to explicitly allowlisted external hosts', async () => {
      // The SSRF prevention blocks internal IPs but allows external ones.
      // The bridge doesn't have an "allowlist of internal hosts" feature —
      // it just blocks known internal ranges and passes external URLs through.
      const handler = vi.fn(async (args: unknown) => args);
      const bridge = createHostBridge({ fetch: { handler } });
      await bridge.call('fetch', { url: 'https://api.example.com/data' });
      expect(handler).toHaveBeenCalledWith({ url: 'https://api.example.com/data' });
    });
  });

  describe('error handling', () => {
    it('propagates handler errors to the sandbox', async () => {
      const bridge = createHostBridge({
        fail: async () => {
          throw new Error('handler boom');
        },
      });
      await expect(bridge.call('fail', null)).rejects.toThrow('handler boom');
    });

    it('does not crash the host when handler throws', async () => {
      const bridge = createHostBridge({
        fail: async () => {
          throw new Error('handler boom');
        },
        ok: async () => 'fine',
      });
      await expect(bridge.call('fail', null)).rejects.toThrow();
      // bridge still works after error
      await expect(bridge.call('ok', null)).resolves.toBe('fine');
    });

    it('slow handler completes within timeout', async () => {
      const bridge = createHostBridge({
        slow: async () => {
          await new Promise(resolve => setTimeout(resolve, 50));
          return 'done';
        },
      });
      const result = await bridge.call('slow', null);
      expect(result).toBe('done');
    });
  });

  describe('timeout enforcement (§3)', () => {
    it('times out a handler that exceeds the default timeout', async () => {
      const bridge = createHostBridge({
        hang: {
          handler: async () => new Promise(resolve => setTimeout(resolve, 60_000)),
          timeoutMs: 50, // override to 50ms for fast test
        },
      });
      await expect(bridge.call('hang', null)).rejects.toThrow(/timed out after 50ms/);
    });

    it('does not time out a fast handler', async () => {
      const bridge = createHostBridge({
        fast: {
          handler: async () => 'quick',
          timeoutMs: 5000,
        },
      });
      await expect(bridge.call('fast', null)).resolves.toBe('quick');
    });
  });

  describe('return value size cap (§3)', () => {
    it('rejects return values exceeding 1MB', async () => {
      const bridge = createHostBridge({
        big: async () => 'x'.repeat(2_000_000), // ~2MB as JSON
      });
      await expect(bridge.call('big', null)).rejects.toThrow(/exceeds size cap/);
    });

    it('allows return values under 1MB', async () => {
      const bridge = createHostBridge({
        small: async () => 'x'.repeat(100),
      });
      await expect(bridge.call('small', null)).resolves.toBe('x'.repeat(100));
    });
  });

  describe('spotlighting non-string returns (§14.6 P2)', () => {
    const defenseOptions: HostBridgeDefenseOptions = {
      spotlightConfig: { strategy: 'delimiter' },
      sandboxId: 'sbx_spot_test',
    };

    it('spotlights string returns', async () => {
      const bridge = createHostBridge(
        { getString: async () => 'hello' },
        defenseOptions,
      );
      const result = await bridge.call('getString', null);
      expect(typeof result).toBe('string');
      expect(result).toContain('hello');
      expect(result).toContain('MAESTRO_BOUNDARY');
    });

    it('spotlights object returns via JSON.stringify', async () => {
      const bridge = createHostBridge(
        { getObj: async () => ({ key: 'value', num: 42 }) },
        defenseOptions,
      );
      const result = await bridge.call('getObj', null);
      expect(typeof result).toBe('string');
      expect(result).toContain('"key":"value"');
      expect(result).toContain('MAESTRO_BOUNDARY');
    });

    it('spotlights array returns via JSON.stringify', async () => {
      const bridge = createHostBridge(
        { getArr: async () => [1, 2, 3] },
        defenseOptions,
      );
      const result = await bridge.call('getArr', null);
      expect(typeof result).toBe('string');
      expect(result).toContain('[1,2,3]');
      expect(result).toContain('MAESTRO_BOUNDARY');
    });

    it('passes through null without spotlighting', async () => {
      const bridge = createHostBridge(
        { getNull: async () => null },
        defenseOptions,
      );
      const result = await bridge.call('getNull', null);
      expect(result).toBeNull();
    });

    it('passes through undefined without spotlighting', async () => {
      const bridge = createHostBridge(
        { getUndef: async () => undefined },
        defenseOptions,
      );
      const result = await bridge.call('getUndef', null);
      expect(result).toBeUndefined();
    });

    it('spotlights number returns', async () => {
      const bridge = createHostBridge(
        { getNum: async () => 42 },
        defenseOptions,
      );
      const result = await bridge.call('getNum', null);
      expect(typeof result).toBe('string');
      expect(result).toContain('42');
      expect(result).toContain('MAESTRO_BOUNDARY');
    });
  });
});

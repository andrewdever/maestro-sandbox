import { describe, it, expect, vi } from 'vitest';
import { createSafeHandler } from '../../safe-handler.js';

describe('createSafeHandler', () => {
  it('returns a HostFunctionDef with wrapped handler', () => {
    const def = createSafeHandler('fetch', {
      allowedUrls: ['api.example.com'],
      handler: async () => 'ok',
    });
    expect(typeof def.handler).toBe('function');
  });

  it('allows calls with URLs in the allowlist', async () => {
    const def = createSafeHandler('fetch', {
      allowedUrls: ['api.example.com'],
      handler: async (args) => `fetched ${args}`,
    });
    const result = await def.handler('https://api.example.com/data');
    expect(result).toBe('fetched https://api.example.com/data');
  });

  it('rejects calls with URLs not in the allowlist', async () => {
    const def = createSafeHandler('fetch', {
      allowedUrls: ['api.example.com'],
      handler: async () => 'ok',
    });
    await expect(def.handler('https://evil.com/steal')).rejects.toThrow(
      'URL not in allowlist',
    );
  });

  it('allows non-URL string arguments', async () => {
    const def = createSafeHandler('process', {
      allowedUrls: ['api.example.com'],
      handler: async (args) => args,
    });
    const result = await def.handler('just a plain string');
    expect(result).toBe('just a plain string');
  });

  it('deep-scans nested objects for URLs', async () => {
    const def = createSafeHandler('fetch', {
      allowedUrls: ['api.example.com'],
      handler: async () => 'ok',
    });
    await expect(
      def.handler({ nested: { url: 'https://evil.com/data' } }),
    ).rejects.toThrow('URL not in allowlist');
  });

  it('passes through schema, rateLimit, and timeoutMs', () => {
    const mockSchema = { safeParse: () => ({ success: true }) } as any;
    const def = createSafeHandler('fetch', {
      allowedUrls: ['api.example.com'],
      handler: async () => 'ok',
      schema: mockSchema,
      rateLimit: { maxCalls: 10, windowMs: 60000 },
      timeoutMs: 5000,
    });
    expect(def.schema).toBe(mockSchema);
    expect(def.rateLimit).toEqual({ maxCalls: 10, windowMs: 60000 });
    expect(def.timeoutMs).toBe(5000);
  });

  it('calls the underlying handler when URL is allowed', async () => {
    const handler = vi.fn(async () => 'result');
    const def = createSafeHandler('fetch', {
      allowedUrls: ['api.example.com'],
      handler,
    });
    await def.handler({ url: 'https://api.example.com/v1', method: 'GET' });
    expect(handler).toHaveBeenCalledOnce();
  });

  it('does not call handler when URL is blocked', async () => {
    const handler = vi.fn(async () => 'result');
    const def = createSafeHandler('fetch', {
      allowedUrls: ['api.example.com'],
      handler,
    });
    await expect(
      def.handler({ url: 'https://evil.com/v1' }),
    ).rejects.toThrow();
    expect(handler).not.toHaveBeenCalled();
  });
});

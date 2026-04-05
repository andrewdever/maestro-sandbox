/**
 * createSafeHandler (§3).
 *
 * Wraps a host function handler with URL allowlisting on top of
 * the bridge's baseline protections (SSRF, timeout, size cap).
 */

import type { HostFunctionDef } from './types.js';
import type { ZodSchema } from 'zod';

export interface SafeHandlerOptions {
  /** Allowed URL hosts (e.g. ['api.openai.com', 'api.anthropic.com']). */
  allowedUrls: string[];
  /** The actual handler function. */
  handler: (args: unknown) => Promise<unknown>;
  /** Zod schema for argument validation. */
  schema?: ZodSchema;
  /** Rate limit. */
  rateLimit?: { maxCalls: number; windowMs: number };
  /** Timeout in ms. Default: 30000. */
  timeoutMs?: number;
}

/**
 * Check if a URL string's host is in the allowlist.
 */
function isAllowedUrl(urlStr: string, allowedHosts: string[]): boolean {
  try {
    const url = new URL(urlStr);
    return allowedHosts.some(host =>
      url.hostname === host || url.host === host,
    );
  } catch {
    return false;
  }
}

/**
 * Deep-scan args for URL strings and verify all are in the allowlist.
 * Returns the first disallowed URL found, or null if all are allowed.
 */
function findDisallowedUrl(args: unknown, allowedHosts: string[]): string | null {
  if (typeof args === 'string') {
    if (/^https?:\/\//i.test(args) && !isAllowedUrl(args, allowedHosts)) {
      return args;
    }
    return null;
  }
  if (args !== null && typeof args === 'object') {
    for (const val of Object.values(args as Record<string, unknown>)) {
      const found = findDisallowedUrl(val, allowedHosts);
      if (found) return found;
    }
  }
  return null;
}

/**
 * Create a safe host function definition with URL allowlisting.
 *
 * The returned HostFunctionDef wraps the handler to reject any URL
 * argument not in the allowlist, on top of the bridge's baseline
 * SSRF checks.
 *
 * @example
 * ```typescript
 * const safeFetch = createSafeHandler('fetch', {
 *   allowedUrls: ['api.openai.com', 'api.anthropic.com'],
 *   handler: async ({ url, method }) => {
 *     const res = await fetch(url, { method });
 *     return { status: res.status, body: await res.text() };
 *   },
 *   schema: z.object({ url: z.string().url(), method: z.enum(['GET', 'POST']) }),
 * });
 * ```
 */
export function createSafeHandler(
  _name: string,
  options: SafeHandlerOptions,
): HostFunctionDef {
  const { allowedUrls, handler, schema, rateLimit, timeoutMs } = options;

  const wrappedHandler = async (args: unknown): Promise<unknown> => {
    // URL allowlist enforcement (on top of bridge SSRF checks)
    const disallowed = findDisallowedUrl(args, allowedUrls);
    if (disallowed) {
      throw new Error(
        `URL not in allowlist: ${new URL(disallowed).hostname}. ` +
        `Allowed: ${allowedUrls.join(', ')}`,
      );
    }

    return handler(args);
  };

  return {
    handler: wrappedHandler,
    ...(schema ? { schema } : {}),
    ...(rateLimit ? { rateLimit } : {}),
    ...(timeoutMs !== undefined ? { timeoutMs } : {}),
  };
}

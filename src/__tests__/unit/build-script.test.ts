import { describe, it, expect } from 'vitest';
import {
  buildScript,
  parseScriptOutput,
  parseExecError,
  confinePath,
  shellEscape,
} from '../../build-script.js';

// ---------------------------------------------------------------------------
// buildScript
// ---------------------------------------------------------------------------
describe('buildScript', () => {
  it('returns a string containing the user code', () => {
    const script = buildScript('return 1 + 1', undefined);
    expect(script).toContain('return 1 + 1');
  });

  it('wraps code in an async IIFE', () => {
    const script = buildScript('return 42', undefined);
    expect(script).toContain('(async () => {');
    expect(script).toContain('await (async () => { return 42 })()');
  });

  it('includes console override for log, error, warn', () => {
    const script = buildScript('return 1', undefined);
    expect(script).toContain('const console = {');
    expect(script).toContain('log:');
    expect(script).toContain('error:');
    expect(script).toContain('warn:');
  });

  it('includes hostCall stub that throws', () => {
    const script = buildScript('return 1', undefined);
    expect(script).toContain('async function hostCall');
    expect(script).toContain('throw new Error');
  });

  it('injects context variables as const declarations', () => {
    const script = buildScript('return x + y', { context: { x: 1, y: 2 } });
    expect(script).toContain('const x = 1;');
    expect(script).toContain('const y = 2;');
  });

  it('context key with value 42 produces const x = 42;', () => {
    const script = buildScript('return x', { context: { x: 42 } });
    expect(script).toContain('const x = 42;');
  });

  it('context key with string value produces const key = "value";', () => {
    const script = buildScript('return key', { context: { key: 'value' } });
    expect(script).toContain('const key = "value";');
  });

  it('empty context produces no declarations', () => {
    const script = buildScript('return 1', { context: {} });
    // No "const " lines between hostCall and the IIFE aside from __logs / console
    const lines = script.split('\n');
    const contextArea = lines.filter(
      (l) =>
        l.startsWith('const ') &&
        !l.startsWith('const __logs') &&
        !l.startsWith('const console') &&
        !l.startsWith('const __result'),
    );
    expect(contextArea).toHaveLength(0);
  });

  it('undefined options treated as empty context', () => {
    // Should not throw
    const script = buildScript('return 1', undefined);
    expect(typeof script).toBe('string');
  });

  it('rejects context key with spaces', () => {
    expect(() => buildScript('return 1', { context: { 'my var': 1 } })).toThrow(
      /Invalid context key/,
    );
  });

  it('rejects context key starting with number', () => {
    expect(() => buildScript('return 1', { context: { '1x': 1 } })).toThrow(
      /Invalid context key/,
    );
  });

  it('rejects context key with injection attempt', () => {
    expect(() =>
      buildScript('return 1', { context: { 'x=1;evil();//': 1 } }),
    ).toThrow(/Invalid context key/);
  });

  it('allows valid JS identifiers', () => {
    const identifiers = ['_foo', '$bar', 'camelCase', 'myVar123'];
    for (const id of identifiers) {
      expect(() =>
        buildScript('return 1', { context: { [id]: 'ok' } }),
      ).not.toThrow();
    }
  });

  it('rejects dangerous prototype-pollution keys', () => {
    const dangerous = ['__proto__', '__proto', 'constructor', 'prototype'];
    for (const key of dangerous) {
      expect(() =>
        buildScript('return 1', { context: { [key]: 'ok' } }),
      ).toThrow(/Dangerous context key/);
    }
  });
});

// ---------------------------------------------------------------------------
// parseScriptOutput
// ---------------------------------------------------------------------------
describe('parseScriptOutput', () => {
  it('parses valid result', () => {
    const out = parseScriptOutput(JSON.stringify({ __result: 42, __logs: [] }));
    expect(out).toEqual({ result: 42, logs: [] });
  });

  it('parses error output', () => {
    const out = parseScriptOutput(
      JSON.stringify({ __error: 'boom', __logs: ['log1'] }),
    );
    expect(out).toEqual({ error: 'boom', logs: ['log1'] });
  });

  it('returns null for empty string', () => {
    expect(parseScriptOutput('')).toBeNull();
  });

  it('returns null for whitespace-only string', () => {
    expect(parseScriptOutput('   \n\t  ')).toBeNull();
  });

  it('returns null for non-JSON string', () => {
    expect(parseScriptOutput('not json at all')).toBeNull();
  });

  it('returns null for non-object JSON string', () => {
    expect(parseScriptOutput('"hello"')).toBeNull();
  });

  it('returns null for non-object JSON number', () => {
    expect(parseScriptOutput('42')).toBeNull();
  });

  it('returns null for JSON null', () => {
    expect(parseScriptOutput('null')).toBeNull();
  });

  it('handles missing __logs (defaults to [])', () => {
    const out = parseScriptOutput(JSON.stringify({ __result: 'ok' }));
    expect(out).toEqual({ result: 'ok', logs: [] });
  });

  it('handles __result: undefined correctly', () => {
    // JSON.stringify drops undefined values, so __result won't be in the JSON
    const out = parseScriptOutput(JSON.stringify({ __result: undefined, __logs: [] }));
    expect(out).not.toBeNull();
    expect(out!.logs).toEqual([]);
    // result will be undefined since the key is missing from the parsed JSON
    expect(out!.result).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// parseExecError
// ---------------------------------------------------------------------------
describe('parseExecError', () => {
  it('extracts structured output from error with stdout property', () => {
    const err = {
      stdout: JSON.stringify({ __error: 'fail', __logs: ['info'] }),
      stderr: '',
    };
    const out = parseExecError(err);
    expect(out).toEqual({ error: 'fail', logs: ['info'] });
  });

  it('returns null if error has no stdout', () => {
    expect(parseExecError({ message: 'oops' })).toBeNull();
  });

  it('returns null if error is not an object', () => {
    expect(parseExecError('string error')).toBeNull();
    expect(parseExecError(42)).toBeNull();
    expect(parseExecError(null)).toBeNull();
    expect(parseExecError(undefined)).toBeNull();
  });

  it('returns null if stdout is empty', () => {
    expect(parseExecError({ stdout: '' })).toBeNull();
    expect(parseExecError({ stdout: '   ' })).toBeNull();
  });

  it('returns null if stdout is not valid structured output', () => {
    expect(parseExecError({ stdout: 'not json' })).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// confinePath
// ---------------------------------------------------------------------------
describe('confinePath', () => {
  it('normal path', () => {
    expect(confinePath('/base', 'foo/bar')).toBe('/base/foo/bar');
  });

  it('rejects .. traversal at start', () => {
    expect(() => confinePath('/base', '../etc/passwd')).toThrow(/escapes base/);
  });

  it('rejects ../../ traversal', () => {
    expect(() => confinePath('/base', '../../etc/passwd')).toThrow(/escapes base/);
  });

  it('handles . segments (ignored)', () => {
    expect(confinePath('/base', './foo')).toBe('/base/foo');
  });

  it('handles mixed ./ and normal', () => {
    expect(confinePath('/base', 'a/./b')).toBe('/base/a/b');
  });

  it('handles .. in middle when safe', () => {
    expect(confinePath('/base', 'a/b/../c')).toBe('/base/a/c');
  });

  it('rejects .. that escapes', () => {
    expect(() => confinePath('/base', 'a/../../etc')).toThrow(/escapes base/);
  });

  it('rejects null bytes', () => {
    expect(() => confinePath('/base', 'foo\0bar')).toThrow(/null bytes/);
  });

  it('empty user path', () => {
    expect(confinePath('/base', '')).toBe('/base');
  });

  it('root-relative file', () => {
    expect(confinePath('/base', 'file.txt')).toBe('/base/file.txt');
  });
});

// ---------------------------------------------------------------------------
// shellEscape
// ---------------------------------------------------------------------------
describe('shellEscape', () => {
  it('simple string', () => {
    expect(shellEscape('hello')).toBe("'hello'");
  });

  it('string with spaces', () => {
    expect(shellEscape('hello world')).toBe("'hello world'");
  });

  it('string with single quote', () => {
    expect(shellEscape("it's")).toBe("'it'\\''s'");
  });

  it('empty string', () => {
    expect(shellEscape('')).toBe("''");
  });

  it('string with special chars', () => {
    expect(shellEscape('a;b|c')).toBe("'a;b|c'");
  });
});

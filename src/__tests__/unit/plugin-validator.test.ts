import { describe, it, expect } from 'vitest';
import { validatePlugin, validatePluginTier } from '../../plugin-validator.js';
import type { SandboxPlugin } from '../../types.js';

function makePlugin(overrides: Partial<SandboxPlugin> = {}): SandboxPlugin {
  return {
    name: 'test-plugin',
    version: '1.0.0',
    requiredCoreVersion: '>=1.0.0',
    isolationLevel: 'isolate',
    create: async () => ({} as any),
    ...overrides,
  };
}

describe('validatePlugin', () => {
  it('passes for a valid plugin', () => {
    const result = validatePlugin(makePlugin(), new Set());
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('rejects invalid plugin names', () => {
    const cases = ['', 'UPPER', '1startswithnumber', 'has spaces', 'has_underscore'];
    for (const name of cases) {
      const result = validatePlugin(makePlugin({ name }), new Set());
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('invalid'))).toBe(true);
    }
  });

  it('accepts valid plugin names', () => {
    const cases = ['mock', 'isolated-vm', 'landlock', 'a', 'my-plugin-2'];
    for (const name of cases) {
      const result = validatePlugin(makePlugin({ name }), new Set());
      expect(result.valid).toBe(true);
    }
  });

  it('rejects plugins without create method', () => {
    const plugin = makePlugin();
    (plugin as any).create = 'not a function';
    const result = validatePlugin(plugin, new Set());
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('create()'))).toBe(true);
  });

  it('rejects plugins without version', () => {
    const result = validatePlugin(makePlugin({ version: '' }), new Set());
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('version'))).toBe(true);
  });

  it('rejects plugins without requiredCoreVersion', () => {
    const result = validatePlugin(makePlugin({ requiredCoreVersion: '' }), new Set());
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('requiredCoreVersion'))).toBe(true);
  });

  it('rejects invalid isolation levels', () => {
    const result = validatePlugin(
      makePlugin({ isolationLevel: 'invalid' as any }),
      new Set(),
    );
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('isolation level'))).toBe(true);
  });

  it('rejects duplicate plugin names', () => {
    const existing = new Set(['test-plugin']);
    const result = validatePlugin(makePlugin(), existing);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('Duplicate'))).toBe(true);
  });

  it('accumulates multiple errors', () => {
    const plugin = makePlugin({
      name: 'INVALID',
      version: '',
      requiredCoreVersion: '',
      isolationLevel: 'bad' as any,
    });
    (plugin as any).create = null;
    const result = validatePlugin(plugin, new Set());
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThanOrEqual(4);
  });
});

describe('validatePluginTier', () => {
  it('passes when isolation level matches tier', () => {
    expect(validatePluginTier(makePlugin({ isolationLevel: 'isolate' }), 1).valid).toBe(true);
    expect(validatePluginTier(makePlugin({ isolationLevel: 'process' }), 2).valid).toBe(true);
    expect(validatePluginTier(makePlugin({ isolationLevel: 'container' }), 3).valid).toBe(true);
    expect(validatePluginTier(makePlugin({ isolationLevel: 'microvm' }), 3).valid).toBe(true);
  });

  it('fails when isolation level does not match tier', () => {
    const result = validatePluginTier(makePlugin({ isolationLevel: 'isolate' }), 2);
    expect(result.valid).toBe(false);
    expect(result.errors[0]).toContain('Tier 2');
    expect(result.errors[0]).toContain('Expected');
  });

  it('passes for unknown tiers (no expected isolation)', () => {
    const result = validatePluginTier(makePlugin({ isolationLevel: 'isolate' }), 99);
    expect(result.valid).toBe(true);
  });
});

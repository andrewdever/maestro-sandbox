import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  registerSandbox,
  unregisterSandbox,
  getSandbox,
  killAll,
  status,
  recordBreachSignal,
  resetBreachCounters,
  doctor,
  resetMaestro,
} from '../../maestro.js';
import type { Sandbox } from '../../types.js';

function makeMockSandbox(destroyFn?: () => Promise<void>): Sandbox {
  return {
    execute: vi.fn(async () => ({ success: true, logs: [], metrics: { cpuMs: 0, memoryMB: 0, wallMs: 0 } })),
    executeStream: vi.fn(async function* () {}),
    fs: { read: vi.fn(), write: vi.fn(), list: vi.fn() } as any,
    git: { inject: vi.fn(), exportPatch: vi.fn(), exportFiles: vi.fn() } as any,
    ready: vi.fn(async () => true),
    destroy: destroyFn ?? vi.fn(async () => {}),
  };
}

describe('Maestro', () => {
  beforeEach(() => {
    resetMaestro();
  });

  describe('sandbox registry', () => {
    it('registers and retrieves a sandbox', () => {
      const sandbox = makeMockSandbox();
      const id = registerSandbox(sandbox);
      expect(id).toMatch(/^sbx_/);
      expect(getSandbox(id)).toBe(sandbox);
    });

    it('returns undefined for unknown ID', () => {
      expect(getSandbox('sbx_unknown')).toBeUndefined();
    });

    it('unregisters a sandbox', () => {
      const sandbox = makeMockSandbox();
      const id = registerSandbox(sandbox);
      unregisterSandbox(id);
      expect(getSandbox(id)).toBeUndefined();
    });

    it('generates unique IDs', () => {
      const ids = new Set<string>();
      for (let i = 0; i < 100; i++) {
        ids.add(registerSandbox(makeMockSandbox()));
      }
      expect(ids.size).toBe(100);
    });
  });

  describe('status', () => {
    it('reports zero sandboxes when empty', () => {
      const s = status();
      expect(s.activeSandboxCount).toBe(0);
      expect(s.sandboxIds).toEqual([]);
    });

    it('reports active sandbox count and IDs', () => {
      const id1 = registerSandbox(makeMockSandbox());
      const id2 = registerSandbox(makeMockSandbox());
      const s = status();
      expect(s.activeSandboxCount).toBe(2);
      expect(s.sandboxIds).toContain(id1);
      expect(s.sandboxIds).toContain(id2);
    });
  });

  describe('killAll', () => {
    it('destroys all active sandboxes', async () => {
      const destroy1 = vi.fn(async () => {});
      const destroy2 = vi.fn(async () => {});
      registerSandbox(makeMockSandbox(destroy1));
      registerSandbox(makeMockSandbox(destroy2));

      const result = await killAll();
      expect(result.destroyed).toBe(2);
      expect(result.failed).toBe(0);
      expect(result.errors).toHaveLength(0);
      expect(destroy1).toHaveBeenCalled();
      expect(destroy2).toHaveBeenCalled();
    });

    it('clears the registry after kill', async () => {
      registerSandbox(makeMockSandbox());
      await killAll();
      expect(status().activeSandboxCount).toBe(0);
    });

    it('handles destroy failures gracefully', async () => {
      const failingDestroy = vi.fn(async () => { throw new Error('destroy failed'); });
      registerSandbox(makeMockSandbox(failingDestroy));
      registerSandbox(makeMockSandbox());

      const result = await killAll();
      expect(result.destroyed).toBe(1);
      expect(result.failed).toBe(1);
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0].error.message).toBe('destroy failed');
    });

    it('force-kills sandboxes that timeout on destroy', async () => {
      const hangingDestroy = () => new Promise<void>(() => {}); // never resolves
      registerSandbox(makeMockSandbox(hangingDestroy));

      const result = await killAll();
      expect(result.failed).toBe(1);
      expect(result.errors[0].error.message).toContain('timed out');
    }, 10000);

    it('logs events when logger is provided', async () => {
      const logger = { log: vi.fn() };
      registerSandbox(makeMockSandbox());
      await killAll(logger as any);
      expect(logger.log).toHaveBeenCalledWith(
        'sandbox.destroy',
        expect.objectContaining({ lifetime: 'emergency' }),
        expect.any(String),
      );
    });
  });

  describe('breach detection', () => {
    it('returns false when under threshold', () => {
      expect(recordBreachSignal('permission-error-spike', 'sbx_001')).toBe(false);
    });

    it('returns true when threshold is reached', () => {
      // permission-error-spike threshold is 10
      for (let i = 0; i < 9; i++) {
        expect(recordBreachSignal('permission-error-spike', 'sbx_001')).toBe(false);
      }
      expect(recordBreachSignal('permission-error-spike', 'sbx_001')).toBe(true);
    });

    it('triggers immediately for single-count signals', () => {
      expect(recordBreachSignal('path-traversal-patch', 'sbx_001')).toBe(true);
      expect(recordBreachSignal('git-internals-patch', 'sbx_001')).toBe(true);
      expect(recordBreachSignal('unexpected-child-process', 'sbx_001')).toBe(true);
      expect(recordBreachSignal('symlink-in-tmpdir', 'sbx_001')).toBe(true);
    });

    it('tracks signals per sandbox independently', () => {
      for (let i = 0; i < 9; i++) {
        recordBreachSignal('permission-error-spike', 'sbx_001');
      }
      // Different sandbox — counter starts fresh
      expect(recordBreachSignal('permission-error-spike', 'sbx_002')).toBe(false);
    });

    it('resets counters after breach', () => {
      // path-traversal-patch triggers at count 1, then counter is deleted
      expect(recordBreachSignal('path-traversal-patch', 'sbx_001')).toBe(true);
      // Next signal starts a new counter
      expect(recordBreachSignal('path-traversal-patch', 'sbx_001')).toBe(true);
    });

    it('logs breach events when logger is provided', () => {
      const logger = { log: vi.fn() };
      recordBreachSignal('path-traversal-patch', 'sbx_001', logger as any);
      expect(logger.log).toHaveBeenCalledWith(
        'breach.detected',
        expect.objectContaining({ signal: 'path-traversal-patch' }),
        'sbx_001',
      );
    });

    it('resetBreachCounters clears all state', () => {
      for (let i = 0; i < 9; i++) {
        recordBreachSignal('permission-error-spike', 'sbx_001');
      }
      resetBreachCounters();
      // After reset, counter starts from 0 again
      expect(recordBreachSignal('permission-error-spike', 'sbx_001')).toBe(false);
    });
  });

  describe('doctor', () => {
    it('returns an array of health checks', async () => {
      const checks = await doctor();
      expect(Array.isArray(checks)).toBe(true);
      expect(checks.length).toBeGreaterThan(0);
    });

    it('includes a platform check', async () => {
      const checks = await doctor();
      const platform = checks.find(c => c.name === 'platform');
      expect(platform).toBeDefined();
      expect(['ok', 'warn']).toContain(platform!.status);
    });

    it('includes a Node.js version check', async () => {
      const checks = await doctor();
      const node = checks.find(c => c.name === 'node');
      expect(node).toBeDefined();
    });

    it('includes tier availability checks', async () => {
      const checks = await doctor();
      const tier1 = checks.find(c => c.name === 'tier-1');
      expect(tier1).toBeDefined();
      expect(tier1!.status).toBe('ok');
    });

    it('all checks have name, status, and message', async () => {
      const checks = await doctor();
      for (const check of checks) {
        expect(check).toHaveProperty('name');
        expect(check).toHaveProperty('status');
        expect(check).toHaveProperty('message');
        expect(['ok', 'warn', 'fail']).toContain(check.status);
      }
    });
  });
});

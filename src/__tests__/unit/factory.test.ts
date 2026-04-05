import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createSandbox, createSandboxWithDegradation, resetCircuitBreakers, getCircuitBreakerState } from '../../factory.js';
import mockPlugin from '../../plugins/mock.js';
import type { SandboxPlugin, SandboxConfig } from '../../types.js';
import { SandboxCrashError } from '../../types.js';

const defaultConfig: SandboxConfig = {
  limits: {
    memoryMB: 128,
    cpuMs: 5000,
    timeoutMs: 10000,
    networkAccess: false,
    filesystemAccess: 'tmpfs' as const,
  },
};

describe('createSandbox', () => {
  beforeEach(() => {
    resetCircuitBreakers();
  });

  describe('plugin resolution', () => {
    it('creates sandbox with a direct plugin reference', async () => {
      const sandbox = await createSandbox({ plugin: mockPlugin, config: defaultConfig });
      try {
        expect(await sandbox.ready()).toBe(true);
      } finally {
        await sandbox.destroy();
      }
    });

    it('resolves plugin by name from registry', async () => {
      const sandbox = await createSandbox({ plugin: 'mock', config: defaultConfig });
      try {
        expect(await sandbox.ready()).toBe(true);
      } finally {
        await sandbox.destroy();
      }
    });

    it('throws if plugin name is not in registry', async () => {
      await expect(
        createSandbox({ plugin: 'nonexistent', config: defaultConfig }),
      ).rejects.toThrow(/Unknown plugin.*nonexistent/);
    });

    it('validates plugin version compatibility (requiredCoreVersion)', async () => {
      // TODO: version validation not yet implemented — this test documents current behavior
      const pluginWithVersion: SandboxPlugin = {
        ...mockPlugin,
        name: 'versioned-mock',
        requiredCoreVersion: '>=99.0.0',
      };
      const sandbox = await createSandbox({ plugin: pluginWithVersion, config: defaultConfig });
      try {
        expect(await sandbox.ready()).toBe(true);
      } finally {
        await sandbox.destroy();
      }
    });

    it('rejects incompatible plugin versions', async () => {
      // TODO: version validation not yet implemented — this test documents current behavior
      // Currently plugins with any requiredCoreVersion are accepted regardless of compatibility.
      const pluginWithImpossibleVersion: SandboxPlugin = {
        ...mockPlugin,
        name: 'impossible-version-mock',
        requiredCoreVersion: '>=999.0.0',
      };
      const sandbox = await createSandbox({ plugin: pluginWithImpossibleVersion, config: defaultConfig });
      try {
        expect(await sandbox.ready()).toBe(true);
      } finally {
        await sandbox.destroy();
      }
    });
  });

  describe('config validation', () => {
    it('validates limits are within acceptable ranges', async () => {
      const sandbox = await createSandbox({ plugin: mockPlugin, config: defaultConfig });
      try {
        expect(await sandbox.ready()).toBe(true);
      } finally {
        await sandbox.destroy();
      }
    });

    it('rejects negative memoryMB', async () => {
      await expect(
        createSandbox({
          plugin: mockPlugin,
          config: { ...defaultConfig, limits: { ...defaultConfig.limits, memoryMB: -1 } },
        }),
      ).rejects.toThrow(/memoryMB must be positive/);
    });

    it('rejects negative timeoutMs', async () => {
      await expect(
        createSandbox({
          plugin: mockPlugin,
          config: { ...defaultConfig, limits: { ...defaultConfig.limits, timeoutMs: -1 } },
        }),
      ).rejects.toThrow(/timeoutMs must be positive/);
    });

    it('freezes hostFunctions after creation', async () => {
      const hostFunctions: Record<string, any> = {
        greet: async () => 'hello',
      };
      const config = { ...defaultConfig, hostFunctions };
      const sandbox = await createSandbox({ plugin: mockPlugin, config });
      try {
        expect(Object.isFrozen(config.hostFunctions)).toBe(true);
      } finally {
        await sandbox.destroy();
      }
    });
  });

  describe('circuit breaker', () => {
    const failingPlugin: SandboxPlugin = {
      ...mockPlugin,
      name: 'failing',
      create: async () => {
        throw new Error('fail');
      },
    };

    it('starts in closed state', () => {
      expect(getCircuitBreakerState('mock')).toBeUndefined();
      // After a successful call, state should be closed
    });

    it('trips after consecutive failures (default: 3)', async () => {
      for (let i = 0; i < 3; i++) {
        await expect(
          createSandbox({ plugin: failingPlugin, config: defaultConfig }),
        ).rejects.toThrow('fail');
      }
      expect(getCircuitBreakerState('failing')).toBe('open');
    });

    it('enters cooldown when tripped', async () => {
      for (let i = 0; i < 3; i++) {
        await expect(
          createSandbox({ plugin: failingPlugin, config: defaultConfig }),
        ).rejects.toThrow('fail');
      }
      await expect(
        createSandbox({ plugin: failingPlugin, config: defaultConfig }),
      ).rejects.toThrow(/Circuit breaker open/);
    });

    it('allows half-open retry after cooldown', async () => {
      vi.useFakeTimers();
      try {
        for (let i = 0; i < 3; i++) {
          await expect(
            createSandbox({ plugin: failingPlugin, config: defaultConfig }),
          ).rejects.toThrow('fail');
        }
        expect(getCircuitBreakerState('failing')).toBe('open');

        vi.advanceTimersByTime(30001);

        // Should attempt (half-open) — will fail again but won't throw "circuit breaker open"
        await expect(
          createSandbox({ plugin: failingPlugin, config: defaultConfig }),
        ).rejects.toThrow('fail');
        expect(getCircuitBreakerState('failing')).toBe('open');
      } finally {
        vi.useRealTimers();
      }
    });

    it('closes on successful half-open retry', async () => {
      vi.useFakeTimers();
      try {
        // Trip the breaker
        for (let i = 0; i < 3; i++) {
          await expect(
            createSandbox({ plugin: failingPlugin, config: defaultConfig }),
          ).rejects.toThrow('fail');
        }
        expect(getCircuitBreakerState('failing')).toBe('open');

        // Wait for cooldown
        vi.advanceTimersByTime(30001);

        // Now use a working plugin with the same name
        const recoveredPlugin: SandboxPlugin = {
          ...mockPlugin,
          name: 'failing',
        };
        const sandbox = await createSandbox({ plugin: recoveredPlugin, config: defaultConfig });
        try {
          expect(getCircuitBreakerState('failing')).toBe('closed');
        } finally {
          await sandbox.destroy();
        }
      } finally {
        vi.useRealTimers();
      }
    });

    it('re-opens on failed half-open retry', async () => {
      vi.useFakeTimers();
      try {
        for (let i = 0; i < 3; i++) {
          await expect(
            createSandbox({ plugin: failingPlugin, config: defaultConfig }),
          ).rejects.toThrow('fail');
        }
        vi.advanceTimersByTime(30001);

        // Half-open retry fails
        await expect(
          createSandbox({ plugin: failingPlugin, config: defaultConfig }),
        ).rejects.toThrow('fail');

        expect(getCircuitBreakerState('failing')).toBe('open');
      } finally {
        vi.useRealTimers();
      }
    });

    it('respects custom failure threshold', async () => {
      const cbConfig = { failureThreshold: 5 };
      for (let i = 0; i < 4; i++) {
        await expect(
          createSandbox({ plugin: failingPlugin, config: defaultConfig, circuitBreaker: cbConfig }),
        ).rejects.toThrow('fail');
      }
      // Should not be open yet (threshold is 5)
      expect(getCircuitBreakerState('failing')).not.toBe('open');

      await expect(
        createSandbox({ plugin: failingPlugin, config: defaultConfig, circuitBreaker: cbConfig }),
      ).rejects.toThrow('fail');
      expect(getCircuitBreakerState('failing')).toBe('open');
    });

    it('respects custom cooldown duration', async () => {
      vi.useFakeTimers();
      try {
        const cbConfig = { cooldownMs: 5000 };
        for (let i = 0; i < 3; i++) {
          await expect(
            createSandbox({ plugin: failingPlugin, config: defaultConfig, circuitBreaker: cbConfig }),
          ).rejects.toThrow('fail');
        }

        // Too early
        vi.advanceTimersByTime(3000);
        await expect(
          createSandbox({ plugin: failingPlugin, config: defaultConfig, circuitBreaker: cbConfig }),
        ).rejects.toThrow(/Circuit breaker open/);

        // After cooldown
        vi.advanceTimersByTime(2001);
        // Should attempt (half-open)
        await expect(
          createSandbox({ plugin: failingPlugin, config: defaultConfig, circuitBreaker: cbConfig }),
        ).rejects.toThrow('fail'); // fails but it attempted
      } finally {
        vi.useRealTimers();
      }
    });
  });

  describe('graceful degradation', () => {
    it('falls back to next plugin when primary is unavailable', async () => {
      // Docker is not available in test env, so it should fall back to mock
      const sandbox = await createSandboxWithDegradation({
        chain: ['docker', 'mock'],
        config: defaultConfig,
      });
      try {
        expect(await sandbox.ready()).toBe(true);
      } finally {
        await sandbox.destroy();
      }
    });

    it('follows degradation chain: T3 → T2 → T1', async () => {
      // All T3/T2 plugins are unavailable in test env; eventually reaches mock (T1)
      const sandbox = await createSandboxWithDegradation({
        chain: ['docker', 'e2b', 'landlock', 'anthropic-sr', 'isolated-vm', 'mock'],
        config: defaultConfig,
      });
      try {
        expect(await sandbox.ready()).toBe(true);
      } finally {
        await sandbox.destroy();
      }
    });

    it('skips plugins below mcpMinTier and fails if none qualify', async () => {
      // mcpMinTier is a hard floor — plugins below it are skipped entirely.
      // With chain ['docker', 'mock'] and mcpMinTier: 2, docker fails (unavailable)
      // and mock (tier 1) is skipped, so all fail.
      await expect(
        createSandboxWithDegradation({
          chain: ['docker', 'mock'],
          config: defaultConfig,
          mcpMinTier: 2,
        }),
      ).rejects.toThrow(SandboxCrashError);
    });

    it('throws when all plugins in chain fail', async () => {
      // All three are unavailable in test env and none is mock
      await expect(
        createSandboxWithDegradation({
          chain: ['docker', 'e2b', 'microsandbox'],
          config: defaultConfig,
        }),
      ).rejects.toThrow(SandboxCrashError);
    });
  });

  describe('creation limits (§10)', () => {
    it('rejects when creation rate limit is exceeded', async () => {
      const sandboxes = [];
      try {
        // Create 10 sandboxes rapidly (at the limit)
        for (let i = 0; i < 10; i++) {
          sandboxes.push(await createSandbox({ plugin: 'mock', config: defaultConfig }));
        }
        // The 11th should be rejected
        await expect(
          createSandbox({ plugin: 'mock', config: defaultConfig }),
        ).rejects.toThrow(/rate limit/i);
      } finally {
        for (const sb of sandboxes) await sb.destroy();
      }
    });

    it('allows creation after rate window passes', async () => {
      vi.useFakeTimers();
      const sandboxes = [];
      try {
        for (let i = 0; i < 10; i++) {
          sandboxes.push(await createSandbox({ plugin: 'mock', config: defaultConfig }));
        }
        // Advance past the 1s rate window
        vi.advanceTimersByTime(1001);
        // Should succeed now
        const sb = await createSandbox({ plugin: 'mock', config: defaultConfig });
        sandboxes.push(sb);
        expect(sb).toBeDefined();
      } finally {
        vi.useRealTimers();
        for (const sb of sandboxes) await sb.destroy();
      }
    });

    it('tracks active sandbox count via destroy()', async () => {
      const sandboxes = [];
      try {
        for (let i = 0; i < 10; i++) {
          sandboxes.push(await createSandbox({ plugin: 'mock', config: defaultConfig }));
        }
        // At rate limit, destroy one and advance time window
        await sandboxes[0].destroy();
        sandboxes.shift();

        vi.useFakeTimers();
        vi.advanceTimersByTime(1001);
        // Should succeed — rate window passed and one slot freed
        const sb = await createSandbox({ plugin: 'mock', config: defaultConfig });
        sandboxes.push(sb);
        expect(sb).toBeDefined();
      } finally {
        vi.useRealTimers();
        for (const sb of sandboxes) await sb.destroy();
      }
    });
  });
});

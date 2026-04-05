import { describe, bench, beforeAll, afterAll } from 'vitest';
import { createSandbox, resetCircuitBreakers } from '../../factory.js';
import type { SandboxConfig, Sandbox } from '../../types.js';
import { platform } from 'node:os';

const config: SandboxConfig = {
  limits: {
    memoryMB: 128,
    cpuMs: 5000,
    timeoutMs: 10000,
    networkAccess: false,
    filesystemAccess: 'tmpfs',
  },
};

const isMac = platform() === 'darwin';

describe('Performance benchmarks', () => {
  beforeAll(() => {
    resetCircuitBreakers();
  });

  describe('sandbox startup', () => {
    bench('Mock plugin startup time (baseline)', async () => {
      const sb = await createSandbox({ plugin: 'mock', config });
      await sb.destroy();
    });

    bench('Tier 1 (isolated-vm) startup time', async () => {
      const sb = await createSandbox({ plugin: 'isolated-vm', config });
      await sb.destroy();
    });

    // Tier 2 benchmarks only on macOS
    bench.skipIf(!isMac)('Tier 2 (Landlock) startup time', async () => {
      const sb = await createSandbox({ plugin: 'landlock', config });
      await sb.destroy();
    });

    // Skip benchmarks that require external services
    bench.skip('Tier 2 (Anthropic SR) startup time', async () => {
      const sb = await createSandbox({ plugin: 'anthropic-sr', config });
      await sb.destroy();
    });

    bench.skip('Tier 3 (Docker Sandboxes) startup time', async () => {
      const sb = await createSandbox({ plugin: 'docker', config });
      await sb.destroy();
    });
  });

  describe('execution (isolated-vm, sandbox reused across iterations)', () => {
    let sb: Sandbox | null = null;

    afterAll(async () => {
      if (sb) await sb.destroy();
      sb = null;
    });

    bench('simple expression evaluation (return 42)', async () => {
      sb ??= await createSandbox({ plugin: 'isolated-vm', config });
      await sb.execute('return 42');
    });

    bench('JSON processing (parse + transform + stringify)', async () => {
      sb ??= await createSandbox({ plugin: 'isolated-vm', config });
      await sb.execute(`
        const data = JSON.parse('{"items":[1,2,3,4,5]}');
        const transformed = { ...data, items: data.items.map(x => x * 2) };
        return JSON.stringify(transformed);
      `);
    });

    bench('compute-heavy (fibonacci)', async () => {
      sb ??= await createSandbox({ plugin: 'isolated-vm', config });
      await sb.execute(`
        function fib(n) { return n <= 1 ? n : fib(n-1) + fib(n-2); }
        return fib(20);
      `);
    });

    bench('host function call round-trip (mock plugin)', async () => {
      const sbConfig: SandboxConfig = {
        ...config,
        hostFunctions: {
          echo: async (args: unknown) => args,
        },
      };
      // Mock plugin needed for hostFunctions — create per iteration
      const mockSb = await createSandbox({ plugin: 'mock', config: sbConfig });
      await mockSb.execute('return await hostCall("echo", { value: 42 })');
      await mockSb.destroy();
    });
  });

  describe('destroy', () => {
    bench('Tier 1 destroy time', async () => {
      const sb = await createSandbox({ plugin: 'isolated-vm', config });
      await sb.destroy();
    });

    bench.skip('Tier 2 destroy time', async () => {
      const sb = await createSandbox({ plugin: 'landlock', config });
      await sb.destroy();
    });

    bench.skip('Tier 3 destroy time', async () => {
      const sb = await createSandbox({ plugin: 'docker', config });
      await sb.destroy();
    });
  });

  describe('throughput', () => {
    bench('sequential: 100 create-execute-destroy cycles', async () => {
      for (let i = 0; i < 100; i++) {
        const sb = await createSandbox({ plugin: 'mock', config });
        await sb.execute('return 1');
        await sb.destroy();
      }
    }, { warmupIterations: 1, iterations: 3 });

    bench('concurrent: 10 sandboxes executing simultaneously', async () => {
      const sandboxes = await Promise.all(
        Array.from({ length: 10 }, () => createSandbox({ plugin: 'mock', config })),
      );
      await Promise.all(sandboxes.map(sb => sb.execute('return 1')));
      await Promise.all(sandboxes.map(sb => sb.destroy()));
    }, { warmupIterations: 1, iterations: 3 });
  });
});

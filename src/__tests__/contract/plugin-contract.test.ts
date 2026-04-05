import { describe, it, expect, afterEach } from 'vitest';
import type { Sandbox, SandboxConfig, SandboxPlugin } from '../../types.js';
import { SandboxTimeoutError, SandboxOOMError } from '../../types.js';
import { platform } from 'node:os';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import mockPlugin from '../../plugins/mock.js';
import isolatedVmPlugin from '../../plugins/isolated-vm.js';
import landlockPlugin from '../../plugins/landlock/index.js';

const execFileAsync = promisify(execFile);

/**
 * Plugin contract test suite.
 *
 * Every sandbox plugin MUST pass these tests. They verify the full
 * lifecycle: create → execute → destroy, and validate that the plugin
 * implements the SandboxPlugin interface correctly.
 *
 * Runs against ALL available plugins. Plugins that require external
 * dependencies (Docker, E2B API key, ripgrep) are auto-skipped when
 * their prerequisites are missing.
 */

// Detect available Tier 2/3 prerequisites
const isMac = platform() === 'darwin';
const isLinux = platform() === 'linux';

let hasDocker = false;
try {
  await execFileAsync('docker', ['info'], { timeout: 5000 });
  hasDocker = true;
} catch { /* docker not available */ }

let hasOpenShell = false;
try {
  await execFileAsync('openshell', ['version'], { timeout: 5000 });
  hasOpenShell = true;
} catch { /* openshell not available */ }

let hasRipgrep = false;
try {
  await execFileAsync('rg', ['--version'], { timeout: 3000 });
  hasRipgrep = true;
} catch { /* rg not available — anthropic-sr requires it */ }

const hasE2bKey = !!process.env['E2B_API_KEY'];

// Build plugin list dynamically based on available prerequisites
type PluginEntry = { name: string; plugin: SandboxPlugin; skip: boolean; skipReason?: string };

const plugins: PluginEntry[] = [
  { name: 'mock', plugin: mockPlugin, skip: false },
  { name: 'isolated-vm', plugin: isolatedVmPlugin, skip: false },
  { name: 'landlock', plugin: landlockPlugin, skip: !(isMac || isLinux), skipReason: 'requires macOS or Linux' },
];

// Anthropic SR — requires @anthropic-ai/sandbox-runtime + ripgrep
try {
  const { default: anthropicSrPlugin } = await import('../../plugins/anthropic-sr.js');
  plugins.push({
    name: 'anthropic-sr',
    plugin: anthropicSrPlugin,
    skip: !hasRipgrep || !(isMac || isLinux),
    skipReason: !hasRipgrep ? 'ripgrep (rg) not installed' : 'requires macOS or Linux',
  });
} catch {
  plugins.push({ name: 'anthropic-sr', plugin: mockPlugin, skip: true, skipReason: 'import failed' });
}

// Docker — requires running Docker daemon
try {
  const { default: dockerPlugin } = await import('../../plugins/docker.js');
  plugins.push({
    name: 'docker',
    plugin: dockerPlugin,
    skip: !hasDocker,
    skipReason: 'Docker not available',
  });
} catch {
  plugins.push({ name: 'docker', plugin: mockPlugin, skip: true, skipReason: 'import failed' });
}

// OpenShell — requires running OpenShell CLI (NVIDIA OpenShell)
try {
  const { default: openshellPlugin } = await import('../../plugins/openshell.js');
  plugins.push({
    name: 'openshell',
    plugin: openshellPlugin,
    skip: !hasOpenShell,
    skipReason: 'OpenShell CLI not available',
  });
} catch {
  plugins.push({ name: 'openshell', plugin: mockPlugin, skip: true, skipReason: 'import failed' });
}

// E2B — requires E2B_API_KEY
try {
  const { default: e2bPlugin } = await import('../../plugins/e2b.js');
  plugins.push({
    name: 'e2b',
    plugin: e2bPlugin,
    skip: !hasE2bKey,
    skipReason: 'E2B_API_KEY not set',
  });
} catch {
  plugins.push({ name: 'e2b', plugin: mockPlugin, skip: true, skipReason: 'import failed' });
}

const defaultConfig: SandboxConfig = {
  limits: { memoryMB: 128, cpuMs: 5000, timeoutMs: 5000, networkAccess: false, filesystemAccess: 'tmpfs' },
};

describe('SandboxPlugin contract', () => {
  describe.each(plugins)('plugin: $name', ({ name, plugin, skip, skipReason }) => {
    let sandbox: Sandbox | undefined;

    // Skip entire plugin suite if prerequisites are missing
    if (skip) {
      it(`skipped: ${skipReason}`, () => {
        expect(true).toBe(true);
      });
      return;
    }

    afterEach(async () => {
      if (sandbox) {
        await sandbox.destroy();
        sandbox = undefined;
      }
    });

    describe('lifecycle', () => {
      it('has a valid name string', () => {
        expect(typeof plugin.name).toBe('string');
        expect(plugin.name.length).toBeGreaterThan(0);
      });

      it('has a valid semver version', () => {
        expect(typeof plugin.version).toBe('string');
        expect(plugin.version).toMatch(/^\d+\.\d+\.\d+/);
      });

      it('has a valid requiredCoreVersion range', () => {
        expect(typeof plugin.requiredCoreVersion).toBe('string');
        expect(plugin.requiredCoreVersion.length).toBeGreaterThan(0);
      });

      it('has a valid isolationLevel', () => {
        expect(['isolate', 'process', 'container', 'microvm']).toContain(plugin.isolationLevel);
      });

      it('create() returns a Sandbox instance', async () => {
        sandbox = await plugin.create(defaultConfig);
        expect(sandbox).toBeDefined();
        expect(typeof sandbox.execute).toBe('function');
        expect(typeof sandbox.executeStream).toBe('function');
        expect(typeof sandbox.ready).toBe('function');
        expect(typeof sandbox.destroy).toBe('function');
        expect(sandbox.fs).toBeDefined();
        expect(sandbox.git).toBeDefined();
      });

      it('ready() returns true after creation', async () => {
        sandbox = await plugin.create(defaultConfig);
        expect(await sandbox.ready()).toBe(true);
      });

      it('destroy() completes without error', async () => {
        sandbox = await plugin.create(defaultConfig);
        await expect(sandbox.destroy()).resolves.toBeUndefined();
        sandbox = undefined; // already destroyed
      });

      it('destroy() can be called multiple times safely', async () => {
        sandbox = await plugin.create(defaultConfig);
        await sandbox.destroy();
        await expect(sandbox.destroy()).resolves.toBeUndefined();
        sandbox = undefined; // already destroyed
      });

      it('execute() after destroy() returns success: false', async () => {
        sandbox = await plugin.create(defaultConfig);
        await sandbox.destroy();
        const result = await sandbox.execute('return 42');
        expect(result.success).toBe(false);
        expect(result.error).toBeDefined();
        sandbox = undefined; // already destroyed
      });
    });

    describe('execute', () => {
      it('executes simple code and returns result', async () => {
        sandbox = await plugin.create(defaultConfig);
        const result = await sandbox.execute('return 42');
        expect(result.success).toBe(true);
        expect(result.result).toBe(42);
      });

      it('returns success: true for valid code', async () => {
        sandbox = await plugin.create(defaultConfig);
        const result = await sandbox.execute('return "hello"');
        expect(result.success).toBe(true);
      });

      it('returns success: false for throwing code', async () => {
        sandbox = await plugin.create(defaultConfig);
        const result = await sandbox.execute('throw new Error("boom")');
        expect(result.success).toBe(false);
        expect(result.error).toBeDefined();
      });

      it('captures error message on failure', async () => {
        sandbox = await plugin.create(defaultConfig);
        const result = await sandbox.execute('throw new Error("test error msg")');
        expect(result.success).toBe(false);
        expect(typeof result.error === 'string' ? result.error : (result.error as Error).message).toContain('test error msg');
      });

      it('captures console.log in logs array', async () => {
        sandbox = await plugin.create(defaultConfig);
        const result = await sandbox.execute('console.log("hello")');
        expect(result.logs).toContain('hello');
      });

      it('returns metrics with cpuMs > 0', async () => {
        sandbox = await plugin.create(defaultConfig);
        // Use a slightly slow operation so wallMs is measurably > 0
        const result = await sandbox.execute('await new Promise(r => setTimeout(r, 5)); return 1');
        expect(result.metrics.cpuMs).toBeGreaterThan(0);
      });

      it('returns metrics with wallMs > 0', async () => {
        sandbox = await plugin.create(defaultConfig);
        const result = await sandbox.execute('await new Promise(r => setTimeout(r, 5)); return 1');
        expect(result.metrics.wallMs).toBeGreaterThan(0);
      });

      it('returns metrics with memoryMB >= 0', async () => {
        sandbox = await plugin.create(defaultConfig);
        const result = await sandbox.execute('return 1 + 1');
        expect(result.metrics.memoryMB).toBeGreaterThanOrEqual(0);
      });
    });

    describe('limits enforcement', () => {
      it('terminates execution that exceeds timeoutMs', async () => {
        const config: SandboxConfig = {
          limits: { ...defaultConfig.limits, timeoutMs: 1000 },
        };
        sandbox = await plugin.create(config);
        const result = await sandbox.execute('await new Promise(r => setTimeout(r, 30000))');
        expect(result.success).toBe(false);
      }, 10000);

      it('returns SandboxTimeoutError on timeout', async () => {
        const config: SandboxConfig = {
          limits: { ...defaultConfig.limits, timeoutMs: 1000 },
        };
        sandbox = await plugin.create(config);
        const result = await sandbox.execute('await new Promise(r => setTimeout(r, 30000))');
        expect(result.success).toBe(false);
        expect(result.error).toBeInstanceOf(SandboxTimeoutError);
      }, 10000);

      // OOM tests only meaningful for plugins with V8-level memory enforcement.
      // Mock runs in the host process. Process-level plugins (landlock, anthropic-sr)
      // use --max-old-space-size but 8MB is too small to start a Node.js process.
      const oomIt = name === 'isolated-vm' ? it : it.skip;

      oomIt('terminates execution that exceeds memoryMB', async () => {
        const config: SandboxConfig = {
          limits: { ...defaultConfig.limits, memoryMB: 8 },
        };
        sandbox = await plugin.create(config);
        const result = await sandbox.execute(
          'const arr = []; while(true) arr.push(new Array(1e6).fill("x"))',
        );
        expect(result.success).toBe(false);
      });

      oomIt('returns SandboxOOMError on memory exceeded', async () => {
        const config: SandboxConfig = {
          limits: { ...defaultConfig.limits, memoryMB: 8 },
        };
        sandbox = await plugin.create(config);
        const result = await sandbox.execute(
          'const arr = []; while(true) arr.push(new Array(1e6).fill("x"))',
        );
        expect(result.success).toBe(false);
        expect(result.error).toBeInstanceOf(SandboxOOMError);
      });

      it('timeout wallMs is less than timeoutMs + buffer', async () => {
        const timeoutMs = 1000;
        const config: SandboxConfig = {
          limits: { ...defaultConfig.limits, timeoutMs },
        };
        sandbox = await plugin.create(config);
        const result = await sandbox.execute('await new Promise(r => setTimeout(r, 30000))');
        // Process-level plugins have larger overhead (node startup)
        const buffer = plugin.isolationLevel === 'process' ? 3000 : 1000;
        expect(result.metrics.wallMs).toBeLessThan(timeoutMs + buffer);
      }, 10000);
    });

    describe('isolation', () => {
      // Isolation tests only meaningful for V8 isolate plugins.
      // Mock and process-level plugins (landlock, anthropic-sr) run real Node.js
      // where process, require, fetch are all available.
      const isolationIt = name === 'isolated-vm' ? it : it.skip;

      isolationIt('cannot access host process.env', async () => {
        sandbox = await plugin.create(defaultConfig);
        const result = await sandbox.execute('return typeof process');
        expect(result.success).toBe(true);
        expect(result.result).toBe('undefined');
      });

      isolationIt('cannot access host filesystem', async () => {
        sandbox = await plugin.create(defaultConfig);
        const result = await sandbox.execute(
          'try { require("fs"); return "ESCAPED" } catch { return "BLOCKED" }',
        );
        expect(result.success).toBe(true);
        expect(result.result).toBe('BLOCKED');
      });

      isolationIt('cannot access host network when networkAccess is false', async () => {
        sandbox = await plugin.create(defaultConfig);
        const result = await sandbox.execute('return typeof fetch');
        expect(result.success).toBe(true);
        expect(result.result).toBe('undefined');
      });

      isolationIt('cannot require/import host modules', async () => {
        sandbox = await plugin.create(defaultConfig);
        const result = await sandbox.execute(
          'try { require("path"); return "ESCAPED" } catch { return "BLOCKED" }',
        );
        expect(result.success).toBe(true);
        expect(result.result).toBe('BLOCKED');
      });
    });

    describe('context injection', () => {
      it('injects context variables into execution scope', async () => {
        sandbox = await plugin.create(defaultConfig);
        const result = await sandbox.execute('return x + y', { context: { x: 1, y: 2 } });
        expect(result.success).toBe(true);
        expect(result.result).toBe(3);
      });

      it('context variables are accessible in executed code', async () => {
        sandbox = await plugin.create(defaultConfig);
        const result = await sandbox.execute('return typeof x', { context: { x: 'hello' } });
        expect(result.success).toBe(true);
        expect(result.result).toBe('string');
      });

      // Context leak test only meaningful for in-process plugins that reuse state.
      // Process-level plugins always spawn a fresh process per execute — no leak possible.
      it('context does not leak between executions', async () => {
        sandbox = await plugin.create(defaultConfig);
        // First execution with context
        const first = await sandbox.execute('return x', { context: { x: 42 } });
        expect(first.success).toBe(true);
        expect(first.result).toBe(42);

        // Second execution without context — x should not be defined
        const second = await sandbox.execute('try { return x } catch { return "not defined" }');
        expect(second.success).toBe(true);
        expect(second.result).toBe('not defined');
      });
    });

    describe('host functions', () => {
      // Host function tests require IPC bridge (only available in isolate-level plugins).
      // Process-level plugins (landlock, anthropic-sr) don't have IPC in V1.
      const hostFnIt = plugin.isolationLevel === 'isolate' ? it : it.skip;

      hostFnIt('can call allowlisted host functions via hostCall()', async () => {
        const config: SandboxConfig = {
          ...defaultConfig,
          hostFunctions: {
            greet: async (args) => 'hello ' + (args as { name: string }).name,
          },
        };
        sandbox = await plugin.create(config);
        const result = await sandbox.execute('return await hostCall("greet", { name: "world" })');
        expect(result.success).toBe(true);
        expect(result.result).toBe('hello world');
      });

      hostFnIt('cannot call functions is not available', async () => {
        const config: SandboxConfig = {
          ...defaultConfig,
          hostFunctions: {
            greet: async () => 'hello',
          },
        };
        sandbox = await plugin.create(config);
        const result = await sandbox.execute('return await hostCall("notAllowed", {})');
        expect(result.success).toBe(false);
        expect(typeof result.error === 'string' ? result.error : (result.error as Error).message).toContain('is not available');
      });

      hostFnIt('receives return value from host function', async () => {
        const config: SandboxConfig = {
          ...defaultConfig,
          hostFunctions: {
            add: async (args) => {
              const { a, b } = args as { a: number; b: number };
              return a + b;
            },
          },
        };
        sandbox = await plugin.create(config);
        const result = await sandbox.execute('return await hostCall("add", { a: 10, b: 20 })');
        expect(result.success).toBe(true);
        expect(result.result).toBe(30);
      });

      hostFnIt('receives error from failing host function', async () => {
        const config: SandboxConfig = {
          ...defaultConfig,
          hostFunctions: {
            fail: async () => { throw new Error('host function exploded'); },
          },
        };
        sandbox = await plugin.create(config);
        const result = await sandbox.execute('return await hostCall("fail", {})');
        expect(result.success).toBe(false);
        expect(typeof result.error === 'string' ? result.error : (result.error as Error).message).toContain('host function exploded');
      });
    });
  });
});

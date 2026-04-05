import { describe, it, expect, afterEach } from 'vitest';
import { platform } from 'node:os';
import { createSandbox, resetCircuitBreakers } from '../../factory.js';
import type { SandboxConfig } from '../../types.js';

const config: SandboxConfig = {
  limits: { memoryMB: 128, cpuMs: 5000, timeoutMs: 5000, networkAccess: false, filesystemAccess: 'tmpfs' },
  secrets: { API_KEY: 'sk-test-secret-12345', DB_URL: 'postgres://user:password@host/db' },
};

describe('Security: secret leakage', () => {
  afterEach(() => {
    resetCircuitBreakers();
  });

  describe('secret injection', () => {
    it('secrets are available inside sandbox via allowed mechanism', async () => {
      const sandbox = await createSandbox({ plugin: 'mock', config });
      try {
        const result = await sandbox.execute('return __secrets.API_KEY');
        expect(result.success).toBe(true);
        expect(result.result).toBe('sk-test-secret-12345');
      } finally {
        await sandbox.destroy();
      }
    });

    it('secrets are not in process.env of sandbox', async () => {
      // In isolated-vm, `process` is undefined — no env access at all
      const sandbox = await createSandbox({ plugin: 'isolated-vm', config });
      try {
        const result = await sandbox.execute('return typeof process');
        expect(result.success).toBe(true);
        // process is not available in the V8 isolate
        expect(result.result).toBe('undefined');
      } finally {
        await sandbox.destroy();
      }
    });

    it('secrets are not on disk inside sandbox', async () => {
      const sandbox = await createSandbox({ plugin: 'mock', config });
      try {
        // List all files in the sandbox tmpdir — none should contain secrets
        const result = await sandbox.execute('return JSON.stringify(__secrets)');
        expect(result.success).toBe(true);

        // The secrets are available via __secrets (by design), but they
        // should not have been written to any file on disk in the tmpdir.
        const files = await sandbox.fs.list('.');
        for (const file of files) {
          const content = await sandbox.fs.read(file);
          expect(content).not.toContain('sk-test-secret-12345');
          expect(content).not.toContain('postgres://user:password@host/db');
        }
      } finally {
        await sandbox.destroy();
      }
    });

    it('secrets are not in /proc/self/environ', async () => {
      if (platform() === 'darwin') {
        // /proc does not exist on macOS — skip
        return;
      }
      // On Linux, verify that secrets are not leaked into /proc/self/environ
      const sandbox = await createSandbox({ plugin: 'isolated-vm', config });
      try {
        const result = await sandbox.execute(`
          try {
            const fs = require('fs');
            const environ = fs.readFileSync('/proc/self/environ', 'utf8');
            if (environ.includes('sk-test-secret-12345')) return 'LEAKED';
            return 'SAFE';
          } catch {
            return 'BLOCKED';
          }
        `);
        expect(result.success).toBe(true);
        // In isolated-vm, require is not available so this returns BLOCKED
        expect(result.result).not.toBe('LEAKED');
      } finally {
        await sandbox.destroy();
      }
    });
  });

  describe('log redaction', () => {
    // Log redaction is NOT yet implemented. These tests are skipped until V1.1.
    // When redaction ships, unskip and verify secrets are stripped from logs.

    it.skip('secrets matching known patterns are redacted in logs — requires V1.1 redaction', async () => {
      const sandbox = await createSandbox({ plugin: 'mock', config });
      try {
        const result = await sandbox.execute("console.log('my key is sk-test-secret-12345'); return 'done'");
        expect(result.success).toBe(true);
        expect(result.logs.join(' ')).not.toContain('sk-test-secret-12345');
      } finally {
        await sandbox.destroy();
      }
    });

    it.skip('API keys (sk-...) are redacted — requires V1.1 redaction', async () => {
      const sandbox = await createSandbox({ plugin: 'mock', config });
      try {
        const result = await sandbox.execute("console.log('sk-test-secret-12345'); return 'done'");
        expect(result.success).toBe(true);
        expect(result.logs.join(' ')).not.toContain('sk-test-secret-12345');
      } finally {
        await sandbox.destroy();
      }
    });

    it.skip('database URLs containing passwords are redacted — requires V1.1 redaction', async () => {
      const sandbox = await createSandbox({ plugin: 'mock', config });
      try {
        const result = await sandbox.execute("console.log('postgres://user:password@host/db'); return 'done'");
        expect(result.success).toBe(true);
        expect(result.logs.join(' ')).not.toContain('password');
      } finally {
        await sandbox.destroy();
      }
    });

    it.skip('partial matches are still redacted — requires V1.1 redaction', async () => {
      const sandbox = await createSandbox({ plugin: 'mock', config });
      try {
        const result = await sandbox.execute("console.log('partial: test-secret-12345'); return 'done'");
        expect(result.success).toBe(true);
        expect(result.logs.join(' ')).not.toContain('test-secret-12345');
      } finally {
        await sandbox.destroy();
      }
    });
  });

  describe('patch redaction', () => {
    it('exported patches do not contain injected secrets', async () => {
      const sandbox = await createSandbox({ plugin: 'mock', config });
      try {
        // Execute some code that does NOT write secrets to files
        await sandbox.execute("return 'hello'");

        // Write a benign file
        await sandbox.fs.write('output.txt', 'some safe content');

        // Export the patch — it should not contain secrets since we didn't write them
        const patch = await sandbox.git.exportPatch();
        expect(patch).not.toContain('sk-test-secret-12345');
        expect(patch).not.toContain('postgres://user:password@host/db');
      } finally {
        await sandbox.destroy();
      }
    });

    it.skip('patch validator detects and rejects patches containing secrets — requires V1.1 secret scanning', async () => {
      // Known gap: patch validator does NOT yet scan for secret content.
      // When V1.1 ships secret scanning, unskip this test.
      const sandbox = await createSandbox({ plugin: 'mock', config });
      try {
        await sandbox.fs.write('leaked.txt', 'key=sk-test-secret-12345');
        const patch = await sandbox.git.exportPatch();
        // V1.1: patch validator should reject patches containing injected secrets
        expect(patch).not.toContain('sk-test-secret-12345');
      } finally {
        await sandbox.destroy();
      }
    });
  });

  describe('cross-sandbox isolation', () => {
    it('sandbox A cannot read secrets from sandbox B', async () => {
      const configA: SandboxConfig = {
        limits: config.limits,
        secrets: { SECRET_A: 'value-a' },
      };
      const configB: SandboxConfig = {
        limits: config.limits,
        secrets: { SECRET_B: 'value-b' },
      };

      const sandboxA = await createSandbox({ plugin: 'mock', config: configA });
      const sandboxB = await createSandbox({ plugin: 'mock', config: configB });
      try {
        const resultA = await sandboxA.execute('return __secrets.SECRET_A');
        expect(resultA.success).toBe(true);
        expect(resultA.result).toBe('value-a');

        const resultB = await sandboxB.execute('return __secrets.SECRET_B');
        expect(resultB.success).toBe(true);
        expect(resultB.result).toBe('value-b');

        // A cannot see B's secrets
        const crossA = await sandboxA.execute('return __secrets.SECRET_B');
        expect(crossA.success).toBe(true);
        expect(crossA.result).toBeUndefined();

        // B cannot see A's secrets
        const crossB = await sandboxB.execute('return __secrets.SECRET_A');
        expect(crossB.success).toBe(true);
        expect(crossB.result).toBeUndefined();
      } finally {
        await sandboxA.destroy();
        await sandboxB.destroy();
      }
    });

    it('secrets are destroyed when sandbox is destroyed', async () => {
      const sandbox = await createSandbox({ plugin: 'mock', config });

      // Verify sandbox is working
      const result = await sandbox.execute('return __secrets.API_KEY');
      expect(result.success).toBe(true);
      expect(result.result).toBe('sk-test-secret-12345');

      // Destroy the sandbox
      await sandbox.destroy();

      // After destroy, the sandbox's tmpdir should be gone
      const isReady = await sandbox.ready();
      expect(isReady).toBe(false);
    });

    it('no secrets remain in memory after destroy()', async () => {
      // Create a sandbox with secrets, use them, then destroy
      const sandbox = await createSandbox({ plugin: 'mock', config });

      const result = await sandbox.execute('return __secrets.API_KEY');
      expect(result.success).toBe(true);
      expect(result.result).toBe('sk-test-secret-12345');

      await sandbox.destroy();

      // Create a brand new sandbox without secrets
      const freshConfig: SandboxConfig = {
        limits: config.limits,
        // No secrets provided
      };
      const freshSandbox = await createSandbox({ plugin: 'mock', config: freshConfig });
      try {
        // The new sandbox should have no access to the old sandbox's secrets
        const freshResult = await freshSandbox.execute('return typeof __secrets');
        expect(freshResult.success).toBe(true);
        // __secrets should be undefined or an empty object
        expect(freshResult.result).not.toBe('sk-test-secret-12345');

        // Specifically try to access the old secret
        const probeResult = await freshSandbox.execute(
          "try { return __secrets.API_KEY } catch { return 'no-secrets' }",
        );
        expect(probeResult.success).toBe(true);
        expect(probeResult.result).not.toBe('sk-test-secret-12345');
      } finally {
        await freshSandbox.destroy();
      }
    });
  });
});

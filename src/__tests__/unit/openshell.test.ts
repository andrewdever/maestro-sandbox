import { describe, it, expect } from 'vitest';
import openshellPlugin, {
  buildPolicy,
  policyToYaml,
  OPENSHELL_VERSION,
  CREATE_TIMEOUT_MS,
  MAX_IDLE_MEMORY_MB,
} from '../../plugins/openshell.js';
import type { SandboxConfig } from '../../types.js';

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

function defaultConfig(overrides: Partial<SandboxConfig> = {}): SandboxConfig {
  return {
    limits: {
      memoryMB: 128,
      cpuMs: 5000,
      timeoutMs: 5000,
      networkAccess: false,
      filesystemAccess: 'tmpfs',
    },
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Plugin metadata
// ---------------------------------------------------------------------------

describe('OpenShell plugin', () => {
  describe('metadata', () => {
    it('has correct name', () => {
      expect(openshellPlugin.name).toBe('openshell');
    });

    it('has semver version', () => {
      expect(openshellPlugin.version).toMatch(/^\d+\.\d+\.\d+/);
    });

    it('has container isolation level', () => {
      expect(openshellPlugin.isolationLevel).toBe('container');
    });

    it('has a required core version', () => {
      expect(openshellPlugin.requiredCoreVersion).toBeTruthy();
    });
  });

  // ---------------------------------------------------------------------------
  // Constants
  // ---------------------------------------------------------------------------

  describe('constants', () => {
    it('pins OpenShell version (no floating tags)', () => {
      expect(OPENSHELL_VERSION).toMatch(/^\d+\.\d+\.\d+$/);
    });

    it('creation timeout allows for K3s pod scheduling', () => {
      expect(CREATE_TIMEOUT_MS).toBeGreaterThanOrEqual(15_000);
    });

    it('max idle memory matches tech review threshold', () => {
      expect(MAX_IDLE_MEMORY_MB).toBe(512);
    });
  });

  // ---------------------------------------------------------------------------
  // Policy generation
  // ---------------------------------------------------------------------------

  describe('buildPolicy', () => {
    it('generates 4-layer policy from SandboxConfig', () => {
      const policy = buildPolicy(defaultConfig());
      expect(policy.filesystem).toBeDefined();
      expect(policy.network).toBeDefined();
      expect(policy.process).toBeDefined();
      expect(policy.inference).toBeDefined();
    });

    it('sets filesystem read-only when filesystemAccess is readonly', () => {
      const policy = buildPolicy(defaultConfig({
        limits: { memoryMB: 128, cpuMs: 5000, timeoutMs: 5000, networkAccess: false, filesystemAccess: 'readonly' },
      }));
      expect(policy.filesystem.readOnly).toBe(true);
    });

    it('sets filesystem read-only when filesystemAccess is none', () => {
      const policy = buildPolicy(defaultConfig({
        limits: { memoryMB: 128, cpuMs: 5000, timeoutMs: 5000, networkAccess: false, filesystemAccess: 'none' },
      }));
      expect(policy.filesystem.readOnly).toBe(true);
      expect(policy.filesystem.tmpfsMounts).toHaveLength(0);
    });

    it('mounts tmpfs overlays with read-only root when filesystemAccess is tmpfs', () => {
      const policy = buildPolicy(defaultConfig());
      expect(policy.filesystem.readOnly).toBe(true);
      expect(policy.filesystem.tmpfsMounts.length).toBeGreaterThan(0);
    });

    it('sets network egress to none when networkAccess is false', () => {
      const policy = buildPolicy(defaultConfig());
      expect(policy.network.egress).toBe('none');
      expect(policy.network.dnsPolicy).toBe('none');
    });

    it('sets network egress to filtered when networkAccess is true', () => {
      const policy = buildPolicy(defaultConfig({
        limits: { memoryMB: 128, cpuMs: 5000, timeoutMs: 5000, networkAccess: true, filesystemAccess: 'tmpfs' },
      }));
      expect(policy.network.egress).toBe('filtered');
      expect(policy.network.dnsPolicy).toBe('restricted');
    });

    it('passes through allowed hosts from network config', () => {
      const policy = buildPolicy(defaultConfig({
        limits: { memoryMB: 128, cpuMs: 5000, timeoutMs: 5000, networkAccess: true, filesystemAccess: 'tmpfs' },
        network: { allowedPeers: ['api.example.com', 'cdn.example.com'] },
      }));
      expect(policy.network.allowedHosts).toEqual(['api.example.com', 'cdn.example.com']);
    });

    it('drops all capabilities (NemoClaw pattern)', () => {
      const policy = buildPolicy(defaultConfig());
      expect(policy.process.capabilities).toEqual([]);
    });

    it('enforces strict seccomp', () => {
      const policy = buildPolicy(defaultConfig());
      expect(policy.process.seccomp).toBe('strict');
    });

    it('sets noNewPrivileges to true', () => {
      const policy = buildPolicy(defaultConfig());
      expect(policy.process.noNewPrivileges).toBe(true);
    });

    it('enables Privacy Router by default', () => {
      const policy = buildPolicy(defaultConfig());
      expect(policy.inference.privacyRouter).toBe(true);
      expect(policy.inference.stripCredentials).toBe(true);
    });

    it('limits PIDs to 64', () => {
      const policy = buildPolicy(defaultConfig());
      expect(policy.process.pidsLimit).toBe(64);
    });
  });

  // ---------------------------------------------------------------------------
  // YAML serialization
  // ---------------------------------------------------------------------------

  describe('policyToYaml', () => {
    it('generates valid YAML with all 4 sections', () => {
      const policy = buildPolicy(defaultConfig());
      const yaml = policyToYaml(policy);

      expect(yaml).toContain('filesystem:');
      expect(yaml).toContain('network:');
      expect(yaml).toContain('process:');
      expect(yaml).toContain('inference:');
    });

    it('includes auto-generated header', () => {
      const policy = buildPolicy(defaultConfig());
      const yaml = policyToYaml(policy);
      expect(yaml).toContain('# Auto-generated by maestro');
    });

    it('serializes filesystem settings correctly', () => {
      const policy = buildPolicy(defaultConfig());
      const yaml = policyToYaml(policy);
      expect(yaml).toContain('read_only: true');
      expect(yaml).toContain('tmpfs_mounts:');
      expect(yaml).toContain('/sandbox');
    });

    it('serializes network egress none', () => {
      const policy = buildPolicy(defaultConfig());
      const yaml = policyToYaml(policy);
      expect(yaml).toContain('egress: none');
      expect(yaml).toContain('dns_policy: none');
    });

    it('serializes allowed_hosts when present', () => {
      const policy = buildPolicy(defaultConfig({
        limits: { memoryMB: 128, cpuMs: 5000, timeoutMs: 5000, networkAccess: true, filesystemAccess: 'tmpfs' },
        network: { allowedPeers: ['api.example.com'] },
      }));
      const yaml = policyToYaml(policy);
      expect(yaml).toContain('allowed_hosts:');
      expect(yaml).toContain('api.example.com');
    });

    it('omits allowed_hosts when empty', () => {
      const policy = buildPolicy(defaultConfig());
      const yaml = policyToYaml(policy);
      expect(yaml).not.toContain('allowed_hosts:');
    });

    it('serializes process security settings', () => {
      const policy = buildPolicy(defaultConfig());
      const yaml = policyToYaml(policy);
      expect(yaml).toContain('capabilities: []');
      expect(yaml).toContain('seccomp: strict');
      expect(yaml).toContain('pids_limit: 64');
      expect(yaml).toContain('no_new_privileges: true');
    });

    it('serializes inference settings', () => {
      const policy = buildPolicy(defaultConfig());
      const yaml = policyToYaml(policy);
      expect(yaml).toContain('privacy_router: true');
      expect(yaml).toContain('strip_credentials: true');
    });

    it('serializes allowed_providers when present', () => {
      const policy = buildPolicy(defaultConfig());
      policy.inference.allowedProviders = ['anthropic', 'openai'];
      const yaml = policyToYaml(policy);
      expect(yaml).toContain('allowed_providers:');
      expect(yaml).toContain('anthropic');
      expect(yaml).toContain('openai');
    });
  });

  // ---------------------------------------------------------------------------
  // create() error handling (without OpenShell CLI)
  // ---------------------------------------------------------------------------

  describe('create()', () => {
    it('throws SandboxCrashError when openshell CLI is not available', async () => {
      await expect(openshellPlugin.create(defaultConfig())).rejects.toThrow(
        /OpenShell CLI is not available/,
      );
    });

    it('throws SandboxCrashError when hostFunctions are provided', async () => {
      const config = defaultConfig({
        hostFunctions: {
          fetch: { handler: async () => ({}), schema: undefined },
        },
      });
      await expect(openshellPlugin.create(config)).rejects.toThrow(
        /does not support hostFunctions/,
      );
    });
  });
});

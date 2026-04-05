import { describe, it, expect } from 'vitest';
import {
  validateTenantId,
  namespaceSandboxId,
  extractTenantId,
  extractSandboxId,
  sameTenant,
  tenantScopedKey,
  breachCounterKey,
  assertTenantId,
  ISOLATION_TIER,
} from '../../tenant.js';
import { createMeshFirewall, type MeshMessage } from '../../mesh-firewall.js';
import { createMessage, InstructionPrivilege } from '../../instruction-hierarchy.js';
import { createAuditLogger } from '../../audit.js';

describe('Tenant Utilities', () => {
  // -------------------------------------------------------------------------
  // validateTenantId
  // -------------------------------------------------------------------------

  describe('validateTenantId', () => {
    it('accepts valid tenant IDs', () => {
      const valid = ['abc', 'tenant-one', 'my-org-123', 'a1b', 'acme', 'a'.repeat(63)];
      for (const id of valid) {
        expect(validateTenantId(id), `expected "${id}" to be valid`).toEqual({ valid: true });
      }
    });

    it('rejects IDs shorter than 3 characters', () => {
      expect(validateTenantId('ab').valid).toBe(false);
      expect(validateTenantId('ab').error).toContain('too short');
      expect(validateTenantId('a').valid).toBe(false);
      expect(validateTenantId('').valid).toBe(false);
    });

    it('rejects IDs longer than 63 characters', () => {
      const result = validateTenantId('a'.repeat(64));
      expect(result.valid).toBe(false);
      expect(result.error).toContain('too long');
    });

    it('rejects IDs starting with a hyphen', () => {
      const result = validateTenantId('-abc');
      expect(result.valid).toBe(false);
      expect(result.error).toContain('start with a hyphen');
    });

    it('rejects IDs ending with a hyphen', () => {
      const result = validateTenantId('abc-');
      expect(result.valid).toBe(false);
      expect(result.error).toContain('end with a hyphen');
    });

    it('rejects IDs with consecutive hyphens', () => {
      const result = validateTenantId('abc--def');
      expect(result.valid).toBe(false);
      expect(result.error).toContain('consecutive hyphens');
    });

    it('rejects IDs with uppercase characters', () => {
      const result = validateTenantId('Abc');
      expect(result.valid).toBe(false);
    });

    it('rejects IDs starting with a digit', () => {
      const result = validateTenantId('1abc');
      expect(result.valid).toBe(false);
    });

    it('rejects IDs with special characters', () => {
      const invalid = ['abc_def', 'abc.def', 'abc@def', 'abc def', 'abc/def'];
      for (const id of invalid) {
        expect(validateTenantId(id).valid, `expected "${id}" to be invalid`).toBe(false);
      }
    });

    it('boundary: exactly 3 characters', () => {
      expect(validateTenantId('abc').valid).toBe(true);
    });

    it('boundary: exactly 63 characters', () => {
      expect(validateTenantId('a'.repeat(63)).valid).toBe(true);
    });
  });

  // -------------------------------------------------------------------------
  // namespaceSandboxId / extractTenantId / extractSandboxId
  // -------------------------------------------------------------------------

  describe('namespaceSandboxId', () => {
    it('creates a namespaced ID', () => {
      expect(namespaceSandboxId('acme', 'sbx_000001')).toBe('acme:sbx_000001');
    });

    it('throws on invalid tenant ID', () => {
      expect(() => namespaceSandboxId('AB', 'sbx_1')).toThrow('Invalid tenant ID');
    });
  });

  describe('extractTenantId', () => {
    it('extracts tenant from namespaced ID', () => {
      expect(extractTenantId('acme:sbx_000001')).toBe('acme');
    });

    it('returns undefined for non-namespaced ID', () => {
      expect(extractTenantId('sbx_000001')).toBeUndefined();
    });

    it('returns undefined if prefix is not a valid tenant ID', () => {
      expect(extractTenantId('AB:sbx_000001')).toBeUndefined();
    });
  });

  describe('extractSandboxId', () => {
    it('extracts bare sandbox ID from namespaced ID', () => {
      expect(extractSandboxId('acme:sbx_000001')).toBe('sbx_000001');
    });

    it('returns the full ID if not namespaced', () => {
      expect(extractSandboxId('sbx_000001')).toBe('sbx_000001');
    });
  });

  // -------------------------------------------------------------------------
  // sameTenant
  // -------------------------------------------------------------------------

  describe('sameTenant', () => {
    it('returns true for same tenant', () => {
      expect(sameTenant('acme:sbx_001', 'acme:sbx_002')).toBe(true);
    });

    it('returns false for different tenants', () => {
      expect(sameTenant('acme:sbx_001', 'globex:sbx_002')).toBe(false);
    });

    it('returns false if either ID is not namespaced', () => {
      expect(sameTenant('sbx_001', 'acme:sbx_002')).toBe(false);
      expect(sameTenant('acme:sbx_001', 'sbx_002')).toBe(false);
    });

    it('returns false if neither ID is namespaced', () => {
      expect(sameTenant('sbx_001', 'sbx_002')).toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  // tenantScopedKey
  // -------------------------------------------------------------------------

  describe('tenantScopedKey', () => {
    it('creates a scoped key', () => {
      expect(tenantScopedKey('acme', 'rate-limit')).toBe('acme:rate-limit');
    });

    it('is consistent: same inputs produce same key', () => {
      const k1 = tenantScopedKey('acme', 'counter');
      const k2 = tenantScopedKey('acme', 'counter');
      expect(k1).toBe(k2);
    });

    it('different tenants produce different keys', () => {
      const k1 = tenantScopedKey('acme', 'counter');
      const k2 = tenantScopedKey('globex', 'counter');
      expect(k1).not.toBe(k2);
    });

    it('throws on invalid tenant ID', () => {
      expect(() => tenantScopedKey('AB', 'key')).toThrow('Invalid tenant ID');
    });
  });

  // -------------------------------------------------------------------------
  // breachCounterKey
  // -------------------------------------------------------------------------

  describe('breachCounterKey', () => {
    it('creates a breach counter key', () => {
      expect(breachCounterKey('permission-error-spike', 'acme:sbx_001')).toBe(
        'permission-error-spike::acme:sbx_001',
      );
    });

    it('uses :: separator to avoid collision with namespaced IDs', () => {
      const key = breachCounterKey('signal', 'tenant:sbx_1');
      // The breach separator is '::' which does not collide with the ':' in namespaced IDs
      expect(key).toBe('signal::tenant:sbx_1');
      expect(key.split('::').length).toBe(2);
    });

    it('is consistent: same inputs produce same key', () => {
      const k1 = breachCounterKey('signal', 'acme:sbx_001');
      const k2 = breachCounterKey('signal', 'acme:sbx_001');
      expect(k1).toBe(k2);
    });
  });

  // -------------------------------------------------------------------------
  // assertTenantId
  // -------------------------------------------------------------------------

  describe('assertTenantId', () => {
    it('passes for valid tenantId', () => {
      expect(() => assertTenantId({ tenantId: 'acme' })).not.toThrow();
    });

    it('throws for missing tenantId', () => {
      expect(() => assertTenantId({})).toThrow('Missing tenantId');
    });

    it('throws for undefined tenantId', () => {
      expect(() => assertTenantId({ tenantId: undefined })).toThrow('Missing tenantId');
    });

    it('throws for invalid tenantId format', () => {
      expect(() => assertTenantId({ tenantId: 'AB' })).toThrow('Invalid tenantId');
    });

    it('includes context in error message', () => {
      expect(() => assertTenantId({}, 'AuditEvent')).toThrow('in AuditEvent');
    });
  });

  // -------------------------------------------------------------------------
  // ISOLATION_TIER
  // -------------------------------------------------------------------------

  describe('ISOLATION_TIER', () => {
    it('marks current tier as namespace', () => {
      expect(ISOLATION_TIER.current).toBe('namespace');
    });

    it('is not HIPAA-eligible', () => {
      expect(ISOLATION_TIER.hipaaEligible).toBe(false);
    });

    it('marks dedicated isolation as P2-planned', () => {
      expect(ISOLATION_TIER.dedicatedIsolationStatus).toBe('P2-planned');
    });
  });

  // -------------------------------------------------------------------------
  // createMessage with tenantId
  // -------------------------------------------------------------------------

  describe('createMessage tenantId propagation', () => {
    it('propagates tenantId through createMessage options', () => {
      const msg = createMessage(
        'hello',
        InstructionPrivilege.AGENT,
        'test',
        { tenantId: 'acme' },
      );
      expect(msg.tenantId).toBe('acme');
    });

    it('creates message without tenantId (backward compatible)', () => {
      const msg = createMessage('hello', InstructionPrivilege.AGENT, 'test');
      expect(msg.tenantId).toBeUndefined();
    });
  });

  // -------------------------------------------------------------------------
  // Cross-tenant mesh denial
  // -------------------------------------------------------------------------

  describe('cross-tenant mesh denial', () => {
    function makeMessage(overrides: Partial<MeshMessage> = {}): MeshMessage {
      return {
        type: 'data',
        from: 'acme:sbx_001',
        to: 'acme:sbx_002',
        payload: 'hello',
        timestamp: new Date().toISOString(),
        ...overrides,
      };
    }

    it('allows same-tenant messages', () => {
      const firewall = createMeshFirewall();
      const result = firewall.send(makeMessage());
      expect(result.allowed).toBe(true);
    });

    it('blocks cross-tenant messages by default', () => {
      const firewall = createMeshFirewall();
      const result = firewall.send(makeMessage({
        from: 'acme:sbx_001',
        to: 'globex:sbx_002',
      }));
      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('cross-tenant mesh denied');
    });

    it('allows cross-tenant messages in the allowlist', () => {
      const firewall = createMeshFirewall({
        allowedCrossTenantMesh: [{ from: 'acme', to: 'globex' }],
      });
      const result = firewall.send(makeMessage({
        from: 'acme:sbx_001',
        to: 'globex:sbx_002',
      }));
      expect(result.allowed).toBe(true);
    });

    it('blocks cross-tenant messages not in the allowlist (directional)', () => {
      const firewall = createMeshFirewall({
        allowedCrossTenantMesh: [{ from: 'acme', to: 'globex' }],
      });
      // Reverse direction is NOT allowed
      const result = firewall.send(makeMessage({
        from: 'globex:sbx_001',
        to: 'acme:sbx_002',
      }));
      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('cross-tenant mesh denied');
    });

    it('allows messages when either ID has no tenant prefix (single-tenant mode)', () => {
      const firewall = createMeshFirewall();

      // from has no tenant prefix
      const r1 = firewall.send(makeMessage({ from: 'sbx_001', to: 'acme:sbx_002' }));
      expect(r1.allowed).toBe(true);

      // to has no tenant prefix
      const r2 = firewall.send(makeMessage({ from: 'acme:sbx_001', to: 'sbx_002' }));
      expect(r2.allowed).toBe(true);

      // neither has tenant prefix
      const r3 = firewall.send(makeMessage({ from: 'sbx_001', to: 'sbx_002' }));
      expect(r3.allowed).toBe(true);
    });

    it('emits mesh.message.blocked audit event for cross-tenant denial', () => {
      const logger = createAuditLogger({ emit: false, store: true });
      const firewall = createMeshFirewall({ auditLogger: logger });

      firewall.send(makeMessage({
        from: 'acme:sbx_001',
        to: 'globex:sbx_002',
      }));

      expect(logger.events).toHaveLength(1);
      expect(logger.events[0].event).toBe('mesh.message.blocked');
      expect(logger.events[0].data['reason']).toBe('cross-tenant mesh denied');
      expect(logger.events[0].data['fromTenant']).toBe('acme');
      expect(logger.events[0].data['toTenant']).toBe('globex');
    });
  });
});

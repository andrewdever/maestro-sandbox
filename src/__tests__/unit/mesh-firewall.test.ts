import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  createMeshFirewall,
  type MeshMessage,
  type MeshFirewallConfig,
} from '../../mesh-firewall.js';
import { createAuditLogger } from '../../audit.js';

describe('MeshFirewall', () => {
  function makeMessage(overrides: Partial<MeshMessage> = {}): MeshMessage {
    return {
      type: 'data',
      from: 'sbx_001',
      to: 'sbx_002',
      payload: 'hello from sandbox 1',
      timestamp: new Date().toISOString(),
      ...overrides,
    };
  }

  describe('message type validation', () => {
    it('allows valid message types', () => {
      const firewall = createMeshFirewall();

      for (const type of ['data', 'status', 'request', 'response'] as const) {
        const result = firewall.send(makeMessage({ type }));
        expect(result.allowed, `type "${type}" should be allowed`).toBe(true);
      }
    });

    it('blocks invalid message types', () => {
      const firewall = createMeshFirewall();
      const result = firewall.send(makeMessage({ type: 'execute' as any }));

      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('Invalid message type');
    });
  });

  describe('rate limiting', () => {
    it('allows messages within the rate limit', () => {
      const firewall = createMeshFirewall({ maxMessagesPerMinute: 5 });

      for (let i = 0; i < 5; i++) {
        const result = firewall.send(makeMessage());
        expect(result.allowed).toBe(true);
      }
    });

    it('blocks messages exceeding the rate limit', () => {
      const firewall = createMeshFirewall({ maxMessagesPerMinute: 3 });

      for (let i = 0; i < 3; i++) {
        firewall.send(makeMessage());
      }

      const result = firewall.send(makeMessage());
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('Rate limit exceeded');
    });

    it('tracks rate limits per sandbox', () => {
      const firewall = createMeshFirewall({ maxMessagesPerMinute: 2 });

      // sbx_001 sends 2 messages (at limit)
      firewall.send(makeMessage({ from: 'sbx_001' }));
      firewall.send(makeMessage({ from: 'sbx_001' }));

      // sbx_002 should still be able to send
      const result = firewall.send(makeMessage({ from: 'sbx_002' }));
      expect(result.allowed).toBe(true);

      // sbx_001 should be blocked
      const blocked = firewall.send(makeMessage({ from: 'sbx_001' }));
      expect(blocked.allowed).toBe(false);
    });

    it('resets counters via resetCounters()', () => {
      const firewall = createMeshFirewall({ maxMessagesPerMinute: 1 });

      firewall.send(makeMessage());
      const blocked = firewall.send(makeMessage());
      expect(blocked.allowed).toBe(false);

      firewall.resetCounters();

      const afterReset = firewall.send(makeMessage());
      expect(afterReset.allowed).toBe(true);
    });

    it('defaults to 30 messages per minute', () => {
      const firewall = createMeshFirewall();

      for (let i = 0; i < 30; i++) {
        const result = firewall.send(makeMessage());
        expect(result.allowed).toBe(true);
      }

      const result = firewall.send(makeMessage());
      expect(result.allowed).toBe(false);
    });
  });

  describe('executable content blocking', () => {
    it('blocks eval() in payload', () => {
      const firewall = createMeshFirewall();
      const result = firewall.send(makeMessage({ payload: 'eval("alert(1)")' }));

      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('Executable content detected');
    });

    it('blocks require() in payload', () => {
      const firewall = createMeshFirewall();
      const result = firewall.send(makeMessage({ payload: 'require("fs")' }));

      expect(result.allowed).toBe(false);
    });

    it('blocks Function() constructor', () => {
      const firewall = createMeshFirewall();
      const result = firewall.send(makeMessage({ payload: 'new Function("return 1")' }));

      expect(result.allowed).toBe(false);
    });

    it('blocks <script> tags', () => {
      const firewall = createMeshFirewall();
      const result = firewall.send(makeMessage({ payload: '<script>alert(1)</script>' }));

      expect(result.allowed).toBe(false);
    });

    it('blocks javascript: URIs', () => {
      const firewall = createMeshFirewall();
      const result = firewall.send(makeMessage({ payload: 'javascript:alert(1)' }));

      expect(result.allowed).toBe(false);
    });

    it('blocks child_process references', () => {
      const firewall = createMeshFirewall();
      const result = firewall.send(makeMessage({ payload: 'child_process.exec("ls")' }));

      expect(result.allowed).toBe(false);
    });

    it('allows clean text payloads', () => {
      const firewall = createMeshFirewall();
      const result = firewall.send(makeMessage({ payload: 'The analysis is complete. Result: 42.' }));

      expect(result.allowed).toBe(true);
    });

    it('supports custom blocked patterns', () => {
      const firewall = createMeshFirewall({
        blockedContentPatterns: [/FORBIDDEN_WORD/],
      });
      const result = firewall.send(makeMessage({ payload: 'contains FORBIDDEN_WORD here' }));

      expect(result.allowed).toBe(false);
    });
  });

  describe('privilege downgrade and spotlighting', () => {
    it('applies spotlighting to the payload', () => {
      const firewall = createMeshFirewall();
      const result = firewall.send(makeMessage({ payload: 'important data' }));

      expect(result.allowed).toBe(true);
      expect(result.message).toBeDefined();
      // Spotlighting adds boundary markers for PEER_AGENT content
      expect(result.message!.payload).toContain('PEER_AGENT');
      expect(result.message!.payload).toContain('important data');
    });

    it('preserves message metadata in the result', () => {
      const firewall = createMeshFirewall();
      const msg = makeMessage({ type: 'status', from: 'sbx_A', to: 'sbx_B' });
      const result = firewall.send(msg);

      expect(result.allowed).toBe(true);
      expect(result.message!.type).toBe('status');
      expect(result.message!.from).toBe('sbx_A');
      expect(result.message!.to).toBe('sbx_B');
    });

    it('uses custom spotlight config', () => {
      const firewall = createMeshFirewall({
        spotlightConfig: { strategy: 'xml-tag' },
      });
      const result = firewall.send(makeMessage({ payload: 'data' }));

      expect(result.allowed).toBe(true);
      expect(result.message!.payload).toMatch(/<maestro-data-[a-f0-9]+/);
    });
  });

  describe('audit logging', () => {
    it('logs mesh.message.blocked for invalid type', () => {
      const logger = createAuditLogger({ emit: false, store: true });
      const firewall = createMeshFirewall({ auditLogger: logger });

      firewall.send(makeMessage({ type: 'execute' as any }));

      expect(logger.events).toHaveLength(1);
      expect(logger.events[0].event).toBe('mesh.message.blocked');
    });

    it('logs mesh.message.blocked for rate limit', () => {
      const logger = createAuditLogger({ emit: false, store: true });
      const firewall = createMeshFirewall({ maxMessagesPerMinute: 1, auditLogger: logger });

      firewall.send(makeMessage());
      firewall.send(makeMessage());

      expect(logger.events).toHaveLength(1);
      expect(logger.events[0].event).toBe('mesh.message.blocked');
    });

    it('logs mesh.coercion.detected for executable content', () => {
      const logger = createAuditLogger({ emit: false, store: true });
      const firewall = createMeshFirewall({ auditLogger: logger });

      firewall.send(makeMessage({ payload: 'eval("pwned")' }));

      expect(logger.events).toHaveLength(1);
      expect(logger.events[0].event).toBe('mesh.coercion.detected');
    });

    it('does not log for allowed messages', () => {
      const logger = createAuditLogger({ emit: false, store: true });
      const firewall = createMeshFirewall({ auditLogger: logger });

      firewall.send(makeMessage());

      expect(logger.events).toHaveLength(0);
    });
  });

  describe('payload length limit (ReDoS prevention)', () => {
    it('blocks payloads exceeding MAX_PAYLOAD_LENGTH', () => {
      const firewall = createMeshFirewall();
      const hugePayload = 'a'.repeat(100_001);
      const result = firewall.send(makeMessage({ payload: hugePayload }));

      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('maximum length');
    });

    it('allows payloads at exactly MAX_PAYLOAD_LENGTH', () => {
      const firewall = createMeshFirewall();
      const payload = 'a'.repeat(100_000);
      const result = firewall.send(makeMessage({ payload }));

      expect(result.allowed).toBe(true);
    });

    it('logs audit event for oversized payloads', () => {
      const logger = createAuditLogger({ emit: false, store: true });
      const firewall = createMeshFirewall({ auditLogger: logger });

      firewall.send(makeMessage({ payload: 'x'.repeat(100_001) }));

      expect(logger.events).toHaveLength(1);
      expect(logger.events[0].event).toBe('mesh.message.blocked');
      expect(logger.events[0].data['payloadLength']).toBe(100_001);
    });
  });
});

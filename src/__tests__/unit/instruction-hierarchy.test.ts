import { describe, it, expect } from 'vitest';
import {
  InstructionPrivilege,
  canOverride,
  resolveConflict,
  createMessage,
  downgradePrivilege,
  enforceOperatorPolicy,
  resolveTrustSubLevel,
  type ProvenancedMessage,
  type OperatorPolicy,
} from '../../instruction-hierarchy.js';

describe('InstructionHierarchy', () => {
  describe('InstructionPrivilege enum', () => {
    it('has 8 levels in correct order', () => {
      expect(InstructionPrivilege.SYSTEM).toBe(0);
      expect(InstructionPrivilege.OPERATOR).toBe(1);
      expect(InstructionPrivilege.SUPERVISOR).toBe(2);
      expect(InstructionPrivilege.AGENT).toBe(3);
      expect(InstructionPrivilege.TOOL_OUTPUT).toBe(4);
      expect(InstructionPrivilege.PEER_AGENT).toBe(5);
      expect(InstructionPrivilege.USER_INPUT).toBe(6);
      expect(InstructionPrivilege.INTERNET).toBe(7);
    });

    it('lower number = higher privilege', () => {
      expect(InstructionPrivilege.SYSTEM).toBeLessThan(InstructionPrivilege.OPERATOR);
      expect(InstructionPrivilege.OPERATOR).toBeLessThan(InstructionPrivilege.AGENT);
      expect(InstructionPrivilege.AGENT).toBeLessThan(InstructionPrivilege.INTERNET);
    });
  });

  describe('canOverride', () => {
    it('higher privilege can override lower privilege', () => {
      expect(canOverride(InstructionPrivilege.SYSTEM, InstructionPrivilege.AGENT)).toBe(true);
      expect(canOverride(InstructionPrivilege.OPERATOR, InstructionPrivilege.USER_INPUT)).toBe(true);
    });

    it('lower privilege cannot override higher privilege', () => {
      expect(canOverride(InstructionPrivilege.AGENT, InstructionPrivilege.SYSTEM)).toBe(false);
      expect(canOverride(InstructionPrivilege.INTERNET, InstructionPrivilege.OPERATOR)).toBe(false);
    });

    it('equal privilege cannot override', () => {
      expect(canOverride(InstructionPrivilege.AGENT, InstructionPrivilege.AGENT)).toBe(false);
    });
  });

  describe('resolveConflict', () => {
    const msgA = createMessage('A', InstructionPrivilege.OPERATOR, 'config');
    const msgB = createMessage('B', InstructionPrivilege.USER_INPUT, 'user');

    it('returns higher privilege message', () => {
      expect(resolveConflict(msgA, msgB)).toBe(msgA);
      expect(resolveConflict(msgB, msgA)).toBe(msgA);
    });

    it('returns first message when equal privilege', () => {
      const msg1 = createMessage('1', InstructionPrivilege.AGENT, 'a');
      const msg2 = createMessage('2', InstructionPrivilege.AGENT, 'b');
      expect(resolveConflict(msg1, msg2)).toBe(msg1);
    });
  });

  describe('createMessage', () => {
    it('creates a message with timestamp', () => {
      const msg = createMessage('hello', InstructionPrivilege.AGENT, 'test');
      expect(msg.content).toBe('hello');
      expect(msg.privilege).toBe(InstructionPrivilege.AGENT);
      expect(msg.source).toBe('test');
      expect(msg.timestamp).toBeTruthy();
    });

    it('accepts optional sandboxId and sessionId', () => {
      const msg = createMessage('hi', InstructionPrivilege.TOOL_OUTPUT, 'src', {
        sandboxId: 'sbx_000001',
        sessionId: 'sess_1',
      });
      expect(msg.sandboxId).toBe('sbx_000001');
      expect(msg.sessionId).toBe('sess_1');
    });
  });

  describe('downgradePrivilege', () => {
    it('downgrades to lower privilege', () => {
      const msg = createMessage('data', InstructionPrivilege.AGENT, 'agent');
      const downgraded = downgradePrivilege(msg, InstructionPrivilege.TOOL_OUTPUT);
      expect(downgraded.privilege).toBe(InstructionPrivilege.TOOL_OUTPUT);
      expect(downgraded.source).toContain('downgraded from AGENT');
    });

    it('cannot elevate privilege', () => {
      const msg = createMessage('data', InstructionPrivilege.USER_INPUT, 'user');
      const result = downgradePrivilege(msg, InstructionPrivilege.SYSTEM);
      expect(result.privilege).toBe(InstructionPrivilege.USER_INPUT);
      expect(result).toBe(msg); // Same object returned
    });

    it('returns same message when downgrading to same level', () => {
      const msg = createMessage('data', InstructionPrivilege.AGENT, 'agent');
      const result = downgradePrivilege(msg, InstructionPrivilege.AGENT);
      expect(result).toBe(msg);
    });
  });

  describe('enforceOperatorPolicy', () => {
    const policy: OperatorPolicy = {
      blockedPatterns: ['password', 'secret_key=\\w+'],
    };

    it('allows messages without blocked patterns', () => {
      const msg = createMessage('hello world', InstructionPrivilege.USER_INPUT, 'user');
      expect(enforceOperatorPolicy(msg, policy)).toEqual({ allowed: true });
    });

    it('blocks messages matching blocked patterns', () => {
      const msg = createMessage('my password is 123', InstructionPrivilege.USER_INPUT, 'user');
      const result = enforceOperatorPolicy(msg, policy);
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('password');
    });

    it('never blocks SYSTEM or OPERATOR messages', () => {
      const sysMsg = createMessage('password', InstructionPrivilege.SYSTEM, 'sys');
      expect(enforceOperatorPolicy(sysMsg, policy)).toEqual({ allowed: true });

      const opMsg = createMessage('password', InstructionPrivilege.OPERATOR, 'op');
      expect(enforceOperatorPolicy(opMsg, policy)).toEqual({ allowed: true });
    });

    it('allows when no blocked patterns are configured', () => {
      const msg = createMessage('anything', InstructionPrivilege.USER_INPUT, 'user');
      expect(enforceOperatorPolicy(msg, {})).toEqual({ allowed: true });
    });

    it('skips invalid regex patterns without crashing', () => {
      const badPolicy: OperatorPolicy = {
        blockedPatterns: ['[unclosed', 'password', '(invalid('],
      };
      const msg = createMessage('my password is 123', InstructionPrivilege.USER_INPUT, 'user');
      // Should still match the valid "password" pattern
      const result = enforceOperatorPolicy(msg, badPolicy);
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('password');
    });

    it('does not crash on all invalid patterns', () => {
      const badPolicy: OperatorPolicy = {
        blockedPatterns: ['[bad', '(worse('],
      };
      const msg = createMessage('hello', InstructionPrivilege.USER_INPUT, 'user');
      expect(enforceOperatorPolicy(msg, badPolicy)).toEqual({ allowed: true });
    });
  });

  describe('resolveTrustSubLevel', () => {
    it('returns null for SYSTEM privilege', () => {
      expect(resolveTrustSubLevel(InstructionPrivilege.SYSTEM)).toBeNull();
    });

    it('returns null for OPERATOR privilege', () => {
      expect(resolveTrustSubLevel(InstructionPrivilege.OPERATOR)).toBeNull();
    });

    it('returns null for SUPERVISOR privilege', () => {
      expect(resolveTrustSubLevel(InstructionPrivilege.SUPERVISOR)).toBeNull();
    });

    it('returns 3a for AGENT privilege', () => {
      expect(resolveTrustSubLevel(InstructionPrivilege.AGENT)).toBe('3a');
    });

    it('returns 3a for TOOL_OUTPUT privilege', () => {
      expect(resolveTrustSubLevel(InstructionPrivilege.TOOL_OUTPUT)).toBe('3a');
    });

    it('returns 3a for USER_INPUT privilege', () => {
      expect(resolveTrustSubLevel(InstructionPrivilege.USER_INPUT)).toBe('3a');
    });

    it('returns 3b for PEER_AGENT privilege', () => {
      expect(resolveTrustSubLevel(InstructionPrivilege.PEER_AGENT)).toBe('3b');
    });

    it('returns 3c for INTERNET privilege', () => {
      expect(resolveTrustSubLevel(InstructionPrivilege.INTERNET)).toBe('3c');
    });
  });
});

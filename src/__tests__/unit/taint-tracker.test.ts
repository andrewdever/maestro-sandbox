import { describe, it, expect } from 'vitest';
import { createTaintTracker, type TaintTracker } from '../../taint-tracker.js';
import { InstructionPrivilege } from '../../instruction-hierarchy.js';
import { createAuditLogger } from '../../audit.js';

describe('TaintTracker', () => {
  function makeTracker(options?: Parameters<typeof createTaintTracker>[0]): TaintTracker {
    return createTaintTracker(options);
  }

  describe('track', () => {
    it('returns a hash string', () => {
      const tracker = makeTracker();
      const hash = tracker.track('secret-data', 'hostbridge:readConfig', InstructionPrivilege.TOOL_OUTPUT);
      expect(hash).toMatch(/^[a-f0-9]{64}$/);
    });

    it('returns consistent hashes for same content', () => {
      const tracker = makeTracker();
      const h1 = tracker.track('data', 'src1', InstructionPrivilege.TOOL_OUTPUT);
      const h2 = tracker.track('data', 'src2', InstructionPrivilege.TOOL_OUTPUT);
      expect(h1).toBe(h2);
    });

    it('increments size', () => {
      const tracker = makeTracker();
      expect(tracker.size).toBe(0);
      tracker.track('a', 'src', InstructionPrivilege.TOOL_OUTPUT);
      expect(tracker.size).toBe(1);
    });

    it('tracks sandboxId', () => {
      const tracker = makeTracker();
      const hash = tracker.track('data', 'src', InstructionPrivilege.TOOL_OUTPUT, 'sbx_001');
      const record = tracker.checkHash(hash);
      expect(record?.sandboxId).toBe('sbx_001');
    });
  });

  describe('check — exact match', () => {
    it('detects exact content match', () => {
      const tracker = makeTracker();
      tracker.track('secret-api-key-12345', 'hostbridge:getSecret', InstructionPrivilege.TOOL_OUTPUT);
      const result = tracker.check('secret-api-key-12345');
      expect(result.tainted).toBe(true);
      expect(result.matchType).toBe('exact');
      expect(result.matches).toHaveLength(1);
      expect(result.matches[0].source).toBe('hostbridge:getSecret');
    });

    it('returns false for unknown content', () => {
      const tracker = makeTracker();
      tracker.track('tracked-data', 'src', InstructionPrivilege.TOOL_OUTPUT);
      const result = tracker.check('completely-different');
      expect(result.tainted).toBe(false);
      expect(result.matches).toHaveLength(0);
    });
  });

  describe('check — substring match', () => {
    it('detects partial exfiltration via substring', () => {
      const tracker = makeTracker({ chunkSize: 16 });
      // Track a long piece of content
      const secret = 'this-is-a-very-long-secret-value-that-should-be-tracked-for-exfiltration-detection-and-more-padding';
      tracker.track(secret, 'hostbridge:readConfig', InstructionPrivilege.TOOL_OUTPUT);

      // Outgoing content that IS the tracked content with prefix/suffix
      // Use prefix whose length is a multiple of step size (8) so chunks align
      const exfilAttempt = '12345678' + secret + '12345678901234567890123456789012345678901234567890123456789012345678';
      const result = tracker.check(exfilAttempt);
      expect(result.tainted).toBe(true);
      expect(result.matchType).toBe('substring');
    });

    it('can be disabled', () => {
      const tracker = makeTracker({ enableSubstringCheck: false });
      const secret = 'a'.repeat(128);
      tracker.track(secret, 'src', InstructionPrivilege.TOOL_OUTPUT);
      // Different content but contains substring — should NOT match when disabled
      const result = tracker.check('prefix' + secret.slice(0, 64) + 'suffix-with-enough-padding-to-reach-minimum-length-for-check');
      // With substring check disabled, only exact match is checked
      expect(result.matchType).not.toBe('substring');
    });
  });

  describe('checkHash', () => {
    it('returns record for known hash', () => {
      const tracker = makeTracker();
      const hash = tracker.track('data', 'src', InstructionPrivilege.TOOL_OUTPUT);
      const record = tracker.checkHash(hash);
      expect(record).toBeDefined();
      expect(record!.source).toBe('src');
      expect(record!.contentLength).toBe(4);
    });

    it('returns undefined for unknown hash', () => {
      const tracker = makeTracker();
      expect(tracker.checkHash('0'.repeat(64))).toBeUndefined();
    });
  });

  describe('preview', () => {
    it('truncates long content in preview', () => {
      const tracker = makeTracker({ previewLength: 10 });
      const hash = tracker.track('abcdefghijklmnopqrstuvwxyz', 'src', InstructionPrivilege.TOOL_OUTPUT);
      const record = tracker.checkHash(hash);
      expect(record!.preview).toBe('abcdefghij…');
    });

    it('keeps short content as-is', () => {
      const tracker = makeTracker({ previewLength: 50 });
      const hash = tracker.track('short', 'src', InstructionPrivilege.TOOL_OUTPUT);
      const record = tracker.checkHash(hash);
      expect(record!.preview).toBe('short');
    });
  });

  describe('eviction', () => {
    it('evicts oldest entries when maxTracked exceeded', () => {
      const tracker = makeTracker({ maxTracked: 3 });
      tracker.track('a', 'src1', InstructionPrivilege.TOOL_OUTPUT);
      tracker.track('b', 'src2', InstructionPrivilege.TOOL_OUTPUT);
      tracker.track('c', 'src3', InstructionPrivilege.TOOL_OUTPUT);
      tracker.track('d', 'src4', InstructionPrivilege.TOOL_OUTPUT);

      // 'a' should be evicted
      const result = tracker.check('a');
      expect(result.tainted).toBe(false);

      // 'd' should still be tracked
      const result2 = tracker.check('d');
      expect(result2.tainted).toBe(true);
    });
  });

  describe('reset', () => {
    it('clears all tracked data', () => {
      const tracker = makeTracker();
      tracker.track('data', 'src', InstructionPrivilege.TOOL_OUTPUT);
      expect(tracker.size).toBe(1);
      tracker.reset();
      expect(tracker.size).toBe(0);
      expect(tracker.check('data').tainted).toBe(false);
    });
  });

  describe('audit events', () => {
    it('emits taint.exfiltration.detected on exact match', () => {
      const logger = createAuditLogger({ emit: false, store: true });
      const tracker = makeTracker({ logger });
      tracker.track('secret', 'hostbridge:getSecret', InstructionPrivilege.TOOL_OUTPUT, 'sbx_001');
      tracker.check('secret');
      expect(logger.events.some(e => e.event === 'taint.exfiltration.detected')).toBe(true);
      const event = logger.events.find(e => e.event === 'taint.exfiltration.detected')!;
      expect(event.data['matchType']).toBe('exact');
    });

    it('emits taint.exfiltration.detected on substring match', () => {
      const logger = createAuditLogger({ emit: false, store: true });
      const tracker = makeTracker({ logger, chunkSize: 16 });
      const secret = 'this-is-a-long-secret-value-that-needs-to-be-at-least-64-chars-for-substring-detection-to-work-properly';
      tracker.track(secret, 'src', InstructionPrivilege.TOOL_OUTPUT, 'sbx_001');
      // Use aligned prefix (multiple of step size 8) so chunk boundaries match
      const exfil = '12345678' + secret + '12345678901234567890123456789012345678901234567890123456789012345678';
      tracker.check(exfil);
      const events = logger.events.filter(e => e.event === 'taint.exfiltration.detected');
      expect(events.some(e => e.data['matchType'] === 'substring')).toBe(true);
    });
  });

  describe('privilege tracking', () => {
    it('stores privilege level in taint record', () => {
      const tracker = makeTracker();
      const hash = tracker.track('data', 'src', InstructionPrivilege.SYSTEM);
      const record = tracker.checkHash(hash);
      expect(record!.privilege).toBe(InstructionPrivilege.SYSTEM);
    });
  });

  describe('substringRegistry eviction cleanup', () => {
    it('cleans substring entries when parent record is evicted', () => {
      // Use small chunkSize so we can create shorter content that generates substring hashes
      const tracker = makeTracker({ maxTracked: 2, chunkSize: 16, enableSubstringCheck: true });

      // Track content long enough to generate substring hashes (>= 64 chars with chunkSize 16)
      const secret1 = 'AAAA'.repeat(20); // 80 chars
      const secret2 = 'BBBB'.repeat(20);
      const secret3 = 'CCCC'.repeat(20);

      tracker.track(secret1, 'src1', InstructionPrivilege.TOOL_OUTPUT);
      tracker.track(secret2, 'src2', InstructionPrivilege.TOOL_OUTPUT);
      // This should evict secret1 and its substring hashes
      tracker.track(secret3, 'src3', InstructionPrivilege.TOOL_OUTPUT);

      // secret1 exact match should be gone
      expect(tracker.check(secret1).tainted).toBe(false);

      // secret1 substring match should also be gone (no orphaned entries)
      const partial1 = secret1.slice(0, 64);
      expect(tracker.check(partial1).tainted).toBe(false);

      // secret3 should still be fully tracked
      expect(tracker.check(secret3).tainted).toBe(true);
    });
  });
});

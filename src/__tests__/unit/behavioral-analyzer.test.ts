import { describe, it, expect } from 'vitest';
import {
  createBehavioralAnalyzer,
  createInMemoryStore,
  createDefaultPatterns,
  shannonEntropy,
  type ActionRecord,
  type BehavioralPattern,
} from '../../behavioral-analyzer.js';
import { createAuditLogger } from '../../audit.js';

let idCounter = 0;
function makeRecord(overrides: Partial<ActionRecord> = {}): ActionRecord {
  return {
    id: `rec_${++idCounter}`,
    timestamp: new Date().toISOString(),
    sandboxId: 'sbx_000001',
    action: 'hostbridge.call',
    ...overrides,
  };
}

describe('BehavioralAnalyzer', () => {
  describe('InMemoryStore', () => {
    it('appends and queries records', () => {
      const store = createInMemoryStore();
      const record = makeRecord();
      store.append(record);
      expect(store.size).toBe(1);
      expect(store.query({})).toHaveLength(1);
    });

    it('filters by sandboxId', () => {
      const store = createInMemoryStore();
      store.append(makeRecord({ sandboxId: 'sbx_a' }));
      store.append(makeRecord({ sandboxId: 'sbx_b' }));
      expect(store.query({ sandboxId: 'sbx_a' })).toHaveLength(1);
    });

    it('filters by action', () => {
      const store = createInMemoryStore();
      store.append(makeRecord({ action: 'hostbridge.call' }));
      store.append(makeRecord({ action: 'patch.apply' }));
      expect(store.query({ action: 'patch.apply' })).toHaveLength(1);
    });

    it('filters by sessionId', () => {
      const store = createInMemoryStore();
      store.append(makeRecord({ sessionId: 'sess_1' }));
      store.append(makeRecord({ sessionId: 'sess_2' }));
      expect(store.query({ sessionId: 'sess_1' })).toHaveLength(1);
    });

    it('respects limit', () => {
      const store = createInMemoryStore();
      for (let i = 0; i < 10; i++) {
        store.append(makeRecord());
      }
      expect(store.query({ limit: 3 })).toHaveLength(3);
    });

    it('evicts oldest records when maxRecords exceeded', () => {
      const store = createInMemoryStore(5);
      for (let i = 0; i < 8; i++) {
        store.append(makeRecord({ id: `rec_evict_${i}` }));
      }
      expect(store.size).toBe(5);
      // Oldest records should be gone
      const remaining = store.query({});
      expect(remaining[0].id).toBe('rec_evict_3');
    });

    it('filters by since timestamp', () => {
      const store = createInMemoryStore();
      store.append(makeRecord({ timestamp: '2025-01-01T00:00:00.000Z' }));
      store.append(makeRecord({ timestamp: '2025-06-01T00:00:00.000Z' }));
      const results = store.query({ since: '2025-03-01T00:00:00.000Z' });
      expect(results).toHaveLength(1);
    });
  });

  describe('createBehavioralAnalyzer', () => {
    it('records actions and returns matches', () => {
      const analyzer = createBehavioralAnalyzer();
      const matches = analyzer.record(makeRecord());
      expect(Array.isArray(matches)).toBe(true);
    });

    it('stores actions in the underlying store', () => {
      const store = createInMemoryStore();
      const analyzer = createBehavioralAnalyzer(store);
      analyzer.record(makeRecord());
      expect(store.size).toBe(1);
    });

    it('resets match history', () => {
      const analyzer = createBehavioralAnalyzer();
      // Trigger a pattern match
      analyzer.record(makeRecord({
        action: 'hostbridge.call',
        target: 'readConfig',
      }));
      analyzer.record(makeRecord({
        action: 'hostbridge.call',
        target: 'fetchUrl',
      }));
      analyzer.reset();
      expect(analyzer.getMatches('sbx_000001')).toHaveLength(0);
    });

    it('accepts custom patterns', () => {
      const customPattern: BehavioralPattern = {
        name: 'always-match',
        detect(_records, current) {
          return {
            pattern: 'always-match',
            score: 0.5,
            evidence: 'always matches',
            sandboxIds: [current.sandboxId],
          };
        },
      };
      const analyzer = createBehavioralAnalyzer(undefined, [customPattern]);
      const matches = analyzer.record(makeRecord());
      expect(matches).toHaveLength(1);
      expect(matches[0].pattern).toBe('always-match');
    });

    it('emits behavioral.anomaly audit event for low-score matches', () => {
      const logger = createAuditLogger({ emit: false, store: true });
      const customPattern: BehavioralPattern = {
        name: 'test-anomaly',
        detect(_records, current) {
          return {
            pattern: 'test-anomaly',
            score: 0.5,
            evidence: 'test',
            sandboxIds: [current.sandboxId],
          };
        },
      };
      const analyzer = createBehavioralAnalyzer(undefined, [customPattern], logger);
      analyzer.record(makeRecord());
      expect(logger.events.some(e => e.event === 'behavioral.anomaly')).toBe(true);
    });

    it('emits behavioral.quarantine audit event for high-score matches', () => {
      const logger = createAuditLogger({ emit: false, store: true });
      const customPattern: BehavioralPattern = {
        name: 'test-quarantine',
        detect(_records, current) {
          return {
            pattern: 'test-quarantine',
            score: 0.9,
            evidence: 'test quarantine',
            sandboxIds: [current.sandboxId],
          };
        },
      };
      const analyzer = createBehavioralAnalyzer(undefined, [customPattern], logger);
      analyzer.record(makeRecord());
      expect(logger.events.some(e => e.event === 'behavioral.quarantine')).toBe(true);
    });
  });

  describe('shannonEntropy', () => {
    it('returns 0 for single-character string', () => {
      expect(shannonEntropy('aaaa')).toBe(0);
    });

    it('returns ~1 for two equally distributed characters', () => {
      const e = shannonEntropy('abababab');
      expect(e).toBeCloseTo(1.0, 1);
    });

    it('returns higher entropy for more diverse strings', () => {
      const low = shannonEntropy('aaaaabbb');
      const high = shannonEntropy('abcdefgh');
      expect(high).toBeGreaterThan(low);
    });
  });

  describe('pattern: read-then-fetch', () => {
    it('detects read followed by network fetch', () => {
      const analyzer = createBehavioralAnalyzer();
      analyzer.record(makeRecord({ action: 'hostbridge.call', target: 'readFile' }));
      const matches = analyzer.record(makeRecord({ action: 'hostbridge.call', target: 'fetchUrl' }));
      expect(matches.some(m => m.pattern === 'read-then-fetch')).toBe(true);
    });
  });

  describe('pattern: write-after-read-secret', () => {
    it('detects write after reading a secret', () => {
      const analyzer = createBehavioralAnalyzer();
      analyzer.record(makeRecord({ action: 'hostbridge.call', target: 'readSecretKey' }));
      const matches = analyzer.record(makeRecord({ action: 'hostbridge.call', target: 'writeFile' }));
      expect(matches.some(m => m.pattern === 'write-after-read-secret')).toBe(true);
    });
  });

  describe('pattern: rapid-tool-cycling', () => {
    it('detects many tool calls in rapid succession', () => {
      const analyzer = createBehavioralAnalyzer();
      const now = Date.now();
      // 11 calls in 5 seconds
      for (let i = 0; i < 11; i++) {
        const matches = analyzer.record(makeRecord({
          action: 'hostbridge.call',
          target: `tool_${i}`,
          timestamp: new Date(now + i * 400).toISOString(),
        }));
        if (i >= 10) {
          expect(matches.some(m => m.pattern === 'rapid-tool-cycling')).toBe(true);
        }
      }
    });
  });

  describe('pattern: repeated-blocked-calls', () => {
    it('detects multiple blocked calls', () => {
      const analyzer = createBehavioralAnalyzer();
      for (let i = 0; i < 3; i++) {
        analyzer.record(makeRecord({
          guardrailResult: {
            action: 'block',
            scores: { 'prompt-injection': 0.95 },
            triggeredCategories: ['prompt-injection'],
            latencyMs: 1,
          },
        }));
      }
      const matches = analyzer.record(makeRecord());
      expect(matches.some(m => m.pattern === 'repeated-blocked-calls')).toBe(true);
    });
  });

  describe('pattern: high-entropy-output', () => {
    it('detects high-entropy output data', () => {
      const analyzer = createBehavioralAnalyzer();
      // Generate high-entropy string
      const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?/~`';
      let highEntropy = '';
      for (let i = 0; i < 200; i++) {
        highEntropy += chars[i % chars.length];
      }
      const matches = analyzer.record(makeRecord({
        metadata: { output: highEntropy },
      }));
      expect(matches.some(m => m.pattern === 'high-entropy-output')).toBe(true);
    });
  });

  describe('pattern: bulk-file-enumeration', () => {
    it('detects systematic file reading', () => {
      const analyzer = createBehavioralAnalyzer();
      const files = [
        'readFile_a', 'readFile_b', 'readFile_c', 'readFile_d',
        'readFile_e', 'readFile_f', 'readFile_g', 'readFile_h',
      ];
      let lastMatches;
      for (const file of files) {
        lastMatches = analyzer.record(makeRecord({
          action: 'hostbridge.call',
          target: file,
        }));
      }
      expect(lastMatches!.some(m => m.pattern === 'bulk-file-enumeration')).toBe(true);
    });
  });

  describe('pattern: systematic-error-probing', () => {
    it('detects many errors across different targets', () => {
      const analyzer = createBehavioralAnalyzer();
      const targets = ['api_a', 'api_b', 'api_c', 'api_d', 'api_e'];
      let lastMatches;
      for (const target of targets) {
        lastMatches = analyzer.record(makeRecord({
          target,
          metadata: { error: 'not found' },
        }));
      }
      expect(lastMatches!.some(m => m.pattern === 'systematic-error-probing')).toBe(true);
    });
  });

  describe('pattern: privilege-escalation-probe', () => {
    it('detects privilege escalation attempts', () => {
      const analyzer = createBehavioralAnalyzer();
      analyzer.record(makeRecord({ target: 'adminPanel' }));
      const matches = analyzer.record(makeRecord({ target: 'rootAccess' }));
      expect(matches.some(m => m.pattern === 'privilege-escalation-probe')).toBe(true);
    });
  });

  describe('pattern: cross-sandbox-coordination', () => {
    it('detects coordinated actions across sandboxes', () => {
      const analyzer = createBehavioralAnalyzer();
      const now = new Date().toISOString();
      analyzer.record(makeRecord({
        sandboxId: 'sbx_a',
        action: 'hostbridge.call',
        target: 'readSecrets',
        timestamp: now,
      }));
      analyzer.record(makeRecord({
        sandboxId: 'sbx_b',
        action: 'hostbridge.call',
        target: 'readSecrets',
        timestamp: now,
      }));
      const matches = analyzer.record(makeRecord({
        sandboxId: 'sbx_c',
        action: 'hostbridge.call',
        target: 'readSecrets',
        timestamp: now,
      }));
      expect(matches.some(m => m.pattern === 'cross-sandbox-coordination')).toBe(true);
    });
  });

  describe('pattern: gradual-prompt-mutation', () => {
    it('detects monotonically increasing guardrail scores', () => {
      const analyzer = createBehavioralAnalyzer();
      const scores = [0.1, 0.2, 0.3, 0.4];
      let lastMatches;
      for (const score of scores) {
        lastMatches = analyzer.record(makeRecord({
          action: 'sandbox.execute',
          guardrailResult: {
            action: 'flag',
            scores: { 'prompt-injection': score },
            triggeredCategories: [],
            latencyMs: 1,
          },
        }));
      }
      expect(lastMatches!.some(m => m.pattern === 'gradual-prompt-mutation')).toBe(true);
    });
  });

  describe('pattern: exfiltration-encoding', () => {
    it('detects encoding followed by egress', () => {
      const analyzer = createBehavioralAnalyzer();
      analyzer.record(makeRecord({ target: 'base64Encode' }));
      const matches = analyzer.record(makeRecord({ target: 'fetchUrl' }));
      expect(matches.some(m => m.pattern === 'exfiltration-encoding')).toBe(true);
    });
  });

  describe('pattern: resource-exhaustion-ramp', () => {
    it('detects increasing memory usage', () => {
      const analyzer = createBehavioralAnalyzer();
      const usages = [1_000_000, 1_500_000, 2_500_000, 4_000_000];
      let lastMatches;
      for (const memoryBytes of usages) {
        lastMatches = analyzer.record(makeRecord({
          metadata: { memoryBytes },
        }));
      }
      expect(lastMatches!.some(m => m.pattern === 'resource-exhaustion-ramp')).toBe(true);
    });
  });

  describe('pattern: boundary-testing', () => {
    it('detects repeated rejections across targets', () => {
      const analyzer = createBehavioralAnalyzer();
      const targets = ['func_a', 'func_b', 'func_c'];
      let lastMatches;
      for (const target of targets) {
        lastMatches = analyzer.record(makeRecord({
          action: 'hostbridge.call.rejected',
          target,
        }));
      }
      expect(lastMatches!.some(m => m.pattern === 'boundary-testing')).toBe(true);
    });
  });

  describe('createDefaultPatterns', () => {
    it('returns 16 patterns', () => {
      const patterns = createDefaultPatterns();
      expect(patterns).toHaveLength(16);
    });

    it('all patterns have unique names', () => {
      const patterns = createDefaultPatterns();
      const names = patterns.map(p => p.name);
      expect(new Set(names).size).toBe(16);
    });
  });
});

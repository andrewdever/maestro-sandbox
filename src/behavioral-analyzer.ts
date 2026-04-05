/**
 * Behavioral Analysis Engine (§14.9).
 *
 * Architecture: Option D — Append-only event log with in-memory
 * materialized view. Designed so a database backend can be plugged in later.
 *
 * Tracks per-session AND cross-sandbox action records. 16 detection
 * patterns (8 re-implemented from V1 call-sequence analyzer + 8 new).
 *
 * Anomaly scoring uses a sliding window (not fixed-size buffer).
 * Cross-sandbox correlation detects multi-agent attacks.
 *
 * Audit events:
 *   behavioral.anomaly   (WARN)
 *   behavioral.quarantine (CRITICAL)
 */

import type { AuditLogger } from './audit.js';
import type { GuardrailResult } from './guardrail-pipeline.js';

// ---------------------------------------------------------------------------
// Storage Backend
// ---------------------------------------------------------------------------

/** Filter for querying action records. */
export interface ActionFilter {
  sandboxId?: string;
  sessionId?: string;
  action?: string;
  since?: string;           // ISO timestamp
  limit?: number;
}

/** A single recorded action in the behavioral log. */
export interface ActionRecord {
  id: string;
  timestamp: string;
  sandboxId: string;
  sessionId?: string;
  /** Optional tenant ID for multi-tenant isolation (§5). */
  tenantId?: string;
  action: string;           // e.g. 'hostbridge.call', 'patch.apply', 'mesh.send'
  target?: string;          // e.g. function name, file path
  metadata?: Record<string, unknown>;
  guardrailResult?: GuardrailResult;
}

/**
 * Storage backend interface — in-memory default, database later.
 *
 * All implementations MUST be append-only (no mutation of existing records).
 */
export interface BehavioralStore {
  append(record: ActionRecord): void;
  query(filter: ActionFilter): ActionRecord[];
  readonly size: number;
}

/**
 * Create an in-memory store with LRU eviction by timestamp.
 *
 * @param maxRecords - Cap before oldest records are evicted. Default: 10000.
 */
export function createInMemoryStore(maxRecords = 10_000): BehavioralStore {
  const records: ActionRecord[] = [];

  return {
    append(record: ActionRecord): void {
      records.push(record);
      // LRU eviction by timestamp (oldest first)
      while (records.length > maxRecords) {
        records.shift();
      }
    },

    query(filter: ActionFilter): ActionRecord[] {
      let result = records;

      if (filter.sandboxId) {
        result = result.filter(r => r.sandboxId === filter.sandboxId);
      }
      if (filter.sessionId) {
        result = result.filter(r => r.sessionId === filter.sessionId);
      }
      if (filter.action) {
        result = result.filter(r => r.action === filter.action);
      }
      if (filter.since) {
        result = result.filter(r => r.timestamp >= filter.since!);
      }
      if (filter.limit) {
        result = result.slice(-filter.limit);
      }

      return result;
    },

    get size(): number {
      return records.length;
    },
  };
}

// ---------------------------------------------------------------------------
// Pattern Detection
// ---------------------------------------------------------------------------

/** Result of a pattern match. */
export interface PatternMatch {
  pattern: string;
  score: number;            // 0-1
  evidence: string;         // human-readable
  sandboxIds: string[];     // involved sandboxes (for cross-sandbox)
}

/** A behavioral detection pattern. */
export interface BehavioralPattern {
  name: string;
  detect(records: ActionRecord[], current: ActionRecord): PatternMatch | null;
}

// ---------------------------------------------------------------------------
// Sliding Window Helpers
// ---------------------------------------------------------------------------

/** Default sliding window: 50 records or 5 minutes, whichever is smaller. */
const DEFAULT_WINDOW_RECORDS = 50;
const DEFAULT_WINDOW_MS = 5 * 60 * 1000;

function windowSlice(records: ActionRecord[], current: ActionRecord): ActionRecord[] {
  const cutoff = new Date(new Date(current.timestamp).getTime() - DEFAULT_WINDOW_MS).toISOString();
  const timeFiltered = records.filter(r => r.timestamp >= cutoff);
  if (timeFiltered.length <= DEFAULT_WINDOW_RECORDS) return timeFiltered;
  return timeFiltered.slice(-DEFAULT_WINDOW_RECORDS);
}

// ---------------------------------------------------------------------------
// 16 Detection Patterns
// ---------------------------------------------------------------------------

// ---- EXISTING (re-implemented from V1) ----

/** 1. Read-then-fetch: read a file/config, then make a network call. */
function readThenFetch(): BehavioralPattern {
  return {
    name: 'read-then-fetch',
    detect(records, current) {
      if (current.action !== 'hostbridge.call' || !isFetchAction(current.target)) return null;
      const window = windowSlice(records, current);
      const reads = window.filter(r =>
        r.action === 'hostbridge.call' && isReadAction(r.target) && r.sandboxId === current.sandboxId,
      );
      if (reads.length === 0) return null;
      return {
        pattern: 'read-then-fetch',
        score: 0.6,
        evidence: `Read ${reads.length} file(s) then attempted network fetch "${current.target}"`,
        sandboxIds: [current.sandboxId],
      };
    },
  };
}

/** 2. Write after reading a secret. */
function writeAfterReadSecret(): BehavioralPattern {
  return {
    name: 'write-after-read-secret',
    detect(records, current) {
      if (current.action !== 'hostbridge.call' || !isWriteAction(current.target)) return null;
      const window = windowSlice(records, current);
      const secretReads = window.filter(r =>
        r.sandboxId === current.sandboxId &&
        r.action === 'hostbridge.call' &&
        isSecretRead(r.target),
      );
      if (secretReads.length === 0) return null;
      return {
        pattern: 'write-after-read-secret',
        score: 0.7,
        evidence: `Read secret(s) then wrote to "${current.target}"`,
        sandboxIds: [current.sandboxId],
      };
    },
  };
}

/** 3. Rapid tool cycling — many distinct tool calls in short window. */
function rapidToolCycling(): BehavioralPattern {
  return {
    name: 'rapid-tool-cycling',
    detect(records, current) {
      const window = windowSlice(records, current).filter(
        r => r.sandboxId === current.sandboxId && r.action === 'hostbridge.call',
      );
      if (window.length < 10) return null;
      // Check if >10 calls in <30 seconds
      const first = new Date(window[0].timestamp).getTime();
      const last = new Date(current.timestamp).getTime();
      const elapsed = last - first;
      if (elapsed > 0 && elapsed < 30_000 && window.length >= 10) {
        return {
          pattern: 'rapid-tool-cycling',
          score: 0.5,
          evidence: `${window.length} tool calls in ${(elapsed / 1000).toFixed(1)}s`,
          sandboxIds: [current.sandboxId],
        };
      }
      return null;
    },
  };
}

/** 4. Repeated blocked calls — keeps trying after being blocked. */
function repeatedBlockedCalls(): BehavioralPattern {
  return {
    name: 'repeated-blocked-calls',
    detect(records, current) {
      const window = windowSlice(records, current).filter(
        r => r.sandboxId === current.sandboxId,
      );
      const blocked = window.filter(r => r.guardrailResult?.action === 'block');
      if (blocked.length >= 3) {
        return {
          pattern: 'repeated-blocked-calls',
          score: Math.min(1.0, 0.5 + blocked.length * 0.1),
          evidence: `${blocked.length} blocked calls in sliding window`,
          sandboxIds: [current.sandboxId],
        };
      }
      return null;
    },
  };
}

/** 5. Unusual hour activity — actions outside business hours (configurable). */
function unusualHourActivity(): BehavioralPattern {
  return {
    name: 'unusual-hour-activity',
    detect(_records, current) {
      const hour = new Date(current.timestamp).getUTCHours();
      // Flag activity between 00:00-05:00 UTC as unusual
      if (hour >= 0 && hour < 5) {
        return {
          pattern: 'unusual-hour-activity',
          score: 0.3,
          evidence: `Activity at ${hour}:00 UTC (unusual hours)`,
          sandboxIds: [current.sandboxId],
        };
      }
      return null;
    },
  };
}

/** 6. High-entropy output — compressed/encoded data in results. */
function highEntropyOutput(): BehavioralPattern {
  return {
    name: 'high-entropy-output',
    detect(_records, current) {
      const output = current.metadata?.['output'] as string | undefined;
      if (!output || output.length < 64) return null;
      const entropy = shannonEntropy(output);
      if (entropy > 5.5) {
        return {
          pattern: 'high-entropy-output',
          score: Math.min(1.0, (entropy - 5.5) / 2.5 + 0.4),
          evidence: `High entropy output: ${entropy.toFixed(2)} bits/char`,
          sandboxIds: [current.sandboxId],
        };
      }
      return null;
    },
  };
}

/** 7. Bulk file enumeration — reading many files systematically. */
function bulkFileEnumeration(): BehavioralPattern {
  return {
    name: 'bulk-file-enumeration',
    detect(records, current) {
      const window = windowSlice(records, current).filter(
        r => r.sandboxId === current.sandboxId &&
          r.action === 'hostbridge.call' &&
          isReadAction(r.target),
      );
      if (window.length >= 8) {
        const uniqueTargets = new Set(window.map(r => r.target).filter(Boolean));
        if (uniqueTargets.size >= 6) {
          return {
            pattern: 'bulk-file-enumeration',
            score: 0.6,
            evidence: `${uniqueTargets.size} unique files read in sliding window`,
            sandboxIds: [current.sandboxId],
          };
        }
      }
      return null;
    },
  };
}

/** 8. Systematic error probing — many errors with varying targets. */
function systematicErrorProbing(): BehavioralPattern {
  return {
    name: 'systematic-error-probing',
    detect(records, current) {
      const window = windowSlice(records, current).filter(
        r => r.sandboxId === current.sandboxId,
      );
      const errors = window.filter(r => r.metadata?.['error'] !== undefined);
      if (errors.length >= 5) {
        const uniqueTargets = new Set(errors.map(r => r.target).filter(Boolean));
        if (uniqueTargets.size >= 3) {
          return {
            pattern: 'systematic-error-probing',
            score: 0.5,
            evidence: `${errors.length} errors across ${uniqueTargets.size} targets — systematic probing`,
            sandboxIds: [current.sandboxId],
          };
        }
      }
      return null;
    },
  };
}

// ---- NEW (V2) ----

/** 9. Privilege escalation probe — attempts to call higher-privilege functions. */
function privilegeEscalationProbe(): BehavioralPattern {
  return {
    name: 'privilege-escalation-probe',
    detect(records, current) {
      const window = windowSlice(records, current).filter(
        r => r.sandboxId === current.sandboxId,
      );
      const privEscAttempts = window.filter(r =>
        r.guardrailResult?.triggeredCategories?.includes('privilege-escalation') ||
        isPrivilegeEscalationTarget(r.target),
      );
      if (privEscAttempts.length >= 2) {
        return {
          pattern: 'privilege-escalation-probe',
          score: Math.min(1.0, 0.5 + privEscAttempts.length * 0.15),
          evidence: `${privEscAttempts.length} privilege escalation attempts`,
          sandboxIds: [current.sandboxId],
        };
      }
      return null;
    },
  };
}

/** 10. Reconnaissance sequence — systematic discovery of capabilities. */
function reconnaissanceSequence(): BehavioralPattern {
  return {
    name: 'reconnaissance-sequence',
    detect(records, current) {
      const window = windowSlice(records, current).filter(
        r => r.sandboxId === current.sandboxId && r.action === 'hostbridge.call',
      );
      const uniqueTargets = new Set(window.map(r => r.target).filter(Boolean));
      const errorCount = window.filter(r => r.metadata?.['error'] !== undefined).length;
      // Many different function calls with errors = reconnaissance
      if (uniqueTargets.size >= 8 && errorCount >= 3) {
        return {
          pattern: 'reconnaissance-sequence',
          score: 0.6,
          evidence: `${uniqueTargets.size} unique targets probed, ${errorCount} errors`,
          sandboxIds: [current.sandboxId],
        };
      }
      return null;
    },
  };
}

/** 11. Cross-sandbox coordination — correlated actions across sandboxes. */
function crossSandboxCoordination(): BehavioralPattern {
  return {
    name: 'cross-sandbox-coordination',
    detect(records, current) {
      // Pre-compute current timestamp once (avoid repeated Date parsing)
      const currentTime = new Date(current.timestamp).getTime();

      // Use count-bounded window (last 200 records max) + time filter
      // to prevent unbounded scans. Records are append-only so newest are at end.
      const startIdx = Math.max(0, records.length - 200);
      const recentWindow: ActionRecord[] = [];
      for (let i = startIdx; i < records.length; i++) {
        const r = records[i];
        if (r.sandboxId === current.sandboxId) continue;
        const diff = currentTime - new Date(r.timestamp).getTime();
        if (diff >= 0 && diff < 10_000) {
          recentWindow.push(r);
        }
      }

      if (recentWindow.length < 2) return null;

      // Check for same action/target across sandboxes
      const sameAction = recentWindow.filter(r =>
        r.action === current.action && r.target === current.target,
      );
      if (sameAction.length >= 2) {
        const sandboxIds = [...new Set([current.sandboxId, ...sameAction.map(r => r.sandboxId)])];
        return {
          pattern: 'cross-sandbox-coordination',
          score: 0.7,
          evidence: `Same action "${current.action}:${current.target}" across ${sandboxIds.length} sandboxes within 10s`,
          sandboxIds,
        };
      }
      return null;
    },
  };
}

/** 12. Gradual prompt mutation — slowly shifting content over time. */
function gradualPromptMutation(): BehavioralPattern {
  return {
    name: 'gradual-prompt-mutation',
    detect(records, current) {
      if (current.action !== 'sandbox.execute') return null;
      const window = windowSlice(records, current).filter(
        r => r.sandboxId === current.sandboxId && r.action === 'sandbox.execute',
      );
      if (window.length < 4) return null;

      // Check for monotonically increasing guardrail scores
      const scores = window
        .map(r => maxGuardrailScore(r.guardrailResult))
        .filter((s): s is number => s !== null);
      if (scores.length < 4) return null;

      // Strict monotonic: any decrease breaks the pattern.
      // Tolerance of 0 prevents attackers from oscillating within a margin.
      let increasing = true;
      for (let i = 1; i < scores.length; i++) {
        if (scores[i] < scores[i - 1]) {
          increasing = false;
          break;
        }
      }

      if (increasing && scores[scores.length - 1] > 0.3) {
        return {
          pattern: 'gradual-prompt-mutation',
          score: Math.min(1.0, scores[scores.length - 1] + 0.2),
          evidence: `Guardrail scores increasing: ${scores.map(s => s.toFixed(2)).join(' → ')}`,
          sandboxIds: [current.sandboxId],
        };
      }
      return null;
    },
  };
}

/** 13. Tool chain abuse — using tools in sequence to circumvent restrictions. */
function toolChainAbuse(): BehavioralPattern {
  return {
    name: 'tool-chain-abuse',
    detect(records, current) {
      if (current.action !== 'hostbridge.call') return null;
      const window = windowSlice(records, current).filter(
        r => r.sandboxId === current.sandboxId && r.action === 'hostbridge.call',
      );
      if (window.length < 3) return null;

      // Detect read → transform → write/send chains
      const chain = window.slice(-3);
      const hasRead = isReadAction(chain[0]?.target);
      const hasTransform = isTransformAction(chain[1]?.target);
      const hasWrite = isWriteAction(chain[2]?.target) || isFetchAction(chain[2]?.target);

      if (hasRead && hasTransform && hasWrite) {
        return {
          pattern: 'tool-chain-abuse',
          score: 0.6,
          evidence: `Tool chain: ${chain.map(r => r.target).join(' → ')}`,
          sandboxIds: [current.sandboxId],
        };
      }
      return null;
    },
  };
}

/** 14. Exfiltration encoding — base64/hex encoding before egress. */
function exfiltrationEncoding(): BehavioralPattern {
  return {
    name: 'exfiltration-encoding',
    detect(records, current) {
      const window = windowSlice(records, current).filter(
        r => r.sandboxId === current.sandboxId,
      );
      const encodingActions = window.filter(r =>
        r.metadata?.['encoding'] !== undefined ||
        /base64|hex|encode|btoa|atob/i.test(r.target ?? '') ||
        /base64|hex|encode|btoa|atob/i.test(r.action),
      );
      const egressActions = window.filter(r =>
        isFetchAction(r.target) || isWriteAction(r.target),
      );

      if (encodingActions.length >= 1 && egressActions.length >= 1) {
        return {
          pattern: 'exfiltration-encoding',
          score: 0.7,
          evidence: `${encodingActions.length} encoding action(s) + ${egressActions.length} egress action(s)`,
          sandboxIds: [current.sandboxId],
        };
      }
      return null;
    },
  };
}

/** 15. Resource exhaustion ramp — gradually increasing resource usage. */
function resourceExhaustionRamp(): BehavioralPattern {
  return {
    name: 'resource-exhaustion-ramp',
    detect(records, current) {
      const window = windowSlice(records, current).filter(
        r => r.sandboxId === current.sandboxId,
      );
      const memoryUsages = window
        .map(r => r.metadata?.['memoryBytes'] as number | undefined)
        .filter((m): m is number => typeof m === 'number');

      if (memoryUsages.length < 3) return null;

      // Check for monotonically increasing memory
      let increasing = true;
      for (let i = 1; i < memoryUsages.length; i++) {
        if (memoryUsages[i] < memoryUsages[i - 1]) {
          increasing = false;
          break;
        }
      }

      if (increasing) {
        const growthFactor = memoryUsages[memoryUsages.length - 1] / memoryUsages[0];
        if (growthFactor >= 2.0) {
          return {
            pattern: 'resource-exhaustion-ramp',
            score: Math.min(1.0, 0.4 + (growthFactor - 2.0) * 0.1),
            evidence: `Memory usage grew ${growthFactor.toFixed(1)}x over ${memoryUsages.length} actions`,
            sandboxIds: [current.sandboxId],
          };
        }
      }
      return null;
    },
  };
}

/** 16. Boundary testing — probing limits of allowed operations. */
function boundaryTesting(): BehavioralPattern {
  return {
    name: 'boundary-testing',
    detect(records, current) {
      const window = windowSlice(records, current).filter(
        r => r.sandboxId === current.sandboxId,
      );
      // Detect many "rejected" or "not available" errors with varying targets
      const rejections = window.filter(r =>
        r.action === 'hostbridge.call.rejected' ||
        r.guardrailResult?.action === 'block' ||
        r.metadata?.['error']?.toString().includes('not available') ||
        r.metadata?.['error']?.toString().includes('not in operator allowlist') ||
        r.metadata?.['error']?.toString().includes('not allowed'),
      );

      if (rejections.length >= 3) {
        const uniqueTargets = new Set(rejections.map(r => r.target).filter(Boolean));
        if (uniqueTargets.size >= 2) {
          return {
            pattern: 'boundary-testing',
            score: Math.min(1.0, 0.4 + rejections.length * 0.1),
            evidence: `${rejections.length} rejections across ${uniqueTargets.size} targets — boundary testing`,
            sandboxIds: [current.sandboxId],
          };
        }
      }
      return null;
    },
  };
}

// ---------------------------------------------------------------------------
// Pattern Helpers
// ---------------------------------------------------------------------------

function isReadAction(target?: string): boolean {
  if (!target) return false;
  return /read|get|load|list|stat|access|open|cat/i.test(target);
}

function isWriteAction(target?: string): boolean {
  if (!target) return false;
  return /write|put|save|create|append|set|store/i.test(target);
}

function isFetchAction(target?: string): boolean {
  if (!target) return false;
  return /fetch|http|request|send|post|upload|webhook/i.test(target);
}

function isSecretRead(target?: string): boolean {
  if (!target) return false;
  return /secret|key|token|password|credential|env|config/i.test(target);
}

function isTransformAction(target?: string): boolean {
  if (!target) return false;
  return /transform|encode|decode|convert|parse|serialize|compress|encrypt/i.test(target);
}

function isPrivilegeEscalationTarget(target?: string): boolean {
  if (!target) return false;
  return /admin|root|sudo|privilege|escalat|override|bypass/i.test(target);
}

function maxGuardrailScore(result?: GuardrailResult): number | null {
  if (!result) return null;
  const values = Object.values(result.scores).filter(
    (v): v is number => typeof v === 'number',
  );
  return values.length > 0 ? Math.max(...values) : null;
}

/** Shannon entropy in bits per character. */
export function shannonEntropy(str: string): number {
  const freq = new Map<string, number>();
  for (const ch of str) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }
  let entropy = 0;
  const len = str.length;
  for (const count of freq.values()) {
    const p = count / len;
    if (p > 0) {
      entropy -= p * Math.log2(p);
    }
  }
  return entropy;
}

// ---------------------------------------------------------------------------
// Default patterns
// ---------------------------------------------------------------------------

export function createDefaultPatterns(): BehavioralPattern[] {
  return [
    // Existing (V1 re-implemented)
    readThenFetch(),
    writeAfterReadSecret(),
    rapidToolCycling(),
    repeatedBlockedCalls(),
    unusualHourActivity(),
    highEntropyOutput(),
    bulkFileEnumeration(),
    systematicErrorProbing(),
    // New (V2)
    privilegeEscalationProbe(),
    reconnaissanceSequence(),
    crossSandboxCoordination(),
    gradualPromptMutation(),
    toolChainAbuse(),
    exfiltrationEncoding(),
    resourceExhaustionRamp(),
    boundaryTesting(),
  ];
}

// ---------------------------------------------------------------------------
// Behavioral Analyzer
// ---------------------------------------------------------------------------

export interface BehavioralAnalyzer {
  /** Record an action and return any pattern matches. */
  record(action: ActionRecord): PatternMatch[];

  /** Get all matches for a sandbox. */
  getMatches(sandboxId: string): PatternMatch[];

  /** The underlying store. */
  readonly store: BehavioralStore;

  /** Reset all state. */
  reset(): void;
}

/** Quarantine threshold: score >= this emits behavioral.quarantine. */
const QUARANTINE_THRESHOLD = 0.8;

/**
 * Create a behavioral analyzer.
 *
 * @param store - Storage backend. Defaults to in-memory (10k records).
 * @param patterns - Detection patterns. Defaults to all 16.
 * @param logger - Optional audit logger.
 */
export function createBehavioralAnalyzer(
  store?: BehavioralStore,
  patterns?: BehavioralPattern[],
  logger?: AuditLogger,
): BehavioralAnalyzer {
  const _store = store ?? createInMemoryStore();
  const _patterns = patterns ?? createDefaultPatterns();
  const matchesBySandbox = new Map<string, PatternMatch[]>();

  return {
    record(action: ActionRecord): PatternMatch[] {
      // Get all records BEFORE appending (patterns compare history to current)
      const allRecords = _store.query({});
      _store.append(action);

      const matches: PatternMatch[] = [];

      for (const pattern of _patterns) {
        const match = pattern.detect(allRecords, action);
        if (match) {
          matches.push(match);
        }
      }

      // Store matches per sandbox
      if (matches.length > 0) {
        const existing = matchesBySandbox.get(action.sandboxId) ?? [];
        existing.push(...matches);
        matchesBySandbox.set(action.sandboxId, existing);

        // Emit audit events
        for (const match of matches) {
          if (match.score >= QUARANTINE_THRESHOLD) {
            logger?.log('behavioral.quarantine', {
              pattern: match.pattern,
              score: match.score,
              evidence: match.evidence,
              sandboxIds: match.sandboxIds,
            }, action.sandboxId);
          } else {
            logger?.log('behavioral.anomaly', {
              pattern: match.pattern,
              score: match.score,
              evidence: match.evidence,
              sandboxIds: match.sandboxIds,
            }, action.sandboxId);
          }
        }
      }

      return matches;
    },

    getMatches(sandboxId: string): PatternMatch[] {
      return matchesBySandbox.get(sandboxId) ?? [];
    },

    get store(): BehavioralStore {
      return _store;
    },

    reset(): void {
      matchesBySandbox.clear();
    },
  };
}

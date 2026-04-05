/**
 * Multi-Turn Escalation Detection (§14.10).
 *
 * Detects gradual escalation across conversation turns using
 * 5 heuristic detectors (no ML required for P0):
 *
 * 1. Blocked-attempt counting — 3+ in 10 turns → quarantine
 * 2. Hash-based similarity — paraphrase probing detection
 * 3. Guardrail score trending — monotonic increase → flag
 * 4. Context length monitoring — >2x growth → flag
 * 5. Tool diversity spike — sudden breadth → reconnaissance
 *
 * Actions: continue | warn-operator | inject-refusal | reset-session | block-session
 */

import { createHash } from 'node:crypto';
import type { GuardrailResult, CategoryScores } from './guardrail-pipeline.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Actions the escalation detector can recommend. */
export type EscalationAction =
  | 'continue'
  | 'warn-operator'
  | 'inject-refusal'
  | 'reset-session'
  | 'block-session';

/** Record of a single conversation turn. */
export interface TurnRecord {
  /** Turn number (1-indexed). */
  turnNumber: number;

  /** ISO 8601 timestamp. */
  timestamp: string;

  /** Guardrail result for this turn's input. */
  inputResult?: GuardrailResult;

  /** Guardrail result for this turn's output. */
  outputResult?: GuardrailResult;

  /** Tool calls made during this turn. */
  toolCalls: string[];

  /** Approximate content length (chars) of input. */
  inputLength: number;

  /** Content hash for similarity detection. */
  contentHash: string;

  /** Embedding vector for semantic similarity (populated when embeddingFn is configured). */
  embedding?: number[];
}

/** Result of escalation analysis. */
export interface EscalationResult {
  /** Recommended action. */
  action: EscalationAction;

  /** Which detectors fired. */
  triggers: string[];

  /** Human-readable reason. */
  reason: string;

  /** Current escalation score (0-1, composite). */
  score: number;
}

/**
 * Embedding function for semantic similarity detection.
 * Maps content to a dense vector (number[]). When provided,
 * Detector 2 uses cosine similarity instead of hash deduplication.
 */
export type EmbeddingFn = (content: string) => number[] | Promise<number[]>;

/** Configuration for the escalation detector. */
export interface EscalationConfig {
  /** Max turns before forced session reset. Default: 50. */
  maxTurns?: number;

  /** Number of blocked attempts before quarantine. Default: 3. */
  blockedAttemptThreshold?: number;

  /** Window size for blocked attempt counting. Default: 10 turns. */
  blockedAttemptWindow?: number;

  /** Similarity threshold (0-1). Default: 0.8. Used for both hash uniqueness and cosine similarity. */
  similarityThreshold?: number;

  /** Context growth multiplier triggering flag. Default: 2.0. */
  contextGrowthMultiplier?: number;

  /** Tool diversity threshold (new unique tools in window). Default: 5. */
  toolDiversityThreshold?: number;

  /** Tool diversity window. Default: 3 turns. */
  toolDiversityWindow?: number;

  /**
   * Optional embedding function for semantic similarity (P2 upgrade).
   * When provided, Detector 2 uses cosine similarity between embeddings
   * instead of SHA-256 hash deduplication. Falls back to hash-based
   * detection when not provided.
   */
  embeddingFn?: EmbeddingFn;
}

// ---------------------------------------------------------------------------
// Escalation Detector
// ---------------------------------------------------------------------------

export interface EscalationDetector {
  /**
   * Record a turn and analyze for escalation.
   * When embeddingFn is configured, pass `content` to compute the embedding.
   */
  recordTurn(turn: Omit<TurnRecord, 'turnNumber' | 'embedding'>, content?: string): EscalationResult | Promise<EscalationResult>;

  /** Get the current turn count. */
  readonly turnCount: number;

  /** Get all turn records. */
  readonly turns: readonly TurnRecord[];

  /** Reset the session state. */
  reset(): void;
}

/**
 * Create an escalation detector for a session.
 */
export function createEscalationDetector(config: EscalationConfig = {}): EscalationDetector {
  const {
    maxTurns = 50,
    blockedAttemptThreshold = 3,
    blockedAttemptWindow = 10,
    similarityThreshold = 0.8,
    contextGrowthMultiplier = 2.0,
    toolDiversityThreshold = 5,
    toolDiversityWindow = 3,
    embeddingFn,
  } = config;

  const turns: TurnRecord[] = [];

  function analyze(record: TurnRecord): EscalationResult {

      const triggers: string[] = [];
      let maxScore = 0;

      // ---------------------------------------------------------------
      // Detector 1: Blocked-attempt counting
      // ---------------------------------------------------------------
      {
        const windowStart = Math.max(0, turns.length - blockedAttemptWindow);
        const windowTurns = turns.slice(windowStart);
        const blockedCount = windowTurns.filter(
          t => t.inputResult?.action === 'block' || t.outputResult?.action === 'block',
        ).length;

        if (blockedCount >= blockedAttemptThreshold) {
          triggers.push(`blocked-attempts: ${blockedCount}/${blockedAttemptThreshold} in last ${blockedAttemptWindow} turns`);
          maxScore = Math.max(maxScore, 0.9);
        }
      }

      // ---------------------------------------------------------------
      // Detector 2: Similarity detection (embedding-based or hash-based)
      // ---------------------------------------------------------------
      {
        const recentTurnsForSim = turns.slice(-10);

        if (embeddingFn && record.embedding) {
          // P2: Embedding-based cosine similarity — catches paraphrases
          let highSimCount = 0;
          for (const t of recentTurnsForSim) {
            if (t === record || !t.embedding) continue;
            const sim = cosineSimilarity(record.embedding, t.embedding);
            if (sim >= similarityThreshold) highSimCount++;
          }
          // If 3+ recent turns are semantically similar → paraphrase probing
          if (highSimCount >= 3) {
            triggers.push(`embedding-similarity: ${highSimCount} turns above ${similarityThreshold} threshold`);
            maxScore = Math.max(maxScore, 0.7);
          }
        } else {
          // Fallback: Hash-based deduplication (P0 behavior)
          const recentHashes = recentTurnsForSim.map(t => t.contentHash);
          const uniqueHashes = new Set(recentHashes).size;
          const totalHashes = recentHashes.length;

          if (totalHashes >= 4) {
            const uniqueRatio = uniqueHashes / totalHashes;
            // Low uniqueness = many similar inputs = possible paraphrase probing
            if (uniqueRatio < (1 - similarityThreshold)) {
              triggers.push(`similarity: ${(1 - uniqueRatio).toFixed(2)} similarity in last ${totalHashes} turns`);
              maxScore = Math.max(maxScore, 0.7);
            }
          }
        }
      }

      // ---------------------------------------------------------------
      // Detector 3: Guardrail score trending
      // ---------------------------------------------------------------
      {
        const recentTurns = turns.slice(-5);
        if (recentTurns.length >= 3) {
          const maxScores = recentTurns.map(t => {
            const scores = { ...t.inputResult?.scores, ...t.outputResult?.scores };
            const vals = Object.values(scores).filter((v): v is number => typeof v === 'number');
            return vals.length > 0 ? Math.max(...vals) : 0;
          });

          // Check for monotonic increase (allowing ties)
          let increasing = true;
          for (let i = 1; i < maxScores.length; i++) {
            if (maxScores[i] < maxScores[i - 1] - 0.05) {
              increasing = false;
              break;
            }
          }

          if (increasing && maxScores[maxScores.length - 1] > 0.3) {
            triggers.push(`score-trending: monotonic increase to ${maxScores[maxScores.length - 1].toFixed(2)}`);
            maxScore = Math.max(maxScore, 0.6);
          }
        }
      }

      // ---------------------------------------------------------------
      // Detector 4: Context length monitoring
      // ---------------------------------------------------------------
      {
        if (turns.length >= 3) {
          const firstLength = turns[0].inputLength;
          const currentLength = record.inputLength;

          if (firstLength > 0 && currentLength > firstLength * contextGrowthMultiplier) {
            const growth = (currentLength / firstLength).toFixed(1);
            triggers.push(`context-growth: ${growth}x (threshold: ${contextGrowthMultiplier}x)`);
            maxScore = Math.max(maxScore, 0.5);
          }
        }
      }

      // ---------------------------------------------------------------
      // Detector 5: Tool diversity spike
      // ---------------------------------------------------------------
      {
        if (turns.length >= toolDiversityWindow) {
          const windowTurns = turns.slice(-toolDiversityWindow);
          const allTools = new Set(windowTurns.flatMap(t => t.toolCalls));
          const previousTools = new Set(
            turns.slice(0, -toolDiversityWindow).flatMap(t => t.toolCalls),
          );
          const newTools = [...allTools].filter(t => !previousTools.has(t));

          if (newTools.length >= toolDiversityThreshold) {
            triggers.push(`tool-diversity: ${newTools.length} new tools in last ${toolDiversityWindow} turns`);
            maxScore = Math.max(maxScore, 0.6);
          }
        }
      }

      // ---------------------------------------------------------------
      // Structural limit: max turns
      // ---------------------------------------------------------------
      if (record.turnNumber > maxTurns) {
        return {
          action: 'reset-session',
          triggers: [`max-turns: ${record.turnNumber}/${maxTurns}`],
          reason: `Session reached maximum turn limit (${maxTurns}). Forced reset.`,
          score: 1.0,
        };
      }

      // ---------------------------------------------------------------
      // Determine action from triggers
      // ---------------------------------------------------------------
      let action: EscalationAction = 'continue';
      if (maxScore >= 0.9) {
        action = 'block-session';
      } else if (maxScore >= 0.7) {
        action = 'reset-session';
      } else if (maxScore >= 0.5) {
        action = 'inject-refusal';
      } else if (triggers.length > 0) {
        action = 'warn-operator';
      }

      return {
        action,
        triggers,
        reason: triggers.length > 0
          ? `Escalation detected: ${triggers.join('; ')}`
          : 'No escalation detected',
        score: maxScore,
      };
  }

  return {
    recordTurn(turn, content?): EscalationResult | Promise<EscalationResult> {
      const turnNumber = turns.length + 1;
      const record: TurnRecord = { ...turn, turnNumber };
      turns.push(record);

      // If embeddingFn is provided and content is available, compute embedding.
      // Errors are caught and fall back to hash-based detection (fail-safe).
      if (embeddingFn && content) {
        try {
          const embeddingResult = embeddingFn(content);
          // Handle both sync and async embedding functions
          if (embeddingResult instanceof Promise) {
            return embeddingResult
              .then(emb => {
                record.embedding = emb;
                return analyze(record);
              })
              .catch(() => {
                // Embedding failed — fall back to hash-based detection
                return analyze(record);
              });
          }
          record.embedding = embeddingResult;
        } catch {
          // Embedding failed — fall back to hash-based detection
        }
      }

      return analyze(record);
    },

    get turnCount() {
      return turns.length;
    },

    get turns(): readonly TurnRecord[] {
      return turns;
    },

    reset() {
      turns.length = 0;
    },
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Compute a content hash for similarity detection.
 * Uses normalized (lowercased, whitespace-collapsed) content
 * hashed with SHA-256 (64 hex chars).
 */
export function contentHash(content: string): string {
  const normalized = content.toLowerCase().replace(/\s+/g, ' ').trim();
  return createHash('sha256').update(normalized, 'utf-8').digest('hex');
}

/**
 * Cosine similarity between two vectors.
 * Returns a value in [-1, 1] where 1 = identical direction.
 * Returns 0 for zero-length vectors.
 */
export function cosineSimilarity(a: number[], b: number[]): number {
  if (a.length !== b.length || a.length === 0) return 0;

  let dot = 0;
  let magA = 0;
  let magB = 0;

  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    magA += a[i] * a[i];
    magB += b[i] * b[i];
  }

  const denom = Math.sqrt(magA) * Math.sqrt(magB);
  if (denom === 0) return 0;
  const result = dot / denom;
  return Number.isFinite(result) ? result : 0;
}

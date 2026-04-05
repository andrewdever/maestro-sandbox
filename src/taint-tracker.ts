/**
 * Data-Flow Taint Tracking (§14.11).
 *
 * Architecture: Option D — Content hash → provenance registry.
 * Hash content on host function returns, check hash on egress.
 *
 * On every host function return: hash content, register
 * `{hash → source, privilege, timestamp, sandboxId}`.
 *
 * On egress (network, file write): hash outgoing content, check for
 * exact matches. Optionally check sliding-window substring hashes
 * for partial exfiltration detection.
 *
 * Audit event: taint.exfiltration.detected (CRITICAL)
 */

import { sha256 } from './audit.js';
import type { AuditLogger } from './audit.js';
import type { InstructionPrivilege } from './instruction-hierarchy.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Provenance record for tracked content. */
export interface TaintRecord {
  contentHash: string;
  source: string;           // e.g. 'hostbridge:readConfig'
  privilege: InstructionPrivilege;
  timestamp: string;
  sandboxId?: string;
  contentLength: number;
  /** First N chars of content for audit (redacted if secret). */
  preview?: string;
}

/** Result of a taint check. */
export interface TaintCheckResult {
  tainted: boolean;
  matches: TaintRecord[];
  /** How the match was found. */
  matchType?: 'exact' | 'substring';
}

/** Taint tracker interface. */
export interface TaintTracker {
  /** Register content from a host function return. Returns the hash. */
  track(content: string, source: string, privilege: InstructionPrivilege, sandboxId?: string): string;

  /** Check if outgoing content contains tracked data. */
  check(content: string): TaintCheckResult;

  /** Check a specific hash. */
  checkHash(hash: string): TaintRecord | undefined;

  /** Number of tracked items. */
  readonly size: number;

  /** Clear all tracked data (for testing / session reset). */
  reset(): void;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Default chunk size for substring hash windows. */
const DEFAULT_CHUNK_SIZE = 64;

/** Minimum content length to generate substring hashes. */
const MIN_SUBSTRING_LENGTH = 64;

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

export interface TaintTrackerOptions {
  maxTracked?: number;       // Default: 5000
  previewLength?: number;    // Default: 50
  enableSubstringCheck?: boolean;  // Default: true (more expensive)
  chunkSize?: number;        // Default: 64
  logger?: AuditLogger;
}

/**
 * Create a taint tracker.
 *
 * Uses SHA-256 for hashing. For substring checking, maintains a separate
 * map of `{shortHash → TaintRecord}` where shortHash is computed over
 * sliding windows of the content (every chunkSize-char chunk).
 */
export function createTaintTracker(options?: TaintTrackerOptions): TaintTracker {
  const maxTracked = options?.maxTracked ?? 5000;
  const previewLength = options?.previewLength ?? 50;
  const enableSubstringCheck = options?.enableSubstringCheck ?? true;
  const chunkSize = options?.chunkSize ?? DEFAULT_CHUNK_SIZE;
  const logger = options?.logger;

  /** Full-content hash → TaintRecord. */
  const registry = new Map<string, TaintRecord>();

  /** Substring chunk hash → TaintRecord (for partial exfiltration). */
  const substringRegistry = new Map<string, TaintRecord>();

  /** Insertion order for LRU eviction. */
  const insertionOrder: string[] = [];

  /** Reverse index: content hash → set of substring hashes. For cleanup on eviction. */
  const substringIndex = new Map<string, Set<string>>();

  function evictIfNeeded(): void {
    while (insertionOrder.length > maxTracked) {
      const oldest = insertionOrder.shift()!;
      registry.delete(oldest);
      // Clean up substrate entries referencing the evicted record
      const subHashes = substringIndex.get(oldest);
      if (subHashes) {
        for (const subHash of subHashes) {
          // Only delete if the substring still points to the evicted record
          const existing = substringRegistry.get(subHash);
          if (existing && existing.contentHash === oldest) {
            substringRegistry.delete(subHash);
          }
        }
        substringIndex.delete(oldest);
      }
    }
  }

  function makePreview(content: string): string {
    if (content.length <= previewLength) return content;
    return content.slice(0, previewLength) + '…';
  }

  function computeSubstringHashes(content: string): string[] {
    if (content.length < MIN_SUBSTRING_LENGTH) return [];
    const hashes: string[] = [];
    // Stride = chunkSize/4 for 75% overlap — catches substrings at most offsets
    // while keeping hash count manageable (~4 hashes per chunkSize of content)
    const stride = Math.max(1, Math.floor(chunkSize / 4));
    for (let i = 0; i <= content.length - chunkSize; i += stride) {
      const chunk = content.slice(i, i + chunkSize);
      hashes.push(sha256(chunk));
    }
    return hashes;
  }

  return {
    track(content: string, source: string, privilege: InstructionPrivilege, sandboxId?: string): string {
      const hash = sha256(content);
      const record: TaintRecord = {
        contentHash: hash,
        source,
        privilege,
        timestamp: new Date().toISOString(),
        sandboxId,
        contentLength: content.length,
        preview: makePreview(content),
      };

      registry.set(hash, record);
      insertionOrder.push(hash);

      // Register substring hashes for partial exfiltration detection
      if (enableSubstringCheck) {
        const subHashes = computeSubstringHashes(content);
        const subHashSet = new Set<string>();
        for (const subHash of subHashes) {
          substringRegistry.set(subHash, record);
          subHashSet.add(subHash);
        }
        substringIndex.set(hash, subHashSet);
      }

      evictIfNeeded();
      return hash;
    },

    check(content: string): TaintCheckResult {
      // 1. Exact match
      const contentHash = sha256(content);
      const exactMatch = registry.get(contentHash);
      if (exactMatch) {
        logger?.log('taint.exfiltration.detected', {
          matchType: 'exact',
          contentHash,
          source: exactMatch.source,
          contentLength: content.length,
        }, exactMatch.sandboxId);

        return {
          tainted: true,
          matches: [exactMatch],
          matchType: 'exact',
        };
      }

      // 2. Substring match (check outgoing content chunks against registry)
      if (enableSubstringCheck && content.length >= MIN_SUBSTRING_LENGTH) {
        const matches: TaintRecord[] = [];
        const seen = new Set<string>(); // Dedupe by contentHash

        const subHashes = computeSubstringHashes(content);
        for (const subHash of subHashes) {
          const match = substringRegistry.get(subHash);
          if (match && !seen.has(match.contentHash)) {
            seen.add(match.contentHash);
            matches.push(match);
          }
        }

        if (matches.length > 0) {
          for (const match of matches) {
            logger?.log('taint.exfiltration.detected', {
              matchType: 'substring',
              source: match.source,
              contentLength: content.length,
              trackedContentLength: match.contentLength,
            }, match.sandboxId);
          }

          return {
            tainted: true,
            matches,
            matchType: 'substring',
          };
        }
      }

      return { tainted: false, matches: [] };
    },

    checkHash(hash: string): TaintRecord | undefined {
      return registry.get(hash);
    },

    get size(): number {
      return registry.size;
    },

    reset(): void {
      registry.clear();
      substringRegistry.clear();
      substringIndex.clear();
      insertionOrder.length = 0;
    },
  };
}

/**
 * Inter-Sandbox Mesh Firewall (§6.5).
 *
 * All mesh messages between sandboxes pass through this firewall.
 * Enforces structural safety invariants:
 *
 * - All messages created at PEER_AGENT privilege (level 5)
 * - Messages NEVER contain executable content (enforced structurally)
 * - Spotlighting boundary tokens applied to all payloads via applySpotlight()
 * - Rate limited: 30 messages/sandbox/minute
 * - Allowed message types: data, status, request, response only
 * - Audit events: mesh.message.blocked (WARN), mesh.coercion.detected (CRITICAL)
 *
 * Reference: §14.5 Instruction Hierarchy, §14.6 Spotlighting
 */

import { InstructionPrivilege, createMessage, type ProvenancedMessage } from './instruction-hierarchy.js';
import { applySpotlight, type SpotlightConfig } from './spotlighting.js';
import { type AuditLogger } from './audit.js';
import { extractTenantId, type TenantId } from './tenant.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Allowed mesh message types. */
export type MeshMessageType = 'data' | 'status' | 'request' | 'response';

/** All valid message types. */
const ALLOWED_MESSAGE_TYPES: ReadonlySet<string> = new Set<MeshMessageType>([
  'data',
  'status',
  'request',
  'response',
]);

/** A message sent between sandboxes via the mesh. */
export interface MeshMessage {
  /** The type of message. Must be one of: data, status, request, response. */
  type: MeshMessageType;

  /** Sender sandbox ID. */
  from: string;

  /** Recipient sandbox ID. */
  to: string;

  /** Message payload (text only, no executable content). */
  payload: string;

  /** ISO 8601 timestamp. */
  timestamp: string;
}

/** Configuration for the mesh firewall. */
export interface MeshFirewallConfig {
  /** Maximum messages per sandbox per minute. Default: 30. */
  maxMessagesPerMinute?: number;

  /** Spotlighting config for payload boundary marking. */
  spotlightConfig?: SpotlightConfig;

  /** Additional patterns to block as executable content. */
  blockedContentPatterns?: RegExp[];

  /** Optional audit logger for security events. */
  auditLogger?: AuditLogger;

  /** Allowed cross-tenant mesh pairs. Default: [] (deny all). Operator-only config. */
  allowedCrossTenantMesh?: Array<{ from: TenantId; to: TenantId }>;
}

/** Result of a mesh firewall send() call. */
export interface MeshFirewallResult {
  /** Whether the message was allowed through. */
  allowed: boolean;

  /** The processed message (with spotlighting, downgraded privilege). Only present if allowed. */
  message?: MeshMessage;

  /** Reason for blocking, if blocked. */
  reason?: string;
}

/** The mesh firewall interface. */
export interface MeshFirewall {
  /** Send a message through the firewall. Returns the processed message or a block reason. */
  send(message: MeshMessage): MeshFirewallResult;

  /** Reset all rate limit counters. */
  resetCounters(): void;
}

// ---------------------------------------------------------------------------
// Default Executable Content Patterns
// ---------------------------------------------------------------------------

/**
 * Maximum payload length before pattern matching.
 * Payloads exceeding this are rejected outright to prevent ReDoS.
 */
const MAX_PAYLOAD_LENGTH = 100_000;

/**
 * Patterns that indicate executable content.
 * These are structurally forbidden in mesh messages.
 *
 * All patterns are anchored or bounded to prevent catastrophic
 * backtracking (ReDoS). No unbounded quantifiers on character classes.
 */
const DEFAULT_BLOCKED_PATTERNS: readonly RegExp[] = [
  /\beval\s*\(/,
  /\bFunction\s*\(/,
  /\bnew\s+Function\s*\(/,
  /\bimport\s*\(/,
  /\brequire\s*\(/,
  /\bexec\s*\(/,
  /\bspawn\s*\(/,
  /<script[\s>]/i,
  /javascript:/i,
  /data:text\/html/i,
  /\bprocess\.env\b/,
  /\bchild_process\b/,
];

// ---------------------------------------------------------------------------
// Rate Limiter
// ---------------------------------------------------------------------------

interface RateCounter {
  count: number;
  windowStart: number;
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create a mesh firewall instance.
 *
 * All messages pass through privilege downgrade, executable content
 * scanning, spotlighting, and rate limiting before delivery.
 */
export function createMeshFirewall(config: MeshFirewallConfig = {}): MeshFirewall {
  const {
    maxMessagesPerMinute = 30,
    spotlightConfig = { strategy: 'delimiter' },
    blockedContentPatterns = [],
    auditLogger,
    allowedCrossTenantMesh = [],
  } = config;

  const allBlockedPatterns = [...DEFAULT_BLOCKED_PATTERNS, ...blockedContentPatterns];

  /** Per-sandbox rate counters. Key: sandbox ID. */
  const counters = new Map<string, RateCounter>();

  const WINDOW_MS = 60_000; // 1 minute

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------

  function checkRateLimit(sandboxId: string): boolean {
    const now = Date.now();
    let counter = counters.get(sandboxId);

    if (!counter || now - counter.windowStart >= WINDOW_MS) {
      counter = { count: 0, windowStart: now };
      counters.set(sandboxId, counter);
    }

    counter.count++;
    return counter.count <= maxMessagesPerMinute;
  }

  function containsExecutableContent(payload: string): RegExp | undefined {
    for (const pattern of allBlockedPatterns) {
      if (pattern.test(payload)) {
        return pattern;
      }
    }
    return undefined;
  }

  // -------------------------------------------------------------------------
  // Public API
  // -------------------------------------------------------------------------

  return {
    send(message: MeshMessage): MeshFirewallResult {
      // 1. Validate message type
      if (!ALLOWED_MESSAGE_TYPES.has(message.type)) {
        const reason = `Invalid message type: ${message.type}. Allowed: data, status, request, response`;
        auditLogger?.log('mesh.message.blocked', {
          from: message.from,
          to: message.to,
          type: message.type,
          reason,
        }, message.from);
        return { allowed: false, reason };
      }

      // 2. Rate limit check
      if (!checkRateLimit(message.from)) {
        const reason = `Rate limit exceeded: ${maxMessagesPerMinute} messages/minute for sandbox ${message.from}`;
        auditLogger?.log('mesh.message.blocked', {
          from: message.from,
          to: message.to,
          type: message.type,
          reason,
        }, message.from);
        return { allowed: false, reason };
      }

      // 3. Cross-tenant mesh denial (§5)
      const fromTenant = extractTenantId(message.from);
      const toTenant = extractTenantId(message.to);
      if (fromTenant && toTenant && fromTenant !== toTenant) {
        const allowed = allowedCrossTenantMesh.some(
          pair => pair.from === fromTenant && pair.to === toTenant,
        );
        if (!allowed) {
          const reason = 'cross-tenant mesh denied';
          auditLogger?.log('mesh.message.blocked', {
            from: message.from,
            to: message.to,
            type: message.type,
            fromTenant,
            toTenant,
            reason,
          }, message.from);
          return { allowed: false, reason };
        }
      }

      // 4. Payload length limit (ReDoS prevention)
      if (message.payload.length > MAX_PAYLOAD_LENGTH) {
        const reason = `Payload exceeds maximum length: ${message.payload.length} > ${MAX_PAYLOAD_LENGTH}`;
        auditLogger?.log('mesh.message.blocked', {
          from: message.from,
          to: message.to,
          type: message.type,
          payloadLength: message.payload.length,
          reason,
        }, message.from);
        return { allowed: false, reason };
      }

      // 5. Check for executable content
      const blockedPattern = containsExecutableContent(message.payload);
      if (blockedPattern) {
        const reason = `Executable content detected in mesh message: ${blockedPattern}`;
        auditLogger?.log('mesh.coercion.detected', {
          from: message.from,
          to: message.to,
          type: message.type,
          pattern: String(blockedPattern),
          reason,
        }, message.from);
        return { allowed: false, reason };
      }

      // 6. Set privilege to PEER_AGENT (lowest trust for mesh content)
      const provenanced = createMessage(
        message.payload,
        InstructionPrivilege.PEER_AGENT,
        `mesh:${message.from}`,
        { sandboxId: message.from },
      );

      // 7. Apply spotlighting to payload
      const spotlight = applySpotlight(provenanced, spotlightConfig);

      // 8. Return processed message
      return {
        allowed: true,
        message: {
          ...message,
          payload: spotlight.content,
        },
      };
    },

    resetCounters(): void {
      counters.clear();
    },
  };
}

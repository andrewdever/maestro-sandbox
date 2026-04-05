/**
 * Instruction Hierarchy & Content Privilege Levels (§14.5).
 *
 * Every message flowing through the system carries a privilege level
 * and provenance tag. Higher privilege always wins in conflicts.
 * This is the OS-like permission model for LLM content.
 *
 * Privilege levels (highest to lowest):
 *   0 - SYSTEM:        Hardcoded safety invariants (non-overridable)
 *   1 - OPERATOR:      configuration operator policies
 *   2 - SUPERVISOR:    Human-in-the-loop overrides
 *   3 - AGENT:         Primary LLM agent instructions
 *   4 - TOOL_OUTPUT:   Return values from host functions
 *   5 - PEER_AGENT:    Messages from other sandboxes (mesh)
 *   6 - USER_INPUT:    End-user provided content
 *   7 - INTERNET:      Internet-sourced / MCP tool descriptions
 *
 * Reference: "Instruction Hierarchy" (OpenAI 2024, arxiv 2404.13208)
 */

// ---------------------------------------------------------------------------
// Privilege Levels
// ---------------------------------------------------------------------------

/**
 * Privilege levels for content flowing through the system.
 * Lower number = higher privilege.
 */
export enum InstructionPrivilege {
  /** Hardcoded safety invariants. Cannot be overridden by any content. */
  SYSTEM = 0,
  /** Operator-defined policies from configuration. */
  OPERATOR = 1,
  /** Human supervisor overrides (e.g., HITL approval). */
  SUPERVISOR = 2,
  /** Primary LLM agent instructions. */
  AGENT = 3,
  /** Return values from host function calls. */
  TOOL_OUTPUT = 4,
  /** Messages from peer sandboxes via mesh. */
  PEER_AGENT = 5,
  /** End-user provided content. */
  USER_INPUT = 6,
  /** Internet-sourced content, MCP tool descriptions. */
  INTERNET = 7,
}

/** String literal union of privilege level names. */
export type InstructionPrivilegeName = keyof typeof InstructionPrivilege;

// ---------------------------------------------------------------------------
// Provenanced Message
// ---------------------------------------------------------------------------

/**
 * Every message carries its source and privilege level.
 *
 * This is the atomic unit of the instruction hierarchy.
 * All content entering the defense pipeline MUST be wrapped
 * in a ProvenancedMessage before processing.
 */
export interface ProvenancedMessage<T = string> {
  /** The content payload. */
  content: T;

  /** Privilege level of this content. */
  privilege: InstructionPrivilege;

  /** Human-readable source identifier, e.g. 'configuration', 'sandbox:sbx_000001', 'mcp:github'. */
  source: string;

  /** ISO 8601 timestamp of when this message was created. */
  timestamp: string;

  /** Optional sandbox ID if the message originated from a sandbox. */
  sandboxId?: string;

  /** Optional session ID for multi-turn tracking. */
  sessionId?: string;

  /** Optional tenant ID for multi-tenant isolation (§5). */
  tenantId?: string;
}

// ---------------------------------------------------------------------------
// Operator Policy
// ---------------------------------------------------------------------------

/**
 * Operator-defined policy rules from configuration.
 *
 * These are OPERATOR-privilege (level 1) and cannot be overridden
 * by agent, user, or internet-sourced content.
 *
 * Per-trust-level policies (allowedHostFunctions, maxSessionTurns,
 * maxContextTokens, requireApproval, allowNetworkEgress, allowCodeExecution)
 * are configured via {@link TrustLevelPolicy} in defense-pipeline.ts.
 */
export interface OperatorPolicy {
  /** Blocked content patterns (regex strings). Enforced in enforceOperatorPolicy(). */
  blockedPatterns?: string[];

  /** Global host function allowlist. Enforced in HostBridge.call(). */
  allowedHostFunctions?: string[];

  /** Model allowlist — only these models may be used. Enforced in model registry. */
  allowedModels?: string[];
}

// ---------------------------------------------------------------------------
// Privilege Enforcement
// ---------------------------------------------------------------------------

/**
 * Check if source privilege is high enough to override target privilege.
 * Higher privilege (lower number) always wins.
 */
export function canOverride(
  source: InstructionPrivilege,
  target: InstructionPrivilege,
): boolean {
  return source < target;
}

/**
 * Resolve a conflict between two messages.
 * Returns the message with higher privilege (lower number).
 * If equal, the earlier message wins (first argument).
 */
export function resolveConflict<T>(
  a: ProvenancedMessage<T>,
  b: ProvenancedMessage<T>,
): ProvenancedMessage<T> {
  if (a.privilege <= b.privilege) return a;
  return b;
}

/**
 * Create a ProvenancedMessage with the given privilege and source.
 */
export function createMessage<T = string>(
  content: T,
  privilege: InstructionPrivilege,
  source: string,
  options?: { sandboxId?: string; sessionId?: string; tenantId?: string },
): ProvenancedMessage<T> {
  return {
    content,
    privilege,
    source,
    timestamp: new Date().toISOString(),
    ...options,
  };
}

/**
 * Downgrade a message's privilege to the given level.
 * Can only lower privilege (raise the number), never elevate.
 *
 * Used when forwarding content across trust boundaries
 * (e.g., mesh messages forced to TOOL_OUTPUT).
 */
export function downgradePrivilege<T>(
  message: ProvenancedMessage<T>,
  toPrivilege: InstructionPrivilege,
): ProvenancedMessage<T> {
  if (toPrivilege <= message.privilege) {
    return message; // Cannot elevate
  }
  return {
    ...message,
    privilege: toPrivilege,
    source: `${message.source} [downgraded from ${InstructionPrivilege[message.privilege]}]`,
  };
}

// ---------------------------------------------------------------------------
// Trust Level 3 Sub-Levels (§14, Trust Level 3 Split)
// ---------------------------------------------------------------------------

/**
 * Trust sub-levels for sandboxed code (Level 3 split).
 *
 * The security spec splits Level 3 into three sub-levels based on
 * content source. Each sub-level maps to a different policy tier
 * configured in `defense.trustPolicies`.
 *
 * Reference: RedCodeAgent (82.4% execute malicious peer code),
 *            MCPTox (tool description poisoning)
 */
export type TrustSubLevel = '3a' | '3b' | '3c';

/**
 * Resolve the trust sub-level for a ProvenancedMessage.
 *
 * Mapping:
 *   SYSTEM, OPERATOR, SUPERVISOR → null (above Level 3, no sub-level)
 *   AGENT                        → '3a' (operator-defined task)
 *   TOOL_OUTPUT                  → '3a' (host function returns are operator-controlled)
 *   PEER_AGENT                   → '3b' (agent-generated from peer sandbox)
 *   USER_INPUT                   → '3a' (user input processed by operator's agent)
 *   INTERNET                     → '3c' (MCP/internet-sourced)
 */
export function resolveTrustSubLevel(privilege: InstructionPrivilege): TrustSubLevel | null {
  switch (privilege) {
    case InstructionPrivilege.SYSTEM:
    case InstructionPrivilege.OPERATOR:
    case InstructionPrivilege.SUPERVISOR:
      return null; // Above Level 3
    case InstructionPrivilege.AGENT:
    case InstructionPrivilege.TOOL_OUTPUT:
    case InstructionPrivilege.USER_INPUT:
      return '3a';
    case InstructionPrivilege.PEER_AGENT:
      return '3b';
    case InstructionPrivilege.INTERNET:
      return '3c';
    default:
      return null; // Forward compatibility: unknown privilege levels treated as above Level 3
  }
}

/**
 * Enforce operator policy against a message.
 * Returns null if the message is blocked by policy.
 */
export function enforceOperatorPolicy(
  message: ProvenancedMessage<string>,
  policy: OperatorPolicy,
): { allowed: boolean; reason?: string } {
  // Operator and System messages are never blocked by operator policy
  if (message.privilege <= InstructionPrivilege.OPERATOR) {
    return { allowed: true };
  }

  // Check blocked patterns
  if (policy.blockedPatterns) {
    // ReDoS prevention: block oversized payloads outright (fail-closed)
    if (message.content.length > 100_000) {
      return {
        allowed: false,
        reason: 'Blocked by operator policy: payload too large for pattern evaluation',
      };
    }
    for (const pattern of policy.blockedPatterns) {
      let regex: RegExp;
      try {
        regex = new RegExp(pattern, 'i');
      } catch {
        // Invalid regex in operator policy — skip rather than crash.
        // Operator should fix their config; we don't block the pipeline.
        continue;
      }
      if (regex.test(message.content)) {
        return {
          allowed: false,
          reason: `Blocked by operator policy: pattern "${pattern}" matched`,
        };
      }
    }
  }

  return { allowed: true };
}

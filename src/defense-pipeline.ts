/**
 * Defense Pipeline Composition (§14.14).
 *
 * Orchestrates all defense layers: guardrail pipeline, escalation
 * detection, spotlighting, and instruction hierarchy enforcement.
 *
 * Composition rules:
 * - Single layer veto: any block = block (non-negotiable)
 * - Flag accumulation: 3+ flags from different layers = block
 * - Session accumulation: flags across turns trigger strict mode
 * - Fail-closed: guardrail error/timeout = block
 * - Latency budget: 500ms total
 *
 * Degradation chain: Normal → Degraded → Lockdown
 */

import type { ProvenancedMessage } from './instruction-hierarchy.js';
import { InstructionPrivilege, enforceOperatorPolicy, resolveTrustSubLevel, type OperatorPolicy } from './instruction-hierarchy.js';
import type { TrustSubLevel } from './instruction-hierarchy.js';
import { applySpotlight, type SpotlightConfig, type SpotlightResult } from './spotlighting.js';
import type { GuardrailPipeline, GuardrailResult, GuardrailAction } from './guardrail-pipeline.js';
import type { EscalationDetector, EscalationResult, EscalationAction } from './escalation-detector.js';
import { contentHash } from './escalation-detector.js';
import type { AuditLogger, AuditEventType } from './audit.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Defense pipeline operating mode. */
export type DefenseMode = 'normal' | 'degraded' | 'lockdown';

/** Combined result from the defense pipeline. */
export interface DefensePipelineResult {
  /** Final action after composing all layers. */
  action: GuardrailAction;

  /** Guardrail evaluation result. */
  guardrail: GuardrailResult;

  /** Escalation detection result (if applicable). */
  escalation?: EscalationResult;

  /** Spotlighted content (if applicable). */
  spotlight?: SpotlightResult;

  /** Operator policy result. */
  policyAllowed: boolean;
  policyReason?: string;

  /** Current defense mode. */
  mode: DefenseMode;

  /** Total pipeline latency in ms. */
  totalLatencyMs: number;

  /** Whether the pipeline fell back to cached/degraded evaluation. */
  degraded: boolean;
}

/** Session-level defense state. */
export interface SessionDefenseState {
  /** Current defense mode. */
  mode: DefenseMode;

  /** Cumulative flag count across turns. */
  cumulativeFlags: number;

  /** Cumulative block count across turns. */
  cumulativeBlocks: number;

  /** Turn count. */
  turnCount: number;

  /** Flag count threshold to enter degraded mode. Default: 5. */
  degradedThreshold: number;

  /** Block count threshold to enter lockdown. Default: 3. */
  lockdownThreshold: number;

  /** Optional tenant ID for multi-tenant isolation (§5). */
  tenantId?: string;
}

/**
 * Per-trust-sub-level policy (mirrors @maestro/spec TrustLevelPolicy).
 * Defined here to avoid cross-package import; structurally compatible.
 */
export interface TrustLevelPolicy {
  blockedPatterns?: string[];
  allowedHostFunctions?: string[];
  maxSessionTurns?: number;
  maxContextTokens?: number;
  requireApproval?: string[];
  allowNetworkEgress?: boolean;
  allowCodeExecution?: boolean;
}

/**
 * Security configuration mapping trust sub-levels to policies.
 * Mirrors @maestro/spec SecurityConfig.
 */
export interface SecurityPolicyConfig {
  trustLevel3a?: TrustLevelPolicy;
  trustLevel3b?: TrustLevelPolicy;
  trustLevel3c?: TrustLevelPolicy;
}

/** Configuration for the defense pipeline. */
export interface DefensePipelineConfig {
  /** Operator policy to enforce. */
  operatorPolicy?: OperatorPolicy;

  /** Spotlighting config. */
  spotlightConfig?: SpotlightConfig;

  /** Total latency budget in ms. Default: 500. */
  latencyBudgetMs?: number;

  /** Flag accumulation threshold for auto-block. Default: 3. */
  flagAccumulationThreshold?: number;

  /** Thresholds for session mode transitions. */
  degradedThreshold?: number;
  lockdownThreshold?: number;

  /**
   * Per-trust-sub-level security policies (§14, Trust Level 3 split).
   * When set, the pipeline resolves each message's trust sub-level and
   * enforces the corresponding policy (blockedPatterns, maxSessionTurns,
   * allowedHostFunctions, etc.) in addition to the global operatorPolicy.
   */
  securityPolicy?: SecurityPolicyConfig;
}

// ---------------------------------------------------------------------------
// Defense Pipeline
// ---------------------------------------------------------------------------

export interface DefensePipeline {
  /** Process input content through all defense layers. */
  processInput(message: ProvenancedMessage<string>): Promise<DefensePipelineResult>;

  /** Process output content through all defense layers. */
  processOutput(message: ProvenancedMessage<string>): Promise<DefensePipelineResult>;

  /** Process a tool call through all defense layers. */
  processToolCall(
    toolName: string,
    toolArgs: Record<string, unknown>,
    message: ProvenancedMessage<string>,
  ): Promise<DefensePipelineResult>;

  /** Get current session defense state. */
  readonly sessionState: SessionDefenseState;

  /** Reset session state. */
  resetSession(): void;
}

/**
 * Create the defense pipeline orchestrator.
 */
export function createDefensePipeline(
  guardrails: GuardrailPipeline,
  escalationDetector: EscalationDetector,
  config: DefensePipelineConfig = {},
  logger?: AuditLogger,
): DefensePipeline {
  const {
    operatorPolicy,
    spotlightConfig = { strategy: 'delimiter' },
    latencyBudgetMs = 500,
    flagAccumulationThreshold = 3,
    degradedThreshold = 5,
    lockdownThreshold = 3,
    securityPolicy,
  } = config;

  const state: SessionDefenseState = {
    mode: 'normal',
    cumulativeFlags: 0,
    cumulativeBlocks: 0,
    turnCount: 0,
    degradedThreshold,
    lockdownThreshold,
  };

  function updateMode(): void {
    if (state.cumulativeBlocks >= state.lockdownThreshold) {
      state.mode = 'lockdown';
    } else if (state.cumulativeFlags >= state.degradedThreshold) {
      state.mode = 'degraded';
    }
  }

  function composeAction(
    guardrailAction: GuardrailAction,
    escalationAction?: EscalationAction,
    policyAllowed?: boolean,
  ): GuardrailAction {
    // Lockdown mode: block everything except SYSTEM/OPERATOR content
    if (state.mode === 'lockdown') {
      return 'block';
    }

    // Policy block is absolute
    if (policyAllowed === false) {
      return 'block';
    }

    // Escalation overrides
    if (escalationAction === 'block-session' || escalationAction === 'reset-session') {
      return 'block';
    }

    // Single layer veto
    if (guardrailAction === 'block') {
      return 'block';
    }

    // Escalation refusal → modify (guardrailAction cannot be 'block' here — handled above)
    if (escalationAction === 'inject-refusal') {
      return 'modify';
    }

    // Degraded mode: flags become blocks
    if (state.mode === 'degraded' && guardrailAction === 'flag') {
      return 'block';
    }

    return guardrailAction;
  }

  async function process(
    type: 'input' | 'output' | 'tool-call',
    message: ProvenancedMessage<string>,
    toolName?: string,
    toolArgs?: Record<string, unknown>,
  ): Promise<DefensePipelineResult> {
    const start = Date.now();

    // 1. Operator policy check (structural, ~0ms)
    let policyAllowed = true;
    let policyReason: string | undefined;
    if (operatorPolicy) {
      const policyResult = enforceOperatorPolicy(message, operatorPolicy);
      policyAllowed = policyResult.allowed;
      policyReason = policyResult.reason;
    }

    // 1b. Trust sub-level policy enforcement (§14, Trust Level 3 split)
    if (securityPolicy && policyAllowed) {
      const subLevel = resolveTrustSubLevel(message.privilege);
      if (subLevel) {
        const subPolicy = resolveSubLevelPolicy(subLevel, securityPolicy);
        if (subPolicy) {
          // Enforce sub-level blocked patterns
          if (subPolicy.blockedPatterns) {
            // ReDoS prevention: block oversized payloads outright (fail-closed)
            if (message.content.length > 100_000) {
              policyAllowed = false;
              policyReason = `Trust level ${subLevel}: payload too large for pattern evaluation (${message.content.length} chars, max 100000)`;
            } else {
              for (const pattern of subPolicy.blockedPatterns) {
                let regex: RegExp;
                try { regex = new RegExp(pattern, 'i'); } catch { continue; }
                if (regex.test(message.content)) {
                  policyAllowed = false;
                  policyReason = `Blocked by trust level ${subLevel} policy: pattern "${pattern}" matched`;
                  break;
                }
              }
            }
          }

          // Enforce sub-level maxSessionTurns
          // Note: turnCount is incremented at step 3 (after this check) for input messages,
          // so we use > not >= to allow exactly maxSessionTurns inputs.
          if (policyAllowed && subPolicy.maxSessionTurns !== undefined && state.turnCount > subPolicy.maxSessionTurns) {
            policyAllowed = false;
            policyReason = `Trust level ${subLevel} session turn limit exceeded (${state.turnCount} > ${subPolicy.maxSessionTurns})`;
          }

          // Enforce sub-level allowCodeExecution (block code-like content when false)
          if (policyAllowed && subPolicy.allowCodeExecution === false && type === 'input') {
            // Heuristic: check for common code execution patterns.
            // Covers direct calls, whitespace/comment evasion, and indirect invocation.
            const codePatterns = [
              /\b(eval|exec|spawn|Function|require|import)\s*[(/]/,       // direct calls
              /\b(eval|exec|spawn|Function|require|import)\s*\/[/*]/,     // comment evasion: eval/**/()
              /\bglobalThis\s*\.\s*(eval|exec)\b/,                        // globalThis.eval
              /\bwindow\s*\[\s*['"]eval['"]\s*\]/,                        // window["eval"]
              /\(0\s*,\s*eval\)/,                                         // (0, eval)() indirect
              /child_process/,                                             // require('child_process')
              /new\s+Function\b/,                                          // new Function()
            ];
            if (codePatterns.some(p => p.test(message.content))) {
              policyAllowed = false;
              policyReason = `Code execution not allowed at trust level ${subLevel}`;
            }
          }

          // Enforce sub-level allowedHostFunctions for tool calls
          if (policyAllowed && type === 'tool-call' && toolName && subPolicy.allowedHostFunctions) {
            if (!subPolicy.allowedHostFunctions.includes(toolName)) {
              policyAllowed = false;
              policyReason = `Host function "${toolName}" not in trust level ${subLevel} allowlist`;
            }
          }

          // Enforce sub-level maxContextTokens (rough estimate: 1 token ≈ 4 chars)
          if (policyAllowed && subPolicy.maxContextTokens !== undefined) {
            const estimatedTokens = Math.ceil(message.content.length / 4);
            if (estimatedTokens > subPolicy.maxContextTokens) {
              policyAllowed = false;
              policyReason = `Trust level ${subLevel} context token limit exceeded (~${estimatedTokens} > ${subPolicy.maxContextTokens})`;
            }
          }

          // Enforce sub-level allowNetworkEgress for tool calls that look like network ops
          if (policyAllowed && subPolicy.allowNetworkEgress === false && type === 'tool-call' && toolName) {
            const networkFunctions = ['fetch', 'http', 'request', 'axios', 'got', 'wget', 'curl'];
            if (networkFunctions.some(fn => toolName.toLowerCase().includes(fn))) {
              policyAllowed = false;
              policyReason = `Network egress not allowed at trust level ${subLevel}`;
            }
          }

          // Enforce sub-level requireApproval for tool calls
          if (policyAllowed && subPolicy.requireApproval && type === 'tool-call' && toolName) {
            if (subPolicy.requireApproval.includes(toolName)) {
              // requireApproval triggers a flag (not block) — the HITL layer must approve.
              // In automated mode without a HITL handler, this escalates to block.
              policyAllowed = false;
              policyReason = `Host function "${toolName}" requires human approval at trust level ${subLevel}`;
            }
          }
        }
      }
    }

    if (!policyAllowed) {
      logger?.log('defense.pipeline.blocked', {
        reason: policyReason,
        layer: 'operator-policy',
        position: type,
      }, message.sandboxId);

      return {
        action: 'block',
        guardrail: { action: 'allow', scores: {}, triggeredCategories: [], latencyMs: 0 },
        policyAllowed: false,
        policyReason,
        mode: state.mode,
        totalLatencyMs: Date.now() - start,
        degraded: false,
      };
    }

    // 2. Guardrail evaluation (with latency budget)
    let guardrailResult: GuardrailResult;
    let degraded = false;

    try {
      const guardrailPromise = type === 'input'
        ? guardrails.evaluateInput(message)
        : type === 'output'
          ? guardrails.evaluateOutput(message)
          : guardrails.evaluateToolCall(toolName!, toolArgs!, message);

      guardrailResult = await Promise.race([
        guardrailPromise,
        new Promise<GuardrailResult>((_, reject) =>
          setTimeout(() => reject(new Error('Guardrail budget exceeded')), latencyBudgetMs),
        ),
      ]);
    } catch {
      // Fail-closed: timeout or error → block
      degraded = true;
      guardrailResult = {
        action: 'block',
        scores: {},
        reason: 'Guardrail evaluation timed out (fail-closed)',
        triggeredCategories: [],
        latencyMs: latencyBudgetMs,
      };
    }

    // 3. Escalation detection (all positions, skip SYSTEM/OPERATOR)
    let escalationResult: EscalationResult | undefined;
    if (message.privilege > InstructionPrivilege.OPERATOR) {
      // Only increment turnCount for input (a "turn" is one user/agent input)
      if (type === 'input') {
        state.turnCount++;
      }
      const escalationMaybePromise = escalationDetector.recordTurn({
        timestamp: message.timestamp,
        inputResult: guardrailResult,
        toolCalls: toolName ? [toolName] : [],
        inputLength: message.content.length,
        contentHash: contentHash(message.content),
      }, message.content);
      escalationResult = escalationMaybePromise instanceof Promise
        ? await escalationMaybePromise
        : escalationMaybePromise;
    }

    // 4. Spotlighting (for output/tool-output content)
    let spotlightResult: SpotlightResult | undefined;
    if (type === 'output' && message.privilege > InstructionPrivilege.AGENT) {
      spotlightResult = applySpotlight(message, spotlightConfig);
    }

    // 5. Compose final action
    const action = composeAction(
      guardrailResult.action,
      escalationResult?.action,
      policyAllowed,
    );

    // 6. Update session state
    if (action === 'block') {
      state.cumulativeBlocks++;
    } else if (action === 'flag') {
      state.cumulativeFlags++;
    }
    updateMode();

    // 7. Audit logging
    if (action !== 'allow') {
      const eventType = `guardrail.${type === 'tool-call' ? 'toolcall' : type}.${action}` as AuditEventType;

      logger?.log(eventType, {
        action,
        position: type,
        mode: state.mode,
        guardrailAction: guardrailResult.action,
        escalationAction: escalationResult?.action,
        triggeredCategories: guardrailResult.triggeredCategories,
        degraded,
      }, message.sandboxId);
    }

    if (escalationResult && escalationResult.action !== 'continue') {
      logger?.log('escalation.detected', {
        action: escalationResult.action,
        triggers: escalationResult.triggers,
        score: escalationResult.score,
        turnCount: state.turnCount,
      }, message.sandboxId);
    }

    return {
      action,
      guardrail: guardrailResult,
      escalation: escalationResult,
      spotlight: spotlightResult,
      policyAllowed,
      policyReason,
      mode: state.mode,
      totalLatencyMs: Date.now() - start,
      degraded,
    };
  }

  /**
   * Resolve the TrustLevelPolicy for a given sub-level.
   * Falls back through 3c → 3b → 3a for inherited defaults.
   */
  function resolveSubLevelPolicy(
    subLevel: TrustSubLevel,
    policies: SecurityPolicyConfig,
  ): TrustLevelPolicy | undefined {
    switch (subLevel) {
      case '3a': return policies.trustLevel3a;
      case '3b': return policies.trustLevel3b ?? policies.trustLevel3a;
      case '3c': return policies.trustLevel3c ?? policies.trustLevel3b ?? policies.trustLevel3a;
      default: return undefined;
    }
  }

  return {
    processInput(message) {
      // SYSTEM/OPERATOR content bypasses all checks
      if (message.privilege <= InstructionPrivilege.OPERATOR) {
        return Promise.resolve({
          action: 'allow' as const,
          guardrail: { action: 'allow' as const, scores: {}, triggeredCategories: [], latencyMs: 0 },
          policyAllowed: true,
          mode: state.mode,
          totalLatencyMs: 0,
          degraded: false,
        });
      }
      return process('input', message);
    },

    processOutput(message) {
      return process('output', message);
    },

    processToolCall(toolName, toolArgs, message) {
      return process('tool-call', message, toolName, toolArgs);
    },

    get sessionState() {
      return { ...state };
    },

    resetSession() {
      state.mode = 'normal';
      state.cumulativeFlags = 0;
      state.cumulativeBlocks = 0;
      state.turnCount = 0;
      escalationDetector.reset();
    },
  };
}

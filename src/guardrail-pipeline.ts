/**
 * Guardrail Pipeline (§14.7).
 *
 * Three-position evaluator (input, output, tool-call) with 11 safety
 * categories and per-category unsafety scoring.
 *
 * Design:
 * - Each guardrail position runs independently
 * - Per-category unsafety scores (0-1) inspired by R2-Guard approach
 * - Actions: allow | flag | modify | block
 * - Single layer veto: any block = block (non-negotiable)
 * - Fail-closed: evaluator error/timeout = block
 *
 * Reference: R2-Guard (ICLR 2025) — per-category unsafety probabilities
 */

import type { ProvenancedMessage } from './instruction-hierarchy.js';
import { InstructionPrivilege } from './instruction-hierarchy.js';

// ---------------------------------------------------------------------------
// Safety Categories
// ---------------------------------------------------------------------------

/**
 * The 11 safety categories evaluated by guardrails.
 *
 * P2 additions (OWASP LLM Top 10 coverage):
 * - 'training-data-poisoning' (LLM03): Attempts to inject malicious data
 *   into fine-tuning datasets or manipulate training pipelines.
 * - 'model-theft' (LLM10): Attempts to extract model weights, architecture,
 *   or proprietary model information.
 */
export type SafetyCategory =
  | 'prompt-injection'
  | 'credential-exfiltration'
  | 'sandbox-escape'
  | 'data-exfiltration'
  | 'privilege-escalation'
  | 'resource-abuse'
  | 'social-engineering'
  | 'tool-misuse'
  | 'harmful-content'
  | 'training-data-poisoning'
  | 'model-theft';

export const ALL_SAFETY_CATEGORIES: readonly SafetyCategory[] = [
  'prompt-injection',
  'credential-exfiltration',
  'sandbox-escape',
  'data-exfiltration',
  'privilege-escalation',
  'resource-abuse',
  'social-engineering',
  'tool-misuse',
  'harmful-content',
  'training-data-poisoning',
  'model-theft',
] as const;

// ---------------------------------------------------------------------------
// Guardrail Types
// ---------------------------------------------------------------------------

/** Position in the defense pipeline where a guardrail runs. */
export type GuardrailPosition = 'input' | 'output' | 'tool-call';

/** Action to take based on guardrail evaluation. */
export type GuardrailAction = 'allow' | 'flag' | 'modify' | 'block';

/** Per-category unsafety score (0 = safe, 1 = maximum unsafety). */
export type CategoryScores = Partial<Record<SafetyCategory, number>>;

/** Result of a single guardrail evaluation. */
export interface GuardrailResult {
  /** The action determined by the guardrail. */
  action: GuardrailAction;

  /** Per-category unsafety scores. Only categories with non-zero scores are included. */
  scores: CategoryScores;

  /** Human-readable reason for the action. */
  reason?: string;

  /** Which categories triggered the action (scores above threshold). */
  triggeredCategories: SafetyCategory[];

  /** Time taken for evaluation in milliseconds. */
  latencyMs: number;
}

/** Thresholds for converting scores to actions. */
export interface GuardrailThresholds {
  /** Score >= this triggers a block. Default: 0.9 */
  block: number;
  /** Score >= this triggers a flag. Default: 0.5 */
  flag: number;
  /** Score >= this triggers a modify (sanitize). Default: 0.7 */
  modify: number;
}

/** Configuration for the guardrail pipeline. */
export interface GuardrailConfig {
  /** Per-category thresholds. Falls back to defaults if not specified. */
  thresholds?: Partial<Record<SafetyCategory, GuardrailThresholds>>;

  /** Global default thresholds. */
  defaultThresholds?: GuardrailThresholds;

  /** Categories to skip entirely. */
  disabledCategories?: SafetyCategory[];

  /** Timeout for individual evaluator calls in ms. Default: 200. */
  evaluatorTimeoutMs?: number;
}

// ---------------------------------------------------------------------------
// Evaluator Interface
// ---------------------------------------------------------------------------

/**
 * A guardrail evaluator scores content against safety categories.
 *
 * Implementations can range from regex patterns (fast, low accuracy)
 * to ML models like LlamaGuard 3 (slower, high accuracy).
 */
export interface GuardrailEvaluator {
  /** Unique identifier for this evaluator. */
  readonly name: string;

  /** Evaluate content and return per-category unsafety scores. */
  evaluate(
    content: string,
    position: GuardrailPosition,
    context?: EvaluatorContext,
  ): Promise<CategoryScores>;
}

/** Context passed to evaluators for richer analysis. */
export interface EvaluatorContext {
  /** Source of the content. */
  source?: string;
  /** Privilege level. */
  privilege?: InstructionPrivilege;
  /** Sandbox ID. */
  sandboxId?: string;
  /** Session ID for multi-turn tracking. */
  sessionId?: string;
  /** Tool name (for tool-call position). */
  toolName?: string;
  /** Tool arguments (for tool-call position). */
  toolArgs?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Default Thresholds
// ---------------------------------------------------------------------------

const DEFAULT_THRESHOLDS: GuardrailThresholds = {
  block: 0.9,
  modify: 0.7,
  flag: 0.5,
};

// ---------------------------------------------------------------------------
// Built-in Pattern Evaluator
// ---------------------------------------------------------------------------

/**
 * Regex-based evaluator for fast, low-latency pattern matching.
 * This is the first layer — catches obvious attacks with ~0ms latency.
 * Not sufficient alone (trivially bypassed), but fast and free.
 */
export function createPatternEvaluator(): GuardrailEvaluator {
  return {
    name: 'pattern-evaluator',
    async evaluate(content: string, position: GuardrailPosition): Promise<CategoryScores> {
      const scores: CategoryScores = {};
      const lower = content.toLowerCase();

      // Prompt injection patterns (Layer 1: regex — fast, low accuracy.
      // Known limitation: trivially bypassed by paraphrasing. Layer 2 ML evaluator
      // provides deeper coverage.)
      if (position === 'input' || position === 'output') {
        const injectionPatterns = [
          /ignore\s+(all\s+)?previous\s+instructions/i,
          /ignore\s+(?:the\s+)?(?:prior|initial|first|original)\s+/i,
          /you\s+are\s+now\s+(?:a|an|in)\s+/i,
          /system\s*:\s*you\s+/i,
          /\bdo\s+not\s+follow\s+(the\s+)?(above|previous)\b/i,
          /\boverride\s+(all\s+)?(safety|rules|instructions)\b/i,
          /\bact\s+as\s+(if\s+)?(you\s+are|a)\b/i,
          /\b(?:pretend|imagine|assume)\s+(?:you\s+)?are\s+/i,
          /\bfrom\s+now\s+on\b/i,
          /\bforget\s+(?:everything|the\s+previous|all\s+prior|this\s+context)\b/i,
          /\bnew\s+instructions?\s*:/i,
          /\bjailbreak\b/i,
          /\bdan\s*mode\b/i,
          /\bdev(eloper)?\s*mode\b/i,
        ];
        const matches = injectionPatterns.filter(p => p.test(content));
        if (matches.length > 0) {
          scores['prompt-injection'] = Math.min(1.0, 0.3 + matches.length * 0.2);
        }
      }

      // Credential exfiltration patterns
      if (position === 'output' || position === 'tool-call') {
        const credPatterns = [
          /(?:api[_-]?key|secret|token|password|credential|auth)[=:]\s*\S+/i,
          /(?:AWS|AZURE|GCP|GITHUB|OPENAI)[_A-Z]*(?:KEY|SECRET|TOKEN)/,
          /Bearer\s+[A-Za-z0-9\-._~+/]+=*/,
          /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/,
        ];
        const matches = credPatterns.filter(p => p.test(content));
        if (matches.length > 0) {
          scores['credential-exfiltration'] = Math.min(1.0, 0.4 + matches.length * 0.2);
        }
      }

      // Sandbox escape patterns
      {
        const escapePatterns = [
          /process\.(?:exit|kill|abort|env)/,
          /child_process/,
          /require\s*\(\s*['"](?:fs|net|http|child_process|os|cluster|worker_threads)['"]\s*\)/,
          /import\s+.*from\s+['"](?:fs|net|http|child_process|os|cluster|worker_threads)['"]/,
          /eval\s*\(/,
          /Function\s*\(/,
          /Reflect\.(?:construct|apply)/,
        ];
        const matches = escapePatterns.filter(p => p.test(content));
        if (matches.length > 0) {
          scores['sandbox-escape'] = Math.min(1.0, 0.3 + matches.length * 0.15);
        }
      }

      // Data exfiltration patterns
      if (position === 'tool-call' || position === 'output') {
        const exfilPatterns = [
          /fetch\s*\(\s*['"]https?:\/\//i,
          /XMLHttpRequest/,
          /navigator\.sendBeacon/,
          /\.webhook\./i,
          /ngrok\.io/i,
          /requestbin/i,
          /pipedream/i,
        ];
        const matches = exfilPatterns.filter(p => p.test(content));
        if (matches.length > 0) {
          scores['data-exfiltration'] = Math.min(1.0, 0.3 + matches.length * 0.2);
        }
      }

      // Privilege escalation patterns
      {
        const privEscPatterns = [
          /sudo\s+/i,
          /chmod\s+[0-7]*7[0-7]*/,
          /chown\s+root/i,
          /setuid/i,
          /privilege/i,
        ];
        const matches = privEscPatterns.filter(p => p.test(content));
        if (matches.length > 0) {
          scores['privilege-escalation'] = Math.min(1.0, 0.2 + matches.length * 0.15);
        }
      }

      // Training data poisoning patterns (OWASP LLM03)
      // Split into intent patterns (high signal: always score) and topic patterns
      // (low signal: only score when paired with intent to reduce false positives
      // on legitimate ML discussions like "how does fine-tuning work?").
      {
        // Intent patterns — describe malicious action + ML target
        const intentPatterns = [
          /inject.*(?:dataset|training|corpus)/i,
          /poison(?:ed|ing)?\s+(?:data|model|training|samples)/i,
          /backdoor\s+(?:trigger|injection|attack)/i,
          /trojan\s+(?:attack|model|trigger)/i,
          /corrupt\s+(?:the\s+)?(?:training|model|weights|dataset)/i,
          /manipulat(?:e|ing)\s+(?:training|fine[_-]?tun|dataset)/i,
          /adversarial\s+(?:training\s+)?(?:examples?|samples?|inputs?)\s+(?:to|into|for)\s+/i,
        ];
        // Topic patterns — ML terms that are benign alone but amplify intent
        const topicPatterns = [
          /fine[_-]?tun(?:e|ing)/i,
          /training[_-]?data/i,
        ];
        const intentMatches = intentPatterns.filter(p => p.test(content));
        const topicMatches = topicPatterns.filter(p => p.test(content));
        if (intentMatches.length > 0) {
          // Intent detected: score based on intent + amplify with topic co-occurrence
          scores['training-data-poisoning'] = Math.min(1.0, 0.4 + intentMatches.length * 0.2 + topicMatches.length * 0.1);
        } else if (topicMatches.length >= 2) {
          // Multiple topic terms without intent — low score for monitoring only
          scores['training-data-poisoning'] = 0.2;
        }
      }

      // Model theft patterns (OWASP LLM10)
      // Same intent/topic split to avoid flagging "describe model architecture".
      {
        // Intent patterns — describe extraction/theft action
        const intentPatterns = [
          /(?:extract|steal|dump|export)\s+(?:the\s+)?(?:model|weights|parameters|embeddings)/i,
          /(?:download|copy|replicate|clone)\s+(?:the\s+)?model/i,
          /\bmodel\s+(?:extraction|stealing|theft|cloning)\b/i,
          /logits?\s+(?:extraction|stealing|output)/i,
          /(?:save|serialize|pickle|torch\.save)\s*\(.*model/i,
          /(?:onnx|torchscript|safetensors).*(?:export|convert|save)/i,
          /\b(?:distill|distillation)\s+(?:the\s+)?(?:model|knowledge)\b/i,
        ];
        // Topic patterns — benign ML terms that amplify intent
        const topicPatterns = [
          /model\s+(?:weights|parameters|architecture|checkpoint)/i,
        ];
        const intentMatches = intentPatterns.filter(p => p.test(content));
        const topicMatches = topicPatterns.filter(p => p.test(content));
        if (intentMatches.length > 0) {
          scores['model-theft'] = Math.min(1.0, 0.4 + intentMatches.length * 0.2 + topicMatches.length * 0.1);
        } else if (topicMatches.length >= 2) {
          scores['model-theft'] = 0.2;
        }
      }

      return scores;
    },
  };
}

// ---------------------------------------------------------------------------
// Guardrail Pipeline
// ---------------------------------------------------------------------------

export interface GuardrailPipeline {
  /** Evaluate input content (before it reaches the agent). */
  evaluateInput(message: ProvenancedMessage<string>): Promise<GuardrailResult>;

  /** Evaluate output content (agent response before delivery). */
  evaluateOutput(message: ProvenancedMessage<string>): Promise<GuardrailResult>;

  /** Evaluate a tool call (before execution). */
  evaluateToolCall(
    toolName: string,
    toolArgs: Record<string, unknown>,
    message: ProvenancedMessage<string>,
  ): Promise<GuardrailResult>;
}

/**
 * Create a guardrail pipeline with the given evaluators and config.
 *
 * Evaluators are run in parallel. Scores are merged by taking the
 * maximum per category. Thresholds determine the final action.
 */
export function createGuardrailPipeline(
  evaluators: GuardrailEvaluator[],
  config: GuardrailConfig = {},
): GuardrailPipeline {
  const {
    defaultThresholds = DEFAULT_THRESHOLDS,
    disabledCategories = [],
    evaluatorTimeoutMs = 200,
  } = config;
  const disabledSet = new Set(disabledCategories);

  function getThresholds(category: SafetyCategory): GuardrailThresholds {
    return config.thresholds?.[category] ?? defaultThresholds;
  }

  /**
   * Run all evaluators, merge scores, and determine action.
   */
  async function evaluate(
    content: string,
    position: GuardrailPosition,
    context: EvaluatorContext,
  ): Promise<GuardrailResult> {
    const start = Date.now();

    // Run evaluators in parallel with timeout
    const scoreResults = await Promise.allSettled(
      evaluators.map(evaluator =>
        Promise.race([
          evaluator.evaluate(content, position, context),
          new Promise<CategoryScores>((_, reject) =>
            setTimeout(() => reject(new Error(`${evaluator.name} timed out`)), evaluatorTimeoutMs),
          ),
        ]),
      ),
    );

    // Merge scores: max per category
    const merged: CategoryScores = {};
    const failedEvaluators: string[] = [];

    for (let i = 0; i < scoreResults.length; i++) {
      const result = scoreResults[i];
      if (result.status === 'fulfilled') {
        for (const [cat, score] of Object.entries(result.value) as [SafetyCategory, number][]) {
          if (disabledSet.has(cat)) continue;
          merged[cat] = Math.max(merged[cat] ?? 0, score);
        }
      } else {
        // Fail-closed: evaluator timeout/error
        failedEvaluators.push(evaluators[i].name);
      }
    }

    // Determine action from merged scores
    let action: GuardrailAction = 'allow';
    const triggeredCategories: SafetyCategory[] = [];
    const reasons: string[] = [];

    // Fail-closed on evaluator error
    if (failedEvaluators.length > 0) {
      action = 'block';
      reasons.push(`Evaluator timeout/error (fail-closed): ${failedEvaluators.join(', ')}`);
    }

    for (const [cat, score] of Object.entries(merged) as [SafetyCategory, number][]) {
      const thresholds = getThresholds(cat);

      if (score >= thresholds.block) {
        action = 'block';
        triggeredCategories.push(cat);
        reasons.push(`${cat}: ${score.toFixed(2)} >= block(${thresholds.block})`);
      } else if (score >= thresholds.modify && action !== 'block') {
        action = 'modify';
        triggeredCategories.push(cat);
        reasons.push(`${cat}: ${score.toFixed(2)} >= modify(${thresholds.modify})`);
      } else if (score >= thresholds.flag && action !== 'block' && action !== 'modify') {
        action = 'flag';
        triggeredCategories.push(cat);
        reasons.push(`${cat}: ${score.toFixed(2)} >= flag(${thresholds.flag})`);
      }
    }

    return {
      action,
      scores: merged,
      reason: reasons.length > 0 ? reasons.join('; ') : undefined,
      triggeredCategories,
      latencyMs: Date.now() - start,
    };
  }

  return {
    async evaluateInput(message) {
      // SYSTEM and OPERATOR content is trusted — skip evaluation
      if (message.privilege <= InstructionPrivilege.OPERATOR) {
        return {
          action: 'allow',
          scores: {},
          triggeredCategories: [],
          latencyMs: 0,
        };
      }

      return evaluate(message.content, 'input', {
        source: message.source,
        privilege: message.privilege,
        sandboxId: message.sandboxId,
        sessionId: message.sessionId,
      });
    },

    async evaluateOutput(message) {
      return evaluate(message.content, 'output', {
        source: message.source,
        privilege: message.privilege,
        sandboxId: message.sandboxId,
        sessionId: message.sessionId,
      });
    },

    async evaluateToolCall(toolName, toolArgs, message) {
      // Serialize tool call for evaluation
      const content = JSON.stringify({ tool: toolName, args: toolArgs });

      return evaluate(content, 'tool-call', {
        source: message.source,
        privilege: message.privilege,
        sandboxId: message.sandboxId,
        sessionId: message.sessionId,
        toolName,
        toolArgs,
      });
    },
  };
}

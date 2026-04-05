/**
 * MCP Tool Description Scanner (§4.2, §14.15).
 *
 * Scans MCP tool definitions for prompt injection and other safety
 * violations. Tool descriptions are treated as INTERNET privilege
 * (level 7) — the lowest trust tier — because they originate from
 * external tool servers.
 *
 * Pipeline:
 * 1. Concatenate all scannable text (name, description, parameters, examples)
 * 2. Run through the pattern evaluator from guardrail-pipeline.ts
 * 3. Score against all safety categories
 * 4. Wrap sanitized descriptions in spotlight boundary tokens
 * 5. Return scan results + sanitized descriptions
 *
 * Reference: §14.5 Instruction Hierarchy, §14.6 Spotlighting, §14.7 Guardrails
 */

import { InstructionPrivilege, createMessage } from './instruction-hierarchy.js';
import { applySpotlight, type SpotlightConfig } from './spotlighting.js';
import {
  createPatternEvaluator,
  type GuardrailEvaluator,
  type CategoryScores,
  type SafetyCategory,
  type GuardrailThresholds,
} from './guardrail-pipeline.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** An MCP tool definition to scan. */
export interface McpToolDefinition {
  /** Tool name. */
  name: string;

  /** Tool description. */
  description: string;

  /** Parameter definitions with optional descriptions and examples. */
  parameters?: Record<string, {
    description?: string;
    type?: string;
    examples?: string[];
  }>;
}

/** Result of scanning a single MCP tool definition. */
export interface McpScanResult {
  /** Tool name. */
  tool: string;

  /** Whether the tool passed all safety checks. */
  safe: boolean;

  /** Per-category unsafety scores. */
  scores: CategoryScores;

  /** Categories that exceeded their threshold. */
  triggeredCategories: SafetyCategory[];

  /** The description with spotlight boundary tokens applied. */
  sanitizedDescription: string;

  /** Human-readable reason if unsafe. */
  reason?: string;
}

/** Configuration for the MCP scanner. */
export interface McpScannerConfig {
  /** Custom evaluators (defaults to pattern evaluator). */
  evaluators?: GuardrailEvaluator[];

  /** Spotlighting config for sanitized descriptions. */
  spotlightConfig?: SpotlightConfig;

  /** Threshold for flagging a tool as unsafe. Default: 0.5. */
  unsafeThreshold?: number;

  /** Per-category custom thresholds. */
  thresholds?: Partial<Record<SafetyCategory, GuardrailThresholds>>;
}

/** The MCP scanner interface. */
export interface McpScanner {
  /** Scan a single tool definition. */
  scanTool(tool: McpToolDefinition): Promise<McpScanResult>;

  /** Scan multiple tool definitions. */
  scanTools(tools: McpToolDefinition[]): Promise<McpScanResult[]>;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Extract all scannable text from an MCP tool definition.
 * Concatenates name, description, parameter descriptions, and examples.
 */
function extractScannableText(tool: McpToolDefinition): string {
  const parts: string[] = [tool.name, tool.description];

  if (tool.parameters) {
    for (const [paramName, paramDef] of Object.entries(tool.parameters)) {
      parts.push(paramName);
      if (paramDef.description) {
        parts.push(paramDef.description);
      }
      if (paramDef.examples) {
        parts.push(...paramDef.examples);
      }
    }
  }

  return parts.join('\n');
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create an MCP tool description scanner.
 *
 * Scans tool definitions for prompt injection and safety violations.
 * All descriptions are treated as INTERNET privilege (level 7) and
 * wrapped in spotlight boundary tokens.
 */
export function createMcpScanner(config: McpScannerConfig = {}): McpScanner {
  const {
    evaluators = [createPatternEvaluator()],
    spotlightConfig = { strategy: 'delimiter' },
    unsafeThreshold = 0.5,
  } = config;

  async function scanTool(tool: McpToolDefinition): Promise<McpScanResult> {
    const scannableText = extractScannableText(tool);

    // Run all evaluators and merge scores (max per category)
    const allScores = await Promise.all(
      evaluators.map(evaluator => evaluator.evaluate(scannableText, 'input')),
    );

    const merged: CategoryScores = {};
    for (const scores of allScores) {
      for (const [cat, score] of Object.entries(scores) as [SafetyCategory, number][]) {
        merged[cat] = Math.max(merged[cat] ?? 0, score);
      }
    }

    // Determine triggered categories
    const triggeredCategories: SafetyCategory[] = [];
    const reasons: string[] = [];

    for (const [cat, score] of Object.entries(merged) as [SafetyCategory, number][]) {
      const threshold = config.thresholds?.[cat]?.flag ?? unsafeThreshold;
      if (score > threshold) {
        triggeredCategories.push(cat);
        reasons.push(`${cat}: ${score.toFixed(2)} > ${threshold}`);
      }
    }

    const safe = triggeredCategories.length === 0;

    // Apply spotlighting to the description (INTERNET privilege)
    const provenanced = createMessage(
      tool.description,
      InstructionPrivilege.INTERNET,
      `mcp:${tool.name}`,
    );
    const spotlight = applySpotlight(provenanced, spotlightConfig);

    return {
      tool: tool.name,
      safe,
      scores: merged,
      triggeredCategories,
      sanitizedDescription: spotlight.content,
      reason: reasons.length > 0 ? reasons.join('; ') : undefined,
    };
  }

  return {
    scanTool,

    async scanTools(tools: McpToolDefinition[]): Promise<McpScanResult[]> {
      return Promise.all(tools.map(scanTool));
    },
  };
}

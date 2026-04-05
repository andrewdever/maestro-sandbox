/**
 * Defense Failure Model (§14.8).
 *
 * Classifies every security control as structural (non-bypassable by
 * prompt manipulation) or heuristic (bypassable). Documents the
 * invariant that structural controls prevent host compromise even
 * when ALL heuristics fail simultaneously.
 *
 * Swiss Cheese Model: each heuristic failure has a structural backup.
 */

// ---------------------------------------------------------------------------
// Control Taxonomy
// ---------------------------------------------------------------------------

/** Whether a control can be bypassed by prompt/content manipulation. */
export type ControlType = 'structural' | 'heuristic';

/** A single security control in the defense model. */
export interface SecurityControl {
  /** Unique name of this control. */
  name: string;

  /** Type classification. */
  type: ControlType;

  /** What this control prevents. */
  prevents: string;

  /** What happens if this control is bypassed. */
  ifBypassed: string;

  /** Structural backup that catches what this control misses (heuristic only). */
  structuralBackup?: string;

  /** Section of the spec that defines this control. */
  specSection: string;
}

// ---------------------------------------------------------------------------
// Control Registry
// ---------------------------------------------------------------------------

/**
 * The complete defense model — all controls and their relationships.
 *
 * Structural controls cannot be bypassed by manipulating LLM output.
 * Heuristic controls can be bypassed but each has a structural backup.
 */
export const DEFENSE_CONTROLS: readonly SecurityControl[] = [
  // --- Structural controls ---
  {
    name: 'sandbox-process-isolation',
    type: 'structural',
    prevents: 'Arbitrary host process access',
    ifBypassed: 'Requires VM/container escape (Tier 3 mitigates)',
    specSection: '§5 (V1)',
  },
  {
    name: 'object-freeze-host-bridge',
    type: 'structural',
    prevents: 'Host bridge prototype pollution / monkey-patching',
    ifBypassed: 'Requires V8 engine bug',
    specSection: '§5.4 (V1)',
  },
  {
    name: 'zod-schema-validation',
    type: 'structural',
    prevents: 'Malformed host function arguments',
    ifBypassed: 'Cannot bypass without code change to schema',
    specSection: '§5.6 (V1)',
  },
  {
    name: 'url-allowlist',
    type: 'structural',
    prevents: 'SSRF / arbitrary network egress',
    ifBypassed: 'Cannot add URLs without config change',
    specSection: '§5.6 (V1)',
  },
  {
    name: 'rate-limiting',
    type: 'structural',
    prevents: 'Resource exhaustion / DoS',
    ifBypassed: 'Cannot exceed without code change',
    specSection: '§5.6 (V1)',
  },
  {
    name: 'instruction-hierarchy',
    type: 'structural',
    prevents: 'Lower-privilege content overriding higher-privilege instructions',
    ifBypassed: 'Requires code change to privilege enforcement',
    specSection: '§14.5',
  },
  {
    name: 'session-turn-limit',
    type: 'structural',
    prevents: 'Unbounded multi-turn escalation',
    ifBypassed: 'Cannot exceed without config change',
    specSection: '§14.10',
  },
  {
    name: 'content-spotlighting',
    type: 'structural',
    prevents: 'Untrusted content confused with instructions',
    ifBypassed: 'Requires matching high-entropy boundary token (2^-128)',
    specSection: '§14.6',
  },

  // --- Heuristic controls ---
  {
    name: 'output-classifier',
    type: 'heuristic',
    prevents: 'Injected instructions in agent output',
    ifBypassed: 'Injected instructions pass through to downstream consumers',
    structuralBackup: 'url-allowlist + rate-limiting prevent exfiltration',
    specSection: '§14.2',
  },
  {
    name: 'call-sequence-analyzer',
    type: 'heuristic',
    prevents: 'Multi-step exfiltration sequences (read → encode → send)',
    ifBypassed: 'Exfiltration sequence goes undetected',
    structuralBackup: 'url-allowlist + secret-redaction block egress',
    specSection: '§14.9',
  },
  {
    name: 'code-review-scanner',
    type: 'heuristic',
    prevents: 'Malicious code entering sandbox via patches',
    ifBypassed: 'Malicious code enters sandbox',
    structuralBackup: 'sandbox-process-isolation contains execution',
    specSection: '§14.4',
  },
  {
    name: 'entropy-analysis',
    type: 'heuristic',
    prevents: 'Encoded secrets in output',
    ifBypassed: 'Encoded secrets pass through',
    structuralBackup: 'secret-redaction + url-allowlist',
    specSection: '§9',
  },
  {
    name: 'multi-turn-detector',
    type: 'heuristic',
    prevents: 'Gradual escalation across conversation turns',
    ifBypassed: 'Escalation goes undetected',
    structuralBackup: 'session-turn-limit forces reset',
    specSection: '§14.10',
  },
  {
    name: 'guardrail-classifier',
    type: 'heuristic',
    prevents: 'Unsafe content across 11 safety categories',
    ifBypassed: 'Unsafe content passes evaluation',
    structuralBackup: 'sandbox-process-isolation + url-allowlist + rate-limiting remain enforced',
    specSection: '§14.7',
  },
  {
    name: 'pattern-evaluator',
    type: 'heuristic',
    prevents: 'Known prompt injection / escape patterns',
    ifBypassed: 'Known attack patterns pass through',
    structuralBackup: 'sandbox-process-isolation + url-allowlist + instruction-hierarchy',
    specSection: '§14.7',
  },
] as const;

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/**
 * Validate the defense model invariant:
 * Every heuristic control must have a structural backup.
 *
 * Returns violations (should be empty in a correct model).
 */
export function validateDefenseModel(): string[] {
  const violations: string[] = [];
  const structuralNames = new Set(
    DEFENSE_CONTROLS.filter(c => c.type === 'structural').map(c => c.name),
  );

  for (const control of DEFENSE_CONTROLS) {
    if (control.type === 'heuristic') {
      if (!control.structuralBackup) {
        violations.push(`Heuristic control "${control.name}" has no structural backup`);
      } else {
        // Verify structuralBackup references at least one real structural control name.
        const referencesAnyStructural = [...structuralNames].some(name =>
          control.structuralBackup!.includes(name),
        );
        if (!referencesAnyStructural) {
          violations.push(
            `Heuristic control "${control.name}" structuralBackup "${control.structuralBackup}" does not reference any known structural control`,
          );
        }
      }
    }
  }

  return violations;
}

/**
 * The core safety invariant.
 *
 * Even if ALL heuristic controls fail simultaneously, structural
 * controls still prevent:
 * (a) Host process compromise
 * (b) Cross-tenant data access
 * (c) Arbitrary network egress
 * (d) Filesystem escape
 */
// ---------------------------------------------------------------------------
// OWASP LLM Top 10 Mapping (§17, Appendix E)
// ---------------------------------------------------------------------------

/**
 * Formal mapping of OWASP LLM Top 10 (2025) categories to Maestro defense layers.
 *
 * Each entry lists the OWASP category, its Maestro defense layers, and whether
 * the 2+ independent layer requirement is met.
 */
export interface OwaspMapping {
  /** OWASP identifier (e.g., 'LLM01'). */
  id: string;
  /** OWASP category name. */
  name: string;
  /** Defense layers in Maestro addressing this category. */
  layers: string[];
  /** Whether 2+ independent layers exist. */
  meetsTarget: boolean;
  /** Notes on coverage gaps or scope exclusions. */
  notes?: string;
}

export const OWASP_LLM_TOP_10: readonly OwaspMapping[] = [
  {
    id: 'LLM01',
    name: 'Prompt Injection',
    layers: [
      'guardrail-pipeline (pattern-evaluator: 14 injection patterns)',
      'instruction-hierarchy (structural privilege enforcement)',
      'content-spotlighting (boundary token isolation)',
      'multi-turn-detector (escalation detection)',
    ],
    meetsTarget: true,
  },
  {
    id: 'LLM02',
    name: 'Insecure Output Handling',
    layers: [
      'guardrail-pipeline (output position evaluation)',
      'content-spotlighting (boundary marking on all returns)',
      'secret-redaction (credential stripping)',
    ],
    meetsTarget: true,
  },
  {
    id: 'LLM03',
    name: 'Training Data Poisoning',
    layers: [
      'guardrail-pipeline (training-data-poisoning: 7 intent + 2 topic patterns)',
      'red-team harness (9 LLM03 attack cases)',
    ],
    meetsTarget: true,
    notes: 'Operational: runtime detection only. Training pipeline integrity is out of scope.',
  },
  {
    id: 'LLM04',
    name: 'Model Denial of Service',
    layers: [
      'rate-limiting (structural per-function limit)',
      'session-turn-limit (structural max turns)',
      'guardrail-pipeline (resource-abuse category)',
    ],
    meetsTarget: true,
  },
  {
    id: 'LLM05',
    name: 'Supply Chain Vulnerabilities',
    layers: [
      'socket.dev (behavioral dependency analysis in CI)',
      'Semgrep SAST (code scanning)',
      'license compliance (GPL/AGPL/SSPL blocking)',
      'plugin-validator (tier enforcement)',
    ],
    meetsTarget: true,
  },
  {
    id: 'LLM06',
    name: 'Sensitive Information Disclosure',
    layers: [
      'guardrail-pipeline (credential-exfiltration + data-exfiltration)',
      'secret-redaction (pattern-based stripping)',
      'taint-tracker (content hash tracking)',
      'url-allowlist (structural egress control)',
    ],
    meetsTarget: true,
  },
  {
    id: 'LLM07',
    name: 'Insecure Plugin Design',
    layers: [
      'mcp-scanner (tool description scanning)',
      'plugin-validator (tier + capability enforcement)',
      'host-bridge (frozen Object.freeze + schema validation)',
    ],
    meetsTarget: true,
  },
  {
    id: 'LLM08',
    name: 'Excessive Agency',
    layers: [
      'task-grounding (capability tag enforcement)',
      'trust-sub-level enforcement (per-source policy)',
      'requireApproval (HITL gating on sensitive ops)',
    ],
    meetsTarget: true,
  },
  {
    id: 'LLM09',
    name: 'Overreliance',
    layers: [],
    meetsTarget: false,
    notes: 'Out of scope: Overreliance is a user/organizational risk, not a runtime control.',
  },
  {
    id: 'LLM10',
    name: 'Model Theft',
    layers: [
      'guardrail-pipeline (model-theft: 6 intent + 2 topic patterns)',
      'red-team harness (9 LLM10 attack cases)',
    ],
    meetsTarget: true,
    notes: 'Operational: runtime detection only. Model access control is provider-side.',
  },
] as const;

/**
 * Validate that the OWASP LLM Top 10 mapping meets the 2+ layer target.
 *
 * Returns categories that fail the requirement (excluding out-of-scope).
 */
export function validateOwaspCoverage(): string[] {
  const violations: string[] = [];
  for (const entry of OWASP_LLM_TOP_10) {
    if (entry.notes?.includes('Out of scope')) continue;
    if (!entry.meetsTarget) {
      violations.push(`${entry.id} (${entry.name}): ${entry.layers.length} layers, need 2+`);
    }
  }
  return violations;
}

export const SAFETY_INVARIANT = {
  statement: 'If ALL heuristic controls fail simultaneously, structural controls still prevent host compromise',
  guarantees: [
    'No host process compromise (sandbox-process-isolation)',
    'No cross-tenant data access (sandbox-process-isolation + instruction-hierarchy)',
    'No arbitrary network egress (url-allowlist + rate-limiting)',
    'No filesystem escape (sandbox-process-isolation + zod-schema-validation)',
  ],
  structuralControlCount: DEFENSE_CONTROLS.filter(c => c.type === 'structural').length,
  heuristicControlCount: DEFENSE_CONTROLS.filter(c => c.type === 'heuristic').length,
} as const;

/**
 * Configuration presets and helpers for standalone usage.
 *
 * When using maestro-sandbox outside the Maestro monorepo, there is no
 * maestro.config.ts to provide defaults. This module fills that gap with:
 *
 * - Typed configuration presets (MINIMAL, STANDARD, HARDENED)
 * - A `defineConfig()` helper for type-safe configuration
 * - A `createSecureSandbox()` convenience factory that wires up
 *   sandbox + defense pipeline + guardrails + escalation detection
 *
 * @example
 * ```typescript
 * import { createSecureSandbox, PRESETS } from 'maestro-sandbox';
 *
 * const { sandbox, defense } = await createSecureSandbox(PRESETS.STANDARD);
 * ```
 */

import type { SandboxConfig, SandboxLimits, Sandbox, CreateSandboxOptions } from './types.js';
import type { DefensePipelineConfig, DefensePipeline, SecurityPolicyConfig, TrustLevelPolicy } from './defense-pipeline.js';
import type { GuardrailConfig, GuardrailEvaluator } from './guardrail-pipeline.js';
import type { EscalationConfig } from './escalation-detector.js';
import type { MeshFirewallConfig, MeshFirewall } from './mesh-firewall.js';
import type { AuditLogger, AuditLoggerOptions } from './audit.js';
import type { RedTeamConfig, RedTeamHarness } from './red-team.js';

import { createSandbox, createSandboxWithDegradation } from './factory.js';
import { createDefensePipeline } from './defense-pipeline.js';
import { createGuardrailPipeline, createPatternEvaluator } from './guardrail-pipeline.js';
import { createEscalationDetector } from './escalation-detector.js';
import { createMeshFirewall } from './mesh-firewall.js';
import { createAuditLogger } from './audit.js';
import { createRedTeamHarness, getBuiltinCorpus } from './red-team.js';

// ---------------------------------------------------------------------------
// Sandbox Configuration
// ---------------------------------------------------------------------------

/**
 * Complete configuration for a standalone maestro-sandbox deployment.
 *
 * Replaces the `sandbox:` section of `maestro.config.ts` with a
 * single, self-contained configuration object.
 */
export interface MaestroSandboxConfig {
  /**
   * Which plugin to use.
   * - `'isolated-vm'` — Tier 1, V8 isolate (default, cross-platform, fast)
   * - `'anthropic-sr'` — Tier 2, Anthropic Secure Runtime (macOS/Linux)
   * - `'landlock'` — Tier 2, Seatbelt/Landlock (macOS)
   * - `'docker'` — Tier 3, Docker containers
   * - `'e2b'` — Tier 3, E2B cloud micro-VMs (requires E2B_API_KEY)
   * - `'openshell'` — Tier 3, NVIDIA OpenShell (requires openshell CLI)
   * - `'mock'` — Tier 1, testing only (no real isolation)
   *
   * Or pass `'auto'` to use the degradation chain.
   */
  plugin: string | 'auto';

  /** Resource limits for sandboxed code. */
  limits: SandboxLimits;

  /**
   * Minimum tier for the degradation chain.
   * Only applies when `plugin: 'auto'`.
   * Set to 2 for MCP servers or untrusted code.
   * @default 1
   */
  mcpMinTier?: number;

  /**
   * Secrets injected into the sandbox.
   * Never written to disk. Destroyed on sandbox.destroy().
   *
   * E2B_API_KEY is read from this or from `process.env.E2B_API_KEY`.
   */
  secrets?: Record<string, string>;

  /** Network configuration for Tier 2+ sandboxes. */
  network?: {
    /** Allowlisted peers, e.g. `['api.openai.com:443']`. */
    allowedPeers?: string[];
  };

  /** Host function definitions. Frozen at creation time. */
  hostFunctions?: SandboxConfig['hostFunctions'];

  /**
   * Defense pipeline configuration.
   * Set to `false` to disable (not recommended).
   */
  defense?: DefenseConfig | false;

  /** Audit logging configuration. */
  audit?: AuditLoggerOptions;
}

/** Defense pipeline configuration for standalone usage. */
export interface DefenseConfig {
  /** Guardrail pipeline settings. */
  guardrails?: GuardrailConfig;

  /** Additional evaluators beyond the built-in pattern evaluator. */
  additionalEvaluators?: GuardrailEvaluator[];

  /** Escalation detection settings. */
  escalation?: EscalationConfig;

  /** Pipeline orchestration settings. */
  pipeline?: DefensePipelineConfig;

  /** Inter-sandbox mesh firewall settings. */
  mesh?: MeshFirewallConfig;

  /**
   * Trust sub-level policies.
   *
   * Controls what different trust levels are allowed to do:
   * - `3a`: Operator-controlled sources (agent, tool output, user input)
   * - `3b`: Peer agent messages (from other sandboxes)
   * - `3c`: Internet/MCP-sourced content (lowest trust)
   */
  trustPolicies?: SecurityPolicyConfig;
}

// ---------------------------------------------------------------------------
// Presets
// ---------------------------------------------------------------------------

/** Default resource limits. */
const DEFAULT_LIMITS: SandboxLimits = {
  memoryMB: 128,
  cpuMs: 5000,
  timeoutMs: 10000,
  networkAccess: false,
  filesystemAccess: 'tmpfs',
};

/** Trust policies for the STANDARD and HARDENED presets. */
const STANDARD_TRUST_POLICIES: SecurityPolicyConfig = {
  // Operator-controlled: permissive
  trustLevel3a: {
    allowCodeExecution: true,
    allowNetworkEgress: false,
    maxSessionTurns: 50,
  },
  // Peer agent: moderate restrictions
  trustLevel3b: {
    allowCodeExecution: false,
    allowNetworkEgress: false,
    maxSessionTurns: 30,
  },
  // Internet/MCP: strict
  trustLevel3c: {
    allowCodeExecution: false,
    allowNetworkEgress: false,
    maxSessionTurns: 20,
    maxContextTokens: 4000,
  },
};

const HARDENED_TRUST_POLICIES: SecurityPolicyConfig = {
  trustLevel3a: {
    allowCodeExecution: true,
    allowNetworkEgress: false,
    maxSessionTurns: 30,
    maxContextTokens: 8000,
  },
  trustLevel3b: {
    allowCodeExecution: false,
    allowNetworkEgress: false,
    maxSessionTurns: 15,
    maxContextTokens: 2000,
    blockedPatterns: ['eval\\(', 'Function\\(', 'import\\('],
  },
  trustLevel3c: {
    allowCodeExecution: false,
    allowNetworkEgress: false,
    maxSessionTurns: 10,
    maxContextTokens: 1000,
    blockedPatterns: ['eval\\(', 'Function\\(', 'import\\(', 'require\\(', 'exec\\('],
    requireApproval: ['*'],
  },
};

/**
 * Configuration presets for common use cases.
 *
 * - **MINIMAL** — Sandbox only, no defense pipeline. For trusted code or testing.
 * - **STANDARD** — Sandbox + defense pipeline + guardrails + escalation detection.
 *   Recommended for most applications.
 * - **HARDENED** — Strict policies, lower thresholds, trust sub-level enforcement.
 *   For untrusted code, MCP servers, or multi-tenant deployments.
 */
export const PRESETS = {
  /** Sandbox only. No defense pipeline. For trusted code or testing. */
  MINIMAL: {
    plugin: 'isolated-vm',
    limits: { ...DEFAULT_LIMITS },
    defense: false as const,
  } satisfies MaestroSandboxConfig,

  /** Sandbox + defense pipeline. Recommended for most applications. */
  STANDARD: {
    plugin: 'isolated-vm',
    limits: { ...DEFAULT_LIMITS },
    defense: {
      guardrails: {},
      escalation: {},
      pipeline: {},
      trustPolicies: STANDARD_TRUST_POLICIES,
    },
  } satisfies MaestroSandboxConfig,

  /** Strict policies for untrusted code, MCP, or multi-tenant. */
  HARDENED: {
    plugin: 'auto',
    mcpMinTier: 2,
    limits: {
      memoryMB: 64,
      cpuMs: 3000,
      timeoutMs: 5000,
      networkAccess: false,
      filesystemAccess: 'tmpfs' as const,
    },
    defense: {
      guardrails: {
        defaultThresholds: { block: 0.8, flag: 0.4, modify: 0.6 },
        evaluatorTimeoutMs: 150,
      },
      escalation: {
        maxTurns: 30,
        blockedAttemptThreshold: 2,
        contextGrowthMultiplier: 1.5,
      },
      pipeline: {
        latencyBudgetMs: 300,
        flagAccumulationThreshold: 2,
        degradedThreshold: 3,
        lockdownThreshold: 2,
      },
      trustPolicies: HARDENED_TRUST_POLICIES,
    },
  } satisfies MaestroSandboxConfig,
} as const;

// ---------------------------------------------------------------------------
// defineConfig helper
// ---------------------------------------------------------------------------

/**
 * Type-safe configuration helper.
 *
 * Provides autocomplete and validation for `MaestroSandboxConfig`.
 * Use this instead of manually constructing the config object.
 *
 * @example
 * ```typescript
 * import { defineConfig } from 'maestro-sandbox';
 *
 * export default defineConfig({
 *   plugin: 'isolated-vm',
 *   limits: {
 *     memoryMB: 256,
 *     cpuMs: 10000,
 *     timeoutMs: 30000,
 *     networkAccess: false,
 *     filesystemAccess: 'tmpfs',
 *   },
 *   defense: {
 *     guardrails: {
 *       disabledCategories: ['training-data-poisoning'],
 *     },
 *     escalation: {
 *       maxTurns: 100,
 *     },
 *   },
 * });
 * ```
 */
export function defineConfig(config: MaestroSandboxConfig): MaestroSandboxConfig {
  return config;
}

// ---------------------------------------------------------------------------
// Convenience Factory
// ---------------------------------------------------------------------------

/** Result of `createSecureSandbox()`. */
export interface SecureSandboxResult {
  /** The sandbox instance. Call `sandbox.destroy()` when done. */
  sandbox: Sandbox;

  /** The defense pipeline (if configured). */
  defense: DefensePipeline | null;

  /** The mesh firewall (if configured). */
  mesh: MeshFirewall | null;

  /** The audit logger. */
  audit: AuditLogger;

  /**
   * Run the built-in red team corpus against the defense pipeline.
   * Returns the Attack Success Rate (ASR) — target: <5% with full stack.
   */
  runRedTeam: (config?: RedTeamConfig) => Promise<{ asr: number; report: import('./red-team.js').RedTeamReport }>;
}

/**
 * Create a sandbox with defense pipeline, guardrails, and escalation
 * detection — all wired together from a single config object.
 *
 * This replaces the multi-step setup that `maestro.config.ts` + `@maestro/spec`
 * used to handle in the monorepo. One function, batteries included.
 *
 * @example
 * ```typescript
 * import { createSecureSandbox, PRESETS } from 'maestro-sandbox';
 *
 * // Use a preset
 * const { sandbox, defense } = await createSecureSandbox(PRESETS.STANDARD);
 *
 * // Or customize
 * const { sandbox, defense } = await createSecureSandbox({
 *   plugin: 'docker',
 *   limits: { memoryMB: 256, cpuMs: 10000, timeoutMs: 30000, networkAccess: false, filesystemAccess: 'tmpfs' },
 *   defense: {
 *     escalation: { maxTurns: 100 },
 *     trustPolicies: {
 *       trustLevel3c: { allowCodeExecution: false, requireApproval: ['*'] },
 *     },
 *   },
 * });
 *
 * try {
 *   // Process input through defense pipeline before executing
 *   const check = await defense.processInput(message);
 *   if (check.action !== 'block') {
 *     const result = await sandbox.execute(code);
 *   }
 * } finally {
 *   await sandbox.destroy();
 * }
 * ```
 */
export async function createSecureSandbox(
  config: MaestroSandboxConfig,
): Promise<SecureSandboxResult> {
  // --- Audit logger ---
  const audit = createAuditLogger(config.audit ?? {});

  // --- Build SandboxConfig ---
  const sandboxConfig: SandboxConfig = {
    limits: config.limits,
    secrets: config.secrets,
    network: config.network,
    hostFunctions: config.hostFunctions,
  };

  // --- Create sandbox ---
  let sandbox: Sandbox;
  if (config.plugin === 'auto') {
    sandbox = await createSandboxWithDegradation({
      config: sandboxConfig,
      mcpMinTier: config.mcpMinTier ?? 1,
    });
  } else {
    sandbox = await createSandbox({
      plugin: config.plugin,
      config: sandboxConfig,
    });
  }

  // --- Defense pipeline ---
  let defense: DefensePipeline | null = null;
  let mesh: MeshFirewall | null = null;

  if (config.defense !== false) {
    const defenseConfig = config.defense ?? {};

    // Evaluators: built-in pattern evaluator + any additional
    const evaluators: GuardrailEvaluator[] = [
      createPatternEvaluator(),
      ...(defenseConfig.additionalEvaluators ?? []),
    ];

    const guardrails = createGuardrailPipeline(evaluators, defenseConfig.guardrails ?? {});
    const escalation = createEscalationDetector(defenseConfig.escalation ?? {});

    const pipelineConfig: DefensePipelineConfig = {
      ...defenseConfig.pipeline,
      securityPolicy: defenseConfig.trustPolicies ?? defenseConfig.pipeline?.securityPolicy,
    };

    defense = createDefensePipeline(guardrails, escalation, pipelineConfig, audit);

    // Mesh firewall (if configured)
    if (defenseConfig.mesh) {
      mesh = createMeshFirewall({ ...defenseConfig.mesh, auditLogger: audit });
    }
  }

  // --- Red team runner ---
  const runRedTeam = async (redTeamConfig?: RedTeamConfig) => {
    if (!defense) {
      throw new Error('Cannot run red team without defense pipeline. Set defense config or use PRESETS.STANDARD.');
    }
    const harness = createRedTeamHarness(defense, redTeamConfig);
    const corpus = getBuiltinCorpus();
    const report = await harness.run(corpus);
    return { asr: report.asr, report };
  };

  return { sandbox, defense, mesh, audit, runRedTeam };
}

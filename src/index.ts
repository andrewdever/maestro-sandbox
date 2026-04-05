export { createSandbox, createSandboxWithDegradation, resetCircuitBreakers, getCircuitBreakerState, OPENSHELL_DEGRADATION_CHAIN } from './factory.js';
export type { DegradationOptions, ShadowModeResult } from './factory.js';

// Types — re-export everything consumers need
export type {
  SandboxPlugin,
  IsolationLevel,
  SandboxConfig,
  SandboxLimits,
  NetworkConfig,
  HostFunctionDef,
  HostFunction,
  RateLimitConfig,
  Sandbox,
  ExecuteOptions,
  SandboxResult,
  SandboxChunk,
  SandboxMetrics,
  SandboxFileAccess,
  SandboxGitAccess,
  SandboxError,
  SandboxErrorCode,
  CircuitBreakerState,
  CircuitBreakerConfig,
  PatchValidationResult,
  PatchValidationError,
  PatchValidationRule,
  CreateSandboxOptions,
  DegradationChain,
} from './types.js';

// Error classes
export {
  SandboxTimeoutError,
  SandboxOOMError,
  SandboxPermissionError,
  SandboxCrashError,
} from './types.js';

// Subsystems
export { validatePatch, type PatchAuditLogger } from './patch-validator.js';
export { createHostBridge, validateNetworkAllowlist, type HostBridge } from './host-bridge.js';
export { createFileAccess, cleanupTmpdir } from './file-access.js';
export { createGitAccess } from './git-access.js';

// Security modules (§3, §5, §6, §8, §10, §11)
export { createRedactor, type Redactor, type RedactionConfig } from './redact.js';
export { createAuditLogger, sha256, type AuditLogger, type AuditLoggerOptions, type AuditEvent, type AuditEventType, type AuditSeverity } from './audit.js';
export { createSafeHandler, type SafeHandlerOptions } from './safe-handler.js';
export { validatePlugin, validatePluginTier, type PluginValidationResult } from './plugin-validator.js';
export {
  registerSandbox,
  unregisterSandbox,
  getSandbox,
  killAll,
  status,
  recordBreachSignal,
  resetBreachCounters,
  doctor,
  resetMaestro,
  type KillAllResult,
  type MaestroStatus,
  type BreachSignal,
  type DoctorCheck,
} from './maestro.js';

// V2 Security — LLM & Agent Threat Hardening (§14)
export {
  InstructionPrivilege,
  canOverride,
  resolveConflict,
  createMessage,
  downgradePrivilege,
  enforceOperatorPolicy,
  resolveTrustSubLevel,
  type TrustSubLevel,
  type InstructionPrivilegeName,
  type ProvenancedMessage,
  type OperatorPolicy,
} from './instruction-hierarchy.js';

export {
  generateBoundaryToken,
  applySpotlight,
  type SpotlightStrategy,
  type SpotlightConfig,
  type SpotlightResult,
} from './spotlighting.js';

export {
  createGuardrailPipeline,
  createPatternEvaluator,
  ALL_SAFETY_CATEGORIES,
  type SafetyCategory,
  type GuardrailPosition,
  type GuardrailAction,
  type CategoryScores,
  type GuardrailResult,
  type GuardrailThresholds,
  type GuardrailConfig,
  type GuardrailEvaluator,
  type EvaluatorContext,
  type GuardrailPipeline,
} from './guardrail-pipeline.js';

export {
  DEFENSE_CONTROLS,
  SAFETY_INVARIANT,
  OWASP_LLM_TOP_10,
  validateDefenseModel,
  validateOwaspCoverage,
  type ControlType,
  type SecurityControl,
  type OwaspMapping,
} from './defense-model.js';

export {
  createEscalationDetector,
  contentHash,
  cosineSimilarity,
  type EmbeddingFn,
  type EscalationAction,
  type TurnRecord,
  type EscalationResult,
  type EscalationConfig,
  type EscalationDetector,
} from './escalation-detector.js';

export {
  createDefensePipeline,
  type DefenseMode,
  type DefensePipelineResult,
  type SessionDefenseState,
  type DefensePipelineConfig,
  type DefensePipeline,
  type TrustLevelPolicy,
  type SecurityPolicyConfig,
} from './defense-pipeline.js';

export {
  createMeshFirewall,
  type MeshMessageType,
  type MeshMessage,
  type MeshFirewallConfig,
  type MeshFirewallResult,
  type MeshFirewall,
} from './mesh-firewall.js';

export {
  createOtelAuditLogger,
  OtelSpanStatusCode,
  type OtelTracer,
  type OtelSpan,
  type OtelAuditLoggerOptions,
} from './audit-otel.js';

export {
  createMcpScanner,
  type McpToolDefinition,
  type McpScanResult,
  type McpScannerConfig,
  type McpScanner,
} from './mcp-scanner.js';

export {
  createBehavioralAnalyzer,
  createInMemoryStore,
  createDefaultPatterns,
  shannonEntropy,
  type ActionRecord,
  type ActionFilter,
  type BehavioralStore,
  type PatternMatch,
  type BehavioralPattern,
  type BehavioralAnalyzer,
} from './behavioral-analyzer.js';

export {
  createTaintTracker,
  type TaintRecord,
  type TaintCheckResult,
  type TaintTracker,
  type TaintTrackerOptions,
} from './taint-tracker.js';

export {
  createModelRegistry,
  validateModelRequirements,
  type ModelRequirements,
  type ModelProviderRequirements,
  type ModelRegistryEntry,
  type ModelValidationResult,
  type ModelRegistry,
} from './model-registry.js';

export {
  createTaskGrounding,
  ALL_CAPABILITY_TAGS,
  type CapabilityTag,
  type TaskScope,
  type CapabilityMapping,
  type GroundingCheckResult,
  type GroundingAnomaly,
  type TaskGroundingConfig,
  type TaskGrounding,
} from './task-grounding.js';

// Multi-Tenant Isolation (§5)
export {
  validateTenantId,
  namespaceSandboxId,
  extractTenantId,
  extractSandboxId,
  sameTenant,
  tenantScopedKey,
  breachCounterKey,
  assertTenantId,
  ISOLATION_TIER,
  type TenantId,
  type NamespacedId,
} from './tenant.js';

export {
  createRedTeamHarness,
  getBuiltinCorpus,
  extractRegressionCases,
  type AttackCase,
  type AttackVector,
  type AttackTurn,
  type AttackResult,
  type RedTeamReport,
  type RedTeamConfig,
  type RedTeamHarness,
  type RegressionExtractionConfig,
} from './red-team.js';

// OpenShell plugin (Tier 3 — NVIDIA OpenShell, §14)
export {
  buildPolicy as buildOpenShellPolicy,
  policyToYaml as openShellPolicyToYaml,
  OPENSHELL_VERSION,
  type OpenShellPolicy,
} from './plugins/openshell.js';

// Threat Model — code-accessible path to the threat model document
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
const __dirname = dirname(fileURLToPath(import.meta.url));
export const THREAT_MODEL_PATH = resolve(__dirname, 'threat-model.md');

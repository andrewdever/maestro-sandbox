# Maestro Sandbox API Reference

Complete API reference for `@maestro/sandbox`. All exports are available from the
package root:

```typescript
import { createSandbox, SandboxTimeoutError, InstructionPrivilege, ... } from '@maestro/sandbox';
```

---

## Table of Contents

- [Core Factory](#core-factory)
- [Configuration](#configuration)
- [Types](#types)
- [Error Classes](#error-classes)
- [Subsystems](#subsystems)
- [Security Modules](#security-modules)
- [V2 Security -- LLM & Agent Threat Hardening](#v2-security----llm--agent-threat-hardening)

---

## Core Factory

### `createSandbox(options: CreateSandboxOptions): Promise<Sandbox>`

Main entry point. Resolves plugin by name or direct reference, validates
limits (memoryMB, cpuMs, timeoutMs must be positive), checks the circuit
breaker, enforces creation rate limits (max 50 concurrent, 10/sec), and
freezes `hostFunctions` with `Object.freeze()`.

```typescript
const sandbox = await createSandbox({
  plugin: 'isolated-vm',
  config: {
    limits: { memoryMB: 128, cpuMs: 5000, timeoutMs: 10000, networkAccess: false, filesystemAccess: 'tmpfs' },
    hostFunctions: {
      fetch: {
        handler: async (args) => { /* ... */ },
        schema: z.object({ url: z.string().url() }),
        rateLimit: { maxCalls: 100, windowMs: 60000 },
      },
    },
  },
});

try {
  const result = await sandbox.execute('return 1 + 1');
} finally {
  await sandbox.destroy();
}
```

### `createSandboxWithDegradation(options: DegradationOptions): Promise<Sandbox>`

Tries plugins in the degradation chain until one succeeds. Skips plugins
below `mcpMinTier` (hard floor). Supports shadow mode for evaluating
experimental plugins against stable ones.

Default chain: Docker (T3) -> E2B (T3) -> Landlock (T2) -> Anthropic SR (T2) -> isolated-vm (T1).

```typescript
const sandbox = await createSandboxWithDegradation({
  config: { /* ... */ },
  mcpMinTier: 2, // Skip Tier 1 plugins
  shadowMode: {
    experimentalPlugin: 'openshell',
    onShadowResult: (result) => {
      console.log(`Diverged: ${result.diverged}, delta: ${result.latencyDeltaMs}ms`);
    },
  },
});
```

#### `DegradationOptions`

```typescript
interface DegradationOptions {
  chain?: DegradationChain;
  config: SandboxConfig;
  mcpMinTier?: number;
  circuitBreaker?: Partial<CircuitBreakerConfig>;
  shadowMode?: {
    experimentalPlugin: string;
    onShadowResult?: (result: ShadowModeResult) => void;
  };
}
```

#### `ShadowModeResult`

```typescript
interface ShadowModeResult {
  experimental: string;
  primary: string;
  diverged: boolean;
  experimentalError?: string;
  latencyDeltaMs: number;
}
```

### `resetCircuitBreakers(): void`

Reset all circuit breakers and creation limits. For testing only.

### `getCircuitBreakerState(pluginName: string): CircuitBreakerState | undefined`

Get the current circuit breaker state for a plugin. Returns `'closed'`,
`'open'`, `'half-open'`, or `undefined` if no breaker exists.

### `OPENSHELL_DEGRADATION_CHAIN: DegradationChain`

Alternative degradation chain with OpenShell at the head. Only used when
`experimental.openshell` is enabled in config. Falls back to Docker -> E2B -> ... if OpenShell fails.

```typescript
const sandbox = await createSandboxWithDegradation({
  chain: OPENSHELL_DEGRADATION_CHAIN,
  config: { /* ... */ },
});
```

---

## Configuration

The configuration system provides a single-function setup for production deployments,
replacing manual wiring of sandbox + defense pipeline + guardrails + escalation.

> **Full reference:** See [CONFIGURATION.md](./CONFIGURATION.md) for all options,
> environment variables, and example configs.

### `defineConfig(config: MaestroSandboxConfig): MaestroSandboxConfig`

Type-safe config helper. Returns the config object unchanged -- exists solely for
editor autocompletion and type checking.

```typescript
import { defineConfig } from '@maestro/sandbox';

export default defineConfig({
  plugin: 'docker',
  limits: { memoryMB: 256, timeoutMs: 30000 },
  defense: { guardrails: { enabled: true }, escalation: { maxTurns: 50 } },
});
```

### `createSecureSandbox(config: MaestroSandboxConfig): Promise<SecureSandboxResult>`

One-function setup that wires together the sandbox, defense pipeline, guardrail
pipeline, and escalation detector. This is the recommended entry point for
production deployments.

```typescript
import { createSecureSandbox, PRESETS } from '@maestro/sandbox';

const { sandbox, defense, shutdown } = await createSecureSandbox(PRESETS.STANDARD);

try {
  const result = await defense.evaluateInput(message);
  if (result.action !== 'block') {
    await sandbox.execute(code);
  }
} finally {
  await shutdown();
}
```

### `SecureSandboxResult`

```typescript
interface SecureSandboxResult {
  sandbox: Sandbox;
  defense: DefensePipeline;
  shutdown: () => Promise<void>;
}
```

### `PRESETS`

Pre-built configuration objects for common deployment scenarios.

```typescript
import { PRESETS } from '@maestro/sandbox';
```

| Preset | Plugin | Memory | Timeout | Network | Defense |
|--------|--------|--------|---------|---------|---------|
| `PRESETS.MINIMAL` | `isolated-vm` | 128MB | 10s | Disabled | Guardrails only |
| `PRESETS.STANDARD` | `docker` | 256MB | 30s | Disabled | Full pipeline |
| `PRESETS.HARDENED` | `docker` | 256MB | 30s | Disabled | Full pipeline + strict trust policies |

`PRESETS.HARDENED` is recommended for executing untrusted code. It enables all
defense layers with the most restrictive trust sub-level policies.

### `MaestroSandboxConfig`

Top-level configuration interface used by `defineConfig()` and `createSecureSandbox()`.

```typescript
interface MaestroSandboxConfig {
  plugin: string | SandboxPlugin;
  limits: SandboxLimits;
  defense?: DefenseConfig;
  permissions?: string[];
  secrets?: Record<string, string>;
  network?: NetworkConfig;
  hostFunctions?: Record<string, HostFunction>;
  mcpMinTier?: number;
  degradationChain?: DegradationChain;
}
```

### `DefenseConfig`

Configuration for the defense pipeline layers.

```typescript
interface DefenseConfig {
  guardrails?: {
    enabled: boolean;
    thresholds?: GuardrailThresholds;
    evaluatorTimeoutMs?: number;
  };
  escalation?: {
    maxTurns?: number;
    embeddingFn?: EmbeddingFn;
  };
  spotlight?: SpotlightConfig;
  operatorPolicy?: OperatorPolicy;
  trustLevels?: SecurityPolicyConfig;
  latencyBudgetMs?: number;
}
```

---

## Types

### `SandboxPlugin`

Interface for sandbox isolation plugins. Each plugin provides a specific
isolation strategy (V8, OS-level, container, microVM).

```typescript
interface SandboxPlugin {
  readonly name: string;
  readonly version: string;
  readonly requiredCoreVersion: string;
  readonly isolationLevel: IsolationLevel;
  create(config: SandboxConfig): Promise<Sandbox>;
}
```

### `IsolationLevel`

```typescript
type IsolationLevel = 'isolate' | 'process' | 'container' | 'microvm';
```

- `'isolate'` -- V8 isolate (Tier 1)
- `'process'` -- OS-level process sandbox (Tier 2)
- `'container'` -- Docker/OCI container (Tier 3)
- `'microvm'` -- microVM like Firecracker (Tier 3)

### `SandboxConfig`

Configuration passed to `SandboxPlugin.create()`.

```typescript
interface SandboxConfig {
  limits: SandboxLimits;
  permissions?: string[];
  secrets?: Record<string, string>;
  network?: NetworkConfig;
  hostFunctions?: Record<string, HostFunction>;
}
```

### `SandboxLimits`

```typescript
interface SandboxLimits {
  memoryMB: number;
  cpuMs: number;
  timeoutMs: number;
  networkAccess: boolean;
  filesystemAccess: 'none' | 'readonly' | 'tmpfs';
}
```

### `NetworkConfig`

```typescript
interface NetworkConfig {
  allowedPeers?: string[];  // e.g. ['api.openai.com:443']
  mTLS?: boolean;
}
```

### `HostFunctionDef`

Full host function definition with schema validation and rate limiting.

```typescript
interface HostFunctionDef {
  handler: (args: unknown) => Promise<unknown>;
  schema?: ZodSchema;
  rateLimit?: RateLimitConfig;
  timeoutMs?: number;  // Default: 30000
}
```

### `HostFunction`

Shorthand: a bare async function or a full `HostFunctionDef`.

```typescript
type HostFunction = HostFunctionDef | ((args: unknown) => Promise<unknown>);
```

### `RateLimitConfig`

```typescript
interface RateLimitConfig {
  maxCalls: number;
  windowMs: number;
}
```

### `Sandbox`

A running sandbox instance. Always call `destroy()` in a `finally` block.

```typescript
interface Sandbox {
  execute(code: string, options?: ExecuteOptions): Promise<SandboxResult>;
  executeStream(code: string, options?: ExecuteOptions): AsyncIterable<SandboxChunk>;
  fs: SandboxFileAccess;
  git: SandboxGitAccess;
  ready(): Promise<boolean>;
  destroy(): Promise<void>;
}
```

### `ExecuteOptions`

```typescript
interface ExecuteOptions {
  context?: Record<string, unknown>;
  shell?: boolean;  // Tier 2+ only
}
```

### `SandboxResult`

```typescript
interface SandboxResult {
  success: boolean;
  result?: unknown;
  error?: SandboxError | string;
  logs: string[];
  metrics: SandboxMetrics;
}
```

### `SandboxChunk`

```typescript
interface SandboxChunk {
  stream: 'stdout' | 'stderr';
  data: string;
  timestamp: number;
}
```

### `SandboxMetrics`

```typescript
interface SandboxMetrics {
  cpuMs: number;
  memoryMB: number;
  wallMs: number;
}
```

### `SandboxFileAccess`

```typescript
interface SandboxFileAccess {
  read(path: string): Promise<string>;
  write(path: string, content: string): Promise<void>;
  list(dir: string): Promise<string[]>;
}
```

### `SandboxGitAccess`

```typescript
interface SandboxGitAccess {
  inject(source: string | Buffer): Promise<void>;
  exportPatch(): Promise<string>;
  exportFiles(paths: string[]): Promise<Buffer>;
}
```

### `CircuitBreakerState`

```typescript
type CircuitBreakerState = 'closed' | 'open' | 'half-open';
```

### `CircuitBreakerConfig`

```typescript
interface CircuitBreakerConfig {
  failureThreshold: number;  // Default: 3
  cooldownMs: number;        // Default: 30000
}
```

### `CreateSandboxOptions`

```typescript
interface CreateSandboxOptions {
  plugin: SandboxPlugin | string;
  config: SandboxConfig;
  circuitBreaker?: Partial<CircuitBreakerConfig>;
}
```

### `DegradationChain`

```typescript
type DegradationChain = string[];
```

### `PatchValidationResult`

```typescript
interface PatchValidationResult {
  valid: boolean;
  errors: PatchValidationError[];
}
```

### `PatchValidationError`

```typescript
interface PatchValidationError {
  rule: PatchValidationRule;
  message: string;
  path?: string;
}
```

### `PatchValidationRule`

The 7 patch validation rules.

```typescript
type PatchValidationRule =
  | 'structural-parse'
  | 'path-traversal'
  | 'symlink-rejection'
  | 'binary-rejection'
  | 'workspace-confinement'
  | 'git-internals'
  | 'audit-log';
```

---

## Error Classes

All error classes extend `Error` and carry a `code` property.

### `SandboxTimeoutError`

Thrown when execution exceeds the wall-clock time limit.

```typescript
class SandboxTimeoutError extends Error {
  readonly code = 'SANDBOX_TIMEOUT';
}
```

### `SandboxOOMError`

Thrown when the sandbox exceeds its memory limit.

```typescript
class SandboxOOMError extends Error {
  readonly code = 'SANDBOX_OOM';
}
```

### `SandboxPermissionError`

Thrown when the sandbox attempts an operation it does not have permission for,
or when creation limits are exceeded.

```typescript
class SandboxPermissionError extends Error {
  readonly code = 'SANDBOX_PERMISSION';
}
```

### `SandboxCrashError`

Thrown when the sandbox process crashes unexpectedly or all plugins in a
degradation chain fail.

```typescript
class SandboxCrashError extends Error {
  readonly code = 'SANDBOX_CRASH';
}
```

### `SandboxErrorCode`

```typescript
type SandboxErrorCode = 'SANDBOX_TIMEOUT' | 'SANDBOX_OOM' | 'SANDBOX_PERMISSION' | 'SANDBOX_CRASH';
```

---

## Subsystems

### Patch Validator

#### `validatePatch(patch: string, workspaceRoot: string, logger?: PatchAuditLogger): PatchValidationResult`

Validate a git patch against all 7 security rules before applying. Returns
a result with `valid: boolean` and any validation errors.

```typescript
const result = validatePatch(patchString, '/workspace/project', auditLogger);
if (!result.valid) {
  console.error('Patch rejected:', result.errors);
}
```

#### `PatchAuditLogger`

Callback type for patch audit logging.

### Host Bridge

#### `createHostBridge(hostFunctions: Record<string, HostFunction>, options?): HostBridge`

Create a host bridge that sandboxed code uses to call host functions. The
bridge enforces the allowlist, validates arguments with Zod schemas, applies
rate limits, and handles timeouts.

```typescript
const bridge = createHostBridge(config.hostFunctions);
const result = await bridge.call('fetch', { url: 'https://api.example.com' });
```

#### `validateNetworkAllowlist(url: string, allowedPeers: string[]): boolean`

Check if a URL is permitted by the network allowlist. Used for SSRF prevention
on the host side.

#### `HostBridge`

```typescript
interface HostBridge {
  call(name: string, args: unknown): Promise<unknown>;
  readonly allowedFunctions: readonly string[];
}
```

### File Access

#### `createFileAccess(tmpdir: string): SandboxFileAccess`

Create a `SandboxFileAccess` implementation backed by a tmpdir. All paths
are confined to the tmpdir root.

#### `cleanupTmpdir(tmpdir: string): Promise<void>`

Remove a sandbox tmpdir and all its contents. Called during `sandbox.destroy()`.

### Git Access

#### `createGitAccess(tmpdir: string): SandboxGitAccess`

Create a `SandboxGitAccess` implementation for injecting code and exporting
patches within a sandbox tmpdir.

---

## Security Modules

### Redact

#### `createRedactor(secrets: Record<string, string>, config?: RedactionConfig): Redactor`

Create a redactor that strips secret values from strings. Applied to all
`SandboxResult.logs` before returning to the caller.

```typescript
const redactor = createRedactor({ API_KEY: 'sk-abc123' });
const safe = redactor.redact('Response included sk-abc123 in body');
// => 'Response included [REDACTED:API_KEY] in body'
```

#### Types: `Redactor`, `RedactionConfig`

### Audit

#### `createAuditLogger(options?: AuditLoggerOptions): AuditLogger`

Create a structured audit logger for security events. V1 outputs JSON to
stdout/stderr. All sandbox lifecycle events, host bridge calls, and security
violations are logged.

```typescript
const logger = createAuditLogger({ minSeverity: 'INFO' });
logger.log('sandbox.create', { plugin: 'isolated-vm', tier: 1 }, sandboxId);
```

#### `sha256(input: string): string`

Compute a SHA-256 hex hash. Used throughout the security modules for content
hashing and audit integrity.

#### Types: `AuditLogger`, `AuditLoggerOptions`, `AuditEvent`, `AuditEventType`, `AuditSeverity`

`AuditEventType` includes 30+ event types covering sandbox lifecycle,
host bridge calls, patch validation, circuit breakers, breach detection,
guardrail evaluations, escalation events, mesh messages, and behavioral analysis.

`AuditSeverity`: `'DEBUG' | 'INFO' | 'WARN' | 'ERROR' | 'CRITICAL'`

### Safe Handler

#### `createSafeHandler(handler: Function, options?: SafeHandlerOptions): Function`

Wrap a host function handler with error boundary, timeout, and logging.
Ensures host function errors never crash the sandbox or leak stack traces.

#### Types: `SafeHandlerOptions`

### Plugin Validator

#### `validatePlugin(plugin: SandboxPlugin): PluginValidationResult`

Validate a plugin's structure: name, version, requiredCoreVersion format,
and isolation level.

#### `validatePluginTier(pluginName: string, requiredTier: number): boolean`

Check if a plugin meets the required minimum tier.

#### Types: `PluginValidationResult`

### Maestro Orchestrator

Top-level orchestration API for managing sandbox lifecycle across the system.

#### `registerSandbox(sandbox: Sandbox): string`

Register a sandbox in the active registry. Returns a unique ID (e.g., `'sbx_000001'`).

#### `unregisterSandbox(id: string): void`

Remove a sandbox from the active registry.

#### `getSandbox(id: string): Sandbox | undefined`

Look up a sandbox by its registered ID.

#### `killAll(logger?: AuditLogger): Promise<KillAllResult>`

Emergency shutdown -- destroys ALL active sandboxes. Calls `destroy()` on
each with a 5-second timeout, force-kills if it does not complete.

```typescript
const result = await killAll(logger);
console.log(`Destroyed: ${result.destroyed}, Failed: ${result.failed}`);
```

#### `status(): MaestroStatus`

Report current sandbox system status.

```typescript
interface MaestroStatus {
  activeSandboxCount: number;
  sandboxIds: string[];
}
```

#### `recordBreachSignal(signal: BreachSignal, sandboxId: string, logger?: AuditLogger): boolean`

Record a security signal. Returns `true` if the breach threshold is exceeded.
7 signal types with per-signal thresholds and time windows.

```typescript
type BreachSignal =
  | 'permission-error-spike'
  | 'path-traversal-patch'
  | 'git-internals-patch'
  | 'ssrf-attempt'
  | 'unexpected-child-process'
  | 'symlink-in-tmpdir'
  | 'circuit-breaker-repeat-trip';
```

#### `resetBreachCounters(): void`

Reset all breach counters. For testing.

#### `doctor(): Promise<DoctorCheck[]>`

Run health checks on the sandbox system: platform, kernel version,
Node.js version, and available sandbox tiers.

```typescript
interface DoctorCheck {
  name: string;
  status: 'ok' | 'warn' | 'fail';
  message: string;
}
```

#### `resetMaestro(): void`

Reset all orchestrator state (sandbox registry, ID counter, breach counters). For testing.

#### Types: `KillAllResult`, `MaestroStatus`, `BreachSignal`, `DoctorCheck`

---

## V2 Security -- LLM & Agent Threat Hardening

### Instruction Hierarchy

OS-like permission model for LLM content. Every message carries a privilege
level and provenance tag. Higher privilege always wins in conflicts.

#### `InstructionPrivilege` (enum)

```typescript
enum InstructionPrivilege {
  SYSTEM = 0,       // Hardcoded safety invariants (non-overridable)
  OPERATOR = 1,     // Operator-defined policies
  SUPERVISOR = 2,   // Human-in-the-loop overrides
  AGENT = 3,        // Primary LLM agent instructions
  TOOL_OUTPUT = 4,  // Return values from host functions
  PEER_AGENT = 5,   // Messages from other sandboxes (mesh)
  USER_INPUT = 6,   // End-user provided content
  INTERNET = 7,     // Internet-sourced / MCP tool descriptions
}
```

#### `canOverride(source: InstructionPrivilege, target: InstructionPrivilege): boolean`

Check if source privilege is high enough to override target privilege.
Higher privilege (lower number) always wins.

#### `resolveConflict<T>(a: ProvenancedMessage<T>, b: ProvenancedMessage<T>): ProvenancedMessage<T>`

Returns the message with higher privilege. If equal, the first argument wins.

#### `createMessage<T>(content: T, privilege: InstructionPrivilege, source: string, options?): ProvenancedMessage<T>`

Create a `ProvenancedMessage` with timestamp and optional sandbox/session/tenant IDs.

```typescript
const msg = createMessage('Hello', InstructionPrivilege.USER_INPUT, 'chat-ui');
```

#### `downgradePrivilege<T>(message: ProvenancedMessage<T>, toPrivilege: InstructionPrivilege): ProvenancedMessage<T>`

Lower a message's privilege level. Can only downgrade (raise number), never elevate.
Used when forwarding content across trust boundaries.

#### `enforceOperatorPolicy(message: ProvenancedMessage<string>, policy: OperatorPolicy): { allowed: boolean; reason?: string }`

Check a message against operator-defined blocked patterns. Messages at
`OPERATOR` or `SYSTEM` privilege are never blocked. Payloads over 100KB
are rejected (ReDoS prevention).

#### `resolveTrustSubLevel(privilege: InstructionPrivilege): TrustSubLevel | null`

Map a privilege level to its Trust Level 3 sub-level:
- `AGENT`, `TOOL_OUTPUT`, `USER_INPUT` -> `'3a'`
- `PEER_AGENT` -> `'3b'`
- `INTERNET` -> `'3c'`
- `SYSTEM`, `OPERATOR`, `SUPERVISOR` -> `null` (above Level 3)

#### Types: `TrustSubLevel`, `InstructionPrivilegeName`, `ProvenancedMessage<T>`, `OperatorPolicy`

### Spotlighting

Content boundary marking to prevent untrusted content from being confused
with instructions.

#### `generateBoundaryToken(): string`

Generate a high-entropy boundary token (32 random bytes, 2^-256 collision probability).

```typescript
const token = generateBoundaryToken();
// => '<<<MAESTRO_BOUNDARY_A1B2C3D4E5F6...>>>'
```

#### `applySpotlight(message: ProvenancedMessage<string>, config?: SpotlightConfig): SpotlightResult`

Apply spotlighting to content based on privilege level. Content at `TOOL_OUTPUT`
or lower privilege is wrapped in boundary markers. Content at `AGENT` or higher
passes through unchanged. Three strategies: `'delimiter'`, `'xml-tag'`, `'base64'`.

```typescript
const result = applySpotlight(msg, { strategy: 'delimiter' });
```

#### Types: `SpotlightStrategy`, `SpotlightConfig`, `SpotlightResult`

### Guardrail Pipeline

Three-position evaluator (input, output, tool-call) with 11 safety categories
and per-category unsafety scoring (inspired by R2-Guard).

#### `createGuardrailPipeline(config: GuardrailConfig): GuardrailPipeline`

Create a guardrail pipeline with configured evaluators and thresholds.
Single layer veto: any `block` = block. Fail-closed: evaluator error/timeout = block.

#### `createPatternEvaluator(thresholds?: GuardrailThresholds): GuardrailEvaluator`

Create the built-in pattern-based evaluator with regex patterns for all
11 safety categories.

#### `ALL_SAFETY_CATEGORIES: readonly SafetyCategory[]`

All 11 safety categories:

```typescript
type SafetyCategory =
  | 'prompt-injection'
  | 'credential-exfiltration'
  | 'sandbox-escape'
  | 'data-exfiltration'
  | 'privilege-escalation'
  | 'resource-abuse'
  | 'social-engineering'
  | 'tool-misuse'
  | 'harmful-content'
  | 'training-data-poisoning'   // OWASP LLM03
  | 'model-theft';              // OWASP LLM10
```

#### Types: `SafetyCategory`, `GuardrailPosition`, `GuardrailAction`, `CategoryScores`, `GuardrailResult`, `GuardrailThresholds`, `GuardrailConfig`, `GuardrailEvaluator`, `EvaluatorContext`, `GuardrailPipeline`

### Defense Model

Documents the Swiss Cheese defense model -- every heuristic control has a
structural backup.

#### `DEFENSE_CONTROLS: readonly SecurityControl[]`

Complete registry of all 15 security controls (8 structural + 7 heuristic)
with their relationships.

```typescript
interface SecurityControl {
  name: string;
  type: ControlType;          // 'structural' | 'heuristic'
  prevents: string;
  ifBypassed: string;
  structuralBackup?: string;  // heuristic only
  specSection: string;
}
```

#### `SAFETY_INVARIANT`

The core safety invariant object. Documents what structural controls guarantee
even when all heuristic controls fail.

```typescript
const SAFETY_INVARIANT: {
  statement: string;
  guarantees: string[];
  structuralControlCount: number;
  heuristicControlCount: number;
};
```

#### `OWASP_LLM_TOP_10: readonly OwaspMapping[]`

Formal mapping of OWASP LLM Top 10 (2025) categories to Maestro defense layers.

```typescript
interface OwaspMapping {
  id: string;        // e.g. 'LLM01'
  name: string;
  layers: string[];
  meetsTarget: boolean;
  notes?: string;
}
```

#### `validateDefenseModel(): string[]`

Validate the defense model invariant: every heuristic control must have a
structural backup that references a real structural control name. Returns
violations (should be empty).

#### `validateOwaspCoverage(): string[]`

Validate that the OWASP mapping meets the 2+ independent layer target.
Returns categories that fail (excluding out-of-scope entries).

#### Types: `ControlType`, `SecurityControl`, `OwaspMapping`

### Escalation Detector

Multi-turn escalation detection using 5 heuristic detectors (no ML required).

#### `createEscalationDetector(config?: EscalationConfig): EscalationDetector`

Create a session-scoped escalation detector. Detectors:
1. Blocked-attempt counting (3+ in 10 turns -> quarantine)
2. Hash-based or embedding-based similarity (paraphrase probing detection)
3. Guardrail score trending (monotonic increase -> flag)
4. Context length monitoring (>2x growth -> flag)
5. Tool diversity spike (sudden breadth -> reconnaissance)

```typescript
const detector = createEscalationDetector({ maxTurns: 50, embeddingFn: myEmbedFn });
const result = detector.recordTurn({
  timestamp: new Date().toISOString(),
  contentHash: contentHash(input),
  inputLength: input.length,
  toolCalls: ['readFile', 'execute'],
}, input);

if (result.action === 'block-session') { /* ... */ }
```

#### `contentHash(content: string): string`

Compute a normalized SHA-256 hash for similarity detection (lowercase,
whitespace-collapsed).

#### `cosineSimilarity(a: number[], b: number[]): number`

Cosine similarity between two vectors. Returns `[-1, 1]` where 1 = identical direction.

#### Types: `EmbeddingFn`, `EscalationAction`, `TurnRecord`, `EscalationResult`, `EscalationConfig`, `EscalationDetector`

`EscalationAction`: `'continue' | 'warn-operator' | 'inject-refusal' | 'reset-session' | 'block-session'`

### Defense Pipeline

Orchestrates all defense layers: guardrail pipeline, escalation detection,
spotlighting, and instruction hierarchy enforcement.

#### `createDefensePipeline(config: DefensePipelineConfig): DefensePipeline`

Create the full defense pipeline. Composition rules:
- Single layer veto: any block = block
- Flag accumulation: 3+ flags from different layers = block
- Session accumulation: flags across turns trigger strict mode
- Fail-closed: guardrail error/timeout = block
- Latency budget: 500ms total
- Degradation chain: Normal -> Degraded -> Lockdown

```typescript
const pipeline = createDefensePipeline({
  operatorPolicy: { blockedPatterns: ['ignore previous'] },
  spotlightConfig: { strategy: 'delimiter' },
  latencyBudgetMs: 500,
});
```

#### Types

```typescript
type DefenseMode = 'normal' | 'degraded' | 'lockdown';

interface DefensePipelineResult {
  action: GuardrailAction;
  guardrail: GuardrailResult;
  escalation?: EscalationResult;
  spotlight?: SpotlightResult;
  policyAllowed: boolean;
  policyReason?: string;
  mode: DefenseMode;
  totalLatencyMs: number;
  degraded: boolean;
}

interface SessionDefenseState {
  mode: DefenseMode;
  cumulativeFlags: number;
  cumulativeBlocks: number;
  turnCount: number;
  degradedThreshold: number;
  lockdownThreshold: number;
  tenantId?: string;
}

interface TrustLevelPolicy {
  blockedPatterns?: string[];
  allowedHostFunctions?: string[];
  maxSessionTurns?: number;
  maxContextTokens?: number;
  requireApproval?: string[];
  allowNetworkEgress?: boolean;
  allowCodeExecution?: boolean;
}

interface SecurityPolicyConfig {
  trustLevel3a?: TrustLevelPolicy;
  trustLevel3b?: TrustLevelPolicy;
  trustLevel3c?: TrustLevelPolicy;
}

interface DefensePipelineConfig {
  operatorPolicy?: OperatorPolicy;
  spotlightConfig?: SpotlightConfig;
  latencyBudgetMs?: number;
  flagAccumulationThreshold?: number;
}

interface DefensePipeline {
  evaluateInput(message: ProvenancedMessage<string>): Promise<DefensePipelineResult>;
  evaluateOutput(message: ProvenancedMessage<string>): Promise<DefensePipelineResult>;
  evaluateToolCall(name: string, args: unknown, message: ProvenancedMessage<string>): Promise<DefensePipelineResult>;
  readonly sessionState: SessionDefenseState;
  resetSession(): void;
}
```

### Mesh Firewall

Inter-sandbox communication firewall. All mesh messages pass through this
firewall before delivery.

#### `createMeshFirewall(config?: MeshFirewallConfig): MeshFirewall`

Create a mesh firewall. Enforces:
- All messages created at `PEER_AGENT` privilege (level 5)
- No executable content (structural enforcement)
- Spotlighting boundary tokens on all payloads
- Rate limiting: 30 messages/sandbox/minute (default)
- Allowed types: `data`, `status`, `request`, `response` only
- Cross-tenant isolation (deny by default)

```typescript
const firewall = createMeshFirewall({
  maxMessagesPerMinute: 30,
  spotlightConfig: { strategy: 'delimiter' },
  auditLogger: logger,
});
const result = await firewall.send({ type: 'data', from: 'sbx_1', to: 'sbx_2', payload: 'hello', timestamp: new Date().toISOString() });
```

#### Types: `MeshMessageType`, `MeshMessage`, `MeshFirewallConfig`, `MeshFirewallResult`, `MeshFirewall`

### OTel Audit

#### `createOtelAuditLogger(options: OtelAuditLoggerOptions): AuditLogger`

Create an audit logger that emits OpenTelemetry spans for each audit event.
Consumers provide their own OTel tracer -- no `@opentelemetry` dependency.

Severity mapping:
- `CRITICAL` / `ERROR` -> `SpanStatusCode.ERROR` (2)
- `WARN` -> `SpanStatusCode.UNSET` (0)
- `INFO` / `DEBUG` -> `SpanStatusCode.OK` (1)

```typescript
const logger = createOtelAuditLogger({
  tracer: myOtelTracer,
  serviceName: 'maestro-sandbox',
});
```

#### `OtelSpanStatusCode`

```typescript
const OtelSpanStatusCode = { UNSET: 0, OK: 1, ERROR: 2 } as const;
```

#### Types: `OtelTracer`, `OtelSpan`, `OtelAuditLoggerOptions`

### MCP Scanner

#### `createMcpScanner(config?: McpScannerConfig): McpScanner`

Create an MCP tool description scanner. Scans tool definitions at `INTERNET`
privilege (level 7) for prompt injection and safety violations. Runs the
pattern evaluator, scores against all safety categories, and wraps sanitized
descriptions in spotlight boundary tokens.

```typescript
const scanner = createMcpScanner();
const results = scanner.scan([
  { name: 'read_file', description: 'Read a file from disk', parameters: { path: { type: 'string' } } },
]);
for (const r of results) {
  if (!r.safe) console.warn(`Unsafe tool: ${r.tool}`, r.violations);
}
```

#### Types: `McpToolDefinition`, `McpScanResult`, `McpScannerConfig`, `McpScanner`

### Behavioral Analyzer

Append-only event log with in-memory materialized view for behavioral
anomaly detection. 16 detection patterns. Cross-sandbox correlation for
multi-agent attack detection.

#### `createBehavioralAnalyzer(store: BehavioralStore, config?): BehavioralAnalyzer`

Create a behavioral analyzer backed by the provided store.

```typescript
const store = createInMemoryStore(10_000);
const analyzer = createBehavioralAnalyzer(store);
analyzer.record({ id: '1', timestamp: new Date().toISOString(), sandboxId: 'sbx_1', action: 'hostbridge.call', target: 'fetch' });
const anomalies = analyzer.analyze('sbx_1');
```

#### `createInMemoryStore(maxRecords?: number): BehavioralStore`

Create an in-memory behavioral store with LRU eviction. Default cap: 10,000 records.

#### `createDefaultPatterns(): BehavioralPattern[]`

Get the 16 built-in detection patterns.

#### `shannonEntropy(str: string): number`

Compute Shannon entropy of a string. Used for detecting encoded/encrypted
content in output (high entropy = suspicious).

#### Types: `ActionRecord`, `ActionFilter`, `BehavioralStore`, `PatternMatch`, `BehavioralPattern`, `BehavioralAnalyzer`

### Taint Tracker

Data-flow taint tracking via content hash provenance registry.

#### `createTaintTracker(options?: TaintTrackerOptions): TaintTracker`

Create a taint tracker. On every host function return, hash the content
and register provenance. On egress, check if outgoing content contains
tracked data (exact match or substring).

```typescript
const tracker = createTaintTracker();
tracker.track(sensitiveData, 'hostbridge:readConfig', InstructionPrivilege.TOOL_OUTPUT, 'sbx_1');
const check = tracker.check(outgoingPayload);
if (check.tainted) {
  console.warn('Tainted content in egress:', check.matches);
}
```

#### Types

```typescript
interface TaintRecord {
  contentHash: string;
  source: string;
  privilege: InstructionPrivilege;
  timestamp: string;
  sandboxId?: string;
  contentLength: number;
  preview?: string;
}

interface TaintCheckResult {
  tainted: boolean;
  matches: TaintRecord[];
  matchType?: 'exact' | 'substring';
}

interface TaintTracker {
  track(content: string, source: string, privilege: InstructionPrivilege, sandboxId?: string): string;
  check(content: string): TaintCheckResult;
  checkHash(hash: string): TaintRecord | undefined;
  readonly size: number;
  reset(): void;
}
```

#### Types: `TaintTrackerOptions`

### Model Registry

Configuration and validation for model requirements.

#### `createModelRegistry(auditLogger?: AuditLogger): ModelRegistry`

Create a model registry. Validates version pins (no `"latest"` or wildcards),
instruction hierarchy support, safety eval URLs, and provider data policies.

```typescript
const registry = createModelRegistry(logger);
const result = registry.register('claude-sonnet-4-6', {
  versionPin: 'claude-sonnet-4-6-20250514',
  instructionHierarchy: true,
  safetyEvalUrl: 'https://...',
}, {
  provider: 'anthropic',
  contentFiltering: true,
  usageLogging: true,
  noTrainingOnData: true,
});
```

#### `validateModelRequirements(requirements: ModelRequirements, provider: ModelProviderRequirements): ModelValidationResult`

Validate model and provider requirements without registering.

#### Types

```typescript
interface ModelRequirements {
  versionPin: string;
  instructionHierarchy: boolean;
  safetyEvalUrl?: string;
  injectionResistanceTrained?: boolean;
  maxInputTokens?: number;
  maxOutputTokens?: number;
}

interface ModelProviderRequirements {
  provider: string;
  contentFiltering: boolean;
  usageLogging: boolean;
  noTrainingOnData: boolean;
}

interface ModelRegistryEntry {
  modelId: string;
  requirements: ModelRequirements;
  provider: ModelProviderRequirements;
  registeredAt: string;
}

interface ModelValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

interface ModelRegistry {
  register(modelId: string, requirements: ModelRequirements, provider: ModelProviderRequirements): ModelValidationResult;
  get(modelId: string): ModelRegistryEntry | undefined;
  validate(modelId: string): ModelValidationResult;
  list(): ModelRegistryEntry[];
  remove(modelId: string): boolean;
  readonly size: number;
}
```

### Task Grounding

Capability-tag-based scoping for sandbox operations. Each task declares
required capabilities; every host function call is checked against the scope.

#### `createTaskGrounding(config: TaskGroundingConfig): TaskGrounding`

Create a task grounding enforcer.

```typescript
const grounding = createTaskGrounding({
  scope: { tags: ['filesystem-read', 'code-execution'] },
  capabilityMapping: {
    readFile: ['filesystem-read'],
    writeFile: ['filesystem-write'],
    exec: ['code-execution'],
  },
  enforcement: 'block',
});
const check = grounding.check('writeFile');
// { allowed: false, missingTags: ['filesystem-write'], operation: 'writeFile' }
```

#### `ALL_CAPABILITY_TAGS: readonly CapabilityTag[]`

All 10 capability tags:

```typescript
type CapabilityTag =
  | 'filesystem-read' | 'filesystem-write'
  | 'code-generation' | 'code-execution'
  | 'network-fetch'   | 'network-listen'
  | 'secret-access'   | 'process-spawn'
  | 'git-read'        | 'git-write';
```

#### Types: `CapabilityTag`, `TaskScope`, `CapabilityMapping`, `GroundingCheckResult`, `GroundingAnomaly`, `TaskGroundingConfig`, `TaskGrounding`

### Multi-Tenant Isolation

Namespace-prefix scheme for tenant isolation. All sandbox IDs, audit events,
and messages carry tenant context.

#### `validateTenantId(tenantId: string): { valid: boolean; error?: string }`

Validate a tenant ID: 3-63 chars, lowercase alphanumeric + hyphens, starts
with a letter, no consecutive hyphens.

#### `namespaceSandboxId(tenantId: TenantId, sandboxId: string): NamespacedId`

Create a namespaced sandbox ID: `{tenantId}:{sandboxId}`. Validates the
tenant ID and throws on invalid input.

#### `extractTenantId(namespacedId: string): TenantId | undefined`

Extract the tenant ID from a namespaced ID. Returns `undefined` if the ID
is not namespaced or the tenant portion is invalid.

#### `extractSandboxId(namespacedId: string): string`

Extract the bare sandbox ID from a namespaced ID. Returns the full ID if
not namespaced.

#### `sameTenant(id1: string, id2: string): boolean`

Check if two namespaced IDs belong to the same tenant.

#### `tenantScopedKey(tenantId: TenantId, key: string): string`

Create a tenant-scoped key for Maps/counters. Always use this instead of
raw string concatenation (security requirement).

#### `breachCounterKey(signal: string, namespacedSandboxId: string): string`

Create a tenant-aware breach counter key. Format: `{signal}::{namespacedSandboxId}`.

#### `assertTenantId(tenantId: string): void`

Assert that a tenant ID is valid. Throws on invalid input.

#### `ISOLATION_TIER`

```typescript
const ISOLATION_TIER = {
  current: 'namespace',
  hipaaEligible: false,
  dedicatedIsolationStatus: 'P2-planned',
} as const;
```

#### Types: `TenantId`, `NamespacedId`

### Red Team

Adversarial test harness for replaying structured attack payloads against
the defense pipeline. Designed for CI integration.

#### `createRedTeamHarness(pipeline: DefensePipeline, config?: RedTeamConfig): RedTeamHarness`

Create a red-team harness that replays attack cases against a defense
pipeline, measures Attack Success Rate (ASR), and produces per-category
breakdowns.

```typescript
const harness = createRedTeamHarness(pipeline, { resetBetweenCases: true });
const corpus = getBuiltinCorpus();
const report = await harness.run(corpus);
console.log(`ASR: ${(report.asr * 100).toFixed(1)}% (target: <5%)`);
```

#### `getBuiltinCorpus(): AttackCase[]`

Get the built-in corpus of 50+ attack cases covering all 11 safety categories.

#### `extractRegressionCases(report: RedTeamReport, config?: RegressionExtractionConfig): AttackCase[]`

Extract regression test cases from a red-team report. Filters by severity
and bypass status. Cases are tagged with `source: 'red-team-finding'`.

```typescript
const regressions = extractRegressionCases(report, { minSeverity: 'high', bypassesOnly: true });
```

#### Types

```typescript
type AttackVector = 'input' | 'output' | 'tool-call';

interface AttackTurn {
  content: string;
  privilege: InstructionPrivilege;
  vector?: AttackVector;
  toolCall?: { name: string; args: Record<string, unknown> };
}

interface AttackCase {
  id: string;
  name: string;
  category: SafetyCategory;
  turns: AttackTurn[];
  expectedBlocked: boolean;
  source: 'manual' | 'corpus' | 'red-team-finding' | 'cve';
  severity: 'critical' | 'high' | 'medium' | 'low';
}

interface AttackResult {
  case: AttackCase;
  blocked: boolean;
  caughtBy?: string;
  turnResults: DefensePipelineResult[];
  pass: boolean;
  totalLatencyMs: number;
}

interface RedTeamReport {
  timestamp: string;
  totalCases: number;
  attackSuccesses: number;
  asr: number;
  passed: number;
  failed: number;
  byCategory: Record<string, { total: number; blocked: number; asr: number }>;
  results: AttackResult[];
  durationMs: number;
}

interface RedTeamConfig {
  resetBetweenCases?: boolean;
  caseTimeoutMs?: number;
}

interface RegressionExtractionConfig {
  minSeverity?: AttackCase['severity'];
  bypassesOnly?: boolean;
  idPrefix?: string;
}

interface RedTeamHarness {
  run(cases: AttackCase[]): Promise<RedTeamReport>;
  runCase(attackCase: AttackCase): Promise<AttackResult>;
}
```

### OpenShell

NVIDIA OpenShell sandbox plugin (Tier 3). Translates Maestro SandboxConfig
into OpenShell's 4-layer YAML policy format.

#### `buildOpenShellPolicy(config: SandboxConfig): OpenShellPolicy`

Translate a SandboxConfig into OpenShell's 4-layer policy (filesystem,
network, process, inference).

```typescript
const policy = buildOpenShellPolicy(config);
const yaml = openShellPolicyToYaml(policy);
```

#### `openShellPolicyToYaml(policy: OpenShellPolicy): string`

Serialize an OpenShell policy to the YAML format expected by OpenShell's
policy engine.

#### `OPENSHELL_VERSION: string`

Pinned OpenShell image version. Update requires full contract test re-run.
Currently: `'0.4.0'`.

#### Types

```typescript
interface OpenShellPolicy {
  filesystem: {
    readOnly: boolean;
    tmpfsMounts: string[];
    allowedPaths: string[];
  };
  network: {
    egress: 'none' | 'filtered' | 'unrestricted';
    allowedHosts?: string[];
    dnsPolicy: 'none' | 'restricted';
  };
  process: {
    capabilities: string[];
    seccomp: 'strict' | 'default';
    pidsLimit: number;
    noNewPrivileges: boolean;
  };
  inference: {
    privacyRouter: boolean;
    stripCredentials: boolean;
    allowedProviders?: string[];
  };
}
```

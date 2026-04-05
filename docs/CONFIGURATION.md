# Configuration Reference

Complete configuration reference for the standalone `maestro-sandbox` package.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Presets](#presets)
3. [MaestroSandboxConfig Reference](#maestrosandboxconfig-reference)
4. [Resource Limits](#resource-limits)
5. [Plugin Selection](#plugin-selection)
6. [Defense Pipeline Config](#defense-pipeline-config)
7. [Trust Sub-Level Policies](#trust-sub-level-policies)
8. [Host Functions](#host-functions)
9. [Secrets](#secrets)
10. [Audit Logging](#audit-logging)
11. [Environment Variables](#environment-variables)
12. [Migration from maestro.config.ts](#migration-from-maestroconfigts)

---

## Quick Start

1. Copy the example config:

```bash
cp sandbox.config.example.ts sandbox.config.ts
```

2. Edit `sandbox.config.ts` to match your requirements:

```typescript
import { defineConfig } from 'maestro-sandbox';

export default defineConfig({
  plugin: 'isolated-vm',
  limits: {
    memoryMB: 128,
    cpuMs: 5000,
    timeoutMs: 10000,
    networkAccess: false,
    filesystemAccess: 'tmpfs',
  },
  defense: {
    guardrails: {},
    escalation: { maxTurns: 50 },
    trustPolicies: {
      trustLevel3a: { allowCodeExecution: true },
      trustLevel3c: { allowCodeExecution: false, maxContextTokens: 4000 },
    },
  },
});
```

3. Use `createSecureSandbox()` to wire everything up:

```typescript
import { createSecureSandbox } from 'maestro-sandbox';
import config from './sandbox.config.js';

const { sandbox, defense, audit } = await createSecureSandbox(config);

try {
  const check = await defense.processInput(message);
  if (check.action !== 'block') {
    const result = await sandbox.execute(code);
  }
} finally {
  await sandbox.destroy();
}
```

Or use a preset directly without a config file:

```typescript
import { createSecureSandbox, PRESETS } from 'maestro-sandbox';

const { sandbox, defense } = await createSecureSandbox(PRESETS.STANDARD);
```

---

## Presets

Three built-in presets cover common deployment scenarios. Use them directly or as a starting point for customization.

### MINIMAL

Sandbox only. No defense pipeline. For trusted code or testing.

| Setting | Value |
|---------|-------|
| Plugin | `isolated-vm` |
| Memory | 128 MB |
| CPU | 5000 ms |
| Timeout | 10000 ms |
| Network | disabled |
| Filesystem | tmpfs |
| Defense | **disabled** |

```typescript
import { createSecureSandbox, PRESETS } from 'maestro-sandbox';

const { sandbox } = await createSecureSandbox(PRESETS.MINIMAL);
```

**When to use:** Unit tests, trusted internal scripts, development environments where defense overhead is unnecessary.

### STANDARD

Sandbox with defense pipeline, guardrails, escalation detection, and trust sub-level policies. Recommended for most applications.

| Setting | Value |
|---------|-------|
| Plugin | `isolated-vm` |
| Memory | 128 MB |
| CPU | 5000 ms |
| Timeout | 10000 ms |
| Network | disabled |
| Filesystem | tmpfs |
| Defense | enabled (default thresholds) |
| Trust policies | STANDARD (see [Trust Sub-Level Policies](#trust-sub-level-policies)) |

```typescript
const { sandbox, defense } = await createSecureSandbox(PRESETS.STANDARD);
```

**When to use:** Single-tenant AI agent applications, internal tools running user-provided code, general-purpose sandboxing with safety guardrails.

### HARDENED

Strict policies, lower resource limits, tighter thresholds, and full trust sub-level enforcement. Uses `auto` plugin selection with `mcpMinTier: 2`.

| Setting | Value |
|---------|-------|
| Plugin | `auto` (min Tier 2) |
| Memory | 64 MB |
| CPU | 3000 ms |
| Timeout | 5000 ms |
| Network | disabled |
| Filesystem | tmpfs |
| Guardrail thresholds | block: 0.8, flag: 0.4, modify: 0.6 |
| Evaluator timeout | 150 ms |
| Escalation: maxTurns | 30 |
| Escalation: blockedAttemptThreshold | 2 |
| Pipeline: latencyBudgetMs | 300 ms |
| Pipeline: flagAccumulationThreshold | 2 |
| Trust policies | HARDENED (see [Trust Sub-Level Policies](#trust-sub-level-policies)) |

```typescript
const { sandbox, defense } = await createSecureSandbox(PRESETS.HARDENED);
```

**When to use:** Untrusted code execution, MCP server integration, multi-tenant deployments, internet-sourced content processing.

---

## MaestroSandboxConfig Reference

The complete `MaestroSandboxConfig` interface accepted by `defineConfig()` and `createSecureSandbox()`:

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `plugin` | `string \| 'auto'` | Yes | - | Which sandbox plugin to use. See [Plugin Selection](#plugin-selection). |
| `limits` | `SandboxLimits` | Yes | - | Resource limits. See [Resource Limits](#resource-limits). |
| `mcpMinTier` | `number` | No | `1` | Minimum tier for the degradation chain. Only applies when `plugin: 'auto'`. Set to `2` for MCP servers or untrusted code. |
| `secrets` | `Record<string, string>` | No | `undefined` | Secrets injected into the sandbox. See [Secrets](#secrets). |
| `network` | `{ allowedPeers?: string[] }` | No | `undefined` | Network allowlist for Tier 2+ sandboxes. Example: `['api.openai.com:443']`. |
| `hostFunctions` | `Record<string, HostFunction>` | No | `undefined` | Host function definitions. See [Host Functions](#host-functions). |
| `defense` | `DefenseConfig \| false` | No | `undefined` | Defense pipeline configuration. Set to `false` to disable. See [Defense Pipeline Config](#defense-pipeline-config). |
| `audit` | `AuditLoggerOptions` | No | `{ emit: true, store: false }` | Audit logging options. See [Audit Logging](#audit-logging). |

---

## Resource Limits

The `limits` field defines hard resource caps enforced by the sandbox runtime.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `memoryMB` | `number` | `128` | Maximum heap memory in megabytes. The sandbox is terminated with `SANDBOX_OOM` if exceeded. |
| `cpuMs` | `number` | `5000` | Maximum CPU time in milliseconds. Measures actual compute time, not wall-clock. |
| `timeoutMs` | `number` | `10000` | Maximum wall-clock time in milliseconds. The sandbox is terminated with `SANDBOX_TIMEOUT` if exceeded. |
| `networkAccess` | `boolean` | `false` | Whether outbound network access is allowed. Keep `false` unless the sandboxed code specifically needs it. |
| `filesystemAccess` | `'none' \| 'readonly' \| 'tmpfs'` | `'tmpfs'` | Filesystem access level inside the sandbox. |

### Practical Guidance

**memoryMB:**
- `64` -- Lightweight scripts, data transformations, simple computations.
- `128` -- General-purpose (default). Covers most LLM agent tool use.
- `256` -- Code that loads large data structures, parses big JSON, or generates files.
- `512+` -- Image processing, ML inference, or heavy computation. Consider Tier 3 plugins.

**cpuMs / timeoutMs:**
- `cpuMs` counts only active CPU time. `timeoutMs` is a wall-clock safety net that also covers I/O waits.
- Set `timeoutMs` to at least 2x `cpuMs` to account for I/O and startup overhead.
- For Tier 3 plugins (Docker, E2B), add extra timeout for VM boot time.

**filesystemAccess:**
- `'none'` -- No filesystem access at all. Strictest option.
- `'readonly'` -- Can read injected files but not write. Useful for code analysis.
- `'tmpfs'` -- Read/write to an ephemeral tmpdir. Files exist only for the sandbox lifetime.

> **Important:** Setting `networkAccess: true` requires a Tier 2+ plugin. V8 isolates (Tier 1) cannot provide network access. If you need network, pair it with a `network.allowedPeers` allowlist.

---

## Plugin Selection

### Available Plugins

| Plugin | Tier | Isolation | Platform | Requirements |
|--------|------|-----------|----------|-------------|
| `isolated-vm` | 1 | V8 isolate | Cross-platform | None (default) |
| `anthropic-sr` | 2 | Anthropic Secure Runtime | macOS, Linux | Runtime installed |
| `landlock` | 2 | Seatbelt/Landlock | macOS | None |
| `docker` | 3 | Docker container | Cross-platform | Docker daemon |
| `e2b` | 3 | Cloud micro-VM | Cross-platform | `E2B_API_KEY` |
| `openshell` | 3 | NVIDIA OpenShell | Linux | `openshell` CLI |
| `mock` | 1 | None | Cross-platform | None (testing only) |

### Choosing a Plugin

- **Start with `isolated-vm`** -- fastest, zero dependencies, sufficient for most use cases.
- **Use Tier 2 (`landlock`, `anthropic-sr`)** when sandboxed code needs OS-level operations (shell commands, filesystem access beyond tmpfs).
- **Use Tier 3 (`docker`, `e2b`, `openshell`)** when you need full process isolation, network access, or multi-language runtimes.

### Auto Mode

Set `plugin: 'auto'` to use the graceful degradation chain. The system tries the best available plugin and falls back through the chain:

```
Docker (T3) -> E2B (T3) -> Landlock (T2) -> Anthropic SR (T2) -> isolated-vm (T1)
```

```typescript
defineConfig({
  plugin: 'auto',
  mcpMinTier: 2, // Refuse to fall back below Tier 2
  limits: { ... },
});
```

### mcpMinTier

When `plugin: 'auto'`, `mcpMinTier` sets the floor for degradation. If the system cannot find a plugin at or above this tier, sandbox creation fails with a `CRITICAL` audit event (`degradation.below-mcp-min`) instead of silently degrading.

| Value | Meaning |
|-------|---------|
| `1` | Allow degradation to any tier (default) |
| `2` | Require at least OS-level isolation. Recommended for MCP servers and untrusted code. |
| `3` | Require infrastructure isolation (Docker, E2B, OpenShell). Strictest. |

---

## Defense Pipeline Config

The `defense` field configures the full defense pipeline. Set to `false` to disable all defense layers, or pass a `DefenseConfig` object.

```typescript
defense: {
  guardrails: { ... },          // Guardrail pipeline settings
  additionalEvaluators: [...],  // Custom evaluators beyond the built-in pattern evaluator
  escalation: { ... },          // Escalation detection settings
  pipeline: { ... },            // Pipeline orchestration settings
  mesh: { ... },                // Inter-sandbox mesh firewall settings
  trustPolicies: { ... },       // Trust sub-level policies
}
```

> **Important:** When `defense` is omitted (not explicitly set to `false`), the defense pipeline is created with default settings. Set `defense: false` only for trusted code in controlled environments.

### GuardrailConfig

Controls how the guardrail pipeline evaluates content across 11 safety categories.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `defaultThresholds` | `GuardrailThresholds` | `{ block: 0.9, flag: 0.5, modify: 0.7 }` | Global score thresholds for determining actions. |
| `thresholds` | `Partial<Record<SafetyCategory, GuardrailThresholds>>` | `undefined` | Per-category threshold overrides. |
| `disabledCategories` | `SafetyCategory[]` | `[]` | Categories to skip entirely. |
| `evaluatorTimeoutMs` | `number` | `200` | Timeout for individual evaluator calls in ms. Evaluators that exceed this are treated as a block (fail-closed). |

**Safety categories:** `prompt-injection`, `credential-exfiltration`, `sandbox-escape`, `data-exfiltration`, `privilege-escalation`, `resource-abuse`, `social-engineering`, `tool-misuse`, `harmful-content`, `training-data-poisoning`, `model-theft`.

**Threshold actions:**
- Score >= `block` threshold: content is blocked (non-negotiable).
- Score >= `modify` threshold: content is sanitized before proceeding.
- Score >= `flag` threshold: content is flagged for review but allowed.

```typescript
guardrails: {
  defaultThresholds: { block: 0.8, flag: 0.4, modify: 0.6 },
  thresholds: {
    'prompt-injection': { block: 0.7, flag: 0.3, modify: 0.5 },
  },
  disabledCategories: ['training-data-poisoning'],
  evaluatorTimeoutMs: 150,
},
```

### Custom Evaluators

The built-in pattern evaluator provides fast regex-based detection. Add custom evaluators (e.g., ML-based models like LlamaGuard) for deeper coverage:

```typescript
defense: {
  additionalEvaluators: [
    {
      name: 'llamaguard-evaluator',
      async evaluate(content, position, context) {
        // Call your ML model and return per-category scores
        return { 'prompt-injection': 0.85, 'harmful-content': 0.2 };
      },
    },
  ],
},
```

Evaluators run in parallel. Scores are merged by taking the maximum per category.

### EscalationConfig

Detects gradual multi-turn escalation using 5 heuristic detectors.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `maxTurns` | `number` | `50` | Maximum turns before forced session reset. |
| `blockedAttemptThreshold` | `number` | `3` | Blocked attempts within the window that trigger quarantine. |
| `blockedAttemptWindow` | `number` | `10` | Number of recent turns to check for blocked attempts. |
| `similarityThreshold` | `number` | `0.8` | Threshold for paraphrase probing detection (0-1). |
| `contextGrowthMultiplier` | `number` | `2.0` | Content length growth factor that triggers a flag (e.g., 2.0 = input doubled). |
| `toolDiversityThreshold` | `number` | `5` | Number of new unique tools in the window that triggers a reconnaissance flag. |
| `toolDiversityWindow` | `number` | `3` | Number of recent turns to check for tool diversity spikes. |
| `embeddingFn` | `(content: string) => number[] \| Promise<number[]>` | `undefined` | Optional embedding function for semantic similarity. Falls back to SHA-256 hash deduplication when not provided. |

**Detectors and their actions:**

| Detector | Trigger | Score | Action |
|----------|---------|-------|--------|
| Blocked-attempt counting | N blocked in window | 0.9 | `block-session` |
| Hash/embedding similarity | Paraphrase probing | 0.7 | `reset-session` |
| Guardrail score trending | Monotonic increase | 0.6 | `inject-refusal` |
| Context length growth | Input doubles | 0.5 | `inject-refusal` |
| Tool diversity spike | N new tools in window | 0.6 | `inject-refusal` |
| Max turns exceeded | Turn > maxTurns | 1.0 | `reset-session` |

```typescript
escalation: {
  maxTurns: 100,
  blockedAttemptThreshold: 2,
  contextGrowthMultiplier: 1.5,
  // Optional: use an embedding model for better paraphrase detection
  embeddingFn: async (content) => {
    return await myEmbeddingModel.embed(content);
  },
},
```

### DefensePipelineConfig

Controls how the pipeline orchestrates defense layers and manages session state.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `operatorPolicy` | `OperatorPolicy` | `undefined` | Operator-level instruction policy to enforce. |
| `spotlightConfig` | `SpotlightConfig` | `{ strategy: 'delimiter' }` | Spotlighting strategy for output boundary marking. |
| `latencyBudgetMs` | `number` | `500` | Total latency budget for the pipeline in ms. Exceeded = fail-closed block. |
| `flagAccumulationThreshold` | `number` | `3` | Number of flags from different layers that auto-escalate to a block. |
| `degradedThreshold` | `number` | `5` | Cumulative flag count across turns to enter degraded mode. |
| `lockdownThreshold` | `number` | `3` | Cumulative block count across turns to enter lockdown mode. |
| `securityPolicy` | `SecurityPolicyConfig` | `undefined` | Trust sub-level policies. See [Trust Sub-Level Policies](#trust-sub-level-policies). |

**Defense modes:**

| Mode | Behavior |
|------|----------|
| **Normal** | Standard evaluation. Flags are flags, blocks are blocks. |
| **Degraded** | Entered when cumulative flags >= `degradedThreshold`. Flags are promoted to blocks. |
| **Lockdown** | Entered when cumulative blocks >= `lockdownThreshold`. All content is blocked. |

**Composition rules:**
- Single layer veto: any block from any layer = block (non-negotiable).
- Flag accumulation: 3+ flags from different layers = block.
- Fail-closed: evaluator error or timeout = block.
- SYSTEM and OPERATOR privilege messages bypass all checks.

### MeshFirewallConfig

Controls the inter-sandbox mesh firewall for multi-sandbox deployments.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `maxMessagesPerMinute` | `number` | `30` | Rate limit per sandbox per minute. |
| `spotlightConfig` | `SpotlightConfig` | `undefined` | Spotlighting config for payload boundary marking. |
| `blockedContentPatterns` | `RegExp[]` | `[]` | Additional patterns to block as executable content. |
| `allowedCrossTenantMesh` | `Array<{ from: TenantId; to: TenantId }>` | `[]` | Allowed cross-tenant communication pairs. Default denies all cross-tenant. |

```typescript
defense: {
  mesh: {
    maxMessagesPerMinute: 50,
    blockedContentPatterns: [/eval\(/],
  },
},
```

---

## Trust Sub-Level Policies

Trust sub-levels split "Trust Level 3" (third-party content) into three granularity levels, each with its own policy. Policies are set via the `trustPolicies` field in the defense config (which maps to `securityPolicy` internally).

### Sub-Levels

| Level | Label | Sources | Default Trust |
|-------|-------|---------|---------------|
| `3a` | Operator-controlled | Agent-generated content, tool output, direct user input | Highest within Level 3 |
| `3b` | Peer agent | Messages from other sandboxes via the mesh | Moderate |
| `3c` | Internet/MCP | Internet-sourced content, MCP server responses | Lowest |

Policy resolution falls back through the chain: `3c` falls back to `3b`, which falls back to `3a`. If no policy is defined, the field is unconstrained.

### TrustLevelPolicy Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `allowCodeExecution` | `boolean` | `undefined` | Whether code execution patterns are allowed in content. When `false`, common patterns like `eval()`, `Function()`, `import()`, `child_process` are blocked. |
| `allowNetworkEgress` | `boolean` | `undefined` | Whether network-related tool calls (fetch, http, etc.) are allowed. |
| `maxSessionTurns` | `number` | `undefined` | Maximum turns allowed for messages at this trust level. |
| `maxContextTokens` | `number` | `undefined` | Maximum estimated tokens (chars / 4) allowed per message. |
| `blockedPatterns` | `string[]` | `undefined` | Regex patterns to block in message content. |
| `allowedHostFunctions` | `string[]` | `undefined` | Allowlist of host functions this trust level can call. Blocks any not listed. |
| `requireApproval` | `string[]` | `undefined` | Host functions that require human-in-the-loop approval. Use `['*']` for all. |

### STANDARD Trust Policies

```typescript
trustPolicies: {
  // 3a: Operator-controlled -- permissive
  trustLevel3a: {
    allowCodeExecution: true,
    allowNetworkEgress: false,
    maxSessionTurns: 50,
  },
  // 3b: Peer agent -- moderate
  trustLevel3b: {
    allowCodeExecution: false,
    allowNetworkEgress: false,
    maxSessionTurns: 30,
  },
  // 3c: Internet/MCP -- strict
  trustLevel3c: {
    allowCodeExecution: false,
    allowNetworkEgress: false,
    maxSessionTurns: 20,
    maxContextTokens: 4000,
  },
},
```

### HARDENED Trust Policies

```typescript
trustPolicies: {
  // 3a: Operator-controlled -- tighter limits
  trustLevel3a: {
    allowCodeExecution: true,
    allowNetworkEgress: false,
    maxSessionTurns: 30,
    maxContextTokens: 8000,
  },
  // 3b: Peer agent -- blocked patterns, low limits
  trustLevel3b: {
    allowCodeExecution: false,
    allowNetworkEgress: false,
    maxSessionTurns: 15,
    maxContextTokens: 2000,
    blockedPatterns: ['eval\\(', 'Function\\(', 'import\\('],
  },
  // 3c: Internet/MCP -- strictest, requires approval for everything
  trustLevel3c: {
    allowCodeExecution: false,
    allowNetworkEgress: false,
    maxSessionTurns: 10,
    maxContextTokens: 1000,
    blockedPatterns: ['eval\\(', 'Function\\(', 'import\\(', 'require\\(', 'exec\\('],
    requireApproval: ['*'],
  },
},
```

### Examples: What to Allow/Block at Each Level

**3a (Operator-controlled):**
- Allow: code execution, generous turn limits, large context windows.
- Block: network egress (unless explicitly needed), sensitive host functions.
- Rationale: content originates from your own agent or direct user input.

**3b (Peer agent):**
- Allow: data exchange, status queries, read-only host functions.
- Block: code execution, network egress, `eval()`/`Function()` patterns.
- Rationale: other sandboxes may be compromised; treat as semi-trusted.

**3c (Internet/MCP):**
- Allow: small data payloads, tightly scoped read operations.
- Block: all code execution, all network egress, large payloads, dynamic patterns.
- Require: human approval for any host function call.
- Rationale: content comes from the internet or third-party MCP servers. Assume hostile.

---

## Host Functions

Host functions bridge the sandbox and the outside world. They are the **only** way sandboxed code can perform async I/O. The allowlist is frozen at creation time with `Object.freeze()`.

### Declaring Host Functions

**Simple form** (bare function, no validation):

```typescript
hostFunctions: {
  lookup: async (args) => {
    const { key } = args as { key: string };
    return database.get(key);
  },
},
```

**Full form** (with schema validation and rate limiting):

```typescript
import { z } from 'zod';

hostFunctions: {
  fetch: {
    handler: async (args) => {
      const { url, method } = args as { url: string; method: string };
      const res = await fetch(url, { method });
      return { status: res.status, body: await res.text() };
    },
    schema: z.object({
      url: z.string().url(),
      method: z.enum(['GET', 'POST']),
    }),
    rateLimit: { maxCalls: 100, windowMs: 60000 },
    timeoutMs: 5000,
  },
},
```

### HostFunctionDef Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `handler` | `(args: unknown) => Promise<unknown>` | Required | The function executed on the host when the sandbox calls it. |
| `schema` | `ZodSchema` | `undefined` | Zod schema for argument validation. Malformed args are rejected before the handler runs. |
| `rateLimit` | `{ maxCalls: number; windowMs: number }` | `undefined` | Rate limit to prevent sandbox abuse. |
| `timeoutMs` | `number` | `30000` | Per-call timeout, independent of the sandbox timeout. |

### Security Considerations

- The sandbox cannot register new host functions or discover functions not in the allowlist.
- Always validate args with a Zod schema for untrusted inputs.
- Use `rateLimit` to prevent denial-of-service via rapid host function calls.
- Trust sub-level policies can further restrict which host functions each trust level can call via `allowedHostFunctions`.

---

## Secrets

Secrets are injected into the sandbox at creation time and follow strict lifecycle rules.

### Injecting Secrets

```typescript
defineConfig({
  plugin: 'isolated-vm',
  limits: { ... },
  secrets: {
    API_TOKEN: process.env.API_TOKEN ?? '',
    DATABASE_URL: process.env.DATABASE_URL ?? '',
  },
});
```

### Lifecycle

1. **Injection:** secrets are passed to the sandbox plugin at creation time.
2. **In-memory only:** secrets are never written to disk.
3. **Scoped:** each sandbox instance gets its own copy.
4. **Redacted:** secret values are automatically redacted from `SandboxResult.logs`.
5. **Destroyed:** secrets are wiped when `sandbox.destroy()` is called.

### E2B_API_KEY

The E2B plugin reads its API key from `secrets.E2B_API_KEY` or falls back to `process.env.E2B_API_KEY`. You can provide it either way:

```typescript
// Via secrets
secrets: { E2B_API_KEY: process.env.E2B_API_KEY ?? '' },

// Or just set the environment variable -- the plugin reads it directly
// E2B_API_KEY=e2b_... in your .env file
```

### .env.example

Copy `.env.example` to `.env` and fill in the values you need:

```bash
# Cloud Sandbox (Tier 3: E2B)
# Required only if using the E2B plugin.
# E2B_API_KEY=e2b_...

# OpenTelemetry (optional)
# OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
# OTEL_SERVICE_NAME=maestro-sandbox
```

> **Important:** Never commit `.env` files. Never pass secrets via `MaestroSandboxConfig` in source-controlled files. Load them from environment variables or a secret manager at runtime.

---

## Audit Logging

The audit logger emits structured JSON events for every significant sandbox and defense pipeline action.

### AuditLoggerOptions

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `emit` | `boolean` | `true` | Write JSON events to stdout (INFO/DEBUG) or stderr (WARN/ERROR/CRITICAL). |
| `store` | `boolean` | `false` | Store events in memory. Enable for testing or post-hoc analysis. |

```typescript
audit: {
  emit: true,   // Log to stdout/stderr
  store: true,  // Also keep in memory (useful for tests)
},
```

### Event Categories

Events are grouped by severity:

| Severity | Examples |
|----------|---------|
| `INFO` | `sandbox.create`, `sandbox.execute`, `hostbridge.call`, `guardrail.input.flag` |
| `WARN` | `sandbox.execute.timeout`, `guardrail.input.block`, `escalation.detected`, `mesh.message.blocked`, `defense.pipeline.blocked` |
| `ERROR` | `sandbox.create.failed`, `hostbridge.call.error`, `plugin.load.failed` |
| `CRITICAL` | `cleanup.tmpdir.failed`, `degradation.below-mcp-min`, `breach.detected`, `mesh.coercion.detected`, `redteam.attack.succeeded` |

### Event Format

Each event is a single JSON line:

```json
{
  "timestamp": "2026-04-04T12:00:00.000Z",
  "level": "WARN",
  "event": "guardrail.input.block",
  "sandboxId": "sbx_abc123",
  "data": {
    "action": "block",
    "position": "input",
    "mode": "normal",
    "triggeredCategories": ["prompt-injection"]
  }
}
```

### OpenTelemetry Integration

Set the OTel environment variables to export audit spans to a collector:

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
OTEL_SERVICE_NAME=maestro-sandbox
```

The audit logger uses the OTel SDK (when available) to emit spans alongside JSON logs.

### Red Team Validation

`createSecureSandbox()` returns a `runRedTeam()` function to validate your defense pipeline against the built-in attack corpus:

```typescript
const { runRedTeam } = await createSecureSandbox(PRESETS.HARDENED);
const { asr, report } = await runRedTeam();
console.log(`Attack Success Rate: ${(asr * 100).toFixed(1)}%`);
// Target: <5% with the full defense stack
```

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `E2B_API_KEY` | Only for E2B plugin | API key for E2B cloud micro-VMs. Get one at [e2b.dev](https://e2b.dev). |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | No | OTel collector endpoint (e.g., `http://localhost:4318`). |
| `OTEL_SERVICE_NAME` | No | Service name for OTel spans. Default: `maestro-sandbox`. |

---

## Migration from maestro.config.ts

If you are migrating from the Maestro monorepo (where configuration lived in `maestro.config.ts` under the `sandbox:` section), this section maps the old structure to the new standalone config.

### Before (monorepo)

```typescript
// maestro.config.ts
import { defineConfig } from '@maestro/spec';

export default defineConfig({
  // ... other monorepo settings ...

  sandbox: {
    plugin: 'isolated-vm',
    limits: {
      memoryMB: 128,
      cpuMs: 5000,
      timeoutMs: 10000,
      networkAccess: false,
      filesystemAccess: 'tmpfs',
    },
  },

  security: {
    trustLevel3a: { allowCodeExecution: true, maxSessionTurns: 50 },
    trustLevel3b: { allowCodeExecution: false, maxSessionTurns: 30 },
    trustLevel3c: { allowCodeExecution: false, maxContextTokens: 4000 },
  },

  // Defense pipeline was wired by @maestro/spec automatically
});
```

### After (standalone)

```typescript
// sandbox.config.ts
import { defineConfig } from 'maestro-sandbox';

export default defineConfig({
  plugin: 'isolated-vm',
  limits: {
    memoryMB: 128,
    cpuMs: 5000,
    timeoutMs: 10000,
    networkAccess: false,
    filesystemAccess: 'tmpfs',
  },

  defense: {
    guardrails: {},
    escalation: {},
    pipeline: {},
    trustPolicies: {
      trustLevel3a: { allowCodeExecution: true, maxSessionTurns: 50 },
      trustLevel3b: { allowCodeExecution: false, maxSessionTurns: 30 },
      trustLevel3c: { allowCodeExecution: false, maxContextTokens: 4000 },
    },
  },

  audit: { emit: true },
});
```

### Key Differences

| Aspect | Monorepo (`maestro.config.ts`) | Standalone (`sandbox.config.ts`) |
|--------|-------------------------------|----------------------------------|
| Import | `from '@maestro/spec'` | `from 'maestro-sandbox'` |
| Config helper | `defineConfig()` from spec | `defineConfig()` from sandbox |
| Security policies | Top-level `security:` field | Nested under `defense.trustPolicies` |
| Defense pipeline | Auto-wired by `@maestro/spec` | Configured explicitly or via presets |
| Sandbox creation | `maestro sync` + factory | `createSecureSandbox(config)` |
| Audit | Configured in monorepo infra | `audit:` field in config |
| Host functions | Registered via spec | Inline in config `hostFunctions:` |

### Migration Checklist

1. Install `maestro-sandbox` as a dependency.
2. Copy `sandbox.config.example.ts` to `sandbox.config.ts`.
3. Move `sandbox.plugin` and `sandbox.limits` to the top level of the new config.
4. Move `security.trustLevel3a/3b/3c` into `defense.trustPolicies`.
5. Add `defense.guardrails`, `defense.escalation`, and `defense.pipeline` sections (empty objects use defaults).
6. Replace factory calls with `createSecureSandbox(config)`.
7. Ensure `sandbox.destroy()` is always called in a `finally` block.
8. Move secrets from `.env.local` to `.env` (the standalone package uses `.env`, not `.env.local`).

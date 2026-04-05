# Maestro Sandbox Security Architecture

This document describes the security architecture of the Maestro Sandbox system.
It is intended for contributors, security auditors, and operators deploying Maestro
in production environments.

**Version:** 1.0
**Last updated:** 2026-04-04

---

## Table of Contents

- [Recommended Configuration](#recommended-configuration)

1. [Defense Pipeline Architecture](#1-defense-pipeline-architecture)
2. [Guardrail Pipeline](#2-guardrail-pipeline)
3. [Escalation Detection](#3-escalation-detection)
4. [Instruction Hierarchy](#4-instruction-hierarchy)
5. [Mesh Firewall](#5-mesh-firewall)
6. [Swiss Cheese Defense Model](#6-swiss-cheese-defense-model)
7. [Behavioral Analysis](#7-behavioral-analysis)
8. [Taint Tracking](#8-taint-tracking)
9. [Task Grounding](#9-task-grounding)
10. [Red Team Harness](#10-red-team-harness)
11. [Audit and Observability](#11-audit-and-observability)
12. [Supply Chain](#12-supply-chain)

---

## Recommended Configuration

For maximum security, use `PRESETS.HARDENED` with `createSecureSandbox()`. This
wires together Tier 3 isolation, the full defense pipeline, guardrails, and
escalation detection in a single call:

```typescript
import { createSecureSandbox, PRESETS } from '@maestro/sandbox';

const { sandbox, defense, shutdown } = await createSecureSandbox(PRESETS.HARDENED);
```

`PRESETS.HARDENED` enables the most restrictive trust sub-level policies described
in [Layer 2](#layer-2-trust-sub-level-enforcement) below:

| Sub-level | Policy in HARDENED preset |
|-----------|--------------------------|
| **3a** (Agent, Tool Output, User Input) | Code execution allowed; network egress denied; host functions restricted to explicit allowlist |
| **3b** (Peer Agent) | Code execution denied; network egress denied; max 20 session turns; operator approval required for sensitive operations |
| **3c** (Internet) | Code execution denied; network egress denied; max 10 session turns; all host functions blocked; max 4096 context tokens |

You can customize individual policies by spreading the preset and overriding
the `defense.trustLevels` field:

```typescript
import { createSecureSandbox, PRESETS, defineConfig } from '@maestro/sandbox';

const config = defineConfig({
  ...PRESETS.HARDENED,
  defense: {
    ...PRESETS.HARDENED.defense,
    trustLevels: {
      ...PRESETS.HARDENED.defense?.trustLevels,
      trustLevel3c: {
        maxContextTokens: 2048,       // Even stricter than default
        allowCodeExecution: false,
        allowNetworkEgress: false,
      },
    },
  },
});

const { sandbox, defense, shutdown } = await createSecureSandbox(config);
```

For the full configuration reference including all presets and environment
variables, see [CONFIGURATION.md](./CONFIGURATION.md).

---

## 1. Defense Pipeline Architecture

Every message entering or leaving the sandbox passes through four independent
defense layers arranged in series. Each layer has full veto authority: a block
decision from any single layer terminates processing immediately. No downstream
layer can override an upstream block.

```
                         500ms latency budget
  ┌─────────────────────────────────────────────────────────────────────┐
  │                                                                     │
  │   ┌──────────────┐   ┌──────────────┐   ┌──────────┐   ┌────────┐ │
  │   │  1. Operator  │──▶│ 2. Trust Sub │──▶│3. Guard- │──▶│4. Esca-│ │
  │   │    Policy     │   │    Level     │   │  rail    │   │ lation │ │
  │   │   (~0ms)      │   │ Enforcement  │   │ Pipeline │   │Detect. │ │
  │   └──────────────┘   └──────────────┘   └──────────┘   └────────┘ │
  │         │                    │                 │             │      │
  │      BLOCK?               BLOCK?            BLOCK?       BLOCK?    │
  │         │                    │                 │             │      │
  │         ▼                    ▼                 ▼             ▼      │
  │   ┌──────────────────────────────────────────────────────────────┐ │
  │   │              Spotlighting (output position only)             │ │
  │   │           High-entropy boundary tokens injected              │ │
  │   └──────────────────────────────────────────────────────────────┘ │
  │                                                                     │
  └─────────────────────────────────────────────────────────────────────┘
```

### Layer 1: Operator Policy (~0ms)

The fastest layer. Evaluates privilege-based blocklists before any heavier
processing begins.

- **Blocked patterns:** global regex blocklist applied to all content.
- **Allowed host functions:** explicit allowlist; anything not listed is denied.
- **ReDoS protection:** payloads exceeding 100K characters are rejected before
  regex evaluation to prevent catastrophic backtracking.

### Layer 2: Trust Sub-Level Enforcement

Level 3 of the instruction hierarchy is split into three trust sub-levels, each
with independent policy controls:

| Sub-level | Sources | Description |
|-----------|---------|-------------|
| **3a** | `AGENT`, `TOOL_OUTPUT`, `USER_INPUT` | Highest trust within Level 3 |
| **3b** | `PEER_AGENT` | Inter-agent messages; reduced trust |
| **3c** | `INTERNET` | Lowest trust; most restrictive policies |

Each sub-level enforces its own set of policies:

- `blockedPatterns` -- per-tier regex blocklists
- `maxSessionTurns` -- conversation length cap
- `allowCodeExecution` -- whether the source can trigger code execution
- `allowedHostFunctions` -- per-tier host function allowlist
- `maxContextTokens` -- token budget per tier
- `allowNetworkEgress` -- whether outbound network is permitted
- `requireApproval` -- whether operator approval is needed before execution

### Layer 3: Guardrail Pipeline

Evaluates content against 11 safety categories in parallel. See
[Section 2](#2-guardrail-pipeline) for full details.

- Individual evaluator timeout: 200ms, **fail-closed** (timeout = block).

### Layer 4: Escalation Detection

Monitors behavioral patterns across the session to detect adversarial
persistence. See [Section 3](#3-escalation-detection) for the five heuristic
detectors.

### Spotlighting

Applied at the output position only. Injects high-entropy boundary tokens into
outgoing content to help downstream consumers distinguish model output from
injected instructions. This is a defense-in-depth measure against prompt
injection in multi-agent pipelines.

### Operating Modes

The pipeline operates in three modes based on cumulative incident counts within
a session:

| Mode | Trigger | Behavior |
|------|---------|----------|
| **Normal** | Default | All layers active, standard thresholds |
| **Degraded** | 5+ cumulative flags | Tighter thresholds, increased logging |
| **Lockdown** | 3+ cumulative blocks | Most restrictive policies, operator notification |

---

## 2. Guardrail Pipeline

The guardrail pipeline evaluates content against 11 safety categories. Evaluators
run in parallel; the maximum score across all evaluators for a given category
determines the outcome.

### Safety Categories

| # | Category | Description |
|---|----------|-------------|
| 1 | `prompt-injection` | Attempts to override system instructions |
| 2 | `credential-exfiltration` | Attempts to extract secrets, API keys, tokens |
| 3 | `sandbox-escape` | Attempts to break out of the execution sandbox |
| 4 | `data-exfiltration` | Unauthorized transfer of data to external destinations |
| 5 | `privilege-escalation` | Attempts to gain higher privilege than granted |
| 6 | `training-data-poisoning` | Attempts to corrupt model training data |
| 7 | `model-theft` | Attempts to extract model weights or architecture |
| 8 | `resource-abuse` | Excessive compute, memory, or network consumption |
| 9 | `tool-misuse` | Using permitted tools for unintended purposes |
| 10 | `social-engineering` | Manipulation of human operators via the agent |
| 11 | `harmful-content` | Generation of dangerous, illegal, or abusive content |

### Scoring Thresholds

| Threshold | Score | Action |
|-----------|-------|--------|
| **Block** | >= 0.9 | Request rejected, event logged |
| **Modify** | >= 0.7 | Content sanitized before forwarding |
| **Flag** | >= 0.5 | Request allowed, flag recorded for escalation tracking |

These are default thresholds and can be adjusted by the operator.

### Evaluator Tiers

**Layer 1 -- Pattern Evaluator (regex-based):**
Fast, deterministic, but limited. Matches known attack signatures using regular
expressions. This layer is acknowledged as **trivially bypassed by paraphrasing**
and exists primarily to catch low-effort attacks quickly.

**P2 Upgrade Path -- ML Evaluator (LlamaGuard 3):**
A planned upgrade to add a machine learning evaluator using LlamaGuard 3 for
semantic-level detection. This will catch attacks that evade pattern matching
through rephrasing or obfuscation.

### Timeout Behavior

Each individual evaluator has a 200ms timeout. If an evaluator does not respond
within this window, it is treated as a **block** (fail-closed). This prevents a
slow or hung evaluator from silently allowing dangerous content.

---

## 3. Escalation Detection

The escalation detector monitors session-level behavioral patterns to identify
adversarial persistence -- repeated attempts to probe, bypass, or overwhelm the
defense pipeline. It runs five heuristic detectors.

### Detector 1: Blocked-Attempt Counting

Tracks the number of blocked requests within a sliding window.

- **Trigger:** 3 or more blocks within 10 turns
- **Score:** 0.9
- **Action:** `block-session`

### Detector 2: Similarity Detection

Identifies repeated or near-identical requests that suggest automated probing.

- **Current implementation:** SHA-256 hash comparison over a 10-turn sliding window.
  Exact duplicates are flagged.
- **P2 upgrade:** Embedding-based similarity using cosine similarity with a
  threshold of >= 0.8 to catch semantically equivalent rephrasing.

### Detector 3: Guardrail Score Trending

Monitors whether guardrail scores are monotonically increasing across turns,
which suggests an attacker is iteratively refining their approach.

- **Trigger:** Monotonic increase over the last 5 turns AND final score > 0.3
- **Action:** `inject-refusal`

### Detector 4: Context Length Monitoring

Detects context stuffing attacks where an adversary inflates the context to push
system instructions out of the model's attention window.

- **Trigger:** Context length exceeds 2.0x the length of the first turn
- **Action:** `inject-refusal`

### Detector 5: Tool Diversity Spike

Detects rapid exploration of new tools, which may indicate an attacker probing
for exploitable tool interfaces.

- **Trigger:** 5 or more new unique tools invoked within the last 3 turns
- **Action:** `reset-session`

### Structural Limit

All sessions are capped at **50 turns maximum**, after which a forced reset
occurs. This limits the total attack surface available in any single session
regardless of whether individual detectors fire.

### Escalation Actions

| Action | Effect |
|--------|--------|
| `continue` | No intervention; log the event |
| `warn-operator` | Alert the operator via the audit system |
| `inject-refusal` | Inject a refusal message into the conversation |
| `reset-session` | Clear session state and start fresh |
| `block-session` | Terminate the session permanently |

---

## 4. Instruction Hierarchy

Maestro enforces a strict 8-level instruction hierarchy. Messages from higher
privilege levels always override messages from lower levels. No message can
elevate its own privilege.

```
Level 0  ██████████████████████████████████████  SYSTEM
Level 1  ████████████████████████████████████    OPERATOR
Level 2  ██████████████████████████████████      SUPERVISOR
Level 3  ████████████████████████████████        AGENT
Level 4  ██████████████████████████████          TOOL_OUTPUT
Level 5  ████████████████████████████            PEER_AGENT
Level 6  ██████████████████████████              USER_INPUT
Level 7  ████████████████████████                INTERNET
```

| Level | Name | Description |
|-------|------|-------------|
| 0 | `SYSTEM` | Hardcoded invariants. Cannot be overridden by any source. |
| 1 | `OPERATOR` | Platform operator configuration and policies. |
| 2 | `SUPERVISOR` | Human supervisor directives during a session. |
| 3 | `AGENT` | The agent's own reasoning and instructions. Split into sub-levels (3a/3b/3c) by the defense pipeline. |
| 4 | `TOOL_OUTPUT` | Return values from tool invocations. |
| 5 | `PEER_AGENT` | Messages from other agents in a multi-agent mesh. |
| 6 | `USER_INPUT` | End-user messages. Treated as untrusted by default. |
| 7 | `INTERNET` | Content fetched from the internet. Lowest trust. |

### Key Properties

- **No privilege escalation:** A message at level N cannot instruct the system
  to treat subsequent messages as level < N.
- **Higher wins:** When instructions conflict, the higher-privilege instruction
  (lower level number) takes precedence unconditionally.
- **Trust sub-level split:** Level 3 is further divided into 3a, 3b, and 3c
  (see [Defense Pipeline, Layer 2](#layer-2-trust-sub-level-enforcement)) to
  provide granular policy control within the agent tier.

---

## 5. Mesh Firewall

The mesh firewall governs all communication between sandboxes in a multi-agent
deployment.

### Default Policies

- All inter-sandbox messages are assigned **`PEER_AGENT` privilege (level 5)**.
- **No executable content** may transit the mesh. Messages containing executable
  payloads are rejected.
- **Rate limit:** 30 messages per minute per sandbox pair.
- **Allowed message types:** `data`, `status`, `request`, `response`. All other
  types are rejected.
- **Spotlighting** is applied to all mesh messages.

### Blocked Content Patterns

The firewall rejects messages containing any of these 12 patterns:

| Pattern | Rationale |
|---------|-----------|
| `eval` | Arbitrary code execution |
| `Function` | Dynamic function construction |
| `import` | Module loading |
| `require` | Module loading (CommonJS) |
| `exec` | Process execution |
| `spawn` | Process spawning |
| `<script` | Script injection |
| `javascript:` | JavaScript URI scheme |
| `data:text/html` | Data URI with HTML content |
| `process.env` | Environment variable access |
| `child_process` | Node.js process spawning module |
| *(12th pattern)* | Reserved for operator-defined custom pattern |

### Cross-Tenant Communication

- **Default:** deny all cross-tenant traffic.
- **Allowlist:** operators must explicitly allowlist specific cross-tenant
  communication paths. There is no wildcard or "allow all" option.

---

## 6. Swiss Cheese Defense Model

The defense model follows the Swiss Cheese principle: multiple independent layers,
each with known gaps, arranged so that no single point of failure compromises the
system.

```
 Attack ──▶ ┊ ┃ ┊ ┃ ┊ ┃ ┊ ┃ ┊ ┃ ┊ ┃ ┊ ┃ ┊ ┃ ──▶ Blocked
             S  H  S  H  S  H  S  H  S  H  S  H  S  H  S  H
             1  1  2  2  3  3  4  4  5  5  6  6  7  7  8  8

             S = Structural control (non-bypassable)
             H = Heuristic control (bypassable, has structural backup)
```

### Structural Controls (8)

Structural controls are enforced by the runtime and cannot be bypassed by
adversarial input:

1. Sandbox memory limit (128MB default)
2. Execution timeout (10,000ms default)
3. Network disabled by default
4. Filesystem restricted to tmpfs
5. Instruction hierarchy privilege enforcement
6. Maximum session turn limit (50)
7. Cross-tenant default deny
8. Mesh message type allowlist

### Heuristic Controls (7)

Heuristic controls use pattern matching or statistical analysis. Each one can
be bypassed by a sufficiently sophisticated attacker, but each has a structural
backup that catches what the heuristic misses:

| Heuristic | Structural Backup |
|-----------|-------------------|
| Pattern-based prompt injection detection | Instruction hierarchy prevents privilege escalation |
| Credential pattern matching | Taint tracking blocks exfiltration at egress |
| Sandbox escape pattern detection | OS-level sandbox isolation (isolated-vm) |
| Data exfiltration heuristics | Network disabled by default; taint tracking |
| Escalation score trending | Forced session reset at 50 turns |
| Tool diversity spike detection | Task grounding restricts available capabilities |
| Behavioral anomaly detection | Rate limits and resource caps |

### Safety Invariant

**If ALL heuristic controls fail simultaneously, the structural controls still
prevent:**

- Host compromise (sandbox isolation)
- Cross-tenant data access (default deny)
- Arbitrary network egress (network disabled by default)
- Filesystem escape (tmpfs-only filesystem)

This is the system's core safety guarantee.

---

## 7. Behavioral Analysis

The behavioral analyzer monitors 16 anomaly patterns across sessions using an
in-memory log with LRU eviction.

### How It Works

- Each sandbox maintains a behavioral log of recent actions.
- The analyzer compares current behavior against 16 predefined anomaly patterns
  (e.g., sudden tool usage changes, unusual output patterns, timing anomalies).
- Anomalies are scored and fed into the escalation detector as additional signals.
- The in-memory log uses LRU eviction to bound memory usage, keeping only the
  most recent entries per session.

### Integration

The behavioral analyzer feeds into the escalation detection layer. It does not
make block decisions on its own -- it contributes evidence that the escalation
detector uses to determine whether an adversarial pattern is emerging.

---

## 8. Taint Tracking

The taint tracker maintains a content hash provenance registry that tracks
the origin and privilege level of every piece of content flowing through the
sandbox.

### Tracked Metadata

For each content hash (SHA-256):

- **Source:** where the content originated (tool output, user input, internet, etc.)
- **Privilege:** the instruction hierarchy level of the source
- **Timestamp:** when the content entered the system

### Exfiltration Detection

When content reaches an egress point (network output, file write, inter-sandbox
message), the taint tracker checks whether the content's provenance permits that
operation. For example:

- Content originating from `secret-access` tagged tools cannot be sent over
  network egress.
- Content from high-privilege sources cannot be forwarded to low-privilege
  destinations without explicit operator approval.

This provides a structural defense against data exfiltration that works
regardless of whether the guardrail pipeline's heuristic detectors are bypassed.

---

## 9. Task Grounding

Task grounding restricts what a sandbox can do based on its declared purpose. Each
sandbox declares a set of capability tags, and the system enforces that only those
capabilities are available.

### Capability Tags

| Tag | Permits |
|-----|---------|
| `filesystem-read` | Reading files within the sandbox |
| `filesystem-write` | Writing files within the sandbox |
| `code-execute` | Running code in the sandbox |
| `code-review` | Analyzing code (read-only) |
| `network-fetch` | Outbound HTTP requests |
| `network-listen` | Binding to network ports |
| `secret-access` | Accessing secrets and credentials |
| `process-spawn` | Spawning child processes |
| `git-read` | Reading git repositories |
| `git-write` | Writing to git repositories (commits, pushes) |

### Enforcement

- A sandbox that declares only `code-review` and `git-read` cannot execute code,
  write files, or access the network -- even if the agent requests those
  capabilities.
- Capability tags are set at sandbox creation time and cannot be modified during
  a session.
- Attempts to use undeclared capabilities are blocked and logged as a
  `privilege-escalation` event.

---

## 10. Red Team Harness

The red team harness provides built-in adversarial testing for the sandbox's
defense pipeline. It ships with 100+ attack cases across all 11 guardrail
categories and is designed to be run as part of CI.

### Running the Red Team Suite

```bash
# Run the full red team suite
pnpm test -- --grep "red-team"

# Run attacks for a specific category
pnpm test -- --grep "red-team" --grep "prompt-injection"
```

### Attack Categories

The 100+ built-in attacks cover all 11 guardrail categories:

1. Prompt injection (instruction override, role-play, jailbreak)
2. Credential exfiltration (env var access, secret dumping)
3. Sandbox escape (process spawning, filesystem traversal)
4. Data exfiltration (encoding tricks, side channels)
5. Privilege escalation (trust level spoofing, hierarchy manipulation)
6. Training data poisoning (output manipulation)
7. Model theft (weight extraction, architecture probing)
8. Resource abuse (memory bombs, infinite loops, fork bombs)
9. Tool misuse (tool chaining, parameter injection)
10. Social engineering (operator impersonation, urgency manipulation)
11. Harmful content (generation of dangerous material)

### Attack Success Rate (ASR)

The harness measures ASR -- the percentage of attacks that bypass all defense
layers. This metric is tracked over time to detect regressions.

- **Target ASR:** 0% for structural controls, minimized for heuristic controls.
- CI pipelines should fail if ASR exceeds a configured threshold.

### Regression Testing

```typescript
import { extractRegressionCases } from '@maestro/sandbox';

// Extract cases that previously succeeded (attacks that bypassed defenses)
// for inclusion in the CI regression suite
const regressionCases = extractRegressionCases();
```

Use `extractRegressionCases()` to extract any attack that has ever succeeded
against the pipeline. These cases are added to the regression suite so that
fixed vulnerabilities stay fixed.

### Writing Custom Attacks

Add new attack cases to the red team suite to test organization-specific threat
models. Each attack case specifies:

- **Category:** which guardrail category it targets
- **Payload:** the attack content
- **Expected outcome:** whether the pipeline should block, modify, or flag it

---

## 11. Audit and Observability

The audit system records security-relevant events for forensic analysis and
operational monitoring.

### Event Coverage

The system defines **63+ event types** covering all security-relevant operations:

- Defense pipeline decisions (block, modify, flag, allow)
- Escalation detector triggers
- Instruction hierarchy violations
- Mesh firewall actions
- Taint tracking alerts
- Behavioral anomalies
- Session lifecycle events (create, reset, destroy)
- Operating mode transitions (normal, degraded, lockdown)

### Severity Mapping

Each event type maps to a severity level (info, warn, error, critical) based on
its security implications. Blocks and session terminations are critical; flags
are warnings.

### Content Hashing

Content in audit logs is SHA-256 hashed by default rather than stored in raw
form. This prevents the audit log itself from becoming a data exfiltration
vector while still enabling correlation and forensic analysis.

### OpenTelemetry Integration

The audit system optionally integrates with OpenTelemetry for export to external
observability platforms.

```typescript
// Enable OpenTelemetry export in your configuration
{
  audit: {
    otel: {
      enabled: true,
      endpoint: "https://your-collector:4318",
      serviceName: "maestro-sandbox"
    }
  }
}
```

When enabled, audit events are emitted as OpenTelemetry spans and logs,
compatible with any OTLP-compatible backend (Jaeger, Grafana, Datadog, etc.).

---

## 12. Supply Chain

Maestro Sandbox has **4 production dependencies**. All others are devDependencies (build/test only, not shipped).

### Production Dependencies

| Package | Version | License | Purpose | Native Code |
|---------|---------|---------|---------|-------------|
| `isolated-vm` | ^6.1.2 | MIT | V8 isolate sandbox (Tier 1 default plugin) | Yes (node-gyp) |
| `zod` | ^3.24.0 | MIT | Schema validation for host function arguments | No |
| `e2b` | ^2.18.0 | MIT | E2B cloud micro-VM sandbox (Tier 3, optional) | No |
| `@anthropic-ai/sandbox-runtime` | ^0.0.46 | MIT | Anthropic Secure Runtime (Tier 2, optional) | No |

### Transitive Dependencies (production)

Total production dependency tree: **~50 packages** (including transitive deps).

**`isolated-vm`** (1 transitive dep):
- `node-gyp-build` — Native addon build tool. Compiles V8 isolate bindings.

**`zod`** — Zero transitive dependencies.

**`e2b`** (~25 transitive deps):
- `@bufbuild/protobuf`, `@connectrpc/connect` — gRPC/protobuf for E2B API
- `glob`, `tar`, `chalk` — File operations and terminal output
- `openapi-fetch` — HTTP client for E2B REST API
- `dockerfile-ast` — Dockerfile parsing

**`@anthropic-ai/sandbox-runtime`** (~5 transitive deps):
- `commander` — CLI argument parsing
- `lodash-es` — Utility functions
- `shell-quote` — Shell command quoting
- `@pondwader/socks5-server` — SOCKS5 proxy for sandbox networking

### Risk Assessment

| Risk | Mitigation |
|------|------------|
| Native code in `isolated-vm` | Pinned version, compiled from source via node-gyp (no prebuilt binaries from untrusted CDN) |
| E2B cloud dependency | Optional — only loaded if `plugin: 'e2b'` is configured. Data leaves your infrastructure. |
| Anthropic runtime dependency | Optional — only loaded if `plugin: 'anthropic-sr'` is configured. |
| Transitive dependency compromise | Dynamic `import()` loading means unused plugins and their deps are never imported at runtime |

### Minimizing the Dependency Surface

If you only use `isolated-vm` (Tier 1), you can mark the optional plugins as optional in your deployment:

- `e2b` is only imported when `plugin: 'e2b'` is selected
- `@anthropic-ai/sandbox-runtime` is only imported when `plugin: 'anthropic-sr'` is selected
- Neither is loaded by `PRESETS.MINIMAL` or `PRESETS.STANDARD`

The core sandbox + defense pipeline + guardrails + escalation detection depend only on `isolated-vm` and `zod`.

---

## Threat Model Summary

The Maestro Sandbox is designed to be secure under the following assumptions:

- **Attacker model:** the agent itself may be adversarial (compromised by prompt
  injection or acting on malicious instructions from untrusted input sources).
- **Trust boundary:** the sandbox boundary is the primary trust boundary. Nothing
  inside the sandbox is trusted; everything outside (host, operator) is trusted.
- **Defense goal:** prevent host compromise, cross-tenant access, unauthorized
  data exfiltration, and arbitrary code execution outside the sandbox, even if
  all heuristic defenses are bypassed.

### Known Limitations

- **Pattern evaluator:** regex-based detection is trivially bypassed by
  paraphrasing. The ML evaluator (LlamaGuard 3) is a planned upgrade.
- **Similarity detection:** SHA-256 hash comparison only catches exact
  duplicates. Embedding-based similarity is a planned upgrade.
- **Behavioral analysis:** in-memory only; does not persist across sandbox
  restarts.
- **50-turn limit:** may be insufficient for long-running legitimate workloads;
  operators should adjust based on their use case.

### Reporting Security Issues

If you discover a security vulnerability in Maestro Sandbox, please report it
responsibly. Do not open a public issue. Instead, email security concerns to the
maintainers directly. See the repository's SECURITY policy for contact details.

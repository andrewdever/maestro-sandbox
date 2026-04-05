# Maestro Sandbox

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Node.js >= 22](https://img.shields.io/badge/node-%3E%3D22-brightgreen.svg)](.nvmrc)

**LLM agent sandboxing with multi-tier isolation and defense-in-depth.**

## 30-Second Setup

```bash
npm install maestro-sandbox
```

```typescript
import { createSecureSandbox, PRESETS } from 'maestro-sandbox';

const { sandbox, defense } = await createSecureSandbox(PRESETS.STANDARD);

const result = await sandbox.execute('return 2 + 2');
console.log(result.result); // 4

await sandbox.destroy();
```

That gives you a V8 isolate sandbox with the full defense pipeline, guardrails, and escalation detection. One function call, batteries included.

## Configuration

### Presets

Three presets cover common deployment scenarios. Pick one and go.

| Preset | Plugin | Defense Pipeline | Use Case |
|--------|--------|-----------------|----------|
| `MINIMAL` | `isolated-vm` | None | Trusted code, testing |
| `STANDARD` | `isolated-vm` | Full pipeline | Most applications |
| `HARDENED` | `auto` (Tier 2+) | Strict thresholds | Untrusted code, MCP, multi-tenant |

```typescript
import { createSecureSandbox, PRESETS } from 'maestro-sandbox';

// Testing or trusted internal code
const { sandbox } = await createSecureSandbox(PRESETS.MINIMAL);

// Production with defense pipeline (recommended)
const { sandbox, defense } = await createSecureSandbox(PRESETS.STANDARD);

// Untrusted code, MCP servers, multi-tenant
const { sandbox, defense } = await createSecureSandbox(PRESETS.HARDENED);
```

> **Warning:** `MINIMAL` disables the defense pipeline entirely. Tier 1 (`isolated-vm`) is NOT a security boundary against determined attackers. Use `STANDARD` or `HARDENED` for untrusted code.

### Custom Configuration with `defineConfig()`

For fine-grained control, use `defineConfig()` for type-safe autocomplete.

```typescript
import { defineConfig, createSecureSandbox } from 'maestro-sandbox';

const config = defineConfig({
  plugin: 'docker',
  limits: {
    memoryMB: 256,
    cpuMs: 10000,
    timeoutMs: 30000,
    networkAccess: false,
    filesystemAccess: 'tmpfs',
  },
  defense: {
    guardrails: {
      disabledCategories: ['training-data-poisoning'],
    },
    escalation: {
      maxTurns: 100,
    },
    trustPolicies: {
      trustLevel3c: {
        allowCodeExecution: false,
        requireApproval: ['*'],
      },
    },
  },
});

const { sandbox, defense } = await createSecureSandbox(config);
```

Copy [`sandbox.config.example.ts`](sandbox.config.example.ts) as a starting point. It documents every option with inline comments.

### Environment Variables

Copy [`.env.example`](.env.example) to `.env`. Most features work without any environment variables. Only `E2B_API_KEY` is required for cloud sandboxing (Tier 3).

| Variable | Required | Purpose |
|----------|----------|---------|
| `E2B_API_KEY` | Only for E2B plugin | Cloud micro-VM sandbox ([e2b.dev](https://e2b.dev)) |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | No | OpenTelemetry audit span export |
| `OTEL_SERVICE_NAME` | No | Service name for OTel spans |

## Dependencies & Supply Chain

4 production dependencies. That's it.

| Package | Version | License | What It Does |
|---------|---------|---------|-------------|
| `isolated-vm` | ^6.1.2 | MIT | V8 isolate sandbox (Tier 1 default) |
| `zod` | ^3.24.0 | MIT | Schema validation for host function args |
| `e2b` | ^2.18.0 | MIT | E2B cloud micro-VMs (Tier 3, optional) |
| `@anthropic-ai/sandbox-runtime` | ^0.0.46 | MIT | Anthropic Secure Runtime (Tier 2, optional) |

The core sandbox + full defense pipeline only needs `isolated-vm` and `zod`. The other two are optional — only loaded at runtime if you select their plugin. ~50 total packages in the transitive tree. See [Supply Chain](docs/SECURITY.md#12-supply-chain) for the full risk assessment.

## Using the Defense Pipeline

`createSecureSandbox()` wires up the defense pipeline automatically. Process input before executing code.

```typescript
const { sandbox, defense } = await createSecureSandbox(PRESETS.STANDARD);

try {
  const check = await defense.processInput(message);
  if (check.action !== 'block') {
    const result = await sandbox.execute(code);
  }
} finally {
  await sandbox.destroy();
}
```

The defense pipeline returns one of four actions: `allow`, `block`, `flag`, or `modify`. See [Defense Pipeline](#defense-pipeline) for details.

## Plugins

10 isolation backends across 3 tiers, with automatic degradation when higher tiers are unavailable:

| Plugin | Tier | Isolation | Platform | Status | Startup |
|--------|------|-----------|----------|--------|---------|
| **isolated-vm** | 1 | V8 isolate | All | Stable | <200ms |
| **mock** | 1 | None (testing) | All | Stable | <50ms |
| **anthropic-sr** | 2 | Seatbelt / Landlock | macOS, Linux | Stable | 50-200ms |
| **landlock** | 2 | Seatbelt (macOS) | macOS | Stable | 50-200ms |
| **firejail** | 2 | Firejail CLI | Linux | V1.1 | TBD |
| **docker** | 3 | Container | All | Stable | 1-3s |
| **e2b** | 3 | Cloud micro-VM | Cloud | Stable | 2-5s |
| **openshell** | 3 | K3s + 4-layer policy | All | Stable | 3-5s |
| **docker-pi** | 2/3 | Process isolation | Windows | V1.1 | TBD |
| **microsandbox** | 3 | libkrun micro-VM | All | V1.1 | <200ms |

**Degradation chain (default):** Docker -> E2B -> Landlock -> Anthropic SR -> isolated-vm

```typescript
import { createSandboxWithDegradation } from 'maestro-sandbox';

const sandbox = await createSandboxWithDegradation({
  config: { limits: { memoryMB: 256, cpuMs: 10000, timeoutMs: 30000, networkAccess: false, filesystemAccess: 'tmpfs' } },
  mcpMinTier: 2, // hard floor -- won't fall below Tier 2
});
```

Or use `PRESETS.HARDENED`, which sets `plugin: 'auto'` and `mcpMinTier: 2` for you.

## Defense Pipeline

4 independent layers, fail-closed. A single layer veto blocks the request.

```
Input -> [Operator Policy] -> [Guardrail Pipeline] -> [Escalation Detector] -> [Spotlighting] -> Output
              |                     |                       |                      |
         Privilege-based       11 safety            5 heuristic          Boundary tokens
         blocklists +          categories            detectors           on untrusted
         ReDoS protection      (pattern eval)        (multi-turn)        content
```

**Operating modes:** `normal` -> `degraded` (5+ flags) -> `lockdown` (3+ blocks)

For manual pipeline construction (advanced):

```typescript
import { createDefensePipeline, createGuardrailPipeline, createEscalationDetector } from 'maestro-sandbox';

const pipeline = createDefensePipeline({
  guardrail: createGuardrailPipeline({ /* ... */ }),
  escalation: createEscalationDetector({ /* ... */ }),
});

const result = await pipeline.evaluate(message);
// result.action: 'allow' | 'block' | 'flag' | 'modify'
```

Most users should use `createSecureSandbox()` instead, which wires this up automatically from a preset or config object.

## Instruction Hierarchy

8-level privilege model. Higher privilege always wins in conflicts.

```
Level 0: SYSTEM         -- Hardcoded safety invariants (nothing overrides)
Level 1: OPERATOR       -- Config-defined policies
Level 2: SUPERVISOR     -- Human-in-the-loop overrides
Level 3: AGENT          -- Primary LLM agent instructions
Level 4: TOOL_OUTPUT    -- Host function return values
Level 5: PEER_AGENT     -- Messages from peer sandboxes
Level 6: USER_INPUT     -- End-user provided content
Level 7: INTERNET       -- Internet / MCP tool descriptions (lowest trust)
```

Trust sub-levels split Level 3 into `3a` (operator-controlled), `3b` (peer-agent), `3c` (internet) for fine-grained policy enforcement. Configure these via `defense.trustPolicies` in your config.

## Security Model

**Swiss Cheese Defense:** Every heuristic control has a structural backup. If ALL heuristics fail simultaneously, structural controls still prevent host compromise.

### Structural Controls (non-bypassable)

| Control | Prevents | Bypass Requires |
|---------|----------|-----------------|
| Sandbox process isolation | Host process access | VM/container escape |
| Object.freeze host bridge | Prototype pollution | V8 engine bug |
| Zod schema validation | Malformed arguments | Code change |
| URL allowlist | SSRF / arbitrary egress | Config change |
| Rate limiting | Resource exhaustion | Code change |
| Instruction hierarchy | Privilege escalation | Code change |
| Session turn limit | Unbounded escalation | Config change |
| Content spotlighting | Instruction confusion | Matching 2^-128 token |

### Heuristic Controls (layered defense)

| Control | Prevents | Structural Backup |
|---------|----------|-------------------|
| Output classifier | Injected instructions | URL allowlist + rate limiting |
| Call-sequence analyzer | Multi-step exfiltration | URL allowlist + secret redaction |
| Code review scanner | Malicious patches | Process isolation |
| Entropy analysis | Encoded secrets | Secret redaction + URL allowlist |
| Multi-turn detector | Gradual escalation | Session turn limit |
| Guardrail classifier | 11 unsafe categories | Process isolation + URL allowlist |
| Pattern evaluator | Known injection patterns | Process isolation + hierarchy |

### OWASP LLM Top 10 Coverage

| ID | Category | Layers | Meets 2+ |
|----|----------|--------|----------|
| LLM01 | Prompt Injection | Guardrail, hierarchy, spotlighting, escalation | Yes |
| LLM02 | Insecure Output | Guardrail, spotlighting, secret redaction | Yes |
| LLM03 | Training Data Poisoning | Guardrail, red team | Yes |
| LLM04 | Model DoS | Rate limiting, session limits, guardrail | Yes |
| LLM05 | Supply Chain | socket.dev, Semgrep, license check, plugin-validator | Yes |
| LLM06 | Sensitive Info Disclosure | Guardrail, redaction, taint tracker, URL allowlist | Yes |
| LLM07 | Insecure Plugin Design | MCP scanner, plugin-validator, host bridge | Yes |
| LLM08 | Excessive Agency | Task grounding, trust sub-levels, HITL gating | Yes |
| LLM09 | Overreliance | -- | Out of scope |
| LLM10 | Model Theft | Guardrail, red team | Yes |

## Red Team Harness

100+ built-in attack cases across 11 categories. Run in CI to measure Attack Success Rate (ASR).

```typescript
// Using createSecureSandbox (recommended)
const { runRedTeam } = await createSecureSandbox(PRESETS.STANDARD);
const { asr, report } = await runRedTeam();
console.log(`ASR: ${asr}%`); // Target: <5% with full stack

// Or manually
import { createRedTeamHarness, getBuiltinCorpus, extractRegressionCases } from 'maestro-sandbox';

const harness = createRedTeamHarness({ pipeline });
const report = await harness.run(getBuiltinCorpus());

// Convert findings to permanent CI tests
const regressions = extractRegressionCases(report, { bypassesOnly: true });
```

## Host Function Bridge

Sandboxed code calls host functions through a frozen, schema-validated, rate-limited bridge with SSRF prevention.

```typescript
import { createSecureSandbox, defineConfig } from 'maestro-sandbox';
import { z } from 'zod';

const { sandbox } = await createSecureSandbox(defineConfig({
  plugin: 'isolated-vm',
  limits: { memoryMB: 128, cpuMs: 5000, timeoutMs: 10000, networkAccess: false, filesystemAccess: 'tmpfs' },
  defense: false,
  hostFunctions: {
    lookup: {
      handler: async (args) => {
        const { key } = args as { key: string };
        return db.get(key);
      },
      schema: z.object({ key: z.string().max(256) }),
      rateLimit: { maxCalls: 100, windowMs: 60000 },
    },
  },
}));

// Inside sandbox:
// const value = await hostCall('lookup', { key: 'user:123' });
```

## Git Workflow

Inject code into sandboxes and extract changes as validated patches.

```typescript
// Host injects a pruned repo
await sandbox.git.inject(tarball);

// Agent works inside sandbox...
await sandbox.execute('...');

// Host extracts and validates changes
const patch = await sandbox.git.exportPatch();

import { validatePatch } from 'maestro-sandbox';
const validation = validatePatch(patch, { workspaceRoot: '/app' });
// Validates: path traversal, symlinks, binaries, git internals, workspace confinement
```

## Multi-Tenant Isolation

Namespace-based tenant isolation with cross-tenant mesh denial by default.

```typescript
import { validateTenantId, namespaceSandboxId, sameTenant } from 'maestro-sandbox';

const tenantId = validateTenantId('org-acme');
const sandboxId = namespaceSandboxId(tenantId, 'agent-1');
// -> 'org-acme::agent-1'

sameTenant(sandboxId1, sandboxId2); // false -> mesh blocked
```

## Testing

```bash
npm test                 # Unit tests (~900+ tests)
npm run test:integration # Integration tests (isolation, git roundtrip, host callbacks)
npm run test:security    # Security tests (escape fuzzing, CVE regression, secret leakage)
npm run test:e2e         # End-to-end (agent lifecycle, degradation chain)
npm run test:perf        # Performance benchmarks
```

**Test layers:** unit, integration, security, e2e, performance, contract (plugin interface validation).

## Documentation

- [Plugin Guide](docs/PLUGINS.md) -- Detailed guide for each of the 10 plugins
- [Security Architecture](docs/SECURITY.md) -- Defense-in-depth, guardrails, escalation detection
- [Threat Model](docs/THREAT_MODEL.md) -- Trust boundaries, security assumptions
- [API Reference](docs/API.md) -- Full API surface documentation

## Architecture

```
maestro-sandbox/
├── src/
│   ├── index.ts                    # Public API (45+ exports)
│   ├── config.ts                   # Presets, defineConfig(), createSecureSandbox()
│   ├── types.ts                    # Core type definitions
│   ├── factory.ts                  # createSandbox() + circuit breaker
│   ├── plugins/
│   │   ├── registry.ts             # Dynamic plugin loading
│   │   ├── isolated-vm.ts          # Tier 1: V8 isolate
│   │   ├── mock.ts                 # Tier 1: Testing
│   │   ├── anthropic-sr.ts         # Tier 2: Anthropic Secure Runtime
│   │   ├── landlock/               # Tier 2: Seatbelt/Landlock
│   │   ├── firejail.ts             # Tier 2: Firejail (V1.1)
│   │   ├── docker.ts               # Tier 3: Docker containers
│   │   ├── docker-pi.ts            # Tier 2/3: Process isolation (V1.1)
│   │   ├── e2b.ts                  # Tier 3: E2B cloud VMs
│   │   ├── microsandbox.ts         # Tier 3: libkrun VMs (V1.1)
│   │   └── openshell.ts            # Tier 3: NVIDIA OpenShell
│   ├── defense-pipeline.ts         # 4-layer defense orchestration
│   ├── guardrail-pipeline.ts       # 11 safety categories
│   ├── escalation-detector.ts      # Multi-turn attack detection
│   ├── instruction-hierarchy.ts    # 8-level privilege model
│   ├── spotlighting.ts             # Boundary token isolation
│   ├── mesh-firewall.ts            # Inter-sandbox communication
│   ├── behavioral-analyzer.ts      # 16 anomaly patterns
│   ├── taint-tracker.ts            # Data flow provenance
│   ├── task-grounding.ts           # Capability tag enforcement
│   ├── red-team.ts                 # Adversarial testing harness
│   ├── defense-model.ts            # Swiss cheese model + OWASP mapping
│   ├── host-bridge.ts              # Host function bridge
│   ├── file-access.ts              # Sandboxed file operations
│   ├── git-access.ts               # Git injection / patch export
│   ├── patch-validator.ts          # 7-rule patch validation
│   ├── audit.ts                    # Structured audit logging
│   ├── audit-otel.ts               # OpenTelemetry integration
│   ├── redact.ts                   # Secret redaction
│   ├── tenant.ts                   # Multi-tenant namespacing
│   └── __tests__/                  # 39 test files across 6 categories
└── docs/
    ├── PLUGINS.md
    ├── SECURITY.md
    ├── THREAT_MODEL.md
    └── API.md
```

## License

[Apache 2.0](LICENSE)

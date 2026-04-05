# Maestro Sandbox

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Node.js >= 22](https://img.shields.io/badge/node-%3E%3D22-brightgreen.svg)](.nvmrc)

**LLM agent sandboxing with multi-tier isolation and defense-in-depth.**

Maestro Sandbox provides a unified interface for executing untrusted code across 10 isolation backends — from in-process V8 isolates to cloud micro-VMs — with a 4-layer defense pipeline, 8-level instruction hierarchy, red team harness, and comprehensive audit logging.

## Quick Start

```bash
npm install maestro-sandbox
```

```typescript
import { createSandbox } from 'maestro-sandbox';

const sandbox = await createSandbox({
  plugin: 'isolated-vm',
  config: {
    limits: { memoryMB: 128, cpuMs: 5000, timeoutMs: 10000, networkAccess: false, filesystemAccess: 'tmpfs' },
  },
});

try {
  const result = await sandbox.execute('return 2 + 2');
  console.log(result.result); // 4
} finally {
  await sandbox.destroy();
}
```

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

**Degradation chain (default):** Docker → E2B → Landlock → Anthropic SR → isolated-vm

```typescript
import { createSandboxWithDegradation } from 'maestro-sandbox';

const sandbox = await createSandboxWithDegradation({
  config: { limits: { memoryMB: 256, cpuMs: 10000, timeoutMs: 30000, networkAccess: false, filesystemAccess: 'tmpfs' } },
  mcpMinTier: 2, // hard floor — won't fall below Tier 2
});
```

## Defense Pipeline

4 independent layers, fail-closed. A single layer veto blocks the request.

```
Input → [Operator Policy] → [Guardrail Pipeline] → [Escalation Detector] → [Spotlighting] → Output
              │                     │                       │                      │
         Privilege-based       11 safety            5 heuristic          Boundary tokens
         blocklists +          categories            detectors           on untrusted
         ReDoS protection      (pattern eval)        (multi-turn)        content
```

**Operating modes:** `normal` → `degraded` (5+ flags) → `lockdown` (3+ blocks)

```typescript
import { createDefensePipeline, createGuardrailPipeline, createEscalationDetector } from 'maestro-sandbox';

const pipeline = createDefensePipeline({
  guardrail: createGuardrailPipeline({ /* ... */ }),
  escalation: createEscalationDetector({ /* ... */ }),
});

const result = await pipeline.evaluate(message);
// result.action: 'allow' | 'block' | 'flag' | 'modify'
```

## Instruction Hierarchy

8-level privilege model — higher privilege always wins in conflicts.

```
Level 0: SYSTEM         — Hardcoded safety invariants (nothing overrides)
Level 1: OPERATOR       — Config-defined policies
Level 2: SUPERVISOR     — Human-in-the-loop overrides
Level 3: AGENT          — Primary LLM agent instructions
Level 4: TOOL_OUTPUT    — Host function return values
Level 5: PEER_AGENT     — Messages from peer sandboxes
Level 6: USER_INPUT     — End-user provided content
Level 7: INTERNET       — Internet / MCP tool descriptions (lowest trust)
```

Trust sub-levels split Level 3 into `3a` (operator-controlled), `3b` (peer-agent), `3c` (internet) for fine-grained policy enforcement.

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
| LLM09 | Overreliance | — | Out of scope |
| LLM10 | Model Theft | Guardrail, red team | Yes |

## Red Team Harness

100+ built-in attack cases across 11 categories. Run in CI to measure Attack Success Rate (ASR).

```typescript
import { createRedTeamHarness, getBuiltinCorpus, extractRegressionCases } from 'maestro-sandbox';

const harness = createRedTeamHarness({ pipeline });
const report = await harness.run(getBuiltinCorpus());

console.log(`ASR: ${report.asr}%`); // Target: <5% with full stack

// Convert findings to permanent CI tests
const regressions = extractRegressionCases(report, { bypassesOnly: true });
```

## Host Function Bridge

Sandboxed code calls host functions through a frozen, schema-validated, rate-limited bridge with SSRF prevention.

```typescript
import { z } from 'zod';

const sandbox = await createSandbox({
  plugin: 'isolated-vm',
  config: {
    limits: { memoryMB: 128, cpuMs: 5000, timeoutMs: 10000, networkAccess: false, filesystemAccess: 'tmpfs' },
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
  },
});

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
// → 'org-acme::agent-1'

sameTenant(sandboxId1, sandboxId2); // false → mesh blocked
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

- [Plugin Guide](docs/PLUGINS.md) — Detailed guide for each of the 10 plugins
- [Security Architecture](docs/SECURITY.md) — Defense-in-depth, guardrails, escalation detection
- [Threat Model](docs/THREAT_MODEL.md) — Trust boundaries, security assumptions
- [API Reference](docs/API.md) — Full API surface documentation

## Architecture

```
maestro-sandbox/
├── src/
│   ├── index.ts                    # Public API (45+ exports)
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

# Maestro Sandbox Threat Model

This document describes the trust boundaries, security assumptions, per-tier
threat analysis, and incident response plan for the `@maestro/sandbox` package.

---

## Trust Boundaries

```
+-----------------------------------------------------+
|  HOST (Maestro process -- TRUSTED)                   |
|  - Manages sandbox lifecycle                         |
|  - Applies validated patches                         |
|  - Runs host callback handlers                       |
|                                                      |
|  +-----------------------------------------------+  |
|  |  SANDBOX (UNTRUSTED)                          |  |
|  |  - Executes arbitrary code                    |  |
|  |  - Can only call allowlisted host functions   |  |
|  |  - Cannot access host filesystem/network      |  |
|  |  - All output treated as untrusted            |  |
|  +-----------------------------------------------+  |
+-----------------------------------------------------+
```

All content produced by sandboxed code is treated as untrusted at
`TOOL_OUTPUT` privilege (level 4) or lower. The host is the only entity
that can elevate privilege or grant access to external resources.

---

## Security Assumptions

### 1. Host process is the trust root

| Aspect | Detail |
|--------|--------|
| **What it means** | The Maestro host process is not itself sandboxed. It is the trusted orchestrator that creates, configures, and destroys sandbox instances. All security policy originates from the host. |
| **What breaks if violated** | A compromised host means game over -- the attacker has full access to the machine, all secrets, and all sandboxes. No sandbox defense can compensate for a compromised host. |
| **Mitigations** | Run the host with minimal OS privileges. Do not run as root. Apply standard server hardening (patched OS, firewall, minimal attack surface). Deploy behind network isolation when possible. |

### 2. Host callback allowlist is the security boundary

| Aspect | Detail |
|--------|--------|
| **What it means** | Sandboxed code can only call host functions explicitly declared in `config.hostFunctions` at creation time. The allowlist is frozen with `Object.freeze()` and cannot be modified after creation. Each function is validated with a Zod schema and rate-limited. SSRF is prevented by resolving URLs against a host-side allowlist. |
| **What breaks if violated** | If the allowlist can be mutated, sandboxed code could register arbitrary host functions, gaining access to the filesystem, network, or secrets outside its scope. |
| **Mitigations** | `Object.freeze()` on the host functions map (structural -- cannot be bypassed by prompt manipulation). Zod schema validation on every argument (structural). Per-function rate limiting prevents resource exhaustion (structural). URL allowlist prevents SSRF (structural). |

### 3. Patches are untrusted

| Aspect | Detail |
|--------|--------|
| **What it means** | Any patch or diff produced by sandboxed code is treated as hostile input. Before applying, the host MUST run all 7 validation rules. |
| **What breaks if violated** | A malicious patch could escape the workspace, overwrite host files, create symlinks to sensitive paths, inject binary payloads, or modify `.git/` internals. |
| **Mitigations** | 7 validation rules enforced by `validatePatch()`: (1) structural parse -- parse the diff format, don't blindly `git apply`; (2) path traversal -- reject `../` in all paths; (3) symlink rejection -- no symlink creation; (4) binary rejection -- no binary blobs by default; (5) workspace confinement -- all paths must resolve within workspace root; (6) git internals -- reject modifications to `.git/` directory; (7) audit log -- full patch logged for forensic review. |

### 4. Tier 1 (isolated-vm) is NOT a security boundary

| Aspect | Detail |
|--------|--------|
| **What it means** | Tier 1 uses V8 isolates (`isolated-vm`). V8's JIT compiler is a complex attack surface with a history of sandbox-escape CVEs. Tier 1 is suitable for trusted or semi-trusted code, but MUST NOT be used as the sole defense for untrusted code. |
| **What breaks if violated** | A V8 JIT exploit could escape the isolate and gain host process access. |
| **Mitigations** | `mcpMinTier: 2` is enforced for MCP servers and other untrusted code sources. The degradation chain skips Tier 1 plugins when `mcpMinTier` is set. Tier 2 (OS-level sandboxing) or Tier 3 (VM/container isolation) provide defense-in-depth against V8 exploits. |

### 5. MCP servers are untrusted

| Aspect | Detail |
|--------|--------|
| **What it means** | MCP tool descriptions are treated as `INTERNET` privilege (level 7 -- lowest trust). MCP-provided code MUST execute in Tier 2+ sandboxes. `mcpMinTier: 2` is a hard floor enforced by `createSandboxWithDegradation()`. |
| **What breaks if violated** | If MCP code runs in Tier 1 (V8 only), a poisoned MCP tool description could contain prompt injection payloads, and a V8 exploit could escape the isolate entirely. |
| **Mitigations** | `mcpMinTier` is a hard floor -- plugins below the tier are rejected, not warned. MCP tool descriptions are scanned by `createMcpScanner()` before use. Spotlighting boundary tokens isolate MCP content from instructions. |

### 6. DNS resolved on host side

| Aspect | Detail |
|--------|--------|
| **What it means** | Sandboxed code cannot perform DNS resolution directly. All DNS lookups happen on the host, where the URL allowlist is enforced. This prevents DNS tunneling as an exfiltration channel. |
| **What breaks if violated** | If sandboxes could resolve DNS directly, they could encode secrets in DNS queries (e.g., `secret-value.attacker.com`) to exfiltrate data even without network access. |
| **Mitigations** | DNS policy is `'none'` or `'restricted'` in sandbox network config. Host-side resolution against the allowlist. Tier 2+ sandboxes have network namespace isolation preventing direct DNS access. |

---

## Per-Tier Threat Analysis

| Threat | Tier 1 (V8 Isolate) | Tier 2 (OS Sandbox) | Tier 3 (VM/Container) |
|--------|---------------------|---------------------|----------------------|
| Host filesystem access | Blocked | Blocked | Blocked |
| Host network access | Blocked | Blocked | Blocked |
| Host process access | Blocked | Blocked | Blocked |
| V8 JIT exploit | **VULNERABLE** | Contained by OS sandbox | Contained by VM boundary |
| Kernel exploit | N/A (no OS access) | **VULNERABLE** | Contained by hypervisor |
| Hypervisor exploit | N/A | N/A | **VULNERABLE** |

**Tier selection guidance:**

- **Tier 1** (`isolated-vm`): Trusted code only. Fast startup, low overhead. NOT suitable as sole defense for untrusted input.
- **Tier 2** (`landlock`, `anthropic-sr`): OS-level restriction. Required minimum for MCP servers and untrusted code (`mcpMinTier: 2`).
- **Tier 3** (`docker`, `e2b`, `openshell`): Full infrastructure isolation. Recommended for production deployments handling adversarial input.

---

## Defense Model: Swiss Cheese

Every heuristic control has a structural backup. Even if ALL heuristic
controls fail simultaneously, structural controls prevent:

1. **Host process compromise** -- `sandbox-process-isolation`
2. **Cross-tenant data access** -- `sandbox-process-isolation` + `instruction-hierarchy`
3. **Arbitrary network egress** -- `url-allowlist` + `rate-limiting`
4. **Filesystem escape** -- `sandbox-process-isolation` + `zod-schema-validation`

### Structural Controls (cannot be bypassed by prompt manipulation)

| Control | Prevents |
|---------|----------|
| `sandbox-process-isolation` | Arbitrary host process access |
| `object-freeze-host-bridge` | Host bridge prototype pollution / monkey-patching |
| `zod-schema-validation` | Malformed host function arguments |
| `url-allowlist` | SSRF / arbitrary network egress |
| `rate-limiting` | Resource exhaustion / DoS |
| `instruction-hierarchy` | Lower-privilege content overriding higher-privilege instructions |
| `session-turn-limit` | Unbounded multi-turn escalation |
| `content-spotlighting` | Untrusted content confused with instructions |

### Heuristic Controls (bypassable, but each has a structural backup)

| Control | Prevents | Structural Backup |
|---------|----------|-------------------|
| `output-classifier` | Injected instructions in agent output | `url-allowlist` + `rate-limiting` |
| `call-sequence-analyzer` | Multi-step exfiltration (read-encode-send) | `url-allowlist` + `secret-redaction` |
| `code-review-scanner` | Malicious code in patches | `sandbox-process-isolation` |
| `entropy-analysis` | Encoded secrets in output | `secret-redaction` + `url-allowlist` |
| `multi-turn-detector` | Gradual escalation across turns | `session-turn-limit` |
| `guardrail-classifier` | Unsafe content (11 categories) | `sandbox-process-isolation` + `url-allowlist` + `rate-limiting` |
| `pattern-evaluator` | Known prompt injection patterns | `sandbox-process-isolation` + `url-allowlist` + `instruction-hierarchy` |

---

## Secrets Handling

Secrets follow a strict lifecycle to prevent exposure:

1. **Injected at creation** -- Passed in `config.secrets` when calling `createSandbox()`. Never written to disk.
2. **Never on disk** -- Secrets exist only in memory within the sandbox process.
3. **Redacted from logs** -- `createRedactor()` strips secret values from all `SandboxResult.logs` entries before they leave the sandbox boundary.
4. **`/proc/self/environ` blocked** -- Tier 2+ sandboxes block access to `/proc/self/environ` via seccomp/Landlock, preventing environment variable enumeration.
5. **Destroyed on `sandbox.destroy()`** -- When the sandbox is destroyed, all memory (including secrets) is released. The runtime force-kills the sandbox if `destroy()` does not complete within 5 seconds.

---

## OWASP LLM Top 10 Coverage

The defense model maps to the OWASP LLM Top 10 (2025). Each category is
covered by 2+ independent defense layers (except LLM09: Overreliance,
which is an organizational risk outside runtime scope).

| OWASP | Category | Layers | Meets 2+ Target |
|-------|----------|--------|------------------|
| LLM01 | Prompt Injection | guardrail-pipeline, instruction-hierarchy, content-spotlighting, multi-turn-detector | Yes |
| LLM02 | Insecure Output Handling | guardrail-pipeline, content-spotlighting, secret-redaction | Yes |
| LLM03 | Training Data Poisoning | guardrail-pipeline, red-team harness | Yes (runtime only) |
| LLM04 | Model Denial of Service | rate-limiting, session-turn-limit, guardrail-pipeline | Yes |
| LLM05 | Supply Chain Vulnerabilities | plugin-validator, socket.dev, Semgrep | Yes |
| LLM06 | Sensitive Information Disclosure | guardrail-pipeline, secret-redaction, taint-tracker, url-allowlist | Yes |
| LLM07 | Insecure Plugin Design | mcp-scanner, plugin-validator, host-bridge | Yes |
| LLM08 | Excessive Agency | task-grounding, trust-sub-level enforcement, requireApproval | Yes |
| LLM09 | Overreliance | -- | Out of scope |
| LLM10 | Model Theft | guardrail-pipeline, red-team harness | Yes (runtime only) |

---

## Incident Response

When a security incident is detected:

1. **Disable plugin** -- Remove the affected plugin from the degradation chain. All new sandbox creation falls through to the next available plugin.
2. **Circuit breaker fallback** -- 3 consecutive failures trip the circuit breaker (30s cooldown). The system automatically degrades to the next tier.
3. **Audit logs** -- All security events are logged with structured audit events (`breach.detected`, `guardrail.*.block`, `mesh.coercion.detected`, etc.). Review `createAuditLogger()` and `createOtelAuditLogger()` output.
4. **CVE** -- File a CVE for any sandbox escape or privilege escalation. Coordinate disclosure with affected plugin maintainers.
5. **Regression test** -- Add the attack case to the red-team corpus via `extractRegressionCases()`. Per policy: automated red-team findings above severity threshold become regression tests within 48 hours.

### Breach Signals

The system monitors 7 breach signals with automatic thresholds:

| Signal | Threshold | Window |
|--------|-----------|--------|
| `permission-error-spike` | 10 | 60s |
| `path-traversal-patch` | 1 | Immediate |
| `git-internals-patch` | 1 | Immediate |
| `ssrf-attempt` | 5 | 60s |
| `unexpected-child-process` | 1 | Immediate |
| `symlink-in-tmpdir` | 1 | Immediate |
| `circuit-breaker-repeat-trip` | 3 | 1 hour |

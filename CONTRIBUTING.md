# Contributing to Maestro Sandbox

We welcome contributions. This document covers how to get started, what's on the roadmap, and where help is needed most.

## Getting Started

```bash
git clone https://github.com/andrewdever/maestro-sandbox.git
cd maestro-sandbox
nvm use           # Node.js >= 22
npm install
npm test          # Run unit tests
npm run typecheck # Verify types
```

### Running Tests

```bash
npm test                 # Unit tests (~900+)
npm run test:integration # Integration (requires Docker for Tier 3)
npm run test:security    # Security (escape fuzzing, CVE regression)
npm run test:e2e         # End-to-end (agent lifecycle, degradation)
npm run test:perf        # Performance benchmarks
```

### Pull Request Process

1. Fork the repo and create a branch from `main`
2. Follow existing code style — run `npm run lint` before submitting
3. Add tests for new functionality
4. Plugin changes must pass the contract test suite (`__tests__/contract/plugin-contract.test.ts`)
5. Keep PRs focused — one feature or fix per PR
6. Security-sensitive changes require review from a maintainer

## Roadmap

### V1.1 — Plugin Completions & Test Hardening

Finishing the plugin matrix and closing test gaps.

**Plugins:**
- [ ] **Landlock Linux native bindings (Rust NAPI-RS)** — The `landlock` plugin currently only works on macOS (Seatbelt). Linux support requires Rust NAPI-RS native bindings for Landlock LSM + seccomp BPF. Needs Rust toolchain, cross-compilation (x86_64 + aarch64), prebuilt binary distribution, and SLSA provenance attestation.
- [ ] **Firejail plugin** — Linux process sandboxing via Firejail CLI (Tier 2)
- [ ] **Docker Process Isolation plugin** — Windows container isolation via `--isolation=process` (Tier 2/3)
- [ ] **Microsandbox plugin** — libkrun micro-VM sandboxing with <200ms startup (Tier 3)
- [ ] **Host function IPC bridge** — `hostCall()` support for Tier 2/3 plugins (currently stub — needs Unix socket or gRPC bridge)

**Redaction enhancements:**
- [ ] Recursive decoding (base64 → hex → URL-encoded) before pattern matching
- [ ] NFKC Unicode normalization to prevent homoglyph bypass
- [ ] Token-entropy analysis for detecting encoded secrets

**Testing:**
- [ ] Enable 5 skipped secret-leakage tests (`redact.test.ts`)
- [ ] Fuzz testing enforcement in CI (currently defined but not gated)
- [ ] Mutation testing enforcement (Stryker config exists but not gated)

### Security — Encryption & Cryptographic Controls

**Transport encryption:**
- [ ] **mTLS between sandboxes** — TLS 1.3 with ECDHE key exchange, AES-256-GCM, certificate pinning for mesh firewall communication
- [ ] DNS-over-HTTPS for sandbox network egress to prevent DNS poisoning
- [ ] IPv6-mapped IPv4 SSRF prevention (e.g., `::ffff:127.0.0.1` bypass)

**Code signing & integrity:**
- [ ] **Plugin code signing** — Ed25519 signatures for plugin packages, verified at load time
- [ ] Prebuilt binary provenance — SLSA attestation + cosign verification for `isolated-vm` native binaries
- [ ] Runtime integrity monitoring — detect tampering of loaded plugin code

**Secrets management:**
- [ ] **Vault integration** — HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager, 1Password Connect for injecting secrets into sandboxes without environment variables
- [ ] Symmetric encryption for secrets at rest within sandbox tmpfs
- [ ] Data-at-rest encryption for audit logs

**Audit integrity:**
- [ ] Signed audit batches with hash chains (tamper-evident audit trail)
- [ ] Merkle tree verification for audit log integrity

### Security — Defense Pipeline Improvements

**ML guardrails (replacing pattern evaluator):**
- [ ] LlamaGuard integration for content safety classification
- [ ] R2-Guard integration as alternative ML guardrail backend
- [ ] Pluggable guardrail evaluator interface (swap pattern → ML without config changes)

**Escalation detection:**
- [ ] Embedding-based semantic similarity detection (complement keyword heuristics)
- [ ] Cross-session escalation tracking (detect slow-burn attacks across sessions)

**Side channel mitigations:**
- [ ] Constant-time comparisons for security-critical paths
- [ ] Timing jitter on sandbox responses to prevent timing oracle attacks

**Penetration testing:**
- [ ] Automated pen-test framework for plugin escape testing
- [ ] CVE regression test generation from vulnerability disclosures

### Package Development — Build & Distribution

**SBOM & supply chain:**
- [ ] SBOM generation (CycloneDX format) on every release
- [ ] Dependency license audit in CI (flag GPL/AGPL transitive deps)
- [ ] `socket.dev` integration for supply chain attack detection

**CI/CD:**
- [ ] GitHub Actions workflow for test + build + publish
- [ ] Automated npm publishing on tagged releases
- [ ] Pre-commit hooks for lint + typecheck

**Observability:**
- [ ] Full OpenTelemetry integration (currently audit-otel.ts is partial)
- [ ] Grafana dashboard templates for sandbox metrics
- [ ] Structured error codes for all failure modes

### Platform & Plugin Ecosystem

- [ ] **Plugin marketplace** — registry for community-contributed sandbox plugins
- [ ] macOS Seatbelt deprecation contingency (Apple may remove `sandbox-exec`)
- [ ] Windows native sandbox plugin (beyond Docker process isolation)

### V2 — Rust Port

- [ ] Port maestro-sandbox to Rust — single binary, native sandboxing primitives, no Node.js runtime dependency

### Research & Long-Term

- [ ] Formal verification of structural controls (instruction hierarchy, mesh firewall)
- [ ] External guardrail ML model training on sandbox-specific attack patterns
- [ ] Research integration cadence — quarterly review of new sandboxing primitives (gVisor, Firecracker, etc.)

### Known Technical Debt

| Issue | Impact | Location |
|-------|--------|----------|
| Anthropic SR singleton | Only one instance per process | `anthropic-sr.ts` |
| `cpuMs` / `memoryMB` inaccurate for Tier 2/3 | Resource limits are best-effort outside V8 | `factory.ts` |
| E2B streaming is buffered | No real-time output for long-running executions | `e2b.ts` |
| `hostCall()` stub for Tier 2/3 | Host functions only work in Tier 1 (isolated-vm) | `host-bridge.ts` |

## Where to Start

Good first contributions:
- Enable the 5 skipped secret-leakage tests and fix any failures
- Add CI workflow (GitHub Actions) for test + typecheck + lint
- SBOM generation script
- Improve error messages for plugin initialization failures

Larger contributions (discuss in an issue first):
- New plugin implementations (Firejail, Microsandbox)
- Host function IPC bridge for Tier 2/3
- Vault integration
- ML guardrail evaluator

## License

By contributing, you agree that your contributions will be licensed under the [Apache 2.0 License](LICENSE).

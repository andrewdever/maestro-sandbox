# Maestro Sandbox Plugin Guide

Maestro Sandbox provides a pluggable isolation system for executing untrusted code. Plugins implement the same `SandboxPlugin` interface, enabling drop-in replacement across isolation tiers. Only the selected plugin is loaded at runtime via dynamic `import()` -- unused plugins add zero overhead.

## Table of Contents

- [Tier Model](#tier-model)
- [Plugin Reference](#plugin-reference)
  - [Tier 1: In-Process Isolation](#tier-1-in-process-isolation)
    - [isolated-vm](#isolated-vm)
    - [mock](#mock)
  - [Tier 2: OS-Level Restriction](#tier-2-os-level-restriction)
    - [anthropic-sr](#anthropic-sr)
    - [landlock](#landlock)
    - [firejail](#firejail)
  - [Tier 3: Infrastructure Isolation](#tier-3-infrastructure-isolation)
    - [docker](#docker)
    - [e2b](#e2b)
    - [openshell](#openshell)
    - [docker-pi](#docker-pi)
    - [microsandbox](#microsandbox)
- [Choosing a Plugin](#choosing-a-plugin)
- [Degradation Chain](#degradation-chain)
- [Writing a Custom Plugin](#writing-a-custom-plugin)

---

## Tier Model

Plugins are organized into three tiers based on the strength of their isolation boundary:

| Tier | Isolation Strategy | Boundary | Trade-off |
|------|--------------------|----------|-----------|
| **Tier 1** | In-process (V8 isolate) | Separate heap, shared process | Fastest startup (<1ms), weakest isolation |
| **Tier 2** | OS-level restriction (Seatbelt, Landlock, seccomp) | Kernel-enforced policy on a child process | Moderate startup (50-200ms), strong isolation |
| **Tier 3** | Infrastructure isolation (containers, micro-VMs) | Separate filesystem, PID namespace, network stack | Strongest isolation, highest startup cost (1-5s) |

**General rule:** Use the highest tier your infrastructure supports. Lower tiers start faster but provide weaker security guarantees.

### Common Behaviors (All Plugins)

Every plugin, regardless of tier:

- Creates an isolated tmpdir via `mkdtemp`, cleaned on `destroy()`
- Never writes secrets to disk (except ephemeral env files for Docker/OpenShell, deleted immediately after use)
- Enforces dual-layer timeouts: plugin-level timeout + OS/container-level timeout
- Returns exit code 137 for out-of-memory kills
- Wraps executed code via `buildScript()` for structured JSON output
- Implements the full `SandboxPlugin` interface (see [Writing a Custom Plugin](#writing-a-custom-plugin))

---

## Plugin Reference

### Tier 1: In-Process Isolation

#### isolated-vm

**Status:** Stable (Default plugin)

The default sandbox. Creates a dedicated V8 isolate via the [`isolated-vm`](https://github.com/nicolo-ribaudo/isolated-vm) npm package. Each sandbox gets its own V8 heap with no access to the host's filesystem, network, or global objects.

| Property | Value |
|----------|-------|
| Isolation level | `isolate` |
| Startup time | Sub-millisecond |
| Platform support | macOS, Linux, Windows |

**Prerequisites:**

```
npm install isolated-vm
```

**Configuration:**

```typescript
// maestro.config.ts
sandbox: {
  plugin: 'isolated-vm',
  limits: {
    memoryMB: 128,       // Enforced via V8 heap cap
    cpuMs: 5000,         // Reported but not enforced (timeout is enforced)
    timeoutMs: 10000,    // Dual timeout: V8-level for sync + Promise.race for async
    networkAccess: false,
    filesystemAccess: 'tmpfs',
  },
}
```

**Injected globals:**

- `console.log()`, `console.error()`, `console.warn()`
- `setTimeout()` polyfill
- `hostCall(name, args)` -- call registered host functions from sandbox code

**How it works:**

- A fresh V8 context is created for each execution (no variable leaking between runs)
- Cross-isolate communication uses JSON round-trip, which is lossy: `Date` becomes a string, `Map`, `Set`, `BigInt`, and `Buffer` are lost
- Host functions are supported via `Reference.applySyncPromise()`
- Timeout enforcement is dual-layered: a V8-level timeout catches synchronous infinite loops, and a host-side `Promise.race` catches runaway async work

**Limitations:**

- **Not a security boundary.** V8's JIT compiler is a complex attack surface. Do not rely on `isolated-vm` alone for untrusted code from adversarial sources. Use Tier 2+ for that.
- CPU time is reported but not enforced -- only wall-clock timeout is enforced
- No shell command execution (`shell: true` is not supported)
- JSON serialization boundary loses type fidelity

---

#### mock

**Status:** Stable (Testing only)

Executes JavaScript in the host process via `new Function()`. Provides **no real isolation** -- exists solely for fast test iteration.

| Property | Value |
|----------|-------|
| Isolation level | `isolate` (nominal) |
| Startup time | Instant |
| Platform support | All |

**Configuration:**

The mock plugin validates configuration exactly as real plugins do, making it useful for testing config parsing and validation logic.

**Capabilities:**

- Timeout enforcement via `Promise.race`
- Heap delta measurement
- Console capture (`console.log`, `console.error`, `console.warn`)
- Host function support
- tmpdir access
- Git access

**Limitations:**

- **No isolation whatsoever.** Code runs in the host process. Never use in production.
- Intended exclusively for unit tests and local development iteration

---

### Tier 2: OS-Level Restriction

#### anthropic-sr

**Status:** Stable

Wraps the [`@anthropic-ai/sandbox-runtime`](https://github.com/anthropics/sandbox-runtime) SDK. Uses Seatbelt (macOS) or Landlock + seccomp (Linux) under the hood to enforce OS-level restrictions on sandboxed processes.

| Property | Value |
|----------|-------|
| Isolation level | `process` |
| Startup time | 50-200ms |
| Platform support | macOS, Linux |

**Prerequisites:**

```
npm install @anthropic-ai/sandbox-runtime
```

Requires macOS or Linux. Not available on Windows.

**Configuration:**

```typescript
sandbox: {
  plugin: 'anthropic-sr',
  limits: { /* ... */ },
  network: {
    allowedPeers: ['api.openai.com:443', 'db.example.com:5432'],
  },
  secrets: {
    API_KEY: process.env.API_KEY!,
  },
}
```

**How it works:**

- Uses a global singleton `SandboxManager` shared across all sandbox instances
- Network access is controlled via a domain allowlist from `config.network.allowedPeers`
- Filesystem writes are restricted to the sandbox tmpdir
- Secrets are passed via a restrictive env object (never written to disk)

**Limitations:**

- Host functions are **not supported** in V1
- Depends on a vendor SDK (`@anthropic-ai/sandbox-runtime`)

---

#### landlock

**Status:** Stable on macOS, Linux stub

Maestro's own OS-level sandbox implementation with no vendor dependencies.

| Property | Value |
|----------|-------|
| Isolation level | `process` |
| Startup time | 50-200ms |
| Platform support | macOS (full), Linux (stub -- Rust NAPI-RS bindings planned for V1.1) |

**Prerequisites:**

- macOS: No additional dependencies (uses built-in `sandbox-exec` and Seatbelt profiles)
- Linux: Kernel 5.13+ required (Landlock support). Full implementation coming in V1.1.

**How it works (macOS):**

The macOS implementation generates a Seatbelt profile with `allow-default` plus targeted deny rules:

- **Blocked writes:** `/Users`, `/home`, `/etc`, `/var/root`, `/opt`, `/usr/local`, `/Library`
- **Allowed writes:** Sandbox tmpdir only
- **Blocked reads:** `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.env`
- **Blocked process spawning:** All system binaries except `/usr/bin/env` and the Node.js binary
- **Path sanitization:** Rejects paths containing quotes, backslashes, or control characters

**Sub-modules:**

- `landlock-profile.ts` -- Linux Landlock rules (kernel 5.13+)
- `seccomp-profile.ts` -- BPF syscall allowlists for x86_64 and aarch64

**Limitations:**

- Host functions are **not supported** in V1
- Linux implementation is a stub in V1 (returns an error directing users to `anthropic-sr` or `docker`)

---

#### firejail

**Status:** V1.1 -- Not Yet Implemented

Planned Firejail-based sandbox for Linux systems.

| Property | Value |
|----------|-------|
| Isolation level | `process` |
| Platform support | Linux only |

Will provide process-level isolation via the [Firejail](https://firejail.wordpress.com/) security sandbox.

---

### Tier 3: Infrastructure Isolation

#### docker

**Status:** Stable

Runs code inside ephemeral Docker containers that persist for the session lifetime.

| Property | Value |
|----------|-------|
| Isolation level | `container` |
| Startup time | 1-3s |
| Platform support | Any platform with Docker |

**Prerequisites:**

- Docker daemon running locally

**Configuration:**

```typescript
sandbox: {
  plugin: 'docker',
  limits: {
    memoryMB: 256,
    timeoutMs: 30000,
    networkAccess: false,
    filesystemAccess: 'tmpfs',
  },
  secrets: {
    DB_URL: process.env.DB_URL!,
  },
}
```

**Container hardening:**

| Flag | Purpose |
|------|---------|
| `--memory` | Memory cap from `limits.memoryMB` |
| `--pids-limit 64` | Prevent fork bombs |
| `--read-only` | Immutable root filesystem |
| `--tmpfs /sandbox:rw,nosuid,size=256m` | Writable workspace |
| `--tmpfs /tmp:rw,noexec,nosuid,size=64m` | Temp space (no exec) |
| `--cap-drop ALL` | Drop all Linux capabilities |
| `--security-opt no-new-privileges` | Prevent privilege escalation |
| `--network none` | No network by default |

**Image:** `node:22-slim`

**Secret handling:** Secrets are written to a temporary env file (`chmod 600`), passed to the container via `--env-file`, and deleted immediately after container creation.

**Code execution:** Scripts are written via stdin to avoid shell injection vulnerabilities. File access uses `docker exec`. Git access uses tarball copy + extraction.

**Limitations:**

- Host functions are **not supported** in V1
- Requires Docker to be installed and running
- Higher startup latency than Tier 1/2

---

#### e2b

**Status:** Stable

Cloud-hosted micro-VMs via the [E2B](https://e2b.dev) platform. Each sandbox runs in its own micro-VM with SOC2/HIPAA compliance.

| Property | Value |
|----------|-------|
| Isolation level | `microvm` |
| Startup time | 2-5s |
| Platform support | Any (cloud-hosted) |

**Prerequisites:**

```
npm install e2b
```

Set the `E2B_API_KEY` environment variable:

```bash
# .env.local
E2B_API_KEY=your-api-key-here
```

**Configuration:**

```typescript
sandbox: {
  plugin: 'e2b',
  limits: {
    memoryMB: 512,
    timeoutMs: 60000,
    networkAccess: true,
    filesystemAccess: 'tmpfs',
  },
}
```

**How it works:**

- Each sandbox gets its own micro-VM
- Sandbox lifetime is calculated as `max(timeoutMs * 5, 300000)` (at least 5 minutes)
- File operations use the E2B files API
- Git access uses tarball injection (same pattern as Docker)

**Limitations:**

- Host functions are **not supported** in V1
- Requires an E2B account and API key
- Network latency to the cloud adds to execution time
- Incurs per-usage cost from E2B

---

#### openshell

**Status:** Stable

NVIDIA OpenShell provides K3s-in-Docker with a 4-layer policy engine for strong infrastructure-level isolation.

| Property | Value |
|----------|-------|
| Isolation level | `container` |
| Startup time | 2-5s |
| Platform support | macOS, Linux (requires Docker) |
| Max idle memory | <512MB |

**Prerequisites:**

- `openshell` CLI binary (version 0.4.0, pinned)
- Docker daemon running

**How it works:**

OpenShell generates a 4-layer policy:

1. **Filesystem policy:** Read-only root, tmpfs mounts for writable paths
2. **Network policy:** Egress filtered or disabled, `allowedHosts` allowlist, DNS policy enforcement
3. **Process policy:** `cap-drop ALL`, seccomp strict mode, PID limit of 64, `no-new-privileges`
4. **Inference policy:** Privacy router, credential stripping

The policy is serialized to YAML and applied to a K3s pod running inside Docker.

**Exports:**

- `buildPolicy()` -- generate a policy object from sandbox config
- `policyToYaml()` -- serialize to YAML for OpenShell CLI
- `OPENSHELL_VERSION` -- pinned version constant (`0.4.0`)

**Feature flag:** OpenShell must be explicitly enabled in configuration. Shadow mode (logging policy violations without enforcing) is recommended before graduating to full enforcement.

**Limitations:**

- Host functions are **not supported** in V1
- Requires both Docker and the OpenShell CLI binary
- Version-pinned to 0.4.0 -- updates require testing the new policy engine

---

#### docker-pi

**Status:** V1.1 -- Not Yet Implemented

Planned Docker process isolation mode for Windows.

| Property | Value |
|----------|-------|
| Isolation level | `container` |
| Platform support | Windows |

---

#### microsandbox

**Status:** V1.1 -- Not Yet Implemented

Planned lightweight micro-VM sandbox using [libkrun](https://github.com/nicolo-ribaudo/libkrun).

| Property | Value |
|----------|-------|
| Isolation level | `microvm` |
| Startup time | Sub-200ms (target) |
| Platform support | Cross-platform |

Aims to combine Tier 3 isolation strength with Tier 1 startup speed.

---

## Choosing a Plugin

### Decision Matrix

| Scenario | Recommended Plugin | Why |
|----------|--------------------|-----|
| **Local development / testing** | `mock` or `isolated-vm` | Fast iteration, no dependencies |
| **Running your own LLM agents** | `isolated-vm` | Fast, low overhead, sufficient for trusted code |
| **Running user-submitted code** | `docker` or `anthropic-sr` | Real isolation boundary needed |
| **Multi-tenant SaaS** | `e2b` or `docker` | Infrastructure isolation, compliance guarantees |
| **CI/CD pipelines** | `docker` | Reproducible, no host-level dependencies |
| **GPU workloads with policy** | `openshell` | NVIDIA integration, 4-layer policy engine |
| **macOS without Docker** | `landlock` or `anthropic-sr` | OS-level restrictions without containers |
| **Windows** | `isolated-vm` (V1), `docker-pi` (V1.1) | Limited options until docker-pi ships |

### Feature Comparison

| Feature | isolated-vm | mock | anthropic-sr | landlock | docker | e2b | openshell |
|---------|:-----------:|:----:|:------------:|:--------:|:------:|:---:|:---------:|
| Host functions | Yes | Yes | No | No | No | No | No |
| Shell execution | No | No | Yes | Yes | Yes | Yes | Yes |
| Network control | N/A | N/A | Allowlist | Deny | None/custom | Yes | Allowlist |
| Secrets handling | In-memory | In-memory | Env object | N/A | Temp env file | Env | Temp env file |
| Security boundary | No | No | Yes | Yes | Yes | Yes | Yes |
| Cloud-hosted | No | No | No | No | No | Yes | No |

### When to Upgrade Tiers

Move from Tier 1 to Tier 2+ when:

- You are executing code from untrusted or semi-trusted sources
- Compliance requirements mandate OS-level or infrastructure-level isolation
- You need network access control (allowlists, egress filtering)
- You need shell command execution (Python, system tools, etc.)

Move from Tier 2 to Tier 3 when:

- You need full filesystem isolation (not just policy-based restrictions)
- You are running multi-tenant workloads
- You need reproducible environments (container images)
- Compliance requires infrastructure-level boundaries (SOC2, HIPAA)

---

## Degradation Chain

When the configured plugin is unavailable (missing binary, failed health check, or circuit breaker tripped), the sandbox factory automatically falls back through the degradation chain:

```
Docker (T3) --> E2B (T3) --> Landlock (T2) --> Anthropic SR (T2) --> isolated-vm (T1)
```

### How It Works

1. The factory attempts to create a sandbox with the configured plugin
2. If creation fails, it tries the next plugin in the chain
3. Each plugin in the chain is protected by a circuit breaker: 3 consecutive failures trip the breaker, which stays open for 30 seconds before a half-open retry
4. If the fallback crosses below the configured `mcpMinTier`, the system logs a loud warning (the sandbox still runs, but the operator is alerted to the degradation)

### Circuit Breaker States

| State | Behavior |
|-------|----------|
| **Closed** | Normal operation. Failures are counted. |
| **Open** | Plugin is bypassed. No creation attempts for `cooldownMs` (default: 30s). |
| **Half-open** | One trial request is allowed. Success closes the breaker; failure re-opens it. |

### Customizing the Chain

The degradation chain order can be customized in `maestro.config.ts`. Only list plugins that are actually available in your environment -- the factory skips unavailable ones automatically, but explicit configuration avoids unnecessary failure/retry cycles.

---

## Writing a Custom Plugin

All plugins implement the `SandboxPlugin` interface. Here is how to build one from scratch.

### Step 1: Implement the SandboxPlugin Interface

```typescript
import type { SandboxPlugin, SandboxConfig, Sandbox } from '@maestro/sandbox';

const myPlugin: SandboxPlugin = {
  name: 'my-plugin',
  version: '1.0.0',
  requiredCoreVersion: '>=1.0.0 <2.0.0',
  isolationLevel: 'process', // 'isolate' | 'process' | 'container' | 'microvm'

  async create(config: SandboxConfig): Promise<Sandbox> {
    // 1. Validate config
    // 2. Set up isolation (spawn process, start container, etc.)
    // 3. Create tmpdir via mkdtemp
    // 4. Return a Sandbox instance
    return {
      async execute(code, options) {
        // Execute code within your isolation boundary.
        // Return a SandboxResult with success, result, logs, and metrics.
      },

      async *executeStream(code, options) {
        // Yield SandboxChunk objects for streaming output.
      },

      fs: {
        async read(path)  { /* Read file from sandbox tmpdir */ },
        async write(path, content) { /* Write file to sandbox tmpdir */ },
        async list(dir)   { /* List files in sandbox tmpdir */ },
      },

      git: {
        async inject(source)      { /* Inject tarball/bundle into sandbox */ },
        async exportPatch()       { /* Export git diff as patch string */ },
        async exportFiles(paths)  { /* Export files as tarball buffer */ },
      },

      async ready() {
        // Return true when the sandbox is ready to execute code.
        return true;
      },

      async destroy() {
        // Clean up: remove tmpdir, kill processes, stop containers.
        // This MUST be safe to call multiple times.
      },
    };
  },
};

export default myPlugin;
```

### Step 2: Register the Plugin

Add your plugin to the registry in `src/plugins/registry.ts`:

```typescript
export const PLUGINS: PluginRegistry = {
  // ... existing plugins ...
  'my-plugin': () => import('./my-plugin.js'),
};
```

The registry uses dynamic `import()` so your plugin is only loaded when selected.

### Step 3: Pass the Contract Tests

Run the contract test suite against your plugin:

```bash
SANDBOX_PLUGIN=my-plugin pnpm test -- __tests__/contract/plugin-contract.test.ts
```

The contract tests verify that your plugin correctly:

- Enforces timeouts (sync and async)
- Enforces memory limits
- Captures console output
- Returns structured `SandboxResult` objects
- Cleans up resources on `destroy()`
- Handles concurrent executions
- Reports accurate metrics

### Step 4: Handle Errors Correctly

Use the typed error classes for all failure modes:

```typescript
import {
  SandboxTimeoutError,  // Wall-clock timeout exceeded
  SandboxOOMError,      // Memory limit exceeded (exit code 137)
  SandboxPermissionError, // Attempted a blocked operation
  SandboxCrashError,    // Process crashed unexpectedly
} from '@maestro/sandbox';
```

### Implementation Checklist

- [ ] `create()` returns a fully functional `Sandbox` instance
- [ ] tmpdir is created via `mkdtemp` and cleaned on `destroy()`
- [ ] Secrets are never written to disk (or are deleted immediately if unavoidable)
- [ ] Timeout is enforced at two layers (plugin-level + isolation-level)
- [ ] OOM kills result in `SandboxOOMError` (detect exit code 137)
- [ ] `destroy()` is idempotent and always cleans up (no leaked processes or files)
- [ ] Console output is captured and returned in `SandboxResult.logs`
- [ ] All contract tests pass
- [ ] Plugin is registered in `src/plugins/registry.ts`

---

## Key Interfaces

For complete type definitions, see [`src/types.ts`](../src/types.ts). The most important types:

| Interface | Purpose |
|-----------|---------|
| `SandboxPlugin` | Plugin entry point: `name`, `version`, `isolationLevel`, `create()` |
| `SandboxConfig` | Creation config: `limits`, `permissions`, `secrets`, `network`, `hostFunctions` |
| `Sandbox` | Running instance: `execute()`, `executeStream()`, `fs`, `git`, `ready()`, `destroy()` |
| `SandboxResult` | Execution output: `success`, `result`, `error`, `logs`, `metrics` |
| `SandboxLimits` | Resource caps: `memoryMB`, `cpuMs`, `timeoutMs`, `networkAccess`, `filesystemAccess` |
| `HostFunction` | Host callback bridge: `handler`, `schema` (Zod), `rateLimit`, `timeoutMs` |

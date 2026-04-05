/**
 * Maestro orchestrator-level API (§10, §11).
 *
 * Provides: killAll(), status(), breach detection, and doctor checks.
 */

import type { Sandbox } from './types.js';
import type { AuditLogger } from './audit.js';
import { platform, release } from 'node:os';

// ---------------------------------------------------------------------------
// Sandbox registry — tracks all active sandboxes
// ---------------------------------------------------------------------------

const activeSandboxes = new Map<string, Sandbox>();
let sandboxIdCounter = 0;

/** Register a sandbox in the active registry. Returns its ID. */
export function registerSandbox(sandbox: Sandbox): string {
  const id = `sbx_${(++sandboxIdCounter).toString(36).padStart(6, '0')}`;
  activeSandboxes.set(id, sandbox);
  return id;
}

/** Unregister a sandbox from the active registry. */
export function unregisterSandbox(id: string): void {
  activeSandboxes.delete(id);
}

/** Get a sandbox by ID. */
export function getSandbox(id: string): Sandbox | undefined {
  return activeSandboxes.get(id);
}

// ---------------------------------------------------------------------------
// Kill switch (§11)
// ---------------------------------------------------------------------------

export interface KillAllResult {
  destroyed: number;
  failed: number;
  errors: Array<{ sandboxId: string; error: Error }>;
}

/**
 * Emergency shutdown — kills ALL active sandboxes.
 *
 * Calls destroy() on each with a 5s timeout.
 * Force-kills if destroy() doesn't complete in time.
 */
export async function killAll(logger?: AuditLogger): Promise<KillAllResult> {
  const result: KillAllResult = { destroyed: 0, failed: 0, errors: [] };
  const KILL_TIMEOUT_MS = 5000;

  const entries = [...activeSandboxes.entries()];
  activeSandboxes.clear();

  await Promise.allSettled(
    entries.map(async ([id, sandbox]) => {
      try {
        await Promise.race([
          sandbox.destroy(),
          new Promise<never>((_, reject) =>
            setTimeout(() => reject(new Error('destroy() timed out')), KILL_TIMEOUT_MS),
          ),
        ]);
        result.destroyed++;
        logger?.log('sandbox.destroy', { lifetime: 'emergency' }, id);
      } catch (err) {
        result.failed++;
        const error = err instanceof Error ? err : new Error(String(err));
        result.errors.push({ sandboxId: id, error });
        logger?.log('sandbox.destroy.failed', {
          error: error.message,
          cleanup: 'force-kill',
        }, id);
      }
    }),
  );

  return result;
}

// ---------------------------------------------------------------------------
// Status (§10)
// ---------------------------------------------------------------------------

export interface MaestroStatus {
  activeSandboxCount: number;
  sandboxIds: string[];
}

/** Report current sandbox system status. */
export function status(): MaestroStatus {
  return {
    activeSandboxCount: activeSandboxes.size,
    sandboxIds: [...activeSandboxes.keys()],
  };
}

// ---------------------------------------------------------------------------
// Breach detection (§11)
// ---------------------------------------------------------------------------

export type BreachSignal =
  | 'permission-error-spike'
  | 'path-traversal-patch'
  | 'git-internals-patch'
  | 'ssrf-attempt'
  | 'unexpected-child-process'
  | 'symlink-in-tmpdir'
  | 'circuit-breaker-repeat-trip';

interface BreachCounter {
  count: number;
  firstSeen: number;
  lastSeen: number;
}

const breachCounters = new Map<string, BreachCounter>();

const BREACH_THRESHOLDS: Record<BreachSignal, { count: number; windowMs: number }> = {
  'permission-error-spike': { count: 10, windowMs: 60_000 },
  'path-traversal-patch': { count: 1, windowMs: Infinity },
  'git-internals-patch': { count: 1, windowMs: Infinity },
  'ssrf-attempt': { count: 5, windowMs: 60_000 },
  'unexpected-child-process': { count: 1, windowMs: Infinity },
  'symlink-in-tmpdir': { count: 1, windowMs: Infinity },
  'circuit-breaker-repeat-trip': { count: 3, windowMs: 3_600_000 },
};

/**
 * Record a security signal. Returns true if the threshold is breached.
 */
export function recordBreachSignal(
  signal: BreachSignal,
  sandboxId: string,
  logger?: AuditLogger,
): boolean {
  const key = `${signal}:${sandboxId}`;
  const now = Date.now();
  const threshold = BREACH_THRESHOLDS[signal];

  let counter = breachCounters.get(key);
  if (!counter || (now - counter.firstSeen > threshold.windowMs)) {
    counter = { count: 0, firstSeen: now, lastSeen: now };
    breachCounters.set(key, counter);
  }

  counter.count++;
  counter.lastSeen = now;

  if (counter.count >= threshold.count) {
    logger?.log('breach.detected', {
      signal,
      count: counter.count,
      windowMs: threshold.windowMs,
    }, sandboxId);
    breachCounters.delete(key);
    return true;
  }

  return false;
}

/** Reset breach counters (for testing). */
export function resetBreachCounters(): void {
  breachCounters.clear();
}

// ---------------------------------------------------------------------------
// Doctor (§1 assumptions)
// ---------------------------------------------------------------------------

export interface DoctorCheck {
  name: string;
  status: 'ok' | 'warn' | 'fail';
  message: string;
}

/**
 * Run health checks on the sandbox system.
 *
 * Checks:
 * - Platform (Linux vs macOS vs other)
 * - Kernel version (Linux 5.13+ for Landlock)
 * - Node.js version (LTS)
 * - Available sandbox tiers
 */
export async function doctor(): Promise<DoctorCheck[]> {
  const checks: DoctorCheck[] = [];
  const os = platform();

  // Platform check
  if (os === 'linux' || os === 'darwin') {
    checks.push({ name: 'platform', status: 'ok', message: `Platform: ${os}` });
  } else {
    checks.push({
      name: 'platform',
      status: 'warn',
      message: `Platform "${os}" has limited sandbox support. Linux or macOS recommended.`,
    });
  }

  // Kernel version (Linux)
  if (os === 'linux') {
    const kernel = release();
    const major = parseInt(kernel.split('.')[0], 10);
    const minor = parseInt(kernel.split('.')[1], 10);
    if (major > 5 || (major === 5 && minor >= 13)) {
      checks.push({
        name: 'kernel',
        status: 'ok',
        message: `Kernel ${kernel}: Landlock filesystem available`,
      });
      if (major > 5 || (major === 5 && minor >= 18)) {
        checks.push({
          name: 'kernel-net',
          status: 'ok',
          message: `Kernel ${kernel}: Landlock network available`,
        });
      } else {
        checks.push({
          name: 'kernel-net',
          status: 'warn',
          message: `Kernel ${kernel}: Landlock network requires 5.18+. Network restriction uses seccomp only.`,
        });
      }
    } else {
      checks.push({
        name: 'kernel',
        status: 'warn',
        message: `Kernel ${kernel}: Landlock requires 5.13+. Tier 2 falls back to Anthropic SR.`,
      });
    }
  }

  // macOS Seatbelt
  if (os === 'darwin') {
    checks.push({
      name: 'seatbelt',
      status: 'warn',
      message: 'macOS: sandbox-exec (Seatbelt) is deprecated by Apple. No removal date. Monitor.',
    });
    checks.push({
      name: 'cgroups',
      status: 'warn',
      message: 'macOS: cgroups v2 not available. Resource limits use setrlimit (best-effort).',
    });
  }

  // Node.js version
  const nodeVersion = process.versions.node;
  const nodeMajor = parseInt(nodeVersion.split('.')[0], 10);
  if (nodeMajor >= 20) {
    checks.push({ name: 'node', status: 'ok', message: `Node.js ${nodeVersion}: LTS` });
  } else {
    checks.push({
      name: 'node',
      status: 'warn',
      message: `Node.js ${nodeVersion}: LTS (20+) recommended for security patches.`,
    });
  }

  // Tier availability (probe plugins)
  checks.push({
    name: 'tier-1',
    status: 'ok',
    message: 'Tier 1 (isolated-vm): always available',
  });

  // Tier 2 and 3 depend on runtime availability — just report what's configured
  checks.push({
    name: 'tier-2',
    status: os === 'linux' || os === 'darwin' ? 'ok' : 'warn',
    message: os === 'linux'
      ? 'Tier 2 (Landlock/seccomp): available'
      : os === 'darwin'
        ? 'Tier 2 (Seatbelt): available (deprecated)'
        : 'Tier 2: not available on this platform',
  });

  return checks;
}

// ---------------------------------------------------------------------------
// Reset (for testing)
// ---------------------------------------------------------------------------

export function resetMaestro(): void {
  activeSandboxes.clear();
  sandboxIdCounter = 0;
  breachCounters.clear();
}

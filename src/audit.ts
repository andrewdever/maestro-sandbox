/**
 * Structured audit event logger (§6).
 *
 * V1: JSON logs to stdout/stderr.
 * V2: OTel spans.
 */

import { createHash } from 'node:crypto';

// ---------------------------------------------------------------------------
// Event types
// ---------------------------------------------------------------------------

export type AuditSeverity = 'DEBUG' | 'INFO' | 'WARN' | 'ERROR' | 'CRITICAL';

export type AuditEventType =
  | 'sandbox.create'
  | 'sandbox.create.failed'
  | 'sandbox.execute'
  | 'sandbox.execute.result'
  | 'sandbox.execute.timeout'
  | 'sandbox.execute.oom'
  | 'sandbox.destroy'
  | 'sandbox.destroy.failed'
  | 'cleanup.tmpdir.failed'
  | 'hostbridge.call'
  | 'hostbridge.call.rejected'
  | 'hostbridge.call.error'
  | 'patch.validate'
  | 'patch.validate.rejected'
  | 'patch.apply'
  | 'plugin.load'
  | 'plugin.load.failed'
  | 'plugin.degradation'
  | 'degradation.below-mcp-min'
  | 'circuit-breaker.trip'
  | 'circuit-breaker.reset'
  | 'secret.redacted'
  | 'cleanup.orphan'
  | 'breach.detected'
  // V2 security events (§14)
  | 'guardrail.input.block'
  | 'guardrail.input.flag'
  | 'guardrail.input.modify'
  | 'guardrail.output.block'
  | 'guardrail.output.flag'
  | 'guardrail.output.modify'
  | 'guardrail.toolcall.block'
  | 'guardrail.toolcall.flag'
  | 'guardrail.toolcall.modify'
  | 'escalation.detected'
  | 'escalation.session-reset'
  | 'mesh.message.blocked'
  | 'mesh.coercion.detected'
  | 'behavioral.anomaly'
  | 'behavioral.quarantine'
  | 'defense.pipeline.blocked'
  | 'defense.mode.changed'
  | 'model.version.changed'
  | 'redteam.attack.succeeded'
  | 'taint.exfiltration.detected'
  | 'grounding.violation'
  | 'grounding.blocked';

export interface AuditEvent {
  timestamp: string;
  level: AuditSeverity;
  event: AuditEventType;
  sandboxId?: string;
  /** Optional tenant ID for multi-tenant isolation (§5). */
  tenantId?: string;
  data: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Severity mapping
// ---------------------------------------------------------------------------

const EVENT_SEVERITY: Record<AuditEventType, AuditSeverity> = {
  'sandbox.create': 'INFO',
  'sandbox.create.failed': 'ERROR',
  'sandbox.execute': 'INFO',
  'sandbox.execute.result': 'INFO',
  'sandbox.execute.timeout': 'WARN',
  'sandbox.execute.oom': 'WARN',
  'sandbox.destroy': 'INFO',
  'sandbox.destroy.failed': 'ERROR',
  'cleanup.tmpdir.failed': 'CRITICAL',
  'hostbridge.call': 'INFO',
  'hostbridge.call.rejected': 'WARN',
  'hostbridge.call.error': 'ERROR',
  'patch.validate': 'INFO',
  'patch.validate.rejected': 'WARN',
  'patch.apply': 'INFO',
  'plugin.load': 'INFO',
  'plugin.load.failed': 'ERROR',
  'plugin.degradation': 'WARN',
  'degradation.below-mcp-min': 'CRITICAL',
  'circuit-breaker.trip': 'WARN',
  'circuit-breaker.reset': 'INFO',
  'secret.redacted': 'DEBUG',
  'cleanup.orphan': 'WARN',
  'breach.detected': 'CRITICAL',
  // V2 security events (§14)
  'guardrail.input.block': 'WARN',
  'guardrail.input.flag': 'INFO',
  'guardrail.input.modify': 'INFO',
  'guardrail.output.block': 'WARN',
  'guardrail.output.flag': 'INFO',
  'guardrail.output.modify': 'INFO',
  'guardrail.toolcall.block': 'WARN',
  'guardrail.toolcall.flag': 'INFO',
  'guardrail.toolcall.modify': 'INFO',
  'escalation.detected': 'WARN',
  'escalation.session-reset': 'CRITICAL',
  'mesh.message.blocked': 'WARN',
  'mesh.coercion.detected': 'CRITICAL',
  'behavioral.anomaly': 'WARN',
  'behavioral.quarantine': 'CRITICAL',
  'defense.pipeline.blocked': 'WARN',
  'defense.mode.changed': 'WARN',
  'model.version.changed': 'WARN',
  'redteam.attack.succeeded': 'CRITICAL',
  'taint.exfiltration.detected': 'CRITICAL',
  'grounding.violation': 'WARN',
  'grounding.blocked': 'WARN',
};

// ---------------------------------------------------------------------------
// Audit logger
// ---------------------------------------------------------------------------

export interface AuditLogger {
  /** Emit a structured audit event. */
  log(event: AuditEventType, data: Record<string, unknown>, sandboxId?: string): void;

  /** Get all recorded events (for testing / in-memory mode). */
  readonly events: readonly AuditEvent[];
}

export interface AuditLoggerOptions {
  /** Write to stdout/stderr. Default: true. */
  emit?: boolean;
  /** Also store in memory (for testing). Default: false. */
  store?: boolean;
}

/**
 * Create an audit logger.
 *
 * V1: writes JSON to stdout (INFO/DEBUG) or stderr (WARN/ERROR/CRITICAL).
 * Options allow in-memory storage for testing.
 */
export function createAuditLogger(options: AuditLoggerOptions = {}): AuditLogger {
  const { emit = true, store = false } = options;
  const stored: AuditEvent[] = [];

  return {
    log(event: AuditEventType, data: Record<string, unknown>, sandboxId?: string): void {
      const level = EVENT_SEVERITY[event];
      const entry: AuditEvent = {
        timestamp: new Date().toISOString(),
        level,
        event,
        ...(sandboxId ? { sandboxId } : {}),
        data,
      };

      if (store) {
        stored.push(entry);
      }

      if (emit) {
        const json = JSON.stringify(entry);
        if (level === 'INFO' || level === 'DEBUG') {
          process.stdout.write(json + '\n');
        } else {
          process.stderr.write(json + '\n');
        }
      }
    },

    get events(): readonly AuditEvent[] {
      return stored;
    },
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** SHA-256 hash of a string (for logging code/patch hashes, not raw content). */
export function sha256(input: string): string {
  return createHash('sha256').update(input, 'utf-8').digest('hex');
}

/**
 * OpenTelemetry Audit Integration (§6).
 *
 * Thin adapter that wraps the existing audit logger and emits
 * OTel spans for each audit event. Consumers provide their own
 * tracer — we do NOT import @opentelemetry packages directly.
 *
 * Severity mapping:
 *   CRITICAL / ERROR  → OTel SpanStatusCode.ERROR (2)
 *   WARN              → OTel SpanStatusCode.UNSET (0)
 *   INFO / DEBUG       → OTel SpanStatusCode.OK (1)
 *
 * Reference: OpenTelemetry Trace Specification
 */

import { createAuditLogger, type AuditLogger, type AuditLoggerOptions, type AuditEventType, type AuditSeverity } from './audit.js';

// ---------------------------------------------------------------------------
// OTel Interface (consumer-provided)
// ---------------------------------------------------------------------------

/**
 * Minimal OTel tracer interface.
 * Consumers pass in their own OTel tracer that satisfies this shape.
 * We do NOT depend on @opentelemetry packages.
 */
export interface OtelTracer {
  /** Start a new span with the given name and optional attributes. */
  startSpan(name: string, options?: { attributes?: Record<string, string | number | boolean> }): OtelSpan;
}

/** Minimal OTel span interface. */
export interface OtelSpan {
  /** Set the span status. */
  setStatus(status: { code: number; message?: string }): void;

  /** End the span. */
  end(): void;
}

// ---------------------------------------------------------------------------
// OTel Span Status Codes
// ---------------------------------------------------------------------------

/** OTel SpanStatusCode values. */
export const OtelSpanStatusCode = {
  /** The default status. */
  UNSET: 0,
  /** The operation completed successfully. */
  OK: 1,
  /** The operation contained an error. */
  ERROR: 2,
} as const;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/** Options for the OTel-aware audit logger. */
export interface OtelAuditLoggerOptions extends AuditLoggerOptions {
  /** OTel tracer instance. If not provided, OTel spans are not emitted. */
  tracer?: OtelTracer;

  /** Service name for OTel attributes. Default: 'maestro-sandbox'. */
  serviceName?: string;
}

// ---------------------------------------------------------------------------
// Severity → OTel Status Mapping
// ---------------------------------------------------------------------------

/**
 * Map audit severity to OTel span status code.
 *
 * CRITICAL / ERROR → ERROR (2)
 * WARN             → UNSET (0)
 * INFO / DEBUG     → OK (1)
 */
function severityToOtelStatus(severity: AuditSeverity): { code: number; message?: string } {
  switch (severity) {
    case 'CRITICAL':
    case 'ERROR':
      return { code: OtelSpanStatusCode.ERROR, message: severity };
    case 'WARN':
      return { code: OtelSpanStatusCode.UNSET };
    case 'INFO':
    case 'DEBUG':
      return { code: OtelSpanStatusCode.OK };
  }
}

// ---------------------------------------------------------------------------
// Severity Lookup (duplicated from audit.ts to avoid re-exporting internals)
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
// Factory
// ---------------------------------------------------------------------------

/**
 * Create an OTel-aware audit logger.
 *
 * Wraps the base audit logger. When a tracer is provided, each
 * audit event also emits an OTel span with event data as attributes
 * and severity mapped to span status.
 */
export function createOtelAuditLogger(options: OtelAuditLoggerOptions = {}): AuditLogger {
  const { tracer, serviceName = 'maestro-sandbox', ...baseOptions } = options;
  const baseLogger = createAuditLogger(baseOptions);

  if (!tracer) {
    // No tracer — just return the base logger
    return baseLogger;
  }

  return {
    log(event: AuditEventType, data: Record<string, unknown>, sandboxId?: string): void {
      // 1. Delegate to the base logger (JSON stdout/stderr + optional memory store)
      baseLogger.log(event, data, sandboxId);

      // 2. Emit OTel span
      const severity = EVENT_SEVERITY[event];
      const attributes: Record<string, string | number | boolean> = {
        'maestro.service': serviceName,
        'maestro.event': event,
        'maestro.severity': severity,
      };

      if (sandboxId) {
        attributes['maestro.sandbox_id'] = sandboxId;
      }

      // Flatten data into attributes (only primitive values, sanitized keys)
      for (const [key, value] of Object.entries(data)) {
        if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
          // Sanitize key: only allow alphanumeric, dots, underscores, hyphens.
          // Prevents attribute injection (e.g., keys like "trace_id" overwriting OTel internals).
          const sanitizedKey = key.replace(/[^a-zA-Z0-9._-]/g, '_');
          attributes[`maestro.data.${sanitizedKey}`] = value;
        }
      }

      const span = tracer.startSpan(`audit.${event}`, { attributes });
      span.setStatus(severityToOtelStatus(severity));
      span.end();
    },

    get events() {
      return baseLogger.events;
    },
  };
}

import { describe, it, expect, vi } from 'vitest';
import {
  createOtelAuditLogger,
  OtelSpanStatusCode,
  type OtelTracer,
  type OtelSpan,
} from '../../audit-otel.js';

describe('OtelAuditLogger', () => {
  function createMockTracer() {
    const spans: Array<{
      name: string;
      attributes: Record<string, string | number | boolean>;
      status: { code: number; message?: string };
      ended: boolean;
    }> = [];

    const tracer: OtelTracer = {
      startSpan(name, options) {
        const record = {
          name,
          attributes: options?.attributes ?? {},
          status: { code: OtelSpanStatusCode.UNSET } as { code: number; message?: string },
          ended: false,
        };
        spans.push(record);

        const span: OtelSpan = {
          setStatus(status) {
            record.status = status;
          },
          end() {
            record.ended = true;
          },
        };
        return span;
      },
    };

    return { tracer, spans };
  }

  describe('without tracer', () => {
    it('returns a working logger with no OTel spans', () => {
      const logger = createOtelAuditLogger({ emit: false, store: true });

      logger.log('sandbox.create', { plugin: 'mock' }, 'sbx_001');

      expect(logger.events).toHaveLength(1);
      expect(logger.events[0].event).toBe('sandbox.create');
    });
  });

  describe('with tracer', () => {
    it('emits an OTel span for each audit event', () => {
      const { tracer, spans } = createMockTracer();
      const logger = createOtelAuditLogger({ emit: false, store: true, tracer });

      logger.log('sandbox.create', { plugin: 'mock' }, 'sbx_001');

      expect(spans).toHaveLength(1);
      expect(spans[0].name).toBe('audit.sandbox.create');
      expect(spans[0].ended).toBe(true);
    });

    it('includes event data as span attributes', () => {
      const { tracer, spans } = createMockTracer();
      const logger = createOtelAuditLogger({ emit: false, tracer });

      logger.log('sandbox.execute', { code: 'console.log(1)', timeout: 5000 });

      expect(spans[0].attributes['maestro.event']).toBe('sandbox.execute');
      expect(spans[0].attributes['maestro.data.timeout']).toBe(5000);
    });

    it('includes sandbox ID in attributes', () => {
      const { tracer, spans } = createMockTracer();
      const logger = createOtelAuditLogger({ emit: false, tracer });

      logger.log('sandbox.create', {}, 'sbx_test');

      expect(spans[0].attributes['maestro.sandbox_id']).toBe('sbx_test');
    });

    it('uses custom service name', () => {
      const { tracer, spans } = createMockTracer();
      const logger = createOtelAuditLogger({
        emit: false,
        tracer,
        serviceName: 'my-service',
      });

      logger.log('sandbox.create', {});

      expect(spans[0].attributes['maestro.service']).toBe('my-service');
    });

    it('defaults service name to maestro-sandbox', () => {
      const { tracer, spans } = createMockTracer();
      const logger = createOtelAuditLogger({ emit: false, tracer });

      logger.log('sandbox.create', {});

      expect(spans[0].attributes['maestro.service']).toBe('maestro-sandbox');
    });

    it('only includes primitive values in attributes', () => {
      const { tracer, spans } = createMockTracer();
      const logger = createOtelAuditLogger({ emit: false, tracer });

      logger.log('sandbox.execute', {
        str: 'hello',
        num: 42,
        bool: true,
        obj: { nested: true },
        arr: [1, 2, 3],
      });

      expect(spans[0].attributes['maestro.data.str']).toBe('hello');
      expect(spans[0].attributes['maestro.data.num']).toBe(42);
      expect(spans[0].attributes['maestro.data.bool']).toBe(true);
      expect(spans[0].attributes['maestro.data.obj']).toBeUndefined();
      expect(spans[0].attributes['maestro.data.arr']).toBeUndefined();
    });
  });

  describe('severity mapping', () => {
    it('maps CRITICAL to ERROR status', () => {
      const { tracer, spans } = createMockTracer();
      const logger = createOtelAuditLogger({ emit: false, tracer });

      logger.log('breach.detected', {});

      expect(spans[0].status.code).toBe(OtelSpanStatusCode.ERROR);
      expect(spans[0].status.message).toBe('CRITICAL');
    });

    it('maps ERROR to ERROR status', () => {
      const { tracer, spans } = createMockTracer();
      const logger = createOtelAuditLogger({ emit: false, tracer });

      logger.log('sandbox.create.failed', {});

      expect(spans[0].status.code).toBe(OtelSpanStatusCode.ERROR);
      expect(spans[0].status.message).toBe('ERROR');
    });

    it('maps WARN to UNSET status', () => {
      const { tracer, spans } = createMockTracer();
      const logger = createOtelAuditLogger({ emit: false, tracer });

      logger.log('sandbox.execute.timeout', {});

      expect(spans[0].status.code).toBe(OtelSpanStatusCode.UNSET);
    });

    it('maps INFO to OK status', () => {
      const { tracer, spans } = createMockTracer();
      const logger = createOtelAuditLogger({ emit: false, tracer });

      logger.log('sandbox.create', {});

      expect(spans[0].status.code).toBe(OtelSpanStatusCode.OK);
    });

    it('maps DEBUG to OK status', () => {
      const { tracer, spans } = createMockTracer();
      const logger = createOtelAuditLogger({ emit: false, tracer });

      logger.log('secret.redacted', {});

      expect(spans[0].status.code).toBe(OtelSpanStatusCode.OK);
    });
  });

  describe('delegation to base logger', () => {
    it('stores events when store=true', () => {
      const { tracer } = createMockTracer();
      const logger = createOtelAuditLogger({ emit: false, store: true, tracer });

      logger.log('sandbox.create', { plugin: 'ivm' }, 'sbx_001');
      logger.log('sandbox.destroy', {}, 'sbx_001');

      expect(logger.events).toHaveLength(2);
      expect(logger.events[0].event).toBe('sandbox.create');
      expect(logger.events[1].event).toBe('sandbox.destroy');
    });
  });

  describe('attribute key sanitization', () => {
    it('sanitizes special characters in data keys', () => {
      const { tracer, spans } = createMockTracer();
      const logger = createOtelAuditLogger({ emit: false, tracer });

      logger.log('sandbox.execute', {
        'normal_key': 'value1',
        'key with spaces': 'value2',
        'key/with/slashes': 'value3',
        'key[0]': 'value4',
      });

      expect(spans[0].attributes['maestro.data.normal_key']).toBe('value1');
      expect(spans[0].attributes['maestro.data.key_with_spaces']).toBe('value2');
      expect(spans[0].attributes['maestro.data.key_with_slashes']).toBe('value3');
      expect(spans[0].attributes['maestro.data.key_0_']).toBe('value4');
    });

    it('preserves dots and hyphens in keys', () => {
      const { tracer, spans } = createMockTracer();
      const logger = createOtelAuditLogger({ emit: false, tracer });

      logger.log('sandbox.execute', {
        'my.dotted.key': 'v1',
        'my-hyphenated-key': 'v2',
      });

      expect(spans[0].attributes['maestro.data.my.dotted.key']).toBe('v1');
      expect(spans[0].attributes['maestro.data.my-hyphenated-key']).toBe('v2');
    });
  });
});

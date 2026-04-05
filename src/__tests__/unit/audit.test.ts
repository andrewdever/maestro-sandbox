import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createAuditLogger, sha256 } from '../../audit.js';

describe('AuditLogger', () => {
  describe('createAuditLogger', () => {
    it('stores events when store option is true', () => {
      const logger = createAuditLogger({ emit: false, store: true });
      logger.log('sandbox.create', { plugin: 'mock' }, 'sbx_001');
      expect(logger.events).toHaveLength(1);
      expect(logger.events[0].event).toBe('sandbox.create');
      expect(logger.events[0].sandboxId).toBe('sbx_001');
    });

    it('does not store events by default', () => {
      const logger = createAuditLogger({ emit: false });
      logger.log('sandbox.create', { plugin: 'mock' });
      expect(logger.events).toHaveLength(0);
    });

    it('emits INFO events to stdout', () => {
      const writeSpy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
      const logger = createAuditLogger({ emit: true, store: false });
      logger.log('sandbox.create', { plugin: 'mock' });
      expect(writeSpy).toHaveBeenCalledOnce();
      const output = writeSpy.mock.calls[0][0] as string;
      expect(JSON.parse(output)).toMatchObject({
        level: 'INFO',
        event: 'sandbox.create',
      });
      writeSpy.mockRestore();
    });

    it('emits ERROR events to stderr', () => {
      const writeSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
      const logger = createAuditLogger({ emit: true, store: false });
      logger.log('sandbox.create.failed', { error: 'boom' });
      expect(writeSpy).toHaveBeenCalledOnce();
      const output = writeSpy.mock.calls[0][0] as string;
      expect(JSON.parse(output)).toMatchObject({
        level: 'ERROR',
        event: 'sandbox.create.failed',
      });
      writeSpy.mockRestore();
    });

    it('emits CRITICAL events to stderr', () => {
      const writeSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
      const logger = createAuditLogger({ emit: true, store: false });
      logger.log('breach.detected', { signal: 'path-traversal-patch' });
      expect(writeSpy).toHaveBeenCalledOnce();
      const output = writeSpy.mock.calls[0][0] as string;
      expect(JSON.parse(output).level).toBe('CRITICAL');
      writeSpy.mockRestore();
    });

    it('includes timestamp in events', () => {
      const logger = createAuditLogger({ emit: false, store: true });
      logger.log('sandbox.execute', { code: 'test' });
      expect(logger.events[0].timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    });

    it('maps event types to correct severity levels', () => {
      const logger = createAuditLogger({ emit: false, store: true });

      const cases: Array<[string, string]> = [
        ['sandbox.create', 'INFO'],
        ['sandbox.execute.timeout', 'WARN'],
        ['sandbox.create.failed', 'ERROR'],
        ['breach.detected', 'CRITICAL'],
        ['secret.redacted', 'DEBUG'],
      ];

      for (const [event, expectedLevel] of cases) {
        logger.log(event as any, {});
      }

      expect(logger.events[0].level).toBe('INFO');
      expect(logger.events[1].level).toBe('WARN');
      expect(logger.events[2].level).toBe('ERROR');
      expect(logger.events[3].level).toBe('CRITICAL');
      expect(logger.events[4].level).toBe('DEBUG');
    });

    it('omits sandboxId from event when not provided', () => {
      const logger = createAuditLogger({ emit: false, store: true });
      logger.log('sandbox.create', { plugin: 'mock' });
      expect(logger.events[0]).not.toHaveProperty('sandboxId');
    });
  });

  describe('sha256', () => {
    it('produces a 64-char hex string', () => {
      const hash = sha256('hello world');
      expect(hash).toHaveLength(64);
      expect(hash).toMatch(/^[a-f0-9]+$/);
    });

    it('is deterministic', () => {
      expect(sha256('test')).toBe(sha256('test'));
    });

    it('produces different hashes for different inputs', () => {
      expect(sha256('a')).not.toBe(sha256('b'));
    });
  });
});

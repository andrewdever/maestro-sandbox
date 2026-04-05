import { describe, it, expect } from 'vitest';
import { createRedactor } from '../../redact.js';

describe('Redactor', () => {
  const secrets = {
    API_KEY: 'sk-test-abc123xyz',
    DB_PASSWORD: 'super-secret-password',
  };

  describe('createRedactor', () => {
    it('creates a redactor with the correct secret count', () => {
      const r = createRedactor({ secrets });
      expect(r.secretCount).toBe(2);
    });

    it('rejects secrets shorter than 8 characters', () => {
      expect(() => createRedactor({ secrets: { SHORT: 'abc' } })).toThrow(
        'too short',
      );
    });

    it('accepts secrets of exactly 8 characters', () => {
      const r = createRedactor({ secrets: { EXACT: 'abcdefgh' } });
      expect(r.secretCount).toBe(1);
    });
  });

  describe('redact', () => {
    it('redacts plain text occurrences', () => {
      const r = createRedactor({ secrets });
      expect(r.redact('Key is sk-test-abc123xyz')).toBe('Key is [REDACTED]');
    });

    it('redacts multiple secrets in the same string', () => {
      const r = createRedactor({ secrets });
      const input = `key=${secrets.API_KEY}&pass=${secrets.DB_PASSWORD}`;
      const result = r.redact(input);
      expect(result).not.toContain(secrets.API_KEY);
      expect(result).not.toContain(secrets.DB_PASSWORD);
    });

    it('redacts base64-encoded variants', () => {
      const r = createRedactor({ secrets });
      const b64 = Buffer.from(secrets.API_KEY).toString('base64');
      expect(r.redact(`token: ${b64}`)).toBe('token: [REDACTED]');
    });

    it('redacts URL-encoded variants', () => {
      const r = createRedactor({ secrets });
      const encoded = encodeURIComponent(secrets.DB_PASSWORD);
      expect(r.redact(`p=${encoded}`)).toBe('p=[REDACTED]');
    });

    it('redacts hex-encoded variants', () => {
      const r = createRedactor({ secrets });
      const hex = Buffer.from(secrets.API_KEY).toString('hex');
      expect(r.redact(`hex: ${hex}`)).toBe('hex: [REDACTED]');
    });

    it('returns the original string when no secrets are present', () => {
      const r = createRedactor({ secrets });
      expect(r.redact('no secrets here')).toBe('no secrets here');
    });
  });

  describe('redactAll', () => {
    it('redacts secrets from an array of strings', () => {
      const r = createRedactor({ secrets });
      const results = r.redactAll([
        `Key: ${secrets.API_KEY}`,
        'No secret',
        `Pass: ${secrets.DB_PASSWORD}`,
      ]);
      expect(results[0]).toBe('Key: [REDACTED]');
      expect(results[1]).toBe('No secret');
      expect(results[2]).toBe('Pass: [REDACTED]');
    });
  });
});

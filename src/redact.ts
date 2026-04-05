/**
 * Secret redaction (§5).
 *
 * Replaces secret values in strings with [REDACTED].
 * Handles plain text, base64, URL-encoded, and hex-encoded variants.
 */

const REDACTED = '[REDACTED]';
const MIN_SECRET_LENGTH = 8;

export interface RedactionConfig {
  /** Secret values to redact. Keys are names, values are the secrets. */
  secrets: Record<string, string>;
}

/** Pre-computed redaction patterns for a set of secrets. */
export interface Redactor {
  /** Redact all secret variants from a string. */
  redact(input: string): string;
  /** Redact all secrets from an array of strings. */
  redactAll(inputs: string[]): string[];
  /** Number of secrets being tracked. */
  readonly secretCount: number;
}

interface SecretPattern {
  /** All string variants to search for, sorted longest first. */
  variants: string[];
}

function toBase64(s: string): string {
  return Buffer.from(s, 'utf-8').toString('base64');
}

function toUrlEncoded(s: string): string {
  return encodeURIComponent(s);
}

function toHex(s: string): string {
  return Buffer.from(s, 'utf-8').toString('hex');
}

/**
 * Build a redactor from a secrets map.
 *
 * Secrets shorter than 8 characters are rejected to avoid
 * false-positive redaction and trivial bypass via encoding.
 *
 * @throws If any secret is shorter than MIN_SECRET_LENGTH.
 */
export function createRedactor(config: RedactionConfig): Redactor {
  const patterns: SecretPattern[] = [];

  for (const [key, value] of Object.entries(config.secrets)) {
    if (value.length < MIN_SECRET_LENGTH) {
      throw new Error(
        `Secret "${key}" is too short (${value.length} chars, minimum ${MIN_SECRET_LENGTH}). ` +
        'Short secrets are trivially bypassed via encoding.',
      );
    }

    // Collect all encoded variants
    const variants = [
      value,
      toBase64(value),
      toUrlEncoded(value),
      toHex(value),
    ];

    // Deduplicate (some values may encode to themselves)
    const unique = [...new Set(variants)].filter(v => v.length > 0);
    patterns.push({ variants: unique });
  }

  // Flatten all variants and sort by length descending to prevent
  // partial matches of shorter substrings.
  const allVariants: string[] = [];
  for (const p of patterns) {
    allVariants.push(...p.variants);
  }
  allVariants.sort((a, b) => b.length - a.length);

  function redact(input: string): string {
    let result = input;
    for (const variant of allVariants) {
      // Use split+join for global replacement (no regex escaping needed)
      result = result.split(variant).join(REDACTED);
    }
    return result;
  }

  return {
    redact,
    redactAll(inputs: string[]): string[] {
      return inputs.map(redact);
    },
    get secretCount() {
      return Object.keys(config.secrets).length;
    },
  };
}

/**
 * Model Registry (§14.13).
 *
 * Architecture: Declarative config format.
 * Defines types and validation for model requirements.
 *
 * Validation rules:
 * - versionPin must not be "latest", empty, or contain wildcards
 * - instructionHierarchy MUST be true for models handling untrusted input
 * - safetyEvalUrl should be a valid URL if provided
 * - provider.noTrainingOnData SHOULD be true (warn if false)
 *
 * Audit event: model.version.changed (WARN)
 */

import type { AuditLogger } from './audit.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Requirements for a model to be used in the system. */
export interface ModelRequirements {
  /** Exact model version (no "latest"). */
  versionPin: string;
  /** Whether model supports instruction hierarchy. */
  instructionHierarchy: boolean;
  /** URL to safety evaluation results. */
  safetyEvalUrl?: string;
  /** Whether model has SecAlign-equivalent injection resistance training. */
  injectionResistanceTrained?: boolean;
  /** Maximum input tokens. */
  maxInputTokens?: number;
  /** Maximum output tokens. */
  maxOutputTokens?: number;
}

/** Requirements for a model provider. */
export interface ModelProviderRequirements {
  /** Provider name. */
  provider: string;
  /** Whether provider offers content filtering. */
  contentFiltering: boolean;
  /** Whether provider logs usage. */
  usageLogging: boolean;
  /** Whether provider guarantees no training on customer data. */
  noTrainingOnData: boolean;
}

/** A registered model entry. */
export interface ModelRegistryEntry {
  /** Model identifier (e.g. 'claude-sonnet-4-6'). */
  modelId: string;
  /** Model requirements. */
  requirements: ModelRequirements;
  /** Provider requirements. */
  provider: ModelProviderRequirements;
  /** When this entry was registered. */
  registeredAt: string;
}

/** Result of model validation. */
export interface ModelValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

/** Model registry interface. */
export interface ModelRegistry {
  register(modelId: string, requirements: ModelRequirements, provider: ModelProviderRequirements): ModelValidationResult;
  get(modelId: string): ModelRegistryEntry | undefined;
  validate(modelId: string): ModelValidationResult;
  list(): ModelRegistryEntry[];
  remove(modelId: string): boolean;
  readonly size: number;
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/** Version pin disallowed patterns. */
const DISALLOWED_VERSION_PATTERNS = [
  /^latest$/i,           // "latest" keyword
  /\*/,                  // Any wildcard
  /^\s*$/,               // Empty/whitespace
  /^v?\d+\.\d+\.$/,     // Incomplete version like "1.0."
  /-latest$/i,           // Trailing "-latest" suffix
  /[?+*]/,               // Glob/regex metacharacters
];

/** Basic URL validation. */
function isValidUrl(url: string): boolean {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
}

/**
 * Validate model requirements standalone.
 * Can be used for config validation without a registry.
 */
export function validateModelRequirements(requirements: ModelRequirements): ModelValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  // versionPin validation
  if (!requirements.versionPin) {
    errors.push('versionPin must not be empty');
  } else {
    for (const pattern of DISALLOWED_VERSION_PATTERNS) {
      if (pattern.test(requirements.versionPin)) {
        errors.push(`versionPin "${requirements.versionPin}" is not allowed — must be an exact version`);
        break;
      }
    }
  }

  // instructionHierarchy
  if (!requirements.instructionHierarchy) {
    warnings.push('instructionHierarchy is false — model may not properly enforce privilege levels with untrusted input');
  }

  // safetyEvalUrl — required for production models.
  // BREAKING CHANGE (V2.1.7): promoted from optional warning to required error.
  // Migration: add a safetyEvalUrl (https:// URL) to all ModelRequirements.
  // Models without a safety evaluation URL cannot be registered.
  if (requirements.safetyEvalUrl === undefined) {
    errors.push('safetyEvalUrl is required — every model must link to its safety evaluation results');
  } else if (!/^https?:\/\//i.test(requirements.safetyEvalUrl)) {
    errors.push(`safetyEvalUrl "${requirements.safetyEvalUrl}" must use http(s) scheme`);
  } else if (!isValidUrl(requirements.safetyEvalUrl)) {
    errors.push(`safetyEvalUrl "${requirements.safetyEvalUrl}" is not a valid URL`);
  }

  // injectionResistanceTrained
  if (requirements.injectionResistanceTrained === false) {
    warnings.push('Model lacks injection resistance training (SecAlign or equivalent)');
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
  };
}

/**
 * Validate provider requirements.
 */
function validateProviderRequirements(provider: ModelProviderRequirements): ModelValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  if (!provider.provider) {
    errors.push('provider name must not be empty');
  }

  if (!provider.noTrainingOnData) {
    warnings.push(`Provider "${provider.provider}" does not guarantee no training on customer data`);
  }

  if (!provider.contentFiltering) {
    warnings.push(`Provider "${provider.provider}" does not offer content filtering`);
  }

  if (!provider.usageLogging) {
    warnings.push(`Provider "${provider.provider}" does not log usage`);
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
  };
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/**
 * Create a model registry.
 *
 * @param logger - Optional audit logger for version change events.
 */
export function createModelRegistry(logger?: AuditLogger): ModelRegistry {
  const entries = new Map<string, ModelRegistryEntry>();

  return {
    register(modelId: string, requirements: ModelRequirements, provider: ModelProviderRequirements): ModelValidationResult {
      // Validate requirements
      const reqResult = validateModelRequirements(requirements);
      const provResult = validateProviderRequirements(provider);

      const combined: ModelValidationResult = {
        valid: reqResult.valid && provResult.valid,
        errors: [...reqResult.errors, ...provResult.errors],
        warnings: [...reqResult.warnings, ...provResult.warnings],
      };

      // Only register if valid
      if (!combined.valid) {
        return combined;
      }

      // Check for version change
      const existing = entries.get(modelId);
      if (existing && existing.requirements.versionPin !== requirements.versionPin) {
        logger?.log('model.version.changed', {
          modelId,
          previousVersion: existing.requirements.versionPin,
          newVersion: requirements.versionPin,
        });
      }

      entries.set(modelId, {
        modelId,
        requirements,
        provider,
        registeredAt: new Date().toISOString(),
      });

      return combined;
    },

    get(modelId: string): ModelRegistryEntry | undefined {
      return entries.get(modelId);
    },

    validate(modelId: string): ModelValidationResult {
      const entry = entries.get(modelId);
      if (!entry) {
        return {
          valid: false,
          errors: [`Model "${modelId}" is not registered`],
          warnings: [],
        };
      }

      const reqResult = validateModelRequirements(entry.requirements);
      const provResult = validateProviderRequirements(entry.provider);

      return {
        valid: reqResult.valid && provResult.valid,
        errors: [...reqResult.errors, ...provResult.errors],
        warnings: [...reqResult.warnings, ...provResult.warnings],
      };
    },

    list(): ModelRegistryEntry[] {
      return [...entries.values()];
    },

    remove(modelId: string): boolean {
      return entries.delete(modelId);
    },

    get size(): number {
      return entries.size;
    },
  };
}

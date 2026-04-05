import { describe, it, expect } from 'vitest';
import {
  createModelRegistry,
  validateModelRequirements,
  type ModelRequirements,
  type ModelProviderRequirements,
} from '../../model-registry.js';
import { createAuditLogger } from '../../audit.js';

function validRequirements(overrides: Partial<ModelRequirements> = {}): ModelRequirements {
  return {
    versionPin: 'claude-sonnet-4-6-20250514',
    instructionHierarchy: true,
    safetyEvalUrl: 'https://safety.example.com/eval/123',
    injectionResistanceTrained: true,
    maxInputTokens: 200_000,
    maxOutputTokens: 8_192,
    ...overrides,
  };
}

function validProvider(overrides: Partial<ModelProviderRequirements> = {}): ModelProviderRequirements {
  return {
    provider: 'anthropic',
    contentFiltering: true,
    usageLogging: true,
    noTrainingOnData: true,
    ...overrides,
  };
}

describe('ModelRegistry', () => {
  describe('validateModelRequirements', () => {
    it('passes for valid requirements', () => {
      const result = validateModelRequirements(validRequirements());
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('rejects empty versionPin', () => {
      const result = validateModelRequirements(validRequirements({ versionPin: '' }));
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('versionPin'))).toBe(true);
    });

    it('rejects "latest" versionPin', () => {
      const result = validateModelRequirements(validRequirements({ versionPin: 'latest' }));
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('latest'))).toBe(true);
    });

    it('rejects "LATEST" (case-insensitive)', () => {
      const result = validateModelRequirements(validRequirements({ versionPin: 'LATEST' }));
      expect(result.valid).toBe(false);
    });

    it('rejects wildcard versionPin', () => {
      const result = validateModelRequirements(validRequirements({ versionPin: 'claude-*' }));
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('exact version'))).toBe(true);
    });

    it('rejects "*" versionPin', () => {
      const result = validateModelRequirements(validRequirements({ versionPin: '*' }));
      expect(result.valid).toBe(false);
    });

    it('warns when instructionHierarchy is false', () => {
      const result = validateModelRequirements(validRequirements({ instructionHierarchy: false }));
      expect(result.valid).toBe(true);
      expect(result.warnings.some(w => w.includes('instructionHierarchy'))).toBe(true);
    });

    it('rejects invalid safetyEvalUrl', () => {
      const result = validateModelRequirements(validRequirements({ safetyEvalUrl: 'not-a-url' }));
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('safetyEvalUrl'))).toBe(true);
    });

    it('rejects missing safetyEvalUrl (P2: promoted to error)', () => {
      const result = validateModelRequirements(validRequirements({ safetyEvalUrl: undefined }));
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('safetyEvalUrl is required'))).toBe(true);
    });

    it('rejects non-http scheme safetyEvalUrl', () => {
      const result = validateModelRequirements(validRequirements({ safetyEvalUrl: 'javascript:alert(1)' }));
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('http(s) scheme'))).toBe(true);
    });

    it('rejects file:// scheme safetyEvalUrl', () => {
      const result = validateModelRequirements(validRequirements({ safetyEvalUrl: 'file:///etc/passwd' }));
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('http(s) scheme'))).toBe(true);
    });

    it('warns when injectionResistanceTrained is false', () => {
      const result = validateModelRequirements(validRequirements({ injectionResistanceTrained: false }));
      expect(result.warnings.some(w => w.includes('injection resistance'))).toBe(true);
    });
  });

  describe('createModelRegistry', () => {
    it('starts empty', () => {
      const registry = createModelRegistry();
      expect(registry.size).toBe(0);
      expect(registry.list()).toHaveLength(0);
    });

    it('registers a valid model', () => {
      const registry = createModelRegistry();
      const result = registry.register('claude-sonnet-4-6', validRequirements(), validProvider());
      expect(result.valid).toBe(true);
      expect(registry.size).toBe(1);
    });

    it('rejects invalid model registration', () => {
      const registry = createModelRegistry();
      const result = registry.register(
        'bad-model',
        validRequirements({ versionPin: 'latest' }),
        validProvider(),
      );
      expect(result.valid).toBe(false);
      expect(registry.size).toBe(0);
    });

    it('gets a registered model', () => {
      const registry = createModelRegistry();
      registry.register('claude-sonnet-4-6', validRequirements(), validProvider());
      const entry = registry.get('claude-sonnet-4-6');
      expect(entry).toBeDefined();
      expect(entry!.modelId).toBe('claude-sonnet-4-6');
      expect(entry!.requirements.versionPin).toBe('claude-sonnet-4-6-20250514');
    });

    it('returns undefined for unregistered model', () => {
      const registry = createModelRegistry();
      expect(registry.get('nonexistent')).toBeUndefined();
    });

    it('validates a registered model', () => {
      const registry = createModelRegistry();
      registry.register('claude-sonnet-4-6', validRequirements(), validProvider());
      const result = registry.validate('claude-sonnet-4-6');
      expect(result.valid).toBe(true);
    });

    it('returns error for validating unregistered model', () => {
      const registry = createModelRegistry();
      const result = registry.validate('nonexistent');
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('not registered'))).toBe(true);
    });

    it('lists all registered models', () => {
      const registry = createModelRegistry();
      registry.register('model-a', validRequirements(), validProvider());
      registry.register('model-b', validRequirements({ versionPin: 'v2.0.0' }), validProvider());
      const list = registry.list();
      expect(list).toHaveLength(2);
      expect(list.map(e => e.modelId)).toContain('model-a');
      expect(list.map(e => e.modelId)).toContain('model-b');
    });

    it('removes a model', () => {
      const registry = createModelRegistry();
      registry.register('claude-sonnet-4-6', validRequirements(), validProvider());
      expect(registry.remove('claude-sonnet-4-6')).toBe(true);
      expect(registry.size).toBe(0);
    });

    it('returns false when removing nonexistent model', () => {
      const registry = createModelRegistry();
      expect(registry.remove('nonexistent')).toBe(false);
    });

    it('overwrites existing model with new version', () => {
      const registry = createModelRegistry();
      registry.register('claude-sonnet-4-6', validRequirements({ versionPin: 'v1.0.0' }), validProvider());
      registry.register('claude-sonnet-4-6', validRequirements({ versionPin: 'v2.0.0' }), validProvider());
      expect(registry.size).toBe(1);
      expect(registry.get('claude-sonnet-4-6')!.requirements.versionPin).toBe('v2.0.0');
    });
  });

  describe('provider validation', () => {
    it('warns when noTrainingOnData is false', () => {
      const registry = createModelRegistry();
      const result = registry.register(
        'test-model',
        validRequirements(),
        validProvider({ noTrainingOnData: false }),
      );
      expect(result.valid).toBe(true);
      expect(result.warnings.some(w => w.includes('no training'))).toBe(true);
    });

    it('warns when contentFiltering is false', () => {
      const registry = createModelRegistry();
      const result = registry.register(
        'test-model',
        validRequirements(),
        validProvider({ contentFiltering: false }),
      );
      expect(result.warnings.some(w => w.includes('content filtering'))).toBe(true);
    });

    it('warns when usageLogging is false', () => {
      const registry = createModelRegistry();
      const result = registry.register(
        'test-model',
        validRequirements(),
        validProvider({ usageLogging: false }),
      );
      expect(result.warnings.some(w => w.includes('usage'))).toBe(true);
    });

    it('rejects empty provider name', () => {
      const registry = createModelRegistry();
      const result = registry.register(
        'test-model',
        validRequirements(),
        validProvider({ provider: '' }),
      );
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('provider name'))).toBe(true);
    });
  });

  describe('audit events', () => {
    it('emits model.version.changed when version changes', () => {
      const logger = createAuditLogger({ emit: false, store: true });
      const registry = createModelRegistry(logger);
      registry.register('claude-sonnet-4-6', validRequirements({ versionPin: 'v1.0.0' }), validProvider());
      registry.register('claude-sonnet-4-6', validRequirements({ versionPin: 'v2.0.0' }), validProvider());
      expect(logger.events.some(e => e.event === 'model.version.changed')).toBe(true);
      const event = logger.events.find(e => e.event === 'model.version.changed')!;
      expect(event.data['previousVersion']).toBe('v1.0.0');
      expect(event.data['newVersion']).toBe('v2.0.0');
    });

    it('does not emit when registering same version', () => {
      const logger = createAuditLogger({ emit: false, store: true });
      const registry = createModelRegistry(logger);
      registry.register('claude-sonnet-4-6', validRequirements({ versionPin: 'v1.0.0' }), validProvider());
      registry.register('claude-sonnet-4-6', validRequirements({ versionPin: 'v1.0.0' }), validProvider());
      expect(logger.events.some(e => e.event === 'model.version.changed')).toBe(false);
    });

    it('does not emit on first registration', () => {
      const logger = createAuditLogger({ emit: false, store: true });
      const registry = createModelRegistry(logger);
      registry.register('claude-sonnet-4-6', validRequirements(), validProvider());
      expect(logger.events.some(e => e.event === 'model.version.changed')).toBe(false);
    });
  });
});

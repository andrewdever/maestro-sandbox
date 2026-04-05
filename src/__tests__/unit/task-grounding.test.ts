import { describe, it, expect, beforeEach } from 'vitest';
import {
  createTaskGrounding,
  ALL_CAPABILITY_TAGS,
  type CapabilityTag,
  type TaskScope,
  type TaskGrounding,
} from '../../task-grounding.js';
import { createAuditLogger } from '../../audit.js';

describe('TaskGrounding', () => {
  // -----------------------------------------------------------------------
  // ALL_CAPABILITY_TAGS
  // -----------------------------------------------------------------------

  describe('ALL_CAPABILITY_TAGS', () => {
    it('contains exactly 10 tags', () => {
      expect(ALL_CAPABILITY_TAGS).toHaveLength(10);
    });

    it('contains all expected tags', () => {
      const expected: CapabilityTag[] = [
        'filesystem-read',
        'filesystem-write',
        'code-generation',
        'code-execution',
        'network-fetch',
        'network-listen',
        'secret-access',
        'process-spawn',
        'git-read',
        'git-write',
      ];
      expect(ALL_CAPABILITY_TAGS).toEqual(expected);
    });

    it('is readonly', () => {
      // TypeScript enforcement — at runtime, as const should prevent mutation
      expect(Object.isFrozen(ALL_CAPABILITY_TAGS)).toBe(false); // as const doesn't freeze
      expect(Array.isArray(ALL_CAPABILITY_TAGS)).toBe(true);
    });
  });

  // -----------------------------------------------------------------------
  // createTaskGrounding
  // -----------------------------------------------------------------------

  describe('createTaskGrounding', () => {
    it('creates an instance with no config', () => {
      const grounding = createTaskGrounding();
      expect(grounding).toBeDefined();
      expect(typeof grounding.check).toBe('function');
      expect(typeof grounding.validateScope).toBe('function');
      expect(grounding.defaultMapping).toBeDefined();
    });

    it('creates an instance with custom config', () => {
      const grounding = createTaskGrounding({
        enforcementMode: 'block',
      });
      expect(grounding).toBeDefined();
    });
  });

  // -----------------------------------------------------------------------
  // defaultMapping
  // -----------------------------------------------------------------------

  describe('defaultMapping', () => {
    it('maps readFile to filesystem-read', () => {
      const grounding = createTaskGrounding();
      expect(grounding.defaultMapping['readFile']).toEqual(['filesystem-read']);
    });

    it('maps writeFile to filesystem-write', () => {
      const grounding = createTaskGrounding();
      expect(grounding.defaultMapping['writeFile']).toEqual(['filesystem-write']);
    });

    it('maps fetch to network-fetch', () => {
      const grounding = createTaskGrounding();
      expect(grounding.defaultMapping['fetch']).toEqual(['network-fetch']);
    });

    it('maps listen to network-listen', () => {
      const grounding = createTaskGrounding();
      expect(grounding.defaultMapping['listen']).toEqual(['network-listen']);
    });

    it('maps exec to process-spawn', () => {
      const grounding = createTaskGrounding();
      expect(grounding.defaultMapping['exec']).toEqual(['process-spawn']);
    });

    it('maps getSecret to secret-access', () => {
      const grounding = createTaskGrounding();
      expect(grounding.defaultMapping['getSecret']).toEqual(['secret-access']);
    });

    it('maps gitLog to git-read', () => {
      const grounding = createTaskGrounding();
      expect(grounding.defaultMapping['gitLog']).toEqual(['git-read']);
    });

    it('maps gitCommit to git-write', () => {
      const grounding = createTaskGrounding();
      expect(grounding.defaultMapping['gitCommit']).toEqual(['git-write']);
    });

    it('maps generateCode to code-generation', () => {
      const grounding = createTaskGrounding();
      expect(grounding.defaultMapping['generateCode']).toEqual(['code-generation']);
    });

    it('maps eval to code-execution', () => {
      const grounding = createTaskGrounding();
      expect(grounding.defaultMapping['eval']).toEqual(['code-execution']);
    });
  });

  // -----------------------------------------------------------------------
  // check — allowed operations
  // -----------------------------------------------------------------------

  describe('check (allowed)', () => {
    let grounding: TaskGrounding;

    const scope: TaskScope = {
      tags: ['filesystem-read', 'filesystem-write', 'code-generation'],
    };

    beforeEach(() => {
      grounding = createTaskGrounding();
    });

    it('allows operations matching scope tags', () => {
      const result = grounding.check('readFile', scope);
      expect(result.allowed).toBe(true);
      expect(result.missingTags).toHaveLength(0);
      expect(result.operation).toBe('readFile');
    });

    it('allows writeFile when filesystem-write is in scope', () => {
      const result = grounding.check('writeFile', scope);
      expect(result.allowed).toBe(true);
      expect(result.missingTags).toHaveLength(0);
    });

    it('allows unknown operations (no capability mapping)', () => {
      const result = grounding.check('unknownOperation', scope);
      expect(result.allowed).toBe(true);
      expect(result.missingTags).toHaveLength(0);
    });

    it('allows operations when all required tags are present', () => {
      const result = grounding.check('generateCode', scope);
      expect(result.allowed).toBe(true);
    });
  });

  // -----------------------------------------------------------------------
  // check — violations (flag mode, default)
  // -----------------------------------------------------------------------

  describe('check (violations — flag mode)', () => {
    let grounding: TaskGrounding;

    const scope: TaskScope = {
      tags: ['filesystem-read'],
    };

    beforeEach(() => {
      grounding = createTaskGrounding(); // default: flag mode
    });

    it('flags but allows network-fetch when not in scope', () => {
      const result = grounding.check('fetch', scope);
      expect(result.allowed).toBe(true); // flag mode = still allowed
      expect(result.missingTags).toContain('network-fetch');
      expect(result.reason).toBeDefined();
    });

    it('reports missing tags for filesystem-write', () => {
      const result = grounding.check('writeFile', scope);
      expect(result.allowed).toBe(true);
      expect(result.missingTags).toContain('filesystem-write');
    });

    it('reports missing tags for secret-access', () => {
      const result = grounding.check('getSecret', scope);
      expect(result.missingTags).toContain('secret-access');
    });

    it('includes the operation name in the result', () => {
      const result = grounding.check('gitPush', scope);
      expect(result.operation).toBe('gitPush');
    });

    it('includes a human-readable reason', () => {
      const result = grounding.check('gitCommit', scope);
      expect(result.reason).toContain('gitCommit');
      expect(result.reason).toContain('git-write');
    });
  });

  // -----------------------------------------------------------------------
  // check — violations (block mode)
  // -----------------------------------------------------------------------

  describe('check (violations — block mode)', () => {
    let grounding: TaskGrounding;

    const scope: TaskScope = {
      tags: ['filesystem-read'],
    };

    beforeEach(() => {
      grounding = createTaskGrounding({ enforcementMode: 'block' });
    });

    it('blocks operations outside scope', () => {
      const result = grounding.check('fetch', scope);
      expect(result.allowed).toBe(false);
      expect(result.missingTags).toContain('network-fetch');
    });

    it('still allows operations within scope', () => {
      const result = grounding.check('readFile', scope);
      expect(result.allowed).toBe(true);
      expect(result.missingTags).toHaveLength(0);
    });

    it('blocks secret-access when not in scope', () => {
      const result = grounding.check('getApiKey', scope);
      expect(result.allowed).toBe(false);
      expect(result.missingTags).toContain('secret-access');
    });

    it('blocks process-spawn when not in scope', () => {
      const result = grounding.check('spawn', scope);
      expect(result.allowed).toBe(false);
      expect(result.missingTags).toContain('process-spawn');
    });
  });

  // -----------------------------------------------------------------------
  // check — pattern matching (non-exact function names)
  // -----------------------------------------------------------------------

  describe('check (pattern matching)', () => {
    let grounding: TaskGrounding;

    const scope: TaskScope = {
      tags: [], // empty scope — everything should be flagged
    };

    beforeEach(() => {
      grounding = createTaskGrounding();
    });

    it('matches readFile pattern for custom names containing readFile', () => {
      const result = grounding.check('myReadFileHelper', scope);
      expect(result.missingTags).toContain('filesystem-read');
    });

    it('matches fetch pattern for custom names containing fetch', () => {
      const result = grounding.check('customFetchData', scope);
      expect(result.missingTags).toContain('network-fetch');
    });

    it('matches exec pattern for names containing exec', () => {
      const result = grounding.check('shellExec', scope);
      expect(result.missingTags).toContain('process-spawn');
    });

    it('matches gitCommit pattern for names containing gitCommit', () => {
      const result = grounding.check('safeGitCommit', scope);
      expect(result.missingTags).toContain('git-write');
    });

    it('matches getSecret pattern for names containing getSecret', () => {
      const result = grounding.check('vaultGetSecret', scope);
      expect(result.missingTags).toContain('secret-access');
    });

    it('matches createServer pattern for network-listen', () => {
      const result = grounding.check('createServer', scope);
      expect(result.missingTags).toContain('network-listen');
    });

    it('does not match completely unrelated names', () => {
      const result = grounding.check('calculateSum', scope);
      expect(result.allowed).toBe(true);
      expect(result.missingTags).toHaveLength(0);
    });
  });

  // -----------------------------------------------------------------------
  // check — custom capability mapping
  // -----------------------------------------------------------------------

  describe('check (custom capability mapping)', () => {
    it('uses custom mapping for exact matches', () => {
      const grounding = createTaskGrounding({
        capabilityMapping: {
          myCustomTool: ['network-fetch', 'secret-access'],
        },
      });
      const scope: TaskScope = { tags: ['network-fetch'] };
      const result = grounding.check('myCustomTool', scope);
      expect(result.missingTags).toContain('secret-access');
      expect(result.missingTags).not.toContain('network-fetch');
    });

    it('overrides default mapping for existing function names', () => {
      const grounding = createTaskGrounding({
        capabilityMapping: {
          readFile: ['secret-access'], // override: readFile now needs secret-access
        },
      });
      const scope: TaskScope = { tags: ['filesystem-read'] };
      const result = grounding.check('readFile', scope);
      expect(result.missingTags).toContain('secret-access');
    });

    it('preserves default mapping for non-overridden functions', () => {
      const grounding = createTaskGrounding({
        capabilityMapping: {
          myCustomTool: ['network-fetch'],
        },
      });
      const scope: TaskScope = { tags: ['filesystem-read'] };
      const result = grounding.check('readFile', scope);
      expect(result.allowed).toBe(true);
    });
  });

  // -----------------------------------------------------------------------
  // check — empty scope
  // -----------------------------------------------------------------------

  describe('check (empty scope)', () => {
    it('flags all mapped operations with empty tags', () => {
      const grounding = createTaskGrounding();
      const scope: TaskScope = { tags: [] };

      const result = grounding.check('readFile', scope);
      expect(result.missingTags).toContain('filesystem-read');
    });

    it('allows unmapped operations with empty tags', () => {
      const grounding = createTaskGrounding();
      const scope: TaskScope = { tags: [] };

      const result = grounding.check('noSuchFunction', scope);
      expect(result.allowed).toBe(true);
    });
  });

  // -----------------------------------------------------------------------
  // check — full scope
  // -----------------------------------------------------------------------

  describe('check (full scope)', () => {
    it('allows everything when all tags are granted', () => {
      const grounding = createTaskGrounding();
      const scope: TaskScope = { tags: [...ALL_CAPABILITY_TAGS] };

      const operations = [
        'readFile', 'writeFile', 'fetch', 'listen',
        'exec', 'getSecret', 'gitLog', 'gitCommit',
        'generateCode', 'eval',
      ];

      for (const op of operations) {
        const result = grounding.check(op, scope);
        expect(result.allowed).toBe(true);
        expect(result.missingTags).toHaveLength(0);
      }
    });
  });

  // -----------------------------------------------------------------------
  // validateScope
  // -----------------------------------------------------------------------

  describe('validateScope', () => {
    let grounding: TaskGrounding;

    beforeEach(() => {
      grounding = createTaskGrounding();
    });

    it('validates a correct scope', () => {
      const result = grounding.validateScope({
        tags: ['filesystem-read', 'network-fetch'],
      });
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('validates an empty tags array', () => {
      const result = grounding.validateScope({ tags: [] });
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('rejects invalid tags', () => {
      const result = grounding.validateScope({
        tags: ['filesystem-read', 'invalid-tag' as CapabilityTag],
      });
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('invalid-tag'))).toBe(true);
    });

    it('rejects duplicate tags', () => {
      const result = grounding.validateScope({
        tags: ['filesystem-read', 'filesystem-read'],
      });
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('Duplicate'))).toBe(true);
    });

    it('rejects non-array tags', () => {
      const result = grounding.validateScope({
        tags: 'not-an-array' as unknown as CapabilityTag[],
      });
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('must be an array'))).toBe(true);
    });

    it('rejects null scope', () => {
      const result = grounding.validateScope(null as unknown as TaskScope);
      expect(result.valid).toBe(false);
    });

    it('validates scope with all tags', () => {
      const result = grounding.validateScope({
        tags: [...ALL_CAPABILITY_TAGS],
      });
      expect(result.valid).toBe(true);
    });
  });

  // -----------------------------------------------------------------------
  // Audit logging
  // -----------------------------------------------------------------------

  describe('audit logging', () => {
    it('logs grounding.violation in flag mode', () => {
      const logger = createAuditLogger({ emit: false, store: true });
      const grounding = createTaskGrounding({
        enforcementMode: 'flag',
        logger,
      });

      grounding.check('fetch', { tags: ['filesystem-read'] });
      expect(logger.events.some(e => e.event === 'grounding.violation')).toBe(true);
    });

    it('logs grounding.blocked in block mode', () => {
      const logger = createAuditLogger({ emit: false, store: true });
      const grounding = createTaskGrounding({
        enforcementMode: 'block',
        logger,
      });

      grounding.check('fetch', { tags: ['filesystem-read'] });
      expect(logger.events.some(e => e.event === 'grounding.blocked')).toBe(true);
    });

    it('does not log for allowed operations', () => {
      const logger = createAuditLogger({ emit: false, store: true });
      const grounding = createTaskGrounding({
        enforcementMode: 'block',
        logger,
      });

      grounding.check('readFile', { tags: ['filesystem-read'] });
      expect(logger.events).toHaveLength(0);
    });

    it('does not log for unmapped operations', () => {
      const logger = createAuditLogger({ emit: false, store: true });
      const grounding = createTaskGrounding({
        enforcementMode: 'block',
        logger,
      });

      grounding.check('unknownOp', { tags: [] });
      expect(logger.events).toHaveLength(0);
    });

    it('includes operation and missing tags in audit data', () => {
      const logger = createAuditLogger({ emit: false, store: true });
      const grounding = createTaskGrounding({
        enforcementMode: 'flag',
        logger,
      });

      grounding.check('getSecret', { tags: ['filesystem-read'] });
      const event = logger.events[0];
      expect(event.data['operation']).toBe('getSecret');
      expect(event.data['missingTags']).toEqual(['secret-access']);
    });
  });

  // -----------------------------------------------------------------------
  // TaskScope forward compatibility
  // -----------------------------------------------------------------------

  describe('TaskScope forward compatibility', () => {
    it('works with extra properties (forward compat)', () => {
      const grounding = createTaskGrounding();
      // Simulate a future scope with description
      const scope = {
        tags: ['filesystem-read'] as CapabilityTag[],
        description: 'Read project files',
      };
      const result = grounding.check('readFile', scope);
      expect(result.allowed).toBe(true);
    });
  });

  // -----------------------------------------------------------------------
  // Edge cases
  // -----------------------------------------------------------------------

  describe('edge cases', () => {
    it('handles empty operation string', () => {
      const grounding = createTaskGrounding();
      const result = grounding.check('', { tags: ['filesystem-read'] });
      expect(result.allowed).toBe(true);
      expect(result.missingTags).toHaveLength(0);
    });

    it('handles operation with special characters', () => {
      const grounding = createTaskGrounding();
      const result = grounding.check('my.readFile.v2', { tags: [] });
      // Pattern should still match because "readFile" is in the string
      expect(result.missingTags).toContain('filesystem-read');
    });

    it('is case-insensitive for pattern matching', () => {
      const grounding = createTaskGrounding();
      const result = grounding.check('READFILE', { tags: [] });
      expect(result.missingTags).toContain('filesystem-read');
    });

    it('handles multiple missing tags', () => {
      const grounding = createTaskGrounding({
        capabilityMapping: {
          dangerousOp: ['filesystem-write', 'network-fetch', 'secret-access'],
        },
      });
      const result = grounding.check('dangerousOp', { tags: ['filesystem-write'] });
      expect(result.missingTags).toHaveLength(2);
      expect(result.missingTags).toContain('network-fetch');
      expect(result.missingTags).toContain('secret-access');
    });
  });
});

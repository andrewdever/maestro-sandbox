/**
 * Task-Grounding Module (§14.12).
 *
 * Enforces capability-tag-based scoping for sandbox operations.
 * Each task declares a TaskScope (an object with `tags` array for
 * forward compatibility) and every host function call is checked
 * against the scope before execution.
 *
 * Design decision: Option C (capability tags) with forward-compatible
 * type. TaskScope is an object (not a bare array) so `description?: string`
 * can be added later without breaking changes.
 *
 * Audit events:
 *   grounding.violation   (WARN)  — operation outside declared scope
 *   grounding.blocked     (WARN)  — operation blocked by enforcement mode
 */

import type { AuditLogger } from './audit.js';

// ---------------------------------------------------------------------------
// Capability Tags
// ---------------------------------------------------------------------------

/** ~10 capability tags mapping to host function categories. */
export type CapabilityTag =
  | 'filesystem-read'
  | 'filesystem-write'
  | 'code-generation'
  | 'code-execution'
  | 'network-fetch'
  | 'network-listen'
  | 'secret-access'
  | 'process-spawn'
  | 'git-read'
  | 'git-write';

export const ALL_CAPABILITY_TAGS: readonly CapabilityTag[] = [
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
] as const;

// ---------------------------------------------------------------------------
// Task Scope
// ---------------------------------------------------------------------------

/** Forward-compatible task scope — object, not bare array. */
export interface TaskScope {
  /** Required capability tags for enforcement. */
  tags: CapabilityTag[];
  // description?: string  — reserved for future ML classifier phase
}

// ---------------------------------------------------------------------------
// Capability Mapping
// ---------------------------------------------------------------------------

/** Maps host function names to required capability tags. */
export interface CapabilityMapping {
  [hostFunctionName: string]: CapabilityTag[];
}

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

/** Result of a task-grounding check. */
export interface GroundingCheckResult {
  allowed: boolean;
  /** Tags that would be needed but aren't in scope. */
  missingTags: CapabilityTag[];
  /** The operation that was checked. */
  operation: string;
  reason?: string;
}

/** Anomaly from grounding analysis (integrates with behavioral analyzer). */
export interface GroundingAnomaly {
  operation: string;
  missingTags: CapabilityTag[];
  score: number;  // 0-1
  reason: string;
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

export interface TaskGroundingConfig {
  /** Custom capability mapping (overrides defaults). */
  capabilityMapping?: CapabilityMapping;
  /** Whether to block or just flag violations. Default: 'flag'. */
  enforcementMode?: 'block' | 'flag';
  /** Logger for audit events. */
  logger?: AuditLogger;
}

// ---------------------------------------------------------------------------
// Interface
// ---------------------------------------------------------------------------

export interface TaskGrounding {
  /** Check if an operation is consistent with the declared task scope. */
  check(operation: string, scope: TaskScope): GroundingCheckResult;

  /** Get the default capability mapping. */
  readonly defaultMapping: CapabilityMapping;

  /** Validate a TaskScope (all tags are valid). */
  validateScope(scope: TaskScope): { valid: boolean; errors: string[] };
}

// ---------------------------------------------------------------------------
// Default Capability Mapping
// ---------------------------------------------------------------------------

/**
 * Pattern-based mapping from host function names to capability tags.
 *
 * Each entry is [pattern, tags]. A function name matches if it
 * contains the pattern (case-insensitive).
 */
const DEFAULT_PATTERNS: Array<[RegExp, CapabilityTag[]]> = [
  // filesystem-read
  [/readFile|listDir|stat(?!us)|openFile|readdir|access/i, ['filesystem-read']],
  // filesystem-write
  [/writeFile|deleteFile|mkdir|rmdir|unlink|rename|copyFile|appendFile/i, ['filesystem-write']],
  // network-fetch
  [/fetch|httpGet|httpPost|httpPut|httpDelete|httpPatch|request(?!Approval)/i, ['network-fetch']],
  // network-listen
  [/listen|serve|createServer|bindPort/i, ['network-listen']],
  // process-spawn
  [/exec(?!ute)|spawn|fork|child_process|runCommand/i, ['process-spawn']],
  // secret-access
  [/getSecret|readEnv|getApiKey|getCredential|getToken|getPassword/i, ['secret-access']],
  // git-read
  [/gitLog|gitDiff|gitBlame|gitStatus|gitShow|gitBranch/i, ['git-read']],
  // git-write
  [/gitCommit|gitPush|gitCheckout|gitMerge|gitRebase|gitReset|gitTag/i, ['git-write']],
  // code-generation
  [/generateCode|editCode|refactor|codeComplete|suggest/i, ['code-generation']],
  // code-execution
  [/eval(?!uate)|runScript|execute|runCode|interpret/i, ['code-execution']],
];

/**
 * Build the default capability mapping as an explicit object.
 * Used for `.defaultMapping` property and as fallback reference.
 */
function buildDefaultExplicitMapping(): CapabilityMapping {
  return {
    // filesystem-read
    readFile: ['filesystem-read'],
    listDir: ['filesystem-read'],
    stat: ['filesystem-read'],
    openFile: ['filesystem-read'],
    readdir: ['filesystem-read'],
    access: ['filesystem-read'],
    // filesystem-write
    writeFile: ['filesystem-write'],
    deleteFile: ['filesystem-write'],
    mkdir: ['filesystem-write'],
    rmdir: ['filesystem-write'],
    unlink: ['filesystem-write'],
    rename: ['filesystem-write'],
    copyFile: ['filesystem-write'],
    appendFile: ['filesystem-write'],
    // network-fetch
    fetch: ['network-fetch'],
    httpGet: ['network-fetch'],
    httpPost: ['network-fetch'],
    httpPut: ['network-fetch'],
    httpDelete: ['network-fetch'],
    httpPatch: ['network-fetch'],
    // network-listen
    listen: ['network-listen'],
    serve: ['network-listen'],
    createServer: ['network-listen'],
    bindPort: ['network-listen'],
    // process-spawn
    exec: ['process-spawn'],
    spawn: ['process-spawn'],
    fork: ['process-spawn'],
    runCommand: ['process-spawn'],
    // secret-access
    getSecret: ['secret-access'],
    readEnv: ['secret-access'],
    getApiKey: ['secret-access'],
    getCredential: ['secret-access'],
    getToken: ['secret-access'],
    getPassword: ['secret-access'],
    // git-read
    gitLog: ['git-read'],
    gitDiff: ['git-read'],
    gitBlame: ['git-read'],
    gitStatus: ['git-read'],
    gitShow: ['git-read'],
    gitBranch: ['git-read'],
    // git-write
    gitCommit: ['git-write'],
    gitPush: ['git-write'],
    gitCheckout: ['git-write'],
    gitMerge: ['git-write'],
    gitRebase: ['git-write'],
    gitReset: ['git-write'],
    gitTag: ['git-write'],
    // code-generation
    generateCode: ['code-generation'],
    editCode: ['code-generation'],
    refactor: ['code-generation'],
    codeComplete: ['code-generation'],
    suggest: ['code-generation'],
    // code-execution
    eval: ['code-execution'],
    runScript: ['code-execution'],
    execute: ['code-execution'],
    runCode: ['code-execution'],
    interpret: ['code-execution'],
  };
}

// ---------------------------------------------------------------------------
// Pattern Resolver
// ---------------------------------------------------------------------------

/**
 * Resolve the capability tags required by an operation.
 *
 * 1. Check explicit mapping first (custom overrides + defaults).
 * 2. Fall back to pattern matching against DEFAULT_PATTERNS.
 * 3. Return empty array if no match (operation is unscoped).
 */
function resolveCapabilities(
  operation: string,
  explicitMapping: CapabilityMapping,
): CapabilityTag[] {
  // Exact match in explicit mapping
  if (explicitMapping[operation]) {
    return explicitMapping[operation];
  }

  // Pattern matching fallback
  const tags = new Set<CapabilityTag>();
  for (const [pattern, patternTags] of DEFAULT_PATTERNS) {
    if (pattern.test(operation)) {
      for (const tag of patternTags) {
        tags.add(tag);
      }
    }
  }

  return [...tags];
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

const VALID_TAGS = new Set<string>(ALL_CAPABILITY_TAGS);

function validateScopeImpl(scope: TaskScope): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  if (!scope || typeof scope !== 'object') {
    errors.push('TaskScope must be a non-null object');
    return { valid: false, errors };
  }

  if (!Array.isArray(scope.tags)) {
    errors.push('TaskScope.tags must be an array');
    return { valid: false, errors };
  }

  for (const tag of scope.tags) {
    if (!VALID_TAGS.has(tag)) {
      errors.push(`Invalid capability tag: "${tag}"`);
    }
  }

  // Check for duplicates
  const seen = new Set<string>();
  for (const tag of scope.tags) {
    if (seen.has(tag)) {
      errors.push(`Duplicate capability tag: "${tag}"`);
    }
    seen.add(tag);
  }

  return { valid: errors.length === 0, errors };
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create a TaskGrounding instance.
 *
 * @param config - Optional configuration (custom mapping, enforcement mode, logger).
 */
export function createTaskGrounding(config?: TaskGroundingConfig): TaskGrounding {
  const enforcementMode = config?.enforcementMode ?? 'flag';
  const logger = config?.logger;

  // Merge custom mapping over defaults
  const defaultMapping = buildDefaultExplicitMapping();
  const explicitMapping: CapabilityMapping = config?.capabilityMapping
    ? { ...defaultMapping, ...config.capabilityMapping }
    : defaultMapping;

  return {
    check(operation: string, scope: TaskScope): GroundingCheckResult {
      const requiredTags = resolveCapabilities(operation, explicitMapping);

      // If no capability mapping found, the operation is unscoped — allow
      if (requiredTags.length === 0) {
        return {
          allowed: true,
          missingTags: [],
          operation,
        };
      }

      // Find tags that are required but not in scope
      const scopeTags = new Set(scope.tags);
      const missingTags = requiredTags.filter(tag => !scopeTags.has(tag));

      if (missingTags.length === 0) {
        return {
          allowed: true,
          missingTags: [],
          operation,
        };
      }

      // Violation detected
      const reason = `Operation "${operation}" requires [${missingTags.join(', ')}] but scope only grants [${scope.tags.join(', ')}]`;

      // Audit
      if (enforcementMode === 'block') {
        logger?.log('grounding.blocked', {
          operation,
          missingTags,
          scopeTags: scope.tags,
          enforcementMode,
        });
      } else {
        logger?.log('grounding.violation', {
          operation,
          missingTags,
          scopeTags: scope.tags,
          enforcementMode,
        });
      }

      return {
        allowed: enforcementMode !== 'block',
        missingTags,
        operation,
        reason,
      };
    },

    get defaultMapping(): CapabilityMapping {
      return defaultMapping;
    },

    validateScope: validateScopeImpl,
  };
}

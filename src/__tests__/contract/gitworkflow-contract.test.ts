import { describe, it, expect } from 'vitest';

/**
 * Git workflow contract test suite.
 *
 * Validates the rules defined in gitworkflow-v1.md:
 * - Branch naming conventions (§2, §10.4)
 * - Commit attribution requirements (§4, §7.4)
 * - Secret detection in commit messages (§15)
 *
 * These are pure validation tests — no git operations required.
 * They verify the BranchValidator contract from §10.4.
 */

// ── Branch naming regex (from gitworkflow-v1.md §10.4) ─────────────

const HUMAN_BRANCH_RE = /^(feature|fix|chore|docs)\/[a-z0-9][a-z0-9-]*$/;
const AGENT_BRANCH_RE = /^agent\/[a-z0-9][a-z0-9-]*\/(feature|fix|chore|docs)\/[a-z0-9][a-z0-9-]*$/;
const RELEASE_BRANCH_RE = /^release\/\d+\.\d+\.\d+$/;
const SALVAGE_BRANCH_RE = /^salvage\/\d{4}-\d{2}-\d{2}-[a-z0-9-]+$/;

function validateBranchName(branch: string, isAgent: boolean): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  if (isAgent) {
    if (!AGENT_BRANCH_RE.test(branch)) {
      errors.push(`Agent branch must match: agent/{agent-id}/{type}/{description} — got: ${branch}`);
    }
  } else {
    const isValid = HUMAN_BRANCH_RE.test(branch)
      || RELEASE_BRANCH_RE.test(branch)
      || SALVAGE_BRANCH_RE.test(branch);
    if (!isValid) {
      errors.push(`Human branch must match: {type}/{description} — got: ${branch}`);
    }
  }

  return { valid: errors.length === 0, errors };
}

// ── Commit message validation (from gitworkflow-v1.md §4, §7.4) ────

const CO_AUTHORED_BY_RE = /Co-Authored-By:\s+.+\s+<.+>/;
const TASK_ID_RE = /Task:\s+.+/;
const MODEL_ID_RE = /Agent:\s+.+/;

// Common secret patterns (simplified — real implementation uses redaction from audit.ts)
const SECRET_PATTERNS = [
  /(?:api[_-]?key|secret|token|password|credential)\s*[:=]\s*\S{8,}/i,
  /sk-[a-zA-Z0-9]{20,}/,                    // OpenAI-style keys
  /maestro_secret_[a-zA-Z0-9]{32,}/,        // Maestro secrets (from security-v2.md)
  /sbx_token_[a-zA-Z0-9]{16,}/,             // Sandbox tokens (from security-v2.md)
  /ghp_[a-zA-Z0-9]{36}/,                    // GitHub PAT
  /-----BEGIN (RSA |EC )?PRIVATE KEY-----/,  // Private keys
];

function validateCommitMessage(message: string, agentId?: string): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  // Secret detection — applies to ALL commits
  for (const pattern of SECRET_PATTERNS) {
    if (pattern.test(message)) {
      errors.push(`Commit message appears to contain a secret matching: ${pattern.source}`);
    }
  }

  // Agent-specific attribution requirements
  if (agentId) {
    if (!CO_AUTHORED_BY_RE.test(message)) {
      errors.push('Agent commit must include Co-Authored-By trailer');
    }
    if (!TASK_ID_RE.test(message)) {
      errors.push('Agent commit must include Task: linkage');
    }
    if (!MODEL_ID_RE.test(message)) {
      errors.push('Agent commit must include Agent: model ID');
    }
  }

  return { valid: errors.length === 0, errors };
}

// ── Tests ───────────────────────────────────────────────────────────

describe('GitWorkflow contract', () => {

  // ── Branch naming (§2, §10.4) ──────────────────────────────────

  describe('branch naming — human branches', () => {
    it('accepts feature branches', () => {
      expect(validateBranchName('feature/filter-bar-redesign', false).valid).toBe(true);
    });

    it('accepts fix branches', () => {
      expect(validateBranchName('fix/toggle-border-styling', false).valid).toBe(true);
    });

    it('accepts chore branches', () => {
      expect(validateBranchName('chore/update-deps', false).valid).toBe(true);
    });

    it('accepts docs branches', () => {
      expect(validateBranchName('docs/api-reference', false).valid).toBe(true);
    });

    it('accepts release branches', () => {
      expect(validateBranchName('release/1.0.0', false).valid).toBe(true);
      expect(validateBranchName('release/2.3.14', false).valid).toBe(true);
    });

    it('accepts salvage branches', () => {
      expect(validateBranchName('salvage/2026-04-03-opus-4-6', false).valid).toBe(true);
    });

    it('rejects branches without type prefix', () => {
      expect(validateBranchName('my-feature', false).valid).toBe(false);
    });

    it('rejects branches with uppercase', () => {
      expect(validateBranchName('feature/FOO', false).valid).toBe(false);
    });

    it('rejects branches with spaces', () => {
      expect(validateBranchName('feature/foo bar', false).valid).toBe(false);
    });

    it('rejects bare main/master', () => {
      expect(validateBranchName('main', false).valid).toBe(false);
      expect(validateBranchName('master', false).valid).toBe(false);
    });

    it('rejects unknown type prefixes', () => {
      expect(validateBranchName('hotfix/urgent', false).valid).toBe(false);
      expect(validateBranchName('refactor/clean-up', false).valid).toBe(false);
    });
  });

  describe('branch naming — agent branches', () => {
    it('accepts valid agent branches', () => {
      expect(validateBranchName('agent/opus-4-6/feature/add-tests', true).valid).toBe(true);
    });

    it('accepts agent fix branches', () => {
      expect(validateBranchName('agent/opus-4-6/fix/null-check', true).valid).toBe(true);
    });

    it('rejects agent branches without agent-id namespace', () => {
      expect(validateBranchName('feature/add-tests', true).valid).toBe(false);
    });

    it('rejects agent branches without type segment', () => {
      expect(validateBranchName('agent/opus-4-6/add-tests', true).valid).toBe(false);
    });

    it('rejects agent branches with missing description', () => {
      expect(validateBranchName('agent/opus-4-6/feature/', true).valid).toBe(false);
    });
  });

  // ── Commit attribution (§4, §7.4) ─────────────────────────────

  describe('commit attribution — agent commits', () => {
    const validAgentMessage = [
      'feat(sandbox): add memory limit configuration',
      '',
      'Implements configurable memory limits for isolated-vm plugin.',
      '',
      'Task: work/tasks/sandbox-memory-limits.yml',
      'Agent: opus-4-6 via claude-code',
      '',
      'Co-Authored-By: opus-4-6 <agent@maestro.dev>',
    ].join('\n');

    it('accepts valid agent commit message', () => {
      expect(validateCommitMessage(validAgentMessage, 'opus-4-6').valid).toBe(true);
    });

    it('rejects agent commit without Co-Authored-By', () => {
      const msg = 'feat: add tests\n\nTask: work/tasks/foo.yml\nAgent: opus-4-6';
      expect(validateCommitMessage(msg, 'opus-4-6').valid).toBe(false);
      expect(validateCommitMessage(msg, 'opus-4-6').errors).toContain(
        'Agent commit must include Co-Authored-By trailer'
      );
    });

    it('rejects agent commit without Task linkage', () => {
      const msg = 'feat: add tests\n\nAgent: opus-4-6\n\nCo-Authored-By: opus-4-6 <agent@maestro.dev>';
      expect(validateCommitMessage(msg, 'opus-4-6').valid).toBe(false);
      expect(validateCommitMessage(msg, 'opus-4-6').errors).toContain(
        'Agent commit must include Task: linkage'
      );
    });

    it('rejects agent commit without Agent model ID', () => {
      const msg = 'feat: add tests\n\nTask: work/tasks/foo.yml\n\nCo-Authored-By: opus-4-6 <agent@maestro.dev>';
      expect(validateCommitMessage(msg, 'opus-4-6').valid).toBe(false);
      expect(validateCommitMessage(msg, 'opus-4-6').errors).toContain(
        'Agent commit must include Agent: model ID'
      );
    });
  });

  describe('commit attribution — human commits', () => {
    it('accepts human commit without agent attribution', () => {
      expect(validateCommitMessage('fix: correct null check in parser').valid).toBe(true);
    });

    it('does not require Co-Authored-By for human commits', () => {
      expect(validateCommitMessage('chore: update dependencies').valid).toBe(true);
    });
  });

  // ── Secret detection (§15) ────────────────────────────────────

  describe('secret detection in commit messages', () => {
    it('rejects commits containing API keys', () => {
      const msg = 'feat: add config\n\nAPI_KEY=sk-1234567890abcdefghijklmnop';
      expect(validateCommitMessage(msg).valid).toBe(false);
    });

    it('rejects commits containing GitHub PATs', () => {
      const msg = 'fix: auth\n\nUsed ghp_abcdefghijklmnopqrstuvwxyz0123456789';
      expect(validateCommitMessage(msg).valid).toBe(false);
    });

    it('rejects commits containing maestro secrets', () => {
      const msg = 'chore: config\n\nmaestro_secret_abcdefghijklmnopqrstuvwxyz012345';
      expect(validateCommitMessage(msg).valid).toBe(false);
    });

    it('rejects commits containing sandbox tokens', () => {
      const msg = 'fix: sandbox\n\nsbx_token_abcdefghijklmnop';
      expect(validateCommitMessage(msg).valid).toBe(false);
    });

    it('rejects commits containing private keys', () => {
      const msg = 'chore: add cert\n\n-----BEGIN RSA PRIVATE KEY-----\nfoo';
      expect(validateCommitMessage(msg).valid).toBe(false);
    });

    it('accepts commits without secrets', () => {
      expect(validateCommitMessage('feat: add new endpoint for user profiles').valid).toBe(true);
    });

    it('accepts commits mentioning secret-related words in context', () => {
      expect(validateCommitMessage('docs: document secret management architecture').valid).toBe(true);
    });
  });
});

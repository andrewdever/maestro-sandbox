import { describe, it, expect } from 'vitest';
import { validatePatch } from '../../patch-validator.js';

const workspaceRoot = '/workspace';

/** Helper to build a minimal valid unified diff targeting a given path. */
function makePatch(filePath: string, extra = ''): string {
  return [
    `diff --git a/${filePath} b/${filePath}`,
    `--- a/${filePath}`,
    `+++ b/${filePath}`,
    extra,
    `@@ -1,3 +1,4 @@`,
    ` line1`,
    `+added`,
    ` line2`,
  ].join('\n');
}

/** Helper to build a patch with extra lines injected into the diff body. */
function makePatchWithBody(filePath: string, bodyLines: string[]): string {
  return [
    `diff --git a/${filePath} b/${filePath}`,
    ...bodyLines,
    `--- a/${filePath}`,
    `+++ b/${filePath}`,
    `@@ -1,3 +1,4 @@`,
    ` line1`,
    `+added`,
    ` line2`,
  ].join('\n');
}

describe('Security: patch attacks', () => {
  describe('path traversal attacks', () => {
    it('rejects ../../etc/passwd', async () => {
      const result = await validatePatch(makePatch('../../etc/passwd'), workspaceRoot);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.rule === 'path-traversal')).toBe(true);
    });

    it('rejects ..\\..\\windows\\system32', async () => {
      const result = await validatePatch(makePatch('..\\..\\windows\\system32'), workspaceRoot);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.rule === 'path-traversal')).toBe(true);
    });

    it('rejects encoded traversal (%2e%2e%2f)', async () => {
      const result = await validatePatch(makePatch('%2e%2e%2fpasswd'), workspaceRoot);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.rule === 'path-traversal')).toBe(true);
    });

    it('rejects double-encoded traversal', async () => {
      const result = await validatePatch(makePatch('%252e%252e%252f'), workspaceRoot);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.rule === 'path-traversal')).toBe(true);
    });

    it('rejects null byte injection in paths', async () => {
      const result = await validatePatch(makePatch('src/foo%00../../etc/passwd'), workspaceRoot);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.rule === 'path-traversal')).toBe(true);
    });
  });

  describe('symlink attacks', () => {
    it('rejects patch creating symlink to /etc/passwd', async () => {
      const patch = makePatchWithBody('link.txt', ['new file mode 120000']);
      const result = await validatePatch(patch, workspaceRoot);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.rule === 'symlink-rejection')).toBe(true);
    });

    it('rejects patch creating symlink to parent directory', async () => {
      const patch = makePatchWithBody('parent-link', ['new file mode 120000']);
      const result = await validatePatch(patch, workspaceRoot);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.rule === 'symlink-rejection')).toBe(true);
    });

    it('rejects patch modifying existing symlink target', async () => {
      const patch = makePatchWithBody('existing-link', ['old mode 120000']);
      const result = await validatePatch(patch, workspaceRoot);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.rule === 'symlink-rejection')).toBe(true);
    });
  });

  describe('git hook injection', () => {
    it('rejects patch modifying .git/hooks/pre-commit', async () => {
      const result = await validatePatch(makePatch('.git/hooks/pre-commit'), workspaceRoot);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.rule === 'git-internals')).toBe(true);
    });

    it('rejects patch modifying .git/hooks/post-checkout', async () => {
      const result = await validatePatch(makePatch('.git/hooks/post-checkout'), workspaceRoot);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.rule === 'git-internals')).toBe(true);
    });

    it('rejects patch creating new hooks in .git/hooks/', async () => {
      const result = await validatePatch(makePatch('.git/hooks/newscript'), workspaceRoot);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.rule === 'git-internals')).toBe(true);
    });

    it('rejects patch modifying .git/config', async () => {
      const result = await validatePatch(makePatch('.git/config'), workspaceRoot);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.rule === 'git-internals')).toBe(true);
    });

    it('rejects patch modifying .git/HEAD', async () => {
      const result = await validatePatch(makePatch('.git/HEAD'), workspaceRoot);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.rule === 'git-internals')).toBe(true);
    });
  });

  describe('binary injection', () => {
    it('rejects patch containing binary blobs', async () => {
      const patch = [
        'diff --git a/image.png b/image.png',
        '--- a/image.png',
        '+++ b/image.png',
        'GIT binary patch',
        'literal 1234',
        'some binary data here',
      ].join('\n');
      const result = await validatePatch(patch, workspaceRoot);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.rule === 'binary-rejection')).toBe(true);
    });

    it('rejects patch with executable content', async () => {
      const patch = [
        'diff --git a/bin/tool b/bin/tool',
        'Binary files differ',
      ].join('\n');
      const result = await validatePatch(patch, workspaceRoot);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.rule === 'binary-rejection')).toBe(true);
    });

    it('detects binary disguised as text', async () => {
      // A patch with binary markers placed in an unusual position.
      // The validator should still detect the GIT binary patch marker
      // regardless of where it appears in the diff.
      const patch = [
        'diff --git a/src/data.bin b/src/data.bin',
        'GIT binary patch',
        'literal 100',
        '--- a/src/data.bin',
        '+++ b/src/data.bin',
        '@@ -1 +1 @@',
        '-old',
        '+new',
      ].join('\n');
      const result = await validatePatch(patch, workspaceRoot);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.rule === 'binary-rejection')).toBe(true);
    });
  });

  describe('workspace escape', () => {
    it('rejects absolute paths outside workspace', async () => {
      const result = await validatePatch(makePatch('/etc/passwd'), workspaceRoot);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.rule === 'workspace-confinement')).toBe(true);
    });

    it('rejects paths that resolve outside workspace after normalization', async () => {
      const result = await validatePatch(makePatch('../../etc/passwd'), workspaceRoot);
      expect(result.valid).toBe(false);
      // Should trigger both path-traversal and workspace-confinement (or at least one)
      const rules = result.errors.map(e => e.rule);
      expect(rules.includes('path-traversal') || rules.includes('workspace-confinement')).toBe(true);
    });

    it('confines all operations to workspace root', async () => {
      const result = await validatePatch(makePatch('src/utils.ts'), workspaceRoot);
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });
  });
});

import { describe, it, expect, vi } from 'vitest';
import { validatePatch } from '../../patch-validator.js';

const VALID_PATCH = `diff --git a/src/index.ts b/src/index.ts
--- a/src/index.ts
+++ b/src/index.ts
@@ -1,3 +1,4 @@
 line1
+new line
 line2
 line3
`;

const MULTI_FILE_PATCH = `diff --git a/src/a.ts b/src/a.ts
--- a/src/a.ts
+++ a/src/a.ts
@@ -1,1 +1,2 @@
 lineA
+added A
diff --git a/src/b.ts b/src/b.ts
--- a/src/b.ts
+++ b/src/b.ts
@@ -1,1 +1,2 @@
 lineB
+added B
`;

function makeLogger() {
  return {
    logPatch: vi.fn(async () => {}),
    logResult: vi.fn(async () => {}),
  };
}

describe('PatchValidator', () => {
  describe('structural parse', () => {
    it('accepts a valid unified diff patch', async () => {
      const result = await validatePatch(VALID_PATCH, '/workspace');
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('rejects malformed patch (not valid diff format)', async () => {
      const result = await validatePatch('not a real diff at all', '/workspace');
      expect(result.valid).toBe(false);
      expect(result.errors[0].rule).toBe('structural-parse');
    });

    it('rejects empty patch', async () => {
      const result = await validatePatch('', '/workspace');
      expect(result.valid).toBe(false);
      expect(result.errors[0].rule).toBe('structural-parse');
    });

    it('handles patches with multiple files', async () => {
      const result = await validatePatch(MULTI_FILE_PATCH, '/workspace');
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });
  });

  describe('path traversal', () => {
    it('rejects paths containing ../', async () => {
      const patch = `diff --git a/../../../etc/passwd b/../../../etc/passwd
--- a/../../../etc/passwd
+++ b/../../../etc/passwd
@@ -1,1 +1,2 @@
 root
+hacked
`;
      const result = await validatePatch(patch, '/workspace');
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.rule === 'path-traversal')).toBe(true);
    });

    it('rejects paths containing ..\\', async () => {
      const patch = `diff --git a/..\\..\\etc\\passwd b/..\\..\\etc\\passwd
--- a/..\\..\\etc\\passwd
+++ b/..\\..\\etc\\passwd
@@ -1,1 +1,2 @@
 root
+hacked
`;
      const result = await validatePatch(patch, '/workspace');
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.rule === 'path-traversal')).toBe(true);
    });

    it('normalizes paths before checking', async () => {
      const patch = `diff --git a/src/../src/index.ts b/src/../src/index.ts
--- a/src/../src/index.ts
+++ b/src/../src/index.ts
@@ -1,1 +1,2 @@
 line
+added
`;
      // src/../src/index.ts contains ".." segment — flagged as traversal
      const result = await validatePatch(patch, '/workspace');
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.rule === 'path-traversal')).toBe(true);
    });

    it('accepts paths that start with ./ (relative to workspace)', async () => {
      const patch = `diff --git a/./src/index.ts b/./src/index.ts
--- a/./src/index.ts
+++ b/./src/index.ts
@@ -1,1 +1,2 @@
 line
+added
`;
      const result = await validatePatch(patch, '/workspace');
      expect(result.valid).toBe(true);
    });

    it('rejects URL-encoded traversal (%2e%2e%2f)', async () => {
      const patch = `diff --git a/%2e%2e%2f%2e%2e%2fetc/passwd b/%2e%2e%2f%2e%2e%2fetc/passwd
--- a/%2e%2e%2f%2e%2e%2fetc/passwd
+++ b/%2e%2e%2f%2e%2e%2fetc/passwd
@@ -1,1 +1,2 @@
 root
+hacked
`;
      const result = await validatePatch(patch, '/workspace');
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.rule === 'path-traversal')).toBe(true);
    });
  });

  describe('symlink rejection', () => {
    it('rejects patches that create symlinks', async () => {
      const patch = `diff --git a/link b/link
new file mode 120000
--- /dev/null
+++ b/link
@@ -0,0 +1 @@
+../etc/passwd
`;
      const result = await validatePatch(patch, '/workspace');
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.rule === 'symlink-rejection')).toBe(true);
    });

    it('rejects patches that modify existing symlinks', async () => {
      const patch = `diff --git a/link b/link
old mode 120000
new mode 120000
--- a/link
+++ b/link
@@ -1 +1 @@
-old-target
+new-target
`;
      const result = await validatePatch(patch, '/workspace');
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.rule === 'symlink-rejection')).toBe(true);
    });

    it('accepts patches to regular files', async () => {
      const result = await validatePatch(VALID_PATCH, '/workspace');
      expect(result.valid).toBe(true);
      expect(result.errors.some(e => e.rule === 'symlink-rejection')).toBe(false);
    });
  });

  describe('binary rejection', () => {
    it('rejects binary blobs by default', async () => {
      const patch = `diff --git a/image.png b/image.png
GIT binary patch
literal 1234
zcmV;@1234abc

`;
      const result = await validatePatch(patch, '/workspace');
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.rule === 'binary-rejection')).toBe(true);
    });

    it('detects binary content in patch hunks', async () => {
      const patch = `diff --git a/data.bin b/data.bin
Binary files /dev/null and b/data.bin differ
`;
      const result = await validatePatch(patch, '/workspace');
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.rule === 'binary-rejection')).toBe(true);
    });

    it('accepts text-only patches', async () => {
      const result = await validatePatch(VALID_PATCH, '/workspace');
      expect(result.valid).toBe(true);
      expect(result.errors.some(e => e.rule === 'binary-rejection')).toBe(false);
    });
  });

  describe('workspace confinement', () => {
    it('rejects paths outside workspace root', async () => {
      const patch = `diff --git a//etc/passwd b//etc/passwd
--- a//etc/passwd
+++ b//etc/passwd
@@ -1,1 +1,2 @@
 root
+hacked
`;
      const result = await validatePatch(patch, '/workspace');
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.rule === 'workspace-confinement')).toBe(true);
    });

    it('accepts paths within workspace root', async () => {
      const result = await validatePatch(VALID_PATCH, '/workspace');
      expect(result.valid).toBe(true);
    });

    it('handles absolute paths correctly', async () => {
      const patch = `diff --git a//workspace/src/index.ts b//workspace/src/index.ts
--- a//workspace/src/index.ts
+++ b//workspace/src/index.ts
@@ -1,1 +1,2 @@
 line
+added
`;
      const result = await validatePatch(patch, '/workspace');
      expect(result.valid).toBe(true);
    });

    it('rejects paths that resolve outside workspace after normalization', async () => {
      const patch = `diff --git a/../../../etc/passwd b/../../../etc/passwd
--- a/../../../etc/passwd
+++ b/../../../etc/passwd
@@ -1,1 +1,2 @@
 root
+hacked
`;
      const result = await validatePatch(patch, '/workspace');
      expect(result.valid).toBe(false);
      // Should be caught by either path-traversal or workspace-confinement
      expect(result.errors.length).toBeGreaterThan(0);
    });
  });

  describe('git internals', () => {
    it('rejects modifications to .git/hooks/', async () => {
      const patch = `diff --git a/.git/hooks/post-checkout b/.git/hooks/post-checkout
--- a/.git/hooks/post-checkout
+++ b/.git/hooks/post-checkout
@@ -1,1 +1,2 @@
 #!/bin/sh
+malicious code
`;
      const result = await validatePatch(patch, '/workspace');
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.rule === 'git-internals')).toBe(true);
    });

    it('rejects modifications to .git/config', async () => {
      const patch = `diff --git a/.git/config b/.git/config
--- a/.git/config
+++ b/.git/config
@@ -1,1 +1,2 @@
 [core]
+\tfsmonitor = malicious
`;
      const result = await validatePatch(patch, '/workspace');
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.rule === 'git-internals')).toBe(true);
    });

    it('rejects modifications to any .git/ path', async () => {
      const patch = `diff --git a/.git/objects/ab/1234 b/.git/objects/ab/1234
--- a/.git/objects/ab/1234
+++ b/.git/objects/ab/1234
@@ -1,1 +1,2 @@
 blob
+tampered
`;
      const result = await validatePatch(patch, '/workspace');
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.rule === 'git-internals')).toBe(true);
    });

    it('accepts modifications to .gitignore (not .git/)', async () => {
      const patch = `diff --git a/.gitignore b/.gitignore
--- a/.gitignore
+++ b/.gitignore
@@ -1,1 +1,2 @@
 node_modules
+dist
`;
      const result = await validatePatch(patch, '/workspace');
      expect(result.valid).toBe(true);
    });

    it('accepts modifications to .github/ (not .git/)', async () => {
      const patch = `diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml
--- a/.github/workflows/ci.yml
+++ b/.github/workflows/ci.yml
@@ -1,1 +1,2 @@
 name: CI
+  push:
`;
      const result = await validatePatch(patch, '/workspace');
      expect(result.valid).toBe(true);
    });
  });

  describe('audit logging', () => {
    it('logs the full patch content for audit', async () => {
      const logger = makeLogger();
      await validatePatch(VALID_PATCH, '/workspace', logger);
      expect(logger.logPatch).toHaveBeenCalledWith(VALID_PATCH);
    });

    it('logs validation result (pass/fail)', async () => {
      const logger = makeLogger();
      await validatePatch(VALID_PATCH, '/workspace', logger);
      expect(logger.logResult).toHaveBeenCalledWith(
        expect.objectContaining({ valid: true }),
      );
    });

    it('logs specific rule failures', async () => {
      const logger = makeLogger();
      await validatePatch('garbage', '/workspace', logger);
      expect(logger.logResult).toHaveBeenCalledWith(
        expect.objectContaining({
          valid: false,
          errors: expect.arrayContaining([
            expect.objectContaining({ rule: 'structural-parse' }),
          ]),
        }),
      );
    });
  });

  describe('combined validation', () => {
    it('returns all errors (not just the first one)', async () => {
      // Patch with both symlink and git-internal violations
      const patch = `diff --git a/.git/hooks/evil b/.git/hooks/evil
new file mode 120000
--- /dev/null
+++ b/.git/hooks/evil
@@ -0,0 +1 @@
+target
`;
      const result = await validatePatch(patch, '/workspace');
      expect(result.valid).toBe(false);
      // Should have both git-internals and symlink-rejection errors
      const rules = result.errors.map(e => e.rule);
      expect(rules).toContain('git-internals');
      expect(rules).toContain('symlink-rejection');
    });

    it('returns valid: true when all rules pass', async () => {
      const result = await validatePatch(VALID_PATCH, '/workspace');
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('returns valid: false with errors when any rule fails', async () => {
      const result = await validatePatch('', '/workspace');
      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });
  });
});

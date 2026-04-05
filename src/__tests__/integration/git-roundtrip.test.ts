import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createGitAccess } from '../../git-access.js';
import { validatePatch } from '../../patch-validator.js';
import { createSandbox, resetCircuitBreakers } from '../../factory.js';
import type { Sandbox, SandboxConfig } from '../../types.js';
import { mkdtemp, rm, writeFile, readFile, mkdir, access, unlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { exec } from 'node:child_process';
import { promisify } from 'node:util';

const execAsync = promisify(exec);

/** Create a tarball containing the given files. Returns path to .tar file. */
async function createTarball(
  files: Record<string, string>,
): Promise<{ tarPath: string; tempDir: string }> {
  const tempDir = await mkdtemp(join(tmpdir(), 'maestro-tar-src-'));
  for (const [name, content] of Object.entries(files)) {
    const filePath = join(tempDir, name);
    await mkdir(join(filePath, '..'), { recursive: true });
    await writeFile(filePath, content, 'utf-8');
  }
  const tarPath = join(tempDir, '..', `maestro-test-${Date.now()}.tar`);
  await execAsync(`tar cf "${tarPath}" -C "${tempDir}" .`);
  return { tarPath, tempDir };
}

describe('Git round-trip (integration)', () => {
  let workdir: string;
  let git: ReturnType<typeof createGitAccess>;

  beforeEach(async () => {
    workdir = await mkdtemp(join(tmpdir(), 'maestro-git-test-'));
    git = createGitAccess(workdir);
  });

  afterEach(async () => {
    await rm(workdir, { recursive: true, force: true });
  });

  describe('inject', () => {
    it('injects a tarball into sandbox', async () => {
      const { tarPath, tempDir } = await createTarball({
        'hello.txt': 'hello world',
      });
      try {
        await git.inject(tarPath);
        const content = await readFile(join(workdir, 'hello.txt'), 'utf-8');
        expect(content).toBe('hello world');
      } finally {
        await rm(tempDir, { recursive: true, force: true });
        await rm(tarPath, { force: true });
      }
    });

    it('sandbox has own .git after injection', async () => {
      const { tarPath, tempDir } = await createTarball({
        'file.txt': 'content',
      });
      try {
        await git.inject(tarPath);
        await expect(
          access(join(workdir, '.git')),
        ).resolves.toBeUndefined();
      } finally {
        await rm(tempDir, { recursive: true, force: true });
        await rm(tarPath, { force: true });
      }
    });

    it('injected files are readable in sandbox', async () => {
      const { tarPath, tempDir } = await createTarball({
        'src/index.ts': 'export const x = 1;',
        'README.md': '# Test',
      });
      try {
        await git.inject(tarPath);
        const index = await readFile(join(workdir, 'src/index.ts'), 'utf-8');
        const readme = await readFile(join(workdir, 'README.md'), 'utf-8');
        expect(index).toBe('export const x = 1;');
        expect(readme).toBe('# Test');
      } finally {
        await rm(tempDir, { recursive: true, force: true });
        await rm(tarPath, { force: true });
      }
    });

    it('rejects invalid tarball', async () => {
      await expect(
        git.inject('/nonexistent/path/to/fake.tar'),
      ).rejects.toThrow();
    });
  });

  describe('work inside sandbox', () => {
    it('can modify files after injection', async () => {
      const { tarPath, tempDir } = await createTarball({
        'data.txt': 'original',
      });
      try {
        await git.inject(tarPath);
        await writeFile(join(workdir, 'data.txt'), 'modified', 'utf-8');
        const content = await readFile(join(workdir, 'data.txt'), 'utf-8');
        expect(content).toBe('modified');
      } finally {
        await rm(tempDir, { recursive: true, force: true });
        await rm(tarPath, { force: true });
      }
    });

    it('can create new files', async () => {
      const { tarPath, tempDir } = await createTarball({
        'existing.txt': 'exists',
      });
      try {
        await git.inject(tarPath);
        await writeFile(join(workdir, 'new-file.txt'), 'brand new', 'utf-8');
        const content = await readFile(join(workdir, 'new-file.txt'), 'utf-8');
        expect(content).toBe('brand new');
      } finally {
        await rm(tempDir, { recursive: true, force: true });
        await rm(tarPath, { force: true });
      }
    });

    it('can delete files', async () => {
      const { tarPath, tempDir } = await createTarball({
        'to-delete.txt': 'goodbye',
      });
      try {
        await git.inject(tarPath);
        await unlink(join(workdir, 'to-delete.txt'));
        await expect(
          access(join(workdir, 'to-delete.txt')),
        ).rejects.toThrow();
      } finally {
        await rm(tempDir, { recursive: true, force: true });
        await rm(tarPath, { force: true });
      }
    });

    it('git operations work inside sandbox', async () => {
      const { tarPath, tempDir } = await createTarball({
        'file.txt': 'content',
      });
      try {
        await git.inject(tarPath);
        const { stdout } = await execAsync('git status', { cwd: workdir });
        expect(stdout).toBeDefined();
        // After inject + commit, working tree should be clean
        expect(stdout).toContain('nothing to commit');
      } finally {
        await rm(tempDir, { recursive: true, force: true });
        await rm(tarPath, { force: true });
      }
    });
  });

  describe('export patch', () => {
    it('exports changes as git diff patch', async () => {
      const { tarPath, tempDir } = await createTarball({
        'code.ts': 'const a = 1;',
      });
      try {
        await git.inject(tarPath);
        // Modify a tracked file so git diff HEAD picks it up
        await writeFile(join(workdir, 'code.ts'), 'const a = 2;', 'utf-8');
        const patch = await git.exportPatch();
        expect(patch).toBeTruthy();
        expect(patch).toContain('code.ts');
        expect(patch).toContain('const a = 2');
      } finally {
        await rm(tempDir, { recursive: true, force: true });
        await rm(tarPath, { force: true });
      }
    });

    it('patch includes all modified files', async () => {
      const { tarPath, tempDir } = await createTarball({
        'a.txt': 'aaa',
        'b.txt': 'bbb',
      });
      try {
        await git.inject(tarPath);
        await writeFile(join(workdir, 'a.txt'), 'aaa-modified', 'utf-8');
        await writeFile(join(workdir, 'b.txt'), 'bbb-modified', 'utf-8');
        const patch = await git.exportPatch();
        expect(patch).toContain('a.txt');
        expect(patch).toContain('b.txt');
      } finally {
        await rm(tempDir, { recursive: true, force: true });
        await rm(tarPath, { force: true });
      }
    });

    it('patch includes new files', async () => {
      const { tarPath, tempDir } = await createTarball({
        'existing.txt': 'original',
      });
      try {
        await git.inject(tarPath);
        await writeFile(join(workdir, 'brand-new.txt'), 'new content', 'utf-8');
        // Stage the new file so git diff HEAD picks it up
        await execAsync('git add brand-new.txt', { cwd: workdir });
        const patch = await git.exportPatch();
        expect(patch).toContain('brand-new.txt');
        expect(patch).toContain('new content');
      } finally {
        await rm(tempDir, { recursive: true, force: true });
        await rm(tarPath, { force: true });
      }
    });

    it('patch includes deleted files', async () => {
      const { tarPath, tempDir } = await createTarball({
        'to-remove.txt': 'goodbye',
        'keep.txt': 'stay',
      });
      try {
        await git.inject(tarPath);
        await unlink(join(workdir, 'to-remove.txt'));
        // Stage the deletion so git diff HEAD picks it up
        await execAsync('git add -A', { cwd: workdir });
        const patch = await git.exportPatch();
        expect(patch).toContain('to-remove.txt');
      } finally {
        await rm(tempDir, { recursive: true, force: true });
        await rm(tarPath, { force: true });
      }
    });

    it('patch is empty when no changes', async () => {
      const { tarPath, tempDir } = await createTarball({
        'stable.txt': 'unchanged',
      });
      try {
        await git.inject(tarPath);
        const patch = await git.exportPatch();
        expect(patch).toBe('');
      } finally {
        await rm(tempDir, { recursive: true, force: true });
        await rm(tarPath, { force: true });
      }
    });
  });

  describe('validate and apply', () => {
    it('exported patch passes validation', async () => {
      const { tarPath, tempDir } = await createTarball({
        'src/main.ts': 'console.log("v1");',
      });
      try {
        await git.inject(tarPath);
        await writeFile(
          join(workdir, 'src/main.ts'),
          'console.log("v2");',
          'utf-8',
        );
        const patch = await git.exportPatch();
        const result = await validatePatch(patch, workdir);
        expect(result.valid).toBe(true);
        expect(result.errors).toHaveLength(0);
      } finally {
        await rm(tempDir, { recursive: true, force: true });
        await rm(tarPath, { force: true });
      }
    });

    it('validated patch applies cleanly to host repo', async () => {
      const { tarPath, tempDir } = await createTarball({
        'lib.ts': 'export const VERSION = "1.0.0";',
      });
      let targetDir: string | undefined;
      try {
        await git.inject(tarPath);
        await writeFile(join(workdir, 'lib.ts'), 'export const VERSION = "2.0.0";', 'utf-8');
        const patch = await git.exportPatch();
        const validation = await validatePatch(patch, workdir);
        expect(validation.valid).toBe(true);

        // Apply to a fresh target
        targetDir = await mkdtemp(join(tmpdir(), 'maestro-apply-'));
        await execAsync('git init', { cwd: targetDir });
        await execAsync('git config user.email "t@t.com"', { cwd: targetDir });
        await execAsync('git config user.name "T"', { cwd: targetDir });
        await execAsync(`tar xf "${tarPath}" -C "${targetDir}"`);
        await execAsync('git add -A && git commit -m "base"', { cwd: targetDir });

        const patchFile = join(targetDir, '.tmp-patch');
        await writeFile(patchFile, patch, 'utf-8');
        await expect(
          execAsync(`git apply "${patchFile}"`, { cwd: targetDir }),
        ).resolves.toBeDefined();
        await unlink(patchFile);
      } finally {
        await rm(tempDir, { recursive: true, force: true });
        await rm(tarPath, { force: true });
        if (targetDir) await rm(targetDir, { recursive: true, force: true });
      }
    });

    it('applied changes match sandbox modifications', async () => {
      const { tarPath, tempDir } = await createTarball({
        'config.json': '{"debug": false}',
      });
      let targetDir: string | undefined;
      try {
        await git.inject(tarPath);
        const newContent = '{"debug": true, "verbose": true}';
        await writeFile(join(workdir, 'config.json'), newContent, 'utf-8');
        const patch = await git.exportPatch();

        targetDir = await mkdtemp(join(tmpdir(), 'maestro-verify-'));
        await execAsync('git init', { cwd: targetDir });
        await execAsync('git config user.email "t@t.com"', { cwd: targetDir });
        await execAsync('git config user.name "T"', { cwd: targetDir });
        await execAsync(`tar xf "${tarPath}" -C "${targetDir}"`);
        await execAsync('git add -A && git commit -m "base"', { cwd: targetDir });

        const patchFile = join(targetDir, '.tmp-patch');
        await writeFile(patchFile, patch, 'utf-8');
        await execAsync(`git apply "${patchFile}"`, { cwd: targetDir });
        await unlink(patchFile);

        const applied = await readFile(join(targetDir, 'config.json'), 'utf-8');
        expect(applied).toBe(newContent);
      } finally {
        await rm(tempDir, { recursive: true, force: true });
        await rm(tarPath, { force: true });
        if (targetDir) await rm(targetDir, { recursive: true, force: true });
      }
    });
  });

  describe('full round-trip', () => {
    it('inject -> modify -> export -> validate -> apply -- complete cycle', async () => {
      const { tarPath, tempDir } = await createTarball({
        'app.ts': 'export function greet() { return "hello"; }',
      });
      let targetDir: string | undefined;
      try {
        // 1. Inject
        await git.inject(tarPath);

        // 2. Modify
        await writeFile(
          join(workdir, 'app.ts'),
          'export function greet() { return "goodbye"; }',
          'utf-8',
        );

        // 3. Export patch
        const patch = await git.exportPatch();
        expect(patch).toBeTruthy();

        // 4. Validate patch
        const result = await validatePatch(patch, workdir);
        expect(result.valid).toBe(true);

        // 5. Apply patch to a fresh copy with the same initial content
        targetDir = await mkdtemp(join(tmpdir(), 'maestro-git-target-'));
        // Set up the target as a git repo with the same base content
        await execAsync('git init', { cwd: targetDir });
        await execAsync('git config user.email "test@test.com"', {
          cwd: targetDir,
        });
        await execAsync('git config user.name "Test"', { cwd: targetDir });
        // Extract the same tarball into target
        await execAsync(`tar xf "${tarPath}" -C "${targetDir}"`);
        await execAsync('git add -A', { cwd: targetDir });
        await execAsync('git commit -m "base"', { cwd: targetDir });

        // Apply the patch — write to a temp file since execAsync doesn't support stdin
        const patchFile = join(targetDir, '.tmp-patch');
        await writeFile(patchFile, patch, 'utf-8');
        await execAsync(`git apply "${patchFile}"`, { cwd: targetDir });
        await unlink(patchFile);

        // 6. Verify the result matches
        const applied = await readFile(join(targetDir, 'app.ts'), 'utf-8');
        expect(applied).toBe(
          'export function greet() { return "goodbye"; }',
        );
      } finally {
        await rm(tempDir, { recursive: true, force: true });
        await rm(tarPath, { force: true });
        if (targetDir) await rm(targetDir, { recursive: true, force: true });
      }
    });

    it('multiple sequential round-trips work correctly', async () => {
      const { tarPath, tempDir } = await createTarball({
        'counter.txt': '0',
      });
      try {
        await git.inject(tarPath);

        // Round-trip 1: 0 → 1
        await writeFile(join(workdir, 'counter.txt'), '1', 'utf-8');
        const patch1 = await git.exportPatch();
        expect(patch1).toContain('1');

        // Commit the change so the next diff is clean
        await execAsync('git add -A && git commit -m "round1"', { cwd: workdir });

        // Round-trip 2: 1 → 2
        await writeFile(join(workdir, 'counter.txt'), '2', 'utf-8');
        const patch2 = await git.exportPatch();
        expect(patch2).toContain('2');

        // Both patches should be valid
        const r1 = await validatePatch(patch1, workdir);
        const r2 = await validatePatch(patch2, workdir);
        expect(r1.valid).toBe(true);
        expect(r2.valid).toBe(true);
      } finally {
        await rm(tempDir, { recursive: true, force: true });
        await rm(tarPath, { force: true });
      }
    });
  });

  describe('sandbox-level round-trip (isolated-vm)', () => {
    const sandboxes: Sandbox[] = [];
    const sandboxConfig: SandboxConfig = {
      limits: { memoryMB: 128, cpuMs: 5000, timeoutMs: 5000, networkAccess: false, filesystemAccess: 'tmpfs' },
    };

    afterEach(async () => {
      for (const sb of sandboxes) {
        await sb.destroy().catch(() => {});
      }
      sandboxes.length = 0;
      resetCircuitBreakers();
    });

    it('inject → fs.read → execute → fs.write → exportPatch → validate', async () => {
      const { tarPath, tempDir } = await createTarball({
        'data.json': JSON.stringify({ values: [1, 2, 3] }),
      });
      try {
        const sandbox = await createSandbox({ plugin: 'isolated-vm', config: sandboxConfig });
        sandboxes.push(sandbox);

        // 1. Inject code into sandbox
        await sandbox.git.inject(tarPath);

        // 2. Read injected file via sandbox.fs
        const raw = await sandbox.fs.read('work/data.json');
        expect(JSON.parse(raw)).toEqual({ values: [1, 2, 3] });

        // 3. Execute computation in the V8 isolate
        const result = await sandbox.execute(
          'return values.reduce((a, b) => a + b, 0)',
          { context: { values: [1, 2, 3] } },
        );
        expect(result.success).toBe(true);
        expect(result.result).toBe(6);

        // 4. Write result back via sandbox.fs (host-mediated for Tier 1)
        await sandbox.fs.write(
          'work/data.json',
          JSON.stringify({ values: [1, 2, 3], sum: result.result }),
        );

        // 5. Export patch
        const patch = await sandbox.git.exportPatch();
        expect(patch).toBeTruthy();
        expect(patch).toContain('data.json');
        expect(patch).toContain('"sum":6');

        // 6. Validate patch
        const validation = await validatePatch(patch, '/workspace');
        expect(validation.valid).toBe(true);
      } finally {
        await rm(tempDir, { recursive: true, force: true });
        await rm(tarPath, { force: true });
      }
    });

    it('multi-step orchestrator pattern: sandbox A computes, sandbox B applies', async () => {
      const { tarPath, tempDir } = await createTarball({
        'config.json': JSON.stringify({ version: 1, features: [] }),
      });
      try {
        // Sandbox A: analyze and compute
        const sbA = await createSandbox({ plugin: 'isolated-vm', config: sandboxConfig });
        sandboxes.push(sbA);
        await sbA.git.inject(tarPath);

        const analysisResult = await sbA.execute(
          'return { newVersion: config.version + 1, features: ["auth", "logging"] }',
          { context: { config: { version: 1, features: [] } } },
        );
        expect(analysisResult.success).toBe(true);

        // Host mediates: write A's result into A's filesystem
        const analysis = analysisResult.result as { newVersion: number; features: string[] };
        await sbA.fs.write(
          'work/config.json',
          JSON.stringify({ version: analysis.newVersion, features: analysis.features }),
        );

        // Export patch from A
        const patch = await sbA.git.exportPatch();
        expect(patch).toBeTruthy();

        // Validate before applying
        const validation = await validatePatch(patch, '/workspace');
        expect(validation.valid).toBe(true);

        // Sandbox B: verify the patch content makes sense
        const sbB = await createSandbox({ plugin: 'isolated-vm', config: sandboxConfig });
        sandboxes.push(sbB);
        const verifyResult = await sbB.execute(
          'return config.version === 2 && config.features.length === 2',
          { context: { config: { version: analysis.newVersion, features: analysis.features } } },
        );
        expect(verifyResult.success).toBe(true);
        expect(verifyResult.result).toBe(true);
      } finally {
        await rm(tempDir, { recursive: true, force: true });
        await rm(tarPath, { force: true });
      }
    });
  });
});

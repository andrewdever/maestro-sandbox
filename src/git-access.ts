import { execFile, spawn } from 'node:child_process';
import { writeFile, readFile, mkdir, unlink } from 'node:fs/promises';
import { join, resolve, relative } from 'node:path';
import { promisify } from 'node:util';
import type { SandboxGitAccess } from './types.js';

const execFileAsync = promisify(execFile);

/** Validate that a path doesn't escape the workdir. */
function confineToWorkdir(workdir: string, filePath: string): string {
  const abs = resolve(workdir, filePath);
  const rel = relative(workdir, abs);
  if (rel.startsWith('..') || resolve(workdir, rel) !== abs) {
    throw new Error(`Path escapes sandbox workdir: ${filePath}`);
  }
  return abs;
}

/** Run a git command safely in the workdir using execFile (no shell). */
async function git(workdir: string, args: string[]): Promise<string> {
  const { stdout } = await execFileAsync('git', args, { cwd: workdir });
  return stdout;
}

/** Run tar safely using spawn with args array (no shell interpolation). */
function tarExtract(tarPath: string, destDir: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn('tar', ['xf', tarPath, '-C', destDir], { stdio: 'pipe' });
    child.on('close', (code) => {
      if (code === 0) resolve();
      else reject(new Error(`tar extract failed with code ${code}`));
    });
    child.on('error', reject);
  });
}

/** Run tar create safely using spawn with args array (no shell interpolation). */
function tarCreate(tarPath: string, cwd: string, files: string[]): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn('tar', ['cf', tarPath, ...files], { cwd, stdio: 'pipe' });
    child.on('close', (code) => {
      if (code === 0) resolve();
      else reject(new Error(`tar create failed with code ${code}`));
    });
    child.on('error', reject);
  });
}

/**
 * Create a git access implementation for the inject/export pattern.
 *
 * V1: inject code via tarball or direct content, export changes as git diff patches.
 * The sandbox has its own `.git` directory and full git capabilities
 * within its isolated filesystem.
 *
 * @param workdir - Absolute path to the sandbox's working directory.
 * @returns Git access interface for inject/export operations.
 */
export function createGitAccess(workdir: string): SandboxGitAccess {
  let initialized = false;

  async function ensureGit(): Promise<void> {
    if (initialized) return;
    await mkdir(workdir, { recursive: true });
    await git(workdir, ['init']);
    await git(workdir, ['config', 'user.email', 'sandbox@maestro.dev']);
    await git(workdir, ['config', 'user.name', 'Maestro Sandbox']);
    // Create initial commit so diff works
    await writeFile(join(workdir, '.gitkeep'), '', 'utf-8');
    await git(workdir, ['add', '-A']);
    await git(workdir, ['commit', '-m', 'initial', '--allow-empty']);
    initialized = true;
  }

  return {
    async inject(source: string | Buffer): Promise<void> {
      await ensureGit();

      if (typeof source === 'string') {
        // Validate path doesn't contain null bytes
        if (source.includes('\0')) {
          throw new Error('Tarball path contains null bytes');
        }
        // Treat as a path to a tarball — use spawn (no shell)
        await tarExtract(source, workdir);
      } else {
        // Buffer — write as tarball then extract
        const tarPath = join(workdir, '.maestro-inject.tar');
        await writeFile(tarPath, source);
        await tarExtract(tarPath, workdir);
        await unlink(tarPath);
      }

      await git(workdir, ['add', '-A']);
      await git(workdir, ['commit', '-m', 'injected', '--allow-empty']);
    },

    async exportPatch(): Promise<string> {
      await ensureGit();
      return await git(workdir, ['diff', 'HEAD']);
    },

    async exportFiles(paths: string[]): Promise<Buffer> {
      await ensureGit();
      // Validate all paths are confined to workdir
      for (const p of paths) {
        confineToWorkdir(workdir, p);
      }
      const tarPath = join(workdir, '.maestro-export.tar');
      await tarCreate(tarPath, workdir, paths);
      const buf = await readFile(tarPath);
      await unlink(tarPath);
      return buf;
    },
  };
}

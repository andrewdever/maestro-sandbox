import { readFile, writeFile, mkdir, readdir, stat, rm, rename, realpath } from 'node:fs/promises';
import { resolve, relative, join } from 'node:path';
import type { SandboxFileAccess } from './types.js';

/**
 * Ensure the resolved path is inside the tmpdir. Prevents path traversal.
 */
function confine(tmpdir: string, filePath: string): string {
  // Strip null bytes — prevents truncation attacks on some platforms
  if (filePath.includes('\0')) {
    throw new Error(`Path contains null bytes: ${filePath}`);
  }
  const abs = resolve(tmpdir, filePath);
  const rel = relative(tmpdir, abs);
  if (rel.startsWith('..') || resolve(tmpdir, rel) !== abs) {
    throw new Error(`Path escapes sandbox tmpdir: ${filePath}`);
  }
  return abs;
}

/**
 * Confine + realpath check. For host-side file access (landlock, anthropic-sr),
 * a symlink inside the tmpdir could point outside it. After confinement we
 * resolve the real path and re-check that it's still inside the base.
 *
 * Only call this for paths that already exist on disk (reads/lists).
 * For writes, the parent dir is checked instead.
 */
async function confineWithRealpath(tmpdir: string, filePath: string): Promise<string> {
  const abs = confine(tmpdir, filePath);
  try {
    const real = await realpath(abs);
    const realBase = await realpath(tmpdir);
    const rel = relative(realBase, real);
    if (rel.startsWith('..') || resolve(realBase, rel) !== real) {
      throw new Error(`Symlink escapes sandbox tmpdir: ${filePath} → ${real}`);
    }
    return real;
  } catch (err) {
    // If the file doesn't exist yet, realpath fails — fall back to logical confinement
    if (err && typeof err === 'object' && 'code' in err && (err as { code: string }).code === 'ENOENT') {
      return abs;
    }
    throw err;
  }
}

/**
 * Create a tmpdir-based file access implementation.
 *
 * V1: all files live in a temporary directory scoped to the sandbox.
 * The tmpdir is created on initialization and cleaned up on `sandbox.destroy()`.
 *
 * @param tmpdir - Absolute path to the sandbox's temporary directory.
 * @returns File access interface bound to the tmpdir.
 */
export function createFileAccess(tmpdir: string): SandboxFileAccess {
  return {
    async read(path: string): Promise<string> {
      const abs = await confineWithRealpath(tmpdir, path);
      return await readFile(abs, 'utf-8');
    },

    async write(path: string, content: string): Promise<void> {
      const abs = confine(tmpdir, path);
      await mkdir(resolve(abs, '..'), { recursive: true });
      await writeFile(abs, content, 'utf-8');
    },

    async list(dir: string): Promise<string[]> {
      const abs = await confineWithRealpath(tmpdir, dir);
      return await readdir(abs);
    },
  };
}

// ---------------------------------------------------------------------------
// Tmpdir cleanup with secret scrubbing (§5, §13)
// ---------------------------------------------------------------------------

const CLEANUP_MAX_RETRIES = 3;
const CLEANUP_BACKOFF_MS = [100, 500, 2000];

/**
 * Cached tmpfs mount points. Parsed once from /proc/mounts on first call.
 * Mounts don't change mid-process in practice.
 */
let tmpfsMountPoints: string[] | null = null;

async function loadTmpfsMounts(): Promise<string[]> {
  if (tmpfsMountPoints !== null) return tmpfsMountPoints;
  tmpfsMountPoints = [];
  try {
    const mounts = await readFile('/proc/mounts', 'utf-8');
    for (const line of mounts.split('\n')) {
      const parts = line.split(' ');
      if (parts[2] === 'tmpfs' && parts[1]) {
        tmpfsMountPoints.push(parts[1]);
      }
    }
  } catch {
    // /proc/mounts not available (macOS, etc.) — assume disk-backed
  }
  return tmpfsMountPoints;
}

/**
 * Check if a path is backed by tmpfs (RAM-only, no disk persistence).
 * On Linux, checks cached /proc/mounts. On other platforms, returns false.
 */
async function isTmpfsBacked(dirPath: string): Promise<boolean> {
  const mounts = await loadTmpfsMounts();
  return mounts.some(mount => dirPath.startsWith(mount));
}

/**
 * Zero-fill all regular files in a directory tree.
 * Prevents secret recovery from disk sectors after deletion.
 */
async function zeroFillDir(dirPath: string): Promise<void> {
  const entries = await readdir(dirPath, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = join(dirPath, entry.name);
    if (entry.isDirectory()) {
      await zeroFillDir(fullPath);
    } else if (entry.isFile()) {
      const info = await stat(fullPath);
      if (info.size > 0) {
        await writeFile(fullPath, Buffer.alloc(info.size, 0));
      }
    }
    // Skip symlinks, sockets, etc. — don't follow them
  }
}

/**
 * Clean up a sandbox tmpdir with secret scrubbing.
 *
 * - On tmpfs: rm -rf (data is RAM-only, no disk persistence).
 * - On disk: zero-fill all files before rm -rf to prevent secret recovery.
 * - On failure: retry with backoff, then quarantine if all retries fail.
 *
 * @param tmpdir - Absolute path to the sandbox's tmpdir.
 * @param sandboxId - Sandbox ID for quarantine dir naming.
 * @param quarantineBase - Base path for quarantine dirs. Defaults to parent of tmpdir.
 * @returns Object indicating success, quarantine path, and any errors encountered.
 */
export async function cleanupTmpdir(
  tmpdir: string,
  sandboxId: string,
  quarantineBase?: string,
): Promise<{ cleaned: boolean; quarantinePath?: string; errors: Error[] }> {
  const onDisk = !(await isTmpfsBacked(tmpdir));
  const errors: Error[] = [];

  for (let attempt = 0; attempt < CLEANUP_MAX_RETRIES; attempt++) {
    try {
      // Zero-fill on disk-backed filesystems before deletion
      if (onDisk) {
        await zeroFillDir(tmpdir);
      }
      await rm(tmpdir, { recursive: true, force: true });
      return { cleaned: true, errors };
    } catch (err) {
      errors.push(err instanceof Error ? err : new Error(String(err)));
      if (attempt < CLEANUP_MAX_RETRIES - 1) {
        await new Promise(r => setTimeout(r, CLEANUP_BACKOFF_MS[attempt]));
      }
    }
  }

  // All retries failed — quarantine. Use sandboxId (UUID) to avoid collision.
  const base = quarantineBase ?? resolve(tmpdir, '..');
  const quarantinePath = join(base, `quarantine-${sandboxId}`);
  try {
    await rename(tmpdir, quarantinePath);
  } catch (err) {
    errors.push(err instanceof Error ? err : new Error(String(err)));
    // If even rename fails, leave tmpdir in place for orphan detection
  }
  return { cleaned: false, quarantinePath, errors };
}

import type { PatchValidationResult, PatchValidationError, PatchValidationRule } from './types.js';

/**
 * Audit logger interface for patch validation.
 *
 * Rule 7 (audit log) requires logging the full patch and validation result.
 * Pass a logger to `validatePatch()` to capture audit events.
 * If no logger is provided, audit logging is skipped (test/dev mode).
 */
export interface PatchAuditLogger {
  /** Log the raw patch content before validation. */
  logPatch(patch: string): Promise<void>;

  /** Log the validation result after all rules have run. */
  logResult(result: PatchValidationResult): Promise<void>;
}

/** Parse a unified diff to extract file paths. */
interface PatchFile {
  oldPath: string;
  newPath: string;
  isNewFile: boolean;
  isBinary: boolean;
  isSymlink: boolean;
  content: string;
}

/**
 * Parse a unified diff patch into structured file entries.
 * Rule 1: structural parse.
 */
function parsePatch(patch: string): PatchFile[] | null {
  if (!patch || patch.trim().length === 0) return null;

  const files: PatchFile[] = [];
  // Split by diff headers
  const diffSections = patch.split(/^diff --git /m).filter(s => s.trim().length > 0);

  if (diffSections.length === 0) return null;

  for (const section of diffSections) {
    const lines = section.split('\n');
    const headerLine = lines[0];

    // Parse "a/path b/path" or quoted paths like "a/path with spaces" from the first line.
    // Git quotes paths containing spaces, tabs, or special chars: "a/foo bar" "b/foo bar"
    const quotedMatch = headerLine.match(/^"?a\/(.+?)"?\s+"?b\/(.+?)"?\s*$/);
    const unquotedMatch = headerLine.match(/^a\/(.+?)\s+b\/(.+)/);
    const headerMatch = quotedMatch ?? unquotedMatch;
    if (!headerMatch) return null;

    const oldPath = headerMatch[1];
    const newPath = headerMatch[2];

    const content = lines.slice(1).join('\n');
    const isBinary = /^Binary files/.test(content) || /^GIT binary patch/m.test(content);
    const isNewFile = /^new file mode/m.test(content);
    const isSymlink = /^new file mode 120000/m.test(content) || /^old mode 120000/m.test(content) || /^new mode 120000/m.test(content);

    files.push({ oldPath, newPath, isNewFile, isBinary, isSymlink, content });
  }

  return files.length > 0 ? files : null;
}

/**
 * Normalize a path and check for traversal.
 * Rule 2: path traversal prevention.
 */
function hasPathTraversal(path: string): boolean {
  // Recursively URL-decode to catch double/triple-encoding attacks
  const MAX_DECODE_DEPTH = 10;
  let decoded = path;
  let prev = '';
  let depth = 0;
  while (decoded !== prev && depth < MAX_DECODE_DEPTH) {
    prev = decoded;
    try {
      decoded = decodeURIComponent(decoded);
    } catch {
      break; // malformed encoding — stop decoding
    }
    depth++;
  }
  // Check for .. in any form
  const segments = decoded.replace(/\\/g, '/').split('/');
  return segments.some(s => s === '..');
}

/**
 * Check if a normalized path is confined within the workspace root.
 * Rule 5: workspace confinement.
 */
function isInsideWorkspace(filePath: string, workspaceRoot: string): boolean {
  // Normalize: remove leading ./ and resolve any path components
  const cleaned = filePath.replace(/\\/g, '/').replace(/^\.\//, '');

  // If absolute, check it starts with workspace root
  if (cleaned.startsWith('/')) {
    const normalizedRoot = workspaceRoot.replace(/\\/g, '/').replace(/\/$/, '');
    return cleaned.startsWith(normalizedRoot + '/') || cleaned === normalizedRoot;
  }

  // Relative paths that don't traverse upward are fine
  return !hasPathTraversal(filePath);
}

/**
 * Check if a path targets .git/ internals.
 * Rule 6: git internals protection.
 */
function isGitInternal(path: string): boolean {
  const normalized = path.replace(/\\/g, '/');
  // .git/ or subdirectories — but NOT .gitignore, .github/, .gitattributes
  return /(?:^|\/)\.git\//.test(normalized);
}

/**
 * Validate a git patch before applying it to the host filesystem.
 *
 * Applies all 7 validation rules:
 * 1. **Structural parse** — parse the patch format, reject malformed patches
 * 2. **Path traversal** — normalize paths, reject `../` sequences
 * 3. **Symlink rejection** — reject patches that create symlinks
 * 4. **Binary rejection** — reject binary blobs by default
 * 5. **Workspace confinement** — all paths must be within the workspace root
 * 6. **Git internals** — reject modifications to `.git/` (prevents hook injection)
 * 7. **Audit log** — log the full patch for audit trail (via optional logger)
 *
 * @param patch - The raw git diff patch string from `sandbox.git.exportPatch()`.
 * @param workspaceRoot - The absolute path to the workspace root.
 * @param logger - Optional audit logger for rule 7. If omitted, audit logging is skipped.
 * @returns Validation result with `valid` flag and any errors.
 */
export async function validatePatch(
  patch: string,
  workspaceRoot: string,
  logger?: PatchAuditLogger,
): Promise<PatchValidationResult> {
  const errors: PatchValidationError[] = [];

  // Rule 7: audit log — log raw patch before validation
  if (logger) {
    await logger.logPatch(patch);
  }

  // Rule 1: structural parse
  const files = parsePatch(patch);
  if (!files) {
    errors.push({
      rule: 'structural-parse' as PatchValidationRule,
      message: 'Patch is malformed or empty',
    });
    const result: PatchValidationResult = { valid: false, errors };
    if (logger) await logger.logResult(result);
    return result;
  }

  // Rules 2-6: check each file
  for (const file of files) {
    for (const path of [file.oldPath, file.newPath]) {
      // Rule 2: path traversal
      if (hasPathTraversal(path)) {
        errors.push({
          rule: 'path-traversal' as PatchValidationRule,
          message: `Path contains traversal: ${path}`,
          path,
        });
      }

      // Rule 5: workspace confinement
      if (!isInsideWorkspace(path, workspaceRoot)) {
        errors.push({
          rule: 'workspace-confinement' as PatchValidationRule,
          message: `Path escapes workspace root: ${path}`,
          path,
        });
      }

      // Rule 6: git internals
      if (isGitInternal(path)) {
        errors.push({
          rule: 'git-internals' as PatchValidationRule,
          message: `Path modifies git internals: ${path}`,
          path,
        });
      }
    }

    // Rule 3: symlink rejection
    if (file.isSymlink) {
      errors.push({
        rule: 'symlink-rejection' as PatchValidationRule,
        message: `Patch creates or modifies symlink: ${file.newPath}`,
        path: file.newPath,
      });
    }

    // Rule 4: binary rejection
    if (file.isBinary) {
      errors.push({
        rule: 'binary-rejection' as PatchValidationRule,
        message: `Patch contains binary content: ${file.newPath}`,
        path: file.newPath,
      });
    }
  }

  const result: PatchValidationResult = {
    valid: errors.length === 0,
    errors,
  };

  // Rule 7: audit log — log validation result
  if (logger) {
    await logger.logResult(result);
  }

  return result;
}

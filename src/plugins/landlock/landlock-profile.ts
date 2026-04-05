/**
 * Landlock filesystem restriction profile (§9).
 *
 * V1 stub: defines the Landlock ruleset as typed constants.
 * V1.1: applied via Rust NAPI-RS using landlock_create_ruleset(2).
 *
 * Landlock is a Linux 5.13+ access control system that restricts
 * filesystem access without requiring root/capabilities.
 */

/**
 * Landlock access rights for filesystem operations.
 * Maps to LANDLOCK_ACCESS_FS_* constants from linux/landlock.h.
 */
export type LandlockFsAccess =
  | 'execute'
  | 'write_file'
  | 'read_file'
  | 'read_dir'
  | 'remove_dir'
  | 'remove_file'
  | 'make_char'
  | 'make_dir'
  | 'make_reg'
  | 'make_sock'
  | 'make_fifo'
  | 'make_block'
  | 'make_sym'
  | 'refer'
  | 'truncate';     // Landlock ABI v3 (kernel 6.2+)

/**
 * Landlock network access rights (kernel 5.18+).
 */
export type LandlockNetAccess =
  | 'bind_tcp'
  | 'connect_tcp';

export interface LandlockFsRule {
  /** Absolute path to grant access to. */
  path: string;
  /** Access rights granted for this path. */
  access: readonly LandlockFsAccess[];
}

export interface LandlockNetRule {
  /** Port to allow. */
  port: number;
  /** Access type. */
  access: readonly LandlockNetAccess[];
}

export interface LandlockProfile {
  /** Filesystem rules — paths and their access rights. */
  fsRules: LandlockFsRule[];
  /** Network rules (requires kernel 5.18+). */
  netRules: LandlockNetRule[];
  /** Handled filesystem access rights — everything not granted is denied. */
  handledFsAccess: readonly LandlockFsAccess[];
  /** Handled network access rights. */
  handledNetAccess: readonly LandlockNetAccess[];
}

/** All filesystem access rights that Landlock can restrict. */
const ALL_FS_ACCESS: readonly LandlockFsAccess[] = Object.freeze([
  'execute', 'write_file', 'read_file', 'read_dir',
  'remove_dir', 'remove_file', 'make_char', 'make_dir',
  'make_reg', 'make_sock', 'make_fifo', 'make_block',
  'make_sym', 'refer', 'truncate',
]);

/** All network access rights. */
const ALL_NET_ACCESS: readonly LandlockNetAccess[] = Object.freeze([
  'bind_tcp', 'connect_tcp',
]);

/** Read-only filesystem access. */
const READ_ONLY: readonly LandlockFsAccess[] = Object.freeze([
  'read_file', 'read_dir',
]);

/** Read-write access for tmpdir. */
const TMPDIR_ACCESS: readonly LandlockFsAccess[] = Object.freeze([
  'read_file', 'read_dir', 'write_file',
  'make_dir', 'make_reg', 'remove_dir', 'remove_file',
  'truncate', 'refer',
]);

/**
 * Build a Landlock profile for a sandbox.
 *
 * @param tmpDir - The sandbox's tmpdir (read-write)
 * @param nodePath - Path to the Node.js binary (execute)
 * @param networkPorts - Ports the sandbox may connect to (empty = no network)
 */
export function buildLandlockProfile(
  tmpDir: string,
  nodePath: string,
  networkPorts: number[] = [],
): LandlockProfile {
  const fsRules: LandlockFsRule[] = [
    // Sandbox tmpdir: full tmpdir access
    { path: tmpDir, access: TMPDIR_ACCESS },

    // Node.js binary: execute only
    { path: nodePath, access: ['execute', 'read_file'] },

    // Node.js standard library: read-only
    { path: '/usr/lib/node_modules', access: READ_ONLY },
    { path: '/usr/local/lib/node_modules', access: READ_ONLY },

    // System libraries needed by Node.js
    { path: '/lib', access: ['read_file'] },
    { path: '/lib64', access: ['read_file'] },
    { path: '/usr/lib', access: ['read_file'] },
    { path: '/usr/lib64', access: ['read_file'] },

    // /proc/self — needed for Node.js process inspection
    { path: '/proc/self', access: READ_ONLY },

    // /dev/null, /dev/urandom — needed for crypto and stdio
    { path: '/dev/null', access: ['read_file', 'write_file'] },
    { path: '/dev/urandom', access: ['read_file'] },
  ];

  const netRules: LandlockNetRule[] = networkPorts.map(port => ({
    port,
    access: ['connect_tcp'] as readonly LandlockNetAccess[],
  }));

  return {
    fsRules,
    netRules,
    handledFsAccess: ALL_FS_ACCESS,
    handledNetAccess: networkPorts.length > 0 ? ALL_NET_ACCESS : [],
  };
}

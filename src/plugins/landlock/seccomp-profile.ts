/**
 * Seccomp BPF allowlist profile definition (§9, Appendix C).
 *
 * V1 stub: defines the syscall allowlist as a typed constant.
 * V1.1: compiled to BPF via Rust NAPI-RS and loaded by the landlock plugin.
 *
 * The allowlist is the minimal set required by Node.js 20+ on Linux.
 * Syscalls not in this list are killed with SIGSYS.
 */

/**
 * Seccomp action applied to non-allowlisted syscalls.
 * KILL_PROCESS terminates the entire process (not just the thread).
 */
export type SeccompAction = 'KILL_PROCESS' | 'KILL_THREAD' | 'LOG' | 'ERRNO';

export interface SeccompProfile {
  /** Default action for syscalls not in the allowlist. */
  defaultAction: SeccompAction;
  /** Architecture filter. */
  arch: 'x86_64' | 'aarch64';
  /** Allowed syscalls. */
  allowlist: readonly string[];
}

/**
 * Minimal Node.js 20+ syscall allowlist for x86_64.
 *
 * Sources:
 * - strace of `node -e "process.exit(0)"` on Ubuntu 22.04
 * - Node.js libuv source (deps/uv/src/unix/)
 * - V8 isolate syscalls (mmap, mprotect for JIT)
 *
 * Review cadence: every Node.js major version bump.
 */
export const SECCOMP_PROFILE_X86_64: SeccompProfile = {
  defaultAction: 'KILL_PROCESS',
  arch: 'x86_64',
  allowlist: Object.freeze([
    // Process lifecycle
    'exit_group',
    'exit',
    'clone',
    'clone3',
    'wait4',
    'getpid',
    'getppid',
    'gettid',

    // Memory management (V8 JIT requires mmap + mprotect)
    'mmap',
    'munmap',
    'mprotect',
    'mremap',
    'brk',
    'madvise',

    // File I/O (required for tmpdir access)
    'read',
    'write',
    'readv',
    'writev',
    'pread64',
    'pwrite64',
    'open',
    'openat',
    'close',
    'fstat',
    'newfstatat',
    'stat',
    'lstat',
    'lseek',
    'access',
    'faccessat',
    'faccessat2',
    'fcntl',
    'ftruncate',
    'unlink',
    'unlinkat',
    'rename',
    'renameat',
    'renameat2',
    'mkdir',
    'mkdirat',
    'rmdir',
    'readlink',
    'readlinkat',
    'getcwd',
    'getdents64',

    // Signals
    'rt_sigaction',
    'rt_sigprocmask',
    'rt_sigreturn',
    'sigaltstack',

    // Timers (libuv event loop)
    'clock_gettime',
    'clock_getres',
    'gettimeofday',
    'nanosleep',
    'clock_nanosleep',

    // Epoll (libuv)
    'epoll_create1',
    'epoll_ctl',
    'epoll_wait',
    'epoll_pwait',
    'eventfd2',

    // Pipes (stdio)
    'pipe2',
    'dup',
    'dup2',
    'dup3',

    // Socket (only if network is enabled — handled separately)
    // Omitted from base profile. Network-enabled sandboxes
    // use a separate profile extension.

    // Futex (threading)
    'futex',
    'set_robust_list',
    'get_robust_list',

    // Memory info
    'sysinfo',
    'getrandom',

    // Misc required by Node.js
    'ioctl',
    'prctl',
    'arch_prctl',
    'set_tid_address',
    'prlimit64',
    'sched_getaffinity',
    'sched_yield',
    'uname',
  ]) as readonly string[],
};

/**
 * Minimal Node.js 20+ syscall allowlist for aarch64 (Apple Silicon Linux VMs).
 */
export const SECCOMP_PROFILE_AARCH64: SeccompProfile = {
  defaultAction: 'KILL_PROCESS',
  arch: 'aarch64',
  allowlist: Object.freeze([
    // aarch64 uses different syscall names for some operations
    'exit_group',
    'exit',
    'clone',
    'clone3',
    'wait4',
    'getpid',
    'getppid',
    'gettid',

    'mmap',
    'munmap',
    'mprotect',
    'mremap',
    'brk',
    'madvise',

    'read',
    'write',
    'readv',
    'writev',
    'pread64',
    'pwrite64',
    'openat',         // aarch64 has no open(), uses openat()
    'close',
    'fstat',
    'newfstatat',
    'lseek',
    'faccessat',
    'faccessat2',
    'fcntl',
    'ftruncate',
    'unlinkat',        // aarch64 has no unlink(), uses unlinkat()
    'renameat',
    'renameat2',
    'mkdirat',         // aarch64 has no mkdir(), uses mkdirat()
    'readlinkat',
    'getcwd',
    'getdents64',

    'rt_sigaction',
    'rt_sigprocmask',
    'rt_sigreturn',
    'sigaltstack',

    'clock_gettime',
    'clock_getres',
    'gettimeofday',
    'nanosleep',
    'clock_nanosleep',

    'epoll_create1',
    'epoll_ctl',
    'epoll_pwait',
    'eventfd2',

    'pipe2',
    'dup',
    'dup3',

    'futex',
    'set_robust_list',
    'get_robust_list',

    'sysinfo',
    'getrandom',

    'ioctl',
    'prctl',
    'set_tid_address',
    'prlimit64',
    'sched_getaffinity',
    'sched_yield',
    'uname',
  ]) as readonly string[],
};

/**
 * Network syscall extension — appended to the base allowlist
 * when `config.limits.networkAccess` is true.
 */
export const NETWORK_SYSCALLS = Object.freeze([
  'socket',
  'connect',
  'sendto',
  'recvfrom',
  'sendmsg',
  'recvmsg',
  'bind',
  'listen',
  'accept4',
  'getsockopt',
  'setsockopt',
  'getsockname',
  'getpeername',
  'shutdown',
]) as readonly string[];

/**
 * Build a complete seccomp profile for a sandbox configuration.
 */
export function buildSeccompProfile(
  arch: 'x86_64' | 'aarch64',
  networkEnabled: boolean,
): SeccompProfile {
  const base = arch === 'x86_64' ? SECCOMP_PROFILE_X86_64 : SECCOMP_PROFILE_AARCH64;

  if (!networkEnabled) {
    return base;
  }

  return {
    ...base,
    allowlist: Object.freeze([...base.allowlist, ...NETWORK_SYSCALLS]),
  };
}

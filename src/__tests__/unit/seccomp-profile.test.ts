import { describe, it, expect } from 'vitest';
import {
  SECCOMP_PROFILE_X86_64,
  SECCOMP_PROFILE_AARCH64,
  NETWORK_SYSCALLS,
  buildSeccompProfile,
} from '../../plugins/landlock/seccomp-profile.js';

describe('SeccompProfile', () => {
  it('x86_64 profile has KILL_PROCESS default action', () => {
    expect(SECCOMP_PROFILE_X86_64.defaultAction).toBe('KILL_PROCESS');
  });

  it('aarch64 profile has KILL_PROCESS default action', () => {
    expect(SECCOMP_PROFILE_AARCH64.defaultAction).toBe('KILL_PROCESS');
  });

  it('x86_64 allowlist includes essential syscalls', () => {
    const essential = ['read', 'write', 'mmap', 'mprotect', 'exit_group', 'clone'];
    for (const syscall of essential) {
      expect(SECCOMP_PROFILE_X86_64.allowlist).toContain(syscall);
    }
  });

  it('aarch64 allowlist uses openat instead of open', () => {
    expect(SECCOMP_PROFILE_AARCH64.allowlist).toContain('openat');
    expect(SECCOMP_PROFILE_AARCH64.allowlist).not.toContain('open');
  });

  it('base profiles do NOT include network syscalls', () => {
    for (const syscall of NETWORK_SYSCALLS) {
      expect(SECCOMP_PROFILE_X86_64.allowlist).not.toContain(syscall);
      expect(SECCOMP_PROFILE_AARCH64.allowlist).not.toContain(syscall);
    }
  });

  it('allowlists are frozen', () => {
    expect(Object.isFrozen(SECCOMP_PROFILE_X86_64.allowlist)).toBe(true);
    expect(Object.isFrozen(SECCOMP_PROFILE_AARCH64.allowlist)).toBe(true);
    expect(Object.isFrozen(NETWORK_SYSCALLS)).toBe(true);
  });

  describe('buildSeccompProfile', () => {
    it('returns base profile when network is disabled', () => {
      const profile = buildSeccompProfile('x86_64', false);
      expect(profile.allowlist).toEqual(SECCOMP_PROFILE_X86_64.allowlist);
    });

    it('appends network syscalls when network is enabled', () => {
      const profile = buildSeccompProfile('x86_64', true);
      expect(profile.allowlist.length).toBe(
        SECCOMP_PROFILE_X86_64.allowlist.length + NETWORK_SYSCALLS.length,
      );
      for (const syscall of NETWORK_SYSCALLS) {
        expect(profile.allowlist).toContain(syscall);
      }
    });

    it('selects correct arch profile', () => {
      const x86 = buildSeccompProfile('x86_64', false);
      const arm = buildSeccompProfile('aarch64', false);
      expect(x86.arch).toBe('x86_64');
      expect(arm.arch).toBe('aarch64');
    });
  });
});

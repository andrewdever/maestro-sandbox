/**
 * Stress/resource-exhaustion code fixtures for sandbox testing.
 *
 * These attempt to exhaust sandbox resources. The sandbox should
 * terminate them cleanly with appropriate error types.
 */

/** Infinite loop — should trigger timeout. */
export const INFINITE_LOOP = 'while (true) {}';

/** Memory bomb — should trigger OOM. */
export const MEMORY_BOMB = `
  const arr = [];
  while (true) arr.push(new Array(1e6));
`;

/** Fork bomb (Tier 2+ only) — should be blocked by seccomp. */
export const FORK_BOMB = `
  const { execSync } = require("child_process");
  execSync(":(){ :|:& };:");
`;

/** CPU-intensive computation — should trigger cpuMs limit. */
export const CPU_INTENSIVE = `
  let n = 0;
  while (true) n++;
`;

/** Deep recursion — should trigger stack overflow, not host crash. */
export const STACK_OVERFLOW = `
  function recurse() { return recurse(); }
  recurse();
`;

/** Large string allocation. */
export const LARGE_STRING = `
  let s = "x";
  for (let i = 0; i < 30; i++) s = s + s;
  return s.length;
`;

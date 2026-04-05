/**
 * Valid code fixtures for sandbox testing.
 *
 * These are code strings that should execute successfully
 * in any sandbox plugin.
 */

/** Simple expression that returns a number. */
export const RETURN_42 = 'return 42;';

/** String concatenation. */
export const STRING_CONCAT = 'return "hello" + " " + "world";';

/** JSON processing. */
export const JSON_ROUNDTRIP = `
  const obj = { name: "test", value: 123 };
  const json = JSON.stringify(obj);
  return JSON.parse(json);
`;

/** Async code. */
export const ASYNC_RESOLVE = `
  const result = await Promise.resolve("async-value");
  return result;
`;

/** Console output. */
export const CONSOLE_LOG = `
  console.log("hello from sandbox");
  return "done";
`;

/** Uses injected context. */
export const USE_CONTEXT = `
  return context.greeting + " " + context.name;
`;

/** Calls a host function. */
export const CALL_HOST_FUNCTION = `
  const result = await hostCall("echo", { message: "ping" });
  return result;
`;

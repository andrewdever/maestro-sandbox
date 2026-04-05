import { describe, it, expect, afterEach } from 'vitest';
import type { SandboxConfig, SandboxChunk } from '../../types.js';
import { SandboxTimeoutError } from '../../types.js';
import { createSandbox, resetCircuitBreakers } from '../../factory.js';
import type { Sandbox } from '../../types.js';

const defaultConfig: SandboxConfig = {
  limits: { memoryMB: 128, cpuMs: 5000, timeoutMs: 5000, networkAccess: false, filesystemAccess: 'tmpfs' },
};

describe('E2E: agent lifecycle', () => {
  const sandboxes: Sandbox[] = [];

  afterEach(async () => {
    for (const sb of sandboxes) {
      await sb.destroy().catch(() => {});
    }
    sandboxes.length = 0;
    resetCircuitBreakers();
  });

  async function makeSandbox(config: SandboxConfig = defaultConfig): Promise<Sandbox> {
    const sb = await createSandbox({ plugin: 'mock', config });
    sandboxes.push(sb);
    return sb;
  }

  describe('full lifecycle', () => {
    it('create sandbox → write file → execute code → read result → destroy', async () => {
      const sandbox = await makeSandbox();

      // Write a data file into the sandbox
      await sandbox.fs.write('input.json', JSON.stringify({ values: [1, 2, 3] }));

      // Execute code that processes the data
      const result = await sandbox.execute('return [1, 2, 3].reduce((a, b) => a + b, 0)');
      expect(result.success).toBe(true);
      expect(result.result).toBe(6);

      // Write output
      await sandbox.fs.write('output.txt', String(result.result));
      const output = await sandbox.fs.read('output.txt');
      expect(output).toBe('6');

      await sandbox.destroy();
    });

    it('sandbox cleanup after successful lifecycle', async () => {
      const sandbox = await makeSandbox();
      await sandbox.fs.write('test.txt', 'data');
      const result = await sandbox.execute('return "done"');
      expect(result.success).toBe(true);
      await sandbox.destroy();

      // After destroy, ready() should return false
      expect(await sandbox.ready()).toBe(false);
    });

    it('sandbox cleanup after failed execution', async () => {
      const sandbox = await makeSandbox();
      const result = await sandbox.execute('throw new Error("agent failed")');
      expect(result.success).toBe(false);

      // Sandbox should still be usable after a failed execution
      expect(await sandbox.ready()).toBe(true);
      await sandbox.destroy();
      expect(await sandbox.ready()).toBe(false);
    });

    it('sandbox cleanup after timeout', async () => {
      const config: SandboxConfig = {
        limits: { ...defaultConfig.limits, timeoutMs: 300 },
      };
      const sandbox = await makeSandbox(config);
      const result = await sandbox.execute('await new Promise(r => setTimeout(r, 10000))');
      expect(result.success).toBe(false);
      expect(result.error).toBeInstanceOf(SandboxTimeoutError);

      // Sandbox should still be destroyable after timeout
      await sandbox.destroy();
      expect(await sandbox.ready()).toBe(false);
    });
  });

  describe('multi-step pattern (orchestrator smoke test)', () => {
    it('sandbox A produces result, sandbox B consumes it via context', async () => {
      // Step 1: Sandbox A computes something
      const sandboxA = await makeSandbox();
      await sandboxA.fs.write('data.json', JSON.stringify({ items: [10, 20, 30] }));
      const resultA = await sandboxA.execute('return { sum: 10 + 20 + 30, count: 3 }');
      expect(resultA.success).toBe(true);

      // Step 2: Sandbox B receives A's result via context and processes further
      const sandboxB = await makeSandbox();
      const resultB = await sandboxB.execute(
        'return { average: previousResult.sum / previousResult.count }',
        { context: { previousResult: resultA.result } },
      );
      expect(resultB.success).toBe(true);
      expect((resultB.result as { average: number }).average).toBe(20);

      await sandboxA.destroy();
      await sandboxB.destroy();
    });

    it('multi-step file handoff via fs.write and fs.read', async () => {
      // Sandbox A writes an intermediate file
      const sandboxA = await makeSandbox();
      await sandboxA.fs.write('intermediate.json', JSON.stringify({ processed: true, data: [4, 5, 6] }));
      const intermediateContent = await sandboxA.fs.read('intermediate.json');

      // Sandbox B receives the file content
      const sandboxB = await makeSandbox();
      await sandboxB.fs.write('input.json', intermediateContent);
      const verifyContent = await sandboxB.fs.read('input.json');
      expect(JSON.parse(verifyContent)).toEqual({ processed: true, data: [4, 5, 6] });

      await sandboxA.destroy();
      await sandboxB.destroy();
    });

    it('validates result from combined multi-step workflow', async () => {
      // Step 1: Generate code
      const gen = await makeSandbox();
      const genResult = await gen.execute('return "return 2 + 2"');
      expect(genResult.success).toBe(true);

      // Step 2: Execute the generated code in a fresh sandbox
      const exec = await makeSandbox();
      const execResult = await exec.execute(genResult.result as string);
      expect(execResult.success).toBe(true);
      expect(execResult.result).toBe(4);

      await gen.destroy();
      await exec.destroy();
    });

    it('each sandbox is independently isolated', async () => {
      const sandboxA = await makeSandbox();
      const sandboxB = await makeSandbox();

      await sandboxA.fs.write('a-only.txt', 'from A');
      await sandboxB.fs.write('b-only.txt', 'from B');

      // A should not see B's file and vice versa
      await expect(sandboxA.fs.read('b-only.txt')).rejects.toThrow();
      await expect(sandboxB.fs.read('a-only.txt')).rejects.toThrow();

      await sandboxA.destroy();
      await sandboxB.destroy();
    });
  });

  describe('streaming', () => {
    it('executeStream produces stdout chunks', async () => {
      const sandbox = await makeSandbox();
      const chunks: SandboxChunk[] = [];
      for await (const chunk of sandbox.executeStream('console.log("line1"); console.log("line2")')) {
        chunks.push(chunk);
      }
      const stdoutChunks = chunks.filter(c => c.stream === 'stdout');
      expect(stdoutChunks.length).toBeGreaterThanOrEqual(1);
      expect(stdoutChunks.some(c => c.data === 'line1')).toBe(true);
      expect(stdoutChunks.some(c => c.data === 'line2')).toBe(true);
    });

    it('executeStream produces stderr chunks on error', async () => {
      const sandbox = await makeSandbox();
      const chunks: SandboxChunk[] = [];
      for await (const chunk of sandbox.executeStream('throw new Error("stream err")')) {
        chunks.push(chunk);
      }
      const stderrChunks = chunks.filter(c => c.stream === 'stderr');
      expect(stderrChunks.length).toBeGreaterThanOrEqual(1);
      expect(stderrChunks.some(c => c.data.includes('stream err'))).toBe(true);
    });

    it('chunks have data, timestamp, and stream fields', async () => {
      const sandbox = await makeSandbox();
      const chunks: SandboxChunk[] = [];
      for await (const chunk of sandbox.executeStream('console.log("check")')) {
        chunks.push(chunk);
      }
      expect(chunks.length).toBeGreaterThan(0);
      for (const chunk of chunks) {
        expect(chunk).toHaveProperty('stream');
        expect(chunk).toHaveProperty('data');
        expect(chunk).toHaveProperty('timestamp');
        expect(typeof chunk.data).toBe('string');
        expect(typeof chunk.timestamp).toBe('number');
        expect(['stdout', 'stderr']).toContain(chunk.stream);
      }
    });

    it('stream terminates on completion', async () => {
      const sandbox = await makeSandbox();
      const chunks: SandboxChunk[] = [];
      for await (const chunk of sandbox.executeStream('console.log("done")')) {
        chunks.push(chunk);
      }
      // If we got here, the stream terminated
      expect(chunks.length).toBeGreaterThan(0);
    });

    it('stream terminates on timeout', async () => {
      const config: SandboxConfig = {
        limits: { ...defaultConfig.limits, timeoutMs: 300 },
      };
      const sandbox = await makeSandbox(config);
      const chunks: SandboxChunk[] = [];
      for await (const chunk of sandbox.executeStream('await new Promise(r => setTimeout(r, 10000))')) {
        chunks.push(chunk);
      }
      // Stream should terminate — the timeout error yields a stderr chunk
      const stderrChunks = chunks.filter(c => c.stream === 'stderr');
      expect(stderrChunks.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('concurrent sandboxes', () => {
    it('multiple sandboxes run concurrently without interference', async () => {
      const sb1 = await makeSandbox();
      const sb2 = await makeSandbox();
      const sb3 = await makeSandbox();

      const [r1, r2, r3] = await Promise.all([
        sb1.execute('return 1'),
        sb2.execute('return 2'),
        sb3.execute('return 3'),
      ]);

      expect(r1.success).toBe(true);
      expect(r1.result).toBe(1);
      expect(r2.success).toBe(true);
      expect(r2.result).toBe(2);
      expect(r3.success).toBe(true);
      expect(r3.result).toBe(3);
    });

    it('each sandbox has its own tmpdir', async () => {
      const sb1 = await makeSandbox();
      const sb2 = await makeSandbox();
      const sb3 = await makeSandbox();

      await sb1.fs.write('file.txt', 'sandbox1');
      await sb2.fs.write('file.txt', 'sandbox2');
      await sb3.fs.write('file.txt', 'sandbox3');

      expect(await sb1.fs.read('file.txt')).toBe('sandbox1');
      expect(await sb2.fs.read('file.txt')).toBe('sandbox2');
      expect(await sb3.fs.read('file.txt')).toBe('sandbox3');
    });

    it('destroying one sandbox does not affect others', async () => {
      const sb1 = await makeSandbox();
      const sb2 = await makeSandbox();
      const sb3 = await makeSandbox();

      await sb1.fs.write('data.txt', 'keep');
      await sb2.fs.write('data.txt', 'keep');
      await sb3.fs.write('data.txt', 'discard');

      // Destroy sb3
      await sb3.destroy();
      expect(await sb3.ready()).toBe(false);

      // sb1 and sb2 should still work
      expect(await sb1.ready()).toBe(true);
      expect(await sb2.ready()).toBe(true);
      expect(await sb1.fs.read('data.txt')).toBe('keep');
      expect(await sb2.fs.read('data.txt')).toBe('keep');

      const r1 = await sb1.execute('return "still alive"');
      expect(r1.success).toBe(true);
      expect(r1.result).toBe('still alive');
    });
  });
});

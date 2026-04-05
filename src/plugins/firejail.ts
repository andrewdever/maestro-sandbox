import type { SandboxPlugin, SandboxConfig, Sandbox } from '../types.js';

/**
 * Tier 2: Firejail sandbox plugin (Linux only).
 *
 * Battle-tested (6k+ stars), CLI-based. Ships in V1.1.
 *
 * ~100-150 LOC when implemented.
 */
const firejailPlugin: SandboxPlugin = {
  name: 'firejail',
  version: '0.0.1',
  requiredCoreVersion: '>=0.0.1',
  isolationLevel: 'process',

  async create(_config: SandboxConfig): Promise<Sandbox> {
    throw new Error('Not implemented — V1.1');
  },
};

export default firejailPlugin;

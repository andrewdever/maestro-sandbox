import type { SandboxPlugin, SandboxConfig, Sandbox } from '../types.js';

/**
 * Tier 2: Docker Process Isolation plugin (Windows).
 *
 * Kernel-sharing containers. Fast but weaker isolation. Ships in V1.1.
 *
 * ~100 LOC when implemented.
 */
const dockerPiPlugin: SandboxPlugin = {
  name: 'docker-pi',
  version: '0.0.1',
  requiredCoreVersion: '>=0.0.1',
  isolationLevel: 'container',

  async create(_config: SandboxConfig): Promise<Sandbox> {
    throw new Error('Not implemented — V1.1');
  },
};

export default dockerPiPlugin;

import type { SandboxPlugin, SandboxConfig, Sandbox } from '../types.js';

/**
 * Tier 3: Microsandbox plugin.
 *
 * Cross-platform, sub-200ms startup via libkrun VMM. Ships in V1.1.
 *
 * ~100-150 LOC when implemented.
 */
const microsandboxPlugin: SandboxPlugin = {
  name: 'microsandbox',
  version: '0.0.1',
  requiredCoreVersion: '>=0.0.1',
  isolationLevel: 'microvm',

  async create(_config: SandboxConfig): Promise<Sandbox> {
    throw new Error('Not implemented — V1.1');
  },
};

export default microsandboxPlugin;

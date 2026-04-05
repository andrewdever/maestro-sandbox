import type { PluginRegistry } from '../types.js';

/**
 * Dynamic plugin registry.
 *
 * Only the plugin named in `maestro.config.ts` gets loaded at runtime.
 * All others are never imported — dynamic `import()` ensures tree-shaking
 * and zero overhead for unused plugins.
 */
export const PLUGINS: PluginRegistry = {
  'isolated-vm': () => import('./isolated-vm.js'),
  'anthropic-sr': () => import('./anthropic-sr.js'),
  'landlock': () => import('./landlock/index.js'),
  'firejail': () => import('./firejail.js'),
  'docker-pi': () => import('./docker-pi.js'),
  'docker': () => import('./docker.js'),
  'microsandbox': () => import('./microsandbox.js'),
  'e2b': () => import('./e2b.js'),
  'openshell': () => import('./openshell.js'),
  'mock': () => import('./mock.js'),
};

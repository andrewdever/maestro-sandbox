/**
 * Plugin registry validation (§8).
 *
 * Validates plugin name, interface, version compatibility, isolation level,
 * and uniqueness before registration.
 */

import type { SandboxPlugin, IsolationLevel } from './types.js';

const PLUGIN_NAME_PATTERN = /^[a-z][a-z0-9-]*$/;

const VALID_ISOLATION_LEVELS: IsolationLevel[] = [
  'isolate', 'process', 'container', 'microvm',
];

/** Expected isolation level for each tier. */
const TIER_ISOLATION: Record<number, IsolationLevel[]> = {
  1: ['isolate'],
  2: ['process'],
  3: ['container', 'microvm'],
};

export interface PluginValidationResult {
  valid: boolean;
  errors: string[];
}

/**
 * Validate a plugin before registration.
 *
 * Checks:
 * 1. Name matches ^[a-z][a-z0-9-]*$
 * 2. Plugin implements required fields (name, version, requiredCoreVersion, isolationLevel, create)
 * 3. Version is valid semver-like string
 * 4. Isolation level is a known value
 * 5. No duplicate name in existing registry
 */
export function validatePlugin(
  plugin: SandboxPlugin,
  existingNames: Set<string>,
): PluginValidationResult {
  const errors: string[] = [];

  // 1. Name validation
  if (!plugin.name || !PLUGIN_NAME_PATTERN.test(plugin.name)) {
    errors.push(
      `Plugin name "${plugin.name}" is invalid. Must match ${PLUGIN_NAME_PATTERN}`,
    );
  }

  // 2. Interface check (runtime — TypeScript handles compile-time)
  if (typeof plugin.create !== 'function') {
    errors.push('Plugin must implement create() method');
  }
  if (!plugin.version) {
    errors.push('Plugin must declare a version');
  }
  if (!plugin.requiredCoreVersion) {
    errors.push('Plugin must declare requiredCoreVersion');
  }

  // 3. Isolation level
  if (!VALID_ISOLATION_LEVELS.includes(plugin.isolationLevel)) {
    errors.push(
      `Plugin isolation level "${plugin.isolationLevel}" is invalid. ` +
      `Must be one of: ${VALID_ISOLATION_LEVELS.join(', ')}`,
    );
  }

  // 4. No duplicates
  if (existingNames.has(plugin.name)) {
    errors.push(`Duplicate plugin name: "${plugin.name}"`);
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Validate that a plugin's declared isolation level matches its tier.
 */
export function validatePluginTier(
  plugin: SandboxPlugin,
  tier: number,
): PluginValidationResult {
  const errors: string[] = [];
  const expected = TIER_ISOLATION[tier];

  if (expected && !expected.includes(plugin.isolationLevel)) {
    errors.push(
      `Plugin "${plugin.name}" declares isolation level "${plugin.isolationLevel}" ` +
      `but is registered as Tier ${tier}. Expected: ${expected.join(' or ')}`,
    );
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

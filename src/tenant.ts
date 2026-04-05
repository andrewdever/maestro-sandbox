/**
 * Multi-Tenant Isolation Utilities (§5).
 *
 * Namespace-prefix scheme (Option D) for tenant isolation.
 * All sandbox IDs, audit events, and messages carry tenant context.
 *
 * Design constraints:
 * - No cross-tenant request batching. Each tenant's requests are processed
 *   independently. Batching across tenants is forbidden to prevent side-channel
 *   leakage via timing or error correlation.
 * - Per-tenant API key plumbing is Phase 2. Currently, tenant identity is
 *   carried via namespace prefix only. JWT-based auth at ingress boundary
 *   is planned for P2.
 */

// ---------------------------------------------------------------------------
// Type Aliases
// ---------------------------------------------------------------------------

/** Tenant ID format: lowercase alphanumeric + hyphens, 3-63 chars. */
export type TenantId = string;

/** A namespaced sandbox ID: `{tenantId}:{sandboxId}`. */
export type NamespacedId = string;

// ---------------------------------------------------------------------------
// Isolation Tier
// ---------------------------------------------------------------------------

/**
 * Namespace isolation (Option D) is NOT HIPAA-eligible.
 * Process isolation (Option C) required for HIPAA BAA compliance.
 * See P2 backlog for Dedicated Isolation tier.
 */
export const ISOLATION_TIER = {
  current: 'namespace' as const,
  hipaaEligible: false,
  dedicatedIsolationStatus: 'P2-planned' as const,
} as const;

// ---------------------------------------------------------------------------
// Separator
// ---------------------------------------------------------------------------

/**
 * The separator between tenant ID and sandbox ID in namespaced IDs.
 * Using a character that is NOT valid in tenant IDs to prevent ambiguity.
 */
const NAMESPACE_SEPARATOR = ':';

/**
 * The separator between signal and namespaced sandbox ID in breach counter keys.
 */
const BREACH_KEY_SEPARATOR = '::';

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/** Tenant ID regex: 3-63 chars, lowercase alphanumeric + hyphens, starts with letter, no leading/trailing/consecutive hyphens. */
const TENANT_ID_REGEX = /^[a-z][a-z0-9]*(-[a-z0-9]+)*$/;

/**
 * Validate a tenant ID format.
 *
 * Rules:
 * - 3-63 characters
 * - Lowercase alphanumeric + hyphens only
 * - Must start with a letter
 * - Must not start or end with hyphen
 * - Must not contain consecutive hyphens
 */
export function validateTenantId(tenantId: string): { valid: boolean; error?: string } {
  if (tenantId.length < 3) {
    return { valid: false, error: `Tenant ID too short: ${tenantId.length} chars (minimum 3)` };
  }
  if (tenantId.length > 63) {
    return { valid: false, error: `Tenant ID too long: ${tenantId.length} chars (maximum 63)` };
  }
  if (tenantId.startsWith('-')) {
    return { valid: false, error: 'Tenant ID must not start with a hyphen' };
  }
  if (tenantId.endsWith('-')) {
    return { valid: false, error: 'Tenant ID must not end with a hyphen' };
  }
  if (tenantId.includes('--')) {
    return { valid: false, error: 'Tenant ID must not contain consecutive hyphens' };
  }
  if (!TENANT_ID_REGEX.test(tenantId)) {
    return { valid: false, error: 'Tenant ID must be lowercase alphanumeric + hyphens, starting with a letter' };
  }
  return { valid: true };
}

// ---------------------------------------------------------------------------
// Namespace Operations
// ---------------------------------------------------------------------------

/** Create a namespaced sandbox ID: `{tenantId}:{sandboxId}`. */
export function namespaceSandboxId(tenantId: TenantId, sandboxId: string): NamespacedId {
  const validation = validateTenantId(tenantId);
  if (!validation.valid) {
    throw new Error(`Invalid tenant ID: ${validation.error}`);
  }
  return `${tenantId}${NAMESPACE_SEPARATOR}${sandboxId}`;
}

/** Extract tenant ID from a namespaced sandbox ID. Returns undefined if not namespaced. */
export function extractTenantId(namespacedId: string): TenantId | undefined {
  const idx = namespacedId.indexOf(NAMESPACE_SEPARATOR);
  if (idx === -1) return undefined;
  const candidate = namespacedId.slice(0, idx);
  const validation = validateTenantId(candidate);
  return validation.valid ? candidate : undefined;
}

/** Extract the bare sandbox ID from a namespaced ID. Returns the full ID if not namespaced. */
export function extractSandboxId(namespacedId: string): string {
  const idx = namespacedId.indexOf(NAMESPACE_SEPARATOR);
  if (idx === -1) return namespacedId;
  return namespacedId.slice(idx + 1);
}

/** Check if two namespaced IDs belong to the same tenant. */
export function sameTenant(id1: string, id2: string): boolean {
  const t1 = extractTenantId(id1);
  const t2 = extractTenantId(id2);
  if (t1 === undefined || t2 === undefined) return false;
  return t1 === t2;
}

// ---------------------------------------------------------------------------
// Key Construction (security review condition #4, #5, #6)
// ---------------------------------------------------------------------------

/**
 * Create a tenant-scoped key for Maps/counters.
 * ALWAYS use this instead of raw string concatenation (security review condition #4).
 */
export function tenantScopedKey(tenantId: TenantId, key: string): string {
  const validation = validateTenantId(tenantId);
  if (!validation.valid) {
    throw new Error(`Invalid tenant ID: ${validation.error}`);
  }
  return `${tenantId}${NAMESPACE_SEPARATOR}${key}`;
}

/**
 * Tenant-aware breach counter key construction.
 * Enforces consistent formatting — no raw concatenation allowed.
 *
 * Format: `{signal}::{namespacedSandboxId}`
 * Uses '::' as separator to avoid collision with the ':' in namespaced IDs.
 */
export function breachCounterKey(signal: string, namespacedSandboxId: string): string {
  return `${signal}${BREACH_KEY_SEPARATOR}${namespacedSandboxId}`;
}

// ---------------------------------------------------------------------------
// Assertion Helper (security review condition #3)
// ---------------------------------------------------------------------------

/**
 * Assert that a tenant ID is present on an object.
 * Use as a lint/type guard in multi-tenant mode to ensure tenant context
 * is always propagated.
 *
 * @throws If tenantId is missing or invalid.
 */
export function assertTenantId(obj: { tenantId?: string }, context?: string): asserts obj is { tenantId: string } {
  if (!obj.tenantId) {
    throw new Error(`Missing tenantId${context ? ` in ${context}` : ''}: multi-tenant mode requires tenant context on all messages`);
  }
  const validation = validateTenantId(obj.tenantId);
  if (!validation.valid) {
    throw new Error(`Invalid tenantId${context ? ` in ${context}` : ''}: ${validation.error}`);
  }
}

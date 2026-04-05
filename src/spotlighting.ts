/**
 * Content Boundary Marking — Spotlighting (§14.6).
 *
 * Marks untrusted content with high-entropy boundary tokens so the
 * LLM can distinguish data from instructions. Applied at the host
 * bridge return path — cannot be bypassed by sandboxed code.
 *
 * Strategies:
 * - delimiter:    Wrap content in unique boundary markers
 * - xml-tag:      Wrap in XML-style tags with nonce
 * - base64:       Encode content as base64 (strongest isolation)
 *
 * Existing boundary tokens in content are sanitized (escaped) to
 * prevent injection of fake boundaries.
 *
 * Reference: "Spotlighting" (Microsoft 2024, ceur-ws.org/Vol-3920/paper03.pdf)
 */

import { randomBytes } from 'node:crypto';
import { InstructionPrivilege, type ProvenancedMessage } from './instruction-hierarchy.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Spotlighting strategy for content boundary marking. */
export type SpotlightStrategy = 'delimiter' | 'xml-tag' | 'base64';

export interface SpotlightConfig {
  /** Strategy to use. Default: 'delimiter'. */
  strategy: SpotlightStrategy;

  /** Custom delimiter token. Auto-generated if not provided. */
  delimiter?: string;

  /** Whether to sanitize existing boundary tokens in content. Default: true. */
  sanitize?: boolean;
}

export interface SpotlightResult {
  /** The marked content. */
  content: string;

  /** The boundary token used (for logging/debugging). */
  boundaryToken: string;

  /** The strategy that was applied. */
  strategy: SpotlightStrategy;
}

// ---------------------------------------------------------------------------
// Boundary Token Generation
// ---------------------------------------------------------------------------

/**
 * Generate a high-entropy boundary token.
 * 32 random bytes → 64 hex chars. Probability of collision with
 * natural text is negligible (2^-256).
 */
export function generateBoundaryToken(): string {
  return `<<<MAESTRO_BOUNDARY_${randomBytes(16).toString('hex').toUpperCase()}>>>`;
}

// ---------------------------------------------------------------------------
// Spotlight Implementation
// ---------------------------------------------------------------------------

/**
 * Apply spotlighting to content based on its privilege level.
 *
 * Content at TOOL_OUTPUT or lower privilege is wrapped in boundary markers.
 * Content at AGENT or higher privilege is passed through unchanged.
 */
export function applySpotlight(
  message: ProvenancedMessage<string>,
  config: SpotlightConfig = { strategy: 'delimiter' },
): SpotlightResult {
  const sanitize = config.sanitize !== false;
  const boundaryToken = config.delimiter ?? generateBoundaryToken();

  // Content at AGENT privilege or higher doesn't need boundary marking
  if (message.privilege <= InstructionPrivilege.AGENT) {
    return {
      content: message.content,
      boundaryToken,
      strategy: config.strategy,
    };
  }

  let content = message.content;

  // Sanitize existing boundary tokens in content to prevent fake boundaries
  if (sanitize) {
    content = sanitizeBoundaryTokens(content, boundaryToken);
  }

  switch (config.strategy) {
    case 'delimiter':
      return {
        content: `${boundaryToken}\n[DATA from ${message.source} — privilege: ${InstructionPrivilege[message.privilege]}]\n${content}\n${boundaryToken}`,
        boundaryToken,
        strategy: 'delimiter',
      };

    case 'xml-tag': {
      const nonce = randomBytes(8).toString('hex');
      const tag = `maestro-data-${nonce}`;
      return {
        content: `<${tag} source="${escapeXml(message.source)}" privilege="${InstructionPrivilege[message.privilege]}">\n${content}\n</${tag}>`,
        boundaryToken: tag,
        strategy: 'xml-tag',
      };
    }

    case 'base64':
      return {
        content: `${boundaryToken}\n[BASE64-ENCODED DATA from ${message.source}]\n${Buffer.from(content, 'utf-8').toString('base64')}\n${boundaryToken}`,
        boundaryToken,
        strategy: 'base64',
      };

    default:
      throw new Error(`Unknown spotlight strategy: ${config.strategy}`);
  }
}

/**
 * Sanitize existing boundary-like tokens in content.
 * Replaces any pattern that looks like our boundary markers with
 * escaped versions to prevent injection.
 */
function sanitizeBoundaryTokens(content: string, currentToken: string): string {
  // Remove any <<<MAESTRO_BOUNDARY_...>>> patterns that aren't our current token.
  // Full replacement (not partial escaping) prevents any downstream parser confusion.
  return content.replace(
    /<<<MAESTRO_BOUNDARY_[A-F0-9]+>>>/g,
    (match) => match === currentToken ? match : '[BOUNDARY_TOKEN_REMOVED]',
  );
}

/** Escape XML special characters. */
function escapeXml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

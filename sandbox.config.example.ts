/**
 * Example configuration file for maestro-sandbox.
 *
 * Copy this to `sandbox.config.ts` and customize.
 * Then import it wherever you create sandboxes:
 *
 *   import config from './sandbox.config.js';
 *   const { sandbox, defense } = await createSecureSandbox(config);
 */
import { defineConfig } from 'maestro-sandbox';

export default defineConfig({
  // --- Plugin Selection ---
  // 'isolated-vm' — Fast, cross-platform V8 isolate (default)
  // 'anthropic-sr' — OS-level sandbox (macOS/Linux)
  // 'landlock'     — Seatbelt sandbox (macOS)
  // 'docker'       — Docker container
  // 'e2b'          — E2B cloud micro-VM (requires E2B_API_KEY)
  // 'openshell'    — NVIDIA OpenShell (requires CLI)
  // 'auto'         — Try best available, degrade gracefully
  plugin: 'isolated-vm',

  // --- Resource Limits ---
  limits: {
    memoryMB: 128,       // Max heap memory
    cpuMs: 5000,         // Max CPU time
    timeoutMs: 10000,    // Max wall-clock time
    networkAccess: false, // Block all outbound network
    filesystemAccess: 'tmpfs', // Ephemeral filesystem only
  },

  // --- Secrets (optional) ---
  // Injected at creation, never written to disk, destroyed on sandbox.destroy().
  // secrets: {
  //   E2B_API_KEY: process.env.E2B_API_KEY ?? '',
  //   API_TOKEN: process.env.API_TOKEN ?? '',
  // },

  // --- Network (optional, Tier 2+ only) ---
  // network: {
  //   allowedPeers: ['api.openai.com:443'],
  // },

  // --- Host Functions (optional) ---
  // Sandboxed code can call these through the frozen bridge.
  // hostFunctions: {
  //   lookup: {
  //     handler: async (args) => { /* ... */ },
  //     schema: z.object({ key: z.string() }),
  //     rateLimit: { maxCalls: 100, windowMs: 60000 },
  //   },
  // },

  // --- Defense Pipeline ---
  // Set to `false` to disable (not recommended for untrusted code).
  defense: {
    // Guardrail thresholds (11 safety categories)
    guardrails: {
      // defaultThresholds: { block: 0.9, flag: 0.5, modify: 0.7 },
      // disabledCategories: ['training-data-poisoning'],
    },

    // Escalation detection (multi-turn attack prevention)
    escalation: {
      maxTurns: 50,          // Force session reset after N turns
      // blockedAttemptThreshold: 3,
      // similarityThreshold: 0.8,
    },

    // Pipeline orchestration
    pipeline: {
      // latencyBudgetMs: 500,
      // flagAccumulationThreshold: 3,
    },

    // Trust sub-level policies (what each trust level can do)
    trustPolicies: {
      // 3a: Operator-controlled (agent, tool output, user input)
      trustLevel3a: {
        allowCodeExecution: true,
        maxSessionTurns: 50,
      },
      // 3b: Peer agent messages
      trustLevel3b: {
        allowCodeExecution: false,
        maxSessionTurns: 30,
      },
      // 3c: Internet/MCP (lowest trust)
      trustLevel3c: {
        allowCodeExecution: false,
        maxSessionTurns: 20,
        maxContextTokens: 4000,
      },
    },
  },

  // --- Audit Logging ---
  audit: {
    emit: true,   // Log to stdout/stderr
    store: false,  // Don't keep in memory (set true for testing)
  },
});

import { z } from "zod";
import { AttestationError } from "./errors.js";

/**
 * Manifest schema for MCP tool attestation.
 *
 * The manifest declares every tool a server may expose, the constraints on
 * each tool's arguments, and the spawn-rules a runtime must enforce. The
 * manifest is signed at build-time with Ed25519 and verified at runtime
 * before any tool call is dispatched.
 */

export const ARG_RULE_KIND = ["regex", "enum", "length", "prefix", "literal", "shellSafeString"] as const;
export type ArgRuleKind = (typeof ARG_RULE_KIND)[number];

const baseArgRule = z.object({
  name: z.string().min(1).max(128),
  kind: z.enum(ARG_RULE_KIND),
  required: z.boolean().default(true),
  description: z.string().max(512).optional(),
});

export const ArgRuleSchema = z.discriminatedUnion("kind", [
  baseArgRule.extend({
    kind: z.literal("regex"),
    pattern: z.string().min(1).max(2048),
    flags: z.string().max(8).optional(),
  }),
  baseArgRule.extend({
    kind: z.literal("enum"),
    values: z.array(z.string().min(1).max(512)).min(1).max(256),
  }),
  baseArgRule.extend({
    kind: z.literal("length"),
    min: z.number().int().nonnegative().max(65536),
    max: z.number().int().nonnegative().max(65536),
  }),
  baseArgRule.extend({
    kind: z.literal("prefix"),
    prefix: z.string().min(1).max(512),
    maxSuffixLength: z.number().int().nonnegative().max(65536).default(2048),
  }),
  baseArgRule.extend({
    kind: z.literal("literal"),
    value: z.string().max(2048),
  }),
  baseArgRule.extend({
    kind: z.literal("shellSafeString"),
    maxLength: z.number().int().positive().max(65536).default(2048),
  }),
]);

export type ArgRule = z.infer<typeof ArgRuleSchema>;

export const ToolDeclSchema = z.object({
  name: z.string().min(1).max(128).regex(/^[a-zA-Z_][a-zA-Z0-9_-]*$/, {
    message: "Tool name must start with letter or underscore and contain only [a-zA-Z0-9_-]",
  }),
  description: z.string().max(2048).optional(),
  readOnlyHint: z.boolean(),
  destructiveHint: z.boolean(),
  args: z.array(ArgRuleSchema).max(64),
});

export type ToolDecl = z.infer<typeof ToolDeclSchema>;

export const SpawnRuleSchema = z.object({
  command: z.string().min(1).max(512),
  description: z.string().max(512).optional(),
  args: z.array(ArgRuleSchema).max(64),
  /** Hard cap on total argv length (defense against buffer-stuffing). */
  maxTotalArgLength: z.number().int().positive().max(131072).default(8192),
});

export type SpawnRule = z.infer<typeof SpawnRuleSchema>;

export const ManifestSchema = z.object({
  schemaVersion: z.literal(1),
  serverName: z
    .string()
    .min(1)
    .max(128)
    .regex(/^[a-zA-Z0-9._-]+$/, {
      message: "Server name must contain only [a-zA-Z0-9._-]",
    }),
  serverVersion: z.string().min(1).max(64),
  mcpSpecVersion: z.enum(["2024-11-05", "2025-03-26", "2025-06-18"]),
  signer: z.string().min(1).max(256),
  publicKeyFingerprint: z
    .string()
    .regex(/^sha256:[0-9a-f]{64}$/, "fingerprint must be sha256:<64-hex>"),
  /** ISO 8601 UTC. */
  signedAt: z.string().datetime({ offset: false }),
  /**
   * Optional ISO 8601 UTC expiry. When set, runtime verifyManifest() rejects
   * the signed manifest after this timestamp. Forces key rotation for
   * compromised-key recovery (THREAT-MODEL.md "Key Lifetime"). Round 2 F6 fix.
   */
  expiresAt: z.string().datetime({ offset: false }).optional(),
  tools: z.array(ToolDeclSchema).min(0).max(256),
  spawnRules: z.array(SpawnRuleSchema).max(64).default([]),
  /**
   * Free-form metadata block for downstream consumers.
   *
   * MEDIUM-3 fix Round 3: this field IS part of the signed canonical-JSON.
   * Tampering with metadata after signing invalidates the signature. The
   * earlier comment ("Not part of the trust boundary") was misleading and
   * could lead consumers to believe metadata is detachable. It is not.
   * If you need a detachable annotation channel, layer it OUTSIDE the
   * SignedManifest envelope.
   */
  metadata: z.record(z.string(), z.unknown()).optional(),
});

export type Manifest = z.infer<typeof ManifestSchema>;

export const SignedManifestSchema = z.object({
  manifest: ManifestSchema,
  /** Hex-encoded Ed25519 signature of the canonical-JSON of `manifest`. */
  signature: z.string().regex(/^[0-9a-f]{128}$/, "Ed25519 signature must be 128 hex chars"),
  /** Hex-encoded Ed25519 public key (32 bytes raw → 64 hex). */
  publicKey: z.string().regex(/^[0-9a-f]{64}$/, "Ed25519 public key must be 64 hex chars"),
});

export type SignedManifest = z.infer<typeof SignedManifestSchema>;

/**
 * Canonicalise a manifest into deterministic JSON. Used as the bytes-to-sign
 * surface so tampering with key order or whitespace changes the hash.
 *
 * Algorithm: recursively sort object keys lexicographically, drop undefined
 * values, then JSON.stringify with no extra whitespace.
 */
export function canonicalize(value: unknown): string {
  return JSON.stringify(canonicalizeValue(value));
}

function canonicalizeValue(value: unknown): unknown {
  if (value === null) return null;
  if (typeof value === "number") {
    // MEDIUM-2 fix Round 3: align with `JSON.stringify` semantics — non-finite
    // numbers (NaN, Infinity, -Infinity) serialise to `null`. By coercing
    // ourselves we close a signature-collision vector: previously
    // `metadata: { count: NaN }` and `metadata: { count: null }` produced
    // different in-memory values but identical canonical bytes via the
    // downstream `JSON.stringify`. Now both consistently canonicalise to
    // `null` *before* signing, so the in-memory shape is unambiguous.
    return Number.isFinite(value) ? value : null;
  }
  if (typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map(canonicalizeValue);
  const obj = value as Record<string, unknown>;
  const sortedKeys = Object.keys(obj).sort();
  const out: Record<string, unknown> = {};
  for (const k of sortedKeys) {
    const v = obj[k];
    if (v === undefined) continue;
    out[k] = canonicalizeValue(v);
  }
  return out;
}

/**
 * Parse arbitrary JSON-string or object as a Manifest. Throws AttestationError
 * with a precise code on failure.
 */
export function parseManifest(input: string | object): Manifest {
  let raw: unknown;
  if (typeof input === "string") {
    try {
      raw = JSON.parse(input);
    } catch (err) {
      throw new AttestationError("MANIFEST_PARSE_ERROR", "Manifest JSON is not parseable", {
        cause: err instanceof Error ? err.message : String(err),
      });
    }
  } else {
    raw = input;
  }
  const result = ManifestSchema.safeParse(raw);
  if (!result.success) {
    throw new AttestationError(
      "MANIFEST_SCHEMA_INVALID",
      "Manifest does not match schema",
      { issues: result.error.issues },
    );
  }
  return result.data;
}

export function parseSignedManifest(input: string | object): SignedManifest {
  let raw: unknown;
  if (typeof input === "string") {
    try {
      raw = JSON.parse(input);
    } catch (err) {
      throw new AttestationError("MANIFEST_PARSE_ERROR", "SignedManifest JSON is not parseable", {
        cause: err instanceof Error ? err.message : String(err),
      });
    }
  } else {
    raw = input;
  }
  const result = SignedManifestSchema.safeParse(raw);
  if (!result.success) {
    throw new AttestationError(
      "MANIFEST_SCHEMA_INVALID",
      "SignedManifest does not match schema",
      { issues: result.error.issues },
    );
  }
  return result.data;
}

/**
 * Produce a manifest template for a server. Useful for `mcp-attest keygen`
 * and the `attest_generate_manifest_template` tool. Caller fills in arg
 * rules per tool.
 */
export function generateTemplate(args: {
  serverName: string;
  serverVersion?: string;
  signer?: string;
  toolNames: string[];
  publicKeyFingerprint?: string;
}): Manifest {
  const tools: ToolDecl[] = args.toolNames.map((name) => ({
    name,
    description: `Tool ${name}. Replace this description and define args before signing.`,
    readOnlyHint: true,
    destructiveHint: false,
    args: [],
  }));
  return {
    schemaVersion: 1,
    serverName: args.serverName,
    serverVersion: args.serverVersion ?? "0.0.0",
    mcpSpecVersion: "2025-06-18",
    signer: args.signer ?? "unset",
    publicKeyFingerprint: args.publicKeyFingerprint ?? `sha256:${"0".repeat(64)}`,
    signedAt: new Date(0).toISOString(),
    tools,
    spawnRules: [],
  };
}

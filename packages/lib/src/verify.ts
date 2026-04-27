import { createPublicKey, verify as cryptoVerify, KeyObject } from "node:crypto";
import { canonicalize, parseSignedManifest, type SignedManifest } from "./manifest.js";
import { AttestationError } from "./errors.js";
import { fingerprintFromPublicKeyHex } from "./sign.js";

export interface VerificationResult {
  valid: boolean;
  signer: string;
  fingerprint: string;
  toolCount: number;
  /** Reasons the verification failed, empty when valid. */
  errors: string[];
}

export interface VerifyOptions {
  /** When provided, the embedded public key must match (used by trust-pinning). */
  expectedPublicKeyHex?: string;
  /**
   * Override clock for testing expiry logic. Defaults to `Date.now()`.
   * F6 fix Round 2.
   */
  now?: Date;
}

/**
 * Verify a SignedManifest.
 *
 * Steps:
 *  1. Parse + schema-validate.
 *  2. Recompute fingerprint from embedded public key, ensure it matches the
 *     fingerprint claimed inside the signed manifest.
 *  3. If `expectedPublicKeyHex` is provided, ensure the signed-manifest's
 *     public key matches it (used by trust-pinning).
 *  4. If manifest carries an `expiresAt`, ensure it has not passed.
 *  5. Verify Ed25519 signature over canonical-JSON of `manifest`.
 *
 * Returns a structured result. Does NOT throw on bad signatures — callers
 * decide how to react. Throws only on schema-level corruption.
 *
 * Round 2 F9+F10 cleanup: redundant conditional + double-cast removed.
 * `parseSignedManifest` itself accepts string or object; the caller-side
 * branch was a No-Op.
 */
export function verifyManifest(
  input: string | object | SignedManifest,
  options: VerifyOptions = {},
): VerificationResult {
  const signed = parseSignedManifest(input);

  const errors: string[] = [];
  const fingerprint = fingerprintFromPublicKeyHex(signed.publicKey);

  if (signed.manifest.publicKeyFingerprint !== fingerprint) {
    errors.push(
      `manifest.publicKeyFingerprint (${signed.manifest.publicKeyFingerprint}) does not match the embedded public key (${fingerprint})`,
    );
  }

  if (options.expectedPublicKeyHex !== undefined) {
    if (options.expectedPublicKeyHex !== signed.publicKey) {
      errors.push(
        `embedded public key does not match expected pinned key (got ${signed.publicKey}, expected ${options.expectedPublicKeyHex})`,
      );
    }
  }

  // F6 Round 2: enforce expiresAt when present
  if (signed.manifest.expiresAt !== undefined) {
    const now = options.now ?? new Date();
    const expiresAt = new Date(signed.manifest.expiresAt);
    if (expiresAt.getTime() <= now.getTime()) {
      errors.push(
        `manifest expired at ${signed.manifest.expiresAt} (now ${now.toISOString()})`,
      );
    }
  }

  const publicKey: KeyObject = importPublicKeyHex(signed.publicKey);
  const bytes = Buffer.from(canonicalize(signed.manifest), "utf-8");
  const sigBuf = Buffer.from(signed.signature, "hex");

  let signatureValid = false;
  try {
    signatureValid = cryptoVerify(null, bytes, publicKey, sigBuf);
  } catch (err) {
    errors.push(`signature verification threw: ${err instanceof Error ? err.message : String(err)}`);
  }
  if (!signatureValid) {
    errors.push("Ed25519 signature does not verify against canonical-JSON manifest bytes");
  }

  return {
    valid: errors.length === 0,
    signer: signed.manifest.signer,
    fingerprint,
    toolCount: signed.manifest.tools.length,
    errors,
  };
}

/**
 * Strict variant: throws AttestationError on any failure. Returns the parsed
 * SignedManifest on success — caches the parse so callers do not re-parse.
 *
 * Round 2 F9 cleanup: previously parsed twice (once via verifyManifest,
 * once on success). Now parses once up front and reuses the value.
 */
export function verifyManifestStrict(
  input: string | object | SignedManifest,
  options: VerifyOptions = {},
): SignedManifest {
  const signed = parseSignedManifest(input);
  const result = verifyManifest(signed, options);
  if (!result.valid) {
    throw new AttestationError("SIGNATURE_INVALID", "Manifest verification failed", {
      errors: result.errors,
    });
  }
  return signed;
}

function importPublicKeyHex(publicKeyHex: string): KeyObject {
  // Reconstruct SPKI by prefixing the standard Ed25519 algorithm header.
  // Header = 302a300506032b6570032100 (12 bytes), then 32-byte raw key.
  const raw = Buffer.from(publicKeyHex, "hex");
  if (raw.length !== 32) {
    throw new AttestationError("KEY_FORMAT_INVALID", "Public key must be 32 raw bytes (64 hex)");
  }
  const header = Buffer.from("302a300506032b6570032100", "hex");
  const der = Buffer.concat([header, raw]);
  return createPublicKey({ key: der, format: "der", type: "spki" });
}

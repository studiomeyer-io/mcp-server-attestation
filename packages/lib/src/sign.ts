import {
  generateKeyPairSync,
  sign as cryptoSign,
  createPublicKey,
  createPrivateKey,
  createHash,
  KeyObject,
} from "node:crypto";
import { canonicalize, type Manifest, type SignedManifest } from "./manifest.js";
import { AttestationError } from "./errors.js";

/**
 * Generate a fresh Ed25519 keypair. Returns hex-encoded raw key bytes plus
 * a sha256 fingerprint of the public key for trust pinning.
 */
export function generateKeyPair(): {
  publicKeyHex: string;
  privateKeyHex: string;
  fingerprint: string;
} {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicKeyHex = exportPublicKeyHex(publicKey);
  const privateKeyHex = exportPrivateKeyHex(privateKey);
  return {
    publicKeyHex,
    privateKeyHex,
    fingerprint: fingerprintFromPublicKeyHex(publicKeyHex),
  };
}

/**
 * Compute sha256 fingerprint from hex-encoded raw Ed25519 public key.
 * Format: `sha256:<64-hex>` to match the manifest schema.
 */
export function fingerprintFromPublicKeyHex(publicKeyHex: string): string {
  if (!/^[0-9a-f]{64}$/.test(publicKeyHex)) {
    throw new AttestationError("KEY_FORMAT_INVALID", "Public key must be 64 hex chars (32 raw bytes)", {
      received: publicKeyHex.length,
    });
  }
  const hash = createHash("sha256").update(Buffer.from(publicKeyHex, "hex")).digest("hex");
  return `sha256:${hash}`;
}

/**
 * Sign a manifest. The manifest is canonicalised before signing so that any
 * later re-serialisation cannot change the signed bytes. Returns a
 * SignedManifest carrying the hex signature plus the hex public key for
 * downstream verification.
 */
export function signManifest(manifest: Manifest, privateKeyHex: string): SignedManifest {
  validateHexLen(privateKeyHex, 32, "private key");
  const privateKey = importPrivateKeyHex(privateKeyHex);
  const publicKey = createPublicKey(privateKey);
  const publicKeyHex = exportPublicKeyHex(publicKey);

  const fingerprint = fingerprintFromPublicKeyHex(publicKeyHex);
  if (manifest.publicKeyFingerprint !== fingerprint) {
    // Fail loud rather than silently mismatch — the architect's plan
    // requires that the manifest's claimed fingerprint matches the actual
    // signing key. This blocks Cursor-style bait-and-switch where a
    // manifest claims one key and is signed by another.
    throw new AttestationError(
      "PUBLIC_KEY_MISMATCH",
      "Manifest publicKeyFingerprint does not match the signing key. Refusing to sign.",
      { manifestFingerprint: manifest.publicKeyFingerprint, signingKeyFingerprint: fingerprint },
    );
  }

  const bytesToSign = Buffer.from(canonicalize(manifest), "utf-8");
  const signatureBuf = cryptoSign(null, bytesToSign, privateKey);
  return {
    manifest,
    signature: signatureBuf.toString("hex"),
    publicKey: publicKeyHex,
  };
}

/**
 * Sign a manifest, automatically writing the resulting public-key fingerprint
 * onto the manifest before signing. Convenience wrapper for CLIs.
 */
export function signManifestAutoFingerprint(
  manifest: Manifest,
  privateKeyHex: string,
): SignedManifest {
  validateHexLen(privateKeyHex, 32, "private key");
  const privateKey = importPrivateKeyHex(privateKeyHex);
  const publicKey = createPublicKey(privateKey);
  const publicKeyHex = exportPublicKeyHex(publicKey);
  const fingerprint = fingerprintFromPublicKeyHex(publicKeyHex);
  const stamped: Manifest = {
    ...manifest,
    publicKeyFingerprint: fingerprint,
    signedAt: new Date().toISOString(),
  };
  return signManifest(stamped, privateKeyHex);
}

// --- Internals -------------------------------------------------------------

function exportPublicKeyHex(key: KeyObject): string {
  // Ed25519 public-key DER (SPKI) wraps a 12-byte algorithm header followed
  // by the 32-byte raw key. We extract the raw 32 bytes and hex-encode.
  const der = key.export({ format: "der", type: "spki" });
  if (der.length < 32) {
    throw new AttestationError("KEY_FORMAT_INVALID", "Public key DER too short", { length: der.length });
  }
  return der.subarray(der.length - 32).toString("hex");
}

function exportPrivateKeyHex(key: KeyObject): string {
  // Ed25519 PKCS8 private key wraps a header followed by an OCTET STRING with
  // the 32-byte seed. The raw seed lives in the last 32 bytes of the DER.
  const der = key.export({ format: "der", type: "pkcs8" });
  if (der.length < 32) {
    throw new AttestationError("KEY_FORMAT_INVALID", "Private key DER too short", { length: der.length });
  }
  return der.subarray(der.length - 32).toString("hex");
}

function importPrivateKeyHex(privateKeyHex: string): KeyObject {
  // Reconstruct PKCS8 by prefixing the standard Ed25519 header.
  // Header = 302e020100300506032b657004220420 (16 bytes), then 32-byte seed.
  const seed = Buffer.from(privateKeyHex, "hex");
  if (seed.length !== 32) {
    throw new AttestationError("KEY_FORMAT_INVALID", "Private key must be 32 raw bytes (64 hex)");
  }
  const header = Buffer.from("302e020100300506032b657004220420", "hex");
  const der = Buffer.concat([header, seed]);
  return createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

function validateHexLen(input: string, byteLen: number, what: string): void {
  if (typeof input !== "string" || input.length !== byteLen * 2 || !/^[0-9a-f]+$/.test(input)) {
    throw new AttestationError(
      "KEY_FORMAT_INVALID",
      `${what} must be ${byteLen * 2} lowercase hex chars (${byteLen} bytes)`,
      { received: input.length },
    );
  }
}

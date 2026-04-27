import { describe, it, expect } from "vitest";
import {
  generateKeyPair,
  signManifest,
  signManifestAutoFingerprint,
  fingerprintFromPublicKeyHex,
  verifyManifest,
  parseManifest,
  generateTemplate,
  AttestationError,
  type Manifest,
} from "../src/index.js";

function freshManifest(): Manifest {
  const tpl = generateTemplate({
    serverName: "test-server",
    toolNames: ["echo", "ping"],
  });
  // generateTemplate gives placeholder fingerprint; tests overwrite where needed
  return {
    ...tpl,
    serverVersion: "1.0.0",
    signer: "tester",
    signedAt: new Date("2026-04-27T00:00:00.000Z").toISOString(),
  };
}

describe("Ed25519 sign/verify roundtrip", () => {
  it("generates a 64-hex public, 64-hex private, sha256:<64hex> fingerprint", () => {
    const { publicKeyHex, privateKeyHex, fingerprint } = generateKeyPair();
    expect(publicKeyHex).toMatch(/^[0-9a-f]{64}$/);
    expect(privateKeyHex).toMatch(/^[0-9a-f]{64}$/);
    expect(fingerprint).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(fingerprintFromPublicKeyHex(publicKeyHex)).toBe(fingerprint);
  });

  it("signs and verifies a basic manifest", () => {
    const kp = generateKeyPair();
    const m = freshManifest();
    m.publicKeyFingerprint = kp.fingerprint;
    const signed = signManifest(m, kp.privateKeyHex);
    const result = verifyManifest(signed);
    expect(result.valid).toBe(true);
    expect(result.errors).toEqual([]);
    expect(result.toolCount).toBe(2);
  });

  it("refuses to sign when manifest fingerprint does not match the key", () => {
    const kp = generateKeyPair();
    const m = freshManifest();
    m.publicKeyFingerprint = `sha256:${"a".repeat(64)}`;
    expect(() => signManifest(m, kp.privateKeyHex)).toThrow(AttestationError);
  });

  it("signManifestAutoFingerprint stamps the right fingerprint and signedAt", () => {
    const kp = generateKeyPair();
    const m = freshManifest();
    m.publicKeyFingerprint = `sha256:${"0".repeat(64)}`;
    const before = Date.now();
    const signed = signManifestAutoFingerprint(m, kp.privateKeyHex);
    const after = Date.now();
    expect(signed.manifest.publicKeyFingerprint).toBe(kp.fingerprint);
    const t = Date.parse(signed.manifest.signedAt);
    expect(t).toBeGreaterThanOrEqual(before);
    expect(t).toBeLessThanOrEqual(after);
  });

  it("flips one byte of signature → fails verify", () => {
    const kp = generateKeyPair();
    const m = freshManifest();
    m.publicKeyFingerprint = kp.fingerprint;
    const signed = signManifest(m, kp.privateKeyHex);
    const tampered = {
      ...signed,
      // Flip the last hex char (4 bits) — preserves length so schema-validation
      // passes and the signature-mismatch is what triggers the failure path.
      signature:
        signed.signature.slice(0, -1) +
        (signed.signature.endsWith("0") ? "1" : "0"),
    };
    const result = verifyManifest(tampered);
    expect(result.valid).toBe(false);
    expect(result.errors.join(" ")).toMatch(/signature/i);
  });

  it("flips one byte of manifest → fails verify", () => {
    const kp = generateKeyPair();
    const m = freshManifest();
    m.publicKeyFingerprint = kp.fingerprint;
    const signed = signManifest(m, kp.privateKeyHex);
    const tampered = {
      ...signed,
      manifest: { ...signed.manifest, signer: "attacker" },
    };
    const result = verifyManifest(tampered);
    expect(result.valid).toBe(false);
  });

  it("wrong public key → fails verify", () => {
    const a = generateKeyPair();
    const b = generateKeyPair();
    const m = freshManifest();
    m.publicKeyFingerprint = a.fingerprint;
    const signed = signManifest(m, a.privateKeyHex);
    const swapped = { ...signed, publicKey: b.publicKeyHex };
    const result = verifyManifest(swapped);
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it("expectedPublicKeyHex pin enforced", () => {
    const a = generateKeyPair();
    const b = generateKeyPair();
    const m = freshManifest();
    m.publicKeyFingerprint = a.fingerprint;
    const signed = signManifest(m, a.privateKeyHex);
    const okResult = verifyManifest(signed, { expectedPublicKeyHex: a.publicKeyHex });
    expect(okResult.valid).toBe(true);
    const mismatchResult = verifyManifest(signed, { expectedPublicKeyHex: b.publicKeyHex });
    expect(mismatchResult.valid).toBe(false);
    expect(mismatchResult.errors.join(" ")).toMatch(/pinned/);
  });

  it("rejects malformed private key hex", () => {
    const m = freshManifest();
    expect(() => signManifest(m, "notHex")).toThrow(AttestationError);
    expect(() => signManifest(m, "0".repeat(63))).toThrow(AttestationError);
  });

  it("rejects malformed public key hex on fingerprint", () => {
    expect(() => fingerprintFromPublicKeyHex("xyz")).toThrow(AttestationError);
  });

  it("parseManifest rejects bad schema", () => {
    expect(() => parseManifest('{"schemaVersion": 999}')).toThrow(AttestationError);
  });
});

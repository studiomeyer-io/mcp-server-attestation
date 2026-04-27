import { describe, it, expect } from "vitest";
import {
  generateKeyPair,
  signManifest,
  verifyManifest,
  verifyManifestStrict,
  generateTemplate,
  AttestationError,
  canonicalize,
  parseSignedManifest,
  type Manifest,
} from "../src/index.js";

function buildSigned() {
  const kp = generateKeyPair();
  const tpl = generateTemplate({ serverName: "verify-test", toolNames: ["echo"] });
  const m: Manifest = {
    ...tpl,
    publicKeyFingerprint: kp.fingerprint,
    signer: "verify-tester",
    signedAt: new Date().toISOString(),
  };
  return { signed: signManifest(m, kp.privateKeyHex), kp };
}

describe("verify happy + sad paths", () => {
  it("happy path returns valid + zero errors", () => {
    const { signed } = buildSigned();
    const r = verifyManifest(signed);
    expect(r.valid).toBe(true);
    expect(r.errors).toEqual([]);
    expect(r.signer).toBe("verify-tester");
    expect(r.toolCount).toBe(1);
  });

  it("verifyManifestStrict throws on tampered", () => {
    const { signed } = buildSigned();
    const tampered = { ...signed, manifest: { ...signed.manifest, signer: "attacker" } };
    expect(() => verifyManifestStrict(tampered)).toThrow(AttestationError);
  });

  it("can also accept the JSON-string form", () => {
    const { signed } = buildSigned();
    const r = verifyManifest(JSON.stringify(signed));
    expect(r.valid).toBe(true);
  });

  it("flagging fingerprint-spoof: claimed != computed", () => {
    const { signed } = buildSigned();
    const spoofed = {
      ...signed,
      manifest: { ...signed.manifest, publicKeyFingerprint: `sha256:${"f".repeat(64)}` },
    };
    const r = verifyManifest(spoofed);
    expect(r.valid).toBe(false);
    expect(r.errors.join(" ")).toMatch(/does not match the embedded public key/);
  });

  it("parseSignedManifest fails on garbage JSON", () => {
    expect(() => parseSignedManifest("{not json")).toThrow(AttestationError);
  });

  it("canonicalize is deterministic regardless of key order", () => {
    const a = canonicalize({ b: 2, a: 1, nested: { y: 1, x: 2 } });
    const b = canonicalize({ a: 1, b: 2, nested: { x: 2, y: 1 } });
    expect(a).toBe(b);
  });
});

// F6 Round 2 fix: optional manifest expiresAt enforced at verify-time
describe("manifest expiry (F6 Round 2)", () => {
  it("rejects a signed manifest whose expiresAt is in the past", () => {
    const kp = generateKeyPair();
    const tpl = generateTemplate({ serverName: "expiry-test", toolNames: ["echo"] });
    const m: Manifest = {
      ...tpl,
      publicKeyFingerprint: kp.fingerprint,
      signer: "expiry-tester",
      signedAt: new Date(Date.now() - 86_400_000).toISOString(), // 1 day ago
      expiresAt: new Date(Date.now() - 3_600_000).toISOString(), // 1h ago
    };
    const signed = signManifest(m, kp.privateKeyHex);
    const r = verifyManifest(signed);
    expect(r.valid).toBe(false);
    expect(r.errors.join(" ")).toMatch(/expired/);
  });

  it("accepts a signed manifest whose expiresAt is in the future", () => {
    const kp = generateKeyPair();
    const tpl = generateTemplate({ serverName: "expiry-test", toolNames: ["echo"] });
    const m: Manifest = {
      ...tpl,
      publicKeyFingerprint: kp.fingerprint,
      signer: "expiry-tester",
      signedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 86_400_000).toISOString(), // 1 day from now
    };
    const signed = signManifest(m, kp.privateKeyHex);
    const r = verifyManifest(signed);
    expect(r.valid).toBe(true);
  });

  it("backward-compat: manifest without expiresAt verifies normally", () => {
    const kp = generateKeyPair();
    const tpl = generateTemplate({ serverName: "expiry-test", toolNames: ["echo"] });
    const m: Manifest = {
      ...tpl,
      publicKeyFingerprint: kp.fingerprint,
      signer: "expiry-tester",
      signedAt: new Date().toISOString(),
      // expiresAt: undefined  ← omitted
    };
    const signed = signManifest(m, kp.privateKeyHex);
    const r = verifyManifest(signed);
    expect(r.valid).toBe(true);
  });

  it("uses the `now` option when provided (deterministic clock)", () => {
    const kp = generateKeyPair();
    const tpl = generateTemplate({ serverName: "expiry-test", toolNames: ["echo"] });
    const m: Manifest = {
      ...tpl,
      publicKeyFingerprint: kp.fingerprint,
      signer: "expiry-tester",
      signedAt: "2026-04-27T00:00:00.000Z",
      expiresAt: "2026-04-28T00:00:00.000Z",
    };
    const signed = signManifest(m, kp.privateKeyHex);
    // Frozen clock BEFORE expiry
    const before = verifyManifest(signed, { now: new Date("2026-04-27T12:00:00Z") });
    expect(before.valid).toBe(true);
    // Frozen clock AFTER expiry
    const after = verifyManifest(signed, { now: new Date("2026-04-29T00:00:00Z") });
    expect(after.valid).toBe(false);
    expect(after.errors.join(" ")).toMatch(/expired/);
  });
});

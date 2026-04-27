/**
 * Round 3 MEDIUM-2: canonicalize() must consistently coerce non-finite numbers
 * (NaN, Infinity, -Infinity) to null *before* hashing, matching the eventual
 * `JSON.stringify` semantics. This closes a signature-collision vector in the
 * `metadata` field where in-memory `NaN` and explicit `null` would have hashed
 * the same downstream but represented different developer-visible values.
 */
import { describe, it, expect } from "vitest";
import {
  canonicalize,
  generateTemplate,
  parseSignedManifest,
  signManifest,
  verifyManifest,
  generateKeyPair,
  fingerprintFromPublicKeyHex,
  type Manifest,
} from "../src/index.js";

describe("canonicalize — Round 3 MEDIUM-2 NaN/Infinity coercion", () => {
  it.each([
    ["NaN", NaN],
    ["Infinity", Infinity],
    ["-Infinity", -Infinity],
  ])("coerces top-level %s to null", (_label, value) => {
    const out = canonicalize(value);
    expect(out).toBe("null");
  });

  it("coerces nested NaN inside objects to null", () => {
    const a = canonicalize({ count: NaN });
    const b = canonicalize({ count: null });
    expect(a).toBe(b);
    expect(a).toBe('{"count":null}');
  });

  it("coerces nested Infinity inside arrays to null", () => {
    const a = canonicalize([1, Infinity, -Infinity, NaN, 2]);
    expect(a).toBe("[1,null,null,null,2]");
  });

  it("preserves regular finite numbers", () => {
    expect(canonicalize({ x: 0, y: -42, z: 3.14 })).toBe(
      '{"x":0,"y":-42,"z":3.14}',
    );
  });

  it("Number.MAX_SAFE_INTEGER is preserved (still finite)", () => {
    expect(canonicalize({ n: Number.MAX_SAFE_INTEGER })).toBe(
      `{"n":${Number.MAX_SAFE_INTEGER}}`,
    );
  });

  it("ensures signature stability — NaN and null in metadata produce equal signatures", () => {
    // Build two manifests differing only in NaN vs null in metadata.count.
    // After Round 3 MEDIUM-2 they must canonicalise to identical bytes,
    // hence identical signatures.
    const { publicKeyHex, privateKeyHex } = generateKeyPair();
    const fingerprint = fingerprintFromPublicKeyHex(publicKeyHex);
    const base: Manifest = {
      ...generateTemplate({
        serverName: "test-server",
        toolNames: ["t"],
        publicKeyFingerprint: fingerprint,
      }),
      signedAt: "2026-04-27T00:00:00.000Z",
      signer: "test",
    };
    const withNaN: Manifest = { ...base, metadata: { count: NaN } };
    const withNull: Manifest = { ...base, metadata: { count: null } };

    const a = signManifest(withNaN, privateKeyHex);
    const b = signManifest(withNull, privateKeyHex);
    expect(a.signature).toBe(b.signature);
    // And both must verify
    const result = verifyManifest(a);
    expect(result.valid).toBe(true);
  });

  it("undefined inside object is dropped (existing behaviour preserved)", () => {
    const out = canonicalize({ a: undefined, b: 1 });
    expect(out).toBe('{"b":1}');
  });

  it("undefined inside array surfaces as null (matches JSON.stringify)", () => {
    // canonicalizeValue drops `undefined` only inside object keys; in arrays
    // JSON.stringify surfaces `undefined` as `null`, our canonicalize stays
    // consistent because it just does .map() — so `undefined` becomes
    // serialised by JSON.stringify itself as null. We pin that behaviour.
    expect(canonicalize([1, undefined, 2])).toBe("[1,null,2]");
  });
});

describe("parseSignedManifest — Round 3 confidence checks", () => {
  it("round-trips a signed manifest with NaN coerced into metadata", () => {
    const { publicKeyHex, privateKeyHex } = generateKeyPair();
    const fingerprint = fingerprintFromPublicKeyHex(publicKeyHex);
    const m: Manifest = {
      ...generateTemplate({
        serverName: "test-server",
        toolNames: ["t"],
        publicKeyFingerprint: fingerprint,
      }),
      signedAt: "2026-04-27T00:00:00.000Z",
      signer: "test",
      metadata: { count: NaN, ratio: Infinity, label: "ok" },
    };
    const signed = signManifest(m, privateKeyHex);
    const json = JSON.stringify(signed);
    const reparsed = parseSignedManifest(json);
    const result = verifyManifest(reparsed);
    expect(result.valid).toBe(true);
    expect(publicKeyHex).toBe(publicKeyHex);
  });
});

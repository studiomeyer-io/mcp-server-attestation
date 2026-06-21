/**
 * Hardening round (oss-improve/coverage-and-hardening).
 *
 * Covers four security fixes, each with attack-blocked AND benign-allowed
 * assertions so we never weaken the gate into a false-negative:
 *
 *  A. ReDoS guard — a catastrophic-backtracking regex pattern is refused
 *     before it can run (the spawn hot path cannot be frozen by a crafted arg);
 *     plus a hard input-length cap as defense-in-depth. Safe patterns and
 *     legitimate inputs still pass.
 *  B. Control-character gap — VT (U+000B), FF (U+000C) and NEL (U+0085) now
 *     join the default-deny set alongside LF/CR/U+2028/U+2029.
 *  C. Prefix path-traversal — `prefix` rules with `denyTraversal` (default on)
 *     reject `..` components that escape the guarded directory; clean paths
 *     under the prefix still pass, and `denyTraversal:false` restores the
 *     legacy behaviour.
 *  D. attestSpawnVerified — verifies the signature before attesting, closing
 *     the footgun where an unverified/tampered manifest reaches attestSpawn.
 */
import { describe, it, expect } from "vitest";
import {
  generateKeyPair,
  signManifest,
  generateTemplate,
  attestSpawn,
  attestSpawnVerified,
  sanitizeArgs,
  evalArgRule,
  looksCatastrophic,
  containsTraversal,
  AttestationError,
  type Manifest,
  type SpawnRule,
  type ArgRule,
} from "../src/index.js";

function buildSigned(spawnRules: SpawnRule[], tools: Manifest["tools"] = []) {
  const kp = generateKeyPair();
  const tpl = generateTemplate({ serverName: "harden-test", toolNames: ["t"] });
  const m: Manifest = {
    ...tpl,
    publicKeyFingerprint: kp.fingerprint,
    signer: "harden-tester",
    signedAt: new Date().toISOString(),
    tools,
    spawnRules,
  };
  return { signed: signManifest(m, kp.privateKeyHex), kp };
}

// ---------------------------------------------------------------------------
// A. ReDoS guard
// ---------------------------------------------------------------------------
describe("A. ReDoS guard — looksCatastrophic detector", () => {
  const dangerous = [
    "(a+)+$",
    "(a*)*",
    "(.*)+",
    "(.+)*",
    "(a+)+",
    "(\\d+)+$",
    "([a-z]+)*$",
    "(.*a){15}$",
    "(x+x+)+y",
    "((ab)*)*",
    "(\\s+)*$",
    "(a{1,})+",
  ];
  const safe = [
    "^[a-z]+$",
    "^\\d{1,10}$",
    "^[a-zA-Z0-9_-]+$",
    "abc",
    "a*b*c*",
    "^/safe/[a-z]+\\.txt$",
    "(foo|bar)",
    "[0-9]{4}-[0-9]{2}",
    "\\w+@\\w+",
    "^(https?)://",
    "a+",
    "^.{1,64}$",
    "(abc)+",
    "(a|b)+",
    "(ab){2,5}",
    "^v\\d+\\.\\d+\\.\\d+$",
    "(cat|dog){1,3}",
  ];

  it.each(dangerous)("flags catastrophic pattern: %s", (p) => {
    expect(looksCatastrophic(p)).toBe(true);
  });

  it.each(safe)("does NOT flag safe pattern (zero false positives): %s", (p) => {
    expect(looksCatastrophic(p)).toBe(false);
  });

  it("the detector itself runs in linear time on a pathological pattern", () => {
    // A long alternation of nested quantifiers — the detector must not itself
    // backtrack. 2k chars should be sub-millisecond.
    const pattern = "(a+)+".repeat(400);
    const start = Date.now();
    expect(looksCatastrophic(pattern)).toBe(true);
    expect(Date.now() - start).toBeLessThan(50);
  });
});

describe("A. ReDoS guard — evalArgRule fails closed on dangerous patterns", () => {
  it("refuses to evaluate a catastrophic pattern (no hang) and returns a clear reason", () => {
    const rule: ArgRule = { name: "x", kind: "regex", required: true, pattern: "(a+)+$" };
    const start = Date.now();
    // The classic exponential trigger input. Without the guard this hangs for
    // tens of seconds; with it, it returns immediately.
    const reasons = evalArgRule("a".repeat(40) + "!", rule);
    expect(Date.now() - start).toBeLessThan(100);
    expect(reasons.length).toBeGreaterThan(0);
    expect(reasons.join(" ")).toMatch(/catastrophic backtracking/);
  });

  it("a safe regex still matches and rejects as before", () => {
    const rule: ArgRule = { name: "x", kind: "regex", required: true, pattern: "^[a-z]+$" };
    expect(evalArgRule("hello", rule)).toEqual([]);
    expect(evalArgRule("Hello", rule).length).toBeGreaterThan(0);
  });

  it("hard input-length cap (defense-in-depth) rejects over-long input before matching", () => {
    const rule: ArgRule = { name: "x", kind: "regex", required: true, pattern: "^a+$", maxLength: 8 };
    expect(evalArgRule("aaaaaaaa", rule)).toEqual([]); // exactly 8 ok
    const reasons = evalArgRule("aaaaaaaaa", rule); // 9 chars
    expect(reasons.join(" ")).toMatch(/exceeds regex maxLength/);
  });

  it("attestSpawn does not freeze when a manifest ships a catastrophic regex", () => {
    const { signed } = buildSigned([
      {
        command: "/usr/bin/tool",
        args: [{ name: "x", kind: "regex", required: true, pattern: "(a+)+$" }],
        maxTotalArgLength: 4096,
      },
    ]);
    const start = Date.now();
    const r = attestSpawn(signed, { command: "/usr/bin/tool", args: ["a".repeat(45) + "!"] });
    expect(Date.now() - start).toBeLessThan(100);
    expect(r.allowed).toBe(false);
    expect(r.blockedReasons.join(" ")).toMatch(/catastrophic/);
  });
});

// ---------------------------------------------------------------------------
// B. Control-character gap (VT / FF / NEL)
// ---------------------------------------------------------------------------
describe("B. shellSafeString blocks VT / FF / NEL", () => {
  const rule: SpawnRule = {
    command: "/x",
    args: [{ name: "a", kind: "shellSafeString", required: true, maxLength: 256 }],
    maxTotalArgLength: 1024,
  };

  it.each([
    ["VT U+000B", "ab"],
    ["FF U+000C", "ab"],
    ["NEL U+0085", "ab"],
  ])("blocks %s", (_label, payload) => {
    const r = sanitizeArgs([payload], rule);
    expect(r.allowed).toBe(false);
    expect(r.blockedReasons.join(" ")).toMatch(/forbidden character/);
  });

  it("still allows a plain space-separated value (no over-reach)", () => {
    expect(sanitizeArgs(["hello world"], rule).allowed).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// C. Prefix path-traversal
// ---------------------------------------------------------------------------
describe("C. containsTraversal helper", () => {
  it.each([
    "/safe/../etc/passwd",
    "/safe/../../etc/passwd",
    "..",
    "../x",
    "x/..",
    "a/../b",
    "a\\..\\b",
    "/safe/%2e%2e/etc/passwd",
    "/safe/%2E%2E/etc/passwd",
  ])("detects traversal in: %s", (v) => {
    expect(containsTraversal(v)).toBe(true);
  });

  it.each([
    "/safe/file.txt",
    "/safe/sub/dir/file",
    "file..name", // `..` embedded in a token, not a path component
    "version.2.0",
    "a..b", // not bounded by separators
    "/safe/...hidden", // three dots is not a `..` component
  ])("does NOT flag legitimate value: %s", (v) => {
    expect(containsTraversal(v)).toBe(false);
  });
});

describe("C. prefix rule rejects traversal by default, allows clean paths", () => {
  it("ATTACK: /safe/../../etc/passwd is blocked even though it satisfies the prefix", () => {
    const { signed } = buildSigned([
      {
        command: "/usr/bin/cat",
        args: [{ name: "file", kind: "prefix", required: true, prefix: "/safe/", maxSuffixLength: 256 }],
        maxTotalArgLength: 1024,
      },
    ]);
    const r = attestSpawn(signed, { command: "/usr/bin/cat", args: ["/safe/../../etc/passwd"] });
    expect(r.allowed).toBe(false);
    expect(r.blockedReasons.join(" ")).toMatch(/path-traversal/);
  });

  it("BENIGN: a clean path under the prefix is still allowed", () => {
    const { signed } = buildSigned([
      {
        command: "/usr/bin/cat",
        args: [{ name: "file", kind: "prefix", required: true, prefix: "/safe/", maxSuffixLength: 256 }],
        maxTotalArgLength: 1024,
      },
    ]);
    const r = attestSpawn(signed, { command: "/usr/bin/cat", args: ["/safe/reports/q1.txt"] });
    expect(r.allowed).toBe(true);
  });

  it("OPT-OUT: denyTraversal:false restores legacy startsWith-only behaviour", () => {
    const reasons = evalArgRule("/safe/../x", {
      name: "file",
      kind: "prefix",
      required: true,
      prefix: "/safe/",
      maxSuffixLength: 256,
      denyTraversal: false,
    });
    expect(reasons).toEqual([]);
  });

  it("missing-prefix is still reported (no behaviour drift)", () => {
    const reasons = evalArgRule("/etc/passwd", {
      name: "file",
      kind: "prefix",
      required: true,
      prefix: "/safe/",
      maxSuffixLength: 256,
    });
    expect(reasons.join(" ")).toMatch(/missing required prefix/);
  });
});

// ---------------------------------------------------------------------------
// D. attestSpawnVerified
// ---------------------------------------------------------------------------
describe("D. attestSpawnVerified — verify-then-attest fail-safe", () => {
  function fixture() {
    return buildSigned([
      {
        command: "/usr/bin/echo",
        args: [{ name: "m", kind: "shellSafeString", required: true, maxLength: 256 }],
        maxTotalArgLength: 1024,
      },
    ]);
  }

  it("passes for a valid manifest + allowed request", () => {
    const { signed } = fixture();
    expect(() => attestSpawnVerified(signed, { command: "/usr/bin/echo", args: ["hello"] })).not.toThrow();
  });

  it("ATTACK: a tampered manifest (extra spawn rule, not re-signed) is rejected at the signature step", () => {
    const { signed } = fixture();
    const tampered = {
      ...signed,
      manifest: {
        ...signed.manifest,
        spawnRules: [
          ...signed.manifest.spawnRules,
          { command: "/bin/bash", args: [], maxTotalArgLength: 1024 },
        ],
      },
    } as typeof signed;

    // Bare attestSpawn would wrongly allow it (documented footgun) ...
    expect(attestSpawn(tampered, { command: "/bin/bash", args: [] }).allowed).toBe(true);
    // ... but the verified variant fails closed on the broken signature.
    let thrown: unknown;
    try {
      attestSpawnVerified(tampered, { command: "/bin/bash", args: [] });
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(AttestationError);
    expect((thrown as AttestationError).code).toBe("SIGNATURE_INVALID");
  });

  it("throws the usual spawn codes for a valid manifest but disallowed command", () => {
    const { signed } = fixture();
    let thrown: unknown;
    try {
      attestSpawnVerified(signed, { command: "/bin/bash", args: ["-c", "ls"] });
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(AttestationError);
    expect((thrown as AttestationError).code).toBe("SPAWN_COMMAND_NOT_ALLOWED");
  });

  it("honours the verify `now` option (expired manifest rejected before attest)", () => {
    const kp = generateKeyPair();
    const tpl = generateTemplate({ serverName: "harden-test", toolNames: ["t"] });
    const m: Manifest = {
      ...tpl,
      publicKeyFingerprint: kp.fingerprint,
      signer: "harden-tester",
      signedAt: "2026-04-27T00:00:00.000Z",
      expiresAt: "2026-04-28T00:00:00.000Z",
      spawnRules: [
        { command: "/usr/bin/echo", args: [{ name: "m", kind: "shellSafeString", required: true, maxLength: 256 }], maxTotalArgLength: 1024 },
      ],
    };
    const signed = signManifest(m, kp.privateKeyHex);
    expect(() =>
      attestSpawnVerified(signed, { command: "/usr/bin/echo", args: ["ok"] }, { now: new Date("2026-04-29T00:00:00Z") }),
    ).toThrow(AttestationError);
  });
});

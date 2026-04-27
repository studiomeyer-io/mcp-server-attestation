import { describe, it, expect } from "vitest";
import {
  generateKeyPair,
  signManifest,
  attestSpawn,
  attestSpawnStrict,
  generateTemplate,
  AttestationError,
  type Manifest,
} from "../src/index.js";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

function buildSignedManifest(): {
  signed: ReturnType<typeof signManifest>;
} {
  const kp = generateKeyPair();
  const tpl = generateTemplate({ serverName: "spawn-test", toolNames: ["search", "open"] });
  const m: Manifest = {
    ...tpl,
    publicKeyFingerprint: kp.fingerprint,
    signer: "spawn-tester",
    signedAt: new Date().toISOString(),
    tools: [
      {
        name: "search",
        description: "Search by query",
        readOnlyHint: true,
        destructiveHint: false,
        args: [{ name: "q", kind: "length", required: true, min: 1, max: 64 }],
      },
      {
        name: "open",
        description: "Open a path",
        readOnlyHint: true,
        destructiveHint: false,
        args: [{ name: "path", kind: "prefix", required: true, prefix: "/safe/", maxSuffixLength: 256 }],
      },
    ],
    spawnRules: [
      {
        command: "/usr/bin/echo",
        args: [{ name: "msg", kind: "shellSafeString", required: true, maxLength: 256 }],
        maxTotalArgLength: 1024,
      },
      {
        command: "/usr/bin/cat",
        args: [{ name: "file", kind: "prefix", required: true, prefix: "/safe/", maxSuffixLength: 256 }],
        maxTotalArgLength: 1024,
      },
    ],
  };
  return { signed: signManifest(m, kp.privateKeyHex) };
}

describe("attestSpawn", () => {
  const { signed } = buildSignedManifest();

  it("allows a clean echo call", () => {
    const r = attestSpawn(signed, { command: "/usr/bin/echo", args: ["hello world"] });
    expect(r.allowed).toBe(true);
    expect(r.matchedRule).toBe("/usr/bin/echo");
    expect(r.signer).toBe("spawn-tester");
    expect(r.serverName).toBe("spawn-test");
  });

  it("blocks an unknown command", () => {
    const r = attestSpawn(signed, { command: "/bin/bash", args: ["-c", "ls"] });
    expect(r.allowed).toBe(false);
    expect(r.matchedRule).toBeNull();
    expect(r.blockedReasons.join(" ")).toMatch(/not allowed/);
  });

  it("blocks shell-meta in echo arg", () => {
    const r = attestSpawn(signed, { command: "/usr/bin/echo", args: ["hi; rm -rf /"] });
    expect(r.allowed).toBe(false);
  });

  it("blocks cat with path-traversal-like prefix violation", () => {
    const r = attestSpawn(signed, { command: "/usr/bin/cat", args: ["/etc/passwd"] });
    expect(r.allowed).toBe(false);
  });

  it("allows cat on whitelisted prefix", () => {
    const r = attestSpawn(signed, { command: "/usr/bin/cat", args: ["/safe/file.txt"] });
    expect(r.allowed).toBe(true);
  });

  it("validates tool args when toolName + toolArgs supplied", () => {
    const r = attestSpawn(signed, {
      command: "/usr/bin/echo",
      args: ["ok"],
      toolName: "search",
      toolArgs: { q: "" },
    });
    expect(r.allowed).toBe(false);
    expect(r.blockedReasons.join(" ")).toMatch(/length/);
  });

  it("rejects unknown tool name", () => {
    const r = attestSpawn(signed, { command: "/usr/bin/echo", args: ["x"], toolName: "unknown" });
    expect(r.allowed).toBe(false);
    expect(r.blockedReasons.join(" ")).toMatch(/not declared/);
  });

  it("rejects unknown tool arg keys (default-deny on shape)", () => {
    const r = attestSpawn(signed, {
      command: "/usr/bin/echo",
      args: ["ok"],
      toolName: "search",
      toolArgs: { q: "ok", extra: "evil" },
    });
    expect(r.allowed).toBe(false);
    expect(r.blockedReasons.join(" ")).toMatch(/unexpected arg/);
  });

  it("attestSpawnStrict throws on block", () => {
    expect(() =>
      attestSpawnStrict(signed, { command: "/bin/bash", args: ["-c", "ls"] }),
    ).toThrow(AttestationError);
  });
});

describe("CVE-replay fixtures", () => {
  const cve69256 = JSON.parse(
    readFileSync(resolve(__dirname, "fixtures/cve-2025-69256-payloads.json"), "utf-8"),
  ) as { payloads: string[] };
  const cve61591 = JSON.parse(
    readFileSync(resolve(__dirname, "fixtures/cve-2025-61591-payloads.json"), "utf-8"),
  ) as { payloads: string[] };

  const { signed } = buildSignedManifest();

  it("CVE-2025-69256 payloads are all blocked on echo", () => {
    for (const p of cve69256.payloads) {
      const r = attestSpawn(signed, { command: "/usr/bin/echo", args: [p] });
      expect(r.allowed, `payload should be blocked: ${JSON.stringify(p)}`).toBe(false);
    }
  });

  it("CVE-2025-61591 spawn-hijack payloads are all blocked", () => {
    for (const p of cve61591.payloads) {
      const r = attestSpawn(signed, { command: p, args: [] });
      expect(r.allowed, `command should be blocked: ${JSON.stringify(p)}`).toBe(false);
    }
  });
});

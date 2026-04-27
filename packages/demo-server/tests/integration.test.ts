import { describe, it, expect } from "vitest";
import { ALL_TOOLS } from "../src/tools/index.js";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  generateKeyPair,
  signManifest,
  generateTemplate,
  type Manifest,
} from "mcp-server-attestation";

describe("demo server tools — schema + smoke", () => {
  it("exposes the 5 tools from the plan", () => {
    const names = ALL_TOOLS.map((t) => t.name).sort();
    expect(names).toEqual(
      [
        "attest_generate_manifest_template",
        "attest_inspect_spawn",
        "attest_keygen",
        "attest_sign_manifest",
        "attest_verify_manifest",
      ].sort(),
    );
  });

  it("annotations declared correctly", () => {
    const verify = ALL_TOOLS.find((t) => t.name === "attest_verify_manifest")!;
    expect(verify.readOnlyHint).toBe(true);
    expect(verify.destructiveHint).toBe(false);
    const keygen = ALL_TOOLS.find((t) => t.name === "attest_keygen")!;
    expect(keygen.readOnlyHint).toBe(false);
    expect(keygen.destructiveHint).toBe(false);
  });

  it("attest_keygen writes both key files and returns matching fingerprint", async () => {
    const dir = join(tmpdir(), `mcp-attest-keygen-${Date.now()}`);
    const keygen = ALL_TOOLS.find((t) => t.name === "attest_keygen")!;
    const out = await keygen.handler(keygen.parse({ outputDir: dir, keyName: "ci-key" }));
    expect(out.isError).toBe(false);
    const parsed = JSON.parse(out.text) as {
      publicKeyPath: string;
      privateKeyPath: string;
      fingerprint: string;
      fingerprintFromHex: string;
    };
    expect(parsed.fingerprint).toBe(parsed.fingerprintFromHex);
    await expect(fs.access(parsed.publicKeyPath)).resolves.toBeUndefined();
    await expect(fs.access(parsed.privateKeyPath)).resolves.toBeUndefined();
  });

  it("attest_generate_manifest_template returns a parseable template", async () => {
    const tpl = ALL_TOOLS.find((t) => t.name === "attest_generate_manifest_template")!;
    const out = await tpl.handler(tpl.parse({ serverName: "x", toolNames: ["a", "b"] }));
    expect(out.isError).toBe(false);
    const parsed = JSON.parse(out.text) as { manifest: Manifest; instructions: string };
    expect(parsed.manifest.serverName).toBe("x");
    expect(parsed.manifest.tools.length).toBe(2);
    expect(parsed.instructions).toMatch(/sign/);
  });

  it("attest_verify_manifest happy roundtrip", async () => {
    // Build a real signed manifest, write it to disk, verify via the tool.
    const kp = generateKeyPair();
    const m: Manifest = {
      ...generateTemplate({ serverName: "verify-it", toolNames: ["x"] }),
      publicKeyFingerprint: kp.fingerprint,
      signer: "ci",
      signedAt: new Date().toISOString(),
    };
    const signed = signManifest(m, kp.privateKeyHex);
    const path = join(tmpdir(), `mcp-attest-signed-${Date.now()}.json`);
    const pubPath = join(tmpdir(), `mcp-attest-pub-${Date.now()}.hex`);
    await fs.writeFile(path, JSON.stringify(signed));
    await fs.writeFile(pubPath, kp.publicKeyHex);

    const verify = ALL_TOOLS.find((t) => t.name === "attest_verify_manifest")!;
    const out = await verify.handler(verify.parse({ manifestPath: path, publicKeyPath: pubPath }));
    expect(out.isError).toBe(false);
    const parsed = JSON.parse(out.text) as { valid: boolean; toolCount: number };
    expect(parsed.valid).toBe(true);
    expect(parsed.toolCount).toBe(1);
  });

  it("attest_inspect_spawn refuses unverifiable manifests", async () => {
    const inspect = ALL_TOOLS.find((t) => t.name === "attest_inspect_spawn")!;
    const kp = generateKeyPair();
    const m: Manifest = {
      ...generateTemplate({ serverName: "spawn-it", toolNames: [] }),
      publicKeyFingerprint: kp.fingerprint,
      signer: "ci",
      signedAt: new Date().toISOString(),
      spawnRules: [
        {
          command: "/usr/bin/echo",
          args: [{ name: "msg", kind: "shellSafeString", required: true, maxLength: 64 }],
          maxTotalArgLength: 1024,
        },
      ],
    };
    const signed = signManifest(m, kp.privateKeyHex);
    // Tamper with manifest before passing — should refuse.
    const tampered = { ...signed, manifest: { ...signed.manifest, signer: "evil" } };
    const out = await inspect.handler(
      inspect.parse({ command: "/usr/bin/echo", args: ["hi"], manifest: tampered }),
    );
    expect(out.isError).toBe(true);
  });
});

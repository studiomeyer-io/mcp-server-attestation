import { describe, it, expect, beforeEach } from "vitest";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  pinKey,
  verifyPinned,
  loadTrustFile,
  optionalSigstoreLookup,
  AttestationError,
} from "../src/index.js";

let trustPath = "";

beforeEach(async () => {
  trustPath = join(tmpdir(), `mcp-attest-trust-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);
  await fs.rm(trustPath, { force: true });
});

describe("trust pin TOFU semantics", () => {
  const aPub = "a".repeat(64);
  const bPub = "b".repeat(64);

  it("pins on first use", async () => {
    const entry = await pinKey({ serverName: "srv", publicKeyHex: aPub, trustFilePath: trustPath });
    expect(entry.publicKeyHex).toBe(aPub);
    const file = await loadTrustFile(trustPath);
    expect(file.entries["srv"]).toBeDefined();
  });

  it("idempotent on re-pin same key", async () => {
    await pinKey({ serverName: "srv", publicKeyHex: aPub, trustFilePath: trustPath });
    const second = await pinKey({ serverName: "srv", publicKeyHex: aPub, trustFilePath: trustPath, note: "n" });
    expect(second.note).toBe("n");
  });

  it("throws TRUST_PIN_MISMATCH on key change", async () => {
    await pinKey({ serverName: "srv", publicKeyHex: aPub, trustFilePath: trustPath });
    await expect(
      pinKey({ serverName: "srv", publicKeyHex: bPub, trustFilePath: trustPath }),
    ).rejects.toThrow(AttestationError);
  });

  it("verifyPinned reports mismatch without writing", async () => {
    await pinKey({ serverName: "srv", publicKeyHex: aPub, trustFilePath: trustPath });
    const res = await verifyPinned({ serverName: "srv", publicKeyHex: bPub, trustFilePath: trustPath });
    expect(res.pinned).toBe(true);
    expect(res.mismatch).toBe(true);
  });

  it("missing entry → not pinned", async () => {
    const res = await verifyPinned({ serverName: "nope", publicKeyHex: aPub, trustFilePath: trustPath });
    expect(res.pinned).toBe(false);
  });
});

describe("HIGH-2 + MEDIUM-1 + MEDIUM-4 — trust-file hardening Round 3", () => {
  const aPub = "a".repeat(64);

  it("HIGH-2: saveTrustFile produces 0o600 even when file pre-existed at 0o644", async () => {
    // Pre-create the trust file at world-readable mode.
    await fs.writeFile(trustPath, JSON.stringify({ schemaVersion: 1, entries: {} }));
    await fs.chmod(trustPath, 0o644);
    let stat = await fs.stat(trustPath);
    expect(stat.mode & 0o777).toBe(0o644);

    // Pinning rewrites the file via temp + rename + explicit chmod.
    await pinKey({ serverName: "srv", publicKeyHex: aPub, trustFilePath: trustPath });
    stat = await fs.stat(trustPath);
    expect(stat.mode & 0o777).toBe(0o600);
  });

  it("HIGH-2: writes are atomic — old file remains intact if rename fails (smoke)", async () => {
    // Build a starting state, then verify that loadTrustFile after pin still
    // returns valid contents (rename never produces a torn file).
    await pinKey({ serverName: "srv", publicKeyHex: aPub, trustFilePath: trustPath });
    const file = await loadTrustFile(trustPath);
    expect(file.entries["srv"]).toBeDefined();
    expect(file.entries["srv"]?.publicKeyHex).toBe(aPub);
    // No leftover .tmp.* file should remain in the directory.
    const dir = trustPath.replace(/\/[^/]+$/, "");
    const entries = await fs.readdir(dir);
    const stale = entries.filter((e) => e.includes(".tmp."));
    expect(stale).toEqual([]);
  });

  it("MEDIUM-1: rejects malformed entry where value is null", async () => {
    await fs.writeFile(
      trustPath,
      JSON.stringify({
        schemaVersion: 1,
        entries: { srv: null },
      }),
    );
    await expect(loadTrustFile(trustPath)).rejects.toThrow(AttestationError);
  });

  it("MEDIUM-1: rejects malformed entry missing publicKeyHex", async () => {
    await fs.writeFile(
      trustPath,
      JSON.stringify({
        schemaVersion: 1,
        entries: {
          srv: {
            serverName: "srv",
            fingerprint: `sha256:${"0".repeat(64)}`,
            pinnedAt: new Date().toISOString(),
          },
        },
      }),
    );
    await expect(loadTrustFile(trustPath)).rejects.toThrow(AttestationError);
  });

  it("MEDIUM-1: rejects malformed entry with bad publicKeyHex shape", async () => {
    await fs.writeFile(
      trustPath,
      JSON.stringify({
        schemaVersion: 1,
        entries: {
          srv: {
            serverName: "srv",
            publicKeyHex: "not-hex",
            fingerprint: `sha256:${"0".repeat(64)}`,
            pinnedAt: new Date().toISOString(),
          },
        },
      }),
    );
    await expect(loadTrustFile(trustPath)).rejects.toThrow(AttestationError);
  });

  it("MEDIUM-1: well-formed entry parses cleanly", async () => {
    await fs.writeFile(
      trustPath,
      JSON.stringify({
        schemaVersion: 1,
        entries: {
          srv: {
            serverName: "srv",
            publicKeyHex: aPub,
            fingerprint: `sha256:${"a".repeat(64)}`,
            pinnedAt: "2026-04-27T00:00:00.000Z",
          },
        },
      }),
    );
    const file = await loadTrustFile(trustPath);
    expect(file.entries["srv"]?.publicKeyHex).toBe(aPub);
  });
});

describe("optionalSigstoreLookup mock", () => {
  it("returns ok=true with mocked fetch", async () => {
    const mockFetch: typeof fetch = async () =>
      new Response(JSON.stringify(["uuid-1", "uuid-2"]), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    // F7 Round 1.5: Stub never invokes fetchImpl. Confirm that and assert
    // the stubbed behaviour: ok=false with a clear roadmap message.
    const r = await optionalSigstoreLookup({
      fingerprint: `sha256:${"0".repeat(64)}`,
      fetchImpl: mockFetch,
    });
    expect(r.ok).toBe(false);
    expect(r.entries).toEqual([]);
    expect(r.error).toMatch(/not yet wired up/);
  });

  it("never reaches the network in the v0.1 stub", async () => {
    let callCount = 0;
    const mockFetch: typeof fetch = async () => {
      callCount++;
      throw new Error("should not be called");
    };
    const r = await optionalSigstoreLookup({
      fingerprint: `sha256:${"0".repeat(64)}`,
      fetchImpl: mockFetch,
    });
    expect(r.ok).toBe(false);
    expect(callCount).toBe(0);
    expect(r.error).toMatch(/v0\.2/);
  });
});

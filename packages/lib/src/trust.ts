import { promises as fs } from "node:fs";
import { dirname, join, isAbsolute } from "node:path";
import { homedir } from "node:os";
import { AttestationError } from "./errors.js";
import { fingerprintFromPublicKeyHex } from "./sign.js";

/**
 * Trust-on-First-Use store for verified MCP-server public keys.
 *
 * File location: $MCP_ATTEST_TRUST_FILE or ~/.mcp-attest/trust.json
 *
 * Per Pre-Build Decision D1: TOFU is the default path. We do NOT ship a
 * curated trusted-keys list. Sigstore Rekor cross-reference is opt-in via
 * `sigstoreEntries` field (filled by the CLI on `verify --sigstore`).
 */

export interface TrustEntry {
  serverName: string;
  publicKeyHex: string;
  fingerprint: string;
  pinnedAt: string;
  /** Optional Sigstore Rekor cross-reference. */
  sigstoreEntries?: Array<{ logIndex: number; uuid: string; fetchedAt: string }>;
  /** Free-form notes from the user (e.g. "verified out-of-band on 2026-04-27"). */
  note?: string;
}

export interface TrustFile {
  schemaVersion: 1;
  entries: Record<string, TrustEntry>;
}

const DEFAULT_TRUST_DIR = ".mcp-attest";
const DEFAULT_TRUST_FILENAME = "trust.json";

export function defaultTrustFilePath(): string {
  const override = process.env["MCP_ATTEST_TRUST_FILE"];
  if (override !== undefined && override.length > 0) {
    return isAbsolute(override) ? override : join(process.cwd(), override);
  }
  return join(homedir(), DEFAULT_TRUST_DIR, DEFAULT_TRUST_FILENAME);
}

export async function loadTrustFile(path: string = defaultTrustFilePath()): Promise<TrustFile> {
  try {
    // F11 Round 2: warn if the trust file is world-readable / group-readable.
    // The file holds public keys + server names — leakage is not catastrophic
    // but does reveal user-server inventory. We warn rather than throw so a
    // first-time install or a botched chmod does not break the CLI.
    try {
      const stat = await fs.stat(path);
      const groupOrOtherReadable = (stat.mode & 0o077) !== 0;
      if (groupOrOtherReadable && process.env["MCP_ATTEST_QUIET_TRUST_MODE"] !== "1") {
        // eslint-disable-next-line no-console
        console.warn(
          `[mcp-attest] trust file ${path} has permissive mode ${(stat.mode & 0o777).toString(8)}; recommended 0600. Set MCP_ATTEST_QUIET_TRUST_MODE=1 to silence.`,
        );
      }
    } catch {
      // Stat failure here is harmless — readFile below will surface a real
      // error. We do not let the mode-check itself block loading.
    }

    const raw = await fs.readFile(path, "utf-8");
    const parsed: unknown = JSON.parse(raw);
    return validateTrustFile(parsed);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ENOENT") {
      return { schemaVersion: 1, entries: {} };
    }
    if (err instanceof AttestationError) throw err;
    throw new AttestationError("TRUST_FILE_PARSE_ERROR", "Failed to read or parse trust file", {
      path,
      cause: err instanceof Error ? err.message : String(err),
    });
  }
}

/**
 * Atomically replace the trust file with the new contents at mode 0o600.
 *
 * HIGH-2 fix Round 3: previously `fs.writeFile(path, data, { mode: 0o600 })`.
 * Node.js (and POSIX) only honours `mode` when the file does NOT yet exist;
 * subsequent writes to a pre-existing trust file inherit whatever permissions
 * are in place. An attacker who pre-creates the trust file at 0o644 (or
 * symlinks it to a world-readable location) keeps those permissions through
 * every later `pinKey` call.
 *
 * The temp-write + explicit chmod + atomic rename combo:
 *   1. Forces 0o600 on the new content regardless of the previous mode.
 *   2. Replaces the trust file in a single rename(2) syscall — closes the
 *      TOFU TOCTOU window between load and save (MEDIUM-4 fix mit-erledigt).
 *   3. Survives partial-write crashes — old file remains intact until rename.
 *
 * The temp file is suffixed with the PID so concurrent `pinKey` calls in the
 * same process do not stomp on each other; on POSIX `rename` is atomic and
 * the last writer wins (still last-write-wins semantically, but no torn
 * intermediate state).
 */
export async function saveTrustFile(file: TrustFile, path: string = defaultTrustFilePath()): Promise<void> {
  await fs.mkdir(dirname(path), { recursive: true });
  const tmpPath = `${path}.tmp.${process.pid}.${Date.now()}`;
  const payload = JSON.stringify(file, null, 2) + "\n";
  try {
    await fs.writeFile(tmpPath, payload, { mode: 0o600 });
    // Explicit chmod survives the case where umask or pre-existing FS state
    // would otherwise leave the temp file with looser permissions.
    await fs.chmod(tmpPath, 0o600);
    await fs.rename(tmpPath, path);
  } catch (err) {
    // Best-effort cleanup — temp file might or might not exist.
    try {
      await fs.rm(tmpPath, { force: true });
    } catch {
      // ignore
    }
    throw err;
  }
}

/**
 * Pin a public key for a server, first-use semantics.
 *
 * If the server already has an entry, the existing public key MUST match.
 * Mismatch throws TRUST_PIN_MISMATCH — this catches the Cursor-style
 * malicious-update scenario.
 */
export async function pinKey(args: {
  serverName: string;
  publicKeyHex: string;
  note?: string;
  trustFilePath?: string;
}): Promise<TrustEntry> {
  const path = args.trustFilePath ?? defaultTrustFilePath();
  const file = await loadTrustFile(path);
  const fingerprint = fingerprintFromPublicKeyHex(args.publicKeyHex);

  const existing = file.entries[args.serverName];
  if (existing !== undefined) {
    if (existing.publicKeyHex !== args.publicKeyHex) {
      throw new AttestationError(
        "TRUST_PIN_MISMATCH",
        `Server "${args.serverName}" is already pinned to a different key. Refusing to overwrite.`,
        {
          existingFingerprint: existing.fingerprint,
          newFingerprint: fingerprint,
          pinnedAt: existing.pinnedAt,
        },
      );
    }
    // Identical pin — idempotent. Update note if provided.
    if (args.note !== undefined) existing.note = args.note;
    await saveTrustFile(file, path);
    return existing;
  }

  const entry: TrustEntry = {
    serverName: args.serverName,
    publicKeyHex: args.publicKeyHex,
    fingerprint,
    pinnedAt: new Date().toISOString(),
    ...(args.note !== undefined ? { note: args.note } : {}),
  };
  file.entries[args.serverName] = entry;
  await saveTrustFile(file, path);
  return entry;
}

/**
 * Look up a pinned key. Returns undefined if no entry — callers decide
 * whether to fall back to TOFU.
 */
export async function verifyPinned(args: {
  serverName: string;
  publicKeyHex: string;
  trustFilePath?: string;
}): Promise<{ pinned: boolean; entry?: TrustEntry; mismatch?: boolean }> {
  const path = args.trustFilePath ?? defaultTrustFilePath();
  const file = await loadTrustFile(path);
  const entry = file.entries[args.serverName];
  if (entry === undefined) return { pinned: false };
  if (entry.publicKeyHex !== args.publicKeyHex) {
    return { pinned: true, entry, mismatch: true };
  }
  return { pinned: true, entry };
}

/**
 * Optional Sigstore Rekor lookup — STUB (v0.2 feature).
 *
 * F7 fix Round 1.5: the previous implementation POSTed
 * `{ hash: <fingerprint> }` to /api/v1/index/retrieve, which is the
 * artifact-hash field, not the public-key index. Lookup never matched even
 * for keys that ARE in Rekor. Per the canonical decision (D1), TOFU is the
 * v1 default; Sigstore-bridge is opt-in but must be functionally correct
 * before we ship it. Rather than ship a broken claim, the function is now
 * an explicit stub returning `ok:false, error:"sigstore-bridge not yet
 * wired up"`. Real implementation needs:
 *   - public-key search via { publicKey: { content: <base64-DER>, format: "x509" }}
 *   - or artifact-hash lookup tied to the signed manifest itself
 *   - integration tests against rekor.sigstore.dev
 * Tracked for v0.2 in the README "Roadmap" section.
 *
 * The function signature is preserved so callers continue to compile.
 * `args.fingerprint` is currently unused but documents the v0.2 contract.
 */
export async function optionalSigstoreLookup(_args: {
  fingerprint: string;
  rekorBaseUrl?: string;
  fetchImpl?: typeof fetch;
}): Promise<{ ok: boolean; entries: Array<{ logIndex: number; uuid: string }>; error?: string }> {
  // Intentional stub. Returning ok:false with a descriptive error makes the
  // behaviour observable to the CLI ("sigstore lookup not yet implemented")
  // and keeps any caller's `if (result.ok)` branches from acting on stale
  // empty arrays. Round 2 will replace this with a correct rekor call.
  return {
    ok: false,
    entries: [],
    error: "sigstore-bridge not yet wired up — v0.2 feature, see README roadmap",
  };
}

/**
 * MEDIUM-1 fix Round 3: per-entry validation + null-prototype container.
 *
 * Previously `entries` was returned as a raw `Record<string, unknown>` cast,
 * which meant a malformed trust file with `entries: { "srv": null }` would
 * crash `pinKey` at access time with `TypeError: Cannot read properties of
 * null` instead of being caught at parse time.
 *
 * The `Object.create(null)` container is a defence-in-depth measure: even
 * though modern Node's `JSON.parse` does not honour `__proto__` keys, a
 * caller passing an arbitrary object to `validateTrustFile` (private but
 * could be re-exported in v0.2) cannot now pollute the entries map.
 */
function validateTrustFile(parsed: unknown): TrustFile {
  if (typeof parsed !== "object" || parsed === null) {
    throw new AttestationError("TRUST_FILE_PARSE_ERROR", "Trust file root must be an object");
  }
  const obj = parsed as Record<string, unknown>;
  if (obj["schemaVersion"] !== 1) {
    throw new AttestationError("TRUST_FILE_PARSE_ERROR", "Trust file schemaVersion must be 1", {
      received: obj["schemaVersion"],
    });
  }
  const rawEntries = obj["entries"];
  if (typeof rawEntries !== "object" || rawEntries === null) {
    throw new AttestationError("TRUST_FILE_PARSE_ERROR", "Trust file entries must be an object");
  }
  const validated: Record<string, TrustEntry> = Object.create(null) as Record<string, TrustEntry>;
  for (const [key, value] of Object.entries(rawEntries as Record<string, unknown>)) {
    if (typeof value !== "object" || value === null) {
      throw new AttestationError(
        "TRUST_FILE_PARSE_ERROR",
        `Trust entry '${key}' must be an object`,
        { receivedType: value === null ? "null" : typeof value },
      );
    }
    const entry = value as Record<string, unknown>;
    if (typeof entry["serverName"] !== "string" || entry["serverName"].length === 0) {
      throw new AttestationError(
        "TRUST_FILE_PARSE_ERROR",
        `Trust entry '${key}' missing or invalid 'serverName'`,
      );
    }
    if (typeof entry["publicKeyHex"] !== "string" || !/^[0-9a-f]{64}$/.test(entry["publicKeyHex"])) {
      throw new AttestationError(
        "TRUST_FILE_PARSE_ERROR",
        `Trust entry '${key}' missing or invalid 'publicKeyHex' (must be 64 lowercase hex chars)`,
      );
    }
    if (typeof entry["fingerprint"] !== "string" || !/^sha256:[0-9a-f]{64}$/.test(entry["fingerprint"])) {
      throw new AttestationError(
        "TRUST_FILE_PARSE_ERROR",
        `Trust entry '${key}' missing or invalid 'fingerprint' (must be sha256:<64-hex>)`,
      );
    }
    if (typeof entry["pinnedAt"] !== "string") {
      throw new AttestationError(
        "TRUST_FILE_PARSE_ERROR",
        `Trust entry '${key}' missing or invalid 'pinnedAt'`,
      );
    }
    validated[key] = entry as unknown as TrustEntry;
  }
  return { schemaVersion: 1, entries: validated };
}

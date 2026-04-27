#!/usr/bin/env node
import { promises as fs } from "node:fs";
import { join, resolve } from "node:path";
import {
  generateKeyPair,
  fingerprintFromPublicKeyHex,
  parseManifest,
  parseSignedManifest,
  signManifest,
  verifyManifest,
  pinKey,
  verifyPinned,
  optionalSigstoreLookup,
  attestSpawn,
  AttestationError,
} from "mcp-server-attestation";

interface ParsedArgs {
  command: string;
  positional: string[];
  flags: Record<string, string | boolean | string[]>;
}

/**
 * Parse argv into command + positional + flags.
 *
 * Repeated flags accumulate into an array (so `--arg a --arg b` becomes
 * `flags.arg = ["a", "b"]`) — F4 fix Round 1.5. Was previously last-wins.
 */
function parseArgv(argv: string[]): ParsedArgs {
  const command = argv[0] ?? "help";
  const rest = argv.slice(1);
  const positional: string[] = [];
  const flags: Record<string, string | boolean | string[]> = {};
  for (let i = 0; i < rest.length; i++) {
    const tok = rest[i];
    if (tok === undefined) continue;
    if (tok.startsWith("--")) {
      const key = tok.slice(2);
      const next = rest[i + 1];
      if (next !== undefined && !next.startsWith("--")) {
        const existing = flags[key];
        if (Array.isArray(existing)) {
          existing.push(next);
        } else if (typeof existing === "string") {
          // promote single string to array on second occurrence
          flags[key] = [existing, next];
        } else {
          // undefined or boolean — set as single string
          flags[key] = next;
        }
        i++;
      } else {
        if (flags[key] === undefined) flags[key] = true;
        // repeated boolean flag is a no-op
      }
    } else {
      positional.push(tok);
    }
  }
  return { command, positional, flags };
}

function help(): string {
  return `mcp-attest — CLI for MCP tool-manifest attestation

Usage:
  mcp-attest keygen   --out-dir <dir> --name <key-name>
  mcp-attest sign     --manifest <path> --private-key <path> --out <path>
  mcp-attest verify   --signed <path> [--pin] [--server <name>] [--sigstore]
  mcp-attest inspect  --signed <path> --command <cmd> [--arg <a> ...]
  mcp-attest help

All cryptographic operations use Ed25519 via Node \`node:crypto\`. No external
crypto dependencies. See README for the 5-line server quickstart.
`;
}

async function cmdKeygen(args: ParsedArgs): Promise<void> {
  const outDir = stringFlag(args, "out-dir");
  const keyName = stringFlag(args, "name");
  const dir = resolve(outDir);
  await fs.mkdir(dir, { recursive: true });
  const { publicKeyHex, privateKeyHex, fingerprint } = generateKeyPair();
  const pubPath = join(dir, `${keyName}.pub`);
  const privPath = join(dir, `${keyName}.key`);
  await fs.writeFile(pubPath, publicKeyHex + "\n", { mode: 0o644 });
  await fs.writeFile(privPath, privateKeyHex + "\n", { mode: 0o600 });
  process.stdout.write(
    JSON.stringify({ publicKeyPath: pubPath, privateKeyPath: privPath, fingerprint }, null, 2) + "\n",
  );
}

async function cmdSign(args: ParsedArgs): Promise<void> {
  const manifestPath = stringFlag(args, "manifest");
  const privateKeyPath = stringFlag(args, "private-key");
  const outPath = stringFlag(args, "out");

  const manifestRaw = await fs.readFile(resolve(manifestPath), "utf-8");
  const manifest = parseManifest(manifestRaw);
  const privateKeyHex = (await fs.readFile(resolve(privateKeyPath), "utf-8")).trim();

  const signed = signManifest(manifest, privateKeyHex);
  await fs.writeFile(resolve(outPath), JSON.stringify(signed, null, 2) + "\n");
  process.stdout.write(
    JSON.stringify(
      {
        signature: signed.signature,
        fingerprint: manifest.publicKeyFingerprint,
        signedAt: manifest.signedAt,
        outPath: resolve(outPath),
      },
      null,
      2,
    ) + "\n",
  );
}

async function cmdVerify(args: ParsedArgs): Promise<void> {
  const signedPath = stringFlag(args, "signed");
  const raw = await fs.readFile(resolve(signedPath), "utf-8");
  const signed = parseSignedManifest(raw);
  const result = verifyManifest(signed);

  let pinResult: { pinned: boolean; mismatch?: boolean } | null = null;
  if (args.flags["pin"] === true) {
    const serverName =
      typeof args.flags["server"] === "string" && args.flags["server"].length > 0
        ? args.flags["server"]
        : signed.manifest.serverName;
    if (result.valid) {
      const pinned = await pinKey({ serverName, publicKeyHex: signed.publicKey });
      pinResult = { pinned: true };
      void pinned;
    } else {
      pinResult = { pinned: false };
    }
  }

  let sigstore: Awaited<ReturnType<typeof optionalSigstoreLookup>> | null = null;
  if (args.flags["sigstore"] === true) {
    sigstore = await optionalSigstoreLookup({ fingerprint: result.fingerprint });
  }

  process.stdout.write(JSON.stringify({ ...result, pin: pinResult, sigstore }, null, 2) + "\n");
  if (!result.valid) process.exitCode = 2;
}

async function cmdInspect(args: ParsedArgs): Promise<void> {
  const signedPath = stringFlag(args, "signed");
  const command = stringFlag(args, "command");
  const argList: string[] = [];
  if (Array.isArray(args.flags["arg"])) {
    // already array
    argList.push(...(args.flags["arg"] as unknown as string[]));
  } else if (typeof args.flags["arg"] === "string") {
    argList.push(args.flags["arg"]);
  }
  // Support repeated --arg by scanning positional fallback
  for (const p of args.positional) argList.push(p);

  const raw = await fs.readFile(resolve(signedPath), "utf-8");
  const signed = parseSignedManifest(raw);
  const result = attestSpawn(signed, { command, args: argList });
  process.stdout.write(JSON.stringify(result, null, 2) + "\n");
  if (!result.allowed) process.exitCode = 2;
}

async function cmdFingerprint(args: ParsedArgs): Promise<void> {
  const pubPath = stringFlag(args, "public-key");
  const hex = (await fs.readFile(resolve(pubPath), "utf-8")).trim();
  process.stdout.write(fingerprintFromPublicKeyHex(hex) + "\n");
}

async function cmdCheckPin(args: ParsedArgs): Promise<void> {
  const serverName = stringFlag(args, "server");
  const signedPath = stringFlag(args, "signed");
  const raw = await fs.readFile(resolve(signedPath), "utf-8");
  const signed = parseSignedManifest(raw);
  const result = await verifyPinned({ serverName, publicKeyHex: signed.publicKey });
  process.stdout.write(JSON.stringify(result, null, 2) + "\n");
  if (result.mismatch === true) process.exitCode = 3;
}

function stringFlag(args: ParsedArgs, name: string): string {
  const v = args.flags[name];
  if (Array.isArray(v)) {
    throw new Error(`Flag --${name} must be a single value, got array`);
  }
  if (typeof v !== "string" || v.length === 0) {
    throw new Error(`Missing required flag --${name}`);
  }
  return v;
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const parsed = parseArgv(argv);

  try {
    switch (parsed.command) {
      case "keygen":
        await cmdKeygen(parsed);
        break;
      case "sign":
        await cmdSign(parsed);
        break;
      case "verify":
        await cmdVerify(parsed);
        break;
      case "inspect":
        await cmdInspect(parsed);
        break;
      case "fingerprint":
        await cmdFingerprint(parsed);
        break;
      case "check-pin":
        await cmdCheckPin(parsed);
        break;
      case "help":
      case "--help":
      case "-h":
        process.stdout.write(help());
        break;
      default:
        process.stderr.write(`Unknown command: ${parsed.command}\n\n${help()}`);
        process.exitCode = 64;
    }
  } catch (err) {
    if (err instanceof AttestationError) {
      process.stderr.write(
        JSON.stringify({ error: err.code, message: err.message, details: err.details }, null, 2) + "\n",
      );
      process.exitCode = 2;
    } else {
      process.stderr.write(`Error: ${err instanceof Error ? err.message : String(err)}\n`);
      process.exitCode = 1;
    }
  }
}

void main();

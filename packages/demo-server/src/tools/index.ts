import { promises as fs } from "node:fs";
import { join, resolve } from "node:path";
import {
  generateKeyPair,
  fingerprintFromPublicKeyHex,
  parseManifest,
  parseSignedManifest,
  signManifest,
  verifyManifest,
  attestSpawn,
  generateTemplate,
  type Manifest,
} from "mcp-server-attestation";
import {
  VerifyManifestArgs,
  InspectSpawnArgs,
  GenerateTemplateArgs,
  SignManifestArgs,
  KeygenArgs,
} from "../types.js";

export interface ToolDefinition<I, O> {
  name: string;
  description: string;
  readOnlyHint: boolean;
  destructiveHint: boolean;
  inputSchema: Record<string, unknown>;
  parse: (raw: unknown) => I;
  handler: (input: I) => Promise<O>;
}

export interface ToolOutput {
  /** Single content block — JSON serialised for stdout response. */
  text: string;
  /** Whether the tool considers this an error (mapped to MCP isError flag). */
  isError: boolean;
}

// ---- Tool 1: attest_verify_manifest ---------------------------------------
export const verifyManifestTool: ToolDefinition<VerifyManifestArgs, ToolOutput> = {
  name: "attest_verify_manifest",
  description:
    "Verify a signed MCP manifest file against an embedded or supplied public key. Returns valid + signer + toolCount + errors[].",
  readOnlyHint: true,
  destructiveHint: false,
  inputSchema: {
    type: "object",
    properties: {
      manifestPath: { type: "string", description: "Path to the signed-manifest JSON file." },
      publicKeyPath: { type: "string", description: "Path to the hex-encoded public key (informational, ignored if manifest carries its own publicKey field)." },
    },
    required: ["manifestPath", "publicKeyPath"],
    additionalProperties: false,
  },
  parse: (raw) => VerifyManifestArgs.parse(raw),
  handler: async (input) => {
    const raw = await fs.readFile(resolve(input.manifestPath), "utf-8");
    const signed = parseSignedManifest(raw);
    const result = verifyManifest(signed);
    return {
      text: JSON.stringify(
        {
          valid: result.valid,
          signer: result.signer,
          fingerprint: result.fingerprint,
          toolCount: result.toolCount,
          errors: result.errors,
        },
        null,
        2,
      ),
      isError: !result.valid,
    };
  },
};

// ---- Tool 2: attest_inspect_spawn -----------------------------------------
export const inspectSpawnTool: ToolDefinition<InspectSpawnArgs, ToolOutput> = {
  name: "attest_inspect_spawn",
  description:
    "Pre-flight a spawn request against an in-memory signed manifest object. Returns allowed + matchedRule + blockedReasons[].",
  readOnlyHint: true,
  destructiveHint: false,
  inputSchema: {
    type: "object",
    properties: {
      command: { type: "string", description: "Command to spawn." },
      args: { type: "array", items: { type: "string" }, description: "argv to validate." },
      manifest: { type: "object", description: "SignedManifest object (full payload, with manifest+signature+publicKey)." },
    },
    required: ["command", "args", "manifest"],
    additionalProperties: false,
  },
  parse: (raw) => InspectSpawnArgs.parse(raw),
  handler: async (input) => {
    const signed = parseSignedManifest(input.manifest);
    const verifyRes = verifyManifest(signed);
    if (!verifyRes.valid) {
      return {
        text: JSON.stringify(
          { allowed: false, matchedRule: null, blockedReasons: ["manifest signature invalid", ...verifyRes.errors] },
          null,
          2,
        ),
        isError: true,
      };
    }
    const result = attestSpawn(signed, { command: input.command, args: input.args });
    return {
      text: JSON.stringify(
        {
          allowed: result.allowed,
          matchedRule: result.matchedRule,
          blockedReasons: result.blockedReasons,
        },
        null,
        2,
      ),
      isError: !result.allowed,
    };
  },
};

// ---- Tool 3: attest_generate_manifest_template ----------------------------
export const generateTemplateTool: ToolDefinition<GenerateTemplateArgs, ToolOutput> = {
  name: "attest_generate_manifest_template",
  description:
    "Generate an unsigned manifest template for a server name and tool list. Caller fills in arg rules and signs.",
  readOnlyHint: true,
  destructiveHint: false,
  inputSchema: {
    type: "object",
    properties: {
      serverName: { type: "string" },
      toolNames: { type: "array", items: { type: "string" } },
    },
    required: ["serverName", "toolNames"],
    additionalProperties: false,
  },
  parse: (raw) => GenerateTemplateArgs.parse(raw),
  handler: async (input) => {
    const tpl: Manifest = generateTemplate({ serverName: input.serverName, toolNames: input.toolNames });
    return {
      text: JSON.stringify(
        {
          manifest: tpl,
          instructions:
            "1) Replace publicKeyFingerprint with `mcp-attest fingerprint --public-key <pub>`. 2) Define args[] per tool. 3) Add spawnRules[] for any child_process.spawn paths. 4) Sign with `mcp-attest sign`.",
        },
        null,
        2,
      ),
      isError: false,
    };
  },
};

// ---- Tool 4: attest_sign_manifest -----------------------------------------
export const signManifestTool: ToolDefinition<SignManifestArgs, ToolOutput> = {
  name: "attest_sign_manifest",
  description:
    "Sign a manifest file with an Ed25519 private key. Writes signed-manifest JSON to outputPath. The manifest's publicKeyFingerprint must already match the signing key.",
  readOnlyHint: false,
  destructiveHint: false,
  inputSchema: {
    type: "object",
    properties: {
      manifestPath: { type: "string" },
      privateKeyPath: { type: "string" },
      outputPath: { type: "string" },
    },
    required: ["manifestPath", "privateKeyPath", "outputPath"],
    additionalProperties: false,
  },
  parse: (raw) => SignManifestArgs.parse(raw),
  handler: async (input) => {
    const manifestRaw = await fs.readFile(resolve(input.manifestPath), "utf-8");
    const manifest = parseManifest(manifestRaw);
    const privateKeyHex = (await fs.readFile(resolve(input.privateKeyPath), "utf-8")).trim();
    const signed = signManifest(manifest, privateKeyHex);
    await fs.writeFile(resolve(input.outputPath), JSON.stringify(signed, null, 2) + "\n");
    return {
      text: JSON.stringify(
        {
          signature: signed.signature,
          fingerprint: manifest.publicKeyFingerprint,
          signedAt: manifest.signedAt,
          outputPath: resolve(input.outputPath),
        },
        null,
        2,
      ),
      isError: false,
    };
  },
};

// ---- Tool 5: attest_keygen ------------------------------------------------
export const keygenTool: ToolDefinition<KeygenArgs, ToolOutput> = {
  name: "attest_keygen",
  description:
    "Generate a fresh Ed25519 keypair and write public + private hex files plus return the sha256 fingerprint.",
  readOnlyHint: false,
  destructiveHint: false,
  inputSchema: {
    type: "object",
    properties: {
      outputDir: { type: "string" },
      keyName: { type: "string", pattern: "^[a-zA-Z0-9._-]+$" },
    },
    required: ["outputDir", "keyName"],
    additionalProperties: false,
  },
  parse: (raw) => KeygenArgs.parse(raw),
  handler: async (input) => {
    const dir = resolve(input.outputDir);
    await fs.mkdir(dir, { recursive: true });
    const { publicKeyHex, privateKeyHex, fingerprint } = generateKeyPair();
    const pub = join(dir, `${input.keyName}.pub`);
    const priv = join(dir, `${input.keyName}.key`);
    await fs.writeFile(pub, publicKeyHex + "\n", { mode: 0o644 });
    await fs.writeFile(priv, privateKeyHex + "\n", { mode: 0o600 });
    return {
      text: JSON.stringify(
        {
          publicKeyPath: pub,
          privateKeyPath: priv,
          fingerprint,
          fingerprintFromHex: fingerprintFromPublicKeyHex(publicKeyHex),
        },
        null,
        2,
      ),
      isError: false,
    };
  },
};

export const ALL_TOOLS = [
  verifyManifestTool,
  inspectSpawnTool,
  generateTemplateTool,
  signManifestTool,
  keygenTool,
] as const;

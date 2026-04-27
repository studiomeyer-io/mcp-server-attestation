export {
  ManifestSchema,
  SignedManifestSchema,
  ToolDeclSchema,
  SpawnRuleSchema,
  ArgRuleSchema,
  parseManifest,
  parseSignedManifest,
  canonicalize,
  generateTemplate,
} from "./manifest.js";
export type {
  Manifest,
  SignedManifest,
  ToolDecl,
  SpawnRule,
  ArgRule,
  ArgRuleKind,
} from "./manifest.js";
export { ARG_RULE_KIND } from "./manifest.js";

export {
  signManifest,
  signManifestAutoFingerprint,
  generateKeyPair,
  fingerprintFromPublicKeyHex,
} from "./sign.js";

export { verifyManifest, verifyManifestStrict } from "./verify.js";
export type { VerificationResult } from "./verify.js";

export {
  attestSpawn,
  attestSpawnStrict,
  sanitizeArgs,
  evalArgRule,
} from "./spawn.js";
export type { SpawnRequest, SanitizationResult, AttestationResult } from "./spawn.js";

export {
  pinKey,
  verifyPinned,
  loadTrustFile,
  saveTrustFile,
  defaultTrustFilePath,
  optionalSigstoreLookup,
} from "./trust.js";
export type { TrustEntry, TrustFile } from "./trust.js";

export { AttestationError } from "./errors.js";
export type { AttestationErrorCode } from "./errors.js";

/**
 * Library version, read dynamically from package.json so cli + server + lib
 * cannot drift on the next bump. F3 fix Round 1.5.
 */
import { readPackageVersion } from "./version.js";
export const LIB_VERSION = readPackageVersion();
export const SUPPORTED_MCP_SPEC_VERSIONS: ReadonlyArray<"2024-11-05" | "2025-03-26" | "2025-06-18"> = [
  "2025-06-18",
];

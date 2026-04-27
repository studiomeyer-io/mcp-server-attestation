import {
  type ArgRule,
  type Manifest,
  type SignedManifest,
  type SpawnRule,
  type ToolDecl,
} from "./manifest.js";
import { AttestationError } from "./errors.js";

/**
 * Default-deny shell-metacharacter set blocked by `shellSafeString` rules.
 *
 * Includes ASCII metacharacters (CVE-2025-69256 payloads) plus a curated set
 * of unicode confusables used in CVE-2025-61591-style spawn-hijack chains:
 *  - U+0000 NULL (argv terminator on POSIX)
 *  - U+000A LF, U+000D CR (newline-injection)
 *  - U+200B-U+200F zero-width / RTL-mark family
 *  - U+202A-U+202E bidi overrides (Trojan-Source CVE-2021-42574)
 *  - U+2028, U+2029 line/paragraph separators
 *  - U+FEFF BOM
 *  - U+2066-U+2069 isolates (Trojan-Source family)
 *  - U+FF01-U+FF5E FULLWIDTH ASCII (HIGH-1 fix Round 3) — without this
 *    block, an attacker can substitute every blocked ASCII metacharacter
 *    with its fullwidth confusable (U+FF04 FULLWIDTH DOLLAR SIGN, U+FF08
 *    FULLWIDTH LEFT PARENTHESIS, etc.) and bypass the sanitizer entirely.
 *    Most shells normalise none of these — but consumers may pipe sanitized
 *    args through layers that do (NFKC normalisation, IME). Default-deny
 *    is safer than retroactive whitelisting.
 */
const FORBIDDEN_CODEPOINTS: ReadonlySet<number> = (() => {
  const set = new Set<number>([
    // ASCII shell meta
    0x00, // null
    0x0a, // LF
    0x0d, // CR
    // Zero-width / formatting
    0x200b, 0x200c, 0x200d, 0x200e, 0x200f,
    // Bidi overrides
    0x202a, 0x202b, 0x202c, 0x202d, 0x202e,
    // Line/paragraph separators
    0x2028, 0x2029,
    // BOM
    0xfeff,
    // Isolates (Trojan-Source family)
    0x2066, 0x2067, 0x2068, 0x2069,
  ]);
  // FULLWIDTH ASCII block U+FF01-U+FF5E (HIGH-1 fix Round 3).
  // Covers FULLWIDTH DOLLAR/PAREN/SEMICOLON/PIPE/AMP/etc. — every char in
  // FORBIDDEN_ASCII_META has a fullwidth equivalent in this range.
  for (let cp = 0xff01; cp <= 0xff5e; cp++) set.add(cp);
  return set;
})();

/**
 * Default-deny ASCII shell metacharacters. Covers POSIX-shell + bash extensions.
 *
 * Rationale per character class:
 *  - Command substitution / param expansion: ` $ ( )
 *  - Statement separators / control: ; & | <newline (LF/CR are in FORBIDDEN_CODEPOINTS)
 *  - Redirects: < >
 *  - Escape: \
 *  - Globbing: * ? [ ] { }
 *  - History / aliasing / comment: ! #
 *  - Tilde expansion: ~
 *  - Quoting (breakouts of unquoted contexts): ' "
 *  - Whitespace splitting: TAB (space is allowed by length-bound shellSafeString rule)
 *
 * HIGH-1 fix Round 3: removed the redundant `"$("` two-byte entry. Both
 * `"$"` and `"("` are individually blocked, so the trigraph add no extra
 * security but produced duplicate `blockedReasons` entries that confused
 * downstream auditors.
 *
 * Listed individually so a future audit can grep for any single forbidden char.
 */
const FORBIDDEN_ASCII_META = [
  "`", "$", "(", ")", "[", "]", "{", "}",
  ";", "|", "&", "<", ">", "\\",
  "*", "?", "~", "!", "#",
  "\t", "'", "\"",
] as const;

export interface SpawnRequest {
  command: string;
  args: string[];
  /** Optional: which Tool the spawn is being made on behalf of. Used for tool-arg checks. */
  toolName?: string;
  /** Optional: tool args being passed to the tool. Validated against the matching tool decl. */
  toolArgs?: Record<string, unknown>;
}

export interface SanitizationResult {
  allowed: boolean;
  matchedRule: string | null;
  blockedReasons: string[];
}

export interface AttestationResult extends SanitizationResult {
  signer: string;
  serverName: string;
}

/**
 * Validate a single string against a single ArgRule. Returns an array of
 * blocked-reasons (empty if the value passes). Does NOT throw — meant to be
 * batch-evaluated.
 */
export function evalArgRule(value: unknown, rule: ArgRule): string[] {
  const reasons: string[] = [];
  if (typeof value !== "string") {
    reasons.push(`arg "${rule.name}" must be a string (got ${typeof value})`);
    return reasons;
  }
  switch (rule.kind) {
    case "regex": {
      let re: RegExp;
      try {
        re = new RegExp(rule.pattern, rule.flags);
      } catch (err) {
        reasons.push(
          `arg "${rule.name}" rule has invalid regex: ${err instanceof Error ? err.message : String(err)}`,
        );
        return reasons;
      }
      if (!re.test(value)) reasons.push(`arg "${rule.name}" did not match regex /${rule.pattern}/${rule.flags ?? ""}`);
      break;
    }
    case "enum": {
      if (!rule.values.includes(value)) {
        reasons.push(`arg "${rule.name}" not in enum [${rule.values.slice(0, 8).join(", ")}${rule.values.length > 8 ? ", ..." : ""}]`);
      }
      break;
    }
    case "length": {
      if (value.length < rule.min || value.length > rule.max) {
        reasons.push(`arg "${rule.name}" length ${value.length} not in [${rule.min}, ${rule.max}]`);
      }
      break;
    }
    case "prefix": {
      if (!value.startsWith(rule.prefix)) {
        reasons.push(`arg "${rule.name}" missing required prefix "${rule.prefix}"`);
      } else {
        const suffix = value.slice(rule.prefix.length);
        if (suffix.length > rule.maxSuffixLength) {
          reasons.push(`arg "${rule.name}" suffix length ${suffix.length} exceeds max ${rule.maxSuffixLength}`);
        }
      }
      break;
    }
    case "literal": {
      if (value !== rule.value) {
        reasons.push(`arg "${rule.name}" must be exactly "${rule.value}"`);
      }
      break;
    }
    case "shellSafeString": {
      if (value.length > rule.maxLength) {
        reasons.push(`arg "${rule.name}" length ${value.length} exceeds shellSafe maxLength ${rule.maxLength}`);
      }
      const forbidden = scanForbidden(value);
      if (forbidden.length > 0) {
        reasons.push(
          `arg "${rule.name}" contains forbidden characters: ${forbidden.map((f) => f.label).join(", ")}`,
        );
      }
      break;
    }
  }
  return reasons;
}

interface ForbiddenHit {
  label: string;
  index: number;
}

function scanForbidden(input: string): ForbiddenHit[] {
  const hits: ForbiddenHit[] = [];
  for (let i = 0; i < input.length; i++) {
    const cp = input.codePointAt(i);
    if (cp === undefined) continue;
    if (FORBIDDEN_CODEPOINTS.has(cp)) {
      hits.push({ label: `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`, index: i });
    }
  }
  for (const meta of FORBIDDEN_ASCII_META) {
    const idx = input.indexOf(meta);
    if (idx >= 0) hits.push({ label: meta, index: idx });
  }
  return hits;
}

/**
 * Sanitise an argv array against a SpawnRule. Returns SanitizationResult with
 * a list of every reason the argv was rejected (empty when allowed).
 */
export function sanitizeArgs(args: string[], rule: SpawnRule): SanitizationResult {
  const reasons: string[] = [];
  const totalLen = args.reduce((sum, a) => sum + (typeof a === "string" ? a.length : 0), 0);
  if (totalLen > rule.maxTotalArgLength) {
    reasons.push(`total argv length ${totalLen} exceeds maxTotalArgLength ${rule.maxTotalArgLength}`);
  }
  // We expect a positional 1:1 mapping between rule.args and argv. Extras are rejected.
  if (args.length > rule.args.length) {
    reasons.push(`argv has ${args.length} entries but rule allows max ${rule.args.length}`);
  }
  for (let i = 0; i < rule.args.length; i++) {
    const argRule = rule.args[i];
    if (argRule === undefined) continue;
    const value = args[i];
    if (value === undefined) {
      if (argRule.required) reasons.push(`argv missing required arg "${argRule.name}" at position ${i}`);
      continue;
    }
    reasons.push(...evalArgRule(value, argRule));
  }
  return { allowed: reasons.length === 0, matchedRule: rule.command, blockedReasons: reasons };
}

/**
 * Match a SpawnRequest against a manifest's spawn rules and return a
 * pre-flight attestation. Use this in the runtime hot path before
 * `child_process.spawn` is called.
 */
export function attestSpawn(
  signed: SignedManifest,
  request: SpawnRequest,
): AttestationResult {
  const manifest: Manifest = signed.manifest;
  const blockedReasons: string[] = [];

  // 1. Tool-level check
  if (request.toolName !== undefined) {
    const tool = manifest.tools.find((t) => t.name === request.toolName);
    if (!tool) {
      blockedReasons.push(`tool "${request.toolName}" is not declared in the signed manifest`);
    } else if (request.toolArgs !== undefined) {
      blockedReasons.push(...checkToolArgs(tool, request.toolArgs));
    }
  }

  // 2. Spawn-rule check — find first command match, run sanitiser
  const rule = manifest.spawnRules.find((r) => r.command === request.command);
  if (!rule) {
    blockedReasons.push(
      `spawn command "${request.command}" not allowed by manifest (${manifest.spawnRules.length} rules declared)`,
    );
    return {
      allowed: false,
      matchedRule: null,
      blockedReasons,
      signer: manifest.signer,
      serverName: manifest.serverName,
    };
  }

  const sanit = sanitizeArgs(request.args, rule);
  blockedReasons.push(...sanit.blockedReasons);

  return {
    allowed: blockedReasons.length === 0,
    matchedRule: rule.command,
    blockedReasons,
    signer: manifest.signer,
    serverName: manifest.serverName,
  };
}

function checkToolArgs(tool: ToolDecl, toolArgs: Record<string, unknown>): string[] {
  const reasons: string[] = [];
  for (const argRule of tool.args) {
    const value = toolArgs[argRule.name];
    if (value === undefined) {
      if (argRule.required) reasons.push(`tool "${tool.name}" missing required arg "${argRule.name}"`);
      continue;
    }
    reasons.push(...evalArgRule(value, argRule));
  }
  // Reject unknown tool args (default-deny on shape).
  for (const key of Object.keys(toolArgs)) {
    if (!tool.args.find((a) => a.name === key)) {
      reasons.push(`tool "${tool.name}" received unexpected arg "${key}"`);
    }
  }
  return reasons;
}

/**
 * Strict wrapper that throws AttestationError instead of returning result.
 */
export function attestSpawnStrict(signed: SignedManifest, request: SpawnRequest): void {
  const result = attestSpawn(signed, request);
  if (!result.allowed) {
    throw new AttestationError(
      result.matchedRule === null ? "SPAWN_COMMAND_NOT_ALLOWED" : "ARGUMENT_RULE_MISMATCH",
      `spawn attestation refused: ${result.blockedReasons.join("; ")}`,
      { request, blockedReasons: result.blockedReasons },
    );
  }
}

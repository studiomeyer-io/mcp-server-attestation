# Threat model

## What this package mitigates

| Threat | Vector | Mitigation in this package |
| --- | --- | --- |
| Marketplace poisoning (OX Security April 2026) | Registry accepts a malicious server impersonating a known one | TOFU pin in `~/.mcp-attest/trust.json` rejects key changes for an already-trusted server name. Optional Sigstore cross-reference. |
| CVE-2025-69256 (Serverless Framework MCP RCE) | Tool argument fed to `child_process.exec()` without escaping | `shellSafeString` argument rule blocks every ASCII shell metacharacter, NUL, CR, LF, VT, FF, NEL, zero-width, BOM, bidi-override, fullwidth-Latin confusables. Argv length capped. |
| CVE-2025-61591 (Cursor MCP RCE) | Malicious server spawns unrelated commands | Spawn-rule whitelist: `attestSpawn` rejects any command not in `manifest.spawnRules[]`. |
| Manifest tampering | Attacker changes a tool description or arg-rule after signing | Ed25519 signature over canonical JSON of the entire manifest. Any byte flip fails verify. |
| Fingerprint spoofing | Manifest claims one fingerprint, signed by another key | Both `signManifest` (refuses to sign) and `verifyManifest` (rejects) check that claimed fingerprint matches the embedded public key. |
| Argument-rule ReDoS (denial of service) | A `regex` arg rule with a backtracking-prone pattern; attacker sends a crafted value that hangs the spawn hot path | `evalArgRule` statically detects nested-unbounded-quantifier patterns (linear scan, cannot itself ReDoS) and refuses to run them. `regex` rules also carry a `maxLength` input cap (default 4096). |
| Path traversal past a `prefix` guard | `/safe/../../etc/passwd` satisfies a `prefix: "/safe/"` rule yet escapes the directory | `prefix` rules reject `..` path components by default (`denyTraversal: true`), including the URL-encoded `%2e%2e` form. |
| Unverified manifest reaching the spawn gate | Caller forgets to `verifyManifestStrict` at startup and hands an unverified/tampered manifest to `attestSpawn` | `attestSpawnVerified` verifies the signature before attesting in one fail-safe call. |

## What this package does NOT mitigate

- Process sandboxing. A whitelisted spawn that is itself vulnerable can still be exploited inside its own permissions.
- OAuth installation-flow attacks. Use `mcp-oauth-shield` (separate build) for that layer.
- Compromised key material. If the private key leaks, the attacker can sign anything. Use a hardware token or KMS for production keys.
- Network egress from the spawned process. Use a separate egress filter.

## Replay corpus

| CVE | Fixture | Test |
| --- | --- | --- |
| CVE-2025-69256 | `packages/lib/tests/fixtures/cve-2025-69256-payloads.json` | `spawn.test.ts` "CVE-2025-69256 payloads are all blocked on echo" |
| CVE-2025-61591 | `packages/lib/tests/fixtures/cve-2025-61591-payloads.json` | `spawn.test.ts` "CVE-2025-61591 spawn-hijack payloads are all blocked" |

When a new MCP CVE is published, add a fixture and a `describe` block. The test suite is the regression contract.

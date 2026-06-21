# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] — 2026-06-21

Security hardening of the argument sanitizer and a new verify-then-attest
helper. All three packages move to 0.2.0 in lockstep.

### Security

- **ReDoS guard on `regex` argument rules.** `evalArgRule` now refuses to run a
  regex pattern whose structure is prone to catastrophic backtracking (nested
  unbounded quantifiers like `(a+)+`, `(.*)+`, `(.*a){15}`). The pattern comes
  from the signed manifest, but the *value* is attacker-controlled — a careless
  author pattern previously let a single crafted argument freeze the spawn hot
  path for tens of seconds. Detection is a linear-time scan of the pattern
  string (the detector itself cannot ReDoS) and fails closed. New optional
  `maxLength` field on `regex` rules (default 4096) caps the input length as a
  second layer. Exposed as `looksCatastrophic(pattern)`.
- **Path-traversal guard on `prefix` argument rules.** A bare `startsWith`
  check was bypassable: `/safe/../../etc/passwd` satisfies `prefix: "/safe/"`
  yet escapes the directory. `prefix` rules now reject `..` path components
  (including the URL-encoded `%2e%2e` form, POSIX and Windows separators) by
  default. New optional `denyTraversal` field (default `true`) opts out.
  The secure default is enforced at evaluation time, so it also protects
  manifests constructed in-memory and signed directly (where the Zod default
  has not materialised). Exposed as `containsTraversal(value)`.
- **Control-character gap closed.** `shellSafeString` now also blocks VT
  (U+000B), FF (U+000C) and NEL (U+0085), completing the newline/whitespace
  separator default-deny set alongside the existing LF, CR, U+2028 and U+2029.
  These can act as token separators or line breaks under some shells, parsers
  and NFKC normalisation. CVE-2025-69256 replay fixtures extended accordingly.

### Added

- `attestSpawnVerified(signed, request, options?)` — verifies the manifest
  signature *then* attests the spawn in a single fail-safe call. Closes the
  footgun where an unverified or tampered manifest is handed to `attestSpawn`
  (which trusts that the caller already ran `verifyManifestStrict` at startup).

### Notes

- The `prefix` rule's `denyTraversal: true` default is a behaviour change: a
  pre-existing manifest that relied on `..` passing a prefix rule will now
  reject it. This is intentional (a `..` in a path-prefix-guarded argument is
  almost always an attack); set `denyTraversal: false` to restore the old
  behaviour.

## [0.1.1] — 2026-04-28

### Added

- `mcpName` field in `mcp-attest-demo/package.json`
  (`io.studiomeyer/server-attestation`) so the reference server can be
  claimed and listed in the official MCP Registry. Library + CLI packages
  remain at 0.1.0 (no MCP-server identity to register).

## [0.1.0] — 2026-04-27

Initial release.

### Added

- `mcp-server-attestation` library: Ed25519 sign/verify, manifest schema with
  Zod, default-deny argument sanitizer, runtime spawn attester, TOFU trust
  store at `~/.mcp-attest/trust.json` (atomic write, `0o600`).
- `mcp-attest-cli` CLI: `keygen`, `sign`, `verify`, `inspect`, `fingerprint`,
  `check-pin`.
- `mcp-attest-demo` reference MCP server (stdio, spec `2025-06-18`) with five
  tools demonstrating the library: `attest_verify_manifest`,
  `attest_inspect_spawn`, `attest_generate_manifest_template`,
  `attest_sign_manifest`, `attest_keygen`.
- Manifest expiry support (`expiresAt` field).
- Optional Sigstore-Rekor bridge (v0.2 stub: returns explicit `ok:false` until
  full Rekor integration).
- CVE-replay fixtures for CVE-2025-69256 (Serverless Framework MCP RCE) and
  CVE-2025-61591 (Cursor MCP RCE).

### Security

- Argument sanitizer with 23 forbidden code points covering shell metas,
  Unicode bidi-override (U+202E), zero-width chars, BOM, **and fullwidth
  Latin (U+FF01 — U+FF5E)** to block fullwidth-evasion bypasses.
- Trust file written via temp-file + chmod + rename pattern (defeats symlink
  hijack and TOFU-TOCTOU).
- `canonicalize()` coerces `NaN` / `Infinity` to `null` before signing
  (prevents signature-collision via metadata payload tricks).
- Per-entry validation of trust-file contents with `Object.create(null)`
  containers.

[0.2.0]: https://github.com/studiomeyer-io/mcp-server-attestation/releases/tag/v0.2.0
[0.1.0]: https://github.com/studiomeyer-io/mcp-server-attestation/releases/tag/v0.1.0

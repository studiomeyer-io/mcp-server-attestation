# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.1.0]: https://github.com/studiomeyer-io/mcp-server-attestation/releases/tag/v0.1.0

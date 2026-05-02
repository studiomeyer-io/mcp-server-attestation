<!-- studiomeyer-mcp-stack-banner:start -->
> **Part of the [StudioMeyer MCP Stack](https://studiomeyer.io)** — Built in Mallorca 🌴 · ⭐ if you use it
<!-- studiomeyer-mcp-stack-banner:end -->

# mcp-server-attestation

Layer-2 supply-chain hardening for Model Context Protocol servers. Ed25519-signed tool manifests, runtime spawn-attestation, default-deny argument sanitizer.

Direct response to:
- **OX Security marketplace-poisoning, April 2026** — 9 of 11 MCP registries accepted malicious servers. Anthropic's published position: "expected behavior".
- **CVE-2025-69256** — Serverless Framework MCP RCE via `child_process.exec()` command injection.
- **CVE-2025-61591** — Cursor MCP RCE through OAuth-installed malicious server with spawn hijack.

This package provides what Anthropic chose not to: cryptographic verification of which tools a server is allowed to expose and which spawn calls it is allowed to make. It is a drop-in dependency, not a runtime replacement.

## Packages (npm workspaces)

| Package | Purpose |
| --- | --- |
| `mcp-server-attestation` (`packages/lib`) | Library: Ed25519 sign/verify, manifest schema, sanitizer, spawn attester, TOFU trust store. |
| `mcp-attest-cli` (`packages/cli`) | CLI `mcp-attest`: `keygen`, `sign`, `verify`, `inspect`, `fingerprint`, `check-pin`. |
| `mcp-attest-demo` (`packages/demo-server`) | Reference MCP server (stdio, spec 2025-06-18) exposing 5 tools that demonstrate the library. |

## Install

```bash
npm install mcp-server-attestation
# CLI:
npm install -g mcp-attest-cli
# Reference MCP server:
npx mcp-attest-demo
```

Node 20+. No external crypto dependencies — uses `node:crypto` Ed25519 primitives.

## Five-line server quickstart

```ts
import { verifyManifestStrict, attestSpawnStrict, type SignedManifest } from "mcp-server-attestation";
import signed from "./signed/manifest.json" assert { type: "json" };

// 1. At startup: prove the manifest you ship is the manifest you signed.
verifyManifestStrict(signed);

// 2. Before every child_process.spawn:
attestSpawnStrict(signed as SignedManifest, { command, args });
```

That is the entire integration. Two function calls, no SaaS, no daemon.

## Tools (reference server `mcp-attest-demo`)

| # | Name | readOnlyHint | destructiveHint |
| - | ---- | ------------ | --------------- |
| 1 | `attest_verify_manifest` | true | false |
| 2 | `attest_inspect_spawn` | true | false |
| 3 | `attest_generate_manifest_template` | true | false |
| 4 | `attest_sign_manifest` | false | false |
| 5 | `attest_keygen` | false | false |

Annotations are honest: `attest_sign_manifest` and `attest_keygen` write files on disk so they are not read-only, but they do not destroy existing data so destructiveHint stays false. See `docs/THREAT-MODEL.md` for the per-tool capability table.

## CLI

```bash
mcp-attest keygen --out-dir ./keys --name prod
mcp-attest sign --manifest manifest.json --private-key keys/prod.key --out signed.json
mcp-attest verify --signed signed.json --pin                  # TOFU pin
mcp-attest verify --signed signed.json --sigstore             # opt-in Rekor cross-ref
mcp-attest inspect --signed signed.json --command /usr/bin/echo --arg "hello"
mcp-attest fingerprint --public-key keys/prod.pub
mcp-attest check-pin --server my-server --signed signed.json
```

`verify` exits with code 2 on bad signature, code 3 on pin mismatch.

## MCP spec compatibility

| Spec version | Status |
| --- | --- |
| 2024-11-05 | parseable in manifest, not target of reference server |
| 2025-03-26 | parseable in manifest, not target of reference server |
| 2025-06-18 | full target |

The library is transport-agnostic. The reference server is stdio-only.

## Security model

- **Trust-on-First-Use** is the default. The first time you verify a server, its public key is pinned to `~/.mcp-attest/trust.json` (override: `MCP_ATTEST_TRUST_FILE`). Subsequent verifications reject any new key for the same server name with `TRUST_PIN_MISMATCH`. This catches the Cursor-style malicious-update vector.
- **No bundled trusted-keys list.** This package does not act as a gatekeeper. If you want stronger assurance, opt into `--sigstore` to cross-reference the public-key fingerprint against the Sigstore Rekor transparency log.
- **Default-deny argument sanitizer.** `shellSafeString` blocks every ASCII shell metacharacter, NUL, CR, LF, zero-width characters, BOM, RTL/LTR overrides, and Trojan-Source isolates. Allowlist behaviour requires the explicit `regex` / `enum` / `prefix` / `literal` rule kinds.
- **Canonical JSON** is the signed surface. Re-serialisation cannot change the signed bytes.

What this package does NOT do (out of scope):
- Sandbox or containerise the server process.
- OAuth flow hardening (separate `mcp-oauth-shield` build).
- Network egress control.
- Auto-patch existing servers.

## Tests

```bash
npm install
npm run typecheck
npm test
```

Test corpus includes CVE-replay fixtures (`packages/lib/tests/fixtures/cve-2025-69256-payloads.json`, `cve-2025-61591-payloads.json`). The build is a regression check: every payload must be blocked.

## Distribution

- npm publish via GitHub Actions OIDC with `--provenance`.
- Reference server submitted to mcp.so and FastMCP Directory.
- Library separately published as `mcp-server-attestation`.

## About StudioMeyer

[StudioMeyer](https://studiomeyer.io) is an AI and design studio from Palma de Mallorca, building custom websites and AI infrastructure for small and medium businesses. Production stack on Claude Agent SDK, MCP and n8n, with Sentry, Langfuse and LangGraph for observability and an in-house guard layer.

## License

MIT, Copyright 2026 Matthias Meyer (StudioMeyer). See `LICENSE`.
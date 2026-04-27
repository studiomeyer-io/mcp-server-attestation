# Security policy

## Reporting a vulnerability

Email `security@studiomeyer.io` or use GitHub Security Advisories on this repository. We respond within 72 hours.

Do not file public issues for vulnerabilities. Do not test against production servers other than your own.

## Scope

- Cryptographic correctness of `signManifest` / `verifyManifest`.
- Bypasses of the argument sanitizer (`shellSafeString` rule kind).
- Trust-pin store integrity (`~/.mcp-attest/trust.json`).
- Manifest-schema bypasses that allow signing of structurally invalid manifests.

## Out of scope

- Sandboxing of the spawned process — explicitly not implemented in this package.
- OAuth / MCP-installation flow attacks — see the separate `mcp-oauth-shield` build.
- Denial-of-service via large manifests — sizes are capped in the schema.

## Disclosure timeline

We follow coordinated disclosure with a 90-day public-disclosure clock starting from the report date.

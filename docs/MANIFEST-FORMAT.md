# Manifest format

A signed manifest is a JSON file with three top-level fields:

```json
{
  "manifest": {
    "schemaVersion": 1,
    "serverName": "my-mcp-server",
    "serverVersion": "1.4.2",
    "mcpSpecVersion": "2025-06-18",
    "signer": "Acme Inc <ops@acme.example>",
    "publicKeyFingerprint": "sha256:abcd...",
    "signedAt": "2026-04-27T08:30:00.000Z",
    "tools": [...],
    "spawnRules": [...],
    "metadata": { ... optional ... }
  },
  "signature": "<128 hex chars Ed25519 signature>",
  "publicKey": "<64 hex chars Ed25519 raw public key>"
}
```

The `signature` covers the canonical-JSON encoding of `manifest` (top-level field). Canonical JSON rules:

1. Recursive lexicographic key ordering on every object.
2. `undefined` values dropped.
3. `JSON.stringify` with no separator whitespace.

## Tool declaration

```json
{
  "name": "search",
  "description": "Search by query",
  "readOnlyHint": true,
  "destructiveHint": false,
  "args": [
    { "name": "q", "kind": "length", "required": true, "min": 1, "max": 256 }
  ]
}
```

Tool name must match `/^[a-zA-Z_][a-zA-Z0-9_-]*$/`. Up to 64 args per tool, 256 tools per manifest.

## Argument rule kinds

| `kind` | Fields | Semantics |
| ------ | ------ | --------- |
| `regex` | `pattern`, `flags`, `maxLength` | Argument must match the regex. Patterns prone to catastrophic backtracking (nested unbounded quantifiers) are **refused, not run** — see ReDoS note below. `maxLength` (default 4096) caps the input length handed to the engine. |
| `enum` | `values[]` | Argument must equal one of the listed values. |
| `length` | `min`, `max` | Argument string length within `[min, max]`. |
| `prefix` | `prefix`, `maxSuffixLength`, `denyTraversal` | Argument starts with `prefix`, suffix length under `maxSuffixLength`. `denyTraversal` (default `true`) rejects any `..` path component, including the URL-encoded `%2e%2e` form — so `/safe/../../etc/passwd` is blocked even though it satisfies `prefix: "/safe/"`. Set `false` only when `..` is legitimately part of the value. |
| `literal` | `value` | Argument exactly equals `value`. |
| `shellSafeString` | `maxLength` | No shell metacharacters, no NUL/CR/LF/VT/FF/NEL, no zero-width, no BOM, no bidi-override, no fullwidth-Latin confusables. |

### ReDoS note

A `regex` rule's `pattern` is part of the signed manifest, but the argument
*value* is attacker-controlled. A careless author pattern such as `(a+)+$` lets
a single crafted argument freeze the spawn hot path for tens of seconds. The
sanitizer statically detects nested-unbounded-quantifier patterns (`(a+)+`,
`(a*)*`, `(.*)+`, `(.*a){15}`, `((ab)*)*`, ...) with a linear-time scan and
**refuses to evaluate them**, failing closed. Flat patterns — `^[a-z]+$`,
`^\d{1,10}$`, `(foo|bar)`, `(ab){2,5}`, semver — are unaffected. If your
pattern is rejected, rewrite it without a nested quantifier.

`shellSafeString` is the right default for any argument that ends up in `child_process.spawn` argv — the sanitizer is implemented in `packages/lib/src/spawn.ts`.

## Spawn rule

```json
{
  "command": "/usr/bin/cat",
  "args": [
    { "name": "file", "kind": "prefix", "required": true, "prefix": "/safe/", "maxSuffixLength": 256, "denyTraversal": true }
  ],
  "maxTotalArgLength": 1024
}
```

`maxTotalArgLength` is a hard cap on the sum of argv string lengths and is the primary defense against buffer-stuffing attacks. `denyTraversal` defaults to `true`; the example shows it explicitly for clarity.

## Trust file (`~/.mcp-attest/trust.json`)

```json
{
  "schemaVersion": 1,
  "entries": {
    "my-mcp-server": {
      "serverName": "my-mcp-server",
      "publicKeyHex": "<64 hex>",
      "fingerprint": "sha256:<64 hex>",
      "pinnedAt": "2026-04-27T08:00:00.000Z",
      "sigstoreEntries": [
        { "logIndex": 0, "uuid": "abc...", "fetchedAt": "2026-04-27T08:00:00.000Z" }
      ],
      "note": "verified out-of-band on 2026-04-27"
    }
  }
}
```

File mode is `0600`. Override the path with `MCP_ATTEST_TRUST_FILE`.

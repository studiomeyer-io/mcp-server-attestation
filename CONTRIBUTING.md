# Contributing

## Local setup

```bash
git clone <repo>
cd mcp-server-attestation
npm install
npm run typecheck
npm test
```

## Pull requests

- Add a test for every new behaviour. CVE-replay fixtures live in `packages/lib/tests/fixtures/`.
- Tools must declare `readOnlyHint` and `destructiveHint` honestly.
- No `any`, no hardcoded versions in `src/server.ts` (read from `package.json`).
- Run `npm run typecheck` and `npm test` before opening a PR.

## Versioning

Semantic versioning. The library and the reference server share a major version; minor/patch may diverge.

## Adding a new CVE replay

1. Add payload list to `packages/lib/tests/fixtures/cve-XXXX-XXXXX-payloads.json` with `cve`, `description`, `source`, `payloads`.
2. Add a `describe` block in `packages/lib/tests/spawn.test.ts` asserting every payload is blocked.
3. Reference the CVE in `docs/THREAT-MODEL.md` under "Replay corpus".

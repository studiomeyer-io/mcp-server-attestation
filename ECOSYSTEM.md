# StudioMeyer Open Source Ecosystem

`mcp-server-attestation` is part of a family of Claude / MCP tools maintained
by [StudioMeyer](https://studiomeyer.io). Each project is self-contained; they
just happen to compose well.

## Related open-source projects

- **[mcp-protocol-conformance](https://github.com/studiomeyer-io/mcp-protocol-conformance)**
  — Conformance test harness for MCP servers. Validates JSON-RPC 2.0, spec
  versions 2024-11-05 / 2025-03-26 / 2025-06-18, OAuth 2.1 PKCE, tool schemas,
  capabilities, smoke roundtrip, annotation hygiene. Run it before you sign:
  passing conformance is a precondition for a meaningful attestation.
- **[local-memory-mcp](https://github.com/studiomeyer-io/local-memory-mcp)**
  — Persistent local memory for Claude, Cursor, Codex. SQLite + FTS5 +
  knowledge graph, stdio-only, zero cloud.
- **[mcp-personal-suite](https://github.com/studiomeyer-io/mcp-personal-suite)**
  — 49 MCP tools for email / calendar / messaging / search / image. Local-first,
  BYOK, zero telemetry.
- **[mcp-video](https://github.com/studiomeyer-io/mcp-video)** — Cinema-grade
  video production MCP server. ffmpeg + Playwright, 8 consolidated tools.
- **[mcp-crew](https://github.com/studiomeyer-io/mcp-crew)** — Agent personas
  for Claude. 8 built-in personas plus user-defined ones.
- **[agent-fleet](https://github.com/studiomeyer-io/agent-fleet)** — Multi-agent
  orchestration for Claude Code CLI. 7 agents, MCP tool integration.
- **[ai-shield](https://github.com/studiomeyer-io/ai-shield)** — LLM security
  for TypeScript. Prompt-injection detection, PII, cost control.
- **[darwin-agents](https://github.com/studiomeyer-io/darwin-agents)** —
  Self-evolving agent framework. A/B testing of prompts, multi-model critics.

## How attestation connects

This package is the **trust layer** between an MCP server and the client that
runs it. The chain is: write a server, prove it is spec-correct with
`mcp-protocol-conformance`, declare its tool surface and child-process
behaviour in a manifest, sign that manifest with Ed25519, verify the signature
at startup, attest every spawn at runtime. A client that pins your public key
gets cryptographic guarantees that the manifest you ship is the manifest you
signed and that the only spawns that can happen are the ones declared.

This is a **drop-in dependency, not a runtime replacement.** Two function
calls (`verifyManifestStrict` + `attestSpawnStrict`) wire it into an existing
MCP server.

## Discussion

- Issues: [github.com/studiomeyer-io/mcp-server-attestation/issues](https://github.com/studiomeyer-io/mcp-server-attestation/issues)
- Discussions: [github.com/studiomeyer-io/mcp-server-attestation/discussions](https://github.com/studiomeyer-io/mcp-server-attestation/discussions)
- Security advisories: [github.com/studiomeyer-io/mcp-server-attestation/security/advisories](https://github.com/studiomeyer-io/mcp-server-attestation/security/advisories)
- Website: [studiomeyer.io](https://studiomeyer.io)

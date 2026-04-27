#!/usr/bin/env node
/**
 * mcp-attest-demo — reference MCP server for the mcp-server-attestation library.
 *
 * Exposes 5 stdio tools demonstrating the full attestation lifecycle:
 *   1. attest_verify_manifest          (read-only)
 *   2. attest_inspect_spawn            (read-only)
 *   3. attest_generate_manifest_template (read-only)
 *   4. attest_sign_manifest            (writes signed manifest file)
 *   5. attest_keygen                   (writes keypair files)
 *
 * Spec version 2025-06-18. Stdio transport. No DB, no network, no SaaS tier.
 */

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { ALL_TOOLS, type ToolDefinition, type ToolOutput } from "./tools/index.js";

function readPackageVersion(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  const candidates = [
    resolve(here, "..", "package.json"),
    resolve(here, "..", "..", "package.json"),
  ];
  for (const c of candidates) {
    try {
      const json = JSON.parse(readFileSync(c, "utf-8")) as { version?: string };
      if (typeof json.version === "string" && json.version.length > 0) return json.version;
    } catch {
      // try next
    }
  }
  return "0.0.0";
}

const SERVER_VERSION = readPackageVersion();
const SERVER_NAME = "mcp-attest-demo";

export function createDemoServer(): Server {
  const server = new Server(
    { name: SERVER_NAME, version: SERVER_VERSION },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: ALL_TOOLS.map((t) => ({
      name: t.name,
      description: t.description,
      inputSchema: t.inputSchema,
      annotations: {
        readOnlyHint: t.readOnlyHint,
        destructiveHint: t.destructiveHint,
        idempotentHint: t.readOnlyHint,
        openWorldHint: false,
      },
    })),
  }));

  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const name = req.params.name;
    const rawArgs = req.params.arguments ?? {};
    const tool = ALL_TOOLS.find((t) => t.name === name) as ToolDefinition<unknown, ToolOutput> | undefined;
    if (!tool) {
      return {
        content: [{ type: "text", text: `Unknown tool: ${name}` }],
        isError: true,
      };
    }
    try {
      const parsed = tool.parse(rawArgs);
      const out = await tool.handler(parsed);
      return {
        content: [{ type: "text", text: out.text }],
        isError: out.isError,
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        content: [{ type: "text", text: `Error: ${message}` }],
        isError: true,
      };
    }
  });

  return server;
}

export async function startStdioServer(): Promise<void> {
  const server = createDemoServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

const isMainModule =
  import.meta.url === `file://${process.argv[1]}` ||
  process.argv[1]?.endsWith("server.js") === true;

if (isMainModule) {
  const shutdown = (): void => {
    process.exit(0);
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);

  startStdioServer().catch((err: unknown) => {
    process.stderr.write(
      `${SERVER_NAME} failed to start: ${err instanceof Error ? (err.stack ?? err.message) : String(err)}\n`,
    );
    process.exit(1);
  });
}

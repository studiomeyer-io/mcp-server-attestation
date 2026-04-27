import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

export default defineConfig({
  test: {
    include: ["packages/**/tests/**/*.test.ts"],
    testTimeout: 30_000,
    hookTimeout: 10_000,
    pool: "forks",
    poolOptions: {
      forks: { singleFork: true },
    },
    alias: {
      // Demo-server imports `mcp-server-attestation` as a workspace dep, but
      // package exports point at ./dist (which doesn't exist pre-build).
      // Vitest resolves to the source so tests work without a pre-build step.
      "mcp-server-attestation": fileURLToPath(
        new URL("./packages/lib/src/index.ts", import.meta.url),
      ),
    },
  },
});

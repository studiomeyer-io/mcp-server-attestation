/**
 * Library version, read from package.json so cli + server + library cannot
 * drift on the next bump. Mirror of the helper in mcp-protocol-conformance.
 *
 * F3 fix Round 1.5 — was previously hardcoded as `"0.1.0"` in index.ts.
 */

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export function readPackageVersion(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  // packages/lib/src → ../package.json
  // packages/lib/dist → ../package.json
  const candidates = [
    resolve(here, "..", "package.json"),
    resolve(here, "..", "..", "package.json"),
  ];
  for (const candidate of candidates) {
    try {
      const json = JSON.parse(readFileSync(candidate, "utf8")) as {
        version?: string;
      };
      if (json.version) return json.version;
    } catch {
      // try next candidate
    }
  }
  return "0.0.0";
}

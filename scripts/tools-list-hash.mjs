#!/usr/bin/env node
/* The tools/list digest: sha256 of the tools/list result the inspector serves (server.toolsListResult), as
 * JSON.stringify writes it. The list holds no paths, times or versions, so the digest is the same on every run and
 * machine; a client or a directory can compare it with lib/inspector/tools-list.sha256 (shipped in the package) to
 * see that the tools did not change.
 *
 *   node scripts/tools-list-hash.mjs            (npm run tools-list-hash)  write lib/inspector/tools-list.sha256
 *   node scripts/tools-list-hash.mjs --check    exit 1 when the file is stale
 *
 * test/mcp-conformance.test.mjs fails when tools/list changes without the file. */
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { toolsListResult } from "../lib/inspector/server.mjs";

const FILE = fileURLToPath(new URL("../lib/inspector/tools-list.sha256", import.meta.url));

export const toolsListDigest = () => createHash("sha256").update(JSON.stringify(toolsListResult())).digest("hex");

function main(argv) {
  const line = `${toolsListDigest()}  tools/list\n`;
  if (argv.length === 0) { writeFileSync(FILE, line); process.stdout.write(line); return 0; }
  if (argv.length === 1 && argv[0] === "--check") {
    let shipped = "";
    try { shipped = readFileSync(FILE, "utf8"); } catch { /* missing: stale */ }
    if (shipped === line) { process.stdout.write(line); return 0; }
    process.stderr.write("lib/inspector/tools-list.sha256 does not match tools/list. Run npm run tools-list-hash and commit it.\n");
    return 1;
  }
  process.stderr.write("usage: node scripts/tools-list-hash.mjs [--check]\n");
  return 2;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) process.exitCode = main(process.argv.slice(2));

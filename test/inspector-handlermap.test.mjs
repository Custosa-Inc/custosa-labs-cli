// The local handler map (custosa inspect --document) works its ids out from the same text the rule engine
// parses, so every handler id in the document is in the map, whatever the file's line breaks.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildLocalDocuments, CORPUS_BUDGET } from "../lib/inspector/factdoc.mjs";
import { loadRules } from "../lib/inspector/rules.mjs";

const temp = (prefix) => realpathSync(mkdtempSync(join(tmpdir(), prefix)));

test("every handler id in the document is in the local map, for LF, CRLF and lone-CR files", async () => {
  const root = temp("custosa-hmap-");
  mkdirSync(join(root, ".git"));
  mkdirSync(join(root, "src"));
  const body = ["// save", "export const one = 1;", "export async function save(p) {",
    '  await db.from("audit_log").insert({ action: "read", p });', "}", ""];
  for (const [name, eol] of [["lf", "\n"], ["crlf", "\r\n"], ["cr", "\r"]]) writeFileSync(join(root, "src", `${name}.ts`), body.join(eol));
  const { documents: [own] } = await buildLocalDocuments([root], {
    ruleset: { id: "2026-10-20.0123abcd", rules: loadRules(fileURLToPath(new URL("./fixtures/rules/", import.meta.url))), queries: [] },
    configDir: join(temp("custosa-hmap-cfg-"), "custosa"), handlerMap: true, ...CORPUS_BUDGET,
  });
  assert.equal(own.problem, null, JSON.stringify(own.problem));
  const withHandler = own.document.matches.filter((m) => m.handler);
  assert.equal(new Set(withHandler.map((m) => m.path)).size, 3, "each file has a handler match");
  for (const m of withHandler) assert.ok(own.handlers[m.handler], `${m.path}: ${m.handler} is not in the map`);
  const names = Object.values(own.handlers).map((h) => `${h.path}:${h.name}:${h.line}`).sort();
  for (const name of ["lf", "crlf", "cr"]) assert.ok(names.includes(`src/${name}.ts:save:3`), JSON.stringify(names));
});

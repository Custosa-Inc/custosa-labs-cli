/* T29 conventions audit row B5: a custom bundle's catalog queries are its own. A query whose .sql the bundle lacks is left
 * out of the list, which the fact document reads as failed ("a query with no entry is read as failed"), never run with
 * the package's own SQL under the bundle's ruleset id. Temp folders only. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { cpSync, mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { DEFAULT_BUNDLE_DIR, loadRuleset, QUERY_IDS } from "../lib/inspector/factdoc.mjs";

const temp = () => realpathSync(mkdtempSync(join(tmpdir(), "bundle-queries-")));

function bundle(queries) {
  const dir = temp();
  cpSync(fileURLToPath(new URL("./fixtures/rules/", import.meta.url)), join(dir, "rules"), { recursive: true });
  writeFileSync(join(dir, "manifest.json"), JSON.stringify({ ruleset_id: "2026-11-10.0b5b5b5b" }));
  mkdirSync(join(dir, "queries"));
  for (const [id, sql] of Object.entries(queries)) writeFileSync(join(dir, "queries", `${id}.sql`), sql);
  return dir;
}

test("a custom bundle runs only the queries it ships, with its own SQL", () => {
  const sql = "select c.relname from pg_catalog.pg_class c\n";
  const { queries } = loadRuleset({ bundleDir: bundle({ rls_status: sql, default_acl: sql }) });
  assert.deepEqual(queries.map((q) => q.query_id), ["rls_status", "default_acl"]);
  assert.ok(queries.every((q) => q.sql === sql));
});

test("a custom bundle with no queries folder runs no catalog query", () => {
  const dir = temp();
  cpSync(fileURLToPath(new URL("./fixtures/rules/", import.meta.url)), join(dir, "rules"), { recursive: true });
  writeFileSync(join(dir, "manifest.json"), JSON.stringify({ ruleset_id: "2026-11-10.0b5b5b5c" }));
  assert.deepEqual(loadRuleset({ bundleDir: dir }).queries, []);
});

test("the shipped bundle lists every query", () => {
  assert.deepEqual(loadRuleset({ bundleDir: DEFAULT_BUNDLE_DIR }).queries.map((q) => q.query_id), [...QUERY_IDS]);
});

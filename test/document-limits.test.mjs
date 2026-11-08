/* checkDocument refuses what the evaluator's intake refuses before the schema (app/core/intake.py): more
   than MAX_TABLES distinct catalog tables, and files.manifests with an ecosystem twice or a count below its paths. Such a
   document used to be sent whole and refused there. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import * as factdoc from "../lib/inspector/factdoc.mjs";

const { buildFactDocuments, checkDocument } = factdoc;

async function documentFor(files) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "t27-limits-repo-")));
  for (const [p, t] of Object.entries(files)) {
    mkdirSync(dirname(join(root, p)), { recursive: true });
    writeFileSync(join(root, p), t);
  }
  const runRules = async () => ({ matches: [], links: [], notAnalyzed: [], analyzed: 1, analyzedPaths: ["src/index.js"],
    languages: ["javascript"], status: "ok", count: 0 });
  const out = await buildFactDocuments([root], { configDir: mkdtempSync(join(tmpdir(), "t27-limits-cfg-")), runRules,
    ruleset: { id: "2026-10-20.0123abcd", rules: [], queries: [] },
    collectCatalog: async () => ({ status: "not_run", count: 0, reason: "service_missing", preflight: null, queries: [] }),
    collectPlatform: async () => ({ provider: null, status: "not_run", reason: "no_token", settings: {} }) });
  return out.documents[0].document;
}

const rows = (n, name = (i) => `t${i}`) => Array.from({ length: n }, (_, i) => ({ schema_name: "public", table_name: name(i) }));

test("the evaluator's table limit is 2,500, and more distinct tables is too_many_tables before the schema", async () => {
  assert.equal(factdoc.MAX_TABLES, 2500);
  const doc = await documentFor({ "package.json": "{}\n", "src/index.js": "export const a = 1;\n" });
  assert.equal(checkDocument(doc), null);
  const over = structuredClone(doc);
  over.catalog.queries = [{ query_id: "table_columns", rows: rows(2000) }, { query_id: "rls_status", rows: rows(501, (i) => `r${i}`) }];
  assert.deepEqual(checkDocument(over), { at: "/catalog/queries/1/rows", keyword: "too_many_tables" });
  // schema.table compared without letter case, and across the three table queries, as intake.table_count does
  const same = structuredClone(doc);
  same.catalog.queries = [{ query_id: "table_columns", rows: rows(2500) }, { query_id: "table_grants", rows: rows(2500, (i) => `T${i}`) },
    { query_id: "role_attributes", rows: rows(10, (i) => `x${i}`) }];
  assert.notEqual(checkDocument(same)?.keyword, "too_many_tables");
});

test("files.manifests: an ecosystem listed twice or a count below its paths is refused", async () => {
  const doc = await documentFor({ "package.json": "{}\n", "yarn.lock": "\n", "Cargo.toml": "[package]\n", "src/index.js": "export const a = 1;\n" });
  assert.deepEqual(doc.files.manifests.map((m) => [m.ecosystem, m.count, m.paths.length]), [["npm", 2, 2], ["cargo", 1, 1]]);
  assert.equal(checkDocument(doc), null);
  const twice = structuredClone(doc);
  twice.files.manifests[1].ecosystem = twice.files.manifests[0].ecosystem;
  assert.deepEqual(checkDocument(twice), { at: "/files/manifests/1/ecosystem", keyword: "strict" });
  const low = structuredClone(doc);
  low.files.manifests[0] = { ...low.files.manifests[0], count: 1 };
  assert.deepEqual(checkDocument(low), { at: "/files/manifests/0/count", keyword: "strict" });
});

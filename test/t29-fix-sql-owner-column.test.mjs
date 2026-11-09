/* T29-P1-C35 (Q1, option a): each rls_policies row carries owner_column, the name of the row's column its judged
 * expressions compare with the session's user, as schema metadata only (never a value, never the policy text). It is
 * set only when every judged expression requires one equality of one column with a trusted user source; anything
 * else (no comparison, OR'd, an untrusted or unknown source, two columns, an expression not read) gives null. A name
 * the inspector hashes in table_columns is sent in that same hashed form. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildFactDocuments, loadRuleset } from "../lib/inspector/factdoc.mjs";
import { loadRules } from "../lib/inspector/rules.mjs";
import { judgePreflight } from "../lib/inspector/catalog.mjs";
import { hashed } from "../lib/inspector/ids.mjs";
import { FACT_SCHEMA } from "../lib/inspector/schema.mjs";

const RULES = loadRules(fileURLToPath(new URL("./fixtures/rules/", import.meta.url)));
const RULESET_ID = "2026-10-20.0123abcd";
const temp = (prefix) => realpathSync(mkdtempSync(join(tmpdir(), prefix)));
const PREFLIGHT = judgePreflight({
  role: "phisc_ro", session_role: "phisc_ro", database: "postgres", system_identifier: "7", settings_mismatched: [],
  superuser: false, bypassrls: false, replication: false, createrole: false, readable_tables: 0, writable_tables: 0,
  extension_relations_readable: [], catalog_tables: [], predefined_roles: [], dangerous_functions: [],
  catalog_extensions: [], owned_objects: 0, definer_functions_executable: 0, readable_large_objects: 0,
  lo_compat_privileges: false, write_relations: 0, write_large_objects: 0, write_schemas: 0, write_database: 0,
  write_default_privileges: 0, write_createdb: 0, write_foreign_servers: 0, write_fdw: 0, user_casts: 0,
  user_casts_implicit: 0, user_operators: 0,
});
const ok = (query_id, rows) => ({ query_id, status: rows.length ? "ok" : "empty", reason: null, rows });
const POL = (name, command, using, check = null) => ({ schema_name: "public", table_name: "photos", policy_name: name, command,
  permissive: true, always_true: false, reads_user_metadata: false, trusted_routes: [], owner_match: false,
  roles: ["authenticated"], using_expression: using, check_expression: check });
const COLS = ["id", "owner_id", "driver_id", "owner id"].map((n) => ({ schema_name: "public", table_name: "photos", column_name: n, data_type: "uuid" }));

async function rows(policies) {
  const root = temp("t29-fixsql-");
  writeFileSync(join(root, "a.ts"), "x\n");
  const configDir = temp("t29-fixsql-cfg-");
  const out = await buildFactDocuments([root], {
    configDir, ruleset: { id: RULESET_ID, rules: RULES, queries: loadRuleset({ bundleDir: "/nonexistent", rulesetId: RULESET_ID }).queries },
    collectCatalog: async () => ({ status: "ok", count: 0, reason: null, preflight: PREFLIGHT, queries: [ok("table_columns", COLS), ok("rls_policies", policies)] }),
    collectPlatform: async () => ({ provider: null, status: "not_run", reason: "no_token", settings: {} }),
  });
  const d = out.documents[0];
  assert.equal(d.problem, null, JSON.stringify(d.problem));
  return { rows: d.document.catalog.queries.find((q) => q.query_id === "rls_policies").rows, key: readFileSync(join(configDir, "install.key")), doc: d.document };
}

test("an owner-scoped policy names the column it compares with the caller", async () => {
  const { rows: r, doc } = await rows([
    POL("own read", "select", "(owner_id = auth.uid())"),
    POL("own insert", "insert", null, "(owner_id = ( SELECT auth.uid() AS uid))"),
    POL("own update", "update", "(auth.uid() = owner_id)", "(owner_id = auth.uid())"),
  ]);
  assert.deepEqual(r.map((x) => x.owner_column), ["owner_id", "owner_id", "owner_id"]);
  assert.ok(!JSON.stringify(doc).includes("auth.uid"), "the policy text never leaves the machine");
});

test("no owner column without one required equality of one column with a trusted user source", async () => {
  const { rows: r } = await rows([
    POL("open", "select", "true"),
    POL("signed in", "select", "(auth.uid() IS NOT NULL)"),
    POL("or'd", "select", "((owner_id = auth.uid()) OR true)"),
    POL("role name", "select", "(owner_id = (CURRENT_USER)::uuid)"),
    POL("two columns", "select", "((owner_id = auth.uid()) AND (driver_id = auth.uid()))"),
    POL("using only", "update", "(owner_id = auth.uid())", "true"),
    POL("membership", "select", "(owner_id IN ( SELECT m.user_id FROM members m WHERE (m.user_id = auth.uid())))"),
    POL("unparsed", "select", "$$x$$"),
    POL("metadata", "select", "(owner_id = (((auth.jwt() -> 'user_metadata'::text) ->> 'sub'::text))::uuid)"),
  ]);
  for (const x of r) assert.equal(x.owner_column, null, x.policy_name);
});

test("a column name the inspector hashes is sent hashed, the same as in table_columns", async () => {
  const { rows: r, key, doc } = await rows([POL("own read", "select", "(\"owner id\" = auth.uid())")]);
  const sent = doc.catalog.queries.find((q) => q.query_id === "table_columns").rows.map((x) => x.column_name);
  assert.ok(sent.includes(r[0].owner_column), r[0].owner_column);
  assert.equal(r[0].owner_column, hashed(key, "owner id"));
});

test("the fact schema takes owner_column on an rls_policies row, optional, a name or null", () => {
  const row = FACT_SCHEMA.$defs.row_rls_policies;
  assert.ok(row.properties.owner_column, "owner_column is a property of the row");
  assert.ok(!row.required.includes("owner_column"), "optional, so a document from 0.1.2 still validates");
});

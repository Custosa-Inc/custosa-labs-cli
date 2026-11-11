/* T29 h4b (T29-P3-C215): each rls_policies row carries using_branches, one word per top-level OR branch of USING
 * (policyexpr usingBranches), so the evaluator can fail a read every caller meets by one branch (the 160-item key's d7
 * and d9) and keep a staff list (t4) for a person. Words only: the policy text never leaves the machine. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildFactDocuments, loadRuleset } from "../lib/inspector/factdoc.mjs";
import { loadRules } from "../lib/inspector/rules.mjs";
import { judgePreflight } from "../lib/inspector/catalog.mjs";
import { FACT_SCHEMA } from "../lib/inspector/schema.mjs";
import { BRANCH_KINDS, MAX_BRANCHES } from "../lib/inspector/policyexpr.mjs";

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
const POL = (table, name, command, using, check = null) => ({ schema_name: "public", table_name: table, policy_name: name,
  command, permissive: true, always_true: false, reads_user_metadata: false, trusted_routes: [], owner_match: false,
  roles: ["authenticated"], using_expression: using, check_expression: check });
const COLS = [["lab_annotations", "author_id"], ["treatment_photos", "clinic_id"], ["dentist_reviews", "patient_id"]]
  .map(([t, n]) => ({ schema_name: "public", table_name: t, column_name: n, data_type: "uuid" }));

const D7 = "((author_id = (current_setting('app.current_user_id'::text, true))::uuid) OR ((current_setting('app.current_user_id'::text, true))::uuid IS NOT NULL))";
const D9 = "(EXISTS ( SELECT 1 FROM private.clinic_members m WHERE (m.clinic_id = treatment_photos.clinic_id)))";
const T4 = "((patient_id = (current_setting('app.current_user'::text, true))::uuid) OR (EXISTS ( SELECT 1 FROM private.staff_members s WHERE (s.user_id = (current_setting('app.current_user'::text, true))::uuid))))";

async function rows(policies) {
  const root = temp("t29-h4b-");
  writeFileSync(join(root, "a.ts"), "x\n");
  const configDir = temp("t29-h4b-cfg-");
  const out = await buildFactDocuments([root], {
    configDir, ruleset: { id: RULESET_ID, rules: RULES, queries: loadRuleset({ bundleDir: "/nonexistent", rulesetId: RULESET_ID }).queries },
    collectCatalog: async () => ({ status: "ok", count: 0, reason: null, preflight: PREFLIGHT, queries: [ok("table_columns", COLS), ok("rls_policies", policies)] }),
    collectPlatform: async () => ({ provider: null, status: "not_run", reason: "no_token", settings: {} }),
  });
  const d = out.documents[0];
  assert.equal(d.problem, null, JSON.stringify(d.problem));
  return { rows: d.document.catalog.queries.find((q) => q.query_id === "rls_policies").rows, doc: d.document };
}

test("the key's d7, d9 and t4 rows carry their branch words, and the text stays on the machine", async () => {
  const { rows: r, doc } = await rows([
    POL("lab_annotations", "d7 read", "select", D7),
    POL("treatment_photos", "d9 read", "select", D9),
    POL("dentist_reviews", "t4 read", "all", T4),
  ]);
  assert.deepEqual(r.map((x) => x.using_branches), [["owner", "signed_in"], ["any_member"], ["owner", "member"]]);
  const text = JSON.stringify(doc);
  for (const s of ["current_setting", "clinic_members", "staff_members", "EXISTS"]) assert.ok(!text.includes(s), s);
});

test("no USING reads as one none branch, and text that doesn't parse is null", async () => {
  const { rows: r } = await rows([
    POL("lab_annotations", "insert any", "insert", null, "true"),
    POL("lab_annotations", "broken", "select", "((author_id = "),
  ]);
  assert.deepEqual(r.map((x) => x.using_branches), [["none"], null]);
});

test("the fact schema takes using_branches on an rls_policies row, optional, at most 8 words or null", () => {
  const row = FACT_SCHEMA.$defs.row_rls_policies;
  const prop = row.properties.using_branches;
  assert.ok(prop, "using_branches is a property of the row");
  assert.ok(!row.required.includes("using_branches"), "optional, so a document from an older CLI still validates");
  assert.deepEqual(prop.anyOf[0].items.enum, [...BRANCH_KINDS]);
  assert.equal(prop.anyOf[0].maxItems, MAX_BRANCHES);
  assert.deepEqual(prop.anyOf[1], { type: "null" });
});

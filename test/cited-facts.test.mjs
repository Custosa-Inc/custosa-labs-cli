/* T29 line item h, h2 (T29-P3-C85, C87): the assistant's fact records become the fact document's cited_facts rows.
 * Each field of the record's rule gives one row: its closed value (from the synced contracts/fact_schema.json) or
 * unknown, the inspector's cite (ok, failed or none) and cited_at for ok only. The token never reaches a row. A record
 * whose rule or candidate is not one the contract allows is dropped; a value outside its field's list, or a column
 * name that isn't a plain catalog name, gives unknown (never in the project's favour). Every row validates against the
 * fact document schema's cited_facts. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Ajv2020Module from "ajv/dist/2020.js";
import { citedFactRows, citedFacts, CITED_FACTS_MAX_BYTES, droppedFactsNote, FACT_FIELDS, FACT_VALUES } from "../lib/inspector/cite.mjs";
import { sentPath } from "../lib/inspector/ids.mjs";

const SCHEMA = JSON.parse(readFileSync(new URL("../lib/inspector/contracts/fact_document.schema.json", import.meta.url), "utf8"));
const FACTS = JSON.parse(readFileSync(new URL("../lib/inspector/contracts/fact_schema.json", import.meta.url), "utf8"));
const Ajv2020 = Ajv2020Module.default ?? Ajv2020Module;
const ajv = new Ajv2020({ strict: false, allErrors: true });
ajv.addSchema(SCHEMA);
const validRows = ajv.compile({ $ref: `${SCHEMA.$id}#/properties/cited_facts` });

const root = mkdtempSync(join(tmpdir(), "facts-"));
mkdirSync(join(root, "app"));
mkdirSync(join(root, "db"));
writeFileSync(join(root, "app", "route.ts"), "export async function GET(req, { params }) {\n  const session = await auth();\n  const { id } = await params;\n  return db.note.findFirst({ where: { id, ownerId: session.user.id } });\n}\n");
writeFileSync(join(root, "db", "init.sql"), "create table public.notes (\n  id uuid primary key,\n  user_id uuid not null\n);\nalter table public.notes enable row level security;\n");
writeFileSync(join(root, "app", "my route.ts"), "export async function GET(req) {\n");
const files = new Map(["app/route.ts", "db/init.sql", "app/my route.ts"].map((p) => [p, { path: p }]));
const key = Buffer.alloc(32, 7);
const rowsOf = (records) => citedFactRows(root, files, key, records);

const AUTHZ = {
  rule: "authz", candidate: "app/route.ts:1",
  handler: { value: "declared", file: "app/route.ts", line: 1, token: "export async function GET" },
  guard: { value: "owner_filter", file: "app/route.ts", line: 4, token: "ownerId: session.user.id" },
  record_id_source: { value: "path_param", file: "app/route.ts", line: 3, token: "await params" },
  owner_value_source: { value: "session", file: "app/route.ts", line: 2, token: "await auth()" },
};
const RLS = {
  rule: "rls", candidate: "public.notes",
  table: { value: "declared", file: "db/init.sql", line: 1, token: "create table public.notes" },
  rls_enabled: { value: "enabled", file: "db/init.sql", line: 5, token: "enable row level security" },
  per_user_columns: { value: ["user_id"], file: "db/init.sql", line: 3, token: "user_id uuid" },
};

const byField = (rows) => Object.fromEntries(rows.map((r) => [r.field, r]));

test("the field lists and values are the synced contract's", () => {
  for (const [rule, spec] of Object.entries(FACTS.rules)) {
    assert.deepEqual(FACT_FIELDS[rule], Object.keys(spec.fields));
    for (const [field, about] of Object.entries(spec.fields)) assert.deepEqual(FACT_VALUES[field], about.values);
  }
});

test("a fully cited authz record gives one ok row per field, with no token", async () => {
  const rows = await rowsOf([AUTHZ]);
  assert.ok(validRows(rows), JSON.stringify(validRows.errors));
  assert.deepEqual(rows.map((r) => r.field), FACT_FIELDS.authz);
  const f = byField(rows);
  assert.deepEqual(f.guard, { rule: "authz", candidate: "app/route.ts:1", field: "guard", value: "owner_filter",
    column_names: [], cited_at: "app/route.ts:4", cite: "ok" });
  assert.ok(!JSON.stringify(rows).includes("ownerId: session"), "the token never leaves the machine");
});

test("an rls record lists its columns, and a field left out is unknown with no citation", async () => {
  const { rls_enabled: _, ...partial } = RLS;
  const rows = await rowsOf([partial]);
  assert.ok(validRows(rows), JSON.stringify(validRows.errors));
  const f = byField(rows);
  assert.deepEqual([f.per_user_columns.value, f.per_user_columns.column_names, f.per_user_columns.cite], ["listed", ["user_id"], "ok"]);
  assert.deepEqual([f.rls_enabled.value, f.rls_enabled.cite, f.rls_enabled.cited_at], ["unknown", "none", null]);
});

test("a citation that doesn't hold keeps the value but is failed, with no location", async () => {
  const rows = await rowsOf([{ ...AUTHZ, guard: { ...AUTHZ.guard, line: 2 } }]);
  assert.deepEqual([byField(rows).guard.value, byField(rows).guard.cite, byField(rows).guard.cited_at], ["owner_filter", "failed", null]);
});

test("a claim of absence may come without a citation (cite none)", async () => {
  const rows = await rowsOf([{ ...AUTHZ, guard: { value: "none" } }]);
  assert.deepEqual([byField(rows).guard.value, byField(rows).guard.cite], ["none", "none"]);
});

test("a value outside the field's list, or a column that isn't a plain name, is unknown", async () => {
  const rows = await rowsOf([
    { ...AUTHZ, guard: { ...AUTHZ.guard, value: "admin_only" } },
    { ...RLS, per_user_columns: { ...RLS.per_user_columns, value: ["user id"] } },
    { ...RLS, candidate: "public.other", per_user_columns: { ...RLS.per_user_columns, value: "user_id" } },
  ]);
  assert.ok(validRows(rows), JSON.stringify(validRows.errors));
  const guard = rows.find((r) => r.field === "guard");
  const cols = rows.filter((r) => r.field === "per_user_columns");
  assert.equal(guard.value, "unknown");
  assert.deepEqual(cols.map((r) => [r.value, r.column_names]), [["unknown", []], ["unknown", []]]);
});

test("a record with an unknown rule or a candidate of the wrong shape is dropped", async () => {
  const rows = await rowsOf([
    { ...AUTHZ, rule: "secrets" }, { ...AUTHZ, candidate: "public.notes" }, { ...RLS, candidate: "db/init.sql:1" },
    { ...AUTHZ, candidate: "../x.ts:1" }, null, "text", { ...AUTHZ, candidate: "app/route.ts:1" },
  ]);
  assert.deepEqual([...new Set(rows.map((r) => r.candidate))], ["app/route.ts:1"]);
  assert.equal(rows.length, FACT_FIELDS.authz.length);
});

test("a cited path goes out as every walked path does (ids.sentPath), and the document stays valid", async () => {
  const rows = await rowsOf([{ ...AUTHZ,
    handler: { value: "declared", file: "app/my route.ts", line: 1, token: "export async function GET" } }]);
  assert.ok(validRows(rows), JSON.stringify(validRows.errors));
  assert.notEqual(sentPath(key, "app/my route.ts"), "app/my route.ts");
  assert.deepEqual([byField(rows).handler.cite, byField(rows).handler.cited_at], ["ok", `${sentPath(key, "app/my route.ts")}:1`]);
});

test("a handler candidate must be a line of a walked file", async () => {
  const rows = await rowsOf([{ ...AUTHZ, candidate: "app/other.ts:1" }, { ...AUTHZ, candidate: "app/route.ts:40" },
    { ...RLS, candidate: "public.my table" }, { ...RLS, candidate: "notes" }]);
  assert.deepEqual(rows, []);
});

test("the check tool takes facts, shaped by the synced fact_schema.json, and only the check tool does", async () => {
  const { INPUT_SCHEMA, GUIDANCE_INPUT_SCHEMA, RESULT_INPUT_SCHEMA } = await import("../lib/inspector/tool.mjs");
  const item = INPUT_SCHEMA.properties.facts.items;
  assert.deepEqual(item.properties.rule.enum, Object.keys(FACTS.rules));
  const fields = new Set(Object.values(FACTS.rules).flatMap((r) => Object.keys(r.fields)));
  assert.deepEqual(new Set(Object.keys(item.properties).filter((k) => k !== "rule" && k !== "candidate")), fields);
  assert.equal(item.additionalProperties, false);
  assert.ok(!("minLength" in item.properties.handler.properties.token), "a short token is a failed cite, not a refused call");
  assert.ok(!GUIDANCE_INPUT_SCHEMA.properties.facts && !RESULT_INPUT_SCHEMA.properties.facts);
});

// T29-P1-C73 point 1 (P3 C96, P2 C70): matches come first, so cited_facts gets a fixed share of the document. Whole
// candidates are kept in the order the records came in while they fit; the rest are dropped and counted (no names),
// and never cut part way, so a kept candidate has a row for every field of its rule.
const rowBytes = (rows) => Buffer.byteLength(JSON.stringify(rows), "utf8");
const threeHandlers = ["app/route.ts:1", "app/route.ts:2", "app/route.ts:3"].map((candidate) => ({ ...AUTHZ, candidate }));

test("cited_facts has a fixed 1 MB share", () => {
  assert.equal(CITED_FACTS_MAX_BYTES, 1_000_000);
});

test("past the share, whole candidates are dropped in record order and counted", async () => {
  const one = rowBytes(await rowsOf([threeHandlers[0]]));
  const { rows, dropped } = await citedFacts(root, files, key, threeHandlers, { maxBytes: 2 * one + 2 });
  assert.ok(validRows(rows), JSON.stringify(validRows.errors));
  assert.deepEqual([...new Set(rows.map((r) => r.candidate))], ["app/route.ts:1", "app/route.ts:2"]);
  assert.equal(rows.length, 2 * FACT_FIELDS.authz.length, "no candidate is cut part way");
  assert.equal(dropped, 1);
  assert.ok(rowBytes(rows) <= 2 * one + 2);
  const again = await citedFacts(root, files, key, threeHandlers, { maxBytes: 2 * one + 2 });
  assert.deepEqual(again, { rows, dropped }, "the same input keeps the same rows");
});

test("the row limit drops whole candidates too, never part of one", async () => {
  const { rows, dropped } = await citedFacts(root, files, key, threeHandlers, { maxRows: FACT_FIELDS.authz.length + 1 });
  assert.deepEqual([...new Set(rows.map((r) => r.candidate))], ["app/route.ts:1"]);
  assert.equal(rows.length, FACT_FIELDS.authz.length);
  assert.equal(dropped, 2);
});

// P2 C72 lows 1 and 2 (T29-P1-C77): past the cut only good records are counted, and the note names both limits.
test("past the cut, a bad record is not counted as dropped", async () => {
  const bad = [{ ...AUTHZ, candidate: "app/other.ts:1" }, { rule: "no-such-rule", candidate: "app/route.ts:1" }];
  const { dropped } = await citedFacts(root, files, key, [...threeHandlers, ...bad], { maxRows: FACT_FIELDS.authz.length + 1 });
  assert.equal(dropped, 2, "only the two good handlers past the cut");
});

test("the dropped note names both limits and no candidate", () => {
  const note = droppedFactsNote(3);
  assert.match(note, /over their share \(1,000,000 bytes or 10,000 rows\)/);
  assert.match(note, /^3 fact records were left out/);
});

test("a bad record is not counted as dropped for size, and under the share nothing is dropped", async () => {
  const { rows, dropped } = await citedFacts(root, files, key, [{ ...AUTHZ, candidate: "app/other.ts:1" }, AUTHZ]);
  assert.equal(rows.length, FACT_FIELDS.authz.length);
  assert.equal(dropped, 0);
});

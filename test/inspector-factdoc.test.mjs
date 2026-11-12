/* The fact document builder: a golden document from a fixture repository validates against the shipped v2.1
 * schema; every collector failure mode gives its status; no absolute path, .env content or secret appears in the
 * serialized document; odd names and path segments are hashed, never dropped. Everything runs on temporary folders;
 * the catalog and platform collectors are replaced (no database, no network). */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { cpSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildFactDocuments, checkDocument, dataFileKind, bytesBucket, DEFAULT_BUNDLE_DIR, LOADER_TIMEOUT_MS, loadRuleset, NOT_ANALYZED_MAX, QUERY_IDS, SETUP_TIMEOUT_NOTE, STALE_BUNDLE_NOTE, secretRuleId, startRuleset, unaccountedFiles } from "../lib/inspector/factdoc.mjs";
import { loadRules, runRules } from "../lib/inspector/rules.mjs";
import { judgePreflight } from "../lib/inspector/catalog.mjs";
import { parseToml } from "../lib/inspector/tomlparse.mjs";
import { classifyColumn, observedTenancy, TECHNICAL_COLUMN_NAMES } from "../lib/inspector/columns.mjs";
import { sentPath, rootId, hashed } from "../lib/inspector/ids.mjs";
import { FACT_SCHEMA, RESPONSE_SCHEMA } from "../lib/inspector/schema.mjs";
import { SOURCE_COMMIT } from "../lib/inspector/contracts.mjs";
import { NOT_ANALYZED_MAX as WALK_NOT_ANALYZED_MAX } from "../lib/inspector/files.mjs";

const RULES = loadRules(fileURLToPath(new URL("./fixtures/rules/", import.meta.url)));
const RULESET_ID = "2026-10-20.0123abcd";
const ENV_VALUE = "sk\x5flive_ENVFILEVALUEabcdefghijklmnop1234";
const SECRET = "sk\x5flive_51HqT7vXk2LmP9rB4wZ8nC3dF6gJ1hY5sA0eU"; // mixed: an alphabet run reads as a placeholder (isShapePlaceholder)
const temp = (prefix) => realpathSync(mkdtempSync(join(tmpdir(), prefix)));

function repo(files) {
  const root = temp("a7-repo-");
  for (const [p, t] of Object.entries(files)) {
    mkdirSync(join(root, p, ".."), { recursive: true });
    writeFileSync(join(root, p), t);
  }
  return root;
}

const BASE = {
  "package.json": JSON.stringify({ dependencies: { next: "14.2.0", "@supabase/supabase-js": "2.0.0" } }),
  "app/api/visits/route.ts": 'import { requireUser } from "@/lib/auth";\nexport async function POST(request) {\n  const user = await requireUser(request);\n  await db.from("audit_log").insert({ user });\n  return Response.json({});\n}\n',
  "supabase/config.toml": '[api]\nenabled = true\n\n[functions.hello-world]\nverify_jwt = false\n\n[functions."odd name"]\nentrypoint = "./functions/odd/main.ts"\n\n[functions.escape]\nentrypoint = "../../outside.ts"\nverify_jwt = "no"\n',
  "data/export.csv": "a,b\n1,2\n",
  "backups/prod.dump": "x",
  "odd dir/ünïcode file.ts": "export const x = 1;\n",
  ".env": `STRIPE=${ENV_VALUE}\n`,
  ".env.local": `STRIPE=${ENV_VALUE}\n`,
  "config/keys.ts": `export const key = "${SECRET}";\n`,
  "README.md": "# demo\n",
};

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
const RLS = (table, text) => ({ schema_name: "public", table_name: table, policy_name: `${table} policy`, command: "select",
  permissive: true, always_true: false, reads_user_metadata: false, trusted_routes: [], owner_match: false,
  roles: ["authenticated"], using_expression: text, check_expression: null });
function catalogResult() {
  return { status: "ok", count: 0, reason: null, preflight: PREFLIGHT, queries: [
    ok("table_columns", [
      { schema_name: "public", table_name: "patients", column_name: "id", data_type: "uuid" },
      { schema_name: "public", table_name: "patients", column_name: "date_of_birth", data_type: "date" },
      { schema_name: "public", table_name: "patients", column_name: "ssn", data_type: "text" },
      { schema_name: "public", table_name: "patients", column_name: "org_id", data_type: "uuid" },
      { schema_name: "public", table_name: "patients", column_name: "flavour", data_type: "text" },
      { schema_name: "public", table_name: "Patient Notes", column_name: "clinical notes", data_type: "text" },
      { schema_name: "public", table_name: "patients", column_name: "created_at", data_type: "timestamp with time zone" },
    ]),
    ok("rls_policies", [RLS("patients", "(org_id = ((auth.jwt() ->> 'org_id'::text))::uuid)")]),
    ok("rls_status", [{ schema_name: "public", table_name: "patients", rls_enabled: true, rls_forced: false }]),
  ] };
}

const quietCatalog = async () => ({ status: "not_run", count: 0, reason: "service_missing", preflight: null, queries: [] });
const quietPlatform = async () => ({ provider: null, status: "not_run", reason: "no_token", settings: {} });

async function build(root, extra = {}) {
  const configDir = temp("a7-cfg-");
  const out = await buildFactDocuments([root], {
    configDir, ruleset: { id: RULESET_ID, rules: RULES, queries: loadRuleset({ bundleDir: "/nonexistent", rulesetId: RULESET_ID }).queries },
    collectCatalog: quietCatalog, collectPlatform: quietPlatform, ...extra,
  });
  return { out, configDir, key: readFileSync(join(configDir, "install.key")) };
}
const col = (doc, name) => doc.collection.find((c) => c.collector === name);

test("the shipped response schema takes exposure_suspected wherever it takes a result reason", () => {
  const enums = [];
  const walk = (x) => {
    if (Array.isArray(x)) { if (x.includes("catalog_not_deployed")) enums.push(x); x.forEach(walk); }
    else if (x && typeof x === "object") Object.values(x).forEach(walk);
  };
  walk(RESPONSE_SCHEMA);
  assert.equal(enums.length, 5);   // T29 o1b 3d-1 removed the answer block, and with it answer.holds[].reason
  for (const e of enums) assert.ok(e.includes("exposure_suspected"), JSON.stringify(e));
});

test("the shipped schemas are the contract's copies, and contracts.mjs names the commit", () => {
  // The fixtures are byte-for-byte copies of the evaluator's schemas, named by the evaluator commit each came from.
  const fixture = JSON.parse(readFileSync(new URL("./fixtures/contracts/fact_document.schema.9faf6c07.json", import.meta.url), "utf8"));
  assert.deepEqual(FACT_SCHEMA, fixture);
  assert.deepEqual(RESPONSE_SCHEMA, JSON.parse(readFileSync(new URL("./fixtures/contracts/response.schema.60d2b175.json", import.meta.url), "utf8")));
  assert.equal(FACT_SCHEMA.$id, "https://custosa.com/schemas/fact-document/2");
  assert.ok(!FACT_SCHEMA.$defs.query_server_version && !FACT_SCHEMA.$defs.row_server_version);
  assert.ok(!JSON.stringify(RESPONSE_SCHEMA).includes("server_version"));
  assert.ok(RESPONSE_SCHEMA.$defs.evaluate_response.properties.not_used);
  assert.ok(RESPONSE_SCHEMA.$defs.evaluate_response.properties.verdicts_unsettled); // T29-P1-C204 item 3
  assert.match(SOURCE_COMMIT, /^9faf6c07/); // the evaluator commit the fact schema was last copied from
  assert.ok(!FACT_SCHEMA.$defs.query_hba_rules);
  // other_execute_roles is optional, so a row from an older CLI stays valid and core holds the function.
  assert.ok(FACT_SCHEMA.$defs.row_definer_functions.properties.other_execute_roles);
  assert.ok(!FACT_SCHEMA.$defs.row_definer_functions.required.includes("other_execute_roles"));
  // api_grantee is optional, so a row whose flag the CLI can't read stays valid and core holds it.
  assert.equal(FACT_SCHEMA.$defs.row_default_acl.properties.api_grantee.type, "boolean");
  assert.ok(!FACT_SCHEMA.$defs.row_default_acl.required.includes("api_grantee"));
  // the three columns an older inspector left out are required now (no compatibility). The CLI
  // sends each on every row, so its own documents stay valid.
  for (const [row, col] of [["row_views", "definer_calls"], ["row_exposed_schemas", "auth_definers"], ["row_rls_policies", "references_row"]]) {
    assert.ok(FACT_SCHEMA.$defs[row].properties[col], `${row}.${col}`);
    assert.ok(FACT_SCHEMA.$defs[row].required.includes(col), `${row}.${col} is not required`);
  }
  // every result reason enum takes unclassified_table_exposed, so an older evaluator's answer isn't refused.
  const reasons = [];
  const walk = (x) => {
    if (Array.isArray(x)) { if (x.includes("exposure_suspected")) reasons.push(x); x.forEach(walk); }
    else if (x && typeof x === "object") Object.values(x).forEach(walk);
  };
  walk(RESPONSE_SCHEMA);
  assert.ok(reasons.length > 0);
  for (const e of reasons) assert.ok(e.includes("unclassified_table_exposed"), JSON.stringify(e));
});

test("The response schema takes contract 2.2's result reasons, so a 2.2 core's answer isn't refused", () => {
  const enums = [];
  const walk = (x) => {
    if (Array.isArray(x)) { if (x.includes("catalog_not_deployed")) enums.push(x); x.forEach(walk); }
    else if (x && typeof x === "object") Object.values(x).forEach(walk);
  };
  walk(RESPONSE_SCHEMA);
  assert.equal(enums.length, 5);   // T29 o1b 3d-1 removed the answer block, and with it answer.holds[].reason
  for (const e of enums) {
    for (const r of ["assistant_located", "code_not_verified", "answer_contradicted", "location_not_confirmed", "assistant_contested"]) {
      assert.ok(e.includes(r), `${r} missing from ${JSON.stringify(e)}`);
    }
  }
});

test("One NOT_ANALYZED_MAX, the shipped fact schema's files.not_analyzed maxItems", () => {
  assert.equal(NOT_ANALYZED_MAX, 20_000);
  assert.equal(NOT_ANALYZED_MAX, WALK_NOT_ANALYZED_MAX);
  assert.equal(NOT_ANALYZED_MAX, FACT_SCHEMA.properties.files.properties.not_analyzed.maxItems);
});

test("tests keep no copy of a contract schema outside fixtures/contracts/", () => {
  // Tests load the shipped schema from lib/inspector/contracts/; fixtures/contracts/ holds only the commit-pinned
  // copies the test above compares it with. A loose copy goes stale unseen (two did: no fingerprints, no public_privileges).
  const testDir = fileURLToPath(new URL("./", import.meta.url));
  const strays = readdirSync(testDir, { recursive: true }).map(String)
    .filter((p) => /(^|[\\/])(fact_document|response)\.schema(\.[^\\/]*)?\.json$/.test(p))
    .filter((p) => !/^fixtures[\\/]contracts[\\/][^\\/]+$/.test(p));
  assert.deepEqual(strays, []);
});

test("golden document: a fixture repository gives a valid, closed document", async () => {
  const root = repo(BASE);
  const { out, key } = await build(root);
  assert.equal(out.documents.length, 1);
  const [{ document: doc, problem }] = out.documents;
  assert.equal(problem, null, JSON.stringify(problem));
  assert.equal(checkDocument(doc), null);
  assert.deepEqual(doc.collection.map((c) => c.collector), ["files", "git", "rules", "catalog", "platform", "secrets"]);
  assert.equal(doc.schema_version, 2);
  assert.equal(doc.ruleset_id, RULESET_ID);
  assert.equal(doc.root_id, createHmac("sha256", key).update(root, "utf8").digest("hex"));
  assert.deepEqual(doc.files.frameworks, ["nextjs", "supabase"]);
  assert.deepEqual(doc.files.fingerprints, []); // supabase-js alone declares none
  assert.deepEqual(col(doc, "files"), { collector: "files", status: "ok", count: 8, reason: null });
  assert.deepEqual(col(doc, "git"), { collector: "git", status: "not_run", count: 0, reason: "not_configured" });
  assert.equal(col(doc, "rules").status, "ok");
  // The odd path is hashed segment by segment and still analysed.
  const odd = `${hashed(key, "odd dir")}/${hashed(key, "ünïcode file.ts")}`;
  assert.equal(sentPath(key, "odd dir/ünïcode file.ts"), odd);
  assert.ok(!JSON.stringify(doc).includes("odd dir"));
  assert.equal(doc.files.analyzed, 3);
  // Edge Functions: declared and default entrypoints, a name hashed, an entrypoint outside the root null, and
  // verify_jwt only as declared.
  assert.deepEqual(doc.supabase.edge_functions, { status: "ok", reason: null, items: [
    { name: "hello-world", entrypoint: "supabase/functions/hello-world/index.ts", verify_jwt: false },
    { name: hashed(key, "odd name"), entrypoint: "supabase/functions/odd/main.ts", verify_jwt: "not_read" },
    { name: "escape", entrypoint: null, verify_jwt: "not_read" },
  ] });
  // The config.toml this module parsed is not forwarded as unsupported_language or unknown_type.
  assert.ok(!doc.files.not_analyzed.some((e) => e.path === "supabase/config.toml"));
  assert.deepEqual(doc.files.data_files, [
    { path: "backups/prod.dump", kind: "sql_dump", bytes_bucket: "under_10kb", tracked: "not_checked" },
    { path: "data/export.csv", kind: "csv", bytes_bucket: "under_10kb", tracked: "not_checked" },
  ]);
  assert.deepEqual(doc.files.env_files.map((e) => e.path).sort(), [".env", ".env.local"]);
  assert.equal(doc.secrets.length, 1);
  assert.deepEqual({ ...doc.secrets[0], fingerprint: undefined }, { rule_id: secretRuleId(doc.secrets[0].rule_id.replace(/^secrets\./, "")), path: "config/keys.ts", line: 1, fingerprint: undefined, in_history: "not_checked" });
  assert.match(doc.secrets[0].rule_id, /^secrets\./);
  // Without a catalog nothing is observed: every query present and not_run, no columns, tenancy unknown.
  assert.deepEqual(doc.catalog.queries.map((q) => q.query_id).sort(), [...QUERY_IDS].sort());
  assert.ok(doc.catalog.queries.every((q) => q.status === "not_run" && q.reason === "not_configured"));
  assert.deepEqual(doc.columns, []);
  assert.deepEqual(doc.tenancy, { model: "unknown", tenant_column: null, source: "answer" });
  assert.ok(Object.values(doc.platform.settings).every((v) => v === "not_read"));
});

test("no absolute path, .env content or secret value appears anywhere in the serialized document", async () => {
  const root = repo(BASE);
  const { out, configDir } = await build(root, { collectCatalog: async () => catalogResult() });
  const text = JSON.stringify(out.documents[0].document);
  for (const needle of [root, configDir, tmpdir(), realpathSync(tmpdir()), homedir(), ENV_VALUE, SECRET, "STRIPE=", "/Users/", "/private/", "/home/", "/tmp/"]) {
    assert.ok(!text.includes(needle), `document holds ${needle}`);
  }
  assert.ok(!text.includes("auth.jwt"), "policy text never leaves");
  assert.ok(!/"[A-Za-z]:\\\\/.test(text));
});

test("catalog facts: column classes, the technical allowlist, hashed names and the observed tenancy", async () => {
  const root = repo({ "a.ts": "export const a = 1;\n" });
  const { out, key } = await build(root, { collectCatalog: async () => catalogResult() });
  const [{ document: doc, problem }] = out.documents;
  assert.equal(problem, null, JSON.stringify(problem));
  assert.deepEqual(doc.columns.map((c) => [c.table, c.column, c.class]), [
    ["public.patients", "id", "technical"],
    ["public.patients", "date_of_birth", "direct_identifier"],
    ["public.patients", "ssn", "government_id"],
    ["public.patients", "org_id", "unknown"],
    ["public.patients", "flavour", "unknown"],
    [`public.${hashed(key, "Patient Notes")}`, hashed(key, "clinical notes"), "health"],
    ["public.patients", "created_at", "technical"],
  ]);
  assert.deepEqual(doc.tenancy, { model: "row_level", tenant_column: "org_id", source: "observed" });
  // Missing queries are explicit failures, never left out.
  const views = doc.catalog.queries.find((q) => q.query_id === "views");
  assert.deepEqual(views, { query_id: "views", status: "failed", reason: "internal_error", rows: [] });
  assert.equal(col(doc, "catalog").status, "ok");
});

// No silent drop between the walk and the rules: every walked file is analysed, listed in not_analyzed, or an edge
// config the edge collector parsed. The real engine accounts for every file; an engine that loses one (here a stub)
// gets the document refused locally, never sent with the file unseen.
test("every walked file is analysed or listed; a file the rules lose refuses the document", async () => {
  const root = repo(BASE);
  const { out } = await build(root);
  const [{ document: doc, problem }] = out.documents;
  assert.equal(problem, null, JSON.stringify(problem));
  assert.ok(doc.files.analyzed > 0);

  let dropped = null;
  const losing = async (rules, files, opts) => {
    const res = await runRules(rules, files, opts);
    dropped = res.analyzedPaths[0];
    return { ...res, analyzedPaths: res.analyzedPaths.slice(1), analyzed: res.analyzed - 1 };
  };
  const { out: out2 } = await build(root, { runRules: losing });
  assert.ok(dropped);
  assert.deepEqual(out2.documents[0].problem, { at: "/files/analyzed", keyword: "unaccounted" });

  assert.deepEqual(unaccountedFiles(["a.ts", "b.ts", "c.toml", "d.ts"], { analyzedPaths: ["a.ts"] },
    [{ path: "b.ts", kind: "file" }, { path: "d.ts", kind: "directory" }], new Set(["c.toml"])), ["d.ts"]);
  assert.deepEqual(unaccountedFiles(["a.ts"], { status: "failed" }, []), []); // the engine didn't run: its status says so
});

test("a collector that throws is failed with internal_error and no error text", async () => {
  const root = repo(BASE);
  const boom = () => { throw new Error("SECRET DETAIL /Users/someone/path"); };
  const { out } = await build(root, { runRules: boom, scanSecrets: boom, collectCatalog: boom, collectPlatform: boom });
  const [{ document: doc, problem }] = out.documents;
  assert.equal(problem, null, JSON.stringify(problem));
  for (const name of ["rules", "catalog", "platform", "secrets"]) {
    assert.deepEqual(col(doc, name), { collector: name, status: "failed", count: 0, reason: "internal_error" }, name);
  }
  assert.ok(!JSON.stringify(doc).includes("SECRET DETAIL"));
  assert.equal(doc.matches.length, 0);
  assert.ok(doc.catalog.queries.every((q) => q.status === "not_run"));

  // The walk itself throwing: files and git failed, the collectors that need it not run, edge failed.
  const walked = await build(root, { walkAll: boom });
  const w = walked.out.documents[0].document;
  assert.equal(walked.out.documents[0].problem, null, JSON.stringify(walked.out.documents[0].problem));
  assert.deepEqual(col(w, "files"), { collector: "files", status: "failed", count: 0, reason: "internal_error" });
  assert.deepEqual(col(w, "git"), { collector: "git", status: "failed", count: 0, reason: "internal_error" });
  assert.equal(col(w, "rules").status, "not_run");
  assert.equal(col(w, "secrets").status, "not_run");
  assert.deepEqual(w.supabase.edge_functions, { status: "failed", reason: "internal_error", items: [] });

  // A bundle whose rules don't load: rules failed, nothing analysed.
  const broken = await build(root, { ruleset: { id: RULESET_ID, rules: null, queries: [] } });
  assert.deepEqual(col(broken.out.documents[0].document, "rules"), { collector: "rules", status: "failed", count: 0, reason: "internal_error" });
  assert.equal(broken.out.documents[0].document.files.analyzed, 0);
});

test("a collector that throws logs one stderr line with its name and error class, never the message", async () => {
  const root = repo(BASE);
  class CatalogBroke extends Error {}
  const lines = [];
  const write = process.stderr.write;
  process.stderr.write = (chunk, ...rest) => {
    if (String(chunk).includes("collector failed")) { lines.push(String(chunk)); return true; }
    return write.call(process.stderr, chunk, ...rest);
  };
  try {
    await build(root, {
      runRules: () => { throw new TypeError("SECRET DETAIL"); },
      collectCatalog: () => { throw new CatalogBroke("SECRET DETAIL"); },
      collectPlatform: () => { throw "SECRET DETAIL"; }, // not an Error: its type only
    });
  } finally { process.stderr.write = write; }
  assert.deepEqual(lines.sort(), [
    "custosa inspect: catalog collector failed: CatalogBroke\n",
    "custosa inspect: platform collector failed: string\n",
    "custosa inspect: rules collector failed: TypeError\n",
  ]);
});

test("edge_functions: every status the contract names", async () => {
  const edge = async (files) => {
    const { out } = await build(repo({ "a.ts": "export const a = 1;\n", ...files }));
    assert.equal(out.documents[0].problem, null, JSON.stringify(out.documents[0].problem));
    return out.documents[0].document;
  };
  let doc = await edge({});
  assert.deepEqual(doc.supabase.edge_functions, { status: "not_run", reason: "not_configured", items: [] });
  doc = await edge({ "supabase/config.toml": "[api\nenabled = true\n" });
  assert.deepEqual(doc.supabase.edge_functions, { status: "failed", reason: "parse_failed", items: [] });
  assert.deepEqual(doc.files.not_analyzed.filter((e) => e.path === "supabase/config.toml"), [{ path: "supabase/config.toml", kind: "file", reason: "parse_error", tracked: null }]);
  assert.ok(!doc.files.not_analyzed.some((e) => e.reason === "unsupported_language" && /config\.toml$/.test(e.path)));
  // One parses, another doesn't: failed, no items.
  doc = await edge({ "supabase/config.toml": "[functions.a]\nverify_jwt = true\n", "apps/web/Supabase/config.toml": "x = = 1\n" });
  assert.deepEqual(doc.supabase.edge_functions, { status: "failed", reason: "parse_failed", items: [] });
  // A [functions] table of the wrong shape.
  doc = await edge({ "supabase/config.toml": "functions = 1\n" });
  assert.deepEqual(doc.supabase.edge_functions, { status: "failed", reason: "parse_failed", items: [] });
  doc = await edge({ "supabase/config.toml": "[functions]\nhello = true\n" });
  assert.equal(doc.supabase.edge_functions.status, "failed");
  // Too large to read: failed, listed as too_large.
  doc = await edge({ "supabase/config.toml": `# ${"x".repeat(1_100_000)}\n` });
  assert.deepEqual(doc.supabase.edge_functions, { status: "failed", reason: "parse_failed", items: [] });
  assert.ok(doc.files.not_analyzed.some((e) => e.path === "supabase/config.toml" && e.reason === "too_large"));
  // Parsed with no functions: empty.
  doc = await edge({ "supabase/config.toml": "[api]\nenabled = true\n" });
  assert.deepEqual(doc.supabase.edge_functions, { status: "empty", reason: null, items: [] });
  // Over 1,000: truncated with the first 1,000.
  doc = await edge({ "supabase/config.toml": Array.from({ length: 1001 }, (_, i) => `[functions.f${i}]\nverify_jwt = true\n`).join("") });
  assert.equal(doc.supabase.edge_functions.status, "truncated");
  assert.equal(doc.supabase.edge_functions.reason, "item_limit");
  assert.equal(doc.supabase.edge_functions.items.length, 1000);
});

test("secrets truncation maps to the secrets entry and to files.not_analyzed", async () => {
  const root = repo(BASE);
  const scan = (files) => ({ secrets: [], truncated: files.filter((f) => f.path === "config/keys.ts").map((f) => ({ path: f.path, in_history: false, reason: "match_cut_at_window" })) });
  const { out } = await build(root, { scanSecrets: scan });
  const [{ document: doc, problem }] = out.documents;
  assert.equal(problem, null, JSON.stringify(problem));
  assert.deepEqual(col(doc, "secrets"), { collector: "secrets", status: "truncated", count: 0, reason: "match_cut_at_window" });
  assert.deepEqual(doc.files.not_analyzed.find((e) => e.path === "config/keys.ts"), { path: "config/keys.ts", kind: "file", reason: "too_large", tracked: null });
  // A file the walk couldn't keep (too large) wasn't scanned either: never ok.
  const big = repo({ "a.ts": "x\n", "big.txt": "y".repeat(2_100_000) });
  const b = (await build(big)).out.documents[0].document;
  assert.deepEqual(col(b, "secrets"), { collector: "secrets", status: "truncated", count: 0, reason: "size_limit" });
});

test("hashing: segments, whole paths over 512 characters, identifiers and root ids", () => {
  const key = Buffer.alloc(32, 7);
  assert.equal(sentPath(key, "src/app.ts"), "src/app.ts");
  assert.equal(sentPath(key, "src/a b.ts"), `src/${hashed(key, "a b.ts")}`);
  assert.match(hashed(key, "x"), /^u_[0-9a-f]{16}$/);
  const long = Array.from({ length: 40 }, () => "abcdefghijklmn").join("/");
  assert.equal(sentPath(key, long), hashed(key, long));
  assert.equal(rootId(key, "/a/b/"), rootId(key, "/a/b"));
});

test("data files: kinds by name, size bands", () => {
  assert.equal(dataFileKind("x/db.SQL.gz", 10), "sql_dump");
  assert.equal(dataFileKind("schema.sql", 500), null);
  assert.equal(dataFileKind("dump.sql", 2_000_000), "sql_dump");
  assert.equal(dataFileKind("a.tar.gz", 1), "archive");
  assert.equal(dataFileKind("a.ndjson", 1), "json_lines");
  assert.equal(dataFileKind("a.ts", 1), null);
  assert.deepEqual([9_999, 10_000, 999_999, 1_000_000, 100_000_000, null].map(bytesBucket),
    ["under_10kb", "10kb_to_1mb", "10kb_to_1mb", "1mb_to_100mb", "over_100mb", "1mb_to_100mb"]);
});

test("column classifier: technical only from the allowlist, unknown otherwise, mixed scripts unknown", () => {
  for (const name of TECHNICAL_COLUMN_NAMES) assert.equal(classifyColumn(name.toUpperCase()), "technical", name);
  for (const name of ["status", "kind", "flavour", "item_count", "is_active", "name"]) assert.equal(classifyColumn(name), "unknown", name);
  assert.equal(classifyColumn("firstName"), "direct_identifier");
  assert.equal(classifyColumn("FIRSTNAME"), "direct_identifier");
  assert.equal(classifyColumn("patient_email"), "contact");
  assert.equal(classifyColumn("password_hash"), "credential");
  assert.equal(classifyColumn("nhs_number"), "government_id");
  assert.equal(classifyColumn("medicaid_id"), "government_id");
  for (const name of ["govt_id", "government_number", "govtId", "government_identifier"]) {
    assert.equal(classifyColumn(name), "government_id", name); // government ids under other names
  }
  assert.equal(classifyColumn("icd10_code"), "health");
  assert.equal(classifyColumn("card_number"), "financial");
  assert.equal(classifyColumn("еmail"), "unknown"); // a Cyrillic e: never technical, never guessed
  assert.equal(classifyColumn("last_ip", "inet"), "direct_identifier");
  assert.equal(classifyColumn("created_at_ssn"), "government_id");
});

test("tenancy: observed only with a usable catalog, never single, row_level only on the column the policy compares (review p4)", async () => {
  assert.deepEqual(observedTenancy({ catalogStatus: "failed" }), { model: "unknown", tenant_column: null, source: "answer" });
  assert.deepEqual(observedTenancy({ catalogStatus: "ok" }), { model: "unknown", tenant_column: null, source: "observed" });
  const cols = [{ schema: "s", table: "t", column: "org_id", sentColumn: "org_id" }, { schema: "s", table: "t", column: "owner_org", sentColumn: "owner_org" }];
  const pol = (tenantColumns, tenant_comparison = true) => ({ schema: "s", table: "t", tenant_comparison, tenantColumns });
  assert.deepEqual(observedTenancy({ catalogStatus: "ok", policies: [pol(["org_id"])], columns: cols }), { model: "row_level", tenant_column: "org_id", source: "observed" });
  assert.equal(observedTenancy({ catalogStatus: "ok", policies: [pol(["owner_org"])], columns: cols }).model, "unknown"); // not a tenant key
  assert.equal(observedTenancy({ catalogStatus: "ok", policies: [pol([])], columns: cols }).model, "unknown"); // column not reported
  assert.equal(observedTenancy({ catalogStatus: "ok", policies: [pol(["org_id", "tenant_id"])], columns: cols }).model, "unknown");
  assert.equal(observedTenancy({ catalogStatus: "ok", policies: [{ ...pol(["org_id"]), table: "other" }], columns: cols }).model, "unknown"); // not that table's column
  assert.equal(observedTenancy({ catalogStatus: "ok", policies: [pol(["org_id"], "not_read")], columns: cols }).model, "unknown");

  // End to end: a policy comparing owner_org on a table that also has org_id is not row_level on org_id.
  const root = repo({ "a.ts": "x\n" });
  const c = (t, n) => ({ schema_name: "public", table_name: t, column_name: n, data_type: "uuid" });
  const run = async (columns, text) => (await build(root, { collectCatalog: async () => ({ status: "ok", count: 0, reason: null, preflight: PREFLIGHT,
    queries: [ok("table_columns", columns), ok("rls_policies", [RLS("patients", text)])] }) })).out.documents[0];
  let d = await run([c("patients", "id"), c("patients", "owner_org"), c("patients", "org_id")], "(owner_org = ((auth.jwt() ->> 'org_id'::text))::uuid)");
  assert.equal(d.problem, null);
  assert.equal(d.document.catalog.queries.find((q) => q.query_id === "rls_policies").rows[0].tenant_comparison, true);
  assert.equal(d.document.tenancy.model, "unknown");
  d = await run([c("patients", "id"), c("patients", "owner_org"), c("visits", "org_id")], "(owner_org = ((auth.jwt() ->> 'org_id'::text))::uuid)");
  assert.equal(d.document.tenancy.model, "unknown");
  d = await run([c("patients", "id"), c("patients", "org_id")], "(org_id = ((auth.jwt() ->> 'org_id'::text))::uuid)");
  assert.deepEqual(d.document.tenancy, { model: "row_level", tenant_column: "org_id", source: "observed" });
  assert.ok(!JSON.stringify(d.document).includes("tenantColumns"));
});

test("the TOML reader refuses what isn't TOML", () => {
  assert.deepEqual(parseToml('[functions."a b"]\nverify_jwt = false # c\n'), { functions: { "a b": { verify_jwt: false } } });
  for (const bad of ["a = 1\na = 2", "[a]\n[a]", "a =", "a = 01", 'a = "x" y', "x = {a=1,}", "a = 'x\n'", "[t]\nk.v = 1\n[t.k]", "a = [1,,2]", "= 1", 'a = "\u0001"']) {
    assert.throws(() => parseToml(bad), { name: "TomlError" }, JSON.stringify(bad));
  }
});

test("secrets: every walked non-.env file goes to the secret scan; a binary file truncates the collector, never skipped silently ", async () => {
  const S = `key = "${SECRET}"\n`;
  const names = ["n.ipynb", "d.mdx", "r.rst", "t.j2", "e.ex", "g.groovy", "c.cnf", "o.ovpn", "Procfile", "w.http", "b.bicep",
    "j.json5", "a.sbt", "s.scss", "id_rsa", ".npmrc", "keys.png"];
  const files = Object.fromEntries(names.map((n) => [n, S]));
  files["src/nul.ts"] = `\0${S}`;
  const { out } = await build(repo({ "a.ts": "x\n", ...files }));
  const doc = out.documents[0].document;
  assert.equal(out.documents[0].problem, null);
  const found = new Set(doc.secrets.map((s) => s.path));
  assert.deepEqual([...names, "src/nul.ts"].filter((n) => !found.has(n)), []);
  assert.equal(col(doc, "secrets").status, "ok");
  // A real binary file (mostly NULs) is the secret scan's unreadable: truncated, and the file is listed.
  const bin = Buffer.alloc(4096); bin.write(S, 100);
  const root = repo({ "a.ts": "x\n" });
  writeFileSync(join(root, "blob.dat"), bin);
  const d = (await build(root)).out.documents[0].document;
  assert.deepEqual(col(d, "secrets"), { collector: "secrets", status: "truncated", count: 0, reason: "unreadable" });
  assert.ok(d.files.not_analyzed.some((e) => e.path === "blob.dat"));
});

test("secrets and edge_functions reflect what the walk didn't see (review p2)", async (t) => {
  const files = { "a.ts": "x\n", "b.ts": "x\n", "c.ts": "x\n", "z/keys.ts": `export const k = "${SECRET}";\n`, "supabase/config.toml": "[functions.f]\nverify_jwt = false\n" };
  const show = (doc) => [col(doc, "secrets").status, col(doc, "secrets").reason, doc.supabase.edge_functions.status, doc.supabase.edge_functions.reason];
  // The file limit, with every not_analyzed entry dropped: nothing reads as complete.
  let d = (await build(repo(files), { walkOptions: { maxFiles: 2, notAnalyzedMax: 0 } })).out.documents[0];
  assert.equal(d.problem, null, JSON.stringify(d.problem));
  assert.deepEqual(show(d.document), ["truncated", "file_limit", "failed", "file_limit"]);
  if (process.platform === "win32" || process.getuid?.() === 0) return t.skip("permissions don't bind here");
  const { chmodSync } = await import("node:fs");
  // An unreadable directory: secrets truncated with the walk's reason; edge functions found elsewhere are collected in part.
  const root = repo(files);
  chmodSync(join(root, "z"), 0o000);
  try {
    d = (await build(root)).out.documents[0];
    assert.equal(d.problem, null, JSON.stringify(d.problem));
    assert.deepEqual(show(d.document), ["truncated", "unreadable", "truncated", "item_limit"]); // a secrets reason
  } finally { chmodSync(join(root, "z"), 0o755); }
  // No config.toml seen, but a directory unread: never not_configured.
  const bare = repo({ "a.ts": "x\n", "z/b.ts": "x\n" });
  chmodSync(join(bare, "z"), 0o000);
  try {
    d = (await build(bare)).out.documents[0];
    assert.deepEqual(d.document.supabase.edge_functions, { status: "failed", reason: "not_permitted", items: [] });
  } finally { chmodSync(join(bare, "z"), 0o755); }
});

test("unknown frameworks are never sent as a clean empty list (review p3)", async () => {
  const d = (await build(repo({ "app/api/route.ts": "export async function POST() {}\n", "package.json": JSON.stringify({ dependencies: { next: "14" } }),
    "zz/package.json": "{bad json", "infra/main.tf": "x\n", "supabase/config.toml": "[api]\n" }))).out.documents[0];
  assert.equal(d.problem, null, JSON.stringify(d.problem));
  assert.deepEqual(d.document.files.frameworks, ["supabase", "terraform"]); // the path-known ones stand
  assert.ok(!("fingerprints" in d.document.files)); // unknown is sent absent, never as []
  assert.deepEqual(col(d.document, "files"), { collector: "files", status: "truncated", count: 5, reason: "ignore_unverified" });
  assert.deepEqual(d.document.files.not_analyzed.find((e) => e.path === "zz/package.json"), { path: "zz/package.json", kind: "file", reason: "parse_error", tracked: null });
});

test("the fingerprint is sent and validates; an unreadable pubspec.yaml leaves it absent and frameworks as they were", async () => {
  const { chmodSync } = await import("node:fs");
  let d = (await build(repo({ "package.json": JSON.stringify({ dependencies: { express: "4", openai: "4", "@sentry/node": "8" } }),
    "src/app.ts": "export const x = 1;\n", "mobile/ios/Runner/Info.plist": "<plist/>\n" }))).out.documents[0];
  assert.equal(d.problem, null, JSON.stringify(d.problem));
  assert.deepEqual(d.document.files.fingerprints, ["ai_sdk", "error_tracking_sdk", "ios"]);
  assert.deepEqual(d.document.files.frameworks, ["express"]);
  const root = repo({ "package.json": JSON.stringify({ dependencies: { express: "4" } }), "src/app.ts": "export const x = 1;\n", "app/pubspec.yaml": "x" });
  chmodSync(join(root, "app/pubspec.yaml"), 0o000);
  try {
    d = (await build(root)).out.documents[0];
    assert.equal(d.problem, null, JSON.stringify(d.problem));
    assert.ok(!("fingerprints" in d.document.files));
    assert.deepEqual(d.document.files.frameworks, ["express"]);
  } finally { chmodSync(join(root, "app/pubspec.yaml"), 0o644); }
});

test("Imports add to the fingerprint and are sent as evidence, even with no manifest", async () => {
  // plumbing-gaps' shape: no manifest, an AI import in source.
  let d = (await build(repo({ "src/ai.ts": "// the model\nimport OpenAI from 'openai';\nexport const ai = new OpenAI();\n",
    "src/db.ts": "import { createClient } from '@supabase/supabase-js';\n", "notes.md": "import Anthropic from '@anthropic-ai/sdk'\n" }))).out.documents[0];
  assert.equal(d.problem, null, JSON.stringify(d.problem));
  assert.deepEqual(d.document.files.fingerprints, ["ai_sdk"]);
  assert.deepEqual(d.document.files.imports, [{ fingerprint: "ai_sdk", package: "openai", path: "src/ai.ts", line: 2 }]);
  assert.deepEqual(d.document.files.frameworks, []); // frameworks from imports are a later slice
  // With a manifest: the imports add to what it declares.
  d = (await build(repo({ "package.json": JSON.stringify({ dependencies: { express: "4", "@sentry/node": "8" } }),
    "src/app.ts": "import * as Sentry from '@sentry/node';\nimport { App } from '@capacitor/app';\n" }))).out.documents[0];
  assert.equal(d.problem, null, JSON.stringify(d.problem));
  assert.deepEqual(d.document.files.fingerprints, ["error_tracking_sdk", "mobile_hybrid"]);
  assert.deepEqual(d.document.files.imports.map((i) => [i.fingerprint, i.line]), [["error_tracking_sdk", 1], ["mobile_hybrid", 2]]);
  // No import seen: an empty list, which means none seen, never "not used".
  d = (await build(repo({ "src/app.ts": "export const x = 1;\n" }))).out.documents[0];
  assert.deepEqual([d.document.files.fingerprints, d.document.files.imports], [[], []]);
  // A manifest that doesn't parse leaves the fingerprint unknown (absent); the imports seen are still sent.
  d = (await build(repo({ "zz/package.json": "{bad json", "src/ai.ts": "import OpenAI from 'openai';\n" }))).out.documents[0];
  assert.equal(d.problem, null, JSON.stringify(d.problem));
  assert.ok(!("fingerprints" in d.document.files));
  assert.deepEqual(d.document.files.imports, [{ fingerprint: "ai_sdk", package: "openai", path: "src/ai.ts", line: 1 }]);
});

test("An import path is sent as the document sends that path", async () => {
  const name = "src/caf\u00e9.ts";
  const { out, key } = await build(repo({ [name]: "import OpenAI from 'openai';\n" }));
  const d = out.documents[0];
  assert.equal(d.problem, null, JSON.stringify(d.problem));
  assert.deepEqual(d.document.files.imports, [{ fingerprint: "ai_sdk", package: "openai", path: sentPath(key, name), line: 1 }]);
  assert.notEqual(sentPath(key, name), name);
});

test("undeclared function folders, a gitignored config.toml, real sizes past the walk's limit", async () => {
  // A function folder the config doesn't declare is listed, never "no functions".
  let d = (await build(repo({ "supabase/config.toml": "[api]\nenabled = true\n", "supabase/functions/hello/index.ts": "Deno.serve(() => new Response('x'));\n",
    "supabase/functions/_shared/util.ts": "export const u = 1;\n", "supabase/functions/raw/main.ts": "x\n" }))).out.documents[0];
  assert.equal(d.problem, null, JSON.stringify(d.problem));
  assert.deepEqual(d.document.supabase.edge_functions, { status: "ok", reason: null, items: [
    { name: "hello", entrypoint: "supabase/functions/hello/index.ts", verify_jwt: "not_read" },
    { name: "raw", entrypoint: null, verify_jwt: "not_read" },
  ] });
  // A supabase folder git ignores: never not_configured beside files ok.
  const root = repo({ ".gitignore": "supabase/\n", "a.ts": "x\n", "supabase/config.toml": "[functions.f]\nverify_jwt = false\n" });
  mkdirSync(join(root, ".git"));
  writeFileSync(join(root, ".git", "HEAD"), "ref: refs/heads/main\n");
  d = (await build(root)).out.documents[0];
  assert.equal(d.problem, null, JSON.stringify(d.problem));
  assert.deepEqual(d.document.supabase.edge_functions, { status: "failed", reason: "ignore_unverified", items: [] });
  assert.deepEqual(col(d.document, "files"), { collector: "files", status: "truncated", count: 2, reason: "ignore_unverified" });
  assert.ok(d.document.files.not_analyzed.some((e) => e.path === "supabase/config.toml" && e.reason === "ignored_unverified"));
  // A dump over the walk's 2 MB limit gets its real size band (lstat only).
  const big = repo({ "a.ts": "x\n" });
  const { truncateSync, closeSync, openSync } = await import("node:fs");
  closeSync(openSync(join(big, "prod.sql"), "w"));
  truncateSync(join(big, "prod.sql"), 150_000_000);
  d = (await build(big)).out.documents[0];
  assert.deepEqual(d.document.files.data_files, [{ path: "prod.sql", kind: "sql_dump", bytes_bucket: "over_100mb", tracked: "not_checked" }]);
  // The environment's source is setup (the schema allows only setup or answer) with value unknown.
  assert.deepEqual(d.document.environment, { value: "unknown", source: "setup" });
});

test("a supabase/config.toml not_analyzed entry is never forwarded as unsupported_language or unknown_type", async () => {
  for (const toml of ["[functions.f]\nverify_jwt = true\n", "[api]\n", "[api\n", "functions = 1\n", `# ${"x".repeat(1_100_000)}\n`]) {
    for (const where of ["supabase/config.toml", "apps/web/Supabase/config.toml"]) {
      const d = (await build(repo({ "a.ts": "x\n", [where]: toml }))).out.documents[0];
      assert.equal(d.problem, null, JSON.stringify(d.problem));
      const entries = d.document.files.not_analyzed.filter((e) => /(?:^|\/)supabase\/config\.toml$/i.test(e.path));
      assert.ok(entries.every((e) => e.reason !== "unsupported_language" && e.reason !== "unknown_type"), JSON.stringify(entries));
    }
  }
});

test("a secret in a file or folder name never leaves in clear: segments are hashed (review 2, q3)", async () => {
  const STRIPE = "sk\x5flive_51Habcdefghijklmnopqrstuv0123456789";
  const AWS = "A\x4bIAQWERTYUIOPASDFGHJ".slice(0, 20);
  const GH = `ghp_${"aB3dE5gH7jK9mN1pQ3sT5vX7zA9cE1gH3jK5"}`;
  const root = repo({
    "package.json": JSON.stringify({ dependencies: { next: "14" } }),
    [`keys/${STRIPE}.txt`]: "x\n",
    [`${AWS}/app/api/x/route.ts`]: 'export async function POST() { await db.from("patients").insert({}); }\n',
    [`.env.${GH}`]: "A=1\n",
    [`exports/${GH}.csv`]: "a,b\n",
    [`cfg/${STRIPE}.ts`]: 'const k = "sk\x5flive_51Hzyxwvutsrqponmlkjihgf9876543210";\n',
    "supabase/config.toml": `[functions.${GH}]\nverify_jwt = true\n`,
    "docs/AKIAIOSFODNN7EXAMPLE.md": "x\n",
  });
  const { out, key } = await build(root);
  const d = out.documents[0];
  assert.equal(d.problem, null, JSON.stringify(d.problem));
  const text = JSON.stringify(d.document);
  for (const s of [STRIPE, AWS, GH]) assert.ok(!text.includes(s), s);
  assert.ok(d.document.files.env_files.some((e) => e.path === hashed(key, `.env.${GH}`)));
  assert.ok(d.document.files.data_files.some((e) => e.path === `exports/${hashed(key, `${GH}.csv`)}`));
  assert.ok(d.document.secrets.some((s) => s.path === `cfg/${hashed(key, `${STRIPE}.ts`)}`));
  assert.ok(d.document.supabase.edge_functions.items.some((i) => i.name === hashed(key, GH)));
  assert.ok(!text.includes("AKIAIOSFODNN7EXAMPLE"), "the generic rule hashes even a documentation placeholder: over-hashing is safe");
  const { sentIdentifier } = await import("../lib/inspector/ids.mjs");
  assert.equal(sentIdentifier(key, STRIPE), hashed(key, STRIPE));
  assert.equal(sentIdentifier(key, "patients"), "patients");
});

test("a folder symlinked out of the root is a gap; one inside the root is not (merge review 2, q2)", async (t) => {
  if (process.platform === "win32") return t.skip("symlinks");
  const { symlinkSync } = await import("node:fs");
  const show = (doc) => [col(doc, "secrets").status, col(doc, "secrets").reason, doc.supabase.edge_functions.status, doc.supabase.edge_functions.reason];
  // supabase -> a folder outside the root: never not_configured, never a clean scan, and nothing outside is touched.
  const outside = repo({ "config.toml": "[functions.f]\nverify_jwt = false\n", "functions/f/index.ts": `const k = "${SECRET}";\n` });
  let root = repo({ "a.ts": "x\n" });
  symlinkSync(outside, join(root, "supabase"));
  let d = (await build(root)).out.documents[0];
  assert.equal(d.problem, null, JSON.stringify(d.problem));
  assert.deepEqual(show(d.document), ["truncated", "unreadable", "failed", "parse_failed"]);
  // src -> outside: the secret scan is truncated and edge functions can't be said absent.
  const out2 = repo({ "keys.ts": `const k = "${SECRET}";\n` });
  root = repo({ "a.ts": "x\n" });
  symlinkSync(out2, join(root, "src"));
  d = (await build(root)).out.documents[0];
  assert.deepEqual(show(d.document), ["truncated", "unreadable", "failed", "not_permitted"]);
  // A broken symlink is a gap too.
  root = repo({ "a.ts": "x\n" });
  symlinkSync(join(root, "missing"), join(root, "gone"));
  d = (await build(root)).out.documents[0];
  assert.equal(col(d.document, "secrets").status, "truncated");
  // alias -> a folder inside the root (walked at its own path): no gap.
  root = repo({ "real/k.ts": `const k = "${SECRET}";\n` });
  symlinkSync(join(root, "real"), join(root, "alias"));
  d = (await build(root)).out.documents[0];
  assert.deepEqual(show(d.document), ["ok", null, "not_run", "not_configured"]);
  assert.equal(d.document.secrets.length, 1);
});

test("holdsSecret: a key glued to _ or letters, escaped, re-punctuated or lowercased is still hashed; ordinary names stay", async () => {
  const { holdsSecret } = await import("../lib/inspector/ids.mjs");
  const STRIPE = "sk\x5flive_51Habcdefghijklmnopqrstuv0123456789";
  const GH = `ghp_${"aB3dE5gH7jK9mN1pQ3sT5vX7zA9cE1gH3jK5"}`;
  const AWS = "A\x4bIAQWERTYUIOPASDFGH";
  const secret = [`stripe_${STRIPE}.txt`, `${GH}_old.csv`, `.env.prod_${GH}`, `key_${STRIPE}_backup.ts`, `xx${GH}yy.txt`,
    `fn_${GH}`, `${STRIPE}_v2.ts`, `dump_${AWS}_2024.sql`, AWS.toLowerCase(), encodeURIComponent(`k=${STRIPE}`),
    "sb\x70_0123456789abcdef0123456789abcdef01234567", `sk-ant-api03-${"x".repeat(93)}AA`, `sk_ant_api03_${"x".repeat(40)}`,
    "xoxb_123456789012_1234567890123_abcdefghijklmnopqrstuvwx", "sb\x5fsecret_N7UND0UgjKTVK-Uodkm0Hg_xSvEMPvz",
    `my ${STRIPE} file.ts`, "glpat\x2dabcdefgh1jklmnopqrst", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0.patch"];
  for (const n of secret) assert.equal(holdsSecret(n), true, n);
  for (const n of ["patients_controller.ts", "2024_01_migration.sql", "route.ts", "README.md", "asia_region.ts", "ghost_mode.ts",
    "useAuth2.ts", "Dashboard.tsx", "node_modules", "20240101120000_create_patients.rb"]) assert.equal(holdsSecret(n), false, n);
  // End to end: nothing of the keys reaches the document.
  const root = repo({ "package.json": "{}", [`keys/stripe_${STRIPE}.txt`]: "x\n", [`exports/${GH}_old.csv`]: "a,b\n", [`.env.prod_${GH}`]: "A=1\n",
    [`supabase/functions/fn_${GH}/index.ts`]: "Deno.serve(() => new Response('x'));\n", [`src/${STRIPE}_v2.ts`]: "export const a = 1;\n" });
  const d = (await build(root)).out.documents[0];
  assert.equal(d.problem, null, JSON.stringify(d.problem));
  const text = JSON.stringify(d.document);
  assert.ok(!text.includes(STRIPE) && !text.includes(GH));
});

test("the platform config's provider reaches the catalog collector, so storage_buckets can run on Supabase", async () => {
  const seen = [];
  const root = repo({ "a.ts": "x\n" });
  await build(root, { collectPlatform: async () => ({ provider: "supabase", status: "not_run", reason: "no_token", settings: {} }),
    collectCatalog: async (queries, opts) => { seen.push(opts); return { status: "not_run", count: 0, reason: "service_missing", preflight: null, queries: [] }; } });
  assert.equal(seen.length, 1);
  assert.equal(seen[0].provider, "supabase");
  assert.ok(seen[0].deadline > Date.now() && seen[0].deadline <= Date.now() + 20_000, "the catalog gets the reads' share of the budget");
  seen.length = 0;
  await build(root, { collectCatalog: async (queries, opts) => { seen.push(opts); return { status: "not_run", count: 0, reason: "service_missing", preflight: null, queries: [] }; } });
  assert.deepEqual(seen.map((o) => o.provider), [null]);
});

test("v1 queries: the shipped text (shippedQuerySql) for every query id; storage_buckets' bigint file_size_limit maps to a number", async () => {
  const { shippedQuerySql, V1_QUERY_IDS } = await import("../lib/inspector/catalogfacts.mjs");
  const ruleset = loadRuleset();
  for (const id of [...V1_QUERY_IDS, "rls_policies"]) {
    assert.equal(ruleset.queries.find((q) => q.query_id === id)?.sql, shippedQuerySql(id), id);
  }
  assert.equal(QUERY_IDS.length, 20); // server_version dropped
  const bucket = (file_size_limit) => ({ bucket: "avatars", public: false, open_read_policies: [], owner_scoped_read: true, open_for_all: [],
    unconfirmed_read_policies: [], owner_by_app_setting: false, objects_rls_on: true, file_size_limit, allowed_mime_types_set: true });
  const run = async (rows) => (await build(repo({ "a.ts": "x\n" }), { collectCatalog: async () => ({ status: "ok", count: 0, reason: null, preflight: PREFLIGHT,
    queries: [ok("storage_buckets", rows)] }) })).out.documents[0];
  let d = await run([bucket("52428800"), { ...bucket(null), bucket: "public" }]);
  assert.equal(d.problem, null, JSON.stringify(d.problem));
  let q = d.document.catalog.queries.find((x) => x.query_id === "storage_buckets");
  assert.equal(q.status, "ok");
  assert.deepEqual(q.rows.map((r) => r.file_size_limit), [52428800, null]);
  d = await run([bucket("99999999999999999999")]);
  q = d.document.catalog.queries.find((x) => x.query_id === "storage_buckets");
  assert.deepEqual([q.status, q.reason, q.rows.length], ["truncated", "value_out_of_pattern", 0]);
});

test("holdsSecret: prefixes with a 16-character body, any separator; look-alike names stay clear", async () => {
  const { holdsSecret } = await import("../lib/inspector/ids.mjs");
  const HF = `hf_${"aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgH"}`;
  for (const n of [HF, `${HF}.txt`, `lin_api_${"aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkLmN"}`, "pypi-AgEIcHlwaS5vcmcCJGE0NjM2NjYz",
    "sk.live.51Habcdefgh.ijklmnopq.rstuv0123456789", `npm_${"a".repeat(36)}`, `whsec_${"Ab".repeat(16)}`, `shpat_${"0f".repeat(16)}`,
    `dop_v1_${"0f".repeat(32)}`, `SG.${"a".repeat(22)}.${"b".repeat(43)}`, `AIza${"B".repeat(35)}`, `ya29.${"c".repeat(40)}`,
    `xapp-1-${"A".repeat(11)}-123456-${"a".repeat(20)}`, `ghr_${"Q".repeat(36)}`, `sk-${"Z".repeat(48)}`]) {
    assert.equal(holdsSecret(n), true, n);
  }
  for (const n of ["keyJson.ts", "surveyJs.tsx", "HeyJude.md", "ASIAN_COUNTRIES.json", "EURASIA.ts", "AKIAMA.png", "risk\x5ftest_utils.ts",
    "work\x5ftest_helpers.py", "mark-test-data.sql", "task_proj_list.ts", "desk-test-fixture.ts", "risk-live-feed.ts", "oauth2callback.ts",
    "patients_controller.ts", "2024_01_migration.sql"]) {
    assert.equal(holdsSecret(n), false, n);
  }
  // End to end: an edge function folder, a file and a plan entity named with an hf_ token stay hashed.
  const root = repo({ "supabase/config.toml": 'project_id = "x"\n', [`supabase/functions/${HF}/index.ts`]: "Deno.serve(() => new Response('x'));\n", [`keys/${HF}.txt`]: "x\n" });
  const d = (await build(root)).out.documents[0];
  assert.equal(d.problem, null, JSON.stringify(d.problem));
  assert.ok(!JSON.stringify(d.document).includes(HF));
});

test("the parsed rule bundle is cached per process", () => {
  const first = loadRuleset();
  const t = performance.now();
  const again = loadRuleset();
  assert.equal(again, first);
  assert.ok(performance.now() - t < 200, "a second load reuses the parsed bundle");
});

test("holdsSecret: a wide-prefix body needs a digit or 24 letters and digits in a row", async () => {
  const { holdsSecret } = await import("../lib/inspector/ids.mjs");
  for (const n of ["sk-live-preview-component.tsx", "whsec_handler_for_stripe.ts", "sk\x5ftest_helpers_for_payments.ts", "rk\x5flive_dashboard_widgets.tsx"]) {
    assert.equal(holdsSecret(n), false, n);
  }
  for (const n of ["sk.live.51Habcdefgh.ijklmnopq.rstuv0123456789", `whsec_${"Ab".repeat(16)}`, `hf_${"aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgH"}`,
    "sb\x5fsecret_N7UND0UgjKTVK-Uodkm0Hg_xSvEMPvz"]) assert.equal(holdsSecret(n), true, n);
});

test("each key prefix has its known body: a letters-only glpat\x2d token is a secret, short look-alikes stay clear", async () => {
  const { holdsSecret } = await import("../lib/inspector/ids.mjs");
  const { randomInt } = await import("node:crypto");
  const pick = (n, cs) => Array.from({ length: n }, () => cs[randomInt(cs.length)]).join("");
  const LET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", AL = `${LET}0123456789`, URL = `${AL}-_`;
  const shapes = { "glpat\x2d": () => `glpat\x2d${pick(20, URL)}`, "glpat\x2d letters": () => `glpat\x2d${pick(20, LET)}`,
    "sk\x5flive_ letters 24": () => `sk\x5flive_${pick(24, LET)}`, "whsec_ 32": () => `whsec_${pick(32, AL)}`,
    "github_pat_": () => `github_pat_${pick(22, AL)}_${pick(59, AL)}`, "AIza": () => `AIza${pick(35, URL)}`,
    "SG.": () => `SG.${pick(22, URL)}.${pick(43, URL)}`, "sb\x5fsecret_": () => `sb\x5fsecret_${pick(31, URL)}` };
  for (const [name, make] of Object.entries(shapes)) for (let i = 0; i < 200; i++) { const t = make(); assert.equal(holdsSecret(t), true, `${name}: ${t}`); }
  for (const n of ["sk-live-preview-component.tsx", "whsec_handler_for_stripe.ts", "sk\x5ftest_helpers_for_payments.ts", "rk\x5flive_dashboard_widgets.tsx",
    `sk\x5flive_${"a".repeat(23)}`]) assert.equal(holdsSecret(n), false, n);
  // The secret scan now finds a GitLab token in file contents too.
  const { scanSecrets } = await import("../lib/inspector/secrets.mjs");
  const out = scanSecrets([{ path: "ci.yml", text: `token: "glpat\x2dxY9_-Qm4Rt7_Lp2-Wz8K"\n` }], { key: Buffer.alloc(32) });
  assert.deepEqual(out.secrets.map((s) => s.rule_id), ["gitlab-token"]);
});

test("an overridden ruleset id is applied per call, never cached for a later plain call", () => {
  const plain = loadRuleset();
  const over = loadRuleset({ rulesetId: "2026-01-01.deadbeef" });
  assert.equal(over.id, "2026-01-01.deadbeef");
  assert.equal(over.rules, plain.rules, "the parsed rules are shared");
  assert.equal(loadRuleset().id, plain.id);
  assert.equal(loadRuleset(), plain);
});

test("Slack prefixes need a digit in the body; re-punctuated tokens still hashed", async () => {
  const { holdsSecret } = await import("../lib/inspector/ids.mjs");
  for (const n of ["xapp-config-settings.json", "xoxb-bot-token-handler.ts", "xoxp-user-token-store.ts"]) assert.equal(holdsSecret(n), false, n);
  for (const n of ["xoxb.123456789012.1234567890123.abcdefghijklmnopqrstuvwx", "xoxb\x2d123456789012-1234567890123-abcdefghijklmnopqrstuvwx"]) {
    assert.equal(holdsSecret(n), true, n);
  }
});

test("Slack prefixes: 24 or more body characters are a secret whatever they hold (final round)", async () => {
  const { holdsSecret } = await import("../lib/inspector/ids.mjs");
  for (const p of ["xoxa-", "xoxb-", "xoxp-", "xoxr-", "xoxs-", "xapp-"]) assert.equal(holdsSecret(`${p}${"abcdefgh".repeat(3)}`), true, p);
  for (const n of ["xapp-config-settings.json", "xoxb-bot-token-handler.ts"]) assert.equal(holdsSecret(n), false, n);
});

test("past the check's time budget the rules and the secret scan stop, truncated timeout, files listed time_limit", async () => {
  const root = repo(BASE);
  const { out } = await build(root, { timeBudgetMs: 0 });
  const d = out.documents[0];
  assert.equal(d.problem, null, JSON.stringify(d.problem));
  assert.deepEqual([col(d.document, "rules").status, col(d.document, "rules").reason], ["truncated", "timeout"]);
  assert.deepEqual([col(d.document, "secrets").status, col(d.document, "secrets").reason], ["truncated", "timeout"]);
  assert.equal(d.document.files.analyzed, 0);
  assert.ok(d.document.files.not_analyzed.some((e) => e.reason === "time_limit"));
  assert.deepEqual(d.document.secrets, []);
});

test("a document past 5,000,000 bytes keeps what fits: violations first, lost files match_limit, rules size_limit", async () => {
  const { fitToSize } = await import("../lib/inspector/factdoc.mjs");
  const root = repo(BASE);
  const { out } = await build(root);
  const doc = out.documents[0].document;
  const fp = (i) => createHmac("sha256", "k").update(String(i)).digest("hex");
  const match = (path, i, kind) => ({ rule_id: "phi-in-logs.javascript-generic.console-phi", practice_id: "phi-in-logs", kind, path,
    line_start: i + 1, line_end: i + 1, fingerprint: fp(`${path}${i}`), has_control: kind === "item" ? true : null, table: null, handler: fp(path),
    shared_fingerprint: fp(`s${path}${i}`) });
  const big = structuredClone(doc);
  big.matches = [];
  for (let f = 0; f < 30; f++) for (let i = 0; i < 600; i++) big.matches.push(match(`src/f${f}.js`, i, f < 2 ? "violation" : "evidence"));
  big.files.analyzed = 30;
  assert.ok(Buffer.byteLength(JSON.stringify(big)) > 5_000_000);
  fitToSize(big, { rules: [], rulesNotAnalyzed: new Set() });
  assert.equal(checkDocument(big), null);
  assert.ok(Buffer.byteLength(JSON.stringify(big)) <= 5_000_000);
  assert.ok(big.matches.length > 10_000 && big.matches.length < 18_000, String(big.matches.length));
  assert.equal(big.matches.filter((m) => m.kind === "violation").length, 1200); // observed against the code first
  const rules = big.collection.find((c) => c.collector === "rules");
  assert.deepEqual([rules.status, rules.reason], ["truncated", "size_limit"]);
  const kept = new Map();
  for (const m of big.matches) kept.set(m.path, (kept.get(m.path) ?? 0) + 1);
  const lost = [];
  for (let f = 0; f < 30; f++) if ((kept.get(`src/f${f}.js`) ?? 0) < 600) lost.push(`src/f${f}.js`);
  assert.ok(lost.length > 0);
  for (const p of lost) assert.ok(big.files.not_analyzed.some((e) => e.path === p && e.reason === "match_limit"), p);
  assert.equal(big.files.analyzed, 30 - lost.length);
  // A document that fits is left as it is.
  const small = structuredClone(doc);
  assert.deepEqual(fitToSize(small), doc);
});

// screenAndFit can fit twice. A file the first fit cut (listed match_limit) that loses more matches
// in the second is counted out of files.analyzed once, not twice.
test("a file cut by the first fit and again by the second is taken from files.analyzed once", async () => {
  const { fitToSize } = await import("../lib/inspector/factdoc.mjs");
  const root = repo(BASE);
  const { out } = await build(root);
  const doc = out.documents[0].document;
  const fp = (i) => createHmac("sha256", "k").update(String(i)).digest("hex");
  const match = (path, i) => ({ rule_id: "phi-in-logs.javascript-generic.console-phi", practice_id: "phi-in-logs", kind: "evidence", path,
    line_start: i + 1, line_end: i + 1, fingerprint: fp(`${path}${i}`), has_control: null, table: null, handler: fp(path),
    shared_fingerprint: fp(`s${path}${i}`) });
  const big = structuredClone(doc);
  big.matches = [];
  for (let f = 0; f < 30; f++) for (let i = 0; i < 600; i++) big.matches.push(match(`src/f${f}.js`, i));
  big.files.analyzed = 30;
  const fit = { rules: [], rulesNotAnalyzed: new Set() };
  fitToSize(big, { ...fit, limit: 4_000_000 });
  const once = big.files.analyzed;
  const cut = new Set(big.files.not_analyzed.filter((e) => e.reason === "match_limit").map((e) => e.path));
  assert.ok(cut.size > 0 && once === 30 - cut.size, `${once} analysed, ${cut.size} cut`);
  fitToSize(big, { ...fit, limit: 3_990_000 });
  const twice = new Set(big.files.not_analyzed.filter((e) => e.reason === "match_limit").map((e) => e.path));
  assert.ok(twice.size >= cut.size);
  assert.equal(big.files.analyzed, 30 - twice.size);
});

// a file the secret scan already listed (time_limit) gets no match_limit entry from a fit, so the
// match_limit entry can't say it was counted down. Each fit that cut it took it from files.analyzed again.
test("a file another collector listed, cut by both fits, is taken from files.analyzed once", async () => {
  const { fitToSize } = await import("../lib/inspector/factdoc.mjs");
  const root = repo(BASE);
  const { out } = await build(root);
  const doc = out.documents[0].document;
  const fp = (i) => createHmac("sha256", "k").update(String(i)).digest("hex");
  const match = (path, i) => ({ rule_id: "phi-in-logs.javascript-generic.console-phi", practice_id: "phi-in-logs", kind: "evidence", path,
    line_start: i + 1, line_end: i + 1, fingerprint: fp(`${path}${i}`), has_control: null, table: null, handler: fp(path),
    shared_fingerprint: fp(`s${path}${i}`) });
  const big = structuredClone(doc);
  big.matches = [];
  for (const f of ["a.js", "b.js", "z.js"]) for (let i = 0; i < 300; i++) big.matches.push(match(f, i));
  big.files.analyzed = 3;
  big.files.not_analyzed = [{ path: "z.js", kind: "file", reason: "time_limit", tracked: null }];
  const size = Buffer.byteLength(JSON.stringify(big));
  const whole = (p) => big.matches.filter((m) => m.path === p).length === 300;
  for (const share of [0.85, 0.75]) {
    fitToSize(big, { rules: [], rulesNotAnalyzed: new Set(), limit: Math.floor(size * share) });
    assert.ok(whole("a.js") && whole("b.js") && !whole("z.js"), `at ${share}: only z.js loses matches`);
    assert.deepEqual(big.files.not_analyzed.map((e) => [e.path, e.reason]), [["z.js", "time_limit"]]);
    assert.equal(big.files.analyzed, 2, `at ${share}`);
  }
});

// the screen runs after the fit and can lengthen what it hashes (an id shaped like 123-45-6789 becomes a
// u_ hash), so a fitted document could pass 5,000,000 bytes again and be refused locally. screenAndFit screens, then
// fits again.
test("a document the screen lengthens past 5,000,000 bytes is fitted again", async () => {
  const factdoc = await import("../lib/inspector/factdoc.mjs");
  const { fitToSize, screenDocument } = factdoc;
  const key = Buffer.from("0123456789abcdef0123456789abcdef");
  const root = repo(BASE);
  const { out } = await build(root);
  const doc = out.documents[0].document;
  const fp = (i) => createHmac("sha256", "k").update(String(i)).digest("hex");
  const match = (path, i) => ({ rule_id: "phi-in-logs.javascript-generic.console-phi", practice_id: "phi-in-logs", kind: "evidence", path,
    line_start: i + 1, line_end: i + 1, fingerprint: fp(`${path}${i}`), has_control: null, table: null, handler: fp(path),
    shared_fingerprint: fp(`s${path}${i}`) });
  const big = structuredClone(doc);
  big.matches = [];
  for (let f = 0; f < 30; f++) for (let i = 0; i < 600; i++) big.matches.push(match(`src/123-45-${String(6000 + f)}/f.js`, i));
  big.files.analyzed = 30;
  const before = structuredClone(big);
  fitToSize(before, { rules: [], rulesNotAnalyzed: new Set() });
  screenDocument(before, key);
  assert.ok(Buffer.byteLength(JSON.stringify(before)) > 5_000_000, "fit, then screen, passes the limit");
  factdoc.screenAndFit(big, key, { rules: [], rulesNotAnalyzed: new Set() });
  assert.ok(Buffer.byteLength(JSON.stringify(big)) <= 5_000_000);
  assert.ok(big.matches.every((m) => !m.path.includes("123-45-")));
  assert.equal(checkDocument(big), null);
});

// the build fits, then screens and fits again. A path the screen hashes (123-45-6789 shaped) and the
// first fit already counted out of files.analyzed is counted once, not again under its hashed name. This did not go
// red (the item was dropped); it stays as a pin.
test("a file the first fit cut and the screen renamed is taken from files.analyzed once", async () => {
  const factdoc = await import("../lib/inspector/factdoc.mjs");
  const key = Buffer.from("0123456789abcdef0123456789abcdef");
  const root = repo(BASE);
  const { out } = await build(root);
  const doc = out.documents[0].document;
  const fp = (i) => createHmac("sha256", "k").update(String(i)).digest("hex");
  const match = (path, i) => ({ rule_id: "phi-in-logs.javascript-generic.console-phi", practice_id: "phi-in-logs", kind: "evidence", path,
    line_start: i + 1, line_end: i + 1, fingerprint: fp(`${path}${i}`), has_control: null, table: null, handler: fp(path),
    shared_fingerprint: fp(`s${path}${i}`) });
  const big = structuredClone(doc);
  big.matches = [];
  big.files.not_analyzed = [];
  for (let f = 0; f < 30; f++) for (let i = 0; i < 600; i++) big.matches.push(match(`src/123-45-${String(6000 + f)}/f.js`, i));
  big.files.analyzed = 30;
  const fit = { rules: [], rulesNotAnalyzed: new Set() };
  factdoc.fitToSize(big, fit);
  factdoc.screenAndFit(big, key, fit);
  const cut = new Set(big.files.not_analyzed.filter((e) => e.reason === "match_limit").map((e) => e.path));
  assert.ok(cut.size > 0);
  assert.ok([...cut].every((p) => !p.includes("123-45-")));
  assert.equal(big.files.analyzed, 30 - cut.size);
});

test("the whole build, rule loading included, ends by the hard deadline (soft budget plus 10 s)", async () => {
  const root = repo(BASE);
  const t0 = Date.now();
  const { out } = await build(root, { timeBudgetMs: 300, ruleset: undefined, bundleDir: undefined, rulesetId: RULESET_ID });
  assert.ok(Date.now() - t0 < 10_300, `took ${Date.now() - t0} ms`);
  assert.equal(out.documents[0].problem, null);
});

/* A rule bundle of its own (a fresh cache entry): the fixture rules, or a copy of the package's bundle. */
function bundle(from = null) {
  const dir = temp("a7-bundle-");
  if (from) cpSync(from, dir, { recursive: true });
  else {
    cpSync(fileURLToPath(new URL("./fixtures/rules/", import.meta.url)), join(dir, "rules"), { recursive: true });
    writeFileSync(join(dir, "manifest.json"), JSON.stringify({ ruleset_id: RULESET_ID }));
  }
  return dir;
}

test("rules parsed in a thread give the same document as rules parsed on the calling thread", async () => {
  const root = repo(BASE);
  const configDir = temp("a7-cfg-");
  const common = { configDir, collectCatalog: quietCatalog, collectPlatform: quietPlatform };
  const dir = bundle();
  const threaded = await buildFactDocuments([root], { ...common, bundleDir: dir });
  const here = await buildFactDocuments([root], { ...common, ruleset: { id: RULESET_ID, rules: RULES, queries: loadRuleset({ bundleDir: dir }).queries } });
  assert.equal(threaded.documents[0].problem, null);
  assert.deepEqual(threaded.documents[0].document, here.documents[0].document);
  assert.deepEqual(threaded.notes, []);
  // The parsed rules are cached: a later start hands out the same array at once.
  const again = startRuleset({ bundleDir: dir });
  assert.equal(again.ready(), true);
  assert.equal(await again.rules, loadRuleset({ bundleDir: dir }).rules);
});

test("the budget spent while the rule bundle is still parsing: rules truncated timeout, every file time_limit, a local note", async () => {
  const root = repo(BASE);
  const dir = bundle(DEFAULT_BUNDLE_DIR); // the package's bundle, copied: seconds to parse, not cached yet
  const out = await buildFactDocuments([root], { configDir: temp("a7-cfg-"), collectCatalog: quietCatalog, collectPlatform: quietPlatform,
    bundleDir: dir, timeBudgetMs: 0 });
  const d = out.documents[0];
  assert.equal(d.problem, null, JSON.stringify(d.problem));
  assert.deepEqual([col(d.document, "rules").status, col(d.document, "rules").reason], ["truncated", "timeout"]);
  assert.equal(d.document.files.analyzed, 0);
  assert.deepEqual(d.document.matches, []);
  // Every walked file is listed (none dropped): the code files as time_limit.
  for (const p of ["app/api/visits/route.ts", "config/keys.ts"]) assert.ok(d.document.files.not_analyzed.some((e) => e.path === p && e.reason === "time_limit"), p);
  assert.equal(out.notes.length, 1);
  assert.match(out.notes[0], /parsing the rule bundle took the first \d+ s/);
  assert.ok(out.notes[0].startsWith(SETUP_TIMEOUT_NOTE.slice(0, 40)));
});

test("a bundle that changed while its rules were read is never paired with the manifest's id: rules failed, reloaded next time", async () => {
  const root = repo(BASE);
  const dir = bundle(DEFAULT_BUNDLE_DIR);
  // A rule file that no longer matches the manifest's sha256 (a sync landing mid-load looks the same).
  const { readdirSync } = await import("node:fs");
  const practice = readdirSync(join(dir, "rules")).find((n) => !n.endsWith(".md"));
  const yml = readdirSync(join(dir, "rules", practice)).find((n) => n.endsWith(".yml"));
  writeFileSync(join(dir, "rules", practice, yml), `${readFileSync(join(dir, "rules", practice, yml), "utf8")}# changed\n`);
  // The load parses the whole bundle before it can tell. Under a loaded full suite that has passed the 45 s collect
  // budget (rules truncated, timeout, which says nothing about the swap), so this build gets the loader's own limit.
  const out = await buildFactDocuments([root], { configDir: temp("a7-cfg-"), collectCatalog: quietCatalog, collectPlatform: quietPlatform, bundleDir: dir,
    timeBudgetMs: LOADER_TIMEOUT_MS });
  const d = out.documents[0];
  assert.equal(d.problem, null, JSON.stringify(d.problem));
  assert.deepEqual([col(d.document, "rules").status, col(d.document, "rules").reason], ["failed", "internal_error"]);
  assert.deepEqual(d.document.matches, []);
  assert.deepEqual(out.notes, [STALE_BUNDLE_NOTE], "said locally, with how to fix it");
  // The same through a synchronous load handed in (options.ruleset).
  const sync = loadRuleset({ bundleDir: dir });
  const viaSync = await buildFactDocuments([root], { configDir: temp("a7-cfg-"), collectCatalog: quietCatalog, collectPlatform: quietPlatform, ruleset: sync });
  assert.deepEqual([col(viaSync.documents[0].document, "rules").status, viaSync.notes], ["failed", [STALE_BUNDLE_NOTE]]);
  assert.equal(startRuleset({ bundleDir: dir }).ready(), false, "nothing cached for that manifest: the next call loads again");
  assert.equal(loadRuleset({ bundleDir: dir }).rules, null, "the synchronous load refuses it too");
});

test("a loading thread that doesn't answer in time is terminated, and the next start loads again", async () => {
  const dir = bundle(DEFAULT_BUNDLE_DIR);
  const first = startRuleset({ bundleDir: dir, loaderTimeoutMs: 1 });
  assert.equal(typeof (await first.rules), "symbol", "given up");
  assert.equal(first.ready(), false);
  const again = startRuleset({ bundleDir: dir });
  const rules = await again.rules;
  assert.ok(Array.isArray(rules) && rules.length > 100);
  assert.equal(again.ready(), true);
});

test("a bundle holding fixtures and docs beside its rules (a hosted knowledge checkout) loads, with the same document", async () => {
  const root = repo(BASE);
  const clean = bundle(DEFAULT_BUNDLE_DIR);
  const extras = bundle(DEFAULT_BUNDLE_DIR);
  const { readdirSync } = await import("node:fs");
  writeFileSync(join(extras, "rules", "README.md"), "# rules\n");
  writeFileSync(join(extras, "rules", "NAMING.md"), "# naming\n");
  for (const practice of readdirSync(join(extras, "rules")).filter((n) => !n.endsWith(".md"))) {
    for (const yml of readdirSync(join(extras, "rules", practice)).filter((n) => n.endsWith("-generic.yml") && n.startsWith("typescript"))) {
      writeFileSync(join(extras, "rules", practice, yml.replace(/\.yml$/, ".fixtures.ts")), "// ok: none\nexport const x = 1;\n");
    }
  }
  const configDir = temp("a7-cfg-");
  // Each build parses the whole bundle (about 6 s idle, 40 s under a loaded full suite), which can pass the 45 s
  // collect budget (rules truncated, timeout, no matches) and says nothing about the extras, so these builds get the
  // loader's own limit, as in the stale-bundle test above. The budget path is covered by the timeBudgetMs: 0 tests.
  const common = { configDir, collectCatalog: quietCatalog, collectPlatform: quietPlatform, timeBudgetMs: LOADER_TIMEOUT_MS };
  const a = (await buildFactDocuments([root], { ...common, bundleDir: clean })).documents[0];
  const built = await buildFactDocuments([root], { ...common, bundleDir: extras });
  assert.ok(!built.notes.includes(STALE_BUNDLE_NOTE), "a bundle that matches its manifest says nothing of the kind");
  const b = built.documents[0];
  assert.equal(b.problem, null, JSON.stringify(b.problem));
  assert.notEqual(col(b.document, "rules").status, "failed");
  assert.ok(b.document.matches.length > 0);
  assert.deepEqual(b.document, a.document);
});

test("secrets are sent once each, in path, line, rule and fingerprint order, whatever order the scan gives", async () => {
  const root = repo(BASE);
  const fp = (c) => c.repeat(64);
  const s = (path, line, rule_id, c, in_history = false) => ({ path, line, rule_id, fingerprint: fp(c), in_history });
  const found = [
    s("src/app.ts", 9, "aws", "2"), s("config/keys.ts", 3, "stripe", "1"), s("src/app.ts", 2, "github", "9"),
    s("src/app.ts", 9, "aws", "1"), s("src/app.ts", 9, "aws", "1", true), s("config/keys.ts", 3, "aws", "7"),
    s("config/keys.ts", 3, "stripe", "1"), s("src/app.ts", 10, "aws", "0"),
  ];
  const scan = () => ({ secrets: found, truncated: [] });
  const { out } = await build(root, { scanSecrets: scan });
  const [{ document: doc, problem }] = out.documents;
  assert.equal(problem, null, JSON.stringify(problem));
  assert.deepEqual(doc.secrets.map((x) => [x.path, x.line, x.rule_id, x.fingerprint, x.in_history]), [
    ["config/keys.ts", 3, "secrets.aws", fp("7"), "not_checked"],
    ["config/keys.ts", 3, "secrets.stripe", fp("1"), "not_checked"],
    ["src/app.ts", 2, "secrets.github", fp("9"), "not_checked"],
    ["src/app.ts", 9, "secrets.aws", fp("1"), "not_checked"],
    ["src/app.ts", 9, "secrets.aws", fp("2"), "not_checked"],
    ["src/app.ts", 10, "secrets.aws", fp("0"), "not_checked"],
  ]);
});

// T29 line item h, h2 (T29-P3-C85, C87): the assistant's fact records reach the primary root's document as
// cited_facts, each citation checked against the walk; none sent leaves the section out.
test("cited facts reach the document checked, and a document without them has no cited_facts", async () => {
  const root = temp("h2-facts-");
  mkdirSync(join(root, "app"));
  writeFileSync(join(root, "app", "route.ts"), "export async function GET(req) {\n  const session = await auth();\n  return null;\n}\n");
  const facts = [{ rule: "authz", candidate: "app/route.ts:1",
    handler: { value: "declared", file: "app/route.ts", line: 1, token: "export async function GET" },
    guard: { value: "signed_in", file: "app/route.ts", line: 2, token: "await auth()" },
    record_id_source: { value: "path_param", file: "app/route.ts", line: 1, token: "nowhere on this line" } }];
  const withFacts = await build(root, { facts });
  const doc = withFacts.out.documents[0].document;
  assert.equal(withFacts.out.documents[0].problem, null, JSON.stringify(withFacts.out.documents[0].problem));
  assert.equal(checkDocument(doc), null);
  const byField = Object.fromEntries(doc.cited_facts.map((r) => [r.field, r]));
  assert.deepEqual([byField.guard.cite, byField.guard.cited_at], ["ok", "app/route.ts:2"]);
  assert.deepEqual([byField.record_id_source.cite, byField.record_id_source.cited_at], ["failed", null]);
  assert.deepEqual([byField.owner_value_source.value, byField.owner_value_source.cite], ["unknown", "none"]);
  assert.ok(!JSON.stringify(doc.cited_facts).includes("await auth()"), "the token never leaves the machine");
  const without = await build(root);
  assert.ok(!("cited_facts" in without.out.documents[0].document));
});

// T29-P1-C73 point 1: past cited_facts' 1 MB share, whole candidates are dropped in record order, and a local note
// gives the count, no names, so a hold reads as too many facts, not as the assistant's miss. The matches are untouched.
test("facts past their 1 MB share drop whole candidates, with a count in the local notes", async () => {
  const root = temp("h2-facts-cap-");
  mkdirSync(join(root, "app"));
  writeFileSync(join(root, "app", "route.ts"), "export async function GET(req) {\n".repeat(2400));
  const facts = Array.from({ length: 2400 }, (_, i) => ({ rule: "authz", candidate: `app/route.ts:${i + 1}`,
    handler: { value: "declared", file: "app/route.ts", line: i + 1, token: "export async function GET" } }));
  const { out } = await build(root, { facts });
  const doc = out.documents[0].document;
  assert.equal(out.documents[0].problem, null, JSON.stringify(out.documents[0].problem));
  const rows = doc.cited_facts;
  assert.ok(Buffer.byteLength(JSON.stringify(rows), "utf8") <= 1_000_000);
  const kept = [...new Set(rows.map((r) => r.candidate))];
  assert.ok(kept.length > 0 && kept.length < 2400);
  assert.deepEqual(kept, facts.slice(0, kept.length).map((f) => f.candidate), "kept in record order, from the first");
  assert.equal(rows.length, kept.length * 4, "every kept candidate has all its rows");
  const note = (out.notes ?? []).find((n) => /fact/.test(n) && n.includes(String(2400 - kept.length)));
  assert.ok(note, JSON.stringify(out.notes));
  assert.ok(!note.includes("route.ts"), "the note names no candidate");
});

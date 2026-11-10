/* T29 o2, the proof runner (T29-P1-C99). A fix call's kept proofs (get_result part proof) are run by this CLI on verify,
 * only against the phisc database the person marked development at setup, inside a read-only transaction that is
 * rolled back, and verify's request carries `proof_results`: one {object_id, proof_id, result} per kept proof, result
 * pass, fail or unread. A proof that can't run is unread, never pass. Red case 3 of C99: a production-marked database
 * (or one marked staging, or not marked) never runs proofs.
 *
 * The tool cases use a stub evaluator and a stubbed runner. The runner cases use a throwaway cluster made with initdb
 * (TCP on 127.0.0.1 only, a free port, no socket), skipped with the reason when initdb is missing. */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";
import { makeRunCheck, PROOF_NOTES } from "../lib/inspector/tool.mjs";
import { proofBlocks, runProofs } from "../lib/inspector/catalog.mjs";
import { writeToken } from "../lib/inspector/auth.mjs";
import { loadRules } from "../lib/inspector/rules.mjs";
import { EVALUATE_OK, stub } from "./stub-evaluator.mjs";

const RULESET = { id: "2026-10-20.0123abcd", rules: loadRules(fileURLToPath(new URL("./fixtures/rules/", import.meta.url))), queries: [] };
const TOKEN = `phisc_${"t".repeat(43)}`;
const temp = (prefix) => realpathSync(mkdtempSync(join(tmpdir(), prefix)));
const cleanups = [];
after(() => { for (const fn of cleanups.reverse()) { try { fn(); } catch { /* best effort */ } } });

/* A proof as core builds one (check_fixes._pinned around _assert or _each blocks), and its id (result_store.proof_id). */
const PIN = "SET search_path = pg_catalog, pg_temp;\n";
const UNPIN = "\nRESET search_path;";
const block = (condition, message = "the proof failed") =>
  `DO $custosa$\nBEGIN\n  IF NOT (${condition}) THEN\n    RAISE EXCEPTION '${message}';\n  END IF;\nEND\n$custosa$;`;
const proofSql = (...blocks) => PIN + blocks.join("\n") + UNPIN;
const idOf = (sql) => createHash("sha256").update(sql, "utf8").digest("hex").slice(0, 16);
const proof = (object_id, sql) => ({ object_id, proof_id: idOf(sql), test_sql: sql });

/* ---------- the tool: reading the proofs, the environment rule, the request ---------- */

const quiet = {
  ruleset: RULESET,
  collectCatalog: async () => ({ status: "not_run", count: 0, reason: "service_missing", preflight: null, queries: [] }),
  collectPlatform: async () => ({ provider: null, status: "not_run", reason: "no_token", settings: {} }),
};
function repo() {
  const root = temp("proofs-");
  mkdirSync(join(root, "src"), { recursive: true });
  writeFileSync(join(root, "src/db.ts"), 'export async function save(p) { await db.from("patients").insert(p); }\n');
  return root;
}
const RLS_SQL = proofSql(block("true"));
const FORCE_SQL = proofSql(block("true"), block("1 = 1"));
const FINDINGS = [
  { finding: "rls-off@public.patients", practice_id: "rls-off", object: "public.patients", kind: "migration", sql: RLS_SQL },
  { finding: "rls-not-forced@public.patients", practice_id: "rls-not-forced", object: "public.patients", kind: "migration", sql: FORCE_SQL },
];
const INDEX = (fixes = []) => ({ result_counts: { by_state: { pass: 0, fail: 2, not_applicable: 0, needs_review: 0, unknown: 0, error: 0 },
  by_severity: {}, by_state_and_severity: [] }, practices: [], fails: [], open: [], questions: [], concerns: [], fixes, lists: [] });
const proofRead = (body) => {
  const hits = FINDINGS.filter((f) => f.practice_id === body.select.practice);
  return { goal: body.goal, session: body.session, select: body.select, part: body.part ?? "detail", matched: hits.length,
    results: hits.map((f) => ({ finding: f.finding, practice_id: f.practice_id, object: f.object, state: "fail", severity: "high",
      proof: { test_sql: f.sql, proof_id: idOf(f.sql) } })), is_fetch_only: true, charged_units: 0, correlation_id: "corr_12345678" };
};
function handler(call) {
  if (call.body.select) return { status: 200, json: proofRead(call.body) };
  const fixes = call.body.goal === "fix" ? FINDINGS.map(({ finding, practice_id, object, kind }) => ({ finding, practice_id, object, kind })) : [];
  return { status: 200, json: { ...EVALUATE_OK, index: INDEX(fixes) } };
}
async function setup({ mark = "development", run = null } = {}) {
  const configDir = join(temp("proofs-cfg-"), "custosa");
  const s = await stub(handler);
  writeToken(TOKEN, { configDir, host: new URL(s.url).origin });
  const ran = [];
  const runCheck = makeRunCheck({ configDir, localOnly: false, buildOptions: quiet,
    environmentFor: () => ({ environment: { value: mark, source: "setup" }, note: null }),
    runProofs: async (proofs, opts) => { ran.push({ proofs, opts }); return run ? run(proofs) : proofs.map((p) => ({ object_id: p.object_id, proof_id: p.proof_id, result: "pass" })); },
    evaluatorUrl: () => ({ url: s.url, origin: new URL(s.url).origin }), clientOptions: { sleep: async () => {} } });
  return { s, runCheck, ran };
}
const session = EVALUATE_OK.session;
const ids = FINDINGS.map((f) => f.finding);
const verifyBody = (s) => s.calls.filter((c) => c.body.goal === "verify" && !c.body.select).at(-1).body;

test("a fix call reads its kept proofs through get_result (part proof, per practice), and verify sends a result for each", async () => {
  const root = repo();
  const { s, runCheck, ran } = await setup();
  try {
    await runCheck({ goal: "fix", session, finding_ids: ids }, { roots: [root] });
    const reads = s.calls.filter((c) => c.body.select).map((c) => c.body);
    assert.deepEqual(reads, [
      { goal: "fix", session, select: { practice: "rls-not-forced" }, part: "proof" },
      { goal: "fix", session, select: { practice: "rls-off" }, part: "proof" },
    ]);
    await runCheck({ goal: "verify", session }, { roots: [root] });
    assert.equal(ran.length, 1);
    assert.deepEqual(ran[0].proofs.map((p) => p.object_id).sort(), [...ids].sort());
    assert.deepEqual(verifyBody(s).proof_results, [
      { object_id: "rls-not-forced@public.patients", proof_id: idOf(FORCE_SQL), result: "pass" },
      { object_id: "rls-off@public.patients", proof_id: idOf(RLS_SQL), result: "pass" },
    ]);
  } finally { await s.close(); }
});

test("C99 red case 3: a production-marked database never runs proofs; every kept proof goes as unread, with a note", async () => {
  for (const mark of ["production", "staging", "unknown"]) {
    const root = repo();
    const { s, runCheck, ran } = await setup({ mark });
    try {
      await runCheck({ goal: "fix", session, finding_ids: ids }, { roots: [root] });
      const out = await runCheck({ goal: "verify", session }, { roots: [root] });
      assert.equal(ran.length, 0, mark);
      assert.deepEqual(verifyBody(s).proof_results.map((r) => r.result), ["unread", "unread"], mark);
      assert.ok(out.local_notes.includes(PROOF_NOTES.not_development.replace("{mark}", mark)), mark);
    } finally { await s.close(); }
  }
});

test("a runner answer other than pass, fail or unread, or one for another proof, is sent as unread", async () => {
  const root = repo();
  const { s, runCheck } = await setup({ run: (proofs) => [{ object_id: proofs[0].object_id, proof_id: proofs[0].proof_id, result: "ok" },
    { object_id: proofs[1].object_id, proof_id: "0".repeat(16), result: "pass" }] });
  try {
    await runCheck({ goal: "fix", session, finding_ids: ids }, { roots: [root] });
    await runCheck({ goal: "verify", session }, { roots: [root] });
    assert.deepEqual(verifyBody(s).proof_results.map((r) => r.result), ["unread", "unread"]);
  } finally { await s.close(); }
});

test("with no fix call in this process for the session, verify sends no proof_results and runs nothing", async () => {
  const root = repo();
  const { s, runCheck, ran } = await setup();
  try {
    await runCheck({ goal: "verify", session }, { roots: [root] });
    assert.equal(ran.length, 0);
    assert.equal(verifyBody(s).proof_results, undefined);
    // a check reads no proofs and sends none
    await runCheck({ goal: "check", session }, { roots: [root] });
    assert.ok(!s.calls.some((c) => c.body.part === "proof"));
    assert.ok(s.calls.every((c) => c.body.proof_results === undefined || c.body.goal === "verify"));
  } finally { await s.close(); }
});

/* ---------- the runner: against a throwaway cluster ---------- */

async function freePort() {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.unref();
    srv.on("error", reject);
    srv.listen(0, "127.0.0.1", () => { const { port } = srv.address(); srv.close(() => resolve(port)); });
  });
}
const secret = () => randomBytes(18).toString("base64url");
async function startCluster() {
  const env = { ...process.env, LC_ALL: "C", LANG: "C" };
  const oneLine = (t) => String(t || "").replace(/\s+/g, " ").trim().slice(-300);
  const probe = spawnSync("initdb", ["--version"], { encoding: "utf8", env });
  if (probe.error || probe.status !== 0) return { skip: "initdb is not on PATH, so no throwaway Postgres cluster can be made" };
  const dir = temp("custosa-pgproof-");
  const data = join(dir, "data");
  const adminPw = secret();
  writeFileSync(join(dir, "pw"), adminPw + "\n", { mode: 0o600 });
  const init = spawnSync("initdb", ["-D", data, "-U", "postgres", "-A", "scram-sha-256", `--pwfile=${join(dir, "pw")}`,
    "-E", "UTF8", "--no-locale", "--no-sync"], { encoding: "utf8", env });
  rmSync(join(dir, "pw"), { force: true });
  if (init.status !== 0) { rmSync(dir, { recursive: true, force: true }); return { skip: `initdb failed: ${oneLine(init.stderr)}` }; }
  const port = await freePort();
  const start = spawnSync("pg_ctl", ["-D", data, "-l", join(dir, "log"), "-w", "-t", "30", "-o",
    `-p ${port} -c listen_addresses=127.0.0.1 -c unix_socket_directories='' -c fsync=off`, "start"], { encoding: "utf8", env });
  if (start.status !== 0) {
    let log = ""; try { log = oneLine(readFileSync(join(dir, "log"), "utf8")); } catch { /* none */ }
    rmSync(dir, { recursive: true, force: true });
    return { skip: `pg_ctl could not start a temporary cluster: ${log || oneLine(start.stderr)}` };
  }
  cleanups.push(() => { spawnSync("pg_ctl", ["-D", data, "-m", "immediate", "-w", "stop"], { env }); rmSync(dir, { recursive: true, force: true }); });
  const roPw = secret();
  const admin = new pg.Client({ host: "127.0.0.1", port, user: "postgres", database: "postgres", password: () => adminPw, ssl: false });
  await admin.connect();
  await admin.query(`
    CREATE SCHEMA app;
    CREATE TABLE app.patients (id int PRIMARY KEY, name text);
    INSERT INTO app.patients VALUES (1, 'not for the inspector');
    ALTER TABLE app.patients ENABLE ROW LEVEL SECURITY;
    CREATE ROLE phisc_ro LOGIN PASSWORD '${roPw}' NOSUPERUSER NOCREATEDB NOCREATEROLE;
  `);
  const ro = { host: "127.0.0.1", port, dbname: "postgres", user: "phisc_ro", sslmode: "prefer", sslrootcert: null };
  Object.defineProperty(ro, "password", { value: roPw, enumerable: false });
  return { admin, ro };
}
const cluster = await startCluster();
const skip = cluster.skip || false;
after(async () => { if (cluster.admin) await cluster.admin.end().catch(() => {}); });

const RLS_ON = "EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'app' AND c.relname = 'patients' AND c.relrowsecurity)";
const RLS_FORCED = "EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'app' AND c.relname = 'patients' AND c.relforcerowsecurity)";
const rows = async () => Number((await cluster.admin.query("SELECT count(*) AS n FROM app.patients")).rows[0].n);
const results = (out) => out.map((r) => r.result);

test("proofBlocks takes only core's shape: the pin, then DO $custosa$ blocks, then the reset", () => {
  assert.deepEqual(proofBlocks(proofSql(block("true"))), [block("true").slice(0, -1)]);
  assert.equal(proofBlocks(proofSql(block("true"), block("false"))).length, 2);
  for (const bad of [
    block("true"),                                                    // no pin
    PIN + block("true"),                                              // no reset
    proofSql(block("true"), "COMMIT;", block("true")),                // a statement between blocks
    proofSql(block("true") + " COMMIT;"),                             // a statement after a block
    proofSql("DO $custosa$\nBEGIN\nEND\n$custosa$ LANGUAGE plpgsql;"), // a clause after the code
    proofSql("DO $custosa$\nBEGIN\n  PERFORM 1;\nEND\n$custosa$; INSERT INTO app.patients VALUES (2, 'x'); DO $custosa$\nBEGIN\nEND\n$custosa$;"),
    proofSql("DO $custosa$\nBEGIN\n  PERFORM $custosa$x$custosa$;\nEND\n$custosa$;"), // the tag inside the body
    PIN + UNPIN,                                                      // no block
    "", null, 7,
  ]) assert.equal(proofBlocks(bad), null, String(bad));
});

test("runProofs: a proof that holds is pass, one that raises is fail, and only {object_id, proof_id, result} comes back", { skip }, async () => {
  const out = await runProofs(cluster.ro, [proof("a", proofSql(block(RLS_ON))), proof("b", proofSql(block(RLS_ON), block(RLS_FORCED)))]);
  assert.deepEqual(out, [
    { object_id: "a", proof_id: idOf(proofSql(block(RLS_ON))), result: "pass" },
    { object_id: "b", proof_id: idOf(proofSql(block(RLS_ON), block(RLS_FORCED))), result: "fail" },
  ]);
  assert.ok(!JSON.stringify(out).includes("the proof failed"));
});

test("runProofs: a write, a missing table, a smuggled COMMIT and a proof id that doesn't match are unread, and nothing is written", { skip }, async () => {
  const before = await rows();
  const write = proofSql("DO $custosa$\nBEGIN\n  INSERT INTO app.patients VALUES (2, 'written');\nEND\n$custosa$;");
  const commit = "SET search_path = pg_catalog, pg_temp;\nCOMMIT;\nINSERT INTO app.patients VALUES (3, 'x');\nRESET search_path;";
  const inner = proofSql("DO $custosa$\nBEGIN\n  COMMIT;\n  EXECUTE 'INSERT INTO app.patients VALUES (4, ''x'')';\nEND\n$custosa$;");
  const missing = proofSql(block("EXISTS (SELECT 1 FROM app.nowhere)"));
  const wrongId = { ...proof("e", proofSql(block("true"))), proof_id: "0".repeat(16) };
  const out = await runProofs(cluster.ro, [proof("a", write), proof("b", commit), proof("c", inner), proof("d", missing), wrongId]);
  assert.deepEqual(results(out), ["unread", "unread", "unread", "unread", "unread"]);
  assert.equal(await rows(), before);
});

test("runProofs: a role that fails the preflight (a write grant) runs nothing; every proof is unread", { skip }, async () => {
  await cluster.admin.query("GRANT INSERT ON app.patients TO phisc_ro");
  try {
    assert.deepEqual(results(await runProofs(cluster.ro, [proof("a", proofSql(block("true")))])), ["unread"]);
  } finally { await cluster.admin.query("REVOKE INSERT ON app.patients FROM phisc_ro"); }
  assert.deepEqual(results(await runProofs(cluster.ro, [proof("a", proofSql(block("true")))])), ["pass"]);
});

test("runProofs: no connection, another login, or a deadline already past gives unread for each, never pass", { skip }, async () => {
  const p = [proof("a", proofSql(block("true")))];
  assert.deepEqual(results(await runProofs(null, p)), ["unread"]);
  assert.deepEqual(results(await runProofs({ ...cluster.ro, user: "postgres" }, p)), ["unread"]);
  const gone = { ...cluster.ro, port: await freePort() };
  Object.defineProperty(gone, "password", { value: "x", enumerable: false });
  assert.deepEqual(results(await runProofs(gone, p, { connectTimeoutMs: 500 })), ["unread"]);
  assert.deepEqual(results(await runProofs(cluster.ro, p, { deadline: Date.now() - 1 })), ["unread"]);
});

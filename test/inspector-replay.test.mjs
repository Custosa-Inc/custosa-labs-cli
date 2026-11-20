/* T29 gap 2 (T29-P1-C529, design lab/T29/gap-rls-sql): migration replay. With no database, the inspector builds a
 * throwaway cluster from the repo's own migrations and reads its catalog with collectCatalog as phisc_ro.
 *
 * The finder and the conditional-DDL scan run everywhere. The replay cases need initdb, pg_ctl and postgres 16+ on
 * PATH; without them they are skipped with the reason. Red rows from the C529 TASK and the design note:
 *   R2 a policy dropped by a later migration, R3 RLS disabled later, R6 conditional DDL, R9 a migration that errors,
 *   R13 a repo with no migrations, R14 the time cap, R20 the sandbox (COPY ... PROGRAM, lo_import, dblink, an extension
 *   outside the allow list), R21 no row value in the result, and no database setting taken from the environment. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import pg from "pg";
import { childEnv, conditionalDdl, findMigrationSet, findPostgres, replayCatalog, startCluster, upSection, BOOT }
  from "../lib/inspector/replay.mjs";
import { QUERY_IDS } from "../lib/inspector/factdoc.mjs";
import { QUERY_ROW_LIMITS, shippedQuerySql } from "../lib/inspector/catalogfacts.mjs";

const QUERIES = QUERY_IDS.map((query_id) => ({ query_id, sql: shippedQuerySql(query_id),
  ...(QUERY_ROW_LIMITS[query_id] ? { row_limit: QUERY_ROW_LIMITS[query_id] } : {}) }));
const temp = (prefix) => realpathSync(mkdtempSync(join(tmpdir(), prefix)));
function repo(files) {
  const root = temp("custosa-replay-repo-");
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(dirname(join(root, rel)), { recursive: true });
    writeFileSync(join(root, rel), text);
  }
  return root;
}
const rowsOf = (r, id) => r.queries.find((q) => q.query_id === id).rows;
const policies = (r) => rowsOf(r, "rls_policies").map((p) => `${p.table_name}.${p.policy_name}:${p.always_true ? "open" : "scoped"}`).sort();
const rls = (r) => Object.fromEntries(rowsOf(r, "rls_status").map((t) => [t.table_name, t.rls_enabled]));
const allNotRun = (r, reason) => r.queries.every((q) => q.status === "not_run" && q.reason === reason && q.rows.length === 0);

/* ---------- the finder ---------- */

test("R13: a repo with no migration set is not_run, no_migrations, and nothing is replayed", async () => {
  const root = repo({ "src/app.ts": "", "docs/example.sql": "create policy p on t using (true);" });
  assert.deepEqual(findMigrationSet(root), { status: "none", reason: "no_migrations" });
  const r = await replayCatalog(root, QUERIES, { bindir: "/nonexistent" });
  assert.equal(r.status, "not_run"); assert.equal(r.reason, "no_migrations"); assert.equal(r.source, "migrations");
  assert.equal(r.replay, null); assert.ok(allNotRun(r, "no_migrations"));
});

test("Supabase: only <digits>_<name>.sql in supabase/migrations, in version order; docs and seeds are never read (R7)", () => {
  const root = repo({
    "supabase/migrations/20240201000000_b.sql": "b", "supabase/migrations/20240101000000_a.sql": "a",
    "supabase/migrations/README.sql": "x", "supabase/seed.sql": "insert", "docs/example.sql": "create policy",
  });
  const s = findMigrationSet(root);
  assert.equal(s.kind, "supabase");
  assert.deepEqual(s.files.map((f) => f.rel), ["supabase/migrations/20240101000000_a.sql", "supabase/migrations/20240201000000_b.sql"]);
});

test("R5: Flyway V2 before V10, numerically; undo files never applied (R8)", () => {
  const root = repo({ "db/migrations/V10__ten.sql": "", "db/migrations/V2__two.sql": "", "db/migrations/V2.1__two_one.sql": "",
    "db/migrations/U2__undo.sql": "" });
  assert.deepEqual(findMigrationSet(root).files.map((f) => f.rel), ["db/migrations/V2__two.sql", "db/migrations/V2.1__two_one.sql", "db/migrations/V10__ten.sql"]);
});

test("R8: golang-migrate .down.sql and a dbmate migrate:down section are never applied", () => {
  const root = repo({ "migrations/1_a.up.sql": "", "migrations/1_a.down.sql": "", "migrations/2_b.up.sql": "", "migrations/2_b.down.sql": "" });
  assert.deepEqual(findMigrationSet(root).files.map((f) => f.rel), ["migrations/1_a.up.sql", "migrations/2_b.up.sql"]);
  const dbmate = "-- migrate:up\ncreate policy p on t using (owner = auth.uid());\n-- migrate:down\ncreate policy q on t using (true);\n";
  assert.ok(!upSection(dbmate).includes("using (true)")); assert.ok(upSection(dbmate).includes("owner"));
  assert.equal(upSection("create table t ();"), "create table t ();");
  assert.equal(upSection("-- migrate:down\ndrop table t;"), "");
});

test("numbered files of mixed width go in numeric order: 2_ before 10_", () => {
  const root = repo({ "migrations/10_c.sql": "", "migrations/2_b.sql": "", "migrations/001_a.sql": "" });
  assert.deepEqual(findMigrationSet(root).files.map((f) => f.rel), ["migrations/001_a.sql", "migrations/2_b.sql", "migrations/10_c.sql"]);
});

test("an order that can't be told is refused: unversioned file, duplicate version, mixed schemes, Flyway repeatable", () => {
  for (const files of [
    { "migrations/1_a.sql": "", "migrations/schema.sql": "" },
    { "migrations/1_a.sql": "", "migrations/01_b.sql": "" },
    { "migrations/1_a.up.sql": "", "migrations/V2__b.sql": "" },
    { "db/migrations/V1__a.sql": "", "db/migrations/R__views.sql": "" },
    { "supabase/migrations/1_a.sql": "", "supabase/migrations/01_b.sql": "" },
  ]) assert.deepEqual(findMigrationSet(repo(files)), { status: "refused", reason: "order_unknown" }, JSON.stringify(files));
});

test("two migration sets in one repo are refused (which one prod ran can't be told)", () => {
  const root = repo({ "supabase/migrations/1_a.sql": "", "prisma/migrations/20240101_init/migration.sql": "" });
  assert.deepEqual(findMigrationSet(root), { status: "refused", reason: "migration_sets_ambiguous" });
});

test("Prisma: migration.sql in each <digits>_ folder, in name order", () => {
  const root = repo({ "prisma/migrations/20240201_b/migration.sql": "", "prisma/migrations/20240101_a/migration.sql": "",
    "prisma/migrations/migration_lock.toml": "" });
  assert.deepEqual(findMigrationSet(root).files.map((f) => f.rel),
    ["prisma/migrations/20240101_a/migration.sql", "prisma/migrations/20240201_b/migration.sql"]);
});

test("a symlinked migration file or folder is refused, never followed", () => {
  const outside = repo({ "x.sql": "create policy p on t using (true);" });
  const root = repo({ "supabase/migrations/1_a.sql": "" });
  symlinkSync(join(outside, "x.sql"), join(root, "supabase/migrations/2_b.sql"));
  assert.deepEqual(findMigrationSet(root), { status: "refused", reason: "symlink" });
  const root2 = repo({ "src/a.ts": "" });
  mkdirSync(join(root2, "db"));
  symlinkSync(outside, join(root2, "db", "migrations"));
  assert.deepEqual(findMigrationSet(root2), { status: "refused", reason: "symlink" });
});

test("a file over the size cap is refused", () => {
  const root = repo({ "migrations/1_a.sql": "x".repeat(1_000_001) });
  assert.deepEqual(findMigrationSet(root), { status: "refused", reason: "too_large" });
});

/* ---------- conditional DDL (R6) ---------- */

test("R6: DO blocks, dynamic EXECUTE and DDL in a function body are conditional; plain DDL and GRANT EXECUTE are not", () => {
  const yes = [
    "DO $$ BEGIN IF current_setting('app.env') = 'prod' THEN CREATE POLICY p ON t USING (true); END IF; END $$;",
    "do $x$ begin perform 1; end $x$;",
    "DO LANGUAGE plpgsql $$ BEGIN NULL; END $$;",
    "DO 'BEGIN NULL; END';",
    "CREATE FUNCTION f() RETURNS void LANGUAGE plpgsql AS $$ BEGIN EXECUTE format('CREATE POLICY p ON %I USING (true)', 't'); END $$;",
    "CREATE FUNCTION f() RETURNS void LANGUAGE sql AS $$ ALTER TABLE t DISABLE ROW LEVEL SECURITY $$; SELECT f();",
    "CREATE FUNCTION f() RETURNS void LANGUAGE plpgsql AS $fn$ BEGIN DROP POLICY p ON t; END $fn$;",
    "\\gexec",
  ];
  const no = [
    "CREATE TABLE t (id int); ALTER TABLE t ENABLE ROW LEVEL SECURITY; CREATE POLICY p ON t USING (owner = auth.uid());",
    "GRANT EXECUTE ON FUNCTION f() TO authenticated;",
    "CREATE TRIGGER tr BEFORE UPDATE ON t FOR EACH ROW EXECUTE FUNCTION touch();",
    "CREATE TRIGGER tr BEFORE UPDATE ON t FOR EACH ROW EXECUTE PROCEDURE touch();",
    "-- DO $$ BEGIN END $$; in a comment\nCREATE TABLE t ();",
    "/* EXECUTE 'x' */ CREATE TABLE t ();",
    "INSERT INTO notes VALUES ('DO $$ nothing $$ EXECUTE');",
    "CREATE FUNCTION touch() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN NEW.updated_at = now(); RETURN NEW; END $$;",
  ];
  for (const s of yes) assert.equal(conditionalDdl(s), true, s);
  for (const s of no) assert.equal(conditionalDdl(s), false, s);
});

test("the children's environment carries no PG* variable and no DATABASE_URL", () => {
  const env = childEnv({ PATH: "/bin", PGHOST: "prod.example", PGOPTIONS: "-c search_path=evil", PGPASSWORD: "x",
    PGSERVICE: "phisc", PGSERVICEFILE: "/x", DATABASE_URL: "postgres://prod", PGDATA: "/var/lib/pg", HOME: "/home/u" });
  assert.deepEqual(Object.keys(env).sort(), ["LANG", "LC_ALL", "PATH", "TZ"]);
});

test("no Postgres programs: not_run, postgres_not_found, with the set described", async () => {
  const root = repo({ "supabase/migrations/1_a.sql": "create table t ();" });
  const r = await replayCatalog(root, QUERIES, { env: { PATH: "" } });
  assert.equal(r.status, "not_run"); assert.equal(r.reason, "postgres_not_found");
  assert.deepEqual(r.replay, { kind: "supabase", files: 1, applied: 0, conditional_ddl: false, failed_file: null });
  assert.ok(allNotRun(r, "postgres_not_found"));
});

/* ---------- the replay, on a real cluster ---------- */

const bindir = findPostgres();
const skip = bindir ? false : "initdb, pg_ctl and postgres are not on PATH, so no replay cluster can be made";
const OWNED = "create table public.notes (id uuid primary key, owner uuid references auth.users(id), body text);\n"
  + "alter table public.notes enable row level security;\n"
  + "create policy own on public.notes for select using (auth.uid() = owner);\n";

test("a Supabase repo replays: the catalog reads as on a live database, from source migrations", { skip }, async () => {
  const r = await replayCatalog(repo({ "supabase/migrations/20240101000000_init.sql": OWNED }), QUERIES, { bindir });
  assert.equal(r.status, "ok", JSON.stringify([r.reason, r.replay]));
  assert.equal(r.source, "migrations"); assert.equal(r.preflight.passed, true);
  assert.deepEqual(r.replay, { kind: "supabase", files: 1, applied: 1, conditional_ddl: false, failed_file: null });
  assert.deepEqual(rls(r), { notes: true });
  assert.deepEqual(policies(r), ["notes.own:scoped"]);
});

test("R2: a policy dropped by a later migration and replaced with USING (true) reads open, not scoped", { skip }, async () => {
  const r = await replayCatalog(repo({
    "supabase/migrations/20240101000000_init.sql": OWNED,
    "supabase/migrations/20240701000000_open.sql": "drop policy own on public.notes;\ncreate policy open_all on public.notes for select using (true);\n",
  }), QUERIES, { bindir });
  assert.equal(r.status, "ok"); assert.deepEqual(policies(r), ["notes.open_all:open"]);
});

test("R3: RLS enabled in 001 and disabled in a later migration reads disabled", { skip }, async () => {
  const r = await replayCatalog(repo({
    "migrations/001_init.sql": "create table notes (id int primary key, owner text);\nalter table notes enable row level security;\n"
      + "create policy own on notes using (owner = current_user);\n",
    "migrations/005_off.sql": "alter table notes disable row level security;\n",
  }), QUERIES, { bindir });
  assert.equal(r.status, "ok", JSON.stringify([r.reason, r.replay])); assert.deepEqual(rls(r), { notes: false });
});

test("R8 end to end: a dbmate down section that opens the table is never applied", { skip }, async () => {
  const r = await replayCatalog(repo({ "db/migrations/20240101_init.sql": "-- migrate:up\n" + OWNED.replace(/auth\.uid\(\)/, "current_user::text::uuid")
    .replace(" references auth.users(id)", "") + "-- migrate:down\ndrop policy own on public.notes;\ncreate policy open_all on public.notes using (true);\n" }),
  QUERIES, { bindir });
  assert.equal(r.status, "ok", JSON.stringify([r.reason, r.replay])); assert.deepEqual(policies(r), ["notes.own:scoped"]);
});

test("R6 end to end: a DO block anywhere in the chain is recorded; the catalog is still read", { skip }, async () => {
  const r = await replayCatalog(repo({
    "supabase/migrations/1_init.sql": OWNED,
    "supabase/migrations/2_env.sql": "DO $$ BEGIN IF current_setting('app.env', true) = 'prod' THEN "
      + "CREATE POLICY open_all ON public.notes USING (true); END IF; END $$;\n",
  }), QUERIES, { bindir });
  assert.equal(r.status, "ok"); assert.equal(r.replay.conditional_ddl, true);
  assert.deepEqual(policies(r), ["notes.own:scoped"]); // the branch prod may take was not; core holds every pass
});

test("R9: migration 3 of 5 errors: failed, replay_failed, the file named, every query not_run", { skip }, async () => {
  const r = await replayCatalog(repo({
    "migrations/1_a.sql": "create table a (id int);", "migrations/2_b.sql": "alter table a enable row level security;",
    "migrations/3_c.sql": "alter table nope add column x int;", "migrations/4_d.sql": "create table d (id int);",
    "migrations/5_e.sql": "create table e (id int);",
  }), QUERIES, { bindir });
  assert.equal(r.status, "failed"); assert.equal(r.reason, "replay_failed");
  assert.equal(r.replay.failed_file, "migrations/3_c.sql"); assert.equal(r.replay.applied, 2);
  assert.ok(allNotRun(r, "replay_failed")); assert.equal(r.preflight, null);
});

test("R14: a migration past the time cap is a failed replay, and the cluster is gone after", { skip }, async () => {
  const before = new Set(readdirSync(tmpdir()));
  const r = await replayCatalog(repo({ "migrations/1_a.sql": "create table a (id int);", "migrations/2_slow.sql": "select pg_sleep(30);" }),
    QUERIES, { bindir, timeMs: 6000 });
  assert.equal(r.status, "failed"); assert.equal(r.reason, "replay_failed"); assert.equal(r.replay.failed_file, "migrations/2_slow.sql");
  const left = readdirSync(tmpdir()).filter((n) => !before.has(n) && /^(custosa-replay-|cr-)/.test(n) && !n.startsWith("custosa-replay-repo-"));
  assert.deepEqual(left, []);
});

test("R20: COPY ... PROGRAM, server lo_import, dblink and an extension outside the allow list all fail to apply", { skip }, async () => {
  const marker = join(temp("custosa-replay-marker-"), "touched");
  for (const sql of [
    `create table x (t text); copy x from program 'touch ${marker}';`,
    `copy (select 1) to '${marker}';`,
    "select lo_import('/etc/hosts');",
    "create extension dblink;",
    "create extension postgres_fdw;",
    "create extension tablefunc;",
    `create function f() returns int language plpython3u as 'return 1';`,
    "alter system set log_statement = 'all';",
    "create role boss superuser;",
    "grant pg_execute_server_program to custosa_migrator;",
    "set session_replication_role = replica;",
  ]) {
    const r = await replayCatalog(repo({ "migrations/1_a.sql": sql }), QUERIES, { bindir });
    assert.equal(r.status, "failed", sql); assert.equal(r.reason, "replay_failed", sql);
    assert.equal(r.replay.failed_file, "migrations/1_a.sql", sql);
  }
  assert.equal(existsSync(marker), false);
});

test("allowed extensions install: uuid-ossp and pgcrypto", { skip }, async () => {
  const r = await replayCatalog(repo({ "migrations/1_a.sql": "create extension if not exists \"uuid-ossp\";\ncreate extension if not exists pgcrypto;\n"
    + "create table t (id uuid default uuid_generate_v4(), h text default encode(digest('x', 'sha256'), 'hex'));" }), QUERIES, { bindir });
  assert.equal(r.status === "ok" || r.status === "empty", true, JSON.stringify([r.status, r.reason, r.replay]));
});

test("R21: rows a migration inserts never reach the result", { skip }, async () => {
  const r = await replayCatalog(repo({ "supabase/migrations/1_init.sql": OWNED
    + "insert into auth.users (id, email) values ('00000000-0000-0000-0000-000000000001', 'patient-ssn-078051120@example.com');\n"
    + "insert into public.notes values ('00000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000001', 'DIAGNOSIS-VALUE');\n" }),
  QUERIES, { bindir });
  assert.equal(r.status, "ok");
  const text = JSON.stringify(r);
  for (const v of ["078051120", "DIAGNOSIS-VALUE", "00000000-0000-0000-0000-000000000002"]) assert.ok(!text.includes(v), v);
});

test("the cluster listens on no TCP address and takes no setting from the environment", { skip }, async () => {
  const env = { ...process.env, PGOPTIONS: "-c search_path=evil", PGHOST: "192.0.2.1", PGPORT: "1", PGDATABASE: "prod",
    DATABASE_URL: "postgres://u:p@192.0.2.1/prod" };
  const c = await startCluster({ bindir, env, deadline: Date.now() + 60_000 });
  assert.equal(c.error, undefined);
  try {
    const client = new pg.Client({ host: c.socketDir, port: c.port, user: BOOT, database: "postgres", password: () => c.bootPw, ssl: false });
    await client.connect();
    try {
      const { rows } = await client.query("select current_setting('listen_addresses') la, current_setting('search_path') sp");
      assert.deepEqual(rows, [{ la: "", sp: '"$user", public' }]);
    } finally { await client.end(); }
  } finally { await c.stop(); }
  assert.equal(existsSync(c.dir), false); assert.equal(existsSync(c.socketDir), false);
});

/* ---------- the fact document (contract 2.8), through inspect --document ---------- */

import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import { validateFactDocument } from "../lib/inspector/schema.mjs";
import { replayFact } from "../lib/inspector/factdoc.mjs";

const BIN = fileURLToPath(new URL("../bin/custosa.mjs", import.meta.url));
// The package's own bundle: its shipped catalog queries are what a replay reads (the fixture bundle ships none).
const inspect = (root, env = {}) => new Promise((ok) => {
  const base = { ...process.env };
  delete base.CUSTOSA_BUNDLE_DIR;
  execFile(process.execPath, [BIN, "inspect", "--document", root], {
    env: { ...base, PGSERVICEFILE: join(temp("g2-nopg-"), "none.conf"), CUSTOSA_CONFIG_DIR: temp("g2-cfg-"),
      CUSTOSA_EVALUATOR_URL: "http://127.0.0.1:9", ...env }, maxBuffer: 50e6 },
  (error, stdout, stderr) => ok({ code: error ? error.code : 0, stdout, stderr }));
});
const catalogEntry = (doc) => doc.collection.find((c) => c.collector === "catalog");

test("with no [phisc] entry, a repo's migrations are replayed: a valid document with source migrations", { skip }, async () => {
  const out = await inspect(repo({ "supabase/migrations/20240101000000_init.sql": OWNED, "package.json": "{}" }));
  assert.equal(out.code, 0, out.stderr);
  const { document } = JSON.parse(out.stdout);
  assert.equal(validateFactDocument(document), null);
  assert.equal(document.catalog.source, "migrations");
  assert.deepEqual(document.catalog.replay, { kind: "supabase", files: 1, applied: 1, conditional_ddl: false, outcome: "applied", failed_file: null });
  assert.equal(document.catalog.preflight.passed, true);
  assert.ok(document.catalog.queries.find((q) => q.query_id === "rls_policies").rows.length >= 1);
  assert.equal(document.tenancy.source, "answer"); // never observed from a throwaway database
});

test("R9 in the document: a migration that fails reads failed, migrations_not_applied, with the file named and no rows", { skip }, async () => {
  const out = await inspect(repo({ "migrations/1_a.sql": "create table a (id int);", "migrations/2_b.sql": "alter table nope add x int;" }));
  assert.equal(out.code, 0, out.stderr);
  const { document } = JSON.parse(out.stdout);
  assert.equal(validateFactDocument(document), null);
  assert.deepEqual(catalogEntry(document), { collector: "catalog", status: "failed", count: 0, reason: "migrations_not_applied" });
  assert.deepEqual(document.catalog.replay, { kind: "plain", files: 2, applied: 1, conditional_ddl: false, outcome: "not_applied", failed_file: "migrations/2_b.sql" });
  assert.equal(document.catalog.preflight.passed, false);
  assert.ok(document.catalog.queries.every((q) => q.status === "not_run" && q.rows.length === 0));
  assert.deepEqual(document.columns, []);
});

test("R13 in the document: no migration set sends exactly the no-database catalog, with no source", async () => {
  const out = await inspect(repo({ "src/a.ts": "export const a = 1;\n" }));
  assert.equal(out.code, 0, out.stderr);
  const { document } = JSON.parse(out.stdout);
  assert.equal(validateFactDocument(document), null);
  assert.equal("source" in document.catalog, false); assert.equal("replay" in document.catalog, false);
  assert.deepEqual(catalogEntry(document), { collector: "catalog", status: "not_run", count: 0, reason: "not_configured" });
});

test("no Postgres on PATH: source migrations, outcome no_postgres, not_run, nothing read", async () => {
  const out = await inspect(repo({ "supabase/migrations/1_a.sql": "create table t ();" }), { PATH: temp("g2-nopath-") });
  assert.equal(out.code, 0, out.stderr);
  const { document } = JSON.parse(out.stdout);
  assert.equal(validateFactDocument(document), null);
  assert.equal(document.catalog.replay.outcome, "no_postgres");
  assert.equal(catalogEntry(document).status, "not_run");
  assert.ok(document.catalog.queries.every((q) => q.status === "not_run"));
});

test("replayFact: a replay result of a shape the contract can't carry is refused, never sent as live", () => {
  const ok = { source: "migrations", status: "ok", reason: null, replay: { kind: "plain", files: 2, applied: 2, conditional_ddl: false, failed_file: null } };
  assert.equal(replayFact(ok, "k").outcome, "applied");
  assert.equal(replayFact({ ...ok, source: undefined }, "k"), null);
  for (const replay of [{ ...ok.replay, kind: "flyway" }, { ...ok.replay, files: 0 }, { ...ok.replay, applied: 3 }, { ...ok.replay, applied: 1 }, null]) {
    assert.deepEqual(replayFact({ ...ok, replay }, "k"), { bad: true }, JSON.stringify(replay));
  }
  assert.deepEqual(replayFact({ ...ok, status: "failed", reason: "replay_failed", replay: { ...ok.replay, applied: 1 } }, "k"), { bad: true }); // no file named
  assert.equal(replayFact({ ...ok, reason: "replay_failed", replay: { ...ok.replay, applied: 1, failed_file: "migrations/2_b.sql" } }, "k").failed_file, "migrations/2_b.sql");
  assert.equal(replayFact({ ...ok, replay: { ...ok.replay, conditional_ddl: undefined } }, "k").conditional_ddl, true); // unknown reads as conditional
});

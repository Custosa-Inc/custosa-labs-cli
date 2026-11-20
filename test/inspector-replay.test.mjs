/* T29 gap 2 (T29-P1-C529, design lab/T29/gap-rls-sql; rebuilt in process by T29-P1-C562): migration replay. With no
 * database, the inspector replays the repo's own migrations into an in-process Postgres (PGlite, in a worker thread)
 * and reads its catalog with the same collector as phisc_ro.
 *
 * Every case runs everywhere: the engine ships in the package, and no Postgres on the machine is needed or used. Red
 * rows from the C529 TASK, the design note and C562:
 *   R2 a policy dropped by a later migration, R3 RLS disabled later, R6 conditional DDL, R9 a migration that errors,
 *   R13 a repo with no migrations, R14 the time cap, R20 the sandbox (COPY ... PROGRAM, lo_import, dblink, an extension
 *   outside the allow list), R21 no row value in the result, and no database setting taken from the environment. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { conditionalDdl, findMigrationSet, replayCatalog, statementCount, upSection, ENGINE_MODULES }
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
  const r = await replayCatalog(root, QUERIES, {});
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

test("C562: the statement count matches the engine's: comments, literals and dollar bodies hold no statement", () => {
  assert.equal(statementCount(""), 0);
  assert.equal(statementCount("-- only a comment\n/* and ; another */"), 0);
  assert.equal(statementCount("create table a (id int);\n\n;;\ncreate table b (id int)"), 2);
  assert.equal(statementCount("insert into a values ('x;y');\ncreate function f() returns int language sql as $f$ select 1; select 2 $f$;"), 2);
  assert.equal(statementCount("select 1; -- trailing; comment\n"), 1);
});

test("C562: the registered extensions are the allow list's, in PGlite's module names; file_fdw and dblink are not", () => {
  assert.ok(ENGINE_MODULES.includes("uuid_ossp") && ENGINE_MODULES.includes("pgcrypto"));
  for (const m of ["file_fdw", "dblink", "postgres_fdw", "vector", "plpgsql"]) assert.ok(!ENGINE_MODULES.includes(m), m);
});

/* ---------- the replay, in the in-process engine ---------- */

const skip = false; // the engine is in the package: every replay case runs, with no Postgres on the machine
const OWNED = "create table public.notes (id uuid primary key, owner uuid references auth.users(id), body text);\n"
  + "alter table public.notes enable row level security;\n"
  + "create policy own on public.notes for select using (auth.uid() = owner);\n";

test("a Supabase repo replays: the catalog reads as on a live database, from source migrations", { skip }, async () => {
  const r = await replayCatalog(repo({ "supabase/migrations/20240101000000_init.sql": OWNED }), QUERIES, {});
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
  }), QUERIES, {});
  assert.equal(r.status, "ok"); assert.deepEqual(policies(r), ["notes.open_all:open"]);
});

test("R3: RLS enabled in 001 and disabled in a later migration reads disabled", { skip }, async () => {
  const r = await replayCatalog(repo({
    "migrations/001_init.sql": "create table notes (id int primary key, owner text);\nalter table notes enable row level security;\n"
      + "create policy own on notes using (owner = current_user);\n",
    "migrations/005_off.sql": "alter table notes disable row level security;\n",
  }), QUERIES, {});
  assert.equal(r.status, "ok", JSON.stringify([r.reason, r.replay])); assert.deepEqual(rls(r), { notes: false });
});

test("R8 end to end: a dbmate down section that opens the table is never applied", { skip }, async () => {
  const r = await replayCatalog(repo({ "db/migrations/20240101_init.sql": "-- migrate:up\n" + OWNED.replace(/auth\.uid\(\)/, "current_user::text::uuid")
    .replace(" references auth.users(id)", "") + "-- migrate:down\ndrop policy own on public.notes;\ncreate policy open_all on public.notes using (true);\n" }),
  QUERIES, {});
  assert.equal(r.status, "ok", JSON.stringify([r.reason, r.replay])); assert.deepEqual(policies(r), ["notes.own:scoped"]);
});

test("R6 end to end: a DO block anywhere in the chain is recorded; the catalog is still read", { skip }, async () => {
  const r = await replayCatalog(repo({
    "supabase/migrations/1_init.sql": OWNED,
    "supabase/migrations/2_env.sql": "DO $$ BEGIN IF current_setting('app.env', true) = 'prod' THEN "
      + "CREATE POLICY open_all ON public.notes USING (true); END IF; END $$;\n",
  }), QUERIES, {});
  assert.equal(r.status, "ok"); assert.equal(r.replay.conditional_ddl, true);
  assert.deepEqual(policies(r), ["notes.own:scoped"]); // the branch prod may take was not; core holds every pass
});

test("R9: migration 3 of 5 errors: failed, replay_failed, the file named, every query not_run", { skip }, async () => {
  const r = await replayCatalog(repo({
    "migrations/1_a.sql": "create table a (id int);", "migrations/2_b.sql": "alter table a enable row level security;",
    "migrations/3_c.sql": "alter table nope add column x int;", "migrations/4_d.sql": "create table d (id int);",
    "migrations/5_e.sql": "create table e (id int);",
  }), QUERIES, {});
  assert.equal(r.status, "failed"); assert.equal(r.reason, "replay_failed");
  assert.equal(r.replay.failed_file, "migrations/3_c.sql"); assert.equal(r.replay.applied, 2);
  assert.ok(allNotRun(r, "replay_failed")); assert.equal(r.preflight, null);
});

test("R14, C562 point 4: the parent's clock ends a runaway statement; statement_timeout is no cap here", { skip }, async () => {
  // 15 s: room for the engine to start and file 1 to apply on a loaded machine. Each shape runs for ever (the engine
  // enforces no statement_timeout, even one the file sets), so only the parent's timer can end it.
  for (const slow of ["select pg_sleep(600);", "do $l$ begin loop end loop; end $l$;",
    "set statement_timeout = '100ms';\nwith recursive r(n) as (select 1 union all select n + 1 from r) select count(*) from r;"]) {
    const before = new Set(readdirSync(tmpdir()));
    const started = Date.now();
    const r = await replayCatalog(repo({ "migrations/1_a.sql": "create table a (id int);", "migrations/2_slow.sql": slow }),
      QUERIES, { timeMs: 15000 });
    assert.ok(Date.now() - started < 25_000, `the cap ends the replay: ${slow}`);
    assert.equal(r.status, "failed", slow); assert.equal(r.reason, "replay_failed", slow);
    assert.equal(r.replay.failed_file, "migrations/2_slow.sql", slow); assert.equal(r.replay.applied, 1, slow);
    assert.ok(allNotRun(r, "replay_failed"), slow);
    const left = readdirSync(tmpdir()).filter((n) => !before.has(n) && !n.startsWith("custosa-replay-repo-"));
    assert.deepEqual(left, [], "the engine writes nothing to the host's temp folder");
  }
});

test("C562 point 3: the three silent session deaths each end as a failed replay naming the file, never an empty catalog", { skip }, async () => {
  const marker = join(temp("custosa-replay-marker-"), "touched");
  const fdw = `create extension file_fdw; create server fs foreign data wrapper file_fdw;
create foreign table public.fp (a text) server fs options (program 'touch ${marker}; echo x');
grant select on public.fp to custosa_migrator;`;
  const cases = [
    // COPY ... PROGRAM: exec returns one empty result for the file, and the session is dead
    [{ "migrations/1_a.sql": "create table a (id int);", "migrations/2_b.sql": `create table b (id int); copy (select 1) to program 'touch ${marker}'; create table c (id int);` }, {}, "migrations/2_b.sql"],
    // the same statement alone in its file: the count matches (1 of 1), the canary catches it
    [{ "migrations/1_a.sql": "create table a (id int);", "migrations/2_b.sql": `copy a from program 'touch ${marker}; echo 1'` }, {}, "migrations/2_b.sql"],
    // a file_fdw program table: not registered, so its CREATE EXTENSION fails
    [{ "migrations/1_a.sql": "create table a (id int);", "migrations/2_b.sql": fdw.replace("grant select on public.fp to custosa_migrator;", "select * from public.fp;") }, {}, "migrations/2_b.sql"],
    // the same table made by the setup as the superuser (tests only), read by a migration alone in its file
    [{ "migrations/1_a.sql": "create table a (id int);", "migrations/2_b.sql": "select * from public.fp" },
      { engineModules: [...ENGINE_MODULES, "file_fdw"], testSetupSql: fdw }, "migrations/2_b.sql"],
    // unbounded recursion: a server reports stack depth; this engine's session dies
    [{ "migrations/1_a.sql": "create function public.f(n int) returns int language plpgsql as $f$ begin return public.f(n + 1); end $f$;",
      "migrations/2_b.sql": "select public.f(1)", "migrations/3_c.sql": "create table c (id int);" }, {}, "migrations/2_b.sql"],
  ];
  for (const [files, opts, failed] of cases) {
    const r = await replayCatalog(repo(files), QUERIES, { timeMs: 60_000, ...opts });
    const what = JSON.stringify(files);
    assert.equal(r.status, "failed", what); assert.equal(r.reason, "replay_failed", what);
    assert.equal(r.replay.failed_file, failed, what);
    assert.ok(allNotRun(r, "replay_failed"), what);
  }
  assert.equal(existsSync(marker), false, "no program ran on the host");
});

test("C562: a file that changes the session's user is the failed file", { skip }, async () => {
  const r = await replayCatalog(repo({ "migrations/1_a.sql": "create table a (id int);\nset session authorization postgres;" }), QUERIES, {});
  assert.equal(r.status, "failed"); assert.equal(r.replay.failed_file, "migrations/1_a.sql");
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
    const r = await replayCatalog(repo({ "migrations/1_a.sql": sql }), QUERIES, {});
    assert.equal(r.status, "failed", sql); assert.equal(r.reason, "replay_failed", sql);
    assert.equal(r.replay.failed_file, "migrations/1_a.sql", sql);
  }
  assert.equal(existsSync(marker), false);
});

test("allowed extensions install: uuid-ossp and pgcrypto", { skip }, async () => {
  const r = await replayCatalog(repo({ "migrations/1_a.sql": "create extension if not exists \"uuid-ossp\";\ncreate extension if not exists pgcrypto;\n"
    + "create table t (id uuid default uuid_generate_v4(), h text default encode(digest('x', 'sha256'), 'hex'));" }), QUERIES, {});
  assert.equal(r.status === "ok" || r.status === "empty", true, JSON.stringify([r.status, r.reason, r.replay]));
});

test("R21: rows a migration inserts never reach the result", { skip }, async () => {
  const r = await replayCatalog(repo({ "supabase/migrations/1_init.sql": OWNED
    + "insert into auth.users (id, email) values ('00000000-0000-0000-0000-000000000001', 'patient-ssn-078051120@example.com');\n"
    + "insert into public.notes values ('00000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000001', 'DIAGNOSIS-VALUE');\n" }),
  QUERIES, {});
  assert.equal(r.status, "ok");
  const text = JSON.stringify(r);
  for (const v of ["078051120", "DIAGNOSIS-VALUE", "00000000-0000-0000-0000-000000000002"]) assert.ok(!text.includes(v), v);
});

test("C562 point 5: the engine's files are in memory only, and it takes no setting from the environment", { skip }, async () => {
  const saved = { ...process.env };
  Object.assign(process.env, { PGOPTIONS: "-c search_path=evil", PGHOST: "192.0.2.1", PGPORT: "1", PGDATABASE: "prod",
    DATABASE_URL: "postgres://u:p@192.0.2.1/prod" });
  try {
    // the setup (tests only) raises unless the data directory is the engine's virtual one and no host folder is listed
    const probe = `do $p$ begin
  if current_setting('data_directory') not like '/pglite/%' then raise exception 'host data directory'; end if;
  if exists (select 1 from pg_ls_dir('/') d where d in ('Users', 'etc', 'var', 'private')) then raise exception 'host root'; end if;
end $p$;`;
    const r = await replayCatalog(repo({ "supabase/migrations/1_init.sql": OWNED }), QUERIES, { testSetupSql: probe });
    assert.equal(r.status, "ok", JSON.stringify([r.reason, r.replay]));
    assert.deepEqual(rls(r), { notes: true });
  } finally {
    for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k];
    Object.assign(process.env, saved);
  }
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

test("C562 point 2: no Postgres on PATH: the replay still applies and the catalog is read", async () => {
  const out = await inspect(repo({ "supabase/migrations/1_a.sql": OWNED }), { PATH: temp("g2-nopath-") });
  assert.equal(out.code, 0, out.stderr);
  const { document } = JSON.parse(out.stdout);
  assert.equal(validateFactDocument(document), null);
  assert.equal(document.catalog.replay.outcome, "applied");
  assert.ok(document.catalog.queries.find((q) => q.query_id === "rls_policies").rows.length >= 1);
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

/* ---------- C637 (P3's gap 2 confirm): findings 1 to 3 ---------- */

test("C637 f3: a Prisma set whose lock file names a provider other than postgresql is no set, provider_not_postgres", () => {
  const files = { "prisma/migrations/20240101_a/migration.sql": "CREATE TABLE `t` (`id` INT);" };
  for (const provider of ["mysql", "sqlite", "sqlserver", "mongodb", "cockroachdb"]) {
    const root = repo({ ...files, "prisma/migrations/migration_lock.toml": `# comment\nprovider = "${provider}"\n` });
    assert.deepEqual(findMigrationSet(root), { status: "none", reason: "provider_not_postgres" }, provider);
  }
  for (const lock of ['provider = "postgresql"\n', "provider = 'postgres'\n", ""]) {
    const root = repo({ ...files, "prisma/migrations/migration_lock.toml": lock });
    assert.equal(findMigrationSet(root).status, "found", lock);
  }
  assert.equal(findMigrationSet(repo(files)).status, "found"); // no lock file: taken as today
});

test("C637 f3: provider_not_postgres reads as no database (not_configured) and the replay builds no cluster", async () => {
  const { catalogReason } = await import("../lib/inspector/catalogfacts.mjs");
  assert.equal(catalogReason("provider_not_postgres"), "not_configured");
  const root = repo({ "prisma/migrations/20240101_a/migration.sql": "x", "prisma/migrations/migration_lock.toml": 'provider = "mysql"' });
  const r = await replayCatalog(root, QUERIES, {});
  assert.equal(r.status, "not_run"); assert.equal(r.reason, "provider_not_postgres"); assert.equal(r.replay, null);
});

test("C637 f1: a stub extension the machine lacks is skipped; the replay applies, and a file that needs it is the failed file", { skip }, async () => {
  const ok = await replayCatalog(repo({ "supabase/migrations/20240101000000_init.sql": OWNED }), QUERIES,
    { stubExtensions: ["custosa_no_such_extension", "pgcrypto"] });
  assert.equal(ok.status, "ok", JSON.stringify([ok.reason, ok.replay]));
  assert.equal(ok.replay.applied, 1);
  const bad = await replayCatalog(repo({ "supabase/migrations/1_a.sql": "create table a (id int);",
    "supabase/migrations/2_b.sql": "create table b (id uuid default extensions.custosa_missing_fn());" }), QUERIES,
    { stubExtensions: ["custosa_no_such_extension"] });
  assert.equal(bad.status, "failed"); assert.equal(bad.reason, "replay_failed");
  assert.equal(bad.replay.failed_file, "supabase/migrations/2_b.sql"); assert.equal(bad.replay.applied, 1);
});

test("C637 f1: a sandbox setup that fails before any file is postgres_unusable (no Postgres here), never a nameless replay_failed", { skip }, async () => {
  const r = await replayCatalog(repo({ "supabase/migrations/1_a.sql": "create table a (id int);" }), QUERIES,
    { testSetupSql: "select custosa_test_setup_fault()" });
  assert.equal(r.status, "not_run"); assert.equal(r.reason, "postgres_unusable");
  assert.equal(r.replay.applied, 0); assert.equal(r.replay.failed_file, null);
  assert.ok(allNotRun(r, "postgres_unusable"));
  const { catalogReason } = await import("../lib/inspector/catalogfacts.mjs");
  assert.equal(catalogReason("postgres_unusable"), "not_configured");
  const { replayFact } = await import("../lib/inspector/factdoc.mjs");
  assert.equal(replayFact(r, null).outcome, "no_postgres");
});

test("C637 f2: a Prisma or plain set whose SQL names the Supabase roles or auth.uid() gets the Supabase stubs, default grants included", { skip }, async () => {
  const sql = "create table public.notes (id uuid primary key, owner uuid, body text);\n"
    + "alter table public.notes enable row level security;\n"
    + "create policy own on public.notes for select to authenticated using (auth.uid() = owner);\n";
  for (const files of [{ "prisma/migrations/20240101_init/migration.sql": sql }, { "migrations/1_init.sql": sql }]) {
    const r = await replayCatalog(repo(files), QUERIES, {});
    assert.equal(r.status, "ok", JSON.stringify([r.reason, r.replay]));
    assert.deepEqual(policies(r), ["notes.own:scoped"]);
    // Supabase's default grants reach the table, as on a Supabase host: a grant to anon is never hidden
    const notes = rowsOf(r, "table_grants").find((g) => g.table_name === "notes");
    assert.deepEqual(notes.api_roles_with_privileges, ["anon", "authenticated"]);
    assert.equal(notes.api_table_select, true);
  }
  // a plain set that names none of them gets no stubs: the role is unknown and the file fails, as before
  const r = await replayCatalog(repo({ "migrations/1_a.sql": "create table a (id int);\ngrant select on a to someone_else;" }), QUERIES, {});
  assert.equal(r.reason, "replay_failed"); assert.equal(r.replay.failed_file, "migrations/1_a.sql");
});

/* ---------- C534 part 2: replay safety and accuracy ---------- */

test("C534: a file that leaves a transaction open (BEGIN with no COMMIT) is the failed file, never counted applied", { skip }, async () => {
  const r = await replayCatalog(repo({ "migrations/1_a.sql": "create table a (id int);",
    "migrations/2_b.sql": "BEGIN;\nalter table a enable row level security;\n", "migrations/3_c.sql": "create table c (id int);" }),
  QUERIES, {});
  assert.equal(r.status, "failed"); assert.equal(r.reason, "replay_failed");
  assert.equal(r.replay.failed_file, "migrations/2_b.sql"); assert.equal(r.replay.applied, 1);
});

test("C534: an aborted transaction in a file is the failed file", { skip }, async () => {
  const r = await replayCatalog(repo({ "migrations/1_a.sql": "create table a (id int);",
    "migrations/2_b.sql": "BEGIN;\nselect 1/0;\n" }), QUERIES, {});
  assert.equal(r.reason, "replay_failed"); assert.equal(r.replay.failed_file, "migrations/2_b.sql");
});

test("C534: session settings a file changes (search_path, role) don't carry into the next file or the read", { skip }, async () => {
  const r = await replayCatalog(repo({
    "migrations/1_a.sql": "select pg_catalog.set_config('search_path', '', false);\nSET ROLE NONE;\ncreate table public.a (id int);",
    "migrations/2_b.sql": "create table b (id int);\nalter table b enable row level security;" }), QUERIES, {});
  assert.equal(r.status, "ok", JSON.stringify([r.reason, r.replay]));
  assert.deepEqual(rls(r), { a: false, b: true });
});

test("C534: a chain whose files make tables but whose replay ends with none is a failed replay, never an empty pass", { skip }, async () => {
  const r = await replayCatalog(repo({ "migrations/1_a.sql": "create table a (id int);\nalter table a enable row level security;",
    "migrations/2_b.sql": "drop table a;" }), QUERIES, {});
  assert.equal(r.status, "failed"); assert.equal(r.reason, "replay_failed");
  assert.equal(r.replay.failed_file, "migrations/2_b.sql"); assert.ok(allNotRun(r, "replay_failed"));
  // a chain with no CREATE TABLE at all may read empty, as before
  const none = await replayCatalog(repo({ "migrations/1_a.sql": "create schema s;" }), QUERIES, {});
  assert.notEqual(none.reason, "replay_failed", JSON.stringify([none.status, none.reason]));
});

const DUMP = "--\n-- PostgreSQL database dump\n--\n\n\\restrict AbC123xyz\n\nSET statement_timeout = 0;\n"
  + "create table public.a (id int);\nalter table public.a enable row level security;\n\n\\unrestrict AbC123xyz\n";
test("C534: pg_dump's \\restrict and \\unrestrict lines are stripped from a dump, and nothing else", () => {
  const dump = findMigrationSet(repo({ "migrations/1_schema.sql": DUMP })).files[0].up;
  assert.ok(!/\\(un)?restrict/.test(dump)); assert.equal(conditionalDdl(dump), false);
  assert.ok(dump.includes("create table public.a"));
  // not a dump: kept, so it still holds passes and fails to apply
  const plain = findMigrationSet(repo({ "migrations/1_a.sql": "\\restrict AbC\ncreate table a (id int);\n" })).files[0].up;
  assert.ok(plain.includes("\\restrict AbC")); assert.equal(conditionalDdl(plain), true);
  // a dump with another meta-command keeps it
  const other = findMigrationSet(repo({ "migrations/1_a.sql": DUMP + "\\connect other\n" })).files[0].up;
  assert.ok(other.includes("\\connect other")); assert.equal(conditionalDdl(other), true);
  // only a whole line of the exact shape
  const inline = findMigrationSet(repo({ "migrations/1_a.sql": DUMP + "\\restrict AbC; drop table a;\n" })).files[0].up;
  assert.ok(inline.includes("\\restrict AbC; drop table a;"));
});

test("C534: a dump with \\restrict lines replays", { skip }, async () => {
  const r = await replayCatalog(repo({ "migrations/1_schema.sql": DUMP }), QUERIES, {});
  assert.equal(r.status, "ok", JSON.stringify([r.reason, r.replay])); assert.deepEqual(rls(r), { a: true });
  assert.equal(r.replay.conditional_ddl, false);
});

test("C562: an engine that can't start is postgres_unusable (no_postgres), nothing applied", async () => {
  const r = await replayCatalog(repo({ "migrations/1_a.sql": "create table a (id int);" }), QUERIES,
    { workerUrl: new URL("data:text/javascript,throw new Error('no engine')") });
  assert.equal(r.status, "not_run"); assert.equal(r.reason, "postgres_unusable");
  assert.equal(r.replay.applied, 0); assert.ok(allNotRun(r, "postgres_unusable"));
});

/* ---------- C534 part 1: sets the repo's own tool config anchors ---------- */

const rels = (root) => { const s = findMigrationSet(root); return s.status === "found" ? s.files.map((f) => f.rel) : s; };

test("C534: Prisma, a postgresql schema.prisma anywhere (a monorepo package) with migrations beside it", () => {
  const root = repo({ "packages/db/prisma/schema.prisma": 'datasource db {\n  provider = "postgresql"\n  url = env("X")\n}\n',
    "packages/db/prisma/migrations/20240201_b/migration.sql": "", "packages/db/prisma/migrations/20240101_a/migration.sql": "" });
  assert.deepEqual(rels(root), ["packages/db/prisma/migrations/20240101_a/migration.sql", "packages/db/prisma/migrations/20240201_b/migration.sql"]);
  // a mysql schema with no lock file: no set, provider_not_postgres
  const my = repo({ "backend/prisma/schema.prisma": 'datasource db {\n  provider = "mysql"\n}\n', "backend/prisma/migrations/1_a/migration.sql": "" });
  assert.deepEqual(findMigrationSet(my), { status: "none", reason: "provider_not_postgres" });
});

test("C534: Prisma, the schema path package.json names (prisma.schema)", () => {
  const root = repo({ "server/package.json": JSON.stringify({ prisma: { schema: "db/app.prisma" } }),
    "server/db/app.prisma": 'datasource db {\n  provider = "postgresql"\n}\n', "server/db/migrations/1_a/migration.sql": "" });
  assert.deepEqual(rels(root), ["server/db/migrations/1_a/migration.sql"]);
});

test("C534: Supabase, supabase/migrations under any folder that holds supabase/config.toml", () => {
  const root = repo({ "apps/api/supabase/config.toml": "project_id = 'x'", "apps/api/supabase/migrations/2_b.sql": "",
    "apps/api/supabase/migrations/10_c.sql": "", "apps/api/supabase/seed.sql": "" });
  assert.deepEqual(rels(root), ["apps/api/supabase/migrations/2_b.sql", "apps/api/supabase/migrations/10_c.sql"]);
  // the root rule and its own config are one set, not two
  const one = repo({ "supabase/config.toml": "", "supabase/migrations/1_a.sql": "" });
  assert.deepEqual(rels(one), ["supabase/migrations/1_a.sql"]);
});

test("C534 R4: Drizzle, the journal's order, not the file names' order", () => {
  const root = repo({ "drizzle.config.ts": 'export default { dialect: "postgresql", out: "./db/out", schema: "./s.ts" };',
    "db/out/meta/_journal.json": JSON.stringify({ entries: [{ idx: 1, tag: "0000_b" }, { idx: 0, tag: "0001_a" }] }),
    "db/out/0000_b.sql": "", "db/out/0001_a.sql": "" });
  assert.deepEqual(rels(root), ["db/out/0001_a.sql", "db/out/0000_b.sql"]);
  // a journal naming a file that isn't there, or a duplicate idx, can't be ordered
  const gone = repo({ "drizzle.config.ts": 'export default { dialect: "postgresql", out: "./d" };',
    "d/meta/_journal.json": JSON.stringify({ entries: [{ idx: 0, tag: "0000_a" }] }) });
  assert.deepEqual(findMigrationSet(gone), { status: "refused", reason: "order_unknown" });
  // a MySQL Drizzle config is not a set
  const my = repo({ "drizzle.config.ts": 'export default { dialect: "mysql", out: "./d" };', "d/meta/_journal.json": "{}" });
  assert.deepEqual(findMigrationSet(my), { status: "none", reason: "no_migrations" });
});

test("C534 R4 twin: Drizzle v1, no journal, timestamped folders with migration.sql in folder-name order", () => {
  const root = repo({ "packages/db/drizzle.config.ts": "export default defineConfig({ dialect: 'postgresql', out: './drizzle' })",
    "packages/db/drizzle/20250102000000_b/migration.sql": "", "packages/db/drizzle/20250101000000_a/migration.sql": "",
    "packages/db/drizzle/20250101000000_a/snapshot.json": "{}" });
  assert.deepEqual(rels(root), ["packages/db/drizzle/20250101000000_a/migration.sql", "packages/db/drizzle/20250102000000_b/migration.sql"]);
  // loose .sql files with no journal can't be ordered
  const loose = repo({ "drizzle.config.ts": "export default { dialect: 'postgresql', out: './drizzle' }", "drizzle/0000_a.sql": "" });
  assert.deepEqual(findMigrationSet(loose), { status: "refused", reason: "order_unknown" });
});

test("C534: a compose file that mounts a folder on /docker-entrypoint-initdb.d: its .sql files in name order; a script there holds", () => {
  const compose = "services:\n  db:\n    image: postgres:16\n    volumes:\n      - ./postgres/init:/docker-entrypoint-initdb.d:ro\n      - pgdata:/var/lib/postgresql/data\nvolumes:\n  pgdata: {}\n";
  const root = repo({ "docker/docker-compose.yml": compose, "docker/postgres/init/02_rls.sql": "", "docker/postgres/init/01_schema.sql": "" });
  const s = findMigrationSet(root);
  assert.deepEqual(s.files.map((f) => f.rel), ["docker/postgres/init/01_schema.sql", "docker/postgres/init/02_rls.sql"]);
  assert.equal(s.hold, undefined);
  for (const extra of ["03_more.sh", "04_data.sql.gz"]) {
    const held = findMigrationSet(repo({ "docker/docker-compose.yml": compose, "docker/postgres/init/01_schema.sql": "", [`docker/postgres/init/${extra}`]: "" }));
    assert.equal(held.hold, true, extra);
  }
  // not a Postgres image, a named volume, or a path out of the repo: no set
  for (const c of [compose.replace("postgres:16", "mysql:8"), compose.replace("./postgres/init", "initvol"),
    compose.replace("./postgres/init", "../../etc")]) assert.equal(findMigrationSet(repo({ "docker/docker-compose.yml": c, "docker/postgres/init/01.sql": "" })).status, "none", c);
});

test("C534: runner configs name the folder: Flyway locations, a sqitch plan, dbmate and node-pg-migrate", () => {
  assert.deepEqual(rels(repo({ "db/flyway.conf": "flyway.url=x\nflyway.locations=filesystem:sql/schema\n",
    "db/sql/schema/V2__b.sql": "", "db/sql/schema/V10__c.sql": "", "db/sql/schema/V1__a.sql": "" })),
  ["db/sql/schema/V1__a.sql", "db/sql/schema/V2__b.sql", "db/sql/schema/V10__c.sql"]);
  assert.deepEqual(rels(repo({ "sqitch.plan": "%syntax-version=1.0.0\n%project=x\n\nusers 2024-01-01T00:00:00Z a <a@b> # u\nrls [users] 2024-01-02T00:00:00Z a <a@b>\n@v1 2024-01-03T00:00:00Z a <a@b>\n",
    "deploy/rls.sql": "", "deploy/users.sql": "", "revert/users.sql": "" })), ["deploy/users.sql", "deploy/rls.sql"]);
  assert.deepEqual(rels(repo({ "package.json": JSON.stringify({ scripts: { migrate: "dbmate --migrations-dir ./src/database/migrations up" } }),
    "src/database/migrations/20240101_a.sql": "" })), ["src/database/migrations/20240101_a.sql"]);
  assert.deepEqual(rels(repo({ "api/package.json": JSON.stringify({ scripts: { m: "node-pg-migrate -m db/sql up" } }),
    "api/db/sql/1700000000000_a.sql": "" })), ["api/db/sql/1700000000000_a.sql"]);
  assert.deepEqual(rels(repo({ ".env": "DBMATE_MIGRATIONS_DIR=./server/database/migrations\n", "server/database/migrations/1_a.sql": "" })),
    ["server/database/migrations/1_a.sql"]);
  // node-pg-migrate with code migrations: no set
  assert.equal(findMigrationSet(repo({ "package.json": JSON.stringify({ scripts: { m: "node-pg-migrate -m migs up" } }),
    "migs/1_a.js": "", "migs/2_b.sql": "" })).status, "none");
});

test("C534 R7: SQL in a folder no config anchors is ignored; docs, examples and tests are never walked", () => {
  assert.deepEqual(findMigrationSet(repo({ "src/db/migrations/1_a.sql": "create policy p on t using (true);",
    "src/infrastructure/database/migrations/1_a.sql": "" })), { status: "none", reason: "no_migrations" });
  assert.deepEqual(findMigrationSet(repo({ "examples/app/supabase/config.toml": "", "examples/app/supabase/migrations/1_a.sql": "",
    "docs/prisma/schema.prisma": 'datasource db {\n provider = "postgresql"\n}', "docs/prisma/migrations/1_a/migration.sql": "" })),
  { status: "none", reason: "no_migrations" });
});

test("C534 R10: two anchored sets in one repo are refused; a symlinked anchor is refused", () => {
  assert.deepEqual(findMigrationSet(repo({ "a/supabase/config.toml": "", "a/supabase/migrations/1_a.sql": "",
    "b/prisma/schema.prisma": 'datasource db {\n provider = "postgresql"\n}', "b/prisma/migrations/1_a/migration.sql": "" })),
  { status: "refused", reason: "migration_sets_ambiguous" });
  const root = repo({ "real/1_a.sql": "", "drizzle.config.ts": "export default { dialect: 'postgresql', out: './linked' }" });
  symlinkSync(join(root, "real"), join(root, "linked"));
  assert.deepEqual(findMigrationSet(root), { status: "refused", reason: "symlink" });
});

test("C534: an anchored monorepo set replays end to end", { skip }, async () => {
  const r = await replayCatalog(repo({ "apps/api/supabase/config.toml": "", "apps/api/supabase/migrations/20240101000000_init.sql": OWNED }),
    QUERIES, {});
  assert.equal(r.status, "ok", JSON.stringify([r.reason, r.replay]));
  assert.deepEqual(policies(r), ["notes.own:scoped"]);
});

test("C534: a held compose set (a script beside the .sql) replays with conditional_ddl true, so core holds its passes", { skip }, async () => {
  const r = await replayCatalog(repo({ "docker-compose.yml": "services:\n  db:\n    image: postgres:16\n    volumes:\n      - ./init:/docker-entrypoint-initdb.d\n",
    "init/01.sql": "create table a (id int);\nalter table a enable row level security;", "init/02.sh": "psql -c 'alter table a disable row level security'" }),
  QUERIES, {});
  assert.equal(r.status, "ok", JSON.stringify([r.reason, r.replay])); assert.equal(r.replay.conditional_ddl, true);
});

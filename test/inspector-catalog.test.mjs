/* Smoke test for the Postgres catalog collector and the service/password file reader.
 *
 * Pure unit tests: service file parsing, password file matching (wildcards, escapes, first match), libpq's permission
 * refusal, the hidden password, the TLS policy. They use temp files and an explicit env/home, never the real
 * ~/.pg_service.conf or ~/.pgpass.
 *
 * Database tests: a throwaway cluster made with initdb in a temp dir (TCP on 127.0.0.1 only, a free port, no socket,
 * scram passwords), started with pg_ctl and stopped at the end. If initdb or pg_ctl is missing or the cluster won't
 * start, those tests are skipped with the reason. The unreachable-host and TLS-policy tests need no database. */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { chmodSync, mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync, readFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { inspect } from "node:util";
import pg from "pg";
import {
  isRequiredLogin, matchPassword, parseServiceEntry, readPassFile, readService, splitPassFields, PgServiceError,
} from "../lib/inspector/pgservice.mjs";
import {
  ALLOWED_FUNCTIONS, PREFLIGHT_SQL, checkShippedSql, clientFor, collectCatalog, isLoopbackHost, judgePreflight, preflightOnly,
  tlsOptions,
} from "../lib/inspector/catalog.mjs";
import { V2_QUERIES, catalogReason, shippedQuerySql, toFactCatalog } from "../lib/inspector/catalogfacts.mjs";
// enums.QUERY_IDS (contract v1.1): the rule set ships one file for each.
const SHIPPED_QUERY_IDS = ["rls_status", "rls_policies", "table_grants", "table_columns", "views", "definer_functions",
  "exposed_schemas", "roles", "storage_buckets", "transport", "logging", "audit", "self_hosted", "advisor",
  "default_acl", "schema_privileges", "triggers", "constraints", "realtime_publication",
  "connected_roles"];
import Ajv2020Module from "ajv/dist/2020.js";

const temp = (prefix) => realpathSync(mkdtempSync(join(tmpdir(), prefix)));
const secret = () => randomBytes(18).toString("base64url");
const cleanups = [];
after(() => { for (const fn of cleanups.reverse()) { try { fn(); } catch { /* best effort */ } } });

function files({ service, pass, passMode = 0o600 }) {
  const dir = temp("custosa-pgsvc-");
  cleanups.push(() => rmSync(dir, { recursive: true, force: true }));
  const env = {};
  if (service !== undefined) { env.PGSERVICEFILE = join(dir, "svc.conf"); writeFileSync(env.PGSERVICEFILE, service); }
  if (pass !== undefined) {
    env.PGPASSFILE = join(dir, "pgpass"); writeFileSync(env.PGPASSFILE, pass); chmodSync(env.PGPASSFILE, passMode);
  }
  return { dir, env };
}

/* ---------- pgservice: pure ---------- */

test("parseServiceEntry follows libpq: first section and first value win, no spaces around =, other sections unparsed", () => {
  const text = "# top comment\ngarbage before any section\n[other]\nthis is not key value\nhost = spaced\n"
    + "[phisc]\r\n  host=db.local  \nport=6543\n# inner\nuser=phisc_ro\nport=7000\n[phisc]\nhost=second\n";
  assert.deepEqual({ ...parseServiceEntry(text, "phisc") }, { host: "db.local", port: "6543", user: "phisc_ro" });
  assert.equal(parseServiceEntry(text, "missing"), null);
  // Errors count only inside the requested section.
  assert.throws(() => parseServiceEntry(text, "other"), (e) => e.code === "service_syntax");
  assert.throws(() => parseServiceEntry("[a]\nhost = x\n", "a"), (e) => e.code === "service_syntax");
  assert.throws(() => parseServiceEntry("[a]\nhost =x\n", "a"), (e) => e.code === "service_syntax");
  assert.throws(() => parseServiceEntry("[a]\nnotakeyword=x\n", "a"), (e) => e.code === "service_syntax");
  assert.throws(() => parseServiceEntry("[a]\nservice=b\n", "a"), (e) => e.code === "service_syntax");
  assert.deepEqual({ ...parseServiceEntry("[a]\nhost= x\n", "a") }, { host: " x" }); // value kept as written
  assert.deepEqual({ ...parseServiceEntry("[ab]\nhost=1\n[a]\nhost=2\n", "a") }, { host: "2" });
  assert.equal(parseServiceEntry("\uFEFF[a]\nhost=1\n", "a"), null); // a BOM spoils the first line, as in libpq
});

test("splitPassFields honours escapes and ends the password at the next unescaped colon", () => {
  // As psql reads it: the password ends at the next unescaped colon.
  assert.deepEqual(splitPassFields("h:5432:db:u:pa:ss").fields, ["h", "5432", "db", "u", "pa"]);
  assert.deepEqual(splitPassFields("h\\:x:5432:d\\\\b:u:p\\:q:rest").fields, ["h:x", "5432", "d\\b", "u", "p:q"]);
  assert.equal(splitPassFields("h:5432:db"), null);
});

test("matchPassword: wildcards, first match wins, socket and empty host match localhost", () => {
  const text = "# comment\nother:5432:db:phisc_ro:nope\n*:5432:appdb:phisc_ro:first\n*:*:*:phisc_ro:second\n"
    + "localhost:5433:*:*:sock\n";
  assert.equal(matchPassword(text, { host: "db.example", port: 5432, dbname: "appdb", user: "phisc_ro" }), "first");
  assert.equal(matchPassword(text, { host: "db.example", port: 6000, dbname: "x", user: "phisc_ro" }), "second");
  assert.equal(matchPassword(text, { host: "/tmp", port: 5433, dbname: "z", user: "bob" }), "sock");
  assert.equal(matchPassword(text, { host: "", port: 5433, dbname: "z", user: "bob" }), "sock");
  assert.equal(matchPassword(text, { host: "h", port: 1, dbname: "z", user: "bob" }), undefined);
  // `*` is a whole-field wildcard only, not a glob inside a value, and an escaped `\*` is a literal star.
  assert.equal(matchPassword("db*:5432:*:*:p\n", { host: "db1", port: 5432, dbname: "d", user: "u" }), undefined);
  assert.equal(matchPassword("\\*:5432:*:*:p\n", { host: "evil.example", port: 5432, dbname: "d", user: "u" }), undefined);
  assert.equal(matchPassword("\\*:5432:*:*:p\n", { host: "*", port: 5432, dbname: "d", user: "u" }), "p");
  // The port is compared as written, as libpq does.
  assert.equal(matchPassword("h:05432:*:*:p\n", { host: "h", port: "5432", dbname: "d", user: "u" }), undefined);
});

test("readService: entry, defaults, pgpass password, PGSERVICEFILE and PGPASSFILE honoured", () => {
  const pw = secret();
  const { env } = files({
    service: "[phisc]\nhost=localhost\nport=5432\ndbname=app\nuser=phisc_ro\n[bare]\nuser=phisc_ro\n",
    pass: `localhost:5432:app:phisc_ro:${pw}\n`,
  });
  const home = temp("custosa-home-"); // empty: proves the env paths are used, not ~
  cleanups.push(() => rmSync(home, { recursive: true, force: true }));
  const s = readService("phisc", { env, home });
  assert.deepEqual({ ...s }, {
    host: "localhost", port: 5432, dbname: "app", user: "phisc_ro", sslmode: "prefer", sslrootcert: null,
    password_source: "pgpass",
  });
  assert.equal(s.password, pw);
  const bare = readService("bare", { env, home });
  assert.equal(bare.host, "localhost"); assert.equal(bare.port, 5432); assert.equal(bare.dbname, "phisc_ro");
  assert.equal(bare.password_source, "pgpass_no_match"); assert.equal(bare.password, undefined);
  assert.throws(() => readService("nope", { env, home }), (e) => e instanceof PgServiceError && e.code === "service_missing");
  assert.throws(() => readService("phisc", { env: {}, home }), (e) => e.code === "service_file_missing");
});

test("readService falls back to home files when the env names none", () => {
  const home = temp("custosa-home-");
  cleanups.push(() => rmSync(home, { recursive: true, force: true }));
  const pw = secret();
  writeFileSync(join(home, ".pg_service.conf"), "[phisc]\nhost=127.0.0.1\nuser=phisc_ro\ndbname=d\n");
  writeFileSync(join(home, ".pgpass"), `127.0.0.1:5432:d:phisc_ro:${pw}\n`, { mode: 0o600 });
  chmodSync(join(home, ".pgpass"), 0o600);
  const s = readService(undefined, { env: {}, home });
  assert.equal(s.password, pw);
});

test("the password is hidden from JSON, inspect and spread, and never in the enumerable fields", () => {
  const pw = secret();
  const { env } = files({ service: "[phisc]\nuser=phisc_ro\ndbname=d\n", pass: `*:*:*:*:${pw}\n` });
  const s = readService("phisc", { env, home: tmpdir() });
  assert.equal(s.password, pw);
  assert.ok(!JSON.stringify(s).includes(pw));
  assert.ok(!inspect(s, { depth: 5 }).includes(pw));
  assert.ok(!Object.values({ ...s }).includes(pw));
});

test("a password file with group or world permission bits is refused, as libpq does", () => {
  const pw = secret();
  for (const mode of [0o644, 0o640, 0o604, 0o620, 0o601, 0o660]) {
    const { env } = files({ service: "[phisc]\nuser=phisc_ro\ndbname=d\n", pass: `*:*:*:*:${pw}\n`, passMode: mode });
    const s = readService("phisc", { env, home: tmpdir() });
    assert.equal(s.password, undefined, `mode ${mode.toString(8)}`);
    assert.equal(s.password_source, "pgpass_refused_permissions");
  }
  const ok = files({ service: "[phisc]\nuser=phisc_ro\ndbname=d\n", pass: `*:*:*:*:${pw}\n`, passMode: 0o400 });
  assert.equal(readService("phisc", { env: ok.env, home: tmpdir() }).password, pw);
  const dir = temp("custosa-pgdir-");
  cleanups.push(() => rmSync(dir, { recursive: true, force: true }));
  assert.equal(readPassFile(dir, { host: "h", port: 1, dbname: "d", user: "u" }).source, "pgpass_not_regular");
  assert.equal(readPassFile(join(dir, "none"), { host: "h", port: 1, dbname: "d", user: "u" }).source, "pgpass_missing");
});

test("a password in the service entry wins over the password file; bad entries are refused", () => {
  const { env } = files({
    service: "[phisc]\nuser=phisc_ro\ndbname=d\npassword=fromservice\n[badport]\nport=99999\nuser=phisc_ro\n"
      + "[badssl]\nsslmode=maybe\nuser=phisc_ro\n[multi]\nhost=a,b\nuser=phisc_ro\n[app]\nuser=app_owner\n",
    pass: "*:*:*:*:frompass\n",
  });
  const s = readService("phisc", { env, home: tmpdir() });
  assert.equal(s.password, "fromservice"); assert.equal(s.password_source, "service");
  assert.throws(() => readService("badport", { env, home: tmpdir() }), (e) => e.code === "service_invalid");
  assert.throws(() => readService("badssl", { env, home: tmpdir() }), (e) => e.code === "service_invalid");
  assert.throws(() => readService("multi", { env, home: tmpdir() }), (e) => e.code === "service_unsupported");
  assert.throws(() => readService("app", { env, home: tmpdir() }), (e) => e.code === "wrong_user");
});

/* Supabase's transaction and session pooler (Supavisor) takes the login as <role>.<project ref> and
 * opens the session as <role>, so phisc_ro.<20-character ref> is the same login. Anything else is still refused. */
test("the Supabase pooler login phisc_ro.<project ref> is phisc_ro; other dotted names are refused", () => {
  const ref = "abcdefghij0123456789";
  const { env } = files({
    service: `[pool]\nhost=aws-0-us-east-1.pooler.supabase.com\nport=6543\nuser=phisc_ro.${ref}\ndbname=postgres\npassword=p\n`
      + "[short]\nuser=phisc_ro.abc\npassword=p\n[two]\nuser=phisc_ro.abcdefghij0123456789.x\npassword=p\n"
      + "[other]\nuser=postgres.abcdefghij0123456789\npassword=p\n[upper]\nuser=phisc_ro.ABCDEFGHIJ0123456789\npassword=p\n",
  });
  const s = readService("pool", { env, home: tmpdir() });
  assert.equal(s.user, `phisc_ro.${ref}`);
  for (const name of ["short", "two", "other", "upper"]) {
    assert.throws(() => readService(name, { env, home: tmpdir() }), (e) => e.code === "wrong_user", name);
  }
  // collectCatalog and the setup checks take the login through the same test.
  assert.equal(isRequiredLogin(`phisc_ro.${ref}`), true);
  assert.equal(isRequiredLogin("phisc_ro"), true);
  assert.equal(isRequiredLogin(`postgres.${ref}`), false);
});

test("the entry's passfile wins over PGPASSFILE, as in libpq", () => {
  const pw = secret();
  const own = files({ pass: `*:*:*:*:${pw}\n` });
  const { env } = files({ service: `[phisc]\nuser=phisc_ro\ndbname=d\npassfile=${own.env.PGPASSFILE}\n`, pass: "*:*:*:*:other\n" });
  assert.equal(readService("phisc", { env, home: tmpdir() }).password, pw);
});

/* ---------- catalog: pure ---------- */

test("loopback detection and the TLS policy", () => {
  for (const h of ["localhost", "127.0.0.1", "127.1.2.3", "::1", "[::1]", "/tmp", ""]) assert.ok(isLoopbackHost(h), h);
  for (const h of ["db.example.com", "10.0.0.5", "192.168.1.2", "::2", "localhost.example.com", "app.localhost"]) assert.ok(!isLoopbackHost(h), h);
  const home = tmpdir();
  for (const sslmode of ["disable", "allow", "prefer", undefined]) {
    assert.deepEqual(tlsOptions({ host: "db.example.com", sslmode }, { home }), { error: "tls_required" });
    assert.deepEqual(tlsOptions({ host: "localhost", sslmode }, { home }), { ssl: false });
  }
  assert.deepEqual(tlsOptions({ host: "db.example.com", sslmode: "require" }, { home }), { ssl: { rejectUnauthorized: false } });
  const full = tlsOptions({ host: "db.example.com", sslmode: "verify-full", sslrootcert: "system" }, { home });
  assert.equal(full.ssl.rejectUnauthorized, true); assert.equal(full.ssl.servername, "db.example.com");
  assert.equal(full.ssl.checkServerIdentity, undefined);
  const ca = tlsOptions({ host: "10.0.0.5", sslmode: "verify-ca", sslrootcert: "system" }, { home });
  assert.equal(typeof ca.ssl.checkServerIdentity, "function");
  // libpq: require with a root certificate present verifies the chain (verify-ca).
  const home2 = temp("custosa-home-");
  cleanups.push(() => rmSync(home2, { recursive: true, force: true }));
  mkdirSync(join(home2, ".postgresql"));
  writeFileSync(join(home2, ".postgresql", "root.crt"), "not really a cert");
  const req = tlsOptions({ host: "db.example.com", sslmode: "require" }, { home: home2 });
  assert.equal(req.ssl.rejectUnauthorized, true); assert.equal(req.ssl.ca, "not really a cert");
  assert.equal(typeof req.ssl.checkServerIdentity, "function");
});

test("the pg client's startup packet ignores PGOPTIONS, PGREPLICATION and the other PG* settings", () => {
  const saved = { ...process.env };
  Object.assign(process.env, {
    PGOPTIONS: "-c search_path=public,pg_catalog -c role=boss", PGREPLICATION: "database", PGAPPNAME: "evil",
    PGCLIENT_ENCODING: "LATIN1", PGSSLNEGOTIATION: "direct", PGPASSWORD: "envpw", PGSSLMODE: "disable",
  });
  try {
    const c = clientFor({ host: "127.0.0.1", port: 1, dbname: "d", user: "phisc_ro" }, false);
    const conf = c.getStartupConf();
    assert.deepEqual(Object.keys(conf).sort(), ["application_name", "database", "user"]);
    assert.equal(conf.application_name, "custosa-inspector");
    assert.equal(c.connectionParameters.client_encoding, "utf8");
    assert.equal(c.connectionParameters.sslnegotiation, "postgres");
  } finally {
    for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k];
    Object.assign(process.env, saved);
  }
});

test("checkShippedSql accepts one SELECT or WITH and nothing else", () => {
  assert.equal(checkShippedSql("  SELECT 1;  ").text, "SELECT 1");
  assert.equal(checkShippedSql("-- c\nWITH a AS (SELECT 1) SELECT * FROM a").text, "-- c\nWITH a AS (SELECT 1) SELECT * FROM a");
  for (const bad of ["DELETE FROM t", "SELECT 1; SELECT 2", "COMMIT", "SET ROLE x", "", null]) {
    const r = checkShippedSql(bad);
    assert.ok(r.error && r.text === undefined, String(bad));
  }
});

test("checkShippedSql refuses wrapper breakouts, escapes and denied functions", () => {
  const bad = {
    "SELECT 1 AS a) q, LATERAL (SELECT 2 AS b": "invalid_query",
    "SELECT (1": "invalid_query",
    "SELECT 'x": "invalid_query",
    "SELECT \"x": "invalid_query",
    "SELECT 1 /* open": "invalid_query",
    "SELECT E'\\x29'": "invalid_query",
    "SELECT $$)$$": "invalid_query",
    "SELECT $1": "invalid_query",
    "SELECT pg_catalog.set_config('role', 'boss', true)": "denied_reference",
    "SELECT query_to_xml('select 1', true, true, '')": "denied_reference",
    "SELECT \"query_to_xmlschema\"('x', true, true, '')": "denied_reference",
    "SELECT table_to_xml('t', true, true, '')": "denied_reference",
    "SELECT * FROM dblink('x', 'y') AS t(a int)": "denied_reference",
    "SELECT lo_get(1)": "denied_reference",
    "SELECT pg_read_file('/etc/passwd')": "denied_reference",
    "SELECT pg_read_binary_file('x')": "denied_reference",
    "SELECT * FROM pg_ls_dir('.')": "denied_reference",
    "SELECT * FROM pg_stat_statements": "denied_reference",
    "SELECT ts_stat('select 1')": "denied_reference",
    "WITH c AS (SELECT 1) SELECT * FROM c, LATERAL (SELECT 1 AS copy) z": "denied_reference",
  };
  for (const [sql, reason] of Object.entries(bad)) assert.equal(checkShippedSql(sql).error, reason, sql);
  // Only allowlisted functions may be called; keywords, casts with type modifiers and alias lists are not calls.
  const notAllowed = ["SELECT now()", "SELECT pg_catalog.version()", "SELECT \"pg_sleep\"(1)", "SELECT pg_sleep (1)",
    "SELECT current_setting('custom.secret')", "SELECT current_setting(c.relname) FROM pg_class c",
    "SELECT x FROM generate_series(1, 2) x", "SELECT 1 FROM pg_class c WHERE pg_catalog.pg_get_viewdef(c.oid) IS NOT NULL",
    "SELECT txid_current() /* a comment */"];
  for (const sql of notAllowed) assert.equal(checkShippedSql(sql).error, "function_not_allowed", sql);
  for (const sql of ["SELECT U&'d\\0061t'", "SELECT u&\"x\"", "SELECT 'a' UESCAPE '!'"]) assert.ok(checkShippedSql(sql).error, sql);
  const allowed = [
    "SELECT c.relname::varchar(64) AS n, CAST(c.relpages AS numeric(10, 2)) AS p FROM pg_catalog.pg_class AS c(oid)",
    "SELECT count(*) FILTER (WHERE c.relrowsecurity) AS n FROM pg_class c WHERE EXISTS (SELECT 1) AND c.oid IN (SELECT 1) AND c.relkind = ANY (ARRAY['r'])",
    "SELECT pg_catalog.has_table_privilege(c.oid, 'SELECT') AS h, current_setting('ssl') AS s, current_setting('ssl', true) AS t FROM pg_class c",
    "WITH RECURSIVE x AS MATERIALIZED (SELECT 1 AS a) SELECT coalesce(max(a), 0) AS m, row_number FROM x, LATERAL (VALUES (1)) v(row_number)",
    // views.sql matches an auth function's body against the stock ones by md5(prosrc).
    "SELECT p.proname FROM pg_catalog.pg_proc p WHERE (p.proname, md5(p.prosrc)) IN (VALUES ('uid', 'x'))",
  ];
  for (const sql of allowed) assert.equal(checkShippedSql(sql).error, undefined, sql);
  assert.ok(Object.isFrozen(ALLOWED_FUNCTIONS) && ALLOWED_FUNCTIONS.includes("has_table_privilege"));
  // Parentheses, semicolons and comment markers inside strings and comments don't count.
  const ok = checkShippedSql("SELECT c.relname FROM pg_catalog.pg_class c WHERE c.relname <> ')' /* ) (( */ -- )\n;");
  assert.equal(ok.error, undefined);
  assert.deepEqual([...ok.qualifiers].sort(), ["c", "pg_catalog"]);
  assert.deepEqual([...checkShippedSql('SELECT * FROM "App".t').qualifiers], ["App"]);
});

const GOOD_ROW = Object.freeze({
  role: "phisc_ro", session_role: "phisc_ro", database: "postgres", system_identifier: "7", settings_mismatched: [],
  superuser: false, bypassrls: false, replication: false, createrole: false, readable_tables: 0, public_readable_tables: 0, writable_tables: 0,
  extension_relations_readable: [], catalog_tables: [], predefined_roles: [], dangerous_functions: [],
  catalog_extensions: [], owned_objects: 0, definer_functions_executable: 0, readable_large_objects: 0,
  lo_compat_privileges: false, write_relations: 0, write_large_objects: 0, write_schemas: 0, write_database: 0,
  write_default_privileges: 0, write_createdb: 0, write_foreign_servers: 0, write_fdw: 0, user_casts: 0,
  user_casts_implicit: 0, user_operators: 0,
});
const GOOD_PREFLIGHT = Object.freeze({
  role: "phisc_ro", session_user: "phisc_ro", database: "postgres", system_identifier: "7", settings_mismatched: [],
  superuser: false, bypassrls: false, replication: false, createrole: false, readable_tables: 0, public_readable_tables: 0, writable_tables: 0,
  extension_relations_readable: [], catalog_tables: [], predefined_roles: [], dangerous_functions: [],
  catalog_extensions: [], owned_objects: 0, large_objects: false, definer_functions_executable: 0, passed: true, failed: [],
  write_parts: { relations: 0, large_objects: 0, schemas: 0, database: 0, default_privileges: 0, createdb: 0, foreign_servers: 0, fdw: 0 },
  user_casts: { any: 0, implicit: 0 }, user_operators: 0, message: null,
});

test("judgePreflight names every failed check", () => {
  assert.deepEqual(judgePreflight(GOOD_ROW), GOOD_PREFLIGHT);
  const bad = judgePreflight({
    ...GOOD_ROW, session_role: "boss", settings_mismatched: ["search_path"], superuser: true, bypassrls: true,
    replication: true, createrole: true, readable_tables: 3, catalog_tables: ["pg_statistic"],
    predefined_roles: ["pg_monitor"], dangerous_functions: ["pg_read_file"], catalog_extensions: ["hstore"],
    owned_objects: 1, lo_compat_privileges: true, definer_functions_executable: 4, writable_tables: 5,
  });
  assert.equal(bad.passed, false);
  assert.deepEqual(bad.failed, ["session_user", "settings", "superuser", "bypassrls", "replication", "createrole",
    "readable_tables", "catalog_tables", "predefined_roles", "dangerous_functions", "catalog_extensions", "ownership",
    "large_objects", "write_privileges"]);
  // Executable SECURITY DEFINER functions are reported, never a failure on their own; missing fields fail closed.
  assert.equal(judgePreflight({ ...GOOD_ROW, definer_functions_executable: 4 }).passed, true);
  assert.deepEqual(judgePreflight({ ...GOOD_ROW, settings_mismatched: null, readable_tables: null }).failed, ["settings", "readable_tables"]);
  assert.deepEqual(judgePreflight({ ...GOOD_ROW, role: "app" }).failed, ["role", "session_user"]);
  // Readable extension relations are listed but do not fail the preflight on their own.
  assert.equal(judgePreflight({ ...GOOD_ROW, extension_relations_readable: ["public.spatial_ref_sys"] }).passed, true);
});

/* ---------- catalog: no database needed ---------- */

const QUERIES = [
  { query_id: "schemas", sql: "SELECT n.nspname::text AS schema_name FROM pg_namespace n WHERE n.nspname = 'app'" },
  { query_id: "rls_tables", sql: "SELECT c.relname::text AS table_name, c.relrowsecurity AS rls_enabled, c.relforcerowsecurity AS rls_forced FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'app' AND c.relkind = 'r' ORDER BY 1;" },
];

function assertAllNotRun(r, reason) {
  assert.equal(r.status, "failed");
  assert.equal(r.reason, reason);
  assert.equal(r.preflight.passed, false);
  assert.equal(r.count, 0);
  assert.deepEqual(r.queries.map((q) => [q.query_id, q.status, q.rows.length]), QUERIES.map((q) => [q.query_id, "not_run", 0]));
}

async function freePort() {
  return new Promise((ok, no) => {
    const srv = createServer(); srv.unref(); srv.on("error", no);
    srv.listen(0, "127.0.0.1", () => { const { port } = srv.address(); srv.close(() => ok(port)); });
  });
}

test("no queries gives not_run; a duplicate query_id or another user is refused before connecting", async () => {
  const conn = { host: "127.0.0.1", port: 1, dbname: "d", user: "phisc_ro", sslmode: "prefer" };
  for (const qs of [[], undefined, null]) {
    const r = await collectCatalog(conn, qs);
    assert.equal(r.status, "not_run"); assert.equal(r.reason, "no_queries"); assert.deepEqual(r.queries, []);
  }
  const dup = await collectCatalog(conn, [QUERIES[0], { ...QUERIES[1], query_id: "schemas" }]);
  assert.equal(dup.status, "failed"); assert.equal(dup.reason, "duplicate_query_id");
  assert.ok(dup.queries.every((q) => q.status === "not_run"));
  assertAllNotRun(await collectCatalog({ ...conn, user: "boss" }, QUERIES), "wrong_user");
});

test("an unreachable host gives every query not_run and the collector failed", async () => {
  const port = await freePort(); // nothing listens here
  const conn = { host: "127.0.0.1", port, dbname: "d", user: "phisc_ro", sslmode: "prefer" };
  const r = await collectCatalog(conn, QUERIES, { connectTimeoutMs: 2000 });
  assertAllNotRun(r, "unreachable");
  assert.deepEqual(r.preflight.failed, ["connect"]);
});

test("a non-loopback host without TLS is refused before any connection", async () => {
  const r = await collectCatalog({ host: "192.0.2.10", port: 5432, dbname: "d", user: "phisc_ro", sslmode: "prefer" }, QUERIES);
  assertAllNotRun(r, "tls_required");
});

test("a non-loopback host that does not answer (TLS required) gives every query not_run", async () => {
  const r = await collectCatalog({ host: "192.0.2.10", port: 5432, dbname: "d", user: "phisc_ro", sslmode: "require" }, QUERIES,
    { connectTimeoutMs: 500 });
  assert.equal(r.status, "failed");
  assert.ok(["unreachable", "connect_failed"].includes(r.reason), r.reason);
  assert.ok(r.queries.every((q) => q.status === "not_run"));
});

/* ---------- catalog: against a throwaway cluster ---------- */

const cluster = await startCluster();
const skip = cluster.skip || false;

async function startCluster() {
  // macOS postmaster refuses to start without a valid locale in the environment ("became multithreaded").
  const env = { ...process.env, LC_ALL: "C", LANG: "C" };
  const oneLine = (t) => String(t || "").replace(/\s+/g, " ").trim().slice(-300);
  const probe = spawnSync("initdb", ["--version"], { encoding: "utf8", env });
  if (probe.error || probe.status !== 0) return { skip: "initdb is not on PATH, so no throwaway Postgres cluster can be made" };
  const dir = temp("custosa-pg-");
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
  cleanups.push(() => {
    spawnSync("pg_ctl", ["-D", data, "-m", "immediate", "-w", "stop"], { env });
    rmSync(dir, { recursive: true, force: true });
  });
  const roPw = secret();
  const admin = new pg.Client({ host: "127.0.0.1", port, user: "postgres", database: "postgres", password: () => adminPw, ssl: false });
  await admin.connect();
  await admin.query(`
    CREATE SCHEMA app;
    CREATE TABLE app.patients (id int PRIMARY KEY, name text);
    INSERT INTO app.patients VALUES (1, 'not for the inspector');
    ALTER TABLE app.patients ENABLE ROW LEVEL SECURITY;
    CREATE ROLE phisc_ro LOGIN PASSWORD '${roPw}' NOSUPERUSER NOCREATEDB NOCREATEROLE;
    CREATE ROLE reader NOLOGIN;
    GRANT SELECT ON app.patients TO reader;
  `);
  const ro = { host: "127.0.0.1", port, dbname: "postgres", user: "phisc_ro", sslmode: "prefer", sslrootcert: null };
  Object.defineProperty(ro, "password", { value: roPw, enumerable: false });
  const asAdmin = { host: "127.0.0.1", port, dbname: "postgres", user: "postgres", sslmode: "disable", sslrootcert: null };
  Object.defineProperty(asAdmin, "password", { value: adminPw, enumerable: false });
  return { port, admin, ro, roPw, asAdmin, dir };
}
after(async () => { if (cluster.admin) await cluster.admin.end().catch(() => {}); });

/* Applies `grant` as the admin, runs the collector, then `undo`, whatever happens. */
async function refusedWith(grant, undo, check) {
  await cluster.admin.query(grant);
  try {
    const r = await collectCatalog(cluster.ro, QUERIES);
    assertAllNotRun(r, "preflight_failed");
    assert.ok(r.preflight.failed.includes(check), `failed ${JSON.stringify(r.preflight.failed)} lacks ${check}`);
    return r;
  } finally { await cluster.admin.query(undo); }
}

test("a catalog-only phisc_ro passes the preflight and both queries return catalog rows", { skip }, async () => {
  const r = await collectCatalog(cluster.ro, QUERIES);
  assert.match(r.preflight.system_identifier, /^[0-9]+$/);
  assert.deepEqual({ ...r.preflight, system_identifier: "7" }, GOOD_PREFLIGHT);
  assert.equal(r.status, "ok"); assert.equal(r.reason, null); assert.equal(r.count, 2);
  assert.deepEqual(r.queries, [
    { query_id: "schemas", status: "ok", reason: null, rows: [{ schema_name: "app" }] },
    { query_id: "rls_tables", status: "ok", reason: null, rows: [{ table_name: "patients", rls_enabled: true, rls_forced: false }] },
  ]);
  const text = JSON.stringify(r);
  assert.ok(!text.includes("not for the inspector")); assert.ok(!text.includes(cluster.roPw));
});

test("readService output drives the collector end to end", { skip }, async () => {
  const { env } = files({
    service: `[phisc]\nhost=127.0.0.1\nport=${cluster.port}\ndbname=postgres\nuser=phisc_ro\n`,
    pass: `127.0.0.1:${cluster.port}:postgres:phisc_ro:${cluster.roPw}\n`,
  });
  const r = await collectCatalog(readService("phisc", { env, home: tmpdir() }), QUERIES);
  assert.equal(r.preflight.passed, true); assert.equal(r.status, "ok");
});

// a transaction pooler (Supavisor, PgBouncer) gives each transaction any server connection, so the
// preflight and every query share one connection, each in its own read-only transaction, with unnamed statements.
// the test counts every connection pg opens and every client a query runs on, so a query on a second
// connection goes red whichever path opened it, not only one that skips the onConnect hook.
test("the preflight and every query run on one connection, with no named prepared statement", { skip }, async (t) => {
  const connects = [], queried = new Set();
  const connect = pg.Client.prototype.connect, query = pg.Client.prototype.query;
  t.mock.method(pg.Client.prototype, "connect", function (...a) { connects.push(this); return connect.apply(this, a); });
  t.mock.method(pg.Client.prototype, "query", function (...a) { queried.add(this); return query.apply(this, a); });
  let hooked = 0, prepared = null;
  const r = await collectCatalog(cluster.ro, QUERIES, {
    onConnect: () => { hooked++; },
    beforeClose: async (client) => {
      prepared = Number((await query.call(client, "SELECT pg_catalog.count(*) AS n FROM pg_catalog.pg_prepared_statements")).rows[0].n);
    },
  });
  assert.equal(r.status, "ok");
  assert.equal(connects.length, 1);
  assert.deepEqual([...queried], connects);
  assert.equal(hooked, 1);
  assert.equal(prepared, 0);
});

test("a wrong password fails to connect: every query not_run", { skip }, async () => {
  const conn = { ...cluster.ro }; Object.defineProperty(conn, "password", { value: "wrong-" + secret() });
  assertAllNotRun(await collectCatalog(conn, QUERIES), "auth_failed");
});

test("SELECT on one table is refused", { skip }, async () => {
  const r = await refusedWith("GRANT SELECT ON app.patients TO phisc_ro", "REVOKE SELECT ON app.patients FROM phisc_ro", "readable_tables");
  assert.equal(r.preflight.readable_tables, 1);
});

test("SELECT on one column is refused", { skip }, async () => {
  await refusedWith("GRANT SELECT (id) ON app.patients TO phisc_ro", "REVOKE SELECT (id) ON app.patients FROM phisc_ro", "readable_tables");
});

// a SELECT granted only to PUBLIC was refused; it is now reported (public_readable_tables) and the
// preflight passes, since the shipped queries are read-only and statically checked. A grant to a role the session
// can become is still refused, with or without PUBLIC beside it.
test("SELECT granted only to PUBLIC is reported, not refused", { skip }, async () => {
  await cluster.admin.query("GRANT SELECT ON app.patients TO PUBLIC");
  try {
    const r = await collectCatalog(cluster.ro, QUERIES);
    assert.equal(r.preflight.passed, true);
    assert.equal(r.preflight.readable_tables, 0);
    assert.equal(r.preflight.public_readable_tables, 1);
    assert.equal(r.status, "ok");
  } finally { await cluster.admin.query("REVOKE SELECT ON app.patients FROM PUBLIC"); }
});

test("SELECT granted to PUBLIC and to the role is still refused", { skip }, async () => {
  await cluster.admin.query("GRANT SELECT ON app.patients TO PUBLIC");
  try {
    const r = await refusedWith("GRANT SELECT (id) ON app.patients TO phisc_ro", "REVOKE SELECT (id) ON app.patients FROM phisc_ro", "readable_tables");
    assert.equal(r.preflight.public_readable_tables, 0);
  } finally { await cluster.admin.query("REVOKE SELECT ON app.patients FROM PUBLIC"); }
});

// a relation an extension owns (pg_cron's cron.job, pgsodium's views) is listed, never refused.
test("a readable relation an extension owns is listed, not refused", { skip }, async () => {
  await cluster.admin.query("CREATE EXTENSION IF NOT EXISTS pg_buffercache; GRANT SELECT ON public.pg_buffercache TO PUBLIC");
  try {
    const r = await collectCatalog(cluster.ro, QUERIES);
    assert.equal(r.preflight.passed, true);
    assert.equal(r.preflight.readable_tables, 0);
    assert.ok(r.preflight.extension_relations_readable.includes("public.pg_buffercache"));
  } finally { await cluster.admin.query("DROP EXTENSION pg_buffercache"); }
});

test("SELECT through role membership is refused, inherited or not", { skip }, async () => {
  await refusedWith("GRANT reader TO phisc_ro", "REVOKE reader FROM phisc_ro", "readable_tables");
  const major = Number((await cluster.admin.query("SHOW server_version_num")).rows[0].server_version_num);
  if (major >= 160000) {
    await refusedWith("GRANT reader TO phisc_ro WITH INHERIT FALSE", "REVOKE reader FROM phisc_ro", "readable_tables");
  }
  await refusedWith("GRANT pg_read_all_data TO phisc_ro", "REVOKE pg_read_all_data FROM phisc_ro", "readable_tables");
});

test("a superuser is refused", { skip }, async () => {
  await refusedWith("ALTER ROLE phisc_ro SUPERUSER", "ALTER ROLE phisc_ro NOSUPERUSER", "superuser");
  // Another login (here the cluster's superuser) is refused before connecting.
  assertAllNotRun(await collectCatalog(cluster.asAdmin, QUERIES), "wrong_user");
});

test("BYPASSRLS is refused", { skip }, async () => {
  await refusedWith("ALTER ROLE phisc_ro BYPASSRLS", "ALTER ROLE phisc_ro NOBYPASSRLS", "bypassrls");
});

test("a readable large object or lo_compat_privileges is refused", { skip }, async () => {
  const oid = (await cluster.admin.query("SELECT lo_create(0) AS oid")).rows[0].oid;
  try {
    await refusedWith(`GRANT SELECT ON LARGE OBJECT ${oid} TO phisc_ro`, `REVOKE SELECT ON LARGE OBJECT ${oid} FROM phisc_ro`, "large_objects");
    await refusedWith(`GRANT SELECT ON LARGE OBJECT ${oid} TO PUBLIC`, `REVOKE SELECT ON LARGE OBJECT ${oid} FROM PUBLIC`, "large_objects");
    // With no grant at all, the object is not readable: the preflight passes.
    assert.equal((await collectCatalog(cluster.ro, QUERIES)).preflight.passed, true);
  } finally { await cluster.admin.query(`SELECT lo_unlink(${oid})`); }
  await refusedWith("ALTER ROLE phisc_ro SET lo_compat_privileges = on", "ALTER ROLE phisc_ro RESET lo_compat_privileges", "large_objects");
});

test("more rows than the limit gives truncated with the limit's rows", { skip }, async () => {
  const r = await collectCatalog(cluster.ro, [
    { query_id: "many", sql: "SELECT a.attname::text AS n FROM pg_catalog.pg_attribute a, pg_catalog.pg_namespace s" },
    { query_id: "exact", sql: "SELECT a.attname::text AS n FROM pg_catalog.pg_attribute a, pg_catalog.pg_namespace s LIMIT 5000" },
    { query_id: "none", sql: "SELECT relname::text AS t FROM pg_class WHERE false" },
  ]);
  assert.equal(r.status, "truncated");
  assert.deepEqual(r.queries.map((q) => [q.status, q.rows.length]), [["truncated", 5000], ["ok", 5000], ["empty", 0]]);
});

test("a slow query times out, a non-SELECT is refused, a non-catalog value type is refused", { skip }, async () => {
  const r = await collectCatalog(cluster.ro, [
    { query_id: "slow", sql: "SELECT count(*)::text AS s FROM pg_catalog.pg_attribute a, pg_catalog.pg_attribute b, pg_catalog.pg_class c" },
    { query_id: "write", sql: "DELETE FROM app.patients" },
    { query_id: "two", sql: "SELECT 1 AS a; SELECT 2 AS b" },
    { query_id: "date", sql: "SELECT '2020-01-01'::timestamptz AS t" },
    { query_id: "fine", sql: "SELECT current_user::text AS u" },
  ], { statementTimeoutMs: 300 });
  assert.equal(r.status, "failed"); assert.equal(r.reason, "query_failed");
  assert.deepEqual(r.queries.map((q) => [q.query_id, q.status, q.reason]), [
    ["slow", "failed", "timeout"], ["write", "failed", "invalid_query"], ["two", "failed", "invalid_query"],
    ["date", "failed", "disallowed_value"], ["fine", "ok", null],
  ]);
});

test("each query runs in a read-only transaction", { skip }, async () => {
  const r = await collectCatalog(cluster.ro, [
    { query_id: "ro", sql: "SELECT current_setting('transaction_read_only')::text AS ro, current_setting('statement_timeout')::text AS st, current_setting('lock_timeout')::text AS lt, current_setting('search_path')::text AS sp" },
  ]);
  assert.deepEqual(r.queries[0].rows, [{ ro: "on", st: "10s", lt: "5s", sp: "pg_catalog, pg_temp" }]);
});

/* ---------- review fixes: forged search_path, session_user, data catalogs, predefined roles, ownership ---------- */

const FORGE = `
  CREATE FUNCTION public.has_table_privilege(oid, oid, text) RETURNS boolean LANGUAGE sql AS 'SELECT false';
  CREATE FUNCTION public.has_any_column_privilege(oid, oid, text) RETURNS boolean LANGUAGE sql AS 'SELECT false';
  CREATE FUNCTION public.current_setting(text) RETURNS text LANGUAGE sql AS 'SELECT ''pg_catalog, pg_temp''::text';
  CREATE VIEW public.pg_class AS SELECT c.oid, c.relname, c.relnamespace, c.relkind,
    NOT c.relrowsecurity AS relrowsecurity, true AS relforcerowsecurity FROM pg_catalog.pg_class c;`;
const UNFORGE = `
  DROP VIEW IF EXISTS public.pg_class;
  DROP FUNCTION IF EXISTS public.has_table_privilege(oid, oid, text);
  DROP FUNCTION IF EXISTS public.has_any_column_privilege(oid, oid, text);
  DROP FUNCTION IF EXISTS public.current_setting(text);
  ALTER ROLE phisc_ro RESET search_path;`;
const PINNED = { query_id: "path", sql: "SELECT current_setting('search_path')::text AS sp" };
const REAL_RLS = [{ table_name: "patients", rls_enabled: true, rls_forced: false }];

test("A role-level search_path cannot forge the preflight or the catalog rows", { skip }, async () => {
  await cluster.admin.query(FORGE + "ALTER ROLE phisc_ro SET search_path = public, pg_catalog;");
  try {
    const r = await collectCatalog(cluster.ro, [...QUERIES, PINNED]);
    assert.equal(r.preflight.passed, true);
    assert.deepEqual(r.queries[1].rows, REAL_RLS); // the real pg_class, not the forged view
    assert.deepEqual(r.queries[2].rows, [{ sp: "pg_catalog, pg_temp" }]);
    // The forged privilege functions cannot hide a table grant.
    await refusedWith("GRANT SELECT ON app.patients TO phisc_ro", "REVOKE SELECT ON app.patients FROM phisc_ro", "readable_tables");
    // A forged view readable by PUBLIC is a readable non-catalog relation. Reported, not refused;
    // the pinned search_path above is what keeps it from shadowing the catalog.
    await cluster.admin.query("GRANT SELECT ON public.pg_class TO PUBLIC");
    try {
      const forged = await collectCatalog(cluster.ro, [...QUERIES, PINNED]);
      assert.equal(forged.preflight.public_readable_tables, 1);
      assert.deepEqual(forged.queries[1].rows, REAL_RLS);
    } finally { await cluster.admin.query("REVOKE SELECT ON public.pg_class FROM PUBLIC"); }
  } finally { await cluster.admin.query(UNFORGE); }
});

test("PGOPTIONS in the environment cannot set the search_path or the role", { skip }, async () => {
  await cluster.admin.query(FORGE);
  const saved = process.env.PGOPTIONS;
  process.env.PGOPTIONS = "-c search_path=public,pg_catalog";
  try {
    const r = await collectCatalog(cluster.ro, [...QUERIES, PINNED]);
    assert.equal(r.preflight.passed, true);
    assert.deepEqual(r.queries[1].rows, REAL_RLS);
    assert.deepEqual(r.queries[2].rows, [{ sp: "pg_catalog, pg_temp" }]);
    await refusedWith("GRANT SELECT ON app.patients TO phisc_ro", "REVOKE SELECT ON app.patients FROM phisc_ro", "readable_tables");
  } finally {
    if (saved === undefined) delete process.env.PGOPTIONS; else process.env.PGOPTIONS = saved;
    await cluster.admin.query(UNFORGE);
  }
});

test("A superuser login whose role setting is phisc_ro is refused", { skip }, async () => {
  const bossPw = secret();
  await cluster.admin.query(`CREATE ROLE boss LOGIN SUPERUSER PASSWORD '${bossPw}'; ALTER ROLE boss SET role = 'phisc_ro';`);
  try {
    const boss = { ...cluster.ro, user: "boss" };
    Object.defineProperty(boss, "password", { value: bossPw });
    assertAllNotRun(await collectCatalog(boss, QUERIES), "wrong_user"); // refused before connecting
    const { env } = files({ service: `[phisc]\nhost=127.0.0.1\nport=${cluster.port}\ndbname=postgres\nuser=boss\n` });
    assert.throws(() => readService("phisc", { env, home: tmpdir() }), (e) => e.code === "wrong_user");
    // And the preflight SQL itself catches it: current_user is phisc_ro but session_user is boss, a superuser.
    const c = clientFor(boss, false);
    await c.connect();
    try {
      await c.query("BEGIN READ ONLY"); await c.query("SET LOCAL search_path = pg_catalog, pg_temp");
      const p = judgePreflight((await c.query(PREFLIGHT_SQL)).rows[0]);
      assert.equal(p.role, "phisc_ro"); assert.equal(p.session_user, "boss");
      assert.ok(p.failed.includes("session_user") && p.failed.includes("superuser"), JSON.stringify(p.failed));
    } finally { await c.end(); }
  } finally { await cluster.admin.query("DROP ROLE boss"); }
});

test("SELECT on a data-holding catalog table is refused", { skip }, async () => {
  for (const t of ["pg_statistic", "pg_largeobject", "pg_authid", "pg_user_mapping", "pg_statistic_ext_data", "pg_shadow",
    "pg_file_settings", "pg_hba_file_rules", "pg_ident_file_mappings"]) {
    const r = await refusedWith(`GRANT SELECT ON pg_catalog.${t} TO phisc_ro`, `REVOKE SELECT ON pg_catalog.${t} FROM phisc_ro`, "catalog_tables");
    assert.deepEqual(r.preflight.catalog_tables, [t]);
  }
  await refusedWith("GRANT SELECT (stavalues1) ON pg_catalog.pg_statistic TO phisc_ro",
    "REVOKE SELECT (stavalues1) ON pg_catalog.pg_statistic FROM phisc_ro", "catalog_tables");
});

test("Membership in a predefined role that reaches past the catalog is refused, inherited or not", { skip }, async () => {
  for (const role of ["pg_execute_server_program", "pg_read_server_files", "pg_write_server_files", "pg_monitor",
    "pg_read_all_stats", "pg_signal_backend", "pg_create_subscription"]) {
    const r = await refusedWith(`GRANT ${role} TO phisc_ro`, `REVOKE ${role} FROM phisc_ro`, "predefined_roles");
    assert.ok(r.preflight.predefined_roles.includes(role), role);
  }
  await refusedWith("GRANT pg_execute_server_program TO phisc_ro WITH INHERIT FALSE",
    "REVOKE pg_execute_server_program FROM phisc_ro", "predefined_roles");
  // pg_read_all_settings shows settings only: allowed.
  await cluster.admin.query("GRANT pg_read_all_settings TO phisc_ro");
  try { assert.equal((await collectCatalog(cluster.ro, QUERIES)).preflight.passed, true); }
  finally { await cluster.admin.query("REVOKE pg_read_all_settings FROM phisc_ro"); }
});

test("owning a non-catalog object is refused even after revoking its own privileges", { skip }, async () => {
  await cluster.admin.query("CREATE TABLE app.owned (id int)");
  try {
    const r = await refusedWith("ALTER TABLE app.owned OWNER TO phisc_ro; REVOKE ALL ON app.owned FROM phisc_ro",
      "ALTER TABLE app.owned OWNER TO postgres", "ownership");
    assert.equal(r.preflight.readable_tables, 0);
    await refusedWith("CREATE FUNCTION app.f() RETURNS int LANGUAGE sql AS 'SELECT 1'; ALTER FUNCTION app.f() OWNER TO phisc_ro",
      "DROP FUNCTION app.f()", "ownership");
  } finally { await cluster.admin.query("DROP TABLE app.owned"); }
});

test("a shipped query naming a non-catalog schema, a denied function or breaking the wrapper fails alone", { skip }, async () => {
  const r = await collectCatalog(cluster.ro, [
    { query_id: "app", sql: "SELECT id FROM app.patients" },
    { query_id: "quoted", sql: 'SELECT 1 AS one FROM "app"."patients"' },
    { query_id: "public", sql: "SELECT 1 AS one FROM public.pg_class" },
    { query_id: "breakout", sql: "SELECT 1 AS a) q, LATERAL (SELECT 2 AS b" },
    { query_id: "xml", sql: "SELECT query_to_xml('select * from app.patients', true, true, '')::text AS x" },
    { query_id: "fine", sql: "SELECT c.relname::text AS t FROM pg_catalog.pg_class c WHERE c.relname = 'pg_class'" },
  ]);
  assert.equal(r.preflight.passed, true); assert.equal(r.status, "failed");
  assert.deepEqual(r.queries.map((q) => [q.query_id, q.status, q.reason]), [
    ["app", "failed", "non_catalog_reference"], ["quoted", "failed", "non_catalog_reference"],
    ["public", "failed", "non_catalog_reference"], ["breakout", "failed", "invalid_query"],
    ["xml", "failed", "denied_reference"], ["fine", "ok", null],
  ]);
  assert.ok(!JSON.stringify(r).includes("not for the inspector"));
});

test("Extension relations readable by PUBLIC are listed, not refused", { skip }, async (t) => {
  const avail = await cluster.admin.query("SELECT 1 FROM pg_available_extensions WHERE name = 'pg_stat_statements'");
  if (avail.rowCount === 0) { t.skip("pg_stat_statements (contrib) is not installed with this server"); return; }
  await cluster.admin.query("CREATE EXTENSION pg_stat_statements");
  try {
    const r = await collectCatalog(cluster.ro, [...QUERIES,
      { query_id: "pss", sql: "SELECT userid::text AS u FROM public.pg_stat_statements" }]);
    assert.equal(r.preflight.passed, true);
    assert.equal(r.preflight.readable_tables, 0);
    assert.ok(r.preflight.extension_relations_readable.includes("public.pg_stat_statements"));
    assert.ok(r.preflight.extension_relations_readable.includes("public.pg_stat_statements_info"));
    assert.equal(r.queries[2].reason, "denied_reference");
    // a plain table only PUBLIC reads is reported now, not refused (its own test above).
  } finally { await cluster.admin.query("DROP EXTENSION pg_stat_statements"); }
});

test("Each query repeats the full preflight, so a grant made after it is caught", { skip }, async () => {
  let granted = false;
  try {
    const r = await collectCatalog(cluster.ro, QUERIES, {
      // a grant to PUBLIC alone no longer fails the guard, so the mid-run grant goes to the role.
      onPreflightDone: async () => { await cluster.admin.query("GRANT SELECT ON app.patients TO phisc_ro"); granted = true; },
    });
    assert.equal(r.preflight.passed, true);
    assert.equal(r.status, "failed");
    assert.deepEqual(r.queries.map((q) => [q.status, q.reason, q.rows.length]), [["failed", "session_guard", 0], ["failed", "session_guard", 0]]);
  } finally { if (granted) await cluster.admin.query("REVOKE SELECT ON app.patients FROM phisc_ro"); }
});

/* ---------- second review: extension allowlist, role attributes, functions, settings, cluster identity ---------- */

test("an app table hidden in an extension and granted to the role is refused; one only PUBLIC reads is listed", { skip }, async (t) => {
  const avail = await cluster.admin.query("SELECT 1 FROM pg_available_extensions WHERE name = 'hstore'");
  if (avail.rowCount === 0) { t.skip("hstore (contrib) is not installed with this server"); return; }
  await cluster.admin.query("CREATE EXTENSION hstore; CREATE TABLE app.pg_stat_statements (id int)");
  try {
    let r = await refusedWith("ALTER EXTENSION hstore ADD TABLE app.patients; GRANT SELECT ON app.patients TO phisc_ro",
      "REVOKE SELECT ON app.patients FROM phisc_ro; ALTER EXTENSION hstore DROP TABLE app.patients", "readable_tables");
    assert.equal(r.preflight.readable_tables, 1);
    // one only PUBLIC reads, owned by any extension, is listed, not refused (no allowlist now).
    await cluster.admin.query("ALTER EXTENSION hstore ADD TABLE app.pg_stat_statements; GRANT SELECT ON app.pg_stat_statements TO PUBLIC");
    try {
      r = await collectCatalog(cluster.ro, QUERIES);
      assert.equal(r.preflight.passed, true);
      assert.deepEqual(r.preflight.extension_relations_readable, ["app.pg_stat_statements"]);
    } finally {
      await cluster.admin.query("REVOKE SELECT ON app.pg_stat_statements FROM PUBLIC; ALTER EXTENSION hstore DROP TABLE app.pg_stat_statements");
    }
  } finally { await cluster.admin.query("DROP TABLE app.pg_stat_statements; DROP EXTENSION hstore"); }
});

test("REPLICATION and CREATEROLE are refused; CREATEDB is refused too", { skip }, async () => {
  await refusedWith("ALTER ROLE phisc_ro REPLICATION", "ALTER ROLE phisc_ro NOREPLICATION", "replication");
  await refusedWith("ALTER ROLE phisc_ro CREATEROLE", "ALTER ROLE phisc_ro NOCREATEROLE", "createrole");
  await cluster.admin.query("CREATE ROLE repl NOLOGIN REPLICATION");
  try { await refusedWith("GRANT repl TO phisc_ro WITH INHERIT FALSE", "REVOKE repl FROM phisc_ro", "replication"); }
  finally { await cluster.admin.query("DROP ROLE repl"); }
  const r = await refusedWith("ALTER ROLE phisc_ro CREATEDB", "ALTER ROLE phisc_ro NOCREATEDB", "write_privileges");
  assert.equal(r.preflight.message, "write_privileges: write_createdb");
});

test("EXECUTE on a file, large-object export or dblink function is refused", { skip }, async (t) => {
  for (const [fn, name] of [["pg_read_file(text)", "pg_read_file"], ["pg_read_binary_file(text, bigint, bigint)", "pg_read_binary_file"],
    ["pg_ls_dir(text)", "pg_ls_dir"], ["pg_stat_file(text)", "pg_stat_file"], ["lo_export(oid, text)", "lo_export"],
    ["lo_import(text)", "lo_import"], ["pg_ls_waldir()", "pg_ls_waldir"]]) {
    const r = await refusedWith(`GRANT EXECUTE ON FUNCTION pg_catalog.${fn} TO phisc_ro`,
      `REVOKE EXECUTE ON FUNCTION pg_catalog.${fn} FROM phisc_ro`, "dangerous_functions");
    assert.deepEqual(r.preflight.dangerous_functions, [name]);
  }
  await cluster.admin.query("CREATE ROLE filer NOLOGIN; GRANT EXECUTE ON FUNCTION pg_catalog.pg_read_file(text) TO filer");
  try { await refusedWith("GRANT filer TO phisc_ro WITH INHERIT FALSE", "REVOKE filer FROM phisc_ro", "dangerous_functions"); }
  finally { await cluster.admin.query("REVOKE EXECUTE ON FUNCTION pg_catalog.pg_read_file(text) FROM filer; DROP ROLE filer"); }
  const avail = await cluster.admin.query("SELECT 1 FROM pg_available_extensions WHERE name = 'dblink'");
  if (avail.rowCount === 0) { t.diagnostic("dblink (contrib) not installed: dblink case not run"); return; }
  await cluster.admin.query("CREATE SCHEMA dbl; CREATE EXTENSION dblink SCHEMA dbl");
  try {
    const r = await collectCatalog(cluster.ro, QUERIES); // dblink is executable by PUBLIC once installed
    assert.ok(r.preflight.failed.includes("dangerous_functions"));
    assert.ok(r.preflight.dangerous_functions.includes("dblink") && r.preflight.dangerous_functions.includes("dblink_exec"));
    await cluster.admin.query("REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA dbl FROM PUBLIC");
    assert.equal((await collectCatalog(cluster.ro, QUERIES)).preflight.passed, true);
  } finally { await cluster.admin.query("DROP EXTENSION dblink; DROP SCHEMA dbl"); }
});

test("an extension installed in pg_catalog other than plpgsql is refused", { skip }, async (t) => {
  const avail = await cluster.admin.query("SELECT 1 FROM pg_available_extensions WHERE name = 'hstore'");
  if (avail.rowCount === 0) { t.skip("hstore (contrib) is not installed with this server"); return; }
  const r = await refusedWith("CREATE EXTENSION hstore SCHEMA pg_catalog", "DROP EXTENSION hstore", "catalog_extensions");
  assert.deepEqual(r.preflight.catalog_extensions, ["hstore"]);
});

test("executable SECURITY DEFINER functions are counted, not refused", { skip }, async () => {
  await cluster.admin.query("CREATE FUNCTION app.peek() RETURNS bigint LANGUAGE sql SECURITY DEFINER AS 'SELECT count(*) FROM app.patients'");
  try {
    const r = await collectCatalog(cluster.ro, QUERIES);
    assert.equal(r.preflight.passed, true);
    assert.equal(r.preflight.definer_functions_executable, 1);
    await cluster.admin.query("REVOKE EXECUTE ON FUNCTION app.peek() FROM PUBLIC");
    assert.equal((await collectCatalog(cluster.ro, QUERIES)).preflight.definer_functions_executable, 0);
  } finally { await cluster.admin.query("DROP FUNCTION app.peek()"); }
});

test("role-level settings that change how values read are pinned in every transaction", { skip }, async () => {
  await cluster.admin.query(`ALTER ROLE phisc_ro SET DateStyle = 'SQL, DMY'; ALTER ROLE phisc_ro SET TimeZone = 'Asia/Kolkata';
    ALTER ROLE phisc_ro SET extra_float_digits = 3; ALTER ROLE phisc_ro SET transform_null_equals = on;
    ALTER ROLE phisc_ro SET bytea_output = 'escape'; ALTER ROLE phisc_ro SET quote_all_identifiers = on;
    ALTER ROLE phisc_ro SET IntervalStyle = 'sql_standard'`);
  try {
    const r = await collectCatalog(cluster.ro, [{ query_id: "s", sql: "SELECT '2020-02-03'::date::text AS d, '1 day'::interval::text AS i, quote_ident('select') AS q, (NULL = NULL) IS NULL AS null_is_unknown" }]);
    assert.equal(r.preflight.passed, true, JSON.stringify(r.preflight.settings_mismatched)); assert.deepEqual(r.preflight.settings_mismatched, []);
    assert.deepEqual(r.queries[0].rows, [{ d: "2020-02-03", i: "1 day", q: '"select"', null_is_unknown: true }]);
  } finally { await cluster.admin.query("ALTER ROLE phisc_ro RESET ALL"); }
});

/* ---------- contract v2.1: write_privileges and the new catalog queries ---------- */

test("v2: any write privilege on any relation, in any schema, through any route, is refused", { skip }, async (t) => {
  for (const [grant, undo] of [
    ["GRANT INSERT ON app.patients TO phisc_ro", "REVOKE INSERT ON app.patients FROM phisc_ro"],
    ["GRANT UPDATE ON app.patients TO phisc_ro", "REVOKE UPDATE ON app.patients FROM phisc_ro"],
    ["GRANT DELETE ON app.patients TO phisc_ro", "REVOKE DELETE ON app.patients FROM phisc_ro"],
    ["GRANT TRUNCATE ON app.patients TO phisc_ro", "REVOKE TRUNCATE ON app.patients FROM phisc_ro"],
    ["GRANT REFERENCES ON app.patients TO phisc_ro", "REVOKE REFERENCES ON app.patients FROM phisc_ro"],
    ["GRANT TRIGGER ON app.patients TO phisc_ro", "REVOKE TRIGGER ON app.patients FROM phisc_ro"],
    ["GRANT UPDATE (name) ON app.patients TO phisc_ro", "REVOKE UPDATE (name) ON app.patients FROM phisc_ro"],
    ["GRANT INSERT (id) ON app.patients TO phisc_ro", "REVOKE INSERT (id) ON app.patients FROM phisc_ro"],
    ["GRANT DELETE ON app.patients TO PUBLIC", "REVOKE DELETE ON app.patients FROM PUBLIC"],
    // pg_settings' default PUBLIC UPDATE (it runs SET) isn't counted; any other privilege on it is.
    ["GRANT DELETE ON pg_catalog.pg_settings TO phisc_ro", "REVOKE DELETE ON pg_catalog.pg_settings FROM phisc_ro"],
    ["CREATE SCHEMA other; CREATE TABLE other.t (id int); GRANT INSERT ON other.t TO phisc_ro", "DROP SCHEMA other CASCADE"],
    ["CREATE SEQUENCE app.s; GRANT UPDATE ON SEQUENCE app.s TO phisc_ro", "DROP SEQUENCE app.s"],
    ["CREATE VIEW app.v AS SELECT id FROM app.patients; GRANT INSERT ON app.v TO phisc_ro", "DROP VIEW app.v"],
    ["CREATE ROLE writer NOLOGIN; GRANT INSERT ON app.patients TO writer; GRANT writer TO phisc_ro",
      "REVOKE writer FROM phisc_ro; REVOKE INSERT ON app.patients FROM writer; DROP ROLE writer"],
    // Review round 1: sequences (USAGE is nextval), large objects, CREATE, default privileges, unusable memberships.
    ["CREATE SEQUENCE app.s2; GRANT USAGE ON SEQUENCE app.s2 TO phisc_ro", "DROP SEQUENCE app.s2"],
    ["SELECT lo_create(4242); GRANT UPDATE ON LARGE OBJECT 4242 TO phisc_ro", "SELECT lo_unlink(4242)"],
    ["GRANT CREATE ON SCHEMA app TO phisc_ro", "REVOKE CREATE ON SCHEMA app FROM phisc_ro"],
    ["GRANT CREATE ON SCHEMA public TO PUBLIC", "REVOKE CREATE ON SCHEMA public FROM PUBLIC"],
    ["GRANT CREATE ON DATABASE postgres TO phisc_ro", "REVOKE CREATE ON DATABASE postgres FROM phisc_ro"],
    ["ALTER DEFAULT PRIVILEGES FOR ROLE postgres GRANT INSERT ON TABLES TO phisc_ro",
      "ALTER DEFAULT PRIVILEGES FOR ROLE postgres REVOKE INSERT ON TABLES FROM phisc_ro"],
    ["ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA app GRANT TRUNCATE ON TABLES TO PUBLIC",
      "ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA app REVOKE TRUNCATE ON TABLES FROM PUBLIC"],
    ["ALTER DEFAULT PRIVILEGES FOR ROLE postgres GRANT USAGE ON SEQUENCES TO phisc_ro",
      "ALTER DEFAULT PRIVILEGES FOR ROLE postgres REVOKE USAGE ON SEQUENCES FROM phisc_ro"],
    ["CREATE ROLE dwriter NOLOGIN; ALTER DEFAULT PRIVILEGES FOR ROLE postgres GRANT DELETE ON TABLES TO dwriter; GRANT dwriter TO phisc_ro",
      "REVOKE dwriter FROM phisc_ro; ALTER DEFAULT PRIVILEGES FOR ROLE postgres REVOKE DELETE ON TABLES FROM dwriter; DROP ROLE dwriter"],
  ]) {
    let r;
    try { r = await refusedWith(grant, undo, "write_privileges"); } catch (err) { throw new Error(`refused nothing after: ${grant}`, { cause: err }); }
    assert.ok(r.preflight.writable_tables >= 1, grant);
    assert.equal(r.preflight.readable_tables, 0, grant); // a write grant alone reads nothing: only write_privileges catches it
  }
  const major = Number((await cluster.admin.query("SHOW server_version_num")).rows[0].server_version_num);
  if (major >= 160000) {
    await refusedWith("CREATE ROLE writer NOLOGIN; GRANT DELETE ON app.patients TO writer; GRANT writer TO phisc_ro WITH INHERIT FALSE",
      "REVOKE writer FROM phisc_ro; REVOKE DELETE ON app.patients FROM writer; DROP ROLE writer", "write_privileges");
  }
  if (major >= 160000) {
    await refusedWith("CREATE ROLE writer NOLOGIN; GRANT INSERT ON app.patients TO writer; GRANT writer TO phisc_ro WITH INHERIT FALSE, SET FALSE",
      "REVOKE writer FROM phisc_ro; REVOKE INSERT ON app.patients FROM writer; DROP ROLE writer", "write_privileges");
  }
  if (major >= 170000) {
    await refusedWith("GRANT MAINTAIN ON app.patients TO phisc_ro", "REVOKE MAINTAIN ON app.patients FROM phisc_ro", "write_privileges");
  } else {
    // Older servers don't know MAINTAIN: the CASE must keep the preflight from asking (it would error).
    t.diagnostic(`server ${major}: MAINTAIN case not run (needs 17)`);
  }
  // A SECURITY DEFINER function that writes stays report-only (definer_functions_executable), as before.
  await cluster.admin.query("CREATE FUNCTION app.wr() RETURNS void LANGUAGE sql SECURITY DEFINER AS 'DELETE FROM app.patients WHERE false'");
  try {
    const d = await collectCatalog(cluster.ro, QUERIES);
    assert.equal(d.preflight.passed, true); assert.equal(d.preflight.definer_functions_executable, 1);
  } finally { await cluster.admin.query("DROP FUNCTION app.wr()"); }
  const r = await collectCatalog(cluster.ro, QUERIES);
  assert.equal(r.preflight.passed, true); assert.equal(r.preflight.writable_tables, 0);
});

const V2_SCHEMA = JSON.parse(readFileSync(new URL("./fixtures/contracts/fact_document.schema.e106f9fb.json", import.meta.url), "utf8"));
const Ajv2020 = Ajv2020Module.default ?? Ajv2020Module;
const v2ajv = new Ajv2020({ strict: false, allErrors: true });
v2ajv.addSchema(V2_SCHEMA);
const validateV2 = v2ajv.compile({
  type: "object", additionalProperties: false, required: ["catalog", "collection"],
  properties: { catalog: { $ref: `${V2_SCHEMA.$id}#/properties/catalog` }, collection: { $ref: `${V2_SCHEMA.$id}#/$defs/collection_entry` } },
});

/* The bundle's rls_policies.sql computes the v1 columns; this stand-in returns them as constants and the parts this
 * test is about: roles and the two expressions, which never leave the machine. */
const RLS_TEST_QUERY = { query_id: "rls_policies", row_limit: 10000, sql: `SELECT n.nspname::text AS schema_name,
  c.relname::text AS table_name, p.polname::text AS policy_name,
  CASE p.polcmd WHEN 'r' THEN 'select' WHEN 'a' THEN 'insert' WHEN 'w' THEN 'update' WHEN 'd' THEN 'delete' WHEN '*' THEN 'all' END AS command,
  p.polpermissive AS permissive, false AS always_true, false AS reads_user_metadata, ARRAY[]::text[] AS trusted_routes,
  false AS owner_match,
  ARRAY(SELECT CASE WHEN r.r = 0 THEN 'public' ELSE g.rolname::text END FROM pg_catalog.unnest(p.polroles) AS r(r)
    LEFT JOIN pg_catalog.pg_roles g ON g.oid = r.r) AS roles,
  pg_catalog.pg_get_expr(p.polqual, p.polrelid) AS using_expression,
  pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid) AS check_expression
FROM pg_catalog.pg_policy p JOIN pg_catalog.pg_class c ON c.oid = p.polrelid JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
ORDER BY 1, 2, 3` };

const V2_SETUP = `
  CREATE SCHEMA auth;
  CREATE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE AS $$ SELECT nullif(current_setting('request.jwt.claim.sub', true), '')::uuid $$;
  CREATE FUNCTION auth.jwt() RETURNS jsonb LANGUAGE sql STABLE AS $$ SELECT coalesce(nullif(current_setting('request.jwt.claims', true), ''), '{}')::jsonb $$;
  CREATE ROLE authenticated NOLOGIN;
  CREATE TABLE app.notes (id int PRIMARY KEY, user_id uuid NOT NULL, tenant_id uuid, body text, "Odd Name" text,
    CONSTRAINT notes_body_len CHECK (length(body) < 1000));
  ALTER TABLE app.notes ADD CONSTRAINT notes_tenant_ok CHECK (tenant_id IS NOT NULL) NOT VALID;
  CREATE TABLE app.links (id int, note_id int REFERENCES app.notes (id), slug text, other text);
  CREATE UNIQUE INDEX links_slug ON app.links (slug);
  CREATE UNIQUE INDEX links_lower_other ON app.links (lower(other)) WHERE other IS NOT NULL;
  CREATE TABLE app.customers (email text UNIQUE);
  CREATE TABLE app.orders (id int, email text, code text, ref text);
  INSERT INTO app.orders VALUES (1, 'nobody@example.com', 'a', 'r'), (2, 'nobody@example.com', 'a', 'r');
  ALTER TABLE app.orders ADD CONSTRAINT orders_email_fk FOREIGN KEY (email) REFERENCES app.customers (email) NOT VALID;
  CREATE UNIQUE INDEX orders_code_invalid ON app.orders (id, code);
  UPDATE pg_catalog.pg_index SET indisvalid = false WHERE indexrelid = 'app.orders_code_invalid'::regclass;
  CREATE UNIQUE INDEX orders_ref_not_ready ON app.orders (id, ref);
  UPDATE pg_catalog.pg_index SET indisvalid = false, indisready = false WHERE indexrelid = 'app.orders_ref_not_ready'::regclass;
  ALTER TABLE app.notes ENABLE ROW LEVEL SECURITY;
  CREATE POLICY own_select ON app.notes FOR SELECT TO authenticated USING (user_id = (SELECT auth.uid()));
  CREATE POLICY own_update ON app.notes FOR UPDATE TO authenticated USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid() OR true);
  CREATE POLICY tenant_insert ON app.notes FOR INSERT WITH CHECK (tenant_id = ((auth.jwt() -> 'user_metadata') ->> 'tenant_id')::uuid);
  CREATE POLICY "needs aal2" ON app.notes AS RESTRICTIVE FOR ALL TO authenticated USING ((SELECT auth.jwt() ->> 'aal') = 'aal2');
  CREATE POLICY same_owner ON app.notes FOR DELETE USING (user_id IS NOT DISTINCT FROM auth.uid());
  CREATE FUNCTION app.touch() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$;
  CREATE TRIGGER notes_touch BEFORE INSERT OR UPDATE ON app.notes FOR EACH ROW EXECUTE FUNCTION app.touch();
  ALTER DEFAULT PRIVILEGES IN SCHEMA app GRANT SELECT, INSERT ON TABLES TO authenticated;
  ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
  GRANT USAGE ON SCHEMA app TO authenticated;
  CREATE PUBLICATION supabase_realtime FOR TABLE app.notes;
  CREATE ROLE app_user LOGIN PASSWORD 'not-a-secret-app-user';`;
const V2_TEARDOWN = `
  DROP PUBLICATION IF EXISTS supabase_realtime;
  ALTER DEFAULT PRIVILEGES IN SCHEMA app REVOKE SELECT, INSERT ON TABLES FROM authenticated;
  ALTER DEFAULT PRIVILEGES GRANT EXECUTE ON FUNCTIONS TO PUBLIC;
  DROP TABLE IF EXISTS app.links, app.notes, app.orders, app.customers; DROP FUNCTION IF EXISTS app.touch();
  REVOKE USAGE ON SCHEMA app FROM authenticated;
  DROP SCHEMA IF EXISTS auth CASCADE; DROP ROLE IF EXISTS authenticated; DROP ROLE IF EXISTS app_user;`;

test("v2: the new queries and the parsed policies, end to end, fit the v2 schema", { skip }, async () => {
  await cluster.admin.query(V2_SETUP);
  const sessions = [];
  try {
    for (const [user, password, application_name] of [["app_user", "not-a-secret-app-user", "PostgREST 12.2.3"],
      ["app_user", "not-a-secret-app-user", "PostgREST 12.2.3"], ["app_user", "not-a-secret-app-user", "Metabase v0.50"]]) {
      const c = new pg.Client({ host: "127.0.0.1", port: cluster.port, user, database: "postgres", password, ssl: false, application_name });
      await c.connect(); sessions.push(c);
    }
    const r = await collectCatalog(cluster.ro, [RLS_TEST_QUERY, ...V2_QUERIES]);
    assert.equal(r.preflight.passed, true, JSON.stringify(r.preflight.failed));
    assert.deepEqual(r.queries.map((q) => [q.query_id, q.status, q.reason]), [RLS_TEST_QUERY, ...V2_QUERIES].map((q) => [q.query_id, "ok", null]));
    const out = toFactCatalog(r, { key: "test-install-key" });
    assert.ok(validateV2(out), JSON.stringify(validateV2.errors, null, 1));
    assert.deepEqual(out.collection, { collector: "catalog", status: "ok", count: 7, reason: null }); // server_version dropped
    const q = Object.fromEntries(out.catalog.queries.map((x) => [x.query_id, x.rows]));

    const pol = Object.fromEntries(q.rls_policies.map((p) => [p.policy_name, p]));
    const pick = (p, ks) => Object.fromEntries(ks.map((k) => [k, p[k]]));
    const OWNER = ["owner_using", "owner_with_check", "owner_required", "owner_source_untrusted"];
    const TENANT = ["tenant_using", "tenant_with_check", "tenant_required", "tenant_source_untrusted"];
    assert.deepEqual(pick(pol.own_select, [...OWNER, "roles"]), { owner_using: true, owner_with_check: false, owner_required: true, owner_source_untrusted: false, roles: ["authenticated"] });
    assert.deepEqual(pick(pol.own_update, OWNER), { owner_using: true, owner_with_check: true, owner_required: false, owner_source_untrusted: false });
    assert.deepEqual(pick(pol.tenant_insert, [...TENANT, "roles"]), { tenant_using: false, tenant_with_check: true, tenant_required: true, tenant_source_untrusted: true, roles: ["public"] });
    assert.deepEqual(pick(pol.same_owner, OWNER), { owner_using: true, owner_with_check: false, owner_required: true, owner_source_untrusted: false });
    const aal = q.rls_policies.find((p) => p.permissive === false);
    assert.match(aal.policy_name, /^u_[0-9a-f]{16}$/); // "needs aal2" has a space: hashed
    assert.equal(aal.requires_aal2, true); assert.equal(aal.owner_comparison, false);
    for (const p of q.rls_policies) for (const v of Object.values(p)) assert.notEqual(v, "not_read", p.policy_name);

    assert.deepEqual(q.default_acl, [ // ORDER BY puts the global default (schema NULL) last
      // authenticated is a Data API grantee, flagged true; postgres is known as not one, false
      { schema_name: "app", object_type: "table", grantor: "postgres", grantee: "authenticated", privileges: ["insert", "select"], api_grantee: true },
      { schema_name: null, object_type: "function", grantor: "postgres", grantee: "postgres", privileges: ["execute"], api_grantee: false },
    ]);
    assert.ok(q.schema_privileges.some((x) => x.schema_name === "app" && x.grantee === "authenticated" && x.usage && !x.create));
    assert.ok(!q.schema_privileges.some((x) => x.grantee === "postgres"), "the owner's own rights are left out");
    assert.ok(!("server_version" in q), "server_version is not collected");
    assert.deepEqual(q.triggers, [{ schema_name: "app", table_name: "notes", trigger_name: "notes_touch", timing: "before", events: ["insert", "update"], enabled: "origin" }]);
    const cons = Object.fromEntries(q.constraints.map((c) => [c.constraint_name, c]));
    // NOT VALID constraints still bind every new or changed row: kept.
    assert.equal(cons.notes_tenant_ok.type, "check");
    assert.deepEqual(cons.orders_email_fk, { schema_name: "app", table_name: "orders", constraint_name: "orders_email_fk", type: "foreign", columns: ["email"], expression: false, partial: false, referenced_table: "app.customers" });
    // A ready but invalid unique index (a failed concurrent build) still enforces on writes: kept; one not ready: left out.
    assert.deepEqual(pick(cons.orders_code_invalid, ["type", "columns"]), { type: "unique_index", columns: ["id", "code"] });
    assert.equal(cons.orders_ref_not_ready, undefined);
    assert.deepEqual(cons.notes_pkey, { schema_name: "app", table_name: "notes", constraint_name: "notes_pkey", type: "primary", columns: ["id"], expression: false, partial: false, referenced_table: null });
    assert.deepEqual(cons.notes_body_len.columns, ["body"]);
    assert.equal(cons.links_note_id_fkey.referenced_table, "app.notes");
    assert.deepEqual(cons.links_slug, { schema_name: "app", table_name: "links", constraint_name: "links_slug", type: "unique_index", columns: ["slug"], expression: false, partial: false, referenced_table: null });
    assert.deepEqual(pick(cons.links_lower_other, ["type", "columns", "expression", "partial"]), { type: "unique_index", columns: [], expression: true, partial: true });
    assert.deepEqual(q.realtime_publication, [{ publication: "supabase_realtime", schema_name: "app", table_name: "notes" }]);
    const conn = q.connected_roles.filter((x) => x.role_name === "app_user");
    assert.deepEqual(conn, [{ role_name: "app_user", application: "other", sessions: 1 }, { role_name: "app_user", application: "postgrest", sessions: 2 }]);
    assert.ok(!q.connected_roles.some((x) => x.role_name === "phisc_ro"), "the inspector's own session is left out");

    const text = JSON.stringify(out);
    for (const s of ["auth.uid", "auth.jwt", "'user_metadata'", "->>", "PostgREST 12", "Metabase", "Odd Name"]) assert.ok(!text.includes(s), s);
  } finally {
    for (const c of sessions) await c.end().catch(() => {});
    await cluster.admin.query(V2_TEARDOWN);
  }
});

test("Every shipped catalog query runs as phisc_ro after the preflight, on the v2 setup", { skip }, async () => {
  await cluster.admin.query(V2_SETUP);
  try {
    const all = SHIPPED_QUERY_IDS.map((id) => ({ query_id: id, sql: shippedQuerySql(id), row_limit: 20000 }));
    const r = await collectCatalog(cluster.ro, all);
    assert.equal(r.preflight.passed, true, JSON.stringify(r.preflight.failed));
    const got = Object.fromEntries(r.queries.map((q) => [q.query_id, [q.status, q.reason]]));
    // This server has no Supabase Storage, so storage_buckets doesn't run (platform_mismatch; the storage tests below
    // run it where there is one). Every other query runs.
    assert.deepEqual(got.storage_buckets, ["not_run", "platform_mismatch"]);
    for (const id of SHIPPED_QUERY_IDS.filter((q) => q !== "storage_buckets")) {
      assert.ok(["ok", "empty"].includes(got[id][0]), `${id}: ${got[id]}`);
    }
    const rows = Object.fromEntries(r.queries.map((q) => [q.query_id, q.rows]));
    const pol = rows.rls_policies.find((p) => p.policy_name === "own_select");
    assert.deepEqual(pol.roles, ["authenticated"]);
    assert.equal(typeof pol.using_expression, "string");
  } finally {
    await cluster.admin.query(V2_TEARDOWN);
  }
});

const STORAGE_SETUP = `
  CREATE ROLE supabase_storage_admin NOLOGIN;
  CREATE SCHEMA storage;
  CREATE TABLE storage.buckets (id text PRIMARY KEY, name text, public boolean, file_size_limit bigint, allowed_mime_types text[]);
  CREATE TABLE storage.objects (id int, bucket_id text, name text, owner_id text);
  ALTER TABLE storage.objects ENABLE ROW LEVEL SECURITY;
  INSERT INTO storage.buckets VALUES ('scans', 'scans', true, 1048576, '{image/png}');
  CREATE POLICY "anyone reads scans" ON storage.objects FOR SELECT USING (bucket_id = 'scans');
  ALTER TABLE storage.buckets OWNER TO supabase_storage_admin;
  GRANT USAGE ON SCHEMA storage TO phisc_ro;
  GRANT SELECT ON storage.buckets TO phisc_ro;`;
const STORAGE_TEARDOWN = "DROP SCHEMA storage CASCADE; DROP ROLE supabase_storage_admin;";
const SHIPPED_STORAGE = () => ({ query_id: "storage_buckets", sql: shippedQuerySql("storage_buckets"), row_limit: 500 });
const statusOf = async (opts = {}) => {
  const r = await collectCatalog(cluster.ro, [SHIPPED_STORAGE()], opts);
  assert.equal(r.preflight.passed, true, JSON.stringify(r.preflight.failed));
  return r.queries[0];
};

test("storage.buckets, and only it, may be read: storage_buckets runs and any other non-catalog schema is refused", { skip }, async () => {
  await cluster.admin.query(STORAGE_SETUP);
  try {
    const others = [
      { query_id: "objects", sql: "SELECT o.name FROM storage.objects o ORDER BY 1" },
      { query_id: "quoted", sql: 'SELECT b.id FROM "storage".buckets b ORDER BY 1' },
      { query_id: "app", sql: "SELECT p.name FROM app.patients p ORDER BY 1" },
      { query_id: "not_storage_buckets", sql: "SELECT b.id FROM ONLY storage.buckets b ORDER BY 1" },
    ];
    const r = await collectCatalog(cluster.ro, [SHIPPED_STORAGE(), ...others]);
    assert.equal(r.preflight.passed, true, JSON.stringify(r.preflight.failed));
    assert.deepEqual(r.queries.map((q) => [q.query_id, q.status, q.reason]), [["storage_buckets", "ok", null],
      ["objects", "failed", "non_catalog_reference"], ["quoted", "failed", "non_catalog_reference"],
      ["app", "failed", "non_catalog_reference"], ["not_storage_buckets", "failed", "non_catalog_reference"]]);
    assert.deepEqual(r.queries[0].rows.map((b) => [b.bucket, b.public, b.open_read_policies]), [["scans", true, ["anyone reads scans"]]]);
    // Reading any other storage relation is still a readable table: the preflight fails.
    await cluster.admin.query("GRANT SELECT ON storage.objects TO phisc_ro");
    const again = await collectCatalog(cluster.ro, [SHIPPED_STORAGE()]);
    assert.equal(again.preflight.passed, false);
    assert.ok(again.preflight.failed.includes("readable_tables"));
  } finally {
    await cluster.admin.query(STORAGE_TEARDOWN);
  }
});

test("storage_buckets is not_permitted while row-level security hides storage.buckets from the role", { skip }, async () => {
  await cluster.admin.query(STORAGE_SETUP);
  try {
    await cluster.admin.query("ALTER TABLE storage.buckets ENABLE ROW LEVEL SECURITY");
    const hidden = await statusOf();
    assert.deepEqual([hidden.status, hidden.reason, hidden.rows], ["failed", "permission_denied", []]);
    assert.equal(catalogReason(hidden.reason), "not_permitted"); // so storage-buckets-private is unknown, not not_applicable
    // A policy for another role doesn't help; one for this role (the documented setup) does.
    await cluster.admin.query("CREATE ROLE someone_else NOLOGIN; CREATE POLICY other ON storage.buckets FOR SELECT TO someone_else USING (true)");
    assert.equal((await statusOf()).reason, "permission_denied");
    await cluster.admin.query("CREATE POLICY phisc_read ON storage.buckets FOR SELECT TO phisc_ro USING (true)");
    assert.deepEqual([(await statusOf()).status], ["ok"]);
  } finally {
    await cluster.admin.query(STORAGE_TEARDOWN + " DROP ROLE IF EXISTS someone_else;");
  }
});

test("storage_buckets is ok only when row-level security provably hides no bucket; otherwise truncated, not_permitted", { skip }, async () => {
  await cluster.admin.query(STORAGE_SETUP);
  await cluster.admin.query("INSERT INTO storage.buckets VALUES ('records', 'records', false, NULL, NULL)");
  try {
    await cluster.admin.query("ALTER TABLE storage.buckets ENABLE ROW LEVEL SECURITY");
    // A: a permissive policy for PUBLIC that shows only public buckets: rows come back, but not provably all of them.
    await cluster.admin.query("CREATE POLICY pub ON storage.buckets FOR SELECT USING (public)");
    let r = await statusOf();
    assert.deepEqual([r.status, r.reason, r.rows.map((x) => x.bucket)], ["truncated", "row_security_filtered", ["scans"]]);
    assert.equal(catalogReason(r.reason), "not_permitted");
    // B: USING true, but a restrictive policy also applies: still not provable.
    await cluster.admin.query("DROP POLICY pub ON storage.buckets; CREATE POLICY everything ON storage.buckets FOR SELECT USING (true);"
      + " CREATE POLICY only_public ON storage.buckets AS RESTRICTIVE FOR SELECT USING (public)");
    r = await statusOf();
    assert.deepEqual([r.status, r.reason], ["truncated", "row_security_filtered"]);
    // The documented setup: USING true for phisc_ro and no restrictive policy: every bucket, ok.
    await cluster.admin.query("DROP POLICY everything ON storage.buckets; DROP POLICY only_public ON storage.buckets;"
      + " CREATE POLICY phisc_read ON storage.buckets FOR SELECT TO phisc_ro USING (true)");
    r = await statusOf();
    assert.deepEqual([r.status, r.reason, r.rows.map((x) => x.bucket).sort()], ["ok", null, ["records", "scans"]]);
    // RLS off: ok.
    await cluster.admin.query("ALTER TABLE storage.buckets DISABLE ROW LEVEL SECURITY");
    assert.equal((await statusOf()).status, "ok");
    // The fact document side: truncated with not_permitted, never ok.
    await cluster.admin.query("ALTER TABLE storage.buckets ENABLE ROW LEVEL SECURITY; DROP POLICY phisc_read ON storage.buckets;"
      + " CREATE POLICY pub ON storage.buckets FOR SELECT USING (public)");
    const fact = toFactCatalog({ status: "ok", count: 0, reason: null, preflight: GOOD_PREFLIGHT, queries: [await statusOf()] }, { key: "k" });
    assert.deepEqual([fact.catalog.queries[0].status, fact.catalog.queries[0].reason, fact.collection.status], ["truncated", "not_permitted", "truncated"]);
  } finally {
    await cluster.admin.query(STORAGE_TEARDOWN);
  }
});

test("storage_buckets runs only on Supabase: the platform's provider, else the catalog's Supabase-owned shape", { skip }, async () => {
  await cluster.admin.query(STORAGE_SETUP);
  try {
    assert.equal((await statusOf()).status, "ok"); // no provider: Supabase's own storage.buckets
    assert.deepEqual(await statusOf({ provider: "rds" }), { query_id: "storage_buckets", status: "not_run", reason: "platform_mismatch", rows: [] });
    assert.equal(catalogReason("platform_mismatch"), "platform_mismatch");
    await cluster.admin.query("ALTER TABLE storage.buckets OWNER TO postgres"); // a storage.buckets of the app's own
    assert.equal((await statusOf()).status, "not_run");
    assert.equal((await statusOf({ provider: "supabase" })).status, "ok");
    await cluster.admin.query("DROP SCHEMA storage CASCADE; CREATE SCHEMA storage;");
    assert.equal((await statusOf({ provider: "supabase" })).reason, "platform_mismatch"); // no Supabase Storage here
  } finally {
    await cluster.admin.query(STORAGE_TEARDOWN);
  }
});

test("A table inheriting from storage.buckets is readable data: the preflight fails and no child row is read", { skip }, async () => {
  await cluster.admin.query(STORAGE_SETUP);
  try {
    await cluster.admin.query(`CREATE TABLE app.bucket_child (note text) INHERITS (storage.buckets);
      INSERT INTO app.bucket_child (id, name, public, note) VALUES ('MRN-12345', 'x', true, 'Jane Doe');`);
    const r = await collectCatalog(cluster.ro, [SHIPPED_STORAGE()]);
    assert.equal(r.preflight.passed, false);
    assert.ok(r.preflight.failed.includes("readable_tables"));
    assert.ok(!JSON.stringify(r).includes("MRN-12345"));
  } finally {
    await cluster.admin.query("DROP TABLE IF EXISTS app.bucket_child; " + STORAGE_TEARDOWN);
  }
});

test("No function body or view definition reaches a query's rows or the fact document", { skip }, async () => {
  const MARK = "zqx_body_marker_7f3a";
  await cluster.admin.query(V2_SETUP);
  await cluster.admin.query(`
    CREATE FUNCTION app.marked_helper() RETURNS boolean LANGUAGE sql STABLE
      AS $$ SELECT '${MARK}' IS NOT NULL /* ${MARK} raw_user_meta_data */ $$;
    CREATE POLICY marked ON app.notes FOR SELECT USING (app.marked_helper());
    CREATE FUNCTION app.marked_definer() RETURNS text LANGUAGE sql SECURITY DEFINER AS $$ SELECT '${MARK}' $$;
    CREATE VIEW app.marked_view AS SELECT '${MARK}'::text AS v;`);
  try {
    const all = SHIPPED_QUERY_IDS.map((id) => ({ query_id: id, sql: shippedQuerySql(id), row_limit: 20000 }));
    const r = await collectCatalog(cluster.ro, all);
    assert.equal(r.preflight.passed, true, JSON.stringify(r.preflight.failed));
    assert.ok(!JSON.stringify(r).includes(MARK), "a definition left the database");
    const marked = r.queries.find((q) => q.query_id === "rls_policies").rows.find((p) => p.policy_name === "marked");
    assert.equal(marked.reads_user_metadata, true); // the helper's body was read, in SQL
    assert.equal(marked.using_expression, "app.marked_helper()"); // the policy's own expression: a call by name
    const out = toFactCatalog(r, { key: "test-install-key" });
    const text = JSON.stringify(out);
    assert.ok(!text.includes(MARK) && !text.includes("using_expression") && !text.includes("marked_helper()"));
  } finally {
    await cluster.admin.query("DROP VIEW app.marked_view; DROP FUNCTION app.marked_definer(); DROP POLICY marked ON app.notes; DROP FUNCTION app.marked_helper();");
    await cluster.admin.query(V2_TEARDOWN);
  }
});

test("v2: without a passed preflight every v2 query is not_run with preflight_failed, and the document still fits", { skip }, async () => {
  await cluster.admin.query("GRANT TRIGGER ON app.patients TO phisc_ro");
  try {
    const r = await collectCatalog(cluster.ro, V2_QUERIES);
    const out = toFactCatalog(r, { key: "k" });
    assert.ok(validateV2(out), JSON.stringify(validateV2.errors));
    assert.deepEqual(out.catalog.preflight.failed, ["write_privileges"]);
    assert.ok(out.catalog.queries.every((q) => q.status === "not_run" && q.reason === "preflight_failed" && q.rows.length === 0));
    assert.deepEqual(out.collection, { collector: "catalog", status: "failed", count: 0, reason: "preflight_failed" });
  } finally { await cluster.admin.query("REVOKE TRIGGER ON app.patients FROM phisc_ro"); }
});

test("v2: the policy print-form fixture matches what this server's pg_get_expr prints", { skip }, async () => {
  const setup = readFileSync(new URL("./fixtures/policies/pg16-print-forms.setup.sql", import.meta.url), "utf8");
  const want = JSON.parse(readFileSync(new URL("./fixtures/policies/pg16-print-forms.json", import.meta.url), "utf8"));
  await cluster.admin.query("CREATE DATABASE print_forms");
  const c = new pg.Client({ host: "127.0.0.1", port: cluster.port, user: "postgres", database: "print_forms",
    password: cluster.admin.connectionParameters.password, ssl: false });
  try {
    await c.connect();
    await c.query(setup);
    await c.query("SET search_path = pg_catalog, pg_temp");
    const got = (await c.query(`SELECT p.polname AS name, p.polcmd::text AS cmd, pg_get_expr(p.polqual, p.polrelid) AS using,
      pg_get_expr(p.polwithcheck, p.polrelid) AS check FROM pg_policy p ORDER BY p.polname`)).rows;
    assert.deepEqual(got, want);
  } finally {
    await c.end().catch(() => {});
    await cluster.admin.query("DROP DATABASE print_forms");
  }
});

/* ---------- review round 2 ---------- */

test("v2 r2: CREATEDB through membership, default CREATE on schemas and USAGE on a foreign server are refused; CREATE on a tablespace isn't", { skip }, async () => {
  const cases = [
    ["CREATE ROLE dbmaker NOLOGIN CREATEDB; GRANT dbmaker TO phisc_ro WITH INHERIT FALSE", "REVOKE dbmaker FROM phisc_ro; DROP ROLE dbmaker",
      "write_privileges: write_createdb"],
    ["ALTER DEFAULT PRIVILEGES FOR ROLE postgres GRANT CREATE ON SCHEMAS TO phisc_ro",
      "ALTER DEFAULT PRIVILEGES FOR ROLE postgres REVOKE CREATE ON SCHEMAS FROM phisc_ro", "write_privileges: write_default_privileges"],
    ["CREATE FOREIGN DATA WRAPPER r2_fdw; CREATE SERVER r2_srv FOREIGN DATA WRAPPER r2_fdw; GRANT USAGE ON FOREIGN SERVER r2_srv TO phisc_ro",
      "DROP SERVER r2_srv; DROP FOREIGN DATA WRAPPER r2_fdw", "write_privileges: write_foreign_servers"],
    ["GRANT CREATE ON SCHEMA app TO phisc_ro", "REVOKE CREATE ON SCHEMA app FROM phisc_ro", "write_privileges: write_schemas"],
    ["CREATE TABLE app.w2 (id int); GRANT INSERT ON app.w2 TO phisc_ro; GRANT CREATE ON DATABASE postgres TO phisc_ro",
      "DROP TABLE app.w2; REVOKE CREATE ON DATABASE postgres FROM phisc_ro", "write_privileges: write_relations, write_database"],
  ];
  for (const [grant, undo, message] of cases) {
    const r = await refusedWith(grant, undo, "write_privileges");
    // The parts that failed are named locally; the fact document carries only the total and the check.
    assert.equal(r.preflight.message, message, grant);
    assert.equal(r.message, message, grant);
    const fact = toFactCatalog(r, { key: "k" });
    assert.ok(!/write_(relations|large_objects|schemas|database|default_privileges|createdb|foreign_servers)|user_casts|"message"/.test(JSON.stringify(fact)), grant);
    assert.ok(validateV2(fact), JSON.stringify(validateV2.errors));
  }
  // A foreign server with no USAGE granted, and CREATE on a tablespace: allowed.
  await cluster.admin.query("CREATE FOREIGN DATA WRAPPER r2_fdw; CREATE SERVER r2_srv FOREIGN DATA WRAPPER r2_fdw; GRANT CREATE ON TABLESPACE pg_default TO phisc_ro");
  try {
    const r = await collectCatalog(cluster.ro, QUERIES);
    assert.equal(r.preflight.passed, true, r.preflight.message);
    assert.deepEqual(r.preflight.write_parts, { relations: 0, large_objects: 0, schemas: 0, database: 0, default_privileges: 0, createdb: 0, foreign_servers: 0, fdw: 0 });
  } finally { await cluster.admin.query("REVOKE CREATE ON TABLESPACE pg_default FROM phisc_ro; DROP SERVER r2_srv; DROP FOREIGN DATA WRAPPER r2_fdw"); }
});

const CONSTRAINTS_QUERY = V2_QUERIES.find((q) => q.query_id === "constraints");

test("v2 r2: a partitioned unique index made ON ONLY enforces nothing until attached everywhere: left out until then", { skip }, async () => {
  await cluster.admin.query(`
    CREATE TABLE app.pp (tenant_id int, x int) PARTITION BY LIST (tenant_id);
    CREATE TABLE app.pp1 PARTITION OF app.pp FOR VALUES IN (1);
    CREATE TABLE app.pp2 PARTITION OF app.pp FOR VALUES IN (2);
    CREATE UNIQUE INDEX pp_x ON ONLY app.pp (tenant_id, x);
    ALTER TABLE ONLY app.pp ADD CONSTRAINT pp_u UNIQUE (tenant_id, x);
    INSERT INTO app.pp VALUES (1, 1), (1, 1), (2, 5), (2, 5);
    CREATE TABLE app.qq (tenant_id int, x int) PARTITION BY LIST (tenant_id);
    CREATE TABLE app.qq1 PARTITION OF app.qq FOR VALUES IN (1);
    CREATE TABLE app.qq2 PARTITION OF app.qq FOR VALUES IN (2);
    CREATE UNIQUE INDEX qq_x ON ONLY app.qq (tenant_id, x);
    CREATE UNIQUE INDEX qq1_x ON app.qq1 (tenant_id, x);
    ALTER INDEX app.qq_x ATTACH PARTITION app.qq1_x;
    CREATE TABLE app.rr (tenant_id int, x int) PARTITION BY LIST (tenant_id);
    CREATE TABLE app.rr1 PARTITION OF app.rr FOR VALUES IN (1);
    ALTER TABLE app.rr ADD CONSTRAINT rr_u UNIQUE (tenant_id, x);`);
  const names = async () => {
    const r = await collectCatalog(cluster.ro, [CONSTRAINTS_QUERY]);
    assert.equal(r.queries[0].status, "ok", r.queries[0].reason);
    return new Set(r.queries[0].rows.map((x) => x.constraint_name));
  };
  try {
    let n = await names();
    for (const gone of ["pp_x", "pp_u", "qq_x"]) assert.ok(!n.has(gone), `${gone} is reported while it enforces nothing`);
    assert.ok(n.has("qq1_x") && n.has("rr_u") && n.has("rr1_tenant_id_x_key"), [...n].join(","));
    // Attached on every partition: Postgres marks the parent index valid, and it is reported.
    await cluster.admin.query("CREATE UNIQUE INDEX qq2_x ON app.qq2 (tenant_id, x); ALTER INDEX app.qq_x ATTACH PARTITION app.qq2_x;");
    n = await names();
    assert.ok(n.has("qq_x"));
    assert.ok(!n.has("pp_x") && !n.has("pp_u"));
  } finally { await cluster.admin.query("DROP TABLE app.pp, app.qq, app.rr"); }
});

/* A database of its own with the reviewer's user-defined cast (public.tag to text through public.tag_to_text). */
async function inDatabase(name, sql, fn) {
  await cluster.admin.query(`CREATE DATABASE ${name}`);
  const c = new pg.Client({ host: "127.0.0.1", port: cluster.port, user: "postgres", database: name,
    password: cluster.admin.connectionParameters.password, ssl: false });
  try {
    await c.connect(); await c.query(sql); await c.end();
    const conn = { ...cluster.ro, dbname: name };
    Object.defineProperty(conn, "password", { value: cluster.roPw, enumerable: false });
    return await fn(conn);
  } finally { await c.end().catch(() => {}); await cluster.admin.query(`DROP DATABASE ${name}`); }
}
const CAST_SETUP = readFileSync(new URL("./fixtures/policies/user-cast.setup.sql", import.meta.url), "utf8");

test("v2 r2: a user-defined implicit cast to text makes every policy field not_read; an explicit one turns cast look-through off", { skip }, async () => {
  await inDatabase("casts_implicit", CAST_SETUP, async (conn) => {
    const r = await collectCatalog(conn, [RLS_TEST_QUERY]);
    assert.equal(r.preflight.passed, true, r.preflight.message);
    assert.deepEqual(r.preflight.user_casts, { any: 1, implicit: 1 });
    const out = toFactCatalog(r, { key: "k" });
    assert.ok(validateV2(out), JSON.stringify(validateV2.errors));
    const rows = out.catalog.queries[0].rows;
    assert.equal(rows.length, 4);
    for (const p of rows) for (const f of ["owner_comparison", "owner_using", "owner_required", "owner_source_untrusted", "tenant_comparison", "requires_aal2"]) {
      assert.equal(p[f], "not_read", `${p.policy_name} ${f}`);
    }
  });
  // Without the implicit cast (and b01, which needs it) and without setup2's own public.= (and b02, which uses it).
  const explicit = CAST_SETUP.replace(" as implicit;", ";").split("\n")
    .filter((l) => !/^create policy b0[12] |operator public\.= |function public\.always/.test(l)).join("\n");
  await inDatabase("casts_explicit", explicit, async (conn) => {
    const r = await collectCatalog(conn, [RLS_TEST_QUERY]);
    assert.deepEqual(r.preflight.user_casts, { any: 1, implicit: 0 });
    const out = toFactCatalog(r, { key: "k" });
    assert.ok(validateV2(out), JSON.stringify(validateV2.errors));
    const pol = Object.fromEntries(out.catalog.queries[0].rows.map((p) => [p.policy_name, p]));
    assert.equal(pol.b04.owner_using, "not_read", "tg::text could run tag_to_text: a cast not looked through is not_read");
    assert.equal(pol.b03.tenant_using, true, "no cast to look through: still a comparison");
  });
  // With no user cast, the main database reads casts as before.
  const r = await collectCatalog(cluster.ro, QUERIES);
  assert.deepEqual(r.preflight.user_casts, { any: 0, implicit: 0 });
});

test("a built-in = whose oprcode points at another function counts as user-defined", { skip }, async () => {
  // A superuser repoints text = text at an always-true function in a throwaway database (a catalog edit, not DDL).
  const setup = `create function public.always_eq(text, text) returns boolean language sql immutable as 'select true';
    update pg_catalog.pg_operator set oprcode = 'public.always_eq'::regproc where oid = 'pg_catalog.=(text,text)'::regoperator;
    create table public.notes (id int, owner text);
    alter table public.notes enable row level security;
    create policy own on public.notes for select using (owner = current_setting('request.jwt.claim.sub', true));`;
  await inDatabase("user_oprcode", setup, async (conn) => {
    const r = await collectCatalog(conn, [RLS_TEST_QUERY]);
    assert.equal(r.preflight.passed, true, r.preflight.message);
    assert.ok(r.preflight.user_operators >= 1, String(r.preflight.user_operators));
    const out = toFactCatalog(r, { key: "k" });
    assert.ok(validateV2(out), JSON.stringify(validateV2.errors));
    const own = out.catalog.queries[0].rows.find((p) => p.policy_name === "own");
    for (const f of ["owner_comparison", "owner_using", "owner_required", "owner_source_untrusted", "tenant_comparison", "requires_aal2"]) {
      assert.equal(own[f], "not_read", f);
    }
  });
});

/* ---------- merge review ---------- */

test("v2 merge: USAGE on a foreign data wrapper is refused (write_fdw)", { skip }, async () => {
  for (const grantee of ["phisc_ro", "PUBLIC"]) {
    const r = await refusedWith(`CREATE FOREIGN DATA WRAPPER m_fdw; GRANT USAGE ON FOREIGN DATA WRAPPER m_fdw TO ${grantee}`,
      "DROP FOREIGN DATA WRAPPER m_fdw", "write_privileges");
    assert.equal(r.preflight.message, "write_privileges: write_fdw", grantee);
    assert.equal(r.preflight.write_parts.fdw, 1);
  }
  await cluster.admin.query("CREATE FOREIGN DATA WRAPPER m_fdw");
  try { assert.equal((await collectCatalog(cluster.ro, QUERIES)).preflight.passed, true); }
  finally { await cluster.admin.query("DROP FOREIGN DATA WRAPPER m_fdw"); }
});

test("v2 merge: a user-defined = (IS NOT DISTINCT FROM hides which one) makes every policy field not_read", { skip }, async () => {
  const setup = readFileSync(new URL("./fixtures/policies/user-operator.setup.sql", import.meta.url), "utf8");
  await inDatabase("user_ops", setup, async (conn) => {
    const r = await collectCatalog(conn, [RLS_TEST_QUERY]);
    assert.equal(r.preflight.passed, true, r.preflight.message);
    assert.equal(r.preflight.user_operators, 3);
    assert.deepEqual(r.preflight.user_casts, { any: 0, implicit: 0 });
    const out = toFactCatalog(r, { key: "k" });
    assert.ok(validateV2(out), JSON.stringify(validateV2.errors));
    const pol = Object.fromEntries(out.catalog.queries[0].rows.map((p) => [p.policy_name, p]));
    assert.equal(Object.keys(pol).length, 13);
    // d10: owner IS NOT DISTINCT FROM the JWT's sub, resolved to an always-true public.= but printed as plain SQL.
    for (const p of Object.values(pol)) {
      for (const f of ["owner_comparison", "owner_using", "owner_required", "owner_source_untrusted", "tenant_comparison", "requires_aal2"]) {
        assert.equal(p[f], "not_read", `${p.policy_name} ${f}`);
      }
    }
  });
  // The same database with only the operators gone (and the policies that need them) reads again.
  const clean = readFileSync(new URL("./fixtures/policies/user-operator.setup.sql", import.meta.url), "utf8")
    .split("\n").filter((l) => !/operator public|function public\.always|policy d03 /.test(l)).join("\n"); // d03 needs text = uuid
  await inDatabase("user_ops_clean", clean, async (conn) => {
    const r = await collectCatalog(conn, [RLS_TEST_QUERY]);
    assert.equal(r.preflight.user_operators, 0);
    const pol = Object.fromEntries(toFactCatalog(r, { key: "k" }).catalog.queries[0].rows.map((p) => [p.policy_name, p]));
    assert.equal(pol.d10.owner_comparison, true);
  });
});

/* ---------- preflightOnly (custosa doctor) ---------- */

test("preflightOnly refuses a missing service, a wrong user, a host without TLS and an unreachable host", async () => {
  const base = { host: "127.0.0.1", port: await freePort(), dbname: "d", user: "phisc_ro", sslmode: "prefer" };
  const error = (reason) => ({ status: "error", reason, message: null, preflight: null });
  assert.deepEqual(await preflightOnly(null), error("service_missing"));
  assert.deepEqual(await preflightOnly({ ...base, user: "boss" }), error("wrong_user"));
  assert.deepEqual(await preflightOnly({ ...base, host: "192.0.2.10" }), error("tls_required"));
  assert.deepEqual(await preflightOnly(base, { connectTimeoutMs: 2000 }), error("unreachable"));
});

test("preflightOnly gives the same preflight as collectCatalog: passed, refused, and a wrong password", { skip }, async () => {
  const full = await collectCatalog(cluster.ro, QUERIES);
  const only = await preflightOnly(cluster.ro);
  assert.equal(only.status, "passed"); assert.equal(only.reason, null); assert.equal(only.message, null);
  assert.deepEqual(only.preflight, full.preflight);
  await cluster.admin.query("GRANT SELECT ON app.patients TO phisc_ro");
  try {
    const refused = await preflightOnly(cluster.ro);
    assert.equal(refused.status, "failed"); assert.equal(refused.reason, "preflight_failed");
    assert.deepEqual(refused.preflight.failed, ["readable_tables"]);
    assert.equal(refused.message, "readable_tables");
    assert.deepEqual(refused.preflight, (await collectCatalog(cluster.ro, QUERIES)).preflight);
  } finally { await cluster.admin.query("REVOKE SELECT ON app.patients FROM phisc_ro"); }
  const conn = { ...cluster.ro }; Object.defineProperty(conn, "password", { value: "wrong-" + secret() });
  assert.deepEqual(await preflightOnly(conn), { status: "error", reason: "auth_failed", message: null, preflight: null });
});

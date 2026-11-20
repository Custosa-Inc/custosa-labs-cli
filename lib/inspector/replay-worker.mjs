/* The migration replay's engine (T29 gap 2, T29-P1-C562): an in-process Postgres (PGlite, Postgres compiled to
 * WebAssembly) inside this worker thread, which replay.mjs starts, times and ends. No child process, no server, no
 * socket and no host path: the database lives in this worker's memory only and is gone when the worker ends.
 *
 * In:  workerData = {files: [{rel, up, statements}], stubs, extensions: [module names], queries, provider, deadline}
 * Out: messages to the parent, in order:
 *        {type: "ready"}                      the engine started and the setup (roles, stubs) applied
 *        {type: "applied", n}                 after each file that applied cleanly (n files so far)
 *        {type: "done", result}               the catalog, read by collectCatalogOn as phisc_ro
 *        {type: "failed", stage}              stage "setup" (no usable engine here), "file" (the next file failed) or
 *                                             "empty" (files that make tables left none)
 *      The parent ends the worker on its own clock: statement_timeout is not enforced in this engine (measured), and a
 *      statement can loop for ever, so a time cap from inside the worker would never fire.
 *
 * One engine has one session, so the files share it. Around each file:
 *   before  SET SESSION AUTHORIZATION custosa_migrator (role reset with it) and the migrator's search_path;
 *   after   the statement count (exec returns one result per statement; a session that died silently returns one
 *           empty result), then a canary that must return exactly one row saying no transaction is open or aborted
 *           and the session is still the migrator's, then SET SESSION AUTHORIZATION postgres, RESET ROLE, RESET ALL,
 *           checked. RESET SESSION AUTHORIZATION is not used: in this engine it does not restore the superuser.
 *   Any miss is a failed file. COPY ... PROGRAM, a file_fdw program table and unbounded recursion end the session
 *   with no error (measured); the count and the canary catch all three, and a session that hangs is the parent's
 *   timer's. Nothing is logged: console is silenced first, since the parent's stdout may be an MCP stream. */
import { parentPort, workerData } from "node:worker_threads";

for (const k of ["log", "info", "warn", "error", "debug", "trace"]) console[k] = () => {};

const MIGRATOR = "custosa_migrator";
const READER = "phisc_ro";
const SUPER = "postgres";

const send = (m) => parentPort.postMessage(m);

/* The pg driver's own text parsers, so a row reads exactly as it would from a live database through pg. */
async function pgParsers() {
  const { default: pg } = await import("pg");
  return new Proxy({}, { get: (_, oid) => {
    const id = Number(oid);
    if (!Number.isInteger(id)) return undefined;
    const parse = pg.types.getTypeParser(id, "text");
    return (v) => parse(v);
  } });
}

/* A pg-like client on the engine's one session, for collectCatalogOn. */
function sessionOf(db, parsers) {
  return {
    async query(q) {
      const text = typeof q === "string" ? q : q.text;
      const r = await db.query(text, [], { parsers });
      return { rows: r.rows, fields: r.fields.map((f) => ({ name: f.name })) };
    },
  };
}

const CANARY = `SELECT pg_catalog.now() = pg_catalog.statement_timestamp() AS idle, 1 AS canary, SESSION_USER::text AS su,
  CURRENT_USER::text AS cu`;
const WHO = "SELECT SESSION_USER::text AS su, CURRENT_USER::text AS cu";
const BEFORE = `SET SESSION AUTHORIZATION ${MIGRATOR}; SET search_path TO "$user", public, extensions`;
const AFTER = `SET SESSION AUTHORIZATION ${SUPER}; RESET ROLE; RESET ALL`;

/* Files that make tables and a replay that ends with no table of the app's own: failed, never an empty catalog. */
const OWN_TABLES = `SELECT count(*)::int AS n FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
  WHERE c.relkind IN ('r', 'p') AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'auth', 'storage', 'extensions')
  AND n.nspname NOT LIKE 'pg\\_%'`;

function bootstrapSql() {
  return `
CREATE ROLE ${MIGRATOR} LOGIN NOSUPERUSER NOBYPASSRLS NOREPLICATION CREATEROLE NOCREATEDB;
ALTER DATABASE ${SUPER} OWNER TO ${MIGRATOR};
ALTER SCHEMA public OWNER TO ${MIGRATOR};
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
`;
}

async function applyFile(db, f) {
  await db.exec(BEFORE);
  if (f.statements > 0) {
    let results;
    try { results = await db.exec(f.up); } catch { return false; }
    if (!Array.isArray(results) || results.length !== f.statements) return false;
  }
  // The canary goes as a simple query, as one statement on its own: inside an open transaction now() is the
  // transaction's start, earlier than this statement's. (Through the extended protocol the two can differ by a tick
  // even with no transaction open, measured, so that path would fail clean files.)
  let c;
  try { c = await db.exec(CANARY); } catch { return false; }
  const rows = Array.isArray(c) && c.length === 1 && Array.isArray(c[0]?.rows) ? c[0].rows : [];
  const row = rows.length === 1 ? rows[0] : null;
  if (!row || row.idle !== true || row.canary !== 1 || row.su !== MIGRATOR) return false;
  try { await db.exec(AFTER); } catch { return false; }
  const who = await db.query(WHO);
  return who.rows.length === 1 && who.rows[0].su === SUPER && who.rows[0].cu === SUPER;
}

async function main() {
  const { files, stubs, extensions, queries, provider, deadline, testSetupSql } = workerData;
  let db, parsers;
  try {
    const { PGlite } = await import("@electric-sql/pglite");
    const ext = {};
    for (const name of extensions) {
      const mod = await import(`@electric-sql/pglite/contrib/${name}`);
      ext[name] = mod[name];
    }
    db = new PGlite({ extensions: ext });
    await db.waitReady;
    parsers = await pgParsers();
    await db.exec(bootstrapSql());
    if (stubs) await db.exec(stubs);
    if (testSetupSql) await db.exec(testSetupSql); // tests only: setup SQL run as the superuser before the files
    const who = await db.query(WHO);
    if (who.rows.length !== 1 || who.rows[0].su !== SUPER || who.rows[0].cu !== SUPER) throw new Error("setup");
  } catch {
    send({ type: "failed", stage: "setup" });
    return;
  }
  send({ type: "ready" });
  let n = 0;
  for (const f of files) {
    let ok;
    try { ok = await applyFile(db, f); } catch { ok = false; }
    if (!ok) { send({ type: "failed", stage: "file" }); return; }
    send({ type: "applied", n: ++n });
  }
  if (files.some((f) => f.makesTables)) {
    const t = await db.query(OWN_TABLES);
    if (t.rows.length !== 1 || t.rows[0].n === 0) { send({ type: "failed", stage: "empty" }); return; }
  }
  await db.exec(`CREATE ROLE ${READER} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
SET SESSION AUTHORIZATION ${READER}`);
  const { collectCatalogOn } = await import("./catalog.mjs");
  const result = await collectCatalogOn(sessionOf(db, parsers), queries, { deadline, ...(provider ? { provider } : {}) });
  send({ type: "done", result });
}

main().catch(() => send({ type: "failed", stage: "file" }));

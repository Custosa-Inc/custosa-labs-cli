/* Migration replay (T29 gap 2, T29-P1-C529, design lab/T29/gap-rls-sql): with no database to read, build a throwaway
 * Postgres from the repo's own migrations and read its catalog with the same collector (collectCatalog, as phisc_ro,
 * preflight first) that reads a live database. What it proves: the repo's migrations, applied in order to an empty
 * database, build these tables, policies and grants. It never proves what is deployed, so core grades a pass on it
 * apart (custosa_on_migrations) and a fail stands.
 *
 * findMigrationSet(root) -> {status: "found", kind, files: [{rel, abs, up}]} | {status: "none" | "refused", reason}
 *   Only one migration set, read from the project root, in its tool's own order:
 *     supabase  supabase/migrations/<digits>_<name>.sql (Supabase CLI; other names there are skipped, as the CLI does)
 *     prisma    prisma/migrations/<digits>_<name>/migration.sql
 *     plain     migrations/, db/migrations/, database/migrations/, sql/migrations/: Flyway V<version>__<name>.sql
 *               (U<version>__ undo files skipped), golang-migrate <n>_<name>.up.sql (.down.sql skipped), dbmate and
 *               plain <n>_<name>.sql (a dbmate file's `-- migrate:down` section is never applied)
 *   Refused (reason, nothing replayed): two sets in one repo (migration_sets_ambiguous), an order that can't be told
 *   (order_unknown: a .sql file with no version, versions of mixed width or schemes, a duplicate version, Flyway
 *   repeatable R__ files), a symlinked file or folder (symlink), too many or too large files (too_large).
 *   ORM code migrations (Rails, Django, Laravel, Knex, TypeORM) are not read: a named limit.
 *
 * conditionalDdl(text) -> true when the text holds SQL whose effect can differ between this replay and production:
 *   a DO block, dynamic EXECUTE in PL/pgSQL (not GRANT EXECUTE ON, nor EXECUTE FUNCTION / PROCEDURE in a trigger), a
 *   psql meta-command, or DDL inside a dollar-quoted body (a function that changes policies, RLS, grants or roles when
 *   it is called). Core holds every replayed pass when any file in the chain has one; fails still stand.
 *
 * replayCatalog(root, queries, opts) -> collectCatalog's result shape plus {source: "migrations", replay}, where
 *   replay = {kind, files, applied, conditional_ddl, failed_file}. status not_run with reason no_migrations,
 *   postgres_not_found, postgres_too_old or the findMigrationSet reason; failed with replay_failed (a migration
 *   errored, the time cap was hit, or the cluster would not start). Never a partial catalog: on any failure every
 *   query is not_run, so nothing from a half-built database is judged.
 *
 * The sandbox. The SQL is the repo's own, so it runs as if hostile:
 *   - a fresh cluster from the machine's own initdb in a new 0700 temp folder, deleted after (also on error and time
 *     out). No TCP at all (listen_addresses empty); the only socket is in that folder. A random port names it.
 *   - migrations run as custosa_migrator: LOGIN NOSUPERUSER NOBYPASSRLS NOREPLICATION CREATEROLE, on Postgres 16 or
 *     later only, where CREATEROLE can't grant roles it doesn't administer (so no pg_execute_server_program, no
 *     pg_read_server_files). Without superuser there is no COPY ... PROGRAM or file COPY, no server lo_import, no
 *     untrusted language, no extension that isn't marked trusted (dblink, postgres_fdw and file_fdw are not).
 *   - an event trigger, owned by the bootstrap superuser, refuses CREATE EXTENSION outside ALLOWED_EXTENSIONS.
 *   - caps: statement_timeout and temp_file_limit on the role, a whole-replay wall clock, a size cap per file and in
 *     total. A capped replay is a failed replay.
 *   - children get a scrubbed environment: no PG* variable (PGHOST, PGOPTIONS, PGPASSWORD, PGSERVICE...) and no
 *     DATABASE_URL, so no setting or database from the environment is ever used. Every connection names its socket,
 *     port, user and database, and passwords are random per replay.
 * Nothing here logs. No row value leaves: the catalog queries read the catalog only. */
import { execFile } from "node:child_process";
import { lstatSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { createHash, randomBytes, randomInt } from "node:crypto";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import pg from "pg";
import { collectCatalog } from "./catalog.mjs";

export const SOURCE = "migrations";
export const MIN_PG_MAJOR = 16;
export const FILE_MAX_BYTES = 1_000_000;
export const TOTAL_MAX_BYTES = 10_000_000;
export const FILES_MAX = 2000;
export const REPLAY_TIME_MS = 90_000;
export const STATEMENT_TIMEOUT_MS = 20_000;
export const TEMP_FILE_LIMIT = "256MB";
export const MIGRATOR = "custosa_migrator";
export const BOOT = "custosa_boot";
export const DBNAME = "app";
/* Trusted extensions that only add types, operators or functions. Anything else (pg_net, pg_graphql, vector, ...) is
 * refused, so the replay fails and the practice stays unknown. */
export const ALLOWED_EXTENSIONS = Object.freeze(["pgcrypto", "uuid-ossp", "citext", "pg_trgm", "btree_gin", "btree_gist",
  "hstore", "ltree", "unaccent", "fuzzystrmatch", "intarray", "cube", "isn", "plpgsql"]);
export const PLAIN_DIRS = Object.freeze(["migrations", "db/migrations", "database/migrations", "sql/migrations"]);

const notRunAll = (queries, reason) => queries.map((q) => ({ query_id: q.query_id, status: "not_run", reason, rows: [] }));

/* ---------------------------------------------------------------- finding and ordering the set */

function isDir(p) { try { return lstatSync(p).isDirectory(); } catch { return false; } }
function isLink(p) { try { return lstatSync(p).isSymbolicLink(); } catch { return false; } }
const exists = (p) => { try { lstatSync(p); return true; } catch { return false; } };

/* Compares two version tuples of digit strings, numerically. */
function compareVersions(a, b) {
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const x = BigInt(a[i] ?? "0"), y = BigInt(b[i] ?? "0");
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

const DOWN = /(^|[._-])(down|rollback|undo|revert)\.sql$/i;

/* One plain folder's files -> {files: [{name, version, up}]} or {refused: reason}. */
function orderPlain(names) {
  const out = [];
  const schemes = new Set();
  for (const name of names) {
    if (!name.toLowerCase().endsWith(".sql")) continue;
    let m;
    if ((m = /^U\d+(?:[._]\d+)*__.+\.sql$/.exec(name))) continue; // Flyway undo
    if (/^R__.+\.sql$/.test(name)) return { refused: "order_unknown" }; // Flyway repeatable: applied by checksum
    if ((m = /^V(\d+(?:[._]\d+)*)__.+\.sql$/.exec(name))) { schemes.add("flyway"); out.push({ name, version: m[1].split(/[._]/) }); continue; }
    if (DOWN.test(name)) continue;
    if ((m = /^(\d+)[_-].+\.sql$/.exec(name))) {
      schemes.add(/\.up\.sql$/i.test(name) ? "updown" : "numbered");
      out.push({ name, version: [m[1]], });
      continue;
    }
    return { refused: "order_unknown" }; // a .sql file with no version: its place in the order can't be told
  }
  if (schemes.size > 1) return { refused: "order_unknown" };
  // 1_x.sql beside 0002_y.sql: numeric and lexical order may differ. Numeric is the runners' rule (golang-migrate and
  // dbmate parse the number), so it is taken; two equal numbers can't be ordered and refuse below.
  out.sort((a, b) => compareVersions(a.version, b.version));
  for (let i = 1; i < out.length; i++) if (compareVersions(out[i - 1].version, out[i].version) === 0) return { refused: "order_unknown" };
  return { files: out };
}

export function findMigrationSet(root) {
  const sets = [];
  let refused = null;
  const sup = join(root, "supabase", "migrations");
  if (isLink(join(root, "supabase")) || isLink(sup)) refused ??= "symlink";
  else if (isDir(sup)) {
    const files = [];
    for (const name of readdirSync(sup).sort()) {
      const m = /^(\d+)_.*\.sql$/.exec(name);
      if (m) files.push({ rel: `supabase/migrations/${name}`, version: [m[1]], width: m[1].length });
    }
    if (files.length) {
      files.sort((a, b) => compareVersions(a.version, b.version));
      const dup = files.some((f, i) => i > 0 && compareVersions(files[i - 1].version, f.version) === 0);
      sets.push(dup ? { refused: "order_unknown" } : { kind: "supabase", files });
    }
  }
  const prisma = join(root, "prisma", "migrations");
  if (isLink(join(root, "prisma")) || isLink(prisma)) refused ??= "symlink";
  else if (isDir(prisma)) {
    const files = [];
    for (const name of readdirSync(prisma).sort()) {
      if (!/^\d+_/.test(name) || !isDir(join(prisma, name))) continue;
      if (exists(join(prisma, name, "migration.sql"))) files.push({ rel: `prisma/migrations/${name}/migration.sql` });
    }
    // C637 f3: a set Prisma wrote for another database (MySQL backticks, SQLite) is not Postgres SQL: no set, with
    // its own reason, rather than a replay that stops at file 1. No lock file, or no provider line: taken as before.
    let provider = null;
    try {
      const m = /^\s*provider\s*=\s*["']([^"']*)["']/m.exec(readFileSync(join(prisma, "migration_lock.toml"), "utf8"));
      if (m) provider = m[1].toLowerCase();
    } catch { /* no lock file */ }
    if (files.length && provider && !["postgresql", "postgres"].includes(provider)) refused ??= "provider_not_postgres";
    else if (files.length) sets.push({ kind: "prisma", files }); // Prisma applies its folders in name order
  }
  for (const dir of PLAIN_DIRS) {
    const abs = join(root, ...dir.split("/"));
    if (dir.split("/").some((_, i, parts) => isLink(join(root, ...parts.slice(0, i + 1))))) { refused ??= "symlink"; continue; }
    if (!isDir(abs)) continue;
    const names = readdirSync(abs).filter((n) => n.toLowerCase().endsWith(".sql"));
    if (!names.length) continue;
    const o = orderPlain(names);
    sets.push(o.refused ? o : { kind: "plain", files: o.files.map((f) => ({ rel: `${dir}/${f.name}` })) });
  }
  if (sets.length > 1) return { status: "refused", reason: "migration_sets_ambiguous" };
  if (refused === "provider_not_postgres" && !sets.length) return { status: "none", reason: refused };
  if (refused) return { status: "refused", reason: refused };
  if (!sets.length) return { status: "none", reason: "no_migrations" };
  if (sets[0].refused) return { status: "refused", reason: sets[0].refused };
  const set = sets[0];
  if (set.files.length > FILES_MAX) return { status: "refused", reason: "too_large" };
  let total = 0;
  const files = [];
  for (const f of set.files) {
    const abs = join(root, ...f.rel.split("/"));
    let st;
    try { st = lstatSync(abs); } catch { return { status: "refused", reason: "unreadable" }; }
    if (st.isSymbolicLink()) return { status: "refused", reason: "symlink" };
    if (!st.isFile()) return { status: "refused", reason: "unreadable" };
    if (st.size > FILE_MAX_BYTES) return { status: "refused", reason: "too_large" };
    total += st.size;
    if (total > TOTAL_MAX_BYTES) return { status: "refused", reason: "too_large" };
    let text;
    try { text = readFileSync(abs, "utf8"); } catch { return { status: "refused", reason: "unreadable" }; }
    files.push({ rel: f.rel, abs, up: upSection(text) });
  }
  return { status: "found", kind: set.kind, files };
}

/* dbmate: only the `-- migrate:up` section runs; a file without the markers runs whole. */
export function upSection(text) {
  const up = /^--\s*migrate:up\b.*$/m.exec(text);
  const down = /^--\s*migrate:down\b.*$/m.exec(text);
  if (!up && !down) return text;
  if (!up) return "";
  const start = up.index + up[0].length;
  const end = down && down.index > up.index ? down.index : text.length;
  return text.slice(start, end);
}

/* ---------------------------------------------------------------- conditional DDL */

/* Comments and quoted literals blanked, dollar-quoted bodies returned apart. */
function splitSql(text) {
  let code = "";
  const bodies = [];
  let i = 0;
  while (i < text.length) {
    const c = text[i], n = text[i + 1];
    if (c === "-" && n === "-") { const e = text.indexOf("\n", i); i = e < 0 ? text.length : e; code += " "; continue; }
    if (c === "/" && n === "*") {
      let depth = 1, j = i + 2;
      while (j < text.length && depth > 0) {
        if (text[j] === "/" && text[j + 1] === "*") { depth++; j += 2; } else if (text[j] === "*" && text[j + 1] === "/") { depth--; j += 2; } else j++;
      }
      i = j; code += " "; continue;
    }
    if (c === "'") { // standard string; '' inside it is a quote, E'' backslashes are treated the same way here
      let j = i + 1;
      while (j < text.length) { if (text[j] === "'" && text[j + 1] === "'") j += 2; else if (text[j] === "\\" && /E$/i.test(code)) j += 2; else if (text[j] === "'") break; else j++; }
      code += "''"; i = j + 1; continue;
    }
    if (c === "$") {
      const m = /^\$([A-Za-z_][A-Za-z0-9_]*)?\$/.exec(text.slice(i, i + 64));
      if (m && !/[A-Za-z0-9_]$/.test(code)) {
        const tag = m[0];
        const end = text.indexOf(tag, i + tag.length);
        const stop = end < 0 ? text.length : end;
        bodies.push(text.slice(i + tag.length, stop));
        code += " $body$ "; i = stop + tag.length; continue;
      }
    }
    code += c; i++;
  }
  return { code, bodies };
}

const DDL_IN_BODY = /\b(CREATE|ALTER|DROP)\s+(POLICY|TABLE|ROLE|USER|SCHEMA|VIEW|FUNCTION|EXTENSION)\b|\bROW\s+LEVEL\s+SECURITY\b|\b(GRANT|REVOKE)\b|\bSET\s+ROLE\b|\bSESSION\s+AUTHORIZATION\b/i;
const DYNAMIC_EXECUTE = /\bEXECUTE\b(?!\s+(ON|FUNCTION|PROCEDURE)\b)/i;

export function conditionalDdl(text) {
  if (/^\s*\\/m.test(text)) return true; // psql meta-command (\if, \gexec, \i): not SQL the server runs as written
  const { code, bodies } = splitSql(text);
  if (/\bDO\s+(\$body\$|''|LANGUAGE\b)/i.test(code)) return true;
  if (/\bDO\b\s*$/i.test(code)) return true;
  for (const b of bodies) {
    // A body may hold nested literals; look at its own code the same way.
    const inner = splitSql(b);
    const seen = [inner.code, ...inner.bodies].join("\n");
    if (DYNAMIC_EXECUTE.test(seen) || DDL_IN_BODY.test(seen)) return true;
  }
  return false;
}

/* ---------------------------------------------------------------- the cluster */

/* The environment for every child: PATH and locale only. No PG* variable and no DATABASE_URL reaches initdb or the
 * server, so nothing in the environment can point the replay at another database or change its settings. */
export function childEnv(env = process.env) {
  return { PATH: env.PATH ?? "", LC_ALL: "C", LANG: "C", TZ: "UTC" };
}

function run(file, args, { env, timeout }) {
  return new Promise((resolve) => {
    execFile(file, args, { env, timeout, encoding: "utf8", maxBuffer: 1 << 20, windowsHide: true }, (err, stdout, stderr) => {
      resolve({ ok: !err, code: err?.code ?? 0, stdout: String(stdout || ""), stderr: String(stderr || "") });
    });
  });
}

/* The Postgres programs on PATH, as one folder: initdb, pg_ctl and postgres side by side. */
export function findPostgres(env = process.env) {
  const exe = process.platform === "win32" ? ".exe" : "";
  for (const dir of String(env.PATH || "").split(delimiter)) {
    if (!dir) continue;
    const have = ["initdb", "pg_ctl", "postgres"].every((p) => exists(join(dir, p + exe)));
    if (have) {
      try { return realpathSync(join(dir, "initdb" + exe)).replace(/[\\/]initdb(\.exe)?$/, ""); } catch { return dir; }
    }
  }
  return null;
}

const secret = () => randomBytes(18).toString("base64url");
const quoteIdent = (s) => `"${String(s).replace(/"/g, '""')}"`;
const quoteLit = (s) => `'${String(s).replace(/'/g, "''")}'`;

/* What Supabase makes before any migration runs: its roles, the auth and storage schemas with the names policies call,
 * and its default grants on public. Stubs define names only; a judge reads policy text, never a stub's result. */
export const STUB_EXTENSIONS = Object.freeze(["uuid-ossp", "pgcrypto"]);
const ROLE_STUBS = `
CREATE ROLE anon NOLOGIN NOINHERIT;
CREATE ROLE authenticated NOLOGIN NOINHERIT;
CREATE ROLE service_role NOLOGIN NOINHERIT BYPASSRLS;
CREATE ROLE authenticator NOLOGIN NOINHERIT;
CREATE ROLE supabase_auth_admin NOLOGIN;
CREATE ROLE supabase_storage_admin NOLOGIN;
CREATE ROLE dashboard_user NOLOGIN;
GRANT anon, authenticated, service_role TO authenticator;
GRANT anon, authenticated, service_role, authenticator TO ${MIGRATOR} WITH ADMIN OPTION;
CREATE SCHEMA auth AUTHORIZATION ${MIGRATOR};
CREATE SCHEMA storage AUTHORIZATION ${MIGRATOR};
CREATE SCHEMA extensions AUTHORIZATION ${MIGRATOR};
GRANT USAGE ON SCHEMA auth, storage, extensions TO anon, authenticated, service_role;
`;
/* C637 f1: a stub extension the machine's Postgres lacks is skipped, so the replay goes on; a migration that needs it
 * then stops at its own file, which is named. Names come from a fixed list (tests pass their own), quoted as idents. */
function extensionStubs(names) {
  return names.map((n) => `DO $ext$ BEGIN IF EXISTS (SELECT 1 FROM pg_catalog.pg_available_extensions WHERE name = ${quoteLit(n)}) THEN
  CREATE EXTENSION IF NOT EXISTS "${String(n).replace(/"/g, '""')}" WITH SCHEMA extensions; END IF; END $ext$;`).join("\n");
}
const AUTH_STUBS = `
SET ROLE ${MIGRATOR};
CREATE TABLE auth.users (id uuid PRIMARY KEY, email text, role text, raw_user_meta_data jsonb, raw_app_meta_data jsonb,
  created_at timestamptz, updated_at timestamptz);
CREATE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE AS 'SELECT NULL::uuid';
CREATE FUNCTION auth.role() RETURNS text LANGUAGE sql STABLE AS 'SELECT NULL::text';
CREATE FUNCTION auth.email() RETURNS text LANGUAGE sql STABLE AS 'SELECT NULL::text';
CREATE FUNCTION auth.jwt() RETURNS jsonb LANGUAGE sql STABLE AS 'SELECT NULL::jsonb';
CREATE TABLE storage.buckets (id text PRIMARY KEY, name text, owner uuid, public boolean DEFAULT false,
  created_at timestamptz, updated_at timestamptz, file_size_limit bigint, allowed_mime_types text[]);
CREATE TABLE storage.objects (id uuid PRIMARY KEY, bucket_id text, name text, owner uuid, metadata jsonb,
  path_tokens text[], created_at timestamptz, updated_at timestamptz, last_accessed_at timestamptz);
CREATE FUNCTION storage.foldername(name text) RETURNS text[] LANGUAGE sql IMMUTABLE AS 'SELECT string_to_array(name, ''/'')';
CREATE FUNCTION storage.filename(name text) RETURNS text LANGUAGE sql IMMUTABLE AS 'SELECT NULL::text';
CREATE FUNCTION storage.extension(name text) RETURNS text LANGUAGE sql IMMUTABLE AS 'SELECT NULL::text';
ALTER TABLE storage.objects ENABLE ROW LEVEL SECURITY;
ALTER TABLE storage.buckets ENABLE ROW LEVEL SECURITY;
GRANT ALL ON ALL TABLES IN SCHEMA storage TO anon, authenticated, service_role;
RESET ROLE;
`;
/* Supabase's default grants on public. A set that names Supabase's roles runs on Supabase, where tables get these
 * grants; leaving them out would hide a real grant to anon and could read as a least-grants pass. */
const SUPABASE_GRANTS = `
SET ROLE ${MIGRATOR};
GRANT USAGE ON SCHEMA public TO anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON FUNCTIONS TO anon, authenticated, service_role;
RESET ROLE;
`;
/* C637 f2: a Prisma or plain set hosted on Supabase names its roles or auth.uid(); it gets the same stubs as a Supabase
 * set, default grants included. Stubs define names only; a judge reads policy text, never a stub's result. */
const NAMES_SUPABASE = /\b(?:anon|authenticated|service_role)\b|\bauth\s*\.\s*(?:uid|role|email|jwt|users)\b|\bstorage\s*\.\s*(?:objects|buckets|foldername)\b/i;
export function stubsFor(set, extensions = STUB_EXTENSIONS) {
  if (set.kind !== "supabase" && !set.files.some((f) => NAMES_SUPABASE.test(f.up))) return "";
  return ROLE_STUBS + extensionStubs(extensions) + AUTH_STUBS + SUPABASE_GRANTS;
}
export const SUPABASE_STUBS = stubsFor({ kind: "supabase", files: [] });

/* Bootstrap, as the superuser in the new database: the migrator, the extension guard and the public schema. */
function bootstrapSql(migratorPw) {
  const allowed = ALLOWED_EXTENSIONS.map(quoteLit).join(", ");
  return `
CREATE ROLE ${MIGRATOR} LOGIN NOSUPERUSER NOBYPASSRLS NOREPLICATION CREATEROLE NOCREATEDB PASSWORD ${quoteLit(migratorPw)};
ALTER ROLE ${MIGRATOR} SET statement_timeout = ${STATEMENT_TIMEOUT_MS};
ALTER ROLE ${MIGRATOR} SET lock_timeout = ${STATEMENT_TIMEOUT_MS};
ALTER ROLE ${MIGRATOR} SET temp_file_limit = ${quoteLit(TEMP_FILE_LIMIT)};
ALTER ROLE ${MIGRATOR} SET search_path = "$user", public, extensions;
ALTER DATABASE ${DBNAME} OWNER TO ${MIGRATOR};
ALTER SCHEMA public OWNER TO ${MIGRATOR};
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
CREATE FUNCTION public.custosa_extension_guard() RETURNS event_trigger LANGUAGE plpgsql AS $guard$
DECLARE r record;
BEGIN
  FOR r IN SELECT * FROM pg_catalog.pg_event_trigger_ddl_commands() LOOP
    IF r.command_tag = 'CREATE EXTENSION' THEN
      IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_extension e WHERE e.oid = r.objid AND e.extname IN (${allowed})) THEN
        RAISE EXCEPTION 'extension not allowed in a replay';
      END IF;
    END IF;
  END LOOP;
END $guard$;
CREATE EVENT TRIGGER custosa_extension_guard ON ddl_command_end WHEN TAG IN ('CREATE EXTENSION')
  EXECUTE FUNCTION public.custosa_extension_guard();
REVOKE ALL ON FUNCTION public.custosa_extension_guard() FROM PUBLIC;
`;
}

/* After the migrations: the read-only role the collector needs, with nothing granted. */
function readerSql(roPw) {
  return `CREATE ROLE phisc_ro LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD ${quoteLit(roPw)};
ALTER EVENT TRIGGER custosa_extension_guard DISABLE;
DROP EVENT TRIGGER custosa_extension_guard;
DROP FUNCTION public.custosa_extension_guard();`;
}

function connFor(socketDir, port, user, password, dbname = DBNAME) {
  const conn = { host: socketDir, port, dbname, user, sslmode: "disable", sslrootcert: null };
  Object.defineProperty(conn, "password", { value: password, enumerable: false });
  return conn;
}

function client(conn, timeoutMs) {
  const c = new pg.Client({ host: conn.host, port: conn.port, database: conn.dbname, user: conn.user,
    password: () => conn.password, ssl: false, connectionTimeoutMillis: timeoutMs, application_name: "custosa-replay",
    keepAlive: false });
  c.connectionParameters.options = undefined;
  c.connectionParameters.replication = undefined;
  c.on("error", () => {});
  return c;
}

async function withPg(conn, timeoutMs, fn) {
  const c = client(conn, timeoutMs);
  try { await c.connect(); return await fn(c); } finally { try { await c.end(); } catch { /* closed */ } }
}

/* The socket's own 0700 folder. A Unix socket path is capped (104 bytes on macOS), and a deep TMPDIR plus
 * "/.s.PGSQL.<port>" can pass it, so a folder too deep is made in /tmp instead. */
const SOCKET_PATH_MAX = 100;
const SAFE_PATH = /^[A-Za-z0-9_\/.-]+$/;
function socketFolder() {
  const tail = "/.s.PGSQL.65535".length;
  let d = mkdtempSync(join(tmpdir(), "cr-"));
  // pg_ctl hands -o to a shell, so the path must be plain characters as well.
  if (process.platform !== "win32" && (d.length + tail > SOCKET_PATH_MAX || !SAFE_PATH.test(d))) {
    rmSync(d, { recursive: true, force: true });
    d = mkdtempSync("/tmp/cr-");
  }
  return d;
}

/* Starts a cluster in a new temp folder -> {dir, data, socketDir, port, bootPw, stop()} or {error: reason}. */
export async function startCluster({ bindir, env = process.env, deadline }) {
  const cenv = childEnv(env);
  const exe = process.platform === "win32" ? ".exe" : "";
  const left = () => Math.max(1000, deadline - Date.now());
  const ver = await run(join(bindir, "postgres" + exe), ["--version"], { env: cenv, timeout: 10_000 });
  const major = Number((/(\d+)(?:\.\d+)?/.exec(ver.stdout) || [])[1]);
  if (!ver.ok || !major) return { error: "postgres_not_found" };
  if (major < MIN_PG_MAJOR) return { error: "postgres_too_old" };
  const dir = mkdtempSync(join(tmpdir(), "custosa-replay-"));
  const stopped = { done: false };
  const data = join(dir, "data");
  const socketDir = socketFolder();
  const bootPw = secret();
  const pwfile = join(dir, "pw");
  const remove = () => {
    for (const d of [dir, socketDir]) { try { rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ } }
  };
  try {
    writeFileSync(pwfile, bootPw + "\n", { mode: 0o600 });
    const init = await run(join(bindir, "initdb" + exe), ["-D", data, "-U", BOOT, "-A", "scram-sha-256", `--pwfile=${pwfile}`,
      "-E", "UTF8", "--no-locale", "--no-sync", "--no-instructions"], { env: cenv, timeout: left() });
    rmSync(pwfile, { force: true });
    if (!init.ok) { remove(); return { error: "replay_failed" }; }
    // Only the socket; no TCP listener. The hba file allows nothing but local scram logins.
    writeFileSync(join(data, "pg_hba.conf"), "local all all scram-sha-256\n");
    if (process.platform !== "win32" && !SAFE_PATH.test(socketDir)) { remove(); return { error: "replay_failed" }; }
    const port = randomInt(20000, 60000);
    const opts = [`-c listen_addresses=''`, `-c unix_socket_directories='${socketDir}'`, `-c unix_socket_permissions=0700`,
      `-p ${port}`, "-c fsync=off", "-c full_page_writes=off", "-c synchronous_commit=off", "-c max_connections=8",
      "-c shared_preload_libraries=''", "-c session_preload_libraries=''", "-c local_preload_libraries=''", "-c jit=off",
      "-c log_min_messages=fatal", "-c logging_collector=off", "-c max_wal_size=64MB"].join(" ");
    const start = await run(join(bindir, "pg_ctl" + exe), ["-D", data, "-l", join(dir, "log"), "-w", "-t", "30", "-o", opts, "start"],
      { env: cenv, timeout: left() });
    const stop = async () => {
      if (stopped.done) return;
      stopped.done = true;
      await run(join(bindir, "pg_ctl" + exe), ["-D", data, "-m", "immediate", "-w", "-t", "20", "stop"], { env: cenv, timeout: 30_000 });
      remove();
    };
    if (!start.ok) { await stop(); return { error: "replay_failed" }; }
    return { dir, data, socketDir, port, bootPw, stop };
  } catch {
    remove();
    return { error: "replay_failed" };
  }
}

/* ---------------------------------------------------------------- the replay */

/* The last few replays, by a hash of the set's kind, every file's path and the bytes applied, and the query texts: a
 * check run again on unchanged migrations reuses the catalog instead of building another cluster. Only applied replays
 * are kept; a failure is tried again next time. */
const CACHE_MAX = 4;
const cache = new Map();
function cacheKey(set, list) {
  const h = createHash("sha256").update(set.kind).update("\0");
  for (const f of set.files) h.update(f.rel).update("\0").update(f.up).update("\0");
  for (const q of list) h.update(String(q.query_id)).update("\0").update(String(q.sql)).update("\0").update(String(q.row_limit ?? "")).update("\0");
  return h.digest("hex");
}
export function clearReplayCache() { cache.clear(); }

export async function replayCatalog(root, queries, opts = {}) {
  const list = Array.isArray(queries) ? queries : [];
  const env = opts.env ?? process.env;
  const deadline = Math.min(opts.deadline ?? Infinity, Date.now() + (opts.timeMs ?? REPLAY_TIME_MS));
  const base = (status, reason, replay) => ({ status, count: 0, reason, preflight: null, queries: notRunAll(list, reason),
    source: SOURCE, replay });
  if (!list.length) return base("not_run", "no_queries", null); // nothing to read: no cluster is built
  const set = findMigrationSet(root);
  if (set.status !== "found") return base("not_run", set.reason, null);
  const replay = { kind: set.kind, files: set.files.length, applied: 0,
    conditional_ddl: set.files.some((f) => conditionalDdl(f.up)), failed_file: null };
  const key = cacheKey(set, list);
  if (cache.has(key)) return structuredClone(cache.get(key));
  const bindir = opts.bindir ?? findPostgres(env);
  if (!bindir) return base("not_run", "postgres_not_found", replay);
  const cluster = await startCluster({ bindir, env, deadline });
  // A cluster that won't start (initdb or pg_ctl failed) is no usable Postgres here: nothing was applied.
  if (cluster.error) return base("not_run", cluster.error === "replay_failed" ? "postgres_not_found" : cluster.error, replay);
  let timer;
  try {
    const work = (async () => {
      const left = () => Math.max(500, deadline - Date.now());
      const boot = connFor(cluster.socketDir, cluster.port, BOOT, cluster.bootPw, "postgres");
      const migratorPw = secret(), roPw = secret();
      await withPg(boot, left(), (c) => c.query(`CREATE DATABASE ${DBNAME} TEMPLATE template0 ENCODING 'UTF8'`));
      const bootApp = connFor(cluster.socketDir, cluster.port, BOOT, cluster.bootPw);
      try {
        await withPg(bootApp, left(), async (c) => {
          await c.query(bootstrapSql(migratorPw));
          const stubs = stubsFor(set, opts.stubExtensions ?? STUB_EXTENSIONS);
          if (stubs) await c.query(stubs);
          if (opts.setupFault) await c.query("SELECT custosa_test_setup_fault()"); // tests only: a setup that fails
        });
      } catch {
        // C637 f1: the sandbox couldn't be set up on this machine's Postgres before any file ran: no usable Postgres
        // here, said plainly, never a replay_failed with no file
        return { error: "postgres_unusable", setup: true };
      }
      const mig = connFor(cluster.socketDir, cluster.port, MIGRATOR, migratorPw);
      for (const f of set.files) {
        if (Date.now() >= deadline) { replay.failed_file = f.rel; return { error: "replay_failed" }; }
        try {
          await withPg(mig, left(), (c) => c.query(f.up));
        } catch {
          replay.failed_file = f.rel;
          return { error: "replay_failed" };
        }
        replay.applied++;
      }
      await withPg(bootApp, left(), (c) => c.query(readerSql(roPw)));
      const ro = connFor(cluster.socketDir, cluster.port, "phisc_ro", roPw);
      return { result: await collectCatalog(ro, list, { deadline, ...(opts.provider ? { provider: opts.provider } : {}) }) };
    })();
    const capped = new Promise((resolve) => { timer = setTimeout(() => resolve({ error: "replay_failed", capped: true }), Math.max(0, deadline - Date.now())); });
    let out;
    try { out = await Promise.race([work, capped]); } catch { out = { error: "replay_failed" }; }
    if (out.capped && !replay.failed_file) {
      // the cap hit while a file applied (that file is named), or after every file applied, while the catalog was
      // read: then the replay applied and only its read ran out of time
      if (replay.applied >= set.files.length) return base("failed", "timeout", replay);
      replay.failed_file = set.files[replay.applied].rel;
    }
    if (out.setup) return base("not_run", out.error, replay);
    if (out.error === "replay_failed" && !replay.failed_file) {
      // a throw outside a file (the database create, the reader role, the read): before the files it is setup, after
      // them the replay applied and only its read failed
      if (replay.applied >= set.files.length) return base("failed", "internal_error", replay);
      return base("not_run", "postgres_unusable", replay);
    }
    if (out.error) return base("failed", out.error, replay);
    const done = { ...out.result, source: SOURCE, replay };
    if (["ok", "empty"].includes(done.status)) {
      cache.set(key, structuredClone(done));
      while (cache.size > CACHE_MAX) cache.delete(cache.keys().next().value);
    }
    return done;
  } finally {
    clearTimeout(timer);
    await cluster.stop();
  }
}

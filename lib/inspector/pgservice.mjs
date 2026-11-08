/* Reads the `phisc` connection entry the way libpq would, without psql: the service file for host, port, database,
 * user and sslmode, and the password file for the password. Pure file reading; no child process, no network.
 *
 * Service file: $PGSERVICEFILE, else ~/.pg_service.conf, read the way libpq's parseServiceFile reads it (the
 * behaviours below were compared with psql in review; other corners may differ): each line is stripped of leading
 * and trailing whitespace; blank lines and `#` lines are skipped; a `[name]` line starts a section; only the FIRST
 * section with the requested name is read, and reading stops at the next section header; inside it every line must
 * be `keyword=value` with a known libpq keyword and nothing between the keyword and `=` (so `host = x` is a syntax
 * error), and the value is everything after `=`; a repeated keyword keeps its FIRST value; lines outside the
 * requested section are never parsed. A byte order mark is not stripped (as in libpq, it spoils the first line). The
 * system-wide pg_service.conf ($PGSYSCONFDIR) is not read.
 *
 * Password file: the entry's `passfile`, else $PGPASSFILE, else ~/.pgpass. One `host:port:database:user:password`
 * entry per line, `#` lines ignored, `\\` escapes the next character, a field that is exactly an unescaped `*` matches
 * anything (an escaped `\\*` is a literal star), the password ends at the next unescaped `:` (as psql reads it), first
 * match wins. Like libpq, a password file that is not a regular file, or that has any group or world permission
 * bits, is not read (libpq warns and ignores it; here `password_source` says so).
 *
 * Differences from libpq, on purpose: with no host, libpq connects to its default Unix socket while the inspector
 * connects to TCP `localhost` (both match the password file host `localhost`); `options`, `client_encoding` and the
 * other session keywords in the entry are not applied; PG* environment variables other than PGSERVICEFILE and
 * PGPASSFILE are ignored.
 *
 * The user must be phisc_ro: any other configured user is refused before anything connects.
 *
 * The password is never returned as an enumerable property, never put in an error message and never logged: it is a
 * non-enumerable `password` on the returned object, so JSON.stringify, util.inspect and object spread leave it out. */
import { readFileSync, statSync } from "node:fs";
import { homedir, userInfo } from "node:os";
import { join } from "node:path";

export const REQUIRED_USER = "phisc_ro";
/* The login the service entry may name: phisc_ro, or phisc_ro.<project ref> for Supabase's pooler (Supavisor), which
 * opens the session as phisc_ro. The catalog preflight still requires session_user and role phisc_ro. */
const POOLER_LOGIN = /^phisc_ro\.[a-z0-9]{20}$/;
export const isRequiredLogin = (user) => user === REQUIRED_USER || POOLER_LOGIN.test(user);

/* libpq's connection keywords (PG 16/17). Any other keyword in the requested section is a syntax error, as in libpq. */
const LIBPQ_KEYWORDS = new Set([
  "host", "hostaddr", "port", "dbname", "user", "password", "passfile", "channel_binding", "connect_timeout",
  "client_encoding", "options", "application_name", "fallback_application_name", "keepalives", "keepalives_idle",
  "keepalives_interval", "keepalives_count", "tcp_user_timeout", "sslmode", "sslnegotiation", "sslcompression",
  "sslcert", "sslkey", "sslpassword", "sslcertmode", "sslrootcert", "sslcrl", "sslcrldir", "sslsni", "requirepeer",
  "require_auth", "ssl_min_protocol_version", "ssl_max_protocol_version", "gssencmode", "krbsrvname", "gsslib",
  "gssdelegation", "replication", "target_session_attrs", "load_balance_hosts",
]);

export const SSL_MODES = Object.freeze(["disable", "allow", "prefer", "require", "verify-ca", "verify-full"]);
/* sslmodes that always encrypt. Anything else may fall back to a plain connection. */
export const TLS_MODES = Object.freeze(["require", "verify-ca", "verify-full"]);

export class PgServiceError extends Error {
  constructor(code, message) { super(message); this.name = "PgServiceError"; this.code = code; }
}

/* Returns the requested section of service file text as {keyword: value}, or null when there is none. */
export function parseServiceEntry(text, name) {
  const lines = String(text).split("\n");
  let found = false;
  let entry = null;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].replace(/^[ \t\r\n\f\v]+|[ \t\r\n\f\v]+$/g, ""); // ASCII whitespace only, like isspace(): a BOM stays
    if (line === "" || line.startsWith("#")) continue;
    if (line.startsWith("[")) {
      if (found) break; // end of the requested section: libpq stops here, so a later duplicate is never read
      if (line.slice(1, 1 + name.length) === name && line[1 + name.length] === "]") { found = true; entry = Object.create(null); }
      continue;
    }
    if (!found) continue; // libpq ignores everything outside the requested section
    const eq = line.indexOf("=");
    if (eq < 0) throw new PgServiceError("service_syntax", `service file line ${i + 1}: syntax error`);
    const key = line.slice(0, eq);
    if (key === "service") throw new PgServiceError("service_syntax", `service file line ${i + 1}: nested service`);
    if (!LIBPQ_KEYWORDS.has(key)) throw new PgServiceError("service_syntax", `service file line ${i + 1}: syntax error`);
    if (!(key in entry)) entry[key] = line.slice(eq + 1); // first value wins, as in libpq
  }
  return entry;
}

/* Splits one password file line into its five fields, honouring `\\` escapes. As psql does, the password is the
 * fifth field up to the next unescaped `:` and anything after it is ignored. Returns null for a line with fewer than
 * five fields (libpq skips those). `wild[i]` is true when field i is a bare unescaped `*`, which is the only form
 * libpq treats as a wildcard. */
export function splitPassFields(line) {
  const fields = [], wild = [];
  let cur = "", raw = "";
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === "\\" && i + 1 < line.length) { cur += line[i + 1]; raw += ch + line[i + 1]; i++; continue; }
    if (ch === ":") {
      fields.push(cur); wild.push(raw === "*"); cur = ""; raw = "";
      if (fields.length === 5) return { fields, wild };
      continue;
    }
    cur += ch; raw += ch;
  }
  fields.push(cur); wild.push(false);
  return fields.length === 5 ? { fields, wild } : null;
}

/* The host string libpq compares with a password file entry: `localhost` for no host or a socket directory. */
function passHost(host) {
  return !host || host.startsWith("/") || host.startsWith("@") ? "localhost" : host;
}

/* Finds the password for {host, port, dbname, user} in password file text. First match wins. */
export function matchPassword(text, { host, port, dbname, user }) {
  const want = [passHost(host), String(port), dbname, user];
  for (const raw of String(text).split(/\r?\n/)) {
    const line = raw.replace(/\r$/, "");
    if (line === "" || line.startsWith("#")) continue;
    const r = splitPassFields(line);
    if (!r) continue;
    if (r.fields.slice(0, 4).every((field, i) => r.wild[i] || field === want[i])) return r.fields[4];
  }
  return undefined;
}

/* Reads the password file under libpq's rules. Returns {password, source} where source is one of
 * "pgpass", "pgpass_missing", "pgpass_no_match", "pgpass_refused_permissions", "pgpass_not_regular". */
export function readPassFile(path, params) {
  let st;
  try { st = statSync(path); } catch { return { password: undefined, source: "pgpass_missing" }; }
  if (!st.isFile()) return { password: undefined, source: "pgpass_not_regular" };
  // libpq (non-Windows): any group or other permission bit (S_IRWXG | S_IRWXO) means the file is ignored.
  if (process.platform !== "win32" && (st.mode & 0o077) !== 0) {
    return { password: undefined, source: "pgpass_refused_permissions" };
  }
  let text;
  try { text = readFileSync(path, "utf8"); } catch { return { password: undefined, source: "pgpass_missing" }; }
  const password = matchPassword(text, params);
  return password === undefined ? { password, source: "pgpass_no_match" } : { password, source: "pgpass" };
}

/* readService(name = "phisc", {env, home}) -> {host, port, dbname, user, sslmode, sslrootcert, password_source}
 * with a non-enumerable `password` (undefined when none was found). `env` and `home` exist so tests never touch the
 * real files; callers pass nothing.
 *
 * Defaults follow libpq where the entry leaves a field out: host `localhost` (node has no default socket path),
 * port 5432, user the OS user, dbname the user, sslmode `prefer`. Environment variables other than PGSERVICEFILE and
 * PGPASSFILE are not consulted: the entry alone decides where the inspector connects. The entry's `options`,
 * `client_encoding` and other session keywords are not applied (the collector pins its own session settings). A user
 * other than phisc_ro is refused (code wrong_user). */
/* The service file every reader uses (the inspector here, the environment mark and setup): $PGSERVICEFILE when it is
   set and not empty, else ~/.pg_service.conf. */
export function serviceFilePath({ env = process.env, home = homedir() } = {}) {
  return env.PGSERVICEFILE || join(home, ".pg_service.conf");
}

export function readService(name = "phisc", { env = process.env, home = homedir() } = {}) {
  const serviceFile = serviceFilePath({ env, home });
  let text;
  try { text = readFileSync(serviceFile, "utf8"); } catch {
    throw new PgServiceError("service_file_missing", "no Postgres service file (~/.pg_service.conf or PGSERVICEFILE)");
  }
  const entry = parseServiceEntry(text, name);
  if (!entry) throw new PgServiceError("service_missing", `no [${name}] entry in the Postgres service file`);

  if (entry.hostaddr) throw new PgServiceError("service_unsupported", "hostaddr is not supported; use host");
  const host = entry.host || "localhost";
  if (host.includes(",")) throw new PgServiceError("service_unsupported", "several hosts in one entry are not supported");
  const portText = entry.port || "5432";
  if (!/^[0-9]{1,5}$/.test(portText) || Number(portText) < 1 || Number(portText) > 65535) {
    throw new PgServiceError("service_invalid", "port must be a number from 1 to 65535");
  }
  const port = Number(portText);
  let user = entry.user;
  if (!user) { try { user = userInfo().username; } catch { user = ""; } }
  if (!user) throw new PgServiceError("service_invalid", "no user in the service entry");
  if (!isRequiredLogin(user)) {
    throw new PgServiceError("wrong_user", `the [${name}] entry must use the ${REQUIRED_USER} login (or ${REQUIRED_USER}.<project ref> through the Supabase pooler)`);
  }
  const dbname = entry.dbname || user;
  const sslmode = entry.sslmode || "prefer";
  if (!SSL_MODES.includes(sslmode)) throw new PgServiceError("service_invalid", `unknown sslmode ${JSON.stringify(sslmode)}`);

  // libpq: a password given in the connection parameters (here the service entry) wins over the password file.
  let password, password_source;
  if (entry.password !== undefined) { password = entry.password; password_source = "service"; } else {
    // libpq order: the entry's passfile, then PGPASSFILE, then ~/.pgpass. The port is matched as written.
    const passFile = entry.passfile || env.PGPASSFILE || join(home, ".pgpass");
    ({ password, source: password_source } = readPassFile(passFile, { host, port: portText, dbname, user }));
  }

  const out = { host, port, dbname, user, sslmode, sslrootcert: entry.sslrootcert || null, password_source };
  Object.defineProperty(out, "password", { value: password, enumerable: false, writable: false, configurable: false });
  return Object.freeze(out);
}

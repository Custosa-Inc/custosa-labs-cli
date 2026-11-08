/* `custosa doctor`: checks this computer's PHI Schema Check setup and prints one pass, warn or fail line per check.
 * Exits 1 when any check fails, else 0.
 *
 * Everything is local except two connections: one unauthenticated GET of the evaluator's liveness probe
 * (client.mjs HEALTH_PATH, /v1/health; skipped with --offline), and the read-only preflight against the [phisc] database entry
 * (catalog.mjs preflightOnly: BEGIN READ ONLY, the preflight query, ROLLBACK). Nothing is sent to Custosa. The sign-in
 * token, the database password and platform tokens are never printed: only whether they are there, and their form.
 *
 * Checks: Node.js version; the package version and the npx cache; each supported assistant's entry; the sign-in and
 * its estimated expiry; the evaluator; the project root setting; the [phisc] entry; the database preflight; the
 * environment mark; the platform token. */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { MIN_NODE, VERSION, nodeSupported, tilde } from "./version.mjs";

const DAY_MS = 86_400_000;
const EXPIRY_WARN_DAYS = 14;

/* The npm cache folder npx installs into: $npm_config_cache, else npm's default for this platform. */
export function npmCacheDir({ env = process.env, home = homedir(), platform = process.platform } = {}) {
  if (env.npm_config_cache) return env.npm_config_cache;
  if (platform === "win32") return join(env.LOCALAPPDATA || join(home, "AppData", "Local"), "npm-cache");
  return join(home, ".npm");
}

/* The custosa versions in the npx cache: [{version, dir}] (unreadable entries skipped). */
export function npxVersions(cacheDir) {
  const out = [];
  let entries = [];
  try { entries = readdirSync(join(cacheDir, "_npx")); } catch { return out; }
  for (const e of entries) {
    try {
      const pkg = JSON.parse(readFileSync(join(cacheDir, "_npx", e, "node_modules", "custosa", "package.json"), "utf8"));
      if (typeof pkg.version === "string") out.push({ version: pkg.version, dir: join(cacheDir, "_npx", e) });
    } catch { /* not a custosa install */ }
  }
  return out;
}


export async function runDoctor({
  env = process.env, home = homedir(), platform = process.platform, out = (line) => console.log(line), offline = false,
  nodeVersion = process.versions.node, fetch = globalThis.fetch, which = null, run = null, now = () => Date.now(),
  preflight = null,
} = {}) {
  const counts = { pass: 0, warn: 0, fail: 0 };
  const line = (level, label, detail) => {
    counts[level]++;
    out(`${level.toUpperCase().padEnd(4)}  ${label}${detail ? `: ${detail}` : ""}`);
  };
  const configDir = (await import("./inspector/secrets.mjs")).defaultConfigDir({ env, home });
  out(`PHI Schema Check, a Custosa Labs project: custosa doctor ${VERSION}`);
  out("");

  // 1. Node.js
  const need = MIN_NODE.join(".");
  if (nodeSupported(nodeVersion)) line("pass", "Node.js", `${nodeVersion} (needs ${need} or later)`);
  else line("fail", "Node.js", `${nodeVersion}; the inspector needs Node.js ${need} or later. Install a current Node.js LTS.`);

  // 2. The package and the npx cache
  const self = fileURLToPath(import.meta.url);
  const fromNpx = /[\\/]_npx[\\/]/.test(self);
  const cache = npmCacheDir({ env, home, platform });
  const cached = npxVersions(cache);
  const versions = [...new Set(cached.map((c) => c.version))];
  const where = fromNpx ? "running from the npx cache" : "running from a local install";
  if (!cached.length) line("pass", "custosa package", `${VERSION}, ${where}; no custosa in the npx cache (${tilde(cache, home)}/_npx)`);
  else if (versions.length === 1 && versions[0] === VERSION) line("pass", "custosa package", `${VERSION}, ${where}; npx cache holds ${VERSION}`);
  else line("warn", "custosa package", `${VERSION}, ${where}; the npx cache holds ${versions.join(", ")}. Assistants start the version their entry pins: to move them to the newest, run npx custosa@latest setup; to clear old copies see the README (Clearing the npx cache).`);

  // 3. The assistants' entries
  try {
    const { CLIENTS } = await import("./clients.mjs");
    const cli = which && run ? { which, run } : await import("./cli.mjs");
    const ctx = { home, platform, env, which: cli.which, run: cli.run, interactive: false, dryRun: true, out: () => {} };
    let found = 0;
    for (const client of CLIENTS) {
      let installed = false;
      try { installed = client.installed(ctx); } catch { installed = false; }
      if (!installed) continue;
      found++;
      let state;
      try { const st = client.status(ctx); state = typeof st === "string" ? st : st.state; } catch (error) {
        line("warn", `${client.label} entry`, `couldn't be read (${String(error.message).slice(0, 200)}). Run npx custosa@latest setup, or set it up by hand.`);
        continue;
      }
      if (state === "configured") line("pass", `${client.label} entry`, `set up (custosa@${VERSION})`);
      else if (state === "outdated") line("warn", `${client.label} entry`, `set up with a different command or version. Run npx custosa@latest setup to update it (its env and timeouts are kept).`);
      else line("warn", `${client.label} entry`, `not set up. Run npx custosa@latest setup to add it.`);
    }
    if (!found) line("warn", "Assistants", "none of the supported assistants was found on this computer.");
  } catch (error) {
    line("warn", "Assistants", `couldn't be checked (${String(error.message).slice(0, 200)}).`);
  }

  // 4. The sign-in (never printed)
  const auth = await import("./inspector/auth.mjs");
  const client = await import("./inspector/client.mjs");
  const t = auth.readToken({ configDir });
  const url = client.evaluatorUrl({ env, configDir });
  if (t.refused) line("fail", "Sign-in", `the saved sign-in can't be used (${t.refused}). Run npx custosa login.`);
  // (npx custosa logout deletes the sign-in here and asks the evaluator to revoke it where the evaluator offers that.)
  else if (!t.token) line("fail", "Sign-in", "not signed in. Run npx custosa login in a terminal.");
  else {
    let written = null;
    try { written = statSync(auth.tokenPath({ configDir })).mtimeMs; } catch { written = null; }
    const expires = written === null ? null : written + auth.DEVICE_TOKEN_DAYS * DAY_MS;
    const left = expires === null ? null : Math.floor((expires - now()) / DAY_MS);
    const when = expires === null ? "expiry unknown" : `expires about ${new Date(expires).toISOString().slice(0, 10)} (${auth.DEVICE_TOKEN_DAYS} days after sign-in; the token itself carries no date)`;
    const otherHost = !url.problem && !client.issuedBy(url, t.host);
    if (otherHost) line("fail", "Sign-in", `a token is saved for ${t.host}, but the evaluator now configured is ${url.origin}. Run npx custosa login again.`);
    else if (left !== null && left < 0) line("fail", "Sign-in", `a token is saved for ${t.host}, ${when}: it has likely expired. Run npx custosa login.`);
    else if (left !== null && left < EXPIRY_WARN_DAYS) line("warn", "Sign-in", `a token is saved for ${t.host}, ${when}. Run npx custosa login soon.`);
    else line("pass", "Sign-in", `a token is saved for ${t.host}, ${when}`);
  }

  // 5. The evaluator
  if (url.problem) line("fail", "Evaluator", client.LOCAL[url.problem]);
  else if (offline) line("warn", "Evaluator", `${url.origin} (from ${url.source}); not contacted (--offline)`);
  else {
    const h = await client.health(url.url, { fetch });
    if (h.ok) line("pass", "Evaluator", `${url.origin} (from ${url.source}) answers its health check`);
    else line("fail", "Evaluator", `${url.origin} (from ${url.source}) didn't answer its health check (${h.why}). Check the connection, or the address in CUSTOSA_EVALUATOR_URL or evaluator.json.`);
  }

  // 6. The project root setting
  if (env.CUSTOSA_PROJECT_ROOT) {
    const dir = env.CUSTOSA_PROJECT_ROOT;
    let ok = false;
    try { ok = statSync(dir).isDirectory(); } catch { ok = false; }
    const { projectRootProblem } = await import("./inspector/projectroot.mjs");
    const why = ok && /^([A-Za-z]:)?[\\/]/.test(dir) ? await projectRootProblem(dir, { home }) : { message: "it is not an existing folder given as an absolute path" };
    if (why) line("fail", "Project root", `CUSTOSA_PROJECT_ROOT is set to ${dir}, which can't be used: ${why.message}`);
    else line("pass", "Project root", `CUSTOSA_PROJECT_ROOT is ${dir}; it takes precedence over the assistant's roots`);
  }

  // 7. The [phisc] entry and 8. the database preflight
  const pg = await import("./inspector/pgservice.mjs");
  let conn = null;
  try {
    conn = pg.readService("phisc", { env, home });
    const pass = conn.password === undefined || conn.password === null ? "no password found" : `password from ${conn.password_source}`;
    line("pass", "[phisc] entry", `${conn.user}@${conn.host}:${conn.port}/${conn.dbname}, sslmode ${conn.sslmode}, ${pass}`);
    if (typeof conn.password === "string" && conn.password.startsWith("sbp_")) {
      line("warn", "[phisc] password", "it looks like a Supabase personal access token (sbp_), not the phisc_ro role's password. Use the role's own password, and revoke the token if it was pasted by mistake.");
    }
  } catch (error) {
    if (["service_file_missing", "service_missing"].includes(error?.code)) line("warn", "[phisc] entry", "none, so the database catalog checks won't run. To add it, run npx custosa setup and follow the database steps.");
    else line("fail", "[phisc] entry", `${error?.message ?? "can't be read"}.`);
  }
  if (conn) {
    if (conn.password === undefined || conn.password === null) line("warn", "Database preflight", "skipped: no password for phisc_ro in the entry or the password file.");
    else if (conn.password.startsWith("sbp_")) line("warn", "Database preflight", "skipped: the [phisc] password looks like a Supabase personal access token (sbp_), so doctor doesn't send it to the database. Put the phisc_ro role's own password there.");
    else {
      const run = preflight ?? (await import("./inspector/catalog.mjs")).preflightOnly;
      const r = await run(conn);
      if (r.status === "passed") line("pass", "Database preflight", "phisc_ro connects read-only and passes every check");
      else if (r.status === "failed") line("fail", "Database preflight", `phisc_ro has more access than the inspector accepts (${r.message}). Fix its grants as the setup guide says.`);
      else line("warn", "Database preflight", `couldn't connect (${r.reason}). Start the database, or check the [phisc] entry.`);
    }
  }

  // 9. The environment mark
  const envmod = await import("./inspector/environment.mjs");
  const mark = envmod.environmentFor({ configDir, env, home });
  if (mark.note) line("warn", "Environment mark", mark.note);
  else if (mark.environment.value === "unknown") line("warn", "Environment mark", "not marked, so results are judged as unknown. Run npx custosa setup in a terminal to mark it.");
  else line("pass", "Environment mark", `${mark.environment.value} (marked at setup, matches the [phisc] entry)`);

  // 10. The platform token (form only, never printed)
  const plat = await import("./inspector/platform.mjs");
  const loaded = plat.loadPlatformConfig({ dir: configDir });
  if (loaded.result) {
    if (loaded.result.reason === "no_token") line("pass", "Platform token", "none (platform checks are off)");
    else line("fail", "Platform token", loaded.result.message ?? `platform.json can't be used (${loaded.result.reason}).`);
  } else {
    const notes = plat.platformTokenNotes(loaded.config);
    const provider = typeof loaded.config?.provider === "string" ? loaded.config.provider : "unknown";
    if (notes.length) for (const n of notes) line("warn", "Platform token", n);
    else line("pass", "Platform token", `${provider}; whether it can write isn't judged (see the README, Platform tokens)`);
  }

  out("");
  out(`${counts.pass} passed, ${counts.warn} warnings, ${counts.fail} failed`);
  return counts.fail ? 1 : 0;
}

/* `custosa setup` and `custosa remove`: find the assistants on this computer, say what will change, ask, then do it.
   Nothing is sent to Custosa from here. Signing in is `custosa login` (bin/custosa.mjs, the device sign-in), run as its
   own process in this terminal, and it saves the token. Setup writes no token and prints none; it only asks the sign-in reader
   whether a usable sign-in is there. */
import { readFileSync } from "node:fs";
import { readToken } from "./inspector/auth.mjs";
import { evaluatorUrl, issuedBy } from "./inspector/client.mjs";
import { defaultConfigDir } from "./inspector/secrets.mjs";
import { join } from "node:path";
import { CLIENTS } from "./clients.mjs";
import { ENVIRONMENTS, readEnvironment, serviceFingerprint, writeEnvironment } from "./inspector/environment.mjs";
import { PgServiceError, parseServiceEntry, serviceFilePath } from "./inspector/pgservice.mjs";
import { Unreadable } from "./files.mjs";
import { SHARED } from "./shared.mjs";
import { tilde } from "./version.mjs";

/* The prompt, the credit step and the price come from shared.json, the same source as https://custosa.com/labs/setup */
const GUIDE = SHARED.guide;
const TRY = SHARED.tryPrompt;
const P = SHARED.price;

const LOGIN = "npx custosa login";
/* where `custosa login` keeps the sign-in: $CUSTOSA_CONFIG_DIR, else ~/.config/custosa (inspector/secrets.mjs) */
export const configDir = (ctx) => defaultConfigDir({ env: ctx.env, home: ctx.home });
/* Signed in means the sign-in reader accepts the saved sign-in and it was made for the evaluator now configured; a refused
   sign-in, or one for another address, counts as not signed in. The token itself stays inside readToken. */
function signedIn(ctx) {
  const where = { configDir: configDir(ctx) };
  const t = readToken(where);
  if (!t.token) return false;
  const url = evaluatorUrl({ env: ctx.env, ...where });
  return !url.problem && issuedBy(url, t.host);
}
/* the exit status custosa login uses when the evaluator's sign-in page isn't one this inspector shows yet */
export const LOGIN_NOT_AVAILABLE = 3;

const list = (labels) => labels.length < 2 ? labels.join("") : `${labels.slice(0, -1).join(", ")} and ${labels.at(-1)}`;

function survey(ctx, clients) {
  return clients.map((client) => {
    if (!client.installed(ctx)) return { client, state: "missing" };
    try {
      const st = client.status(ctx);
      return typeof st === "string" ? { client, state: st } : { client, ...st };
    }
    catch (error) { return { client, state: "manual", why: error instanceof Unreadable ? error.message : `couldn’t check: ${error.message}` }; }
  });
}

function describe(found, mode) {
  const text = {
    missing: "not found",
    ready: mode === "setup" ? "found" : "not set up",
    configured: mode === "setup" ? "already set up" : "set up",
    outdated: mode === "setup" ? "set up with a different command, will update it" : "set up (with a different command)",
  };
  return found.state === "manual" ? found.why : found.detail ?? text[found.state];
}

export async function main(mode, { clients: only, yes = false, environment = null }, ctx) {
  const { out, style: s } = ctx;
  const clients = only ? CLIENTS.filter((c) => only.includes(c.id)) : CLIENTS;
  out(`\n${s.bold("PHI Schema Check")}${s.dim(", a Custosa Labs project")}\n`);
  out(s.dim(mode === "setup" ? "Looking for AI assistants on this computer.\n" : "Looking for PHI Schema Check in your assistants.\n"));

  const found = survey(ctx, clients);
  const width = Math.max(...found.map((f) => f.client.label.length)) + 3;
  for (const f of found) {
    const mark = f.state === "missing" ? s.dim("·") : f.state === "manual" ? s.yellow("!") : s.green("✓");
    out(`  ${mark} ${f.client.label.padEnd(width)}${f.state === "missing" ? s.dim(describe(f, mode)) : describe(f, mode)}`);
  }
  out("");

  const todo = found.filter((f) => (mode === "setup" ? ["ready", "outdated"] : ["configured", "outdated"]).includes(f.state));
  const manual = found.filter((f) => f.state === "manual");
  const configured = found.filter((f) => f.state === "configured");

  if (!todo.length) {
    for (const f of manual) out(`Set up ${f.client.label} by hand: ${GUIDE}?assistant=${f.client.id}\n`);
    if (mode === "remove") out("Nothing to remove.\n");
    else if (configured.length) { if (!ctx.dryRun) await signIn(ctx, yes); const marked = await markEnvironment(ctx, environment, yes); nextSteps(ctx); if (!marked) return 1; }
    else if (!manual.length) out(`No supported assistants found. For other tools, follow ${GUIDE}\n`);
    return manual.length ? 1 : 0;
  }

  const names = list(todo.map((f) => f.client.label));
  const question = mode === "setup" ? `Add PHI Schema Check to ${names}?` : `Remove PHI Schema Check from ${names}?`;
  if (ctx.dryRun) out(s.dim("Dry run, so nothing changes."));
  else if (!yes) {
    if (!ctx.interactive) { out(`${question} Run again with --yes to make the change.\n`); return 1; }
    if (!(await ctx.ask(question))) { out("Nothing changed.\n"); return 0; }
  }

  const done = [];
  let failed = manual.length;
  for (const f of todo) {
    try {
      const result = mode === "setup" ? await f.client.add(ctx, f.state, { yes }) : await f.client.remove(ctx, { yes });
      const verb = ctx.dryRun ? (mode === "setup" ? (f.state === "outdated" ? "would be updated" : "would be added") : "would be removed") : mode === "setup" ? (f.state === "outdated" ? "updated" : "added") : "removed";
      out(`  ${s.green("✓")} ${f.client.label.padEnd(width)}${verb}${f.client.note && mode === "setup" ? s.dim(` (${f.client.note})`) : ""}`);
      if (result.note) out(s.dim(`    ${" ".repeat(width)}${result.note}`));
      if (result.backup) out(s.dim(`    ${" ".repeat(width)}previous file saved as ${tilde(result.backup, ctx.home)}`));
      done.push({ client: f.client });
    } catch (error) {
      failed++;
      out(`  ${s.red("✗")} ${f.client.label.padEnd(width)}${error.message}`);
      out(`    ${" ".repeat(width)}${mode === "setup" ? `Set it up by hand: ${GUIDE}?assistant=${f.client.id}` : "Remove it in the assistant’s settings."}`);
    }
  }
  for (const f of manual) out(`  ${s.yellow("!")} ${f.client.label.padEnd(width)}Set it up by hand: ${GUIDE}?assistant=${f.client.id}`);
  out("");

  if (mode === "setup" && !ctx.dryRun && (done.length || configured.length)) {
    await signIn(ctx, yes);
    if (!(await markEnvironment(ctx, environment, yes))) failed++;
    nextSteps(ctx);
  } else if (mode === "setup" && ctx.dryRun && !(await markEnvironment(ctx, environment, yes))) failed++;
  if (mode === "remove" && !ctx.dryRun && signedIn(ctx)) out(s.dim(`This computer is still signed in. To remove the sign-in too, run npx custosa logout.\n`));
  return failed ? 1 : 0;
}

/* The sign-in, once per computer: `custosa login` in this terminal, while the person is here. It shows a code and
   the address to enter it at, waits for the approval and saves the token itself. Without a terminal, or when
   the person says not now, setup says how to do it later. */
async function signIn(ctx, yes) {
  const { out, style: s } = ctx;
  if (signedIn(ctx)) { out(s.dim(`Signed in on this computer already. To sign in anew, run ${LOGIN}.\n`)); return true; }
  const later = () => { out(`${s.bold("Sign in")}  Run ${LOGIN} in a terminal, then sign in to Custosa in your browser, or create an account.\n`); return false; };
  if (!ctx.interactive) return later();
  if (!yes && !(await ctx.ask("Sign in to PHI Schema Check now? It gives you a code to enter in your browser."))) return later();
  out("");
  const status = ctx.run(ctx.self[0], [...ctx.self.slice(1), "login"], { interactive: true }).status;
  out("");
  if (status === LOGIN_NOT_AVAILABLE) { out(`${s.bold("Sign in")}  PHI Schema Check sign-in isn’t available yet. Try again later with ${LOGIN}.\n`); return false; }
  return status === 0 || later();
}

/* The environment mark (evaluator_api.md 1.4, source "setup"): what the `phisc` database entry points at. It is the only
   way to earn a production readiness score, so it is asked of the person here, never taken from the assistant. Saved by
   inspector/environment.mjs in the config folder (environment.json, 0600), where the inspector reads it. */
const ENV_WHY = "Results are judged against this mark, and the evaluator treats production as your own statement that the entry is your production database.";
const ENV_LATER = "run npx custosa setup in a terminal";
/* The mark is asked at the terminal (no local check can tell a person from a pseudo-terminal, so the evaluator treats it
   as the person's own statement): --environment only saves the question, and production is typed out in full. A
   mark is tied to the [phisc] entry it was made for (its host, port and dbname, fingerprinted); when the entry changes,
   the inspector reads the environment as unknown until it is marked again. Returns false when it refused. */
async function markEnvironment(ctx, chosen, yes) {
  const { out, style: s } = ctx;
  const where = { configDir: configDir(ctx) };
  const service = serviceFingerprint({ env: ctx.env, home: ctx.home });
  const current = readEnvironment(where);
  if (current.refused) out(`  ${s.yellow("!")} The saved environment mark can’t be used: ${current.refused}.`);
  const mark = current.mark ?? null;
  const was = mark && mark.service === service ? mark.value : null;
  if (mark && !was) out(`  ${s.yellow("!")} The phisc entry has changed since it was marked ${mark.value}, so it counts as unknown until it is marked again.`);
  if (!ctx.interactive) {
    if (chosen) { out(`${s.red("✗")} Environment not marked: the mark is asked at a terminal. To mark it, ${ENV_LATER}.\n`); return false; }
    out(was ? `${s.bold("Environment")}  ${was}, as marked earlier. To change it, ${ENV_LATER}.\n`
      : `${s.bold("Environment")}  Not marked, so results are judged as unknown. To mark it, ${ENV_LATER}.\n`);
    return true;
  }
  if (service === "unreadable") { out(`${s.bold("Environment")}  Not marked: the [phisc] entry in ${tilde(serviceFile(ctx), ctx.home)} can’t be read. Fix it, then run setup again.\n`); return !chosen; }
  let value = chosen;
  if (!value) {
    if (ctx.dryRun) return true;
    if (yes) { out(was ? `${s.bold("Environment")}  ${was}, as marked earlier.\n` : `${s.bold("Environment")}  Not marked, so results are judged as unknown. To mark it, run setup again without --yes.\n`); return true; }
    const entry = service ? "" : " (there is no [phisc] entry yet: adding one later sets the mark back to unknown)";
    value = await ctx.choose(`Which environment does the phisc database entry (${tilde(serviceFile(ctx), ctx.home)}) point at${entry}? ${ENV_WHY}`, [...ENVIRONMENTS], was ?? "unknown");
    if (!value) { out(`Not marked. To mark it, ${ENV_LATER}.\n`); return true; }
  }
  if (value === "production" && service === null) { out(`Not marked production: there is no [phisc] entry in ${tilde(serviceFile(ctx), ctx.home)} yet. Add it, then run setup again.\n`); return !chosen; }
  if (value === "production" && value !== was && !ctx.dryRun) {
    const typed = await ctx.input("A production mark lets a check earn a production readiness score. Type production to confirm:");
    if (typed !== "production") { out(`Not marked production${was ? `; it stays ${was}` : ""}.\n`); return !chosen; }
  }
  if (ctx.dryRun) { out(`  ${s.green("✓")} Environment would be marked ${value}\n`); return true; }
  if (value === was) { out(`${s.bold("Environment")}  ${value}, unchanged.\n`); return true; }
  try {
    writeEnvironment(value, { ...where, service });
    out(`${s.bold("Environment")}  marked ${value}${s.dim(` (saved in ${tilde(join(where.configDir, "environment.json"), ctx.home)})`)}\n`);
    return true;
  } catch (error) { out(`  ${s.red("✗")} ${error.message}\n`); return false; }
}

/* The read-only database role, its checks and the connection entry: printed, never run (setup runs no SQL). The SQL is
   shared.json's, the same as the setup page's and client/CLIENT-SETUP.md's. Once a [phisc] entry exists, one line. */
const DB = SHARED.database;
const serviceFile = (ctx) => serviceFilePath({ env: ctx.env, home: ctx.home });
// Read as libpq, doctor and the inspector read it. A [phisc] entry with a bad line is still there.
function hasPhiscEntry(ctx) {
  let text;
  try { text = readFileSync(serviceFile(ctx), "utf8"); } catch { return false; }
  try { return parseServiceEntry(text, "phisc") !== null; } catch (error) { if (error instanceof PgServiceError) return true; throw error; }
}
function databaseGuide(ctx) {
  const { out, style: s } = ctx;
  const sql = (text) => { for (const line of text.split("\n")) out(`    ${line}`); out(""); };
  if (hasPhiscEntry(ctx)) {
    out(`${s.bold("Your database")}  The phisc entry is in ${tilde(serviceFile(ctx), ctx.home)}. Its read and write checks: ${GUIDE}#database\n`);
    return;
  }
  out(`${s.bold("Your database (optional, Postgres)")}  Run this SQL once yourself, not through your assistant, as a user who can create roles.`);
  out(s.dim("  Setup runs no SQL. The inspector reads only your database catalog, as phisc_ro, never the rows of a table."));
  out(s.dim(`  To run a block, save it to a file and run it with psql as that user, so it stops at the first error:`));
  out(s.dim(`    ${DB.runFile}\n`));
  out("  1. The read-only role. Give it a password and have it sign in only with that password: never through a trusted");
  out("     socket (a trust or peer line in pg_hba.conf that lets it in without one).");
  sql(DB.role);
  out("     On Supabase, also let it read the bucket list's settings (names, public flag, size and type limits), never the");
  out("     files in them (storage.objects stays closed). Without these three the storage bucket checks can't read anything:");
  sql(DB.supabaseBuckets);
  out("  2. On PostgreSQL 14 or older, and on any database upgraded from one (pg_upgrade or a dump and restore keeps the");
  out("     old grants), every role can create in the public schema. First grant CREATE on public to the app or migration");
  out("     role that relies on it, then revoke it from PUBLIC, in one transaction. This step needs the owner of the public");
  out("     schema or a superuser:");
  sql(DB.pg14Steps);
  out("  3. Check that the role can't read rows. Both must return no rows, and lo_compat_privileges must be off.");
  out("     The first leaves out Supabase's storage.buckets, granted above, as the inspector's own check does:");
  sql(DB.readCheck);
  sql(DB.largeObjectCheck);
  out("  4. Check that the role has no direct write privileges. It must return no rows: no table write grants, no");
  out("     CREATE on any schema or the database, no CREATEDB, and no default privileges that grant a write:");
  sql(DB.writeCheck);
  out(`  5. The connection entry: add this to ${tilde(serviceFile(ctx), ctx.home)}`);
  sql(DB.service);
  out("     and this line to ~/.pgpass, then run chmod 600 ~/.pgpass:");
  sql(DB.pgpass);
  out("  6. Try a write as the role. It must fail with \"permission denied\" (it rolls back either way):");
  sql(DB.writeProbe);
  out(s.dim(`  Functions that run with their owner's rights, and what the role can still do: ${GUIDE}#database\n`));
}

function nextSteps(ctx) {
  const { out, style: s } = ctx;
  databaseGuide(ctx);
  out(`${s.bold("Add credit")}  ${SHARED.credit}`);
  out(s.dim(`  $${P.unitUsd} per work unit, prepaid. Every result is charged, unknown results and practices with no rule for the stack included. ${SHARED.billing}\n`));
  out(`${s.bold("Try it")}  Start a new session in your project, check that ${SHARED.name} shows connected with its three tools, check_schema, schema_guidance and get_result (enter /mcp), then send:`);
  out(`  ${TRY}\n`);
  out(s.dim(`Guide: ${GUIDE}    Remove: npx custosa remove\n`));
}


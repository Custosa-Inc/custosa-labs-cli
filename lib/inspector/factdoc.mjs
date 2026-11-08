/* The fact document builder: runs the collectors over each project root and assembles one closed fact document
 * per root (fact_document.schema.json v2.1, evaluator_api.md), validated before anything may send it.
 *
 * buildFactDocuments(projectRoots, options) -> {documents: [{project, label, nested, document, problem}]}
 *   projectRoots: absolute paths (the MCP roots). Each is walked with walkAll, so every nested repository (submodule,
 *   nested clone or worktree) is a root of its own with its own document. `label` is the nested root's path relative
 *   to its project root, for the local caller only ("" for the project root); it is never put in a document.
 *   problem: null, or {at, keyword} when the assembled document fails the schema or a strict intake check: such a
 *   document must not be sent (our bug, not the person's).
 *   options:
 *     key          the per-install key (default: secrets.loadInstallKey({configDir}))
 *     configDir    where install.key lives (default $CUSTOSA_CONFIG_DIR, then ~/.config/custosa)
 *     bundleDir    the rule bundle (manifest.json, rules/, queries/; default the package's knowledge/ folder)
 *     rulesetId    overrides the manifest's ruleset_id (tests)
 *     session, answers, environment, inspectorVersion
 *     collectCatalog(queries) -> collectCatalog's result; collectPlatform() -> collectPlatform's result (replaceable;
 *       the defaults read the phisc service entry and platform.json)
 *     walkOptions  passed to walkAll
 *     includeOther  how many roots beyond the first project root's own (nested repositories, then other project
 *       roots, in walk order) get a document (default all); the rest come back as
 *       {skipped: true, root_id} with no document. Such a document's catalog and platform collectors are not_run.
 *     selectOther  root ids (from an earlier listing): only those extra roots get a document, within the budget.
 *       Every project root is walked either way, so the listing is complete.
 *
 * The rule the whole module keeps (the governing question: could this let something pass that we didn't observe?):
 * every collector has exactly one collection entry with an explicit status; a collector that throws is failed with
 * internal_error and no error text; anything not observed is absent with a reason, never a default that reads as
 * clean. No absolute path is ever put in a document (root_id is an HMAC of it; walkAll's gitdirAbs stays local), and
 * odd names and path segments are hashed (ids.mjs), never dropped. .env files are listed by name; only one git tracks
 * is read, for the secret scan, and no value from it is sent. */
import { readFileSync, existsSync, statSync } from "node:fs";
import { createHash } from "node:crypto";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { assertInside, EXCLUDED_DIRS, NOT_ANALYZED_MAX, walkAll as defaultWalkAll } from "./files.mjs";
import { readdir } from "node:fs/promises";
import { locateGitdir, readTracked, isCaseInsensitive } from "./gitread.mjs";
import { contentKeyOf, readState } from "./state.mjs";
import { bundleMatches, byMatch, byPriority, defaultWorkers, linksOf, loadRules, loadRulesInThread, runRules as defaultRunRules, toContractNotAnalyzed } from "./rules.mjs";
import { languageOf as parseLanguageOf, mainRepairBudget, parseCode } from "./parse.mjs";
import { Handlers } from "./captures.mjs";
import { normalizeBreaks } from "./rules-worker.mjs";
import { scanSecrets as defaultScanSecrets, loadInstallKey, configDirFor, compareSecrets } from "./secrets.mjs";
import { toFactCatalog, QUERY_ROW_LIMITS, shippedQuerySql, V1_QUERY_IDS, V2_QUERIES } from "./catalogfacts.mjs";
import { collectCatalog } from "./catalog.mjs";
import { readService } from "./pgservice.mjs";
import { collectPlatform as defaultCollectPlatform, toFactPlatform, CONTRACT_KEYS } from "./platform.mjs";
import { collectEdgeFunctions } from "./edgefunctions.mjs";
import { detectFrameworks, FINGERPRINTS, FRAMEWORKS as FRAMEWORK_LIST } from "./frameworks.mjs";
import { scanImports } from "./imports.mjs";
import { manifestsOf } from "./manifests.mjs";
import { classifyColumn, observedTenancy } from "./columns.mjs";
import { hashed, rootId, sentIdentifier, sentPath } from "./ids.mjs";
import { documentValueProblem, screenValue } from "./valueshape.mjs";
import { readWalked } from "./walkread.mjs";
import { kindAt } from "./locationkind.mjs";
import { validateFactDocument } from "./schema.mjs";
import { LOCATION_RANGE_MAX } from "./contracts.mjs";
import { VERSION as PACKAGE_VERSION } from "../version.mjs";

// The rule bundle shipped in the package: rules/ (manifest.json, rules/, queries/), synced by npm run sync-rules.
export const DEFAULT_BUNDLE_DIR = fileURLToPath(new URL("../../rules/", import.meta.url));
export { NOT_ANALYZED_MAX };
export const DATA_FILES_MAX = 1_000;
export const SECRETS_MAX = 1_000;
export const MAX_DOCUMENT_BYTES = 5_000_000;
// The evaluator's limit on distinct catalog tables, counted across these queries' rows (the evaluator's intake.py MAX_TABLES
// and _TABLE_QUERIES). A document past it is refused there before the schema, so it is never sent.
export const MAX_TABLES = 2_500;
const TABLE_QUERIES = new Set(["table_columns", "rls_status", "table_grants"]);

/* The first rows pointer where the distinct schema.table names, compared without letter case as intake.table_count
 * does, pass MAX_TABLES; null when they don't. Tolerant of any shape: it runs before the schema. */
function tooManyTables(doc) {
  const queries = Array.isArray(doc?.catalog?.queries) ? doc.catalog.queries : [];
  const seen = new Set();
  for (const [i, q] of queries.entries()) {
    if (!q || !TABLE_QUERIES.has(q.query_id) || !Array.isArray(q.rows)) continue;
    for (const r of q.rows) if (r && typeof r === "object") seen.add(`${r.schema_name}.${r.table_name}`.toLowerCase());
    if (seen.size > MAX_TABLES) return `/catalog/queries/${i}/rows`;
  }
  return null;
}
/* The time one check may spend collecting (walk, rules, secret scan), from the start of the build. The
 * budget fits the call's 290 s (tool.mjs CALL_BUDGET_MS), keeping the evaluator's answer its full margin: the whole
 * build (TOTAL_BUDGET_MS, 140 s) plus the longest wait for one answer (client.mjs EVALUATOR_TIMEOUT_MS, 150 s) is the
 * call. Collection gets 120 s of that, and the steps after it 20 s. Past it, files not yet matched are time_limit and
 * the rules collector is truncated, timeout; files not yet scanned for secrets make the secrets collector truncated,
 * timeout. */
export const COLLECT_BUDGET_MS = 120_000;
/* The whole check, rule loading, catalog, platform, walk, rules, secrets and the steps after them, ends within this from
 * the start of the build: per-file limits and worker exits shrink to fit it. */
export const TOTAL_BUDGET_MS = 140_000;
/* the corpus fixed budget. Custosa's corpus scorer sets
 * CUSTOSA_CORPUS_FIXED_BUDGET=1 for `custosa inspect --document`. The build then gets these limits on every machine,
 * far above what any corpus app needs, and a document that still hit one is refused (timedOut), so the gate sees one
 * output per input or an error, never a cut that depends on the machine's speed or load. Never set for users. */
export const CORPUS_BUDGET = Object.freeze({ timeBudgetMs: 20 * 60_000, readsBudgetMs: 5 * 60_000, fileTimeoutMs: 120_000 });
export function corpusBudget(env = process.env) {
  const v = env.CUSTOSA_CORPUS_FIXED_BUDGET;
  if (v === undefined || v === "") return null;
  if (v === "1") return CORPUS_BUDGET;
  throw new Error("CUSTOSA_CORPUS_FIXED_BUDGET must be 1 or unset.");
}
/* Whether a document was cut by time anywhere: a time_limit file, or a collector truncated on timeout. */
export function timedOut(doc) {
  return (doc?.files?.not_analyzed ?? []).some((e) => e.reason === "time_limit")
    || (doc?.collection ?? []).some((c) => c.reason === "timeout");
}
/* The catalog and platform reads get at most this much of the budget (they run first). */
const READS_BUDGET_MS = 20_000;
const SECRETS_RESERVE_MS = 5_000; // the rules stop this long before the budget ends, so the secret scan still runs
const IMPORTS_BUDGET_MS = 5_000; // the most the import scan takes; what it hasn't reached is just not listed
/* Once every file is decided, how long the rules step waits for workers it terminated (a time_limit file whose native
 * parse or match is still running) before going on. It used to be the 30 s close grace, which on a file like 100,000
 * nested brackets spent most of the budget left waiting, starving the secret scan; the result is the same either way
 * (a terminated worker means a time_limit file, so the collector is already truncated, timeout). A thread still
 * running is left to finish on its own (rules.mjs MatchWorker). */
const RULES_END_GRACE_MS = 2_000;
const SECRET_READ_MAX = 2_000_000;
const SECRET_BATCH = 256;
const RULESET_ID = /^[0-9]{4}-[0-9]{2}-[0-9]{2}\.[0-9a-f]{8}$/;
export const QUERY_IDS = Object.freeze([...V1_QUERY_IDS.slice(0, 1), "rls_policies", ...V1_QUERY_IDS.slice(1),
  ...V2_QUERIES.map((q) => q.query_id)]);

/* The walker's collection reasons in the contract's vocabulary. Its own codes: tracked_set_unknown (ignored
 * paths couldn't be checked against the tracked set; each is listed as ignored_unverified, which is the contract's
 * ignore_unverified), unreadable_directory and root_unreadable (the walk was refused a directory: not_permitted). */
export const A2_REASON_TO_CONTRACT = Object.freeze({
  file_limit: "file_limit", item_limit: "item_limit", tracked_set_unknown: "ignore_unverified",
  ignore_unverified: "ignore_unverified", unreadable_directory: "not_permitted", root_unreadable: "not_permitted",
});
/* What the walk didn't see, as a contract reason, or null when it saw everything that could hold a file of this root:
 * the walk truncated (its own reason), a count that stopped (totalExact false), not_analyzed entries dropped past the
 * cap, a directory it didn't enter for a reason that isn't "not app code" (unreadable, a symlink, ignored but
 * unverified, past the file or time limit), or a dependency or build folder git may track (tracked yes or not_checked).
 * The secrets and edge_functions collectors read it: what wasn't walked wasn't scanned or searched for a config.toml. */
// A symlink to a folder inside the root is no gap: its target is walked at its own path.
const BLIND_DIRECTORY = Object.freeze({ unreadable: "not_permitted", symlink_outside_root: "not_permitted",
  symlink_broken: "not_permitted", file_limit: "file_limit", time_limit: "timeout", ignored_unverified: "ignore_unverified",
  ignore_file_unreadable: "ignore_unverified" });
const VCS_DIRS = new Set([".git", ".hg", ".svn"]);
export function walkGap(result) {
  if (!result) return null;
  const counts = result.counts ?? {};
  if (result.status === "truncated") return A2_REASON_TO_CONTRACT[result.reason] ?? "internal_error";
  if (counts.totalExact === false) return "file_limit";
  if ((counts.notAnalyzedDropped ?? 0) > 0) return "item_limit";
  const entries = result.notAnalyzed ?? [];
  // A symlink out of the root, or a broken one, may stand for a whole folder (the walk lists it as a file entry when
  // it doesn't follow it): a gap whatever its kind.
  if (entries.some((e) => e.reason === "symlink_outside_root" || e.reason === "symlink_broken")) return "not_permitted";
  const dir = entries.find((e) => e.kind === "directory" && Object.hasOwn(BLIND_DIRECTORY, e.reason));
  if (dir) return BLIND_DIRECTORY[dir.reason];
  if (entries.some((e) => e.reason === "excluded_directory" && e.tracked !== "no" && !VCS_DIRS.has(e.path.slice(e.path.lastIndexOf("/") + 1)))) {
    return "ignore_unverified";
  }
  return null;
}

/* The git collector's failures the contract names (rule_bundle.md 3.4); any other index failure is internal_error. */
const GIT_REASON = Object.freeze({ index_hard_link: "index_hard_link", shared_index_missing: "shared_index_missing",
  shared_index_hard_link: "shared_index_hard_link" });
/* the secret scan's truncation reasons on files.not_analyzed (a file the secret scan didn't read in full counts against coverage). */
export const SECRETS_TO_NOT_ANALYZED = Object.freeze({ unreadable: "binary", scan_error: "parse_error",
  bad_input: "unreadable", joined_view_budget: "too_large", match_cut_at_window: "too_large" });
const SECRETS_REASON_ORDER = ["bad_input", "scan_error", "unreadable", "match_cut_at_window", "joined_view_budget"];
export class NoRulesetError extends Error {
  constructor() {
    super("This build of the custosa package has no rule bundle (rules/manifest.json), so it can't send a fact document.");
    this.name = "NoRulesetError"; this.code = "NO_RULESET";
  }
}

const reasonOrNull = (status, reason) => (status === "ok" || status === "empty" ? null : reason);
const entry = (collector, status, count, reason) => ({ collector, status, count: Math.max(0, Math.min(count | 0, 100_000_000)), reason: reasonOrNull(status, reason) });
/* A collector that throws gives its fallback. One stderr line names the collector and the error's class, never its
 * message or any value, so a failure can be found without leaking what it read. */
async function guarded(name, fn, fallback) {
  try { return await fn(); } catch (err) {
    const kind = err instanceof Error ? err.constructor?.name || "Error" : typeof err;
    process.stderr.write(`custosa inspect: ${name} collector failed: ${kind}\n`);
    return fallback();
  }
}

/* ---------------------------------------------------------------- the rule bundle */

/* bundleDir defaults to $CUSTOSA_BUNDLE_DIR (a rule bundle checkout, for the corpus scorer and CI), then the package's
 * rules/ folder. The document's ruleset_id is the bundle manifest's. The package's own query text is read with
 * catalogfacts.shippedQuerySql (cli-b7's loader); an override bundle's from its queries/ folder. */
/* Parsed once per process and bundle (loading and checking every rule takes seconds), keyed by the bundle folder and
 * the manifest's sha256 and mtime, so a synced bundle is picked up on the next call. A rulesetId override (tests) is
 * applied per call and never stored: a later plain call gets the manifest's id.
 * Two ways in, sharing one cache entry: loadRuleset (synchronous: the rules parsed on the calling thread) and
 * startRuleset (the rules parsed in a thread of their own, rules.loadRulesInThread, while the caller reads the catalog,
 * the platform and walks; the stdio server starts it once at launch, preloadRuleset). Either way the rules of one
 * entry are parsed once and the same array is handed out. */
const RULESET_CACHE = new Map(); // key -> {id: the manifest's or null, queries, rules?: Rule[] | null, loading?: {promise, worker, holds}}
const RULESET_CACHE_MAX = 4; // older bundles (a long-lived server across syncs) are let go
function bundleEntry({ bundleDir = process.env.CUSTOSA_BUNDLE_DIR || DEFAULT_BUNDLE_DIR, rulesetId = null } = {}) {
  let manifest = null, mtime = 0;
  try { manifest = readFileSync(join(bundleDir, "manifest.json"), "utf8"); mtime = statSync(join(bundleDir, "manifest.json")).mtimeMs; } catch { manifest ??= null; }
  let manifestId = null;
  try { manifestId = JSON.parse(manifest).ruleset_id; } catch { manifestId = null; }
  const id = rulesetId ?? manifestId;
  if (typeof id !== "string" || !RULESET_ID.test(id)) throw new NoRulesetError(); // before any rule is loaded
  const cacheKey = `${bundleDir}\0${createHash("sha256").update(manifest ?? "").digest("hex")}\0${mtime}`;
  let base = RULESET_CACHE.get(cacheKey);
  if (!base) {
    base = { id: manifestId, queries: loadQueries(bundleDir) };
    RULESET_CACHE.set(cacheKey, base);
    while (RULESET_CACHE.size > RULESET_CACHE_MAX) RULESET_CACHE.delete(RULESET_CACHE.keys().next().value);
  }
  return { base, id, bundleDir, manifest: manifest ?? "", cacheKey };
}
/* The rules parsed on this thread: Rule[], null for a broken bundle (rules failed), or "stale" when the bundle changed
 * while it was read (rules.bundleMatches). */
const loadRulesHere = (bundleDir, manifest) => {
  let rules;
  try { rules = loadRules(join(bundleDir, "rules")); } catch { rules = null; }
  return bundleMatches(bundleDir, manifest) ? rules : "stale";
};
/* A load that saw the bundle change under it (a sync mid-read) is never kept: its cache entry goes, so the next call
 * starts over keyed on the new manifest, and this call's rules collector is failed, internal_error. Rules are never
 * paired with a ruleset_id they don't belong to. */
const forget = (cacheKey, base) => { if (RULESET_CACHE.get(cacheKey) === base) RULESET_CACHE.delete(cacheKey); };

export function loadRuleset(options = {}) {
  const { base, id, bundleDir, manifest, cacheKey } = bundleEntry(options);
  if (!("rules" in base)) {
    const rules = loadRulesHere(bundleDir, manifest);
    if (rules === "stale") { forget(cacheKey, base); return { ...base, id, rules: null, stale: true }; }
    base.rules = rules;
  }
  return id === base.id ? base : { ...base, id };
}

/* How long the loading thread may take before it is terminated and the load given up (a hung thread): far past any
 * check's budget, so only a thread that will never answer meets it. The next call starts a new one. */
export const LOADER_TIMEOUT_MS = 120_000;
const LOAD_TIMED_OUT = Symbol("load timed out");
/* What a load resolves to when the bundle's rule files aren't the ones its manifest names (rules.bundleMatches). */
const BUNDLE_STALE = Symbol("bundle stale");

/* -> {id, queries, rules: Promise<Rule[] | null | BUNDLE_STALE | LOAD_TIMED_OUT>, ready(): whether the rules are parsed,
 * hold(), release()} (null: an invalid rule set; BUNDLE_STALE: rule files that aren't the manifest's). Throws
 * NoRulesetError at once (no thread started) when the package has no bundle. hold() keeps the loading thread
 * referenced while the caller waits on it; release() lets it go (a CLI run that gave up on it can then exit, while a
 * server's cache still gets the rules when it finishes). */
export function startRuleset(options = {}) {
  const { base, id, bundleDir, manifest, cacheKey } = bundleEntry(options);
  if (!("rules" in base) && !base.loading) {
    let worker = null, promise;
    try {
      const t = loadRulesInThread(bundleDir, manifest);
      worker = t.worker;
      worker.unref();
      let timer;
      const hung = new Promise((resolve) => { timer = setTimeout(() => resolve(LOAD_TIMED_OUT), options.loaderTimeoutMs ?? LOADER_TIMEOUT_MS); });
      timer.unref();
      promise = Promise.race([t.result.catch(() => loadRulesHere(bundleDir, manifest)), hung]) // no thread: parsed here instead
        .then((rules) => { clearTimeout(timer); if (rules === LOAD_TIMED_OUT) t.worker.terminate().catch(() => {}); return rules; });
    } catch { promise = Promise.resolve().then(() => loadRulesHere(bundleDir, manifest)); }
    const loading = { worker, holds: 0 };
    loading.promise = promise.then((rules) => {
      if (base.loading === loading) base.loading = null;
      // Hung (terminated) or stale: nothing is kept, so the next call loads again.
      if (rules === LOAD_TIMED_OUT) return rules;
      if (rules === "stale") { forget(cacheKey, base); return BUNDLE_STALE; }
      if (!("rules" in base)) base.rules = rules;
      return base.rules;
    });
    base.loading = loading;
  }
  const loading = base.loading;
  let held = false;
  return {
    id, queries: base.queries,
    rules: "rules" in base ? Promise.resolve(base.rules) : loading.promise,
    ready: () => "rules" in base,
    hold() { if (held || !loading?.worker) return; held = true; if (loading.holds++ === 0) loading.worker.ref(); },
    release() { if (!held) return; held = false; if (--loading.holds === 0) loading.worker.unref(); },
  };
}

/* Start parsing the rule bundle now (the stdio server, at launch), so the first check doesn't spend its budget on it.
 * Never throws; a package without a bundle is reported by the check itself. */
export function preloadRuleset(options = {}) {
  try { const r = startRuleset(options); r.rules.catch(() => {}); return r; } catch { return null; }
}

function loadQueries(bundleDir) {
  const queries = [];
  for (const query_id of QUERY_IDS) {
    const file = join(bundleDir, "queries", `${query_id}.sql`);
    let sql = null;
    try {
      if (bundleDir === DEFAULT_BUNDLE_DIR) sql = shippedQuerySql(query_id);
      else if (existsSync(file)) sql = readFileSync(file, "utf8");
    } catch { sql = null; }
    if (sql === null) sql = V2_QUERIES.find((q) => q.query_id === query_id)?.sql ?? null;
    if (sql !== null) queries.push({ query_id, sql, ...(QUERY_ROW_LIMITS[query_id] ? { row_limit: QUERY_ROW_LIMITS[query_id] } : {}) });
  }
  return queries;
}

/* ---------------------------------------------------------------- shared: catalog and platform */

/* opts.provider: the platform config's provider (platform.mjs), so the catalog collector runs storage_buckets on
 * Supabase instead of reporting it not_run with platform_mismatch. */
async function defaultCollectCatalog(queries, opts = {}) {
  let conn;
  try { conn = readService("phisc"); } catch (err) {
    const reason = ["service_file_missing", "service_missing"].includes(err?.code) ? "service_missing" : err?.code === "wrong_user" ? "wrong_user" : "service_invalid";
    return { status: reason === "service_missing" ? "not_run" : "failed", count: 0, reason, preflight: null,
      queries: queries.map((q) => ({ query_id: q.query_id, status: "not_run", reason, rows: [] })) };
  }
  return collectCatalog(conn, queries, { ...(opts.provider ? { provider: opts.provider } : {}), ...(opts.deadline ? { deadline: opts.deadline } : {}) });
}

export const STORAGE_FILTERED_NOTE = "Row-level security on storage.buckets may hide buckets from the inspector's read-only role (phisc_ro), so the bucket list was sent as incomplete. To have every bucket checked, the user can add a SELECT policy on storage.buckets for phisc_ro with USING (true).";

export async function catalogFacts(ruleset, key, collect = defaultCollectCatalog, { provider = null, deadline = null } = {}) {
  const shipped = ruleset.queries;
  const raw = await guarded("catalog", () => collect(shipped, { provider, ...(deadline ? { deadline } : {}) }), () => ({ status: "failed", count: 0, reason: "internal_error", preflight: null,
    queries: shipped.map((q) => ({ query_id: q.query_id, status: "not_run", reason: "internal_error", rows: [] })) }));
  const res = raw && typeof raw === "object" ? { ...raw } : { status: "failed", reason: "internal_error", preflight: null, queries: [] };
  const listed = new Set((Array.isArray(res.queries) ? res.queries : []).map((q) => q?.query_id));
  // A query the bundle doesn't ship: an explicit failure (a broken build), never left for the evaluator to infer.
  res.queries = [...(Array.isArray(res.queries) ? res.queries : []),
    ...QUERY_IDS.filter((id) => !listed.has(id)).map((query_id) => ({ query_id, status: "failed", reason: "no_sql", rows: [] }))];
  const pairs = { table_columns: [], rls_policies: [] };
  const fact = await guarded("catalog_facts",
    () => toFactCatalog(res, { key, onRow: (id, r, m) => { if (pairs[id]) pairs[id].push([r, m]); } }),
    () => { pairs.table_columns = []; pairs.rls_policies = []; return toFactCatalog({ status: "failed", reason: "internal_error", preflight: null,
      queries: QUERY_IDS.map((query_id) => ({ query_id, status: "not_run", reason: "internal_error", rows: [] })) }, { key }); });
  const status = (id) => fact.catalog.queries.find((q) => q.query_id === id)?.status;
  const usable = (s) => s === "ok" || s === "truncated";
  const columns = usable(status("table_columns")) ? pairs.table_columns.map(([r, m]) => ({
    table: `${m.schema_name}.${m.table_name}`, column: m.column_name, type: m.data_type,
    class: classifyColumn(r.column_name, r.data_type),
  })) : [];
  const tenancy = observedTenancy({
    catalogStatus: fact.collection.status,
    policies: usable(status("rls_policies")) && usable(status("table_columns"))
      ? pairs.rls_policies.map(([r, m]) => ({ schema: r.schema_name, table: r.table_name, tenant_comparison: m.tenant_comparison, tenantColumns: m.tenantColumns ?? [] })) : [],
    columns: pairs.table_columns.map(([r, m]) => ({ schema: r.schema_name, table: r.table_name, column: r.column_name, sentColumn: m.column_name })),
  });
  // Said to the assistant locally (local_notes), never sent: a bucket list row-level security may have filtered.
  const notes = (Array.isArray(res.queries) ? res.queries : []).some((q) => q && q.reason === "row_security_filtered")
    ? [STORAGE_FILTERED_NOTE] : [];
  return { catalog: fact.catalog, collection: fact.collection, columns, tenancy, notes };
}

export async function platformFacts(collect, deadline = null) {
  collect ??= () => defaultCollectPlatform(undefined, deadline ? { deadline } : {});
  const raw = await guarded("platform", collect, () => ({ provider: null, status: "failed", reason: "internal_error", settings: {} }));
  const provider = raw && typeof raw.provider === "string" ? raw.provider : null; // platform.mjs's id: supabase, rds, ...
  const out = await guarded("platform_facts", () => toFactPlatform(raw), () => ({
    platform: { provider: "unknown", settings: Object.fromEntries(CONTRACT_KEYS.map((k) => [k, "not_read"])) },
    collection: { collector: "platform", status: "failed", count: 0, reason: "internal_error" },
  }));
  // notes: local warnings about the platform token (platform.mjs platformTokenNotes), never sent.
  const notes = Array.isArray(raw?.notes) ? raw.notes.filter((n) => typeof n === "string") : [];
  return { ...out, provider, notes };
}

/* ---------------------------------------------------------------- per root */

function filesEntry(result) {
  if (!result) return entry("files", "failed", 0, "internal_error");
  const status = ["ok", "empty", "truncated", "failed", "not_run"].includes(result.status) ? result.status : "failed";
  return entry("files", status, result.count ?? 0, A2_REASON_TO_CONTRACT[result.reason] ?? "internal_error");
}

function gitEntry(result) {
  const g = result?.git;
  if (!g) return entry("git", "failed", 0, "internal_error");
  if (g.status === "ok" || g.status === "empty") return entry("git", g.status, g.tracked ?? 0, null);
  if (g.status === "not_run") return entry("git", "not_run", 0, g.reason === "no_git_dir" ? "not_configured" : "not_permitted");
  return entry("git", "failed", 0, GIT_REASON[g.reason] ?? "internal_error");
}

/* files.data_files (rule_bundle.md section 8): by name and size only, never opened. */
export function dataFileKind(path, size) {
  const name = path.slice(path.lastIndexOf("/") + 1).toLowerCase();
  if (name.endsWith(".sql.gz")) return "sql_dump";
  const ext = name.includes(".") ? name.slice(name.lastIndexOf(".") + 1) : "";
  if (["dump", "backup", "bak", "pgdump"].includes(ext)) return "sql_dump";
  if (ext === "sql") return size === null || size >= 1_000_000 ? "sql_dump" : null; // size unknown: at least the walk's limit
  if (ext === "csv" || ext === "tsv") return "csv";
  if (ext === "parquet") return "parquet";
  if (ext === "jsonl" || ext === "ndjson") return "json_lines";
  if (name.endsWith(".tar.gz") || ["zip", "tar", "tgz", "7z", "gz"].includes(ext)) return "archive";
  return null;
}
export function bytesBucket(size) {
  if (size === null) return "1mb_to_100mb"; // over the walk's 2 MB limit, exact size unread: the lowest band it can be in
  if (size < 10_000) return "under_10kb";
  if (size < 1_000_000) return "10kb_to_1mb";
  if (size < 100_000_000) return "1mb_to_100mb";
  return "over_100mb";
}

async function trackedLookup(abs, boundary) {
  try {
    const loc = await locateGitdir(abs, boundary ? { boundary } : {});
    const t = await readTracked(abs, loc);
    if (!t.known) return () => "not_checked";
    const ci = await isCaseInsensitive(loc.realRoot);
    const fold = ci ? (p) => p.toLowerCase() : (p) => p;
    const set = new Set([...t.paths].map(fold));
    return (p) => (set.has(fold(p)) ? "yes" : "no");
  } catch { return () => "not_checked"; }
}

async function dataFiles(rootEntry, top, key) {
  const r = rootEntry.result;
  const found = [];
  for (const f of r.files) { const kind = dataFileKind(f.path, f.size); if (kind) found.push({ path: f.path, kind, size: f.size }); }
  for (const e of r.notAnalyzed) {
    if (e.kind !== "file" || e.reason !== "too_large") continue;
    // Over the walk's limit, so not in files: its real size when it can be read (lstat only, never opened).
    const size = await assertInside(rootEntry.abs, e.path).then((st) => st.size, () => null);
    const kind = dataFileKind(e.path, size);
    if (kind) found.push({ path: e.path, kind, size });
  }
  if (found.length === 0) return { items: [], cut: false };
  const tracked = await trackedLookup(rootEntry.abs, rootEntry.rel ? top : null);
  const items = found.map((d) => ({ path: sentPath(key, d.path), kind: d.kind, bytes_bucket: bytesBucket(d.size), tracked: tracked(d.path) }));
  return { items: items.slice(0, DATA_FILES_MAX), cut: items.length > DATA_FILES_MAX };
}

/* the secret scan's pattern ids are bare names (stripe-secret-key); the contract's secret rule ids are secrets.<name>
 * (rule_bundle.md section 6, enums.RULE_ID_PATTERN). */
export const secretRuleId = (id) => (id.startsWith("secrets.") ? id : `secrets.${id}`);

async function secretsFacts(rootEntry, key, sent, scan, configDir, deadline = null) {
  const r = rootEntry.result;
  const secrets = [], truncated = [];
  let outOfTime = false;
  let batch = [];
  const flush = () => {
    if (!batch.length) return;
    const out = scan(batch, { configDir });
    for (const s of out.secrets) secrets.push(s);
    for (const t of out.truncated) truncated.push(t);
    batch = [];
  };
  // Every walked file goes to the secret scan (the walk lists .env files apart and never here): no extension list and no binary
  // sniff decide what is scanned. the secret scan's own rule reads a binary file as unreadable, which truncates the collector, so
  // nothing is skipped silently. A file this module can't read is listed and truncates the collector too.
  const sizeCut = [], timeCut = [];
  for (const f of r.files) {
    if (deadline !== null && Date.now() >= deadline) { outOfTime = true; timeCut.push(sent.get(f.path)); continue; }
    const read = await readWalked(rootEntry.abs, f.disk ?? f.path, SECRET_READ_MAX);
    if (!read.buf) {
      if (read.refused === "too_large") sizeCut.push(sent.get(f.path));
      else truncated.push({ path: sent.get(f.path), in_history: false, reason: "unreadable" });
      continue;
    }
    batch.push({ path: sent.get(f.path), text: read.buf });
    if (batch.length >= SECRET_BATCH) flush();
  }
  flush();
  // Env-named files: one git tracks is committed, so it is read here and
  // scanned like any file; nothing about its values leaves this machine (the secret scan sends rule, path, line and fingerprint).
  // Untracked and ignored ones are never opened, and don't count against the scan. One whose standing couldn't be
  // checked is never opened either, and keeps the scan from reading as clean: truncated, unreadable (its path is the
  // files.env_files entry, git not_checked).
  let envUnchecked = false;
  const envBatch = [];
  const flushEnv = () => {
    if (!envBatch.length) return;
    const out = scan([], { configDir, envFiles: envBatch.splice(0) });
    for (const s of out.secrets) secrets.push(s);
    for (const t of out.truncated) truncated.push(t);
  };
  for (const e of r.envFiles ?? []) {
    if (e.git === "not_checked") { envUnchecked = true; continue; }
    if (e.git !== "tracked") continue;
    const path = sentPath(key, e.path);
    if (deadline !== null && Date.now() >= deadline) { outOfTime = true; timeCut.push(path); continue; }
    const read = await readWalked(rootEntry.abs, e.path, SECRET_READ_MAX, { envName: true });
    if (!read.buf) {
      if (read.refused === "too_large") sizeCut.push(path);
      else truncated.push({ path, in_history: false, reason: "unreadable" });
      continue;
    }
    envBatch.push({ path, tracked: true, text: read.buf });
    if (envBatch.length >= SECRET_BATCH) flushEnv();
  }
  flushEnv();
  // Files the walk listed but couldn't keep were not scanned either.
  const walkCut = r.notAnalyzed.filter((e) => e.kind === "file" && ["too_large", "unreadable", "file_limit"].includes(e.reason));
  const seen = new Set();
  const list = secrets.filter((s) => {
    const id = `${s.rule_id}\0${s.path}\0${s.line}\0${s.fingerprint}`;
    if (seen.has(id)) return false;
    seen.add(id); return true;
  }).sort(compareSecrets)
    .map((s) => ({ rule_id: secretRuleId(s.rule_id), path: s.path, line: s.line, fingerprint: s.fingerprint, in_history: "not_checked" }));
  let status = list.length ? "ok" : "empty", reason = null;
  const a5 = SECRETS_REASON_ORDER.find((x) => truncated.some((t) => t.reason === x));
  const gap = walkGap(r);
  if (outOfTime) { status = "truncated"; reason = "timeout"; } // the check's time budget ran out mid-scan
  // What the walk didn't see wasn't scanned. A folder or link the walk was refused or never follows (not_permitted on
  // the files side: a symlink out of the root, an unreadable folder) is, for the secret scan, files it could not read:
  // unreadable, one of enums.SECRETS_TRUNCATED_REASONS (rule_bundle.md section 6).
  else if (gap) { status = "truncated"; reason = gap === "not_permitted" ? "unreadable" : gap; }
  else if (a5) { status = "truncated"; reason = a5; }
  else if (list.length > SECRETS_MAX) { status = "truncated"; reason = "item_limit"; }
  else if (envUnchecked || walkCut.some((e) => e.reason === "unreadable")) { status = "truncated"; reason = "unreadable"; }
  else if (sizeCut.length || walkCut.some((e) => e.reason === "too_large")) { status = "truncated"; reason = "size_limit"; }
  else if (walkCut.length) { status = "truncated"; reason = "file_limit"; }
  const notAnalyzed = [
    ...truncated.map((t) => ({ path: t.path, kind: "file", reason: SECRETS_TO_NOT_ANALYZED[t.reason] ?? "unreadable", tracked: null })),
    ...sizeCut.map((path) => ({ path, kind: "file", reason: "too_large", tracked: null })),
    ...timeCut.map((path) => ({ path, kind: "file", reason: "time_limit", tracked: null })),
  ];
  return { secrets: list.slice(0, SECRETS_MAX), collection: entry("secrets", status, list.length, reason), notAnalyzed };
}

/* The assistant's answers (tool.mjs input, each with the issuing question's expects when the tool has it) as fact
 * answers. A location is confirmed here: the path must be a file this root's walk listed and the lines must exist in
 * it; then it is sent (path hashed where needed) with location_kind set to the question's expected kind when
 * locationkind.kindAt sees that construct there (E3), else other. Otherwise the location is null with not_found (or not_checked when the file couldn't be read): an
 * unconfirmed path is never forwarded. */
async function factAnswers(answers, rootEntry, key, given = new Map()) {
  const out = [];
  const files = new Map((rootEntry?.result?.files ?? []).map((f) => [f.path, f]));
  // One span, path:line or path:line-line: its sent form and the file's text, or a kind saying why it isn't confirmed.
  const confirm = async (span) => {
    const m = typeof span === "string" ? /^(.*):(\d+)(?:-(\d+))?$/.exec(span) : null;
    const f = m ? files.get(m[1].normalize("NFC")) : null;
    if (!m || !f) return { kind: "not_found" };
    const n = Number(m[2]), last = m[3] === undefined ? n : Number(m[3]);
    const read = await readWalked(rootEntry.abs, f.disk ?? f.path, SECRET_READ_MAX);
    if (!read.buf) return { kind: "not_checked" };
    const text = normalizeBreaks(read.buf.toString("utf8")); // a lone CR is a line break
    const lines = text.split("\n").length;
    if (!(n >= 1 && last >= n && last - n < LOCATION_RANGE_MAX && last <= lines)) return { kind: "not_found" };
    return { sent: `${sentPath(key, f.path)}:${n}${m[3] === undefined ? "" : `-${last}`}`, f, text, n, last };
  };
  for (const a of answers ?? []) {
    if (a.answer !== "here") { out.push({ object_id: a.object_id, question_id: a.question_id, answer: a.answer, location: null, location_kind: null }); continue; }
    const at = await confirm(a.location);
    if (!at.sent) { out.push({ object_id: a.object_id, question_id: a.question_id, answer: a.answer, location: null, location_kind: at.kind }); continue; }
    // every other span must be confirmed too, or none is sent (a shorter list would only make the answer
    // easier to grade E3). Duplicates of a span already named are dropped.
    const spans = [];
    const forms = new Map([[at.sent, a.location]]); // each sent span's form as the assistant gave it (spanWarnings)
    let unconfirmed = null;
    for (const span of Array.isArray(a.at) ? a.at : []) {
      const c = await confirm(span);
      if (!c.sent) { unconfirmed = c.kind; break; }
      if (c.sent !== at.sent && !spans.includes(c.sent)) { spans.push(c.sent); forms.set(c.sent, span); }
    }
    if (unconfirmed) { out.push({ object_id: a.object_id, question_id: a.question_id, answer: a.answer, location: null, location_kind: unconfirmed }); continue; }
    for (const [sent, span] of forms) given.set(sent, span);
    // The kind the question expected (its E3 location kind): the first listed one whose construct is seen there; else other.
    const lang = at.f.lang ?? parseLanguageOf(at.f.path);
    const kinds = (Array.isArray(a.expects) ? a.expects : typeof a.expects === "string" ? [a.expects] : []).filter((k) => typeof k === "string" && k !== "other");
    const kind = kinds.find((k) => kindAt(k, { path: at.f.path, lang, text: at.text, start: at.n, end: at.last, key })) ?? "other";
    out.push({ object_id: a.object_id, question_id: a.question_id, answer: a.answer, location: at.sent, location_kind: kind,
      ...(typeof a.code === "string" ? { code: a.code } : {}), ...(spans.length ? { at: spans } : {}) });
  }
  return out;
}

/* the local span pre-check, a warning only. Each span of a located answer (location and at)
 * must overlap a match of the object's practice in the same file that the evaluator can confirm on: evidence or an
 * item with has_control true, or with a code only such an item. The answer is sent as it is either way, and nothing
 * about the check is sent. given maps a sent span to the span as the assistant gave it, so the note never shows a
 * hashed path. -> the notes, one per answer with a missed span. */
export const SPAN_PRECHECK_NOTE = "{object_id}: {spans} touch no evidence or controlled item of its practice that this check found, so the evaluator won't confirm the location there. Check the file and line numbers, then answer again.";
export function spanWarnings(answers, matches, given) {
  const notes = [];
  for (const a of answers ?? []) {
    if (typeof a.location !== "string") continue;
    const practice = String(a.object_id).split("@")[0];
    const confirms = (x) => (x.kind === "item" && x.has_control === true) || (x.kind === "evidence" && typeof a.code !== "string");
    const missed = [a.location, ...(a.at ?? [])].filter((span) => {
      const s = /^(.*):(\d+)(?:-(\d+))?$/.exec(span);
      if (!s) return true;
      const n = Number(s[2]), last = s[3] === undefined ? n : Number(s[3]);
      return !(matches ?? []).some((x) => x.practice_id === practice && x.path === s[1] && confirms(x)
        && x.line_start <= last && n <= x.line_end);
    });
    if (missed.length) {
      notes.push(SPAN_PRECHECK_NOTE.replace("{object_id}", a.object_id)
        .replace("{spans}", missed.map((span) => given.get(span) ?? span).join(", ")));
    }
  }
  return notes;
}

async function buildOne(rootEntry, ctx) {
  const { key, ruleset, shared, top } = ctx;
  const result = rootEntry.result;
  const files = filesEntry(result);
  const git = result ? gitEntry(result) : entry("git", "failed", 0, "internal_error");
  const usable = result && (files.status === "ok" || files.status === "empty" || files.status === "truncated");
  const walkFiles = usable ? result.files : [];
  const walkNotAnalyzed = result ? result.notAnalyzed ?? [] : [];
  const sent = new Map(walkFiles.map((f) => [f.path, sentPath(key, f.path)]));

  const edgeOut = await guarded("edge_functions",
    () => collectEdgeFunctions(rootEntry.abs, result ?? {}, { key, filesStatus: files.status, filesReason: files.reason, gap: walkGap(result) }),
    () => ({ edge: { status: "failed", reason: "internal_error", items: [] }, notAnalyzed: [], configPaths: new Set() }));

  // Frameworks: unknown when a manifest couldn't be read or parsed. Then only the ones known from paths are sent, the
  // manifest is listed, and the files collector is truncated, so an empty list never reads as "no framework".
  const fw = usable ? await guarded("frameworks", () => detectFrameworks(rootEntry.abs, result), () => ({ frameworks: null, fromPaths: [], problems: [] }))
    : { frameworks: [], fromPaths: [], problems: [] };
  const frameworks = fw.frameworks;
  ctx.frameworks = frameworks ?? fw.fromPaths;
  // The import scan, before the rules: SDK imports in JS, TS and Python source add to the fingerprint, and
  // each fingerprint's first one is sent as evidence (files.imports). A fingerprint left unknown by a manifest stays so.
  const imp = usable ? await guarded("imports", () => scanImports(rootEntry.abs,
    walkFiles.map((f) => ({ disk: f.disk ?? f.path, path: sent.get(f.path), local: f.path, lang: f.lang ?? parseLanguageOf(f.path) ?? null })),
    { until: Math.min(ctx.deadline - SECRETS_RESERVE_MS, Date.now() + IMPORTS_BUDGET_MS) }), () => null) : null;
  // frameworks from imports and paths, sent apart from the manifests' (files.derived_frameworks); the rules run
  // for the union, while the core counts a derived one for coverage only where files.imports_dynamic says 0.
  const derived = imp ? FRAMEWORK_LIST.filter((f) => imp.frameworks.has(f)) : null;
  const ruleFrameworks = frameworks === null || !derived ? frameworks : [...new Set([...frameworks, ...derived])];
  // manifests and lockfiles by ecosystem, from walk paths only; null (sent absent) when the walk could hide one.
  const manifests = usable ? manifestsOf(result, (p) => sentPath(key, p), walkGap(result)) : null;
  const fingerprints = Array.isArray(fw.fingerprints) ? FINGERPRINTS.filter((f) => fw.fingerprints.includes(f) || imp?.seen.has(f)) : null;

  // Rules.
  let rules, rulesOut = { matches: [], links: [], notAnalyzed: [], analyzed: 0, languages: [] };
  let ruleList = null;
  if (usable) {
    const loaded = await ctx.rules();
    if (loaded.stale) ctx.stale(); // the rules collector is failed below; a local note says why
    ctx.signal?.throwIfAborted();
    if (loaded.timedOut) {
      // The bundle was still being parsed when the rules' share of the budget ran out: no file was matched. Each is
      // listed time_limit (never dropped, never a pass) and the collector is truncated, timeout; a local note says why.
      rulesOut = { matches: [], links: [], notAnalyzed: walkFiles.map((f) => ({ path: sent.get(f.path), reason: "time_limit" })),
        analyzed: 0, analyzedPaths: [], languages: [], status: "truncated", reason: "timeout", count: 0 };
      ctx.setup("parsing the rule bundle");
    } else ruleList = loaded.rules;
  }
  if (!usable) rules = entry("rules", "not_run", 0, files.reason ?? "internal_error");
  else if (rulesOut.status === "truncated") rules = entry("rules", rulesOut.status, 0, rulesOut.reason);
  else if (!ruleList) rules = entry("rules", "failed", 0, "internal_error");
  else {
    const input = [];
    for (const f of walkFiles) {
      const path = sent.get(f.path);
      // local: the shared fingerprint's path, the same on every install (contract 2.3 §3.5); never sent.
      const item = { path, local: f.path, lang: f.lang ?? parseLanguageOf(f.path) ?? null };
      if (path !== (f.disk ?? f.path)) { // the engine reads by the sent path: give it the text of a renamed file
        const read = await readWalked(rootEntry.abs, f.disk ?? f.path, 2_000_000);
        if (read.buf) item.text = read.buf.toString("utf8");
        else item.refused = read.refused; // the sent path isn't on disk, so the engine can't read it
      }
      input.push(item);
    }
    ctx.signal?.throwIfAborted();
    ctx.progress?.({ phase: "rules", done: 0, total: input.length });
    // Contract 2.3 section 3.5: each root's matches are keyed with its own .custosa/state.json content key, or null,
    // from the one read of that file the committed block is sent from too (ctx.stateRead).
    const contentKey = contentKeyOf(ctx.stateRead ?? readState(rootEntry.abs));
    rulesOut = await guarded("rules", () => ctx.runRules(ruleList, input, { key, contentKey, frameworks: ruleFrameworks, root: rootEntry.abs, workers: ctx.workers, endGraceMs: RULES_END_GRACE_MS, deadline: ctx.deadline - SECRETS_RESERVE_MS, hardDeadline: ctx.hardDeadline,
      ...(ctx.signal ? { signal: ctx.signal } : {}), ...(ctx.warm ? { warm: ctx.warm } : {}),
      ...(ctx.fileTimeoutMs ? { timeoutMs: ctx.fileTimeoutMs } : {}), onFile: (done, total) => ctx.progress?.({ phase: "rules", done, total }) }),
      () => ({ matches: [], links: [], notAnalyzed: [], analyzed: 0, languages: [], status: "failed", reason: "internal_error", count: 0 }));
    if (rulesOut.setupTimedOut) ctx.setup("starting the rule workers");
    if (rulesOut.threadsBusy) ctx.busy();
    rules = entry("rules", rulesOut.status, rulesOut.count ?? 0, rulesOut.reason ?? "internal_error");
  }

  // Secrets.
  ctx.signal?.throwIfAborted();
  ctx.progress?.({ phase: "secrets" });
  const secretsOut = usable
    ? await guarded("secrets", () => secretsFacts(rootEntry, key, sent, ctx.scanSecrets, ctx.configDir, ctx.deadline),
      () => ({ secrets: [], collection: entry("secrets", "failed", 0, "internal_error"), notAnalyzed: [] }))
    : { secrets: [], collection: entry("secrets", "not_run", 0, files.reason ?? "internal_error"), notAnalyzed: [] };

  const data = usable ? await guarded("data_files", () => dataFiles(rootEntry, top, key), () => ({ items: [], cut: true })) : { items: [], cut: false };

  // files.not_analyzed: the walk's entries, the rule engine's, the edge collector's and the secret scan's, each path
  // once per kind. A config.toml this module parsed itself is not forwarded as unsupported_language or unknown_type.
  const na = [], naSeen = new Set();
  const addNa = (e) => {
    const id = `${e.kind}\0${e.path}`;
    if (naSeen.has(id)) return;
    naSeen.add(id); na.push(e);
  };
  for (const e of walkNotAnalyzed) addNa({ path: sentPath(key, e.path), kind: e.kind, reason: e.reason, tracked: e.kind === "directory" ? e.tracked ?? "not_checked" : null });
  for (const e of edgeOut.notAnalyzed) addNa(e);
  for (const p of fw.problems) addNa({ path: sentPath(key, p.path), kind: "file", reason: p.reason, tracked: null });
  for (const e of toContractNotAnalyzed(rulesOut.notAnalyzed ?? [])) {
    if (edgeOut.configPaths.has(e.path) && (e.reason === "unsupported_language" || e.reason === "unknown_type")) continue;
    if (edgeOut.notAnalyzed.some((x) => x.path === e.path)) continue;
    addNa({ path: e.path, kind: "file", reason: e.reason, tracked: null });
  }
  for (const e of secretsOut.notAnalyzed) addNa(e);
  na.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0) || (a.kind < b.kind ? -1 : 1));

  // No silent drop: every file the walk listed as analysable is analysed by the rules, listed in not_analyzed, or a
  // config.toml the edge collector parsed. When the engine ran (it reports its analysed paths) and one isn't, the
  // document is refused (a bug here must never let a file pass unseen).
  const unaccounted = unaccountedFiles(walkFiles.map((f) => sent.get(f.path)), rulesOut, na, edgeOut.configPaths);

  let filesFinal = files;
  if ((na.length > NOT_ANALYZED_MAX || data.cut) && (files.status === "ok" || files.status === "empty")) filesFinal = entry("files", "truncated", files.count, "item_limit");
  else if (usable && (frameworks === null || edgeOut.ignored) && (files.status === "ok" || files.status === "empty")) filesFinal = entry("files", "truncated", files.count, "ignore_unverified");

  const given = new Map();
  const document = {
    schema_version: 2,
    inspector_version: ctx.inspectorVersion,
    ruleset_id: ruleset.id,
    root_id: rootId(key, rootEntry.abs),
    session: rootEntry.rel === "" && ctx.primary ? ctx.session ?? null : null,
    environment: ctx.environment,
    collection: [filesFinal, git, rules, shared.catalog.collection, shared.platform.collection, secretsOut.collection],
    files: {
      analyzed: rulesOut.analyzed ?? 0,
      not_analyzed: na.slice(0, NOT_ANALYZED_MAX),
      languages: [...new Set(rulesOut.languages ?? [])],
      frameworks: ctx.frameworks ?? [],
      // Sent only when every manifest was read; absent means unknown, never "none found".
      ...(usable && fingerprints ? { fingerprints } : {}),
      ...(imp ? { imports: imp.imports } : {}), // absent when no import scan ran
      ...(imp ? { derived_frameworks: derived, imports_dynamic: imp.dynamic } : {}), // likewise
      // with them, unless the scan didn't read every file (then the core keeps the practice open)
      ...(imp?.helpers ? { helpers: imp.helpers.map((h) => ({ path: sentPath(key, h.path), language: h.language,
        functions: [...new Set(h.functions.map((n) => sentIdentifier(key, n)))], work: h.work,
        importers: [...new Set(h.importers.map((p) => sentPath(key, p)))], importers_complete: h.importers_complete })) } : {}),
      // likewise absent unless every file was read; paths and lines only, never a name
      ...(imp?.elevated ? { elevated_imports: imp.elevated.rows.map((r) => ({ path: sentPath(key, r.path), line: r.line,
        module: sentPath(key, r.module), depth: r.depth })), elevated_imports_complete: imp.elevated.complete } : {}),
      ...(manifests ? { manifests } : {}), // absent when a skipped folder could hide a manifest
      env_files: (result?.envFiles ?? []).map((e) => ({ path: sentPath(key, e.path), git: e.git })),
      data_files: data.items,
    },
    matches: rulesOut.matches ?? [],
    catalog: shared.catalog.catalog,
    platform: shared.platform.platform,
    secrets: secretsOut.secrets,
    answers: rootEntry.rel === "" && ctx.primary ? await factAnswers(ctx.answers, rootEntry, key, given) : [],
    links: rulesOut.links ?? [],
    columns: shared.catalog.columns,
    tenancy: shared.catalog.tenancy,
    supabase: { edge_functions: edgeOut.edge },
  };
  ctx.frameworks = undefined;
  const fit = { rules: ruleList ?? [], rulesNotAnalyzed: new Set(toContractNotAnalyzed(rulesOut.notAnalyzed ?? []).map((e) => e.path)) };
  fitToSize(document, fit);
  const handlers = ctx.handlerMap ? await guarded("handlers", () => handlerMap(rootEntry, document, key, ctx.hardDeadline), () => ({})) : undefined;
  const spanNotes = spanWarnings(document.answers, document.matches, given);
  screenAndFit(document, key, fit);
  const problem = unaccounted.length ? { at: "/files/analyzed", keyword: "unaccounted" } : checkDocument(document);
  return { document, problem, ...(handlers ? { handlers } : {}), ...(spanNotes.length ? { notes: spanNotes } : {}) };
}

/* The sent paths of walked files that are neither analysed by the rules (rulesOut.analyzedPaths), nor a file entry
 * of not_analyzed, nor an edge config the edge collector parsed. Empty when the engine didn't run (rules failed or
 * not_run: the collector's status says nothing was analysed) or gave no analysedPaths (a test's stub). */
export function unaccountedFiles(sentPaths, rulesOut, na, configPaths = new Set()) {
  if (!Array.isArray(rulesOut?.analyzedPaths)) return [];
  const analyzed = new Set(rulesOut.analyzedPaths);
  const listed = new Set(na.filter((e) => e.kind === "file").map((e) => e.path));
  return sentPaths.filter((p) => !analyzed.has(p) && !listed.has(p) && !configPaths.has(p));
}

/* Keep the document under MAX_DOCUMENT_BYTES. A match costs about 360 bytes and every field of it is
 * required by the contract, so about 13,800 fit, fewer than the 20,000 matches allows. Past the limit, matches are
 * kept in byPriority order (violations and items without their control first) while they fit, with room set aside for
 * a match_limit entry for every file that could lose one and for the links; every file that lost a match is listed
 * match_limit and no longer counted as analysed; links are rebuilt from the kept matches; the rules collector is
 * truncated, size_limit (unless already truncated for another reason). If what remains is still too large (very long
 * paths in a full not_analyzed list), not_analyzed is cut from the end and the files collector is truncated, size_limit.
 * Mutates and returns the document. */
const docBytes = (doc) => Buffer.byteLength(JSON.stringify(doc), "utf8");
const SIZE_MARGIN = 4_096;
const byNa = (a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0) || (a.kind < b.kind ? -1 : a.kind > b.kind ? 1 : 0);
// document -> the paths a fit already took out of files.analyzed. screenAndFit fits twice, and a file another collector
// listed first gets no match_limit entry, so the not_analyzed list can't say which files were counted down.
const countedDown = new WeakMap();
export function fitToSize(document, { rules = [], rulesNotAnalyzed = new Set(), limit = MAX_DOCUMENT_BYTES } = {}) {
  if (docBytes(document) <= limit) return document;
  const truncate = (collector, reason) => {
    const i = document.collection.findIndex((c) => c.collector === collector);
    const c = document.collection[i];
    if (c && (c.status === "ok" || c.status === "empty")) document.collection[i] = entry(collector, "truncated", c.count, reason);
  };
  const all = [...document.matches].sort(byPriority);
  if (all.length) {
    const naEntry = (path) => ({ path, kind: "file", reason: "match_limit", tracked: null });
    const paths = [...new Set(all.map((m) => m.path))];
    const reserve = paths.reduce((n, p) => n + docBytes(naEntry(p)) + 1, 0) + docBytes(document.links);
    const base = docBytes({ ...document, matches: [], links: [] });
    let room = limit - base - reserve - SIZE_MARGIN;
    const kept = [];
    for (const m of all) {
      const cost = docBytes(m) + 1;
      if (cost > room) break;
      room -= cost; kept.push(m);
    }
    const keptCount = new Map();
    for (const m of kept) keptCount.set(m.path, (keptCount.get(m.path) ?? 0) + 1);
    const fullCount = new Map();
    for (const m of all) fullCount.set(m.path, (fullCount.get(m.path) ?? 0) + 1);
    const lost = paths.filter((p) => (keptCount.get(p) ?? 0) < fullCount.get(p));
    kept.sort(byMatch);
    document.matches = kept;
    document.links = linksOf(kept, rules);
    const listed = new Set(document.files.not_analyzed.filter((e) => e.kind === "file").map((e) => e.path));
    if (!countedDown.has(document)) countedDown.set(document, new Set());
    const done = countedDown.get(document);
    let wasAnalyzed = 0;
    for (const p of lost) {
      if (!rulesNotAnalyzed.has(p) && !done.has(p)) { wasAnalyzed++; done.add(p); }
      if (!listed.has(p)) document.files.not_analyzed.push(naEntry(p));
    }
    document.files.not_analyzed.sort(byNa);
    document.files.analyzed = Math.max(0, document.files.analyzed - wasAnalyzed);
    if (lost.length) truncate("rules", "size_limit");
    if (document.files.not_analyzed.length > NOT_ANALYZED_MAX) {
      document.files.not_analyzed = document.files.not_analyzed.slice(0, NOT_ANALYZED_MAX);
      truncate("files", "item_limit");
    }
  }
  // Still too large without the matches (long paths in a full not_analyzed list): cut not_analyzed from the end.
  while (docBytes(document) > limit && document.files.not_analyzed.length) {
    const over = docBytes(document) - limit + SIZE_MARGIN;
    let cut = 0, bytes = 0;
    const na = document.files.not_analyzed;
    while (cut < na.length && bytes < over) { bytes += docBytes(na[na.length - 1 - cut]) + 1; cut++; }
    document.files.not_analyzed = na.slice(0, na.length - cut);
    truncate("files", "size_limit");
  }
  return document;
}

/* LOCAL ONLY (custosa inspect --document): handler id -> {path, name, line, column}, the readable identity behind each
 * matches[].handler and links[].handler id in the document. Worked out again from the files with captures.Handlers,
 * the same code the rule engine uses, and kept only for ids the document holds. Never put in a document, never sent. */
/* It parses every file with a handler match again on this thread, so it stops at the check's hard deadline: ids it
 * didn't reach are left out of the map (local only; the document is the same either way). */
async function handlerMap(rootEntry, document, key, until = null) {
  const wanted = new Set([...document.matches.map((m) => m.handler), ...document.links.map((l) => l.handler)].filter(Boolean));
  if (!wanted.size) return {};
  const paths = new Set(document.matches.filter((m) => m.handler).map((m) => m.path));
  const out = {};
  for (const f of rootEntry.result.files) {
    const sent = sentPath(key, f.path);
    if (!paths.has(sent)) continue;
    if (until !== null && Date.now() >= until) break;
    const lang = f.lang ?? parseLanguageOf(f.path);
    const read = await readWalked(rootEntry.abs, f.disk ?? f.path, 2_000_000);
    if (!lang || !read.buf) continue;
    let h;
    // The text the rule engine parsed (rules-worker.mjs): a lone \r is a line break there, so it must be here, or a
    // file with such breaks gets other handler ids and its functions drop out of the map.
    const text = normalizeBreaks(read.buf.toString("utf8"));
    // the repair is bounded by the check's deadline and MAIN_REPAIR_MS (this is the main thread). A tree that is
    // still recovered names no handler: the worker linked none in a recovered file, and one whose repair ran out of
    // time here would be read differently from the worker's clean tree. Its ids are left out of the map.
    try {
      const parsed = parseCode(lang, text, mainRepairBudget(until));
      if (parsed.recovered) continue;
      h = new Handlers(parsed.root, lang, sent, key); h.load();
    } catch { continue; }
    h.fns.forEach((_, i) => {
      const ident = h.identity(i);
      if (!ident) return;
      const id = h.idOfFunction(i);
      const fn = h.fns[ident.owner];
      if (wanted.has(id)) out[id] = { path: f.path, name: ident.name, line: fn.line, column: fn.column };
    });
  }
  return Object.fromEntries(Object.entries(out).sort(([a], [b]) => (a < b ? -1 : 1)));
}

/* The documents built with no network and no sign-in (local-only mode, custosa inspect --document): the catalog and
 * platform collectors are not_run (not_configured), nested repositories are left out unless asked. */
export const NO_NETWORK = Object.freeze({
  collectCatalog: async (queries) => ({ status: "not_run", count: 0, reason: "service_missing", preflight: null,
    queries: queries.map((q) => ({ query_id: q.query_id, status: "not_run", reason: "service_missing", rows: [] })) }),
  collectPlatform: async () => ({ provider: null, status: "not_run", reason: "no_token", settings: {} }),
});
export function buildLocalDocuments(roots, options = {}) {
  return buildFactDocuments(roots, { includeOther: 0, ...NO_NETWORK, ...options });
}

/* The schema, then the strict intake checks a schema can't state (evaluator_api.md 1.2 step 3) that this document
 * could break, and the size limit. */
/* The last pass before a document is checked: the evaluator refuses, uncharged, any string its value screen
 * reads as a record value or a secret (valueshape.mjs). Names and paths are hashed where they are made (ids.mjs
 * sentPath and sentIdentifier, catalogfacts, captures); this replaces any string that still trips the screen with its
 * keyed hash, the same text for the same string everywhere in the document, so cross-references still agree. A path
 * keeps its folders and extension readable where they pass (sentPath); an object_id keeps its practice before the '@'.
 * Mutates the document; checkDocument then refuses it locally if anything is still left (value_shape). */
/* The screen, then the fit again: a hash can be longer than the value it replaces, so a fitted document can pass
 * MAX_DOCUMENT_BYTES after the screen. The second fit returns at once when it is under the limit, and
 * what it adds (match_limit entries, rebuilt links) comes from values already screened. */
export function screenAndFit(doc, key, fit) {
  screenDocument(doc, key);
  return fitToSize(doc, fit);
}

export function screenDocument(doc, key) {
  const fix = (text, field) => {
    if (field === "object_id") {
      const at = text.indexOf("@");
      return at < 0 ? text : `${text.slice(0, at)}@${hashed(key, text.slice(at + 1))}`;
    }
    if (text.includes("/")) {
      const path = sentPath(key, text);
      if (!screenValue(path, field)) return path;
    }
    return hashed(key, text);
  };
  const walk = (node) => {
    if (Array.isArray(node)) {
      node.forEach((v, i) => { if (typeof v === "string") { if (screenValue(v, null)) node[i] = fix(v, null); } else walk(v); });
    } else if (node && typeof node === "object") {
      for (const [k, v] of Object.entries(node)) {
        if (typeof v === "string") { if (screenValue(v, k)) node[k] = fix(v, k); } else walk(v);
      }
    }
  };
  walk(doc);
  return doc;
}

export function checkDocument(doc) {
  const tables = tooManyTables(doc);
  if (tables) return { at: tables, keyword: "too_many_tables" };
  const schema = validateFactDocument(doc);
  if (schema) return schema;
  // The evaluator's value screen: a hit here is never sent, since the evaluator would refuse it.
  const shaped = documentValueProblem(doc);
  if (shaped) return { at: shaped.at, keyword: "value_shape" };
  for (const [i, m] of doc.matches.entries()) if (m.line_end < m.line_start) return { at: `/matches/${i}/line_end`, keyword: "strict" };
  for (const [i, a] of doc.answers.entries()) {
    const m = a.location && /:(\d+)(?:-(\d+))?$/.exec(a.location);
    if (m && m[2] !== undefined && (Number(m[2]) < Number(m[1]) || Number(m[2]) - Number(m[1]) >= LOCATION_RANGE_MAX)) return { at: `/answers/${i}/location`, keyword: "strict" };
  }
  const tc = doc.catalog.queries.find((q) => q.query_id === "table_columns");
  const tcRows = tc && (tc.status === "ok" || tc.status === "truncated") ? tc.rows : [];
  if (doc.columns.length !== tcRows.length) return { at: "/columns", keyword: "strict" };
  for (const [i, c] of doc.columns.entries()) {
    const r = tcRows[i];
    if (c.table !== `${r.schema_name}.${r.table_name}` || c.column !== r.column_name || c.type !== r.data_type) return { at: `/columns/${i}`, keyword: "strict" };
  }
  if (doc.tenancy.source === "observed" && doc.tenancy.model === "row_level") {
    const pol = doc.catalog.queries.find((q) => q.query_id === "rls_policies");
    if (!pol || !pol.rows.some((p) => p.tenant_comparison === true) || !tcRows.some((r) => r.column_name === doc.tenancy.tenant_column)) {
      return { at: "/tenancy", keyword: "strict" };
    }
  }
  // intake._check_manifests: each ecosystem once, and its count covers its paths.
  const ecosystems = new Set();
  for (const [i, e] of (doc.files.manifests ?? []).entries()) {
    if (ecosystems.has(e.ecosystem)) return { at: `/files/manifests/${i}/ecosystem`, keyword: "strict" };
    ecosystems.add(e.ecosystem);
    if (e.paths.length > e.count) return { at: `/files/manifests/${i}/count`, keyword: "strict" };
  }
  const pairs = new Set(doc.matches.map((m) => `${m.handler}\0${m.table}`));
  for (const [i, l] of doc.links.entries()) if (!pairs.has(`${l.handler}\0${l.table}`)) return { at: `/links/${i}`, keyword: "strict" };
  if (Buffer.byteLength(JSON.stringify(doc), "utf8") > MAX_DOCUMENT_BYTES) return { at: "", keyword: "too_large" };
  return null;
}

export async function buildFactDocuments(projectRoots, options = {}) {
  // The time budget runs from the start, rule loading included (options.deadline: an epoch ms; timeBudgetMs: tests
  // and the corpus budget, with readsBudgetMs and fileTimeoutMs, the rule engine's per-file limit).
  const started = Date.now();
  const timeBudget = options.timeBudgetMs ?? COLLECT_BUDGET_MS;
  const deadline = options.deadline ?? started + timeBudget;
  // The hard end keeps the same 10 s margin over the soft one as the defaults (45 s and 55 s).
  const hardDeadline = options.hardDeadline ?? deadline + (TOTAL_BUDGET_MS - COLLECT_BUDGET_MS);
  const readsDeadline = Math.min(deadline, started + (options.readsBudgetMs ?? READS_BUDGET_MS));
  const workers = options.workers ?? defaultWorkers();
  const configDir = configDirFor(options);
  // The rule bundle first: a package without one creates nothing (not even install.key) before saying so. Its rules
  // are parsed in a thread of their own while the catalog, the platform and the walk run (startRuleset); each root's
  // rules step waits for them, never past its own deadline (rulesWithin).
  const loading = options.ruleset ? null : startRuleset({ bundleDir: options.bundleDir, rulesetId: options.rulesetId });
  const ruleset = options.ruleset ?? { id: loading.id, queries: loading.queries, rules: undefined };
  loading?.hold();
  try {
    return await buildWith(projectRoots, options, { started, deadline, hardDeadline, readsDeadline, workers, configDir, ruleset, loading });
  } finally { loading?.release(); }
}

/* The rules, once parsed, or {timedOut} when the deadline (epoch ms) comes first, or the signal is aborted. */
async function rulesWithin(loading, deadline, signal) {
  if (loading.ready()) return { rules: await loading.rules };
  const settled = (rules) => (rules === LOAD_TIMED_OUT ? { timedOut: true } : rules === BUNDLE_STALE ? { rules: null, stale: true } : { rules });
  let timer, onAbort;
  const out = await Promise.race([
    loading.rules.then(settled, () => ({ rules: null })),
    new Promise((resolve) => { timer = setTimeout(() => resolve({ timedOut: true }), Math.max(0, deadline - Date.now())); }),
    new Promise((resolve) => { onAbort = () => resolve({ timedOut: true }); if (signal?.aborted) onAbort(); else signal?.addEventListener("abort", onAbort, { once: true }); }),
  ]);
  clearTimeout(timer); signal?.removeEventListener("abort", onAbort);
  return out;
}

/* Said locally (local_notes) when the check ran out of time before the rules matched any file because setup (parsing
 * the rule bundle, starting the rule workers) took the budget. The document says only what the contract can: the rules
 * collector truncated, timeout, and every file time_limit. */
export const SETUP_TIMEOUT_NOTE = "The time budget ran out before the rules matched any file: {what} took the first {s} s of it on this computer. Every file is listed as not analysed (time_limit), so nothing passed unseen. Run the check again: this inspector keeps the rules and its rule workers loaded, so the next check spends its time on the files.";

/* Said locally when no rule worker could start because workers stopped by earlier checks (each on a file whose
 * matching ran past its time limit) are still running inside a native call that can't be interrupted. */
export const THREADS_BUSY_NOTE = "Some files were not matched against the rules (listed time_limit): rule workers stopped during earlier checks, each on a file whose matching ran past its time limit, are still finishing, and this inspector starts no more until they exit. Run the check again in a minute, or restart the assistant to end them.";

/* Said locally when the rule bundle's files are not the ones its manifest names (rules.bundleMatches): its rules are
 * never run under the manifest's ruleset_id, so the rules collector is failed, internal_error. */
export const STALE_BUNDLE_NOTE = "No rule was run: the rule bundle's manifest doesn't match its rule files (a rule file was changed, added or removed after the bundle was built). Rebuild the bundle with scripts/build_ruleset.py, then run the check again.";

async function buildWith(projectRoots, options, { started, deadline, hardDeadline, readsDeadline, workers, configDir, ruleset, loading }) {
  const key = options.key ?? loadInstallKey({ configDir });
  // options.signal: the call's cancellation. Checked between phases and passed to the rule engine, which stops its
  // workers; a cancelled build throws the signal's reason (AbortError) and returns nothing.
  // options.onProgress({phase, done?, total?, root?, roots?}): progress events for the host (throttled by the server).
  const signal = options.signal ?? null;
  const progress = typeof options.onProgress === "function" ? options.onProgress : () => {};
  const roots = projectRoots.length;
  signal?.throwIfAborted();
  progress({ phase: "platform" });
  const shared = {
    platform: await platformFacts(options.collectPlatform, readsDeadline),
  };
  signal?.throwIfAborted();
  progress({ phase: "catalog" });
  shared.catalog = await catalogFacts(ruleset, key, options.collectCatalog, { provider: shared.platform.provider, deadline: readsDeadline });
  signal?.throwIfAborted();
  // A nested repository, or another of the client's project roots, is a root of its own, but the phisc entry and
  // platform.json name the first project's database and host, not its: its catalog and platform collectors are not_run
  // (not_configured), never that project's facts.
  let otherShared = null;
  const otherFacts = async () => (otherShared ??= {
    catalog: await catalogFacts(ruleset, key, async (queries) => ({ status: "not_run", count: 0, reason: "service_missing", preflight: null,
      queries: queries.map((q) => ({ query_id: q.query_id, status: "not_run", reason: "service_missing", rows: [] })) })),
    platform: await platformFacts(async () => ({ provider: null, status: "not_run", reason: "no_token", settings: {} })),
  });
  // How many roots beyond the first project root's own get a document: nested repositories and other project roots,
  // in walk order. The rest come back {skipped: true, root_id}; another project root past the budget isn't walked.
  // selectOther: a set of root ids; then exactly those extra roots get a document (the budget still caps them).
  const budget = options.includeOther ?? Infinity;
  const select = options.selectOther ? new Set(options.selectOther) : null;
  let extra = 0;
  const walkAll = options.walkAll ?? defaultWalkAll;
  const documents = [];
  // Roots that won't be sent are not walked: a cheap scan (nestedRepos) finds the repositories inside them, so the
  // listing still names them (and they can be chosen by id next time). It stops at a cap; then the count is a lower
  // bound (listingCapped).
  const wanted = (abs) => extra < budget && (!select || select.has(rootId(key, abs)));
  let listingCapped = false;
  let setupCut = null; // {what, s}: the first root whose rules ran out of time in setup
  let threadsBusy = false; // a root's rules found too many terminated workers still running (rules.STOPPING_MAX)
  let staleBundle = false; // the rule bundle's files didn't match its manifest (rules.bundleMatches)
  const rootNotes = []; // each built root's own local notes (spanWarnings)
  const skippedEntry = (project, label, nested, abs) => ({ project, label, nested, other: project > 0, skipped: true,
    root_id: rootId(key, abs), document: null, problem: null });
  const listInside = async (project, top, abs) => {
    const found = await nestedRepos(abs);
    if (found.capped) listingCapped = true;
    const out = [];
    for (const repo of found.repos) {
      const label = relative(top, repo).split(sep).join("/");
      if (wanted(repo)) { extra++; out.push({ walk: repo, label }); } // chosen by id: walked as a root of its own
      else documents.push(skippedEntry(project, label, true, repo));
    }
    return out;
  };
  const build = async (project, r, isExtra, top) => {
    const ctx = {
      key, ruleset, shared: isExtra ? await otherFacts() : shared, top, configDir, primary: project === 0,
      session: options.session ?? null, answers: options.answers ?? [],
      environment: options.environment ?? { value: "unknown", source: "setup" },
      inspectorVersion: options.inspectorVersion ?? PACKAGE_VERSION,
      runRules: options.runRules ?? defaultRunRules, scanSecrets: options.scanSecrets ?? defaultScanSecrets,
      handlerMap: options.handlerMap === true, deadline, hardDeadline, workers, signal, warm: options.warm ?? null,
      fileTimeoutMs: options.fileTimeoutMs ?? null,
      rules: loading ? () => rulesWithin(loading, deadline - SECRETS_RESERVE_MS, signal) : async () => ({ rules: ruleset.rules, stale: ruleset.stale === true }),
      setup: (what) => { setupCut ??= { what, s: Math.round((Date.now() - started) / 1000) }; },
      busy: () => { threadsBusy = true; },
      stale: () => { staleBundle = true; },
      progress: (e) => progress({ ...e, root: project, roots }),
    };
    signal?.throwIfAborted();
    // The root's .custosa/state.json, read once: the content key and the committed block both come from this read.
    ctx.stateRead = readState(r.abs);
    const { notes: builtNotes = [], ...built } = await guarded("document", () => buildOne(r, ctx), () => ({ document: null, problem: { at: "", keyword: "internal_error" } }));
    rootNotes.push(...builtNotes);
    signal?.throwIfAborted(); // a build cut short by cancellation is never returned
    // abs and stateRead stay on this machine: the CLI sends the root's committed block from stateRead and writes the
    // root's own .custosa/state.json at abs (contract 2.3 section 1.1).
    documents.push({ project, label: r.rel, nested: r.rel !== "", other: project > 0, skipped: false, root_id: rootId(key, r.abs), abs: r.abs,
      stateRead: ctx.stateRead, ...built });
  };
  // Ignore matching stops at the soft deadline (its answers past it are unverified, the walk truncated).
  const walkBudget = () => ({ ignoreDeadlineMs: Math.max(1_000, deadline - Date.now()) });
  const walkOne = async (abs, extraOpts = {}) => guarded("files", () => walkAll(abs, { ...walkBudget(), ...(options.walkOptions ?? {}), ...extraOpts }),
    () => ({ roots: [{ abs, rel: "", reason: null, result: null }] }));
  // Nested roots walkAll meets: walked only when wanted (each counted against the budget as it is decided).
  const walkNested = (abs) => { if (!wanted(abs)) return false; extra++; return true; };

  for (const [project, top] of projectRoots.entries()) {
    if (project > 0 && !wanted(top)) { // another project root not chosen: listed, with what the cheap scan finds in it
      documents.push(skippedEntry(project, "", false, top));
      for (const w of await listInside(project, top, top)) {
        const walked = await walkOne(w.walk, { walkNested: () => false });
        await build(project, { ...walked.roots[0], rel: w.label }, true, top);
      }
      continue;
    }
    if (project > 0) extra++;
    signal?.throwIfAborted();
    progress({ phase: "walk", root: project, roots });
    const walked = await walkOne(top, { walkNested });
    signal?.throwIfAborted();
    const topAbs = walked.roots[0].abs;
    for (const r of walked.roots) {
      if (r.skipped) {
        documents.push(skippedEntry(project, r.rel, true, r.abs));
        for (const w of await listInside(project, topAbs, r.abs)) {
          const inner = await walkOne(w.walk, { walkNested: () => false });
          await build(project, { ...inner.roots[0], rel: w.label }, true, topAbs);
        }
        continue;
      }
      await build(project, r, r.rel !== "" || project > 0, topAbs);
    }
  }
  const setupNotes = [...(setupCut ? [SETUP_TIMEOUT_NOTE.replace("{what}", setupCut.what).replace("{s}", String(setupCut.s))] : []),
    ...(threadsBusy ? [THREADS_BUSY_NOTE] : []), ...(staleBundle ? [STALE_BUNDLE_NOTE] : [])];
  return { documents, listingCapped, notes: [...(shared.platform.notes ?? []), ...(shared.catalog.notes ?? []), ...setupNotes, ...rootNotes] };
}

/* The repositories inside a folder, found cheaply: directories only, never a file listing, never a file read. A
 * folder holding a .git entry (folder or file) other than the start is one; the scan goes on inside it. Symlinks and
 * the walker's excluded folders (dependencies, build output, version control) are not entered. Stops past maxDirs
 * folders or maxRepos repositories (capped). */
export async function nestedRepos(start, { maxDirs = 20_000, maxRepos = 1_000 } = {}) {
  const repos = [];
  const queue = [start];
  let visited = 0, capped = false;
  while (queue.length) {
    if (++visited > maxDirs || repos.length >= maxRepos) { capped = true; break; }
    const dir = queue.shift();
    let entries;
    try { entries = await readdir(dir, { withFileTypes: true }); } catch { continue; }
    if (dir !== start && entries.some((e) => e.name === ".git")) repos.push(dir);
    for (const e of entries) {
      if (e.isDirectory() && !e.isSymbolicLink() && !EXCLUDED_DIRS.has(e.name) && e.name.toLowerCase() !== ".git") queue.push(join(dir, e.name));
    }
  }
  return { repos: repos.sort(), capped };
}



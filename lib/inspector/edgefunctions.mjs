/* The edge_functions collector (contract v2.1, evaluator_api.md 1.7, rule_bundle.md 3.5): the Edge Functions every
 * supabase/config.toml the walk found declares, parsed on the machine with a TOML parser (./tomlparse.mjs).
 *
 * collectEdgeFunctions(root, walkResult, {key, filesStatus, filesReason, maxBytes})
 *   -> {edge: {status, reason, items}, notAnalyzed: [{path, kind, reason, tracked}], configPaths: Set<sent path>}
 *
 * - The files collector not usable (failed or not_run): failed, with its reason when the schema allows that reason
 *   on a failed edge_functions, else internal_error. Never not_configured: a walk that didn't run found nothing.
 * - No supabase/config.toml found (SUPABASE_CONFIG_PATTERN, any letter case, at the root or in a package) and no
 *   function folder: not_run, not_configured.
 * - A function folder in a supabase directory with no config.toml is listed the same way as an undeclared
 *   one below, so function folders with no config are a list, never not_configured.
 * - Any one found and not parsed (listed by the walk as not analysed, unreadable, too large, not valid TOML, a
 *   [functions] table of the wrong shape) or a skipped folder named supabase: failed, parse_failed, no items, even
 *   when another parsed. The file goes to files.not_analyzed with parse_error, too_large or unreadable.
 * - The walk didn't see everything (gap): failed with the walk's reason when nothing or no function was found,
 *   truncated (item_limit) when functions were found.
 * - A function folder (<supabase dir>/functions/<name>/) the config doesn't declare is listed too (its index file as
 *   the entrypoint, verify_jwt not_read): Supabase deploys it anyway, so a parsed config is never "no functions"
 *   beside one.
 * - A supabase/config.toml git ignores (on disk, dropped by the walk without a listing): failed, ignore_unverified,
 *   listed as ignored_unverified. More folders than the look for one probes (MAX_IGNORED_PROBES): failed,
 *   ignore_unverified, nothing listed.
 * - Parsed, no [functions.<name>] table and no function folder: empty. Over MAX_EDGE_FUNCTIONS: truncated, item_limit, the first 1,000.
 * Each item: name (hashed when it isn't an identifier), entrypoint (the declared one resolved against the config's
 * supabase directory, else <supabase dir>/functions/<name>/index.ts; null when it leaves the root, is absolute, names
 * a scheme, or can't be a path), verify_jwt (the declared boolean, else not_read; no default).
 * configPaths: the sent paths of the config.toml files this collector parsed. runRules lists such a file as
 * unsupported_language or unknown_type (no rule grammar reads TOML); the fact document doesn't forward that entry. */
import { lstat } from "node:fs/promises";
import { join } from "node:path";
import { sentIdentifier, sentPath } from "./ids.mjs";
import { parseToml } from "./tomlparse.mjs";
import { readWalked } from "./walkread.mjs";

export const SUPABASE_CONFIG_PATTERN = /(?:^|\/)supabase\/config\.toml$/i; // enums.SUPABASE_CONFIG_PATTERN
const SUPABASE_DIR = /(?:^|\/)supabase$/i;
export const MAX_EDGE_FUNCTIONS = 1000;
export const MAX_CONFIG_BYTES = 1_000_000;
// enums.EDGE_FUNCTIONS_STATUS_REASONS["failed"]: parse_failed and the files collector's reasons but not_configured,
// item_limit and size_limit.
export const EDGE_FAILED_REASONS = Object.freeze(["parse_failed", "config_insecure", "unreachable", "auth_failed",
  "tls_required", "preflight_failed", "not_permitted", "platform_mismatch", "unsupported_engine", "unsupported_platform",
  "timeout", "row_limit", "file_limit", "value_out_of_pattern", "rate_limited", "internal_error", "index_hard_link",
  "shared_index_missing", "shared_index_hard_link", "ignore_unverified"]);

const isTable = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

/* The entrypoint as a root-relative path, or null. */
function resolveEntrypoint(supabaseDir, declared) {
  if (declared.includes("\\") || declared.startsWith("/") || /^[A-Za-z][A-Za-z0-9+.-]*:/.test(declared) || declared.includes("\0")) return null;
  const out = supabaseDir ? supabaseDir.split("/") : [];
  for (const seg of declared.split("/")) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") { if (out.length === 0) return null; out.pop(); continue; }
    out.push(seg);
  }
  return out.length ? out.join("/") : null;
}

export const MAX_IGNORED_PROBES = 20_000;
const ENTRY_NAMES = ["index.ts", "index.tsx", "index.js", "index.jsx", "index.mjs"];

/* supabase/config.toml files the walk dropped without listing them (git ignores them, so they never show as
 * walked): for each folder the walk listed a file in (and the root), <folder>/supabase/config.toml is looked up on
 * disk (lstat only, never read) unless the walk saw or listed it. Each one found is a config the collector can't
 * vouch for. -> {paths, capped}: capped when more folders were left than MAX_IGNORED_PROBES allows, so one it never
 * looked in could hold such a config. */
async function ignoredConfigs(root, walk) {
  const files = walk.files ?? [];
  const seen = new Set([...files.map((f) => f.path.toLowerCase()), ...(walk.notAnalyzed ?? []).filter((e) => e.kind === "file").map((e) => e.path.toLowerCase())]);
  // Never look under anything the walk listed (a symlink above all: lstat must not touch a path outside the root).
  const dirsSkipped = (walk.notAnalyzed ?? []).map((e) => `${e.path.toLowerCase()}/`);
  const dirs = new Set([""]);
  for (const f of files) for (let i = f.path.indexOf("/"); i >= 0; i = f.path.indexOf("/", i + 1)) dirs.add(f.path.slice(0, i));
  const out = [];
  let probes = 0;
  for (const d of dirs) {
    if (++probes > MAX_IGNORED_PROBES) return { paths: out, capped: true };
    const cfg = d ? `${d}/supabase/config.toml` : "supabase/config.toml";
    const lower = cfg.toLowerCase();
    if (seen.has(lower) || dirsSkipped.some((p) => lower.startsWith(p))) continue;
    try { await lstat(join(root, ...cfg.split("/"))); out.push(cfg); } catch { /* not there */ }
  }
  return { paths: out, capped: false };
}

/* Function folders (<supabase dir>/functions/<name>/, not _shared or another _ folder) holding a file the walk saw,
 * for names the config doesn't declare: Supabase deploys them anyway, so each is listed, with its index file as the
 * entrypoint when there is one (else null) and verify_jwt not_read. */
function undeclaredFunctions(walk, supabaseDir, declared) {
  const prefix = `${supabaseDir}/functions/`;
  const byName = new Map();
  for (const p of [...(walk.files ?? []).map((f) => f.path), ...(walk.notAnalyzed ?? []).filter((e) => e.kind === "file").map((e) => e.path)]) {
    if (!p.startsWith(prefix)) continue;
    const rest = p.slice(prefix.length);
    const slash = rest.indexOf("/");
    if (slash <= 0) continue;
    const name = rest.slice(0, slash);
    if (name.startsWith("_") || name.startsWith(".") || declared.has(name)) continue;
    if (!byName.has(name)) byName.set(name, new Set());
    byName.get(name).add(rest.slice(slash + 1));
  }
  return [...byName.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([name, inside]) => {
    const entry = ENTRY_NAMES.find((n) => inside.has(n));
    return { name, entrypoint: entry ? `${prefix}${name}/${entry}` : null };
  });
}

const FUNCTION_FILE = /^((?:.*\/)?supabase)\/functions\/[^/]+\/./i;

/* The supabase directories ("supabase", "apps/web/supabase") holding a function folder file the walk saw or listed,
 * that no config.toml in `configs` sits in, sorted. Their folders are listed with no config. */
function bareSupabaseDirs(walk, configs) {
  const withConfig = new Set(configs.map((f) => f.path.slice(0, f.path.lastIndexOf("/")).toLowerCase()));
  const dirs = new Set();
  for (const p of [...(walk.files ?? []).map((f) => f.path), ...(walk.notAnalyzed ?? []).filter((e) => e.kind === "file").map((e) => e.path)]) {
    const m = FUNCTION_FILE.exec(p);
    if (m && !withConfig.has(m[1].toLowerCase())) dirs.add(m[1]);
  }
  return [...dirs].sort();
}

export async function collectEdgeFunctions(root, walk, { key, filesStatus, filesReason, gap = null, maxBytes = MAX_CONFIG_BYTES } = {}) {
  const none = { notAnalyzed: [], configPaths: new Set() };
  if (filesStatus === "failed" || filesStatus === "not_run") {
    const reason = EDGE_FAILED_REASONS.includes(filesReason) ? filesReason : "internal_error";
    return { ...none, edge: { status: "failed", reason, items: [] } };
  }
  const configs = (walk.files ?? []).filter((f) => SUPABASE_CONFIG_PATTERN.test(f.path));
  // A config.toml the walk listed, or a supabase folder it didn't enter (a directory entry, or a symlink listed as a
  // file entry because it wasn't followed), whatever the entry's kind.
  const skipped = (walk.notAnalyzed ?? []).filter((e) => (e.kind === "file" && SUPABASE_CONFIG_PATTERN.test(e.path))
    || (SUPABASE_DIR.test(e.path) && e.reason !== "excluded_directory"));
  // gap: the walk's own reason when it didn't see everything (factdoc.walkGap): a config.toml could be in what it
  // missed, so "no config.toml" and "no functions" can't be said, and a list it found is collected in part.
  const blind = gap === null ? null : EDGE_FAILED_REASONS.includes(gap) ? gap : gap === "item_limit" ? "file_limit" : "internal_error";
  // A config.toml git ignores: never not_configured or a clean list beside it (review): failed, ignore_unverified, and
  // the file listed as ignored_unverified.
  // Only for a walk with no gap: past a limit or an unread folder, the walk's own reason says why (below).
  const ignored = blind ? { paths: [], capped: false } : await ignoredConfigs(root, walk);
  if (ignored.paths.length) {
    return { notAnalyzed: ignored.paths.map((p) => ({ path: sentPath(key, p), kind: "file", reason: "ignored_unverified", tracked: null })),
      configPaths: new Set(), ignored: true, edge: { status: "failed", reason: "ignore_unverified", items: [] } };
  }
  // Past the look's limit nothing was found, but an unprobed folder could still hold one: this collector can't vouch
  // for its answer. The walk listed every file it saw, so the files collector keeps its status.
  if (ignored.capped) return { ...none, edge: { status: "failed", reason: "ignore_unverified", items: [] } };
  // Function folders in a supabase directory with no config.toml: Supabase deploys them anyway.
  const bareItems = bareSupabaseDirs(walk, configs).flatMap((dir) => undeclaredFunctions(walk, dir, new Set()));
  if (configs.length === 0 && skipped.length === 0 && bareItems.length === 0) {
    return { ...none, edge: blind ? { status: "failed", reason: blind, items: [] } : { status: "not_run", reason: "not_configured", items: [] } };
  }

  let failed = skipped.length > 0;
  const notAnalyzed = [];
  const configPaths = new Set();
  const items = [];
  const seen = new Set();
  for (const f of configs) {
    const sent = sentPath(key, f.path);
    const read = await readWalked(root, f.disk ?? f.path, maxBytes);
    if (!read.buf) { failed = true; notAnalyzed.push({ path: sent, kind: "file", reason: read.refused, tracked: null }); continue; }
    let doc;
    try {
      const text = new TextDecoder("utf-8", { fatal: true }).decode(read.buf);
      doc = parseToml(text);
    } catch { failed = true; notAnalyzed.push({ path: sent, kind: "file", reason: "parse_error", tracked: null }); continue; }
    const functions = doc.functions;
    if (functions !== undefined && !isTable(functions)) { failed = true; notAnalyzed.push({ path: sent, kind: "file", reason: "parse_error", tracked: null }); continue; }
    const supabaseDir = f.path.slice(0, f.path.lastIndexOf("/")); // "supabase", or "apps/web/supabase"
    const mine = [];
    let shapeOk = true;
    for (const [name, fn] of Object.entries(functions ?? {})) {
      if (!isTable(fn) || (fn.entrypoint !== undefined && typeof fn.entrypoint !== "string")) { shapeOk = false; break; }
      let entry;
      if (typeof fn.entrypoint === "string") entry = resolveEntrypoint(supabaseDir, fn.entrypoint);
      else entry = name.includes("/") || name === "." || name === ".." || name === "" ? null : `${supabaseDir}/functions/${name}/index.ts`;
      mine.push({
        name: sentIdentifier(key, name),
        entrypoint: entry === null ? null : sentPath(key, entry),
        verify_jwt: typeof fn.verify_jwt === "boolean" ? fn.verify_jwt : "not_read",
      });
    }
    if (!shapeOk) { failed = true; notAnalyzed.push({ path: sent, kind: "file", reason: "parse_error", tracked: null }); continue; }
    for (const u of undeclaredFunctions(walk, supabaseDir, new Set(Object.keys(functions ?? {})))) {
      mine.push({ name: sentIdentifier(key, u.name), entrypoint: u.entrypoint === null ? null : sentPath(key, u.entrypoint), verify_jwt: "not_read" });
    }
    configPaths.add(sent);
    for (const item of mine) {
      const id = JSON.stringify([item.name, item.entrypoint, item.verify_jwt]);
      if (!seen.has(id)) { seen.add(id); items.push(item); }
    }
  }
  for (const u of bareItems) {
    const item = { name: sentIdentifier(key, u.name), entrypoint: u.entrypoint === null ? null : sentPath(key, u.entrypoint), verify_jwt: "not_read" };
    const id = JSON.stringify([item.name, item.entrypoint, item.verify_jwt]);
    if (!seen.has(id)) { seen.add(id); items.push(item); }
  }
  if (failed) return { edge: { status: "failed", reason: "parse_failed", items: [] }, notAnalyzed, configPaths };
  if (items.length === 0) return { edge: blind ? { status: "failed", reason: blind, items: [] } : { status: "empty", reason: null, items: [] }, notAnalyzed, configPaths };
  if (blind) return { edge: { status: "truncated", reason: "item_limit", items: items.slice(0, MAX_EDGE_FUNCTIONS) }, notAnalyzed, configPaths };
  if (items.length > MAX_EDGE_FUNCTIONS) {
    return { edge: { status: "truncated", reason: "item_limit", items: items.slice(0, MAX_EDGE_FUNCTIONS) }, notAnalyzed, configPaths };
  }
  return { edge: { status: "ok", reason: null, items }, notAnalyzed, configPaths };
}

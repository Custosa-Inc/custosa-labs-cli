/* The inspector's structural rule engine: load the rules shipped in the package, run them on parsed files, and
 * check them against their fixtures. The format is rule_bundle.md (the evaluator's contracts, v1.1)
 * sections 3 and 4; each match is the fact schema's `matches` item, with its table and handler captures (3.3).
 *
 * - loadRules(dir, {strict}) -> Rule[]: validates every rule file and throws one error listing each
 *   `file: field: problem` when any is bad (a bundle with a bad rule is a broken build: the caller reports the rules
 *   collector failed, internal_error, instead of running part of it). Taint/dataflow rules are refused: none at launch
 *   (spec 14). At run time (not strict) rules for a language this platform can't parse are left out.
 * - runRules(rules, files, {key, frameworks, ...}) -> {matches, links, notAnalyzed, analyzed, languages, status, reason,
 *   count}
 *   Parsing and matching run in a worker thread (rules-worker.mjs) with a hard per-file deadline.
 * - runFixtures(dir) -> {passed, failed: [{rule_id, file, line, expected, got}]}
 *
 * Fingerprint: the schema's recipe, HMAC-SHA256 keyed with the per-install key over rule_id, path and the matched
 * node's text with whitespace runs collapsed to one space, joined by newlines, lowercase hex. The text never leaves
 * this process. No network, no child processes, nothing written. */
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { createHash } from "node:crypto";
import { availableParallelism, cpus } from "node:os";
import { basename, join, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { isMainThread, parentPort, Worker, workerData } from "node:worker_threads";
import { parseAllDocuments } from "yaml";
import { ENGINE_VERSION, LANGUAGES, MAX_BYTES, TIMEOUT_MS, engineAvailable, expandoChar, isSupported, languageOf, parseSync,
  unsupportedReason } from "./parse.mjs";
import { fingerprint, normalizeBreaks } from "./rules-worker.mjs";
import { engineConfigs } from "./factor.mjs";
import { PATH as PATH_PATTERN } from "./contracts.mjs";
import { readWalked } from "./walkread.mjs";

// --- Vocabularies (enums.py, contract v2.1) ---------------------------------------------------------------------
export const RULE_FRAMEWORKS = Object.freeze(["express", "nextjs", "nestjs", "fastify", "hono", "koa", "remix",
  "sveltekit", "nuxt", "django", "flask", "fastapi", "rails", "laravel", "spring", "gin", "echo", "aspnetcore", "prisma",
  "drizzle", "typeorm", "sequelize", "sqlalchemy", "alembic", "knex", "supabase", "firebase", "expo", "react_native",
  "terraform", "github_actions", "generic"]);
const LANGS = LANGUAGES; // enums.LANGUAGES, from parse.mjs's extension table
export const RULE_KINDS = Object.freeze(["evidence", "violation", "items"]);
const PRACTICE_ID = /^[a-z0-9][a-z0-9-]{0,63}$/;
const RULE_NAME = /^[a-z0-9][a-z0-9-]{0,31}$/;
const RULE_ID = new RegExp(`^[a-z0-9][a-z0-9-]{0,63}\\.(?:${LANGS.join("|")})-(?:${RULE_FRAMEWORKS.join("|")})\\.[a-z0-9][a-z0-9-]{0,31}$`);
const VERSION = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/;
// The fact schema's path ($defs.path).
const PATH = new RegExp(PATH_PATTERN);
const MAX_MATCHES = 20000; // matches maxItems

// Fixture extension and line-comment syntax by language (rule_bundle.md section 4).
export const FIXTURE = Object.freeze({
  javascript: ["js", "//"], typescript: ["ts", "//"], tsx: ["tsx", "//"], python: ["py", "#"], go: ["go", "//"],
  java: ["java", "//"], kotlin: ["kt", "//"], ruby: ["rb", "#"], php: ["php", "//"], csharp: ["cs", "//"],
  sql: ["sql", "--"], yaml: ["yml", "#"], json: ["jsonc", "//"], toml: ["toml", "#"], hcl: ["hcl", "#"],
});

const DOC_KEYS = ["id", "practice_id", "language", "frameworks", "kind", "rule", "control", "min_engine", "table", "path_regex",
  "follow_import"];
const OPTIONAL_KEYS = ["control", "table", "path_regex", "follow_import"];
// follow_import (T28-P1-C5): an evidence rule on JavaScript or TypeScript whose matches are calls by a bare name, followed
// one import hop after the run (followimport.mjs).
const FOLLOW_LANGS = ["javascript", "typescript", "tsx"];
// path_regex (rule_bundle.md 3.4): the rule runs only on files whose root-relative path it matches. Anchored
// to the start of the path or of a folder segment, so it names folders, never a substring of a name. A loader that
// predates the key refuses the whole rule set (unknown key), so an older package never runs such a rule on every file.
const PATH_REGEX_ANCHOR = /^(?:\^|\(\^\|\/\))/;
const PATH_REGEX_MAX = 200;
export const TABLE_ACCESS = Object.freeze(["read", "write"]); // fact schema links[].access
// A metavariable that captures one node: $_ and $_NAME capture nothing, $$NAME and $$$NAME aren't one named node.
const CAPTURING_METAVAR = /^\$[A-Z][A-Z0-9_]*$/;
// Files other than rules and fixtures the rule set may hold, at its root or in a practice directory: documentation.
const DOC_FILES = new Set(["README.md", "NAMING.md"]);
const ATOMIC = ["pattern", "kind", "regex"];
const RELATIONAL = ["inside", "has", "precedes", "follows"];
const COMPOSITE = ["all", "any", "not"];
const STRICTNESS = ["cst", "smart", "ast", "relaxed", "signature"];
// Keys that mean a dataflow rule (semgrep and ast-grep spellings). Refused with the launch reason, not "unknown key".
const TAINT_KEYS = new Set(["taint", "mode", "sources", "sinks", "sanitizers", "propagators", "pattern-sources",
  "pattern-sinks", "pattern-sanitizers", "pattern-propagators", "dataflow"]);
// ast-grep operators the contract leaves out at launch (3.1), named so the refusal says so.
const NOT_AT_LAUNCH = new Set(["matches", "utils", "constraints", "transform", "fix", "nthChild", "range"]);
const TAINT_PROBLEM = "dataflow/taint rules are not supported at launch (spec 14): structural rules only, and a practice that needs dataflow ends needs_review";

/** The packaged rule set (synced from the evaluator's app/knowledge/rules/ by scripts/sync-rules.mjs). */
export const DEFAULT_RULES_DIR = new URL("../../rules/", import.meta.url);

export function compareVersions(a, b) {
  const x = a.split(".").map(Number), y = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] < y[i] ? -1 : 1;
  return 0;
}

const inAllWithAtom = new WeakSet(); // rule objects that sit in an all beside a pattern or kind
const isMap = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const toPosix = (p) => p.split(sep).join("/");

// --- Loading ---------------------------------------------------------------------------------------------------------

/* Check one ast-grep rule object against the launch operators. top: the file's `rule` (needs a pattern or kind). */
function checkRuleObject(obj, field, lang, problems, { top = false, control = false, relation = null } = {}) {
  if (!isMap(obj)) { problems.push([field, "must be a mapping (an ast-grep rule object)"]); return; }
  const keys = Object.keys(obj);
  const allowed = new Set([...ATOMIC, ...RELATIONAL, ...COMPOSITE, ...(relation ? ["stopBy"] : []),
    ...(relation === "inside" || relation === "has" ? ["field"] : [])]);
  if (keys.filter((k) => !["stopBy", "field"].includes(k)).length === 0) problems.push([field, "is empty: needs at least one operator"]);
  for (const k of keys) {
    if (allowed.has(k)) continue;
    if (TAINT_KEYS.has(k)) problems.push([`${field}.${k}`, TAINT_PROBLEM]);
    else if (NOT_AT_LAUNCH.has(k)) problems.push([`${field}.${k}`, "not used at launch (rule_bundle.md 3.1)"]);
    else if (k === "field") problems.push([`${field}.${k}`, relation ? `not allowed in ${relation}: field is for has and inside only` : "only allowed in has and inside"]);
    else if (k === "stopBy") problems.push([`${field}.${k}`, "only allowed in a relational rule (inside, has, precedes, follows)"]);
    else problems.push([`${field}.${k}`, "unknown operator"]);
  }
  if ("pattern" in obj) checkPattern(obj.pattern, `${field}.pattern`, lang, problems);
  if ("kind" in obj && (typeof obj.kind !== "string" || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(obj.kind))) problems.push([`${field}.kind`, "must be a node kind name"]);
  if ("regex" in obj) {
    if (typeof obj.regex !== "string" || obj.regex === "") problems.push([`${field}.regex`, "must be a non-empty string"]);
    if (!("pattern" in obj) && !("kind" in obj) && !inAllWithAtom.has(obj)) problems.push([`${field}.regex`, "only refines a pattern or kind (beside it, or in the same all), never alone"]);
  }
  if ("stopBy" in obj) {
    const s = obj.stopBy;
    if (relation === "precedes" || relation === "follows") {
      // Sibling walks to the end (or to a stop rule that may never match) run once per candidate node: quadratic.
      if (s !== "neighbor") problems.push([`${field}.stopBy`, `only neighbor on ${relation} (a walk over every sibling for every node is quadratic; use inside or has instead)`]);
    } else if (isMap(s)) checkRuleObject(s, `${field}.stopBy`, lang, problems);
    else if (s !== "neighbor" && s !== "end") problems.push([`${field}.stopBy`, "must be neighbor, end or a rule object"]);
  }
  if ("field" in obj && (typeof obj.field !== "string" || obj.field === "")) problems.push([`${field}.field`, "must be a field name"]);
  for (const r of RELATIONAL) if (r in obj) checkRuleObject(obj[r], `${field}.${r}`, lang, problems, { relation: r });
  if ("not" in obj) checkRuleObject(obj.not, `${field}.not`, lang, problems);
  for (const c of ["all", "any"]) {
    if (!(c in obj)) continue;
    const list = obj[c];
    if (!Array.isArray(list) || list.length === 0) { problems.push([`${field}.${c}`, "must be a non-empty list of rule objects"]); continue; }
    const hasAtom = c === "all" && list.some((r) => isMap(r) && ("pattern" in r || "kind" in r));
    list.forEach((r, i) => {
      if (hasAtom && isMap(r)) inAllWithAtom.add(r);
      checkRuleObject(r, `${field}.${c}[${i}]`, lang, problems);
    });
  }
  if (top && !hasPositive(obj)) problems.push([field, "needs a pattern or kind to match (directly, in an all, or in every any branch)"]);
  if (control && !hasPositiveControl(obj)) problems.push([field, "needs a positive matcher (a pattern or kind, directly or under has, inside, all, or every any branch); not alone matches almost anything"]);
}

/* A control is positive when it needs some node to exist: an atom, a relation to a positive rule, an all holding one,
 * or an any whose every branch is positive. */
function hasPositiveControl(obj) {
  if (!isMap(obj)) return false;
  if ("pattern" in obj || "kind" in obj) return true;
  if (RELATIONAL.some((r) => isMap(obj[r]) && hasPositiveControl(obj[r]))) return true;
  if (Array.isArray(obj.all) && obj.all.some(hasPositiveControl)) return true;
  if (Array.isArray(obj.any) && obj.any.length && obj.any.every(hasPositiveControl)) return true;
  return false;
}

function hasPositive(obj) {
  if (!isMap(obj)) return false;
  if ("pattern" in obj || "kind" in obj) return true;
  if (Array.isArray(obj.all) && obj.all.some(hasPositive)) return true;
  if (Array.isArray(obj.any) && obj.any.length && obj.any.every(hasPositive)) return true;
  return false;
}

function checkPattern(p, field, lang, problems) {
  let source;
  if (typeof p === "string") {
    if (p.trim() === "") { problems.push([field, "must not be empty"]); return; }
    if (BARE_METAVAR.test(p)) { problems.push([field, "a lone metavariable matches every node"]); return; }
    if (lang === "php") { problems.push([field, "a PHP pattern must be the object form with a `<?php` context and a selector (a bare PHP pattern never matches)"]); return; }
    source = p;
  } else if (isMap(p)) {
    for (const k of Object.keys(p)) if (!["context", "selector", "strictness"].includes(k)) problems.push([`${field}.${k}`, "unknown key (context, selector, strictness)"]);
    if (typeof p.context !== "string" || p.context.trim() === "") { problems.push([`${field}.context`, "must be a non-empty string"]); return; }
    if ("selector" in p && (typeof p.selector !== "string" || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(p.selector))) problems.push([`${field}.selector`, "must be a node kind name"]);
    if ("strictness" in p && !STRICTNESS.includes(p.strictness)) problems.push([`${field}.strictness`, `must be one of ${STRICTNESS.join(", ")}`]);
    if (BARE_METAVAR.test(p.context)) { problems.push([`${field}.context`, "a lone metavariable matches every node"]); return; }
    source = p.context;
  } else { problems.push([field, "must be a string or {context, selector, strictness}"]); return; }
  // ast-grep doesn't report a pattern that fails to parse; it just never matches. Refuse it here.
  if (!isSupported(lang)) return;
  try {
    const root = parseSync(lang, source.split("$").join(expandoChar(lang))).root();
    if (root.find({ rule: { kind: "ERROR" } })) problems.push([field, `does not parse as ${lang} (use the object form with a context)`]);
  } catch (error) { problems.push([field, `does not parse: ${firstLine(error.message)}`]); }
}

const BARE_METAVAR = /^\s*\$(?:\$\$?)?(?:[A-Z_][A-Z0-9_]*)?\s*;?\s*$/; // $A, $$A and $$$A
const firstLine = (s) => String(s).split("\n").map((l) => l.replace(/^\s*\|->/, "").trim()).filter(Boolean).join("; ");

/* Compile rule and control once against an empty file: catches bad kinds, regexes and selectors at load. */
function compileCheck(doc, problems) {
  if (!isSupported(doc.language)) return;
  const root = parseSync(doc.language, "").root();
  try { root.findAll({ rule: doc.rule }); } catch (error) { problems.push(["rule", firstLine(error.message)]); }
  if (doc.kind === "items" && isMap(doc.control)) {
    try { root.matches({ rule: doc.control }); } catch (error) { problems.push(["control", firstLine(error.message)]); }
  }
}

function checkDocument(doc, ctx, problems) {
  const { practiceId, lang, framework } = ctx;
  if (!isMap(doc)) { problems.push(["(document)", "must be a mapping with the rule keys"]); return; }
  for (const k of Object.keys(doc)) {
    if (DOC_KEYS.includes(k)) continue;
    problems.push([k, TAINT_KEYS.has(k) ? TAINT_PROBLEM : "unknown key (no other key is allowed: words live in the registry)"]);
  }
  for (const k of DOC_KEYS) if (!OPTIONAL_KEYS.includes(k) && !(k in doc)) problems.push([k, "is required"]);
  const prefix = `${practiceId}.${lang}-${framework}.`;
  if ("id" in doc) {
    if (typeof doc.id !== "string" || !RULE_ID.test(doc.id)) problems.push(["id", "must match <practice_id>.<lang>-<framework>.<name> (enums.RULE_ID_PATTERN)"]);
    else if (!doc.id.startsWith(prefix) || !RULE_NAME.test(doc.id.slice(prefix.length))) problems.push(["id", `must start with ${prefix} (the directory and file name)`]);
  }
  if ("practice_id" in doc && doc.practice_id !== practiceId) problems.push(["practice_id", `must be ${practiceId} (the directory name)`]);
  if ("language" in doc) {
    if (doc.language !== lang) problems.push(["language", `must be ${lang} (the file name)`]);
    else if (!isSupported(lang) && ctx.strict) problems.push(["language", `no parser for ${lang} in this build (${unsupportedReason(lang)}); its files are not_analyzed unsupported_language and no rule for it ships`]);
  }
  if ("frameworks" in doc) {
    const f = doc.frameworks;
    if (!Array.isArray(f) || f.length === 0) problems.push(["frameworks", "must be a non-empty list"]);
    else {
      const bad = f.filter((x) => !RULE_FRAMEWORKS.includes(x));
      if (bad.length) problems.push(["frameworks", `unknown framework ${bad.map(String).join(", ")}`]);
      if (new Set(f).size !== f.length) problems.push(["frameworks", "has duplicates"]);
      if (!f.includes(framework)) problems.push(["frameworks", `must include ${framework} (the file name)`]);
      if (f.includes("generic") && f.length > 1) problems.push(["frameworks", "generic stands alone: [generic] for a generic file"]);
    }
  }
  if ("kind" in doc && !RULE_KINDS.includes(doc.kind)) problems.push(["kind", `must be one of ${RULE_KINDS.join(", ")}`]);
  if ("rule" in doc) checkRuleObject(doc.rule, "rule", lang, problems, { top: true });
  if (doc.kind === "items") {
    if (!("control" in doc)) problems.push(["control", "is required for kind items"]);
    else checkRuleObject(doc.control, "control", lang, problems, { control: true });
  } else if ("control" in doc) problems.push(["control", "only allowed for kind items"]);
  if ("follow_import" in doc) {
    if (doc.follow_import !== true) problems.push(["follow_import", "must be true when given"]);
    else if (doc.kind !== "evidence") problems.push(["follow_import", "only allowed for kind evidence"]);
    else if (!FOLLOW_LANGS.includes(lang)) problems.push(["follow_import", `only for ${FOLLOW_LANGS.join(", ")}`]);
  }
  if ("table" in doc) checkTable(doc.table, doc.rule, lang, problems);
  if ("path_regex" in doc) checkPathRegex(doc.path_regex, problems);
  if ("min_engine" in doc) {
    if (typeof doc.min_engine !== "string" || !VERSION.test(doc.min_engine)) problems.push(["min_engine", "must be x.y.z"]);
    else if (compareVersions(doc.min_engine, ENGINE_VERSION) > 0) problems.push(["min_engine", `needs @ast-grep/napi ${doc.min_engine}, this build has ${ENGINE_VERSION}`]);
  }
  // Compiling every rule takes seconds; strict loading (custosa rules test, CI) does it for the shipped bundle. At run
  // time a rule that doesn't compile fails on the first file it meets: that file is rule_error and the rules collector
  // is truncated, internal_error, never a pass.
  if (!problems.length && ctx.strict) compileCheck(doc, problems);
}

/* path_regex: a string that starts with ^ or (^|/), compiles here and in Python's re (the registry checks it there), and
 * has no lookaround, backreference or inline flag, so both engines read it alike. */
function checkPathRegex(re, problems) {
  if (typeof re !== "string" || !re.length || re.length > PATH_REGEX_MAX) { problems.push(["path_regex", `must be a string of 1 to ${PATH_REGEX_MAX} characters`]); return; }
  if (!PATH_REGEX_ANCHOR.test(re)) { problems.push(["path_regex", "must start with ^ or (^|/): it names folders from a segment start, never a substring"]); return; }
  if (/\(\?|\\[1-9k]/.test(re)) { problems.push(["path_regex", "no lookaround, backreference, named group or inline flag"]); return; }
  try { new RegExp(re); } catch { problems.push(["path_regex", "does not compile"]); return; }
  // without the u flag JS reads \Z or \A as a letter, where Python reads an anchor; \p is a class in JS
  // only. The u flag refuses every escape it doesn't define, and \p and \P are refused by name.
  try { new RegExp(re, "u"); } catch { problems.push(["path_regex", "an escape JS and Python read differently"]); return; }
  if (/\\[pP]/.test(re)) problems.push(["path_regex", "an escape JS and Python read differently"]);
}

const PATH_REGEXES = new Map(); // path_regex source -> RegExp
const pathRegex = (src) => { let re = PATH_REGEXES.get(src); if (!re) PATH_REGEXES.set(src, (re = new RegExp(src))); return re; };
/* Whether a rule runs on a file at this root-relative path: always, unless its path_regex doesn't match it. */
export const ruleCoversPath = (rule, path) => typeof rule.path_regex !== "string" || pathRegex(rule.path_regex).test(path);

/* table: {metavariable, access} (rule_bundle.md 3.3). The metavariable must be bound on every match of `rule`, so a
 * null table means the code named no table, never that the rule's shape left the capture out. */
function checkTable(table, rule, lang, problems) {
  if (!isMap(table)) { problems.push(["table", "must be a mapping {metavariable, access}"]); return; }
  for (const k of Object.keys(table)) if (k !== "metavariable" && k !== "access") problems.push([`table.${k}`, "unknown key (metavariable, access)"]);
  if (!TABLE_ACCESS.includes(table.access)) problems.push(["table.access", `must be one of ${TABLE_ACCESS.join(", ")}`]);
  const mv = table.metavariable;
  if (typeof mv !== "string" || !CAPTURING_METAVAR.test(mv)) {
    problems.push(["table.metavariable", "must be one capturing metavariable such as $TABLE ($_, $_NAME, $$NAME and $$$NAME capture no single node)"]);
    return;
  }
  if (isMap(rule) && !boundMetavariables(rule, lang).has(mv.slice(1))) {
    problems.push(["table.metavariable", `${mv} is not bound on every match of rule: it must appear in a pattern every match satisfies (not under not, in every any branch, inside the selector of a context pattern)`]);
  }
}

/* The metavariables bound on every match of a rule object: a pattern's own, the union over all and relational
 * sub-rules (ast-grep shares one environment), the intersection over any branches, nothing from not. */
export function boundMetavariables(obj, lang) {
  const out = new Set();
  if (!isMap(obj)) return out;
  if ("pattern" in obj) for (const v of patternMetavariables(obj.pattern, lang)) out.add(v);
  for (const r of RELATIONAL) if (isMap(obj[r])) for (const v of boundMetavariables(obj[r], lang)) out.add(v);
  if (Array.isArray(obj.all)) for (const sub of obj.all) for (const v of boundMetavariables(sub, lang)) out.add(v);
  if (Array.isArray(obj.any) && obj.any.length) {
    const sets = obj.any.map((sub) => boundMetavariables(sub, lang));
    for (const v of sets[0]) if (sets.every((s) => s.has(v))) out.add(v);
  }
  return out;
}

const METAVAR_TEXT = /^\$([A-Z][A-Z0-9_]*)$/;

/* The capturing metavariables of a parsed pattern, as ast-grep reads them: a node whose whole text is `$NAME` (after
 * the language's expando is mapped back), so `foo$T`, `$Tx` and a `$T` inside a comment don't count, and a `$T` that
 * is the whole content of a string literal does. */
function metavariablesOfNode(node, expando, out = new Set()) {
  const text = expando === "$" ? node.text() : node.text().split(expando).join("$");
  const m = METAVAR_TEXT.exec(text);
  if (m) { out.add(m[1]); return out; }
  if (/comment/.test(node.kind())) return out;
  for (const c of node.children()) metavariablesOfNode(c, expando, out);
  return out;
}

/* Without a parser for the language (a rule loaded but left out at run time): whole tokens outside comments. */
const metavariablesInText = (text) => new Set([...text.replace(/\/\*[\s\S]*?\*\/|\/\/.*|#.*/g, "")
  .matchAll(/(?<![\w$])\$([A-Z][A-Z0-9_]*)(?![\w$])/g)].map((m) => m[1]));

/* The capturing metavariables of a pattern. In the object form only the selected node is the pattern: a metavariable
 * elsewhere in the context is never bound. */
function patternMetavariables(p, lang) {
  const source = typeof p === "string" ? p : isMap(p) && typeof p.context === "string" ? p.context : null;
  if (source === null) return new Set();
  if (!isSupported(lang)) return metavariablesInText(source);
  const expando = expandoChar(lang);
  try {
    let node = parseSync(lang, source.split("$").join(expando)).root();
    if (isMap(p) && typeof p.selector === "string") node = node.find({ rule: { kind: p.selector } });
    return node ? metavariablesOfNode(node, expando) : new Set();
  } catch { return new Set(); } // a bad selector is reported by compileCheck
}

/* A rules or bundle folder given as a path or a file URL, as a path (URL.pathname would keep %20 and other escapes). */
const asPath = (dir) => (dir instanceof URL ? fileURLToPath(dir) : String(dir));

function rulesRoot(dir) {
  const d = asPath(dir);
  // Accept the knowledge directory (holding rules/ and manifest.json) or the rules directory itself.
  return existsSync(join(d, "rules")) && statSync(join(d, "rules")).isDirectory() && existsSync(join(d, "manifest.json")) ? join(d, "rules") : d;
}

const RULE_FILE = /^([a-z0-9_]+)-([a-z0-9_]+)\.yml$/;
const FIXTURE_FILE = /^([a-z0-9_]+)-([a-z0-9_]+)\.fixtures\.([a-z]+)$/;

/* The rule files of the rule set, with name problems for anything else in it. */
function listRuleFiles(root, problems) {
  const files = [];
  let entries;
  try { entries = readdirSync(root, { withFileTypes: true }); } catch (error) { problems.push(`${root}: (directory): ${error.message}`); return files; }
  for (const e of entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))) {
    if (DOC_FILES.has(e.name) && e.isFile()) continue;
    if (!e.isDirectory()) { problems.push(`${e.name}: (file): not a practice directory`); continue; }
    if (!PRACTICE_ID.test(e.name)) problems.push(`${e.name}: (directory): not a practice id`);
    for (const ent of readdirSync(join(root, e.name), { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))) {
      const f = ent.name;
      const rel = `${e.name}/${f}`;
      if (!ent.isFile()) { problems.push(`${rel}: (file): not a regular file`); continue; }
      if (DOC_FILES.has(f)) continue;
      const m = RULE_FILE.exec(f);
      if (m) {
        if (!LANGS.includes(m[1])) problems.push(`${rel}: (file name): ${m[1]} is not a language of enums.LANGUAGES`);
        else if (!RULE_FRAMEWORKS.includes(m[2])) problems.push(`${rel}: (file name): ${m[2]} is not a framework of enums.RULE_FRAMEWORKS`);
        else files.push({ rel, abs: join(root, e.name, f), practiceId: e.name, lang: m[1], framework: m[2] });
        continue;
      }
      const fx = FIXTURE_FILE.exec(f);
      if (fx && existsSync(join(root, e.name, `${fx[1]}-${fx[2]}.yml`))) {
        if (FIXTURE[fx[1]] && FIXTURE[fx[1]][0] !== fx[3]) problems.push(`${rel}: (file name): fixtures for ${fx[1]} end .${FIXTURE[fx[1]][0]}`);
        continue;
      }
      problems.push(`${rel}: (file name): neither <lang>-<framework>.yml nor its .fixtures.<ext>`);
    }
  }
  return files;
}

/* An error that callers tell apart by its code (RULES_INVALID, SETUP_DEADLINE, BAD_INPUT, ...). The stack starts where
 * it is thrown, not here. */
function coded(message, code, Type = Error) {
  const error = new Type(message);
  Error.captureStackTrace(error, coded);
  error.code = code;
  return error;
}

/**
 * loadRules(dir, {strict=false}) -> Rule[]. strict refuses a rule for a language with no parser on this platform; not
 * strict leaves such rules out (their files are then unsupported_language). Rule: {id, practice_id, language, frameworks, kind, rule, control?, min_engine, table?, path_regex?, file}
 * (file: the rule file relative to the rules directory). Throws an Error (code RULES_INVALID, .problems) listing every
 * `file: field: problem`.
 */
export function loadRules(dir = DEFAULT_RULES_DIR, { strict = false } = {}) {
  const root = rulesRoot(dir);
  const problems = [];
  const rules = [];
  const seen = new Map();
  for (const f of listRuleFiles(root, problems)) {
    let text;
    try { text = readFileSync(f.abs, "utf8"); } catch (error) { problems.push(`${f.rel}: (file): could not be read (${error.code ?? "error"})`); continue; }
    const docs = parseAllDocuments(text, { uniqueKeys: true, prettyErrors: false, maxAliasCount: 100 });
    const list = Array.isArray(docs) ? docs : [docs];
    if (list.length === 0) { problems.push(`${f.rel}: (file): holds no rule`); continue; }
    list.forEach((d, i) => {
      const where = list.length > 1 ? `${f.rel}#${i + 1}` : f.rel;
      if (d.errors.length) { for (const e of d.errors) problems.push(`${where}: (yaml): ${firstLine(e.message)}`); return; }
      const doc = d.toJS({ maxAliasCount: 100 });
      const local = [];
      checkDocument(doc, { ...f, strict }, local);
      for (const [field, problem] of local) problems.push(`${where}: ${field}: ${problem}`);
      if (local.length) return;
      if (seen.has(doc.id)) { problems.push(`${where}: id: ${doc.id} is also defined in ${seen.get(doc.id)}`); return; }
      seen.set(doc.id, where);
      // Not strict (the inspector at run time): a rule for a language this platform can't parse is left out, and that
      // language's files are unsupported_language. Strict (custosa rules test, CI) refuses it above.
      if (isSupported(doc.language)) rules.push(Object.freeze({ ...doc, file: f.rel }));
    });
  }
  if (problems.length) {
    const error = coded(`The rule set has ${problems.length} problem${problems.length === 1 ? "" : "s"}:\n${problems.join("\n")}`, "RULES_INVALID");
    error.problems = problems;
    throw error;
  }
  return rules;
}

/* Whether the rule files on disk are the ones the bundle's manifest names, the manifest being the text a load was
 * keyed on (manifestText): the manifest still reads the same, and, when it lists rule files (manifest.files, as the
 * shipped bundle does), every rule file the loader reads is listed there with its sha256 and every listed rules/ file
 * is there.
 * Checked after a load, so a sync that lands while the rules are read (new rule files, or a new manifest) is caught
 * and the rules are never paired with the other ruleset_id. */
export function bundleMatches(bundleDir, manifestText) {
  bundleDir = asPath(bundleDir);
  try {
    if (readFileSync(join(bundleDir, "manifest.json"), "utf8") !== manifestText) return false;
    const listed = JSON.parse(manifestText)?.files;
    const want = new Map((Array.isArray(listed) ? listed : []).filter((f) => typeof f?.path === "string" && f.path.startsWith("rules/"))
      .map((f) => [f.path, f.sha256]));
    if (!want.size) return true; // a manifest that lists no rule file (a test or hand-made bundle): the manifest only
    // Only what the loader reads (its own listing, listRuleFiles): fixtures, README.md, NAMING.md and anything else it
    // skips may sit beside the rules unlisted (a hosted knowledge checkout holds them).
    const root = rulesRoot(join(bundleDir, "rules"));
    for (const f of listRuleFiles(root, [])) {
      const sha = createHash("sha256").update(readFileSync(f.abs)).digest("hex");
      if (want.get(`rules/${f.rel}`) !== sha) return false;
    }
    for (const p of want.keys()) if (!statSync(join(bundleDir, ...p.split("/"))).isFile()) return false;
    return true;
  } catch { return false; }
}

/* loadRules(<bundleDir>/rules) in a thread of its own (this module, run as a worker), so the seconds of YAML parsing
 * and rule checking overlap the walk and the catalog and platform reads instead of coming before them. The same
 * function, the same rules (each frozen again on arrival, as loadRules returns them), then bundleMatches against the
 * manifest the load was keyed on. The thread also works out each rule's factored NapiConfigs (factor.mjs) once for the
 * bundle, so no rule worker has to (runRules hands them to the workers with the rules).
 * -> {result: Promise<Rule[] | null | "stale">, worker}: null when the rule set is invalid (the caller's rules
 * collector is failed, internal_error, as with a synchronous load); "stale" when the bundle changed under the load;
 * rejects when the thread itself couldn't run (the caller then loads on the main thread). worker: ref() while someone
 * waits on the result, unref() once nobody does. */
export function loadRulesInThread(bundleDir, manifestText) {
  const worker = new Worker(new URL(import.meta.url), { workerData: { custosaLoadRules: true, bundleDir: asPath(bundleDir), manifestText },
    stdout: true, stderr: true });
  worker.stdout.resume(); worker.stderr.resume();
  const result = new Promise((resolve, reject) => {
    worker.once("message", (m) => {
      if (m?.ok && Array.isArray(m.rules)) {
        const rules = m.rules.map((r) => Object.freeze(r));
        if (Array.isArray(m.engine) && m.engine.length === rules.length) rules.forEach((r, i) => ENGINE.set(r, m.engine[i]));
        resolve(rules);
      }
      else if (m?.stale) resolve("stale");
      else if (m?.invalid) resolve(null);
      else reject(new Error("rule loader failed"));
    });
    worker.once("error", reject);
    worker.once("exit", () => reject(new Error("rule loader exited"))); // a no-op once the message settled it
  });
  return { result, worker };
}

if (!isMainThread && workerData?.custosaLoadRules) {
  const { bundleDir, manifestText } = workerData;
  try {
    const rules = loadRules(join(bundleDir, "rules"));
    let engine = null;
    try { engine = engineConfigs(rules); } catch { engine = null; } // the workers work them out instead
    parentPort.postMessage(bundleMatches(bundleDir, manifestText) ? { ok: true, rules, engine } : { ok: false, stale: true });
  } catch (error) {
    parentPort.postMessage(bundleMatches(bundleDir, manifestText) ? { ok: false, invalid: error?.code === "RULES_INVALID" } : { ok: false, stale: true });
  }
}

// --- Running ---------------------------------------------------------------------------------------------------------

/* Each rule's factored NapiConfigs (factor.mjs), for rules the loader's thread worked them out for. A rule without one
 * has them worked out in each rule worker, on its first file. */
const ENGINE = new WeakMap();

export { fingerprint };
import { followImports } from "./followimport.mjs";

/* notAnalyzed reasons runRules uses beyond the contract's files.not_analyzed enum, and the contract reason each maps to
 * until the contract names them (asked on issue #4). Every other reason is already a contract reason. */
export const CONTRACT_REASON = Object.freeze({
  no_rule_for_framework: "unsupported_language", // rules exist for the language, none for the detected frameworks
  frameworks_unknown: "unsupported_language", // the caller didn't know the frameworks: framework rules not judged
  rule_error: "parse_error", // a rule failed on the file
  // match_limit (the run passed 20,000 matches, or the document's size limit, and this file lost some) is a contract
  // reason since v2.1 and is sent as it is.
});
/** files.not_analyzed entries in the contract's vocabulary. */
export const toContractNotAnalyzed = (list) => list.map(({ path, reason }) => ({ path, reason: CONTRACT_REASON[reason] ?? reason }));

const isGeneric = (rule) => rule.frameworks.length === 1 && rule.frameworks[0] === "generic";

/* Workers alive in this process (started and not yet exited). */
let live = 0;
/** How many rule workers are alive (started, not yet exited). 0 whenever no runRules call is in progress, unless a
 * run gave up on a stuck worker (see MatchWorker). */
export const liveWorkers = () => live;

const READY_MS = 10000; // a worker that doesn't load its rules in this long is a failed run
/* Terminated rule worker threads not yet exited, across every pool of this process, and the most there may be before
 * no new worker starts (two per worker of a full run: what one run can leave behind). */
let stoppingAll = 0;
export const STOPPING_MAX = 2 * 4;
/** How many terminated rule worker threads are still running (inside a native call Node can't interrupt). */
export const stoppingWorkers = () => stoppingAll;
const MAX_STOPPING = 2; // terminated workers still finishing a native call, at most, before the next file waits
export const CLOSE_GRACE_MS = 30000; // how long a run waits, at most, for terminated workers to exit

/* The worker pool of one runRules call: one worker at a time runs a file. A worker past the deadline is terminated and
 * the next file gets a fresh one. terminate() takes effect when the worker's current native call returns to
 * JavaScript, so a terminated worker can go on running for a while: it is kept in `stopping` (at most MAX_STOPPING at
 * once) and close() waits for every one to exit, up to a grace limit.
 *
 * Past the grace limit the pool is poisoned: it starts no more workers, close() returns false, and runRules returns
 * what it gathered with the collector truncated, timeout. A poisoned pool is never used again: without a WarmPool every
 * runRules call builds its own, and a WarmPool drops a poisoned one, so the next call never reuses a stuck worker.
 * until (epoch ms, set by runRules from the check's hard deadline): neither the wait for terminated workers nor a new
 * worker's start goes past it (the file is then time_limit, and the pool is not poisoned). Accepted trade-off: a
 * native call that never returns (no rule the loader accepts should do this) leaves its thread running until the
 * process exits; Node can't kill a thread mid native call, and a child process (which could be killed) is ruled out
 * for the inspector. */
/* The keys a worker's matches depend on: the install key (fingerprints, handler ids) and the root's content key
 * (shared fingerprints). A warm worker is reused only under the same pair. */
const keyIdOf = (key, contentKey) => Buffer.from(key).toString("hex") + (contentKey ? `:${contentKey}` : "");

export class MatchWorker { // exported for tests only
  constructor(rules, key, graceMs = CLOSE_GRACE_MS, factor = true, contentKey = null) {
    this.rules = rules; this.key = key; this.graceMs = graceMs; this.factor = factor; this.contentKey = contentKey;
    this.worker = null; this.stopping = new Set(); this.poisoned = false; this.until = null;
    this.keyId = keyIdOf(key, contentKey); // the keys its threads fingerprint with (WarmPool)
  }

  /* Terminate a worker; the returned promise resolves once its thread has exited (whatever terminate() reports). */
  stop(worker) {
    worker.terminate().catch(() => {});
    stoppingAll++;
    const done = worker.exited.then(() => { this.stopping.delete(done); stoppingAll--; });
    this.stopping.add(done);
    return done;
  }

  /* Wait until `stopping` holds at most `max` workers; false (and the pool poisoned) when that takes over graceMs.
   * until (epoch ms, optional): the run's own limit. Reached before the grace limit, the wait ends with "deadline" and
   * the pool is not poisoned (the workers aren't stuck; the run is out of time). */
  async drain(max, until = null) {
    if (this.poisoned) return this.stopping.size <= max;
    const grace = Date.now() + this.graceMs;
    const deadline = until === null ? grace : Math.min(grace, until);
    while (this.stopping.size > max) {
      const left = deadline - Date.now();
      let timer;
      const expired = await Promise.race([
        Promise.race(this.stopping).then(() => false),
        new Promise((resolve) => { timer = setTimeout(() => resolve(true), Math.max(0, left)); }),
      ]);
      clearTimeout(timer);
      if (expired && this.stopping.size > max) {
        if (deadline < grace) return "deadline";
        this.poisoned = true; return false;
      }
    }
    return true;
  }

  /* Keep (unref) or hold (ref) the idle worker: a warm pool's idle thread must not keep the process alive. */
  ref() { this.worker?.ref(); }
  unref() { this.worker?.unref(); }

  async ensure() {
    if (this.worker) return;
    // this.until (epoch ms or null): set by runRules from the check's hard deadline. Neither the wait for terminated
    // workers nor a new worker's start may run past it: past it the file is time_limit (code SETUP_DEADLINE).
    const until = this.until ?? null;
    const drained = await this.drain(MAX_STOPPING - 1, until);
    if (drained === "deadline") throw coded("out of time waiting for terminated workers", "SETUP_DEADLINE");
    if (!drained) throw coded("terminated workers did not exit", "POOL_STUCK");
    if (until !== null && Date.now() >= until) throw coded("out of time before a worker could start", "SETUP_DEADLINE");
    // Threads terminated (by this run or an earlier one) that are still inside a native call, process-wide: past
    // STOPPING_MAX no new worker starts. A long-lived server whose calls keep meeting such files would otherwise pile
    // them up (each holds a core and its memory until its call returns). The file is time_limit (code THREADS_BUSY).
    if (stoppingAll >= STOPPING_MAX) throw coded("too many terminated workers still running", "THREADS_BUSY");
    const worker = new Worker(new URL("./rules-worker.mjs", import.meta.url), {
      workerData: { custosaRules: true, rules: this.rules, key: this.key, factor: this.factor, contentKey: this.contentKey },
      stdout: true, stderr: true,
    });
    live++;
    // Permanent: whenever the thread exits (crash, terminate, or death while idle) it stops being the pool's worker,
    // so the next file starts a fresh one instead of posting to a dead thread and waiting out its deadline.
    worker.exited = new Promise((resolve) => worker.once("exit", () => {
      live--;
      if (this.worker === worker) this.worker = null;
      resolve();
    }));
    // A thread that fails while idle (a warm pool's, between calls) must not throw in the server: its exit, above, is
    // what retires it. A job in flight has its own error listener (run) and counts the file as rule_error.
    worker.on("error", () => {});
    // The inspector's stdout belongs to MCP: the worker's output is drained here, never forwarded.
    worker.stdout.resume(); worker.stderr.resume();
    try {
      await new Promise((resolve, reject) => {
        const readyBy = until === null ? READY_MS : Math.min(READY_MS, Math.max(0, until - Date.now()));
        const timer = setTimeout(() => {
          cleanup();
          const e = new Error("worker did not start");
          // Out of time only when the check's own limit has passed; a worker that never got ready within READY_MS
          // (or exits or errors first, below) is a broken worker: the run fails, worker_failed.
          if (until !== null && Date.now() >= until) e.code = "SETUP_DEADLINE";
          reject(e);
        }, readyBy);
        const onMessage = (m) => { if (m?.type === "ready") { cleanup(); resolve(); } };
        const onError = (error) => { cleanup(); reject(error); };
        const cleanup = () => { clearTimeout(timer); worker.off("message", onMessage); worker.off("error", onError); };
        worker.on("message", onMessage); worker.on("error", onError);
        worker.exited.then(() => { cleanup(); reject(new Error("worker exited")); });
      });
    } catch (error) {
      this.stop(worker);
      throw error;
    }
    this.worker = worker;
  }

  /* -> {found, done (the worker's done message) | null, killed, crashed} */
  async run(job, timeoutMs, signal = null) {
    await this.ensure();
    const worker = this.worker;
    const found = [];
    const outcome = await new Promise((resolve) => {
      let settled = false;
      const timer = setTimeout(() => finish({ killed: true }), timeoutMs);
      // Cancellation stops the file at once: the worker is terminated like one past its deadline.
      const onAbort = () => finish({ killed: true });
      const onMessage = (m) => {
        if (m?.type === "found") found.push(...m.matches);
        else if (m?.type === "replace") { found.length = 0; for (const x of m.matches) found.push(x); } // runJob
        else if (m?.type === "done") finish({ done: m });
      };
      const onError = () => finish({ crashed: true });
      function finish(result) {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        signal?.removeEventListener("abort", onAbort);
        worker.off("message", onMessage); worker.off("error", onError);
        resolve(result);
      }
      worker.on("message", onMessage); worker.on("error", onError);
      // Resolves at once if the thread already exited: a dead worker is a crash now, never a wait to the deadline.
      worker.exited.then(() => finish({ crashed: true }));
      if (signal?.aborted) { onAbort(); return; }
      signal?.addEventListener("abort", onAbort, { once: true });
      worker.postMessage(job);
    });
    if (outcome.killed || outcome.crashed) {
      // The file is decided now (time_limit or rule_error); the thread is stopped and close() waits for it to exit.
      if (this.worker === worker) this.worker = null;
      this.stop(worker);
    }
    return { found, done: outcome.done ?? null, killed: !!outcome.killed, crashed: !!outcome.crashed };
  }

  /* Stop the current worker and wait for every worker this pool started to exit, up to graceMs. -> true when all
   * exited; false when the grace limit passed (the pool is then poisoned and the stuck threads are left behind). */
  async close() {
    if (this.worker) { const w = this.worker; this.worker = null; this.stop(w); }
    return this.drain(0);
  }
}

/* What survives from a file that wasn't fully and cleanly analysed: what was observed against the code (violations
 * and items without their control). Evidence and controls from a recovered tree, a failed rule or a cut-off run are
 * dropped, since a recovered tree can show a control that isn't there. */
const observedOnly = (m) => m.kind === "violation" || (m.kind === "item" && m.has_control === false);

/**
 * runRules(rules, files, opts) -> Promise<{matches, notAnalyzed, analyzed, analyzedPaths, languages, status, reason, count, code?}>
 *
 * files: [{path, lang?, text?, local?}]; path is the root-relative path as sent (fact schema path); lang defaults to
 * languageOf(path); text, when absent, is read from opts.root; local (default path) is the root-relative path on this
 * machine, before any hashing: the shared fingerprint takes it, so it is the same on every install (§3.5). It is
 * never sent.
 * opts: key (the per-install HMAC key, required); frameworks (required: the detected frameworks, or null when they are
 * unknown); root; timeoutMs (hard per-file deadline, default 5000); maxBytes (default 2,000,000); closeGraceMs (below).
 *
 * Each file is parsed and matched in a worker thread; past the deadline the file is time_limit, its worker is
 * terminated and the next file gets a fresh one. runRules resolves after every worker it started has exited
 * (liveWorkers() is back to 0), or after closeGraceMs. notAnalyzed: [{path, reason}], reason one of the contract's (unknown_type,
 * unsupported_language, too_large, unreadable, parse_error, time_limit, match_limit) or CONTRACT_REASON's
 * (no_rule_for_framework, frameworks_unknown, rule_error); toContractNotAnalyzed maps them for the fact document.
 * - A language with no parser or no rule: unsupported_language. Rules for the language but none for the detected
 *   frameworks: no_rule_for_framework (never counted as analysed with zero rules run).
 * - frameworks null: only [generic] rules run, and a file whose language has framework rules is frameworks_unknown.
 * - A recovered parse (ERROR or MISSING nodes, after parse.mjs's repairs): parse_error. A failing rule:
 *   rule_error. Past the time limit: time_limit. In these three the file's violations and items without their control
 *   are kept; its evidence and items with their control are dropped.
 * - Over 20,000 matches in all (the contract's matches maxItems): violations and items without their control are kept
 *   first, then evidence and items with their control, in match order, up to 20,000; every file that lost a match is
 *   match_limit and no longer counted as analysed. A match_limit file parsed cleanly, so the evidence it kept is real
 *   and stays in matches, but the file counts as not analysed, so no pass can rest on it.
 * - closeGraceMs (default 30,000): how long the run waits, at most, for terminated workers to exit (endGraceMs, default
 *   the same: that wait once every file is decided). Past it the run
 *   returns what it gathered with the collector truncated, timeout; files it could not start are time_limit, and a
 *   stuck thread may run on until the process exits (see MatchWorker).
 * analyzed: files parsed cleanly, run through every applicable rule, with every match reported; analyzedPaths: their
 * paths (sorted). Every input file is in exactly one of analyzedPaths and notAnalyzed (absent on failed). status (the rules
 * collector): ok; empty; truncated with timeout, internal_error (a rule failed) or item_limit (over 20,000 matches);
 * failed with internal_error and a code (engine_unavailable, worker_failed, run_failed), never an error text.
 * count: rules that ran on at least one file.
 * Each match carries table (rules that declare table) and handler (the id of the function it belongs to; captures.mjs).
 * A file with a not-analysed reason keeps its matches without a handler (its tree may have recovered). links: one
 * {handler, table, access} per distinct triple on the reported matches of rules that declare table, both non-null.
 * - signal (an AbortSignal, optional): once aborted, the file in each worker is stopped and its worker terminated, no
 *   further file starts, and the run returns after the workers exit (the caller discards the result).
 * - onFile(done, total) (optional): called after each matched file, for progress.
 */
export async function runRules(rules, files, opts = {}) {
  const { key, frameworks, root = null, timeoutMs = TIMEOUT_MS, maxBytes = MAX_BYTES, closeGraceMs = CLOSE_GRACE_MS,
    endGraceMs = closeGraceMs, workers = 1, deadline = null, hardDeadline = null, signal = null, onFile = null } = opts;
  if (!key || !(typeof key === "string" || Buffer.isBuffer(key) || key instanceof Uint8Array)) throw new TypeError("runRules needs opts.key, the per-install key");
  if (frameworks !== null && !(Array.isArray(frameworks) && frameworks.every((f) => typeof f === "string"))) {
    throw new TypeError("runRules needs opts.frameworks: the detected frameworks, or null when they are unknown");
  }
  // opts.contentKey: the root's content key from its state file, 64 hex, or null. With it,
  // every match carries shared_fingerprint; without it the field is null.
  const contentKey = opts.contentKey ?? null;
  if (contentKey !== null && !(typeof contentKey === "string" && /^[0-9a-f]{64}$/.test(contentKey))) {
    throw new TypeError("runRules needs opts.contentKey as 64 lowercase hex, or null");
  }
  const failed = (code) => ({ matches: [], links: [], notAnalyzed: [], analyzed: 0, languages: [], status: "failed", reason: "internal_error", count: 0, code });
  if (!engineAvailable()) return failed("engine_unavailable");
  // opts.factor (default true; false only to check the two against each other): run each rule from its factored
  // NapiConfigs (rules-worker.mjs). The same matches either way.
  const factor = opts.factor !== false;
  const slim = () => rules.map((r) => {
    const { id, practice_id, kind, rule, control, table } = r;
    return { id, practice_id, kind, rule, control, table, ...(factor && ENGINE.has(r) ? { engine: ENGINE.get(r) } : {}) };
  });
  const size = Math.max(1, Math.min(MAX_WORKERS, Math.floor(Number(workers)) || 1));
  // opts.warm (a WarmPool, the stdio server's): workers already started for these rules and this key are reused, and
  // the ones left healthy go back to it instead of exiting. Without it every call starts and stops its own.
  const warm = opts.warm instanceof WarmPool ? opts.warm : null;
  let pool;
  if (warm) pool = warm.checkout(rules, slim, key, size, closeGraceMs, factor, contentKey);
  else { const s = slim(); pool = Array.from({ length: size }, () => new MatchWorker(s, key, closeGraceMs, factor, contentKey)); }
  for (const w of pool) w.until = hardDeadline === null ? null : hardDeadline - HARD_RESERVE_MS;
  let result;
  try {
    result = await run(rules, files, { pool, frameworks, root, timeoutMs, maxBytes, deadline, hardDeadline, signal, onFile });
    // T28-P1-C5: follow_import evidence, one import hop, once every file has run (followimport.mjs).
    if (rules.some((r) => r.follow_import === true)) {
      const matches = await followImports(rules, result.matches, files, { root, maxBytes, key });
      if (matches !== result.matches) result = { ...result, matches };
    }
  } catch (error) {
    await Promise.all(pool.map((w) => w.close())); // never handed back: a run that failed may have left them broken
    if (error instanceof TypeError && error.code === "BAD_INPUT") throw error;
    return failed(error?.code === "WORKER_FAILED" ? "worker_failed" : "run_failed");
  }
  // Bounded: past the grace limit the results gathered so far go back with the collector truncated, timeout. Near
  // the check's hard deadline the grace shrinks to what is left (at least half a second). endGraceMs (default
  // closeGraceMs): the wait once every file is decided. The result is final by then; a longer wait only keeps the
  // steps after the rules (the secret scan) from their share of the budget.
  for (const w of pool) w.graceMs = Math.min(w.graceMs, endGraceMs);
  if (hardDeadline !== null) for (const w of pool) w.graceMs = Math.max(500, Math.min(w.graceMs, hardDeadline - HARD_RESERVE_MS - Date.now()));
  // A cancelled run waits only briefly for its terminated workers: nobody is waiting for its result.
  if (signal?.aborted) for (const w of pool) w.graceMs = Math.min(w.graceMs, CANCEL_GRACE_MS);
  // Warm: wait (bounded the same way) for the workers this run terminated, keep the idle one. A pool past the grace
  // limit is poisoned and checkin drops it, so the next call never meets a stuck worker.
  const closed = await Promise.all(pool.map((w) => (warm ? w.drain(0) : w.close())));
  for (const w of pool) w.until = null;
  if (warm) warm.checkin(rules, pool);
  if (closed.includes(false)) return { ...result, status: "truncated", reason: "timeout" };
  return result;
}

/* Rule workers kept between runRules calls (the stdio server's): starting one costs a second or more on a busy
 * computer (the grammars, the rules copied in, every rule's prefilter worked out on its first file), and a server
 * answers many calls. At most MAX_WORKERS idle MatchWorkers are kept, each holding at most one live thread (unref'd
 * while idle, so it never keeps the process alive), and all are stopped after idleMs without a call. Only a
 * MatchWorker that isn't poisoned goes back; one whose worker was terminated (a time_limit, a crash, a cancelled call)
 * goes back with no thread and starts a fresh one on its next file. New rules (a synced bundle) or another key drop
 * every idle worker. Concurrent calls each take their own MatchWorkers (new ones when the idle ones are taken). */
export const WARM_IDLE_MS = 10 * 60 * 1000;
export class WarmPool {
  constructor({ idleMs = WARM_IDLE_MS, max = MAX_WORKERS } = {}) {
    this.idleMs = idleMs; this.max = max; this.idle = []; this.rules = null; this.keyId = null; this.factor = true; this.timer = null;
    this.closing = new Set(); // close() of MatchWorkers let go, until their threads exited (drop() waits for them)
    this.started = 0; // MatchWorkers this pool created (for tests and the timing harness)
  }

  checkout(rules, slim, key, size, graceMs, factor = true, contentKey = null) {
    const keyId = keyIdOf(key, contentKey);
    if (this.rules !== rules || this.keyId !== keyId || this.factor !== factor) {
      this.drop(); this.rules = rules; this.keyId = keyId; this.factor = factor; this.slim = null;
    }
    clearTimeout(this.timer); this.timer = null;
    const out = [];
    while (out.length < size && this.idle.length) {
      const w = this.idle.pop();
      if (w.poisoned || w.keyId !== this.keyId) { this.retire(w); continue; }
      w.graceMs = graceMs;
      w.ref();
      out.push(w);
    }
    if (out.length < size) this.slim ??= slim();
    while (out.length < size) { out.push(new MatchWorker(this.slim, key, graceMs, factor, contentKey)); this.started++; }
    return out;
  }

  checkin(rules, workers) {
    for (const w of workers) {
      // A worker from a call that ran while another call switched the pool to other rules or another key (two
      // installs' keys never mix: a worker's fingerprints and handler ids are its key's) is retired, never kept.
      if (w.poisoned || rules !== this.rules || w.keyId !== this.keyId || w.factor !== this.factor || this.idle.length >= this.max) { this.retire(w); continue; }
      w.unref();
      this.idle.push(w);
    }
    clearTimeout(this.timer);
    this.timer = this.idle.length ? setTimeout(() => this.drop(), this.idleMs) : null;
    this.timer?.unref();
  }

  /* How many idle MatchWorkers hold a started thread. */
  get warmThreads() { return this.idle.filter((w) => w.worker).length; }

  retire(w) {
    const done = w.close().finally(() => this.closing.delete(done));
    this.closing.add(done);
  }

  /* Stop every idle worker; resolves once every worker this pool let go has exited (each wait bounded by its grace). */
  drop() {
    clearTimeout(this.timer); this.timer = null;
    for (const w of this.idle) this.retire(w);
    this.idle = [];
    return Promise.all([...this.closing]);
  }
}

const CANCEL_GRACE_MS = 2_000;

/* How long before the hard deadline the rules must be done (worker exits, then the steps after the rules). */
const HARD_RESERVE_MS = 4_000;

/** The most rule workers one run uses. Each holds the grammars and rules (tens of MB): a few, never one per core. */
export const MAX_WORKERS = 4;
/** The worker count a whole-project run uses on this computer: one per core, at most MAX_WORKERS. The main thread
 * spends well under a second of CPU on a whole run (it hands out files and gathers matches), so it needs no core of
 * its own. */
export function defaultWorkers() {
  let cores = 1;
  try { cores = typeof availableParallelism === "function" ? availableParallelism() : cpus().length; } catch { cores = 1; }
  return Math.max(1, Math.min(MAX_WORKERS, cores));
}

/* Files are decided in order (classification, input checks), matched by up to pool.length workers at once, and put
 * back together in file order, so the result is the same whatever the worker count. deadline (epoch ms): a file not
 * started by then is time_limit and the collector is truncated, timeout (the run's overall time budget). */
async function run(rules, files, { pool, frameworks, root, timeoutMs, maxBytes, deadline, hardDeadline, signal = null, onFile = null }) {
  const byLang = new Map();
  for (const r of rules) { if (!byLang.has(r.language)) byLang.set(r.language, []); byLang.get(r.language).push(r); }
  const ran = new Set(), languages = new Set();
  const slots = files.map(() => ({ matches: [], notAnalyzed: [], analyzed: null }));
  let timedOut = false, ruleFailed = false, stuck = false, setupCut = false, ranAny = false, busy = false;
  const jobs = [];
  files.forEach((file, index) => {
    const path = file.path;
    if (typeof path !== "string" || !PATH.test(path)) {
      throw coded(`runRules: ${JSON.stringify(path)} is not a root-relative path as sent (fact schema path)`, "BAD_INPUT", TypeError);
    }
    const slot = slots[index];
    if (file.local !== undefined && !(typeof file.local === "string" && file.local)) {
      throw coded(`runRules: the local path of ${JSON.stringify(path)} is not a non-empty string`, "BAD_INPUT", TypeError);
    }
    const lang = file.lang ?? languageOf(path);
    if (!lang) { slot.notAnalyzed.push({ path, reason: "unknown_type" }); return; }
    const forLang = byLang.get(lang);
    if (!isSupported(lang) || !forLang) { slot.notAnalyzed.push({ path, reason: "unsupported_language" }); return; }
    // A rule whose path_regex leaves this file out is not applicable to it; a file left with none is
    // no_rule_for_framework, as with no rule for its frameworks (never analysed with zero rules run).
    const applicable = forLang.filter((r) => (isGeneric(r) || (frameworks !== null && r.frameworks.some((f) => frameworks.includes(f))))
      && ruleCoversPath(r, path));
    const unjudged = frameworks === null && forLang.some((r) => !isGeneric(r));
    if (!applicable.length) { slot.notAnalyzed.push({ path, reason: unjudged ? "frameworks_unknown" : "no_rule_for_framework" }); return; }
    jobs.push({ index, file, path, lang, applicable, unjudged });
  });

  const one = async (worker, { index, file, path, lang, applicable, unjudged }) => {
    const slot = slots[index];
    if (stuck || signal?.aborted || (deadline !== null && Date.now() >= deadline)) {
      timedOut = true;
      slot.notAnalyzed.push({ path, reason: "time_limit" });
      return;
    }
    let text = file.text;
    if (typeof text !== "string") {
      if (file.refused) { slot.notAnalyzed.push({ path, reason: file.refused }); return; } // a renamed file's read refusal
      if (/^\.env/.test(basename(path)) || !root) { slot.notAnalyzed.push({ path, reason: "unreadable" }); return; }
      // Through readWalked, as every other reader: a regular file inside the root, never a symlink or a FIFO, and the
      // open handle the file that was checked.
      const read = await readWalked(root instanceof URL ? fileURLToPath(root) : root, path, maxBytes);
      if (!read.buf) { slot.notAnalyzed.push({ path, reason: read.refused }); return; }
      text = read.buf.toString("utf8");
    }
    if (Buffer.byteLength(text, "utf8") > maxBytes) { slot.notAnalyzed.push({ path, reason: "too_large" }); return; }
    let res;
    try {
      // Near the hard deadline a file gets no more time than is left before it (at least a quarter second).
      const limit = hardDeadline === null ? timeoutMs : Math.max(250, Math.min(timeoutMs, hardDeadline - HARD_RESERVE_MS - Date.now()));
      res = await worker.run({ path, local: file.local ?? path, lang, text, ruleIds: applicable.map((r) => r.id), softMs: Math.floor(limit * 0.8) }, limit, signal);
    } catch (error) {
      if (error?.code === "SETUP_DEADLINE") {
        // The check ran out of time while a worker was starting (or while terminated ones exited): this file and,
        // by the deadline check above, every later one are time_limit. Said apart (setupTimedOut) when no file ran.
        timedOut = true; setupCut = true;
        slot.notAnalyzed.push({ path, reason: "time_limit" });
        return;
      }
      if (error?.code === "THREADS_BUSY") {
        // Earlier terminated workers are still running (stoppingWorkers() at STOPPING_MAX): no new worker starts, so
        // this file and every later one are time_limit, and the run says so (threadsBusy, a local note).
        stuck = true; timedOut = true; busy = true;
        slot.notAnalyzed.push({ path, reason: "time_limit" });
        return;
      }
      if (error?.code === "POOL_STUCK") {
        // Terminated workers outlived the grace limit: no new worker starts. This file and every later one that
        // would have run are time_limit; what was gathered so far is kept.
        stuck = true;
        timedOut = true;
        slot.notAnalyzed.push({ path, reason: "time_limit" });
        return;
      }
      throw coded("worker failed", "WORKER_FAILED");
    }
    ranAny = true;
    for (const m of res.found) ran.add(m.rule_id);
    let reason = null;
    if (res.killed || res.done?.late) reason = "time_limit";
    else if (res.crashed || res.done?.ruleError) reason = "rule_error";
    else if (res.done.parseError) reason = "parse_error";
    else if (res.done.recovered) reason = "parse_error";
    if (reason === "time_limit") timedOut = true;
    if (reason === "rule_error") ruleFailed = true;
    if (reason) {
      // Kept without its handler: in a tree that recovered, or wasn't checked for it, code can sit in the wrong
      // function, so the match is never linked to one.
      slot.matches = res.found.filter(observedOnly).map((m) => ({ ...m, handler: null }));
      slot.notAnalyzed.push({ path, reason });
      if (res.found.length) languages.add(lang);
      return;
    }
    for (const r of applicable) ran.add(r.id);
    slot.matches = res.found;
    languages.add(lang);
    if (unjudged) slot.notAnalyzed.push({ path, reason: "frameworks_unknown" });
    else slot.analyzed = path;
  };
  let next = 0, finished = 0;
  await Promise.all(pool.slice(0, Math.max(1, Math.min(pool.length, jobs.length))).map(async (worker) => {
    while (next < jobs.length) {
      await one(worker, jobs[next++]);
      finished++;
      if (onFile) { try { onFile(finished, jobs.length); } catch { /* progress only */ } }
    }
  }));

  const matches = [], notAnalyzed = [], analyzedPaths = new Set();
  for (const slot of slots) {
    for (const m of slot.matches) matches.push(m); // a loop: spreading a huge array into push() overflows the stack
    for (const e of slot.notAnalyzed) notAnalyzed.push(e);
    if (slot.analyzed !== null) analyzedPaths.add(slot.analyzed);
  }
  const overCap = matches.length > MAX_MATCHES;
  if (overCap) {
    // Over the contract's 20,000: keep what was observed against the code first (violations, items without their
    // control), then the rest, and cut the end. A file that loses any match is no longer analysed (match_limit), so
    // its kept matches never stand for the whole file.
    matches.sort(byPriority);
    for (const m of matches.splice(MAX_MATCHES)) {
      if (analyzedPaths.delete(m.path)) notAnalyzed.push({ path: m.path, reason: "match_limit" });
    }
  }
  matches.sort(byMatch);
  let reason = null;
  if (timedOut) reason = "timeout";
  else if (ruleFailed) reason = "internal_error";
  else if (overCap) reason = "item_limit";
  const status = reason ? "truncated" : (languages.size === 0 ? "empty" : "ok");
  return { matches, links: linksOf(matches, rules), notAnalyzed, analyzed: analyzedPaths.size, analyzedPaths: [...analyzedPaths].sort(),
    languages: [...languages].sort(), status, reason, count: ran.size, ...(setupCut && !ranAny ? { setupTimedOut: true } : {}),
    ...(busy ? { threadsBusy: true } : {}) };
}

/** The order matches are kept in when some must be cut: what was observed against the code first (violations, items
 * without their control), then the rest, each in match order. */
export const byPriority = (a, b) => (observedOnly(a) ? 0 : 1) - (observedOnly(b) ? 0 : 1) || byMatch(a, b);

/* links (rule_bundle.md 3.3): one entry per distinct (handler, table, access) from the matches of rules that declare
 * table, where both are non-null; sorted. Built from the reported matches only, so every pair is on some match. */
export function linksOf(matches, rules) {
  const access = new Map(rules.filter((r) => r.table).map((r) => [r.id, r.table.access]));
  const seen = new Map();
  for (const m of matches) {
    if (!access.has(m.rule_id) || m.handler === null || m.table === null) continue;
    const link = { handler: m.handler, table: m.table, access: access.get(m.rule_id) };
    seen.set(`${link.handler}\n${link.table}\n${link.access}`, link);
  }
  return [...seen.values()].sort((a, b) => cmp(a.handler, b.handler) || cmp(a.table, b.table) || cmp(a.access, b.access));
}

const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
export function byMatch(a, b) {
  return cmp(a.path, b.path) || a.line_start - b.line_start || cmp(a.rule_id, b.rule_id) || a.line_end - b.line_end
    || cmp(a.fingerprint, b.fingerprint);
}

// --- Fixtures --------------------------------------------------------------------------------------------------------

const FIXTURE_KEY = Buffer.alloc(32); // fixtures are code samples; the key only has to be fixed

/* A strict marker line in a language whose line comment is `comment`: groups 1 (ruleid or ok) and 2 (the rule id).
 * readMarkers reads these, and malformedMarkers reports any marker-like line that isn't one. */
function markerPattern(comment) {
  const esc = comment.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`^\\s*${esc}\\s*(ruleid|ok):\\s*(\\S+)\\s*$`);
}

/* A path line in a fixture (`<comment> path: <root-relative path>`): the lines after it, up to the next path line, are
 * run as a file at that path, so a rule with path_regex can be tested in and out of its folders. */
function pathMarkerPattern(comment) {
  const esc = comment.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`^\\s*${esc}\\s*path:\\s*(\\S*)\\s*$`);
}

/* The sections of a fixture: [{path (null: the fixture's own path), lines: [first, last]}], lines from 1, each path
 * line in the section it opens. With no path line, one section over the whole file. */
export function fixtureSections(text, comment) {
  const pathLine = pathMarkerPattern(comment);
  const all = normalizeBreaks(text).split(/\r?\n/); // a lone CR breaks a line, as in the worker
  const out = [{ path: null, lines: [1, all.length] }];
  all.forEach((l, i) => {
    const m = pathLine.exec(l);
    if (!m) return;
    out[out.length - 1].lines[1] = i;
    out.push({ path: m[1], lines: [i + 1, all.length] });
  });
  return out.filter((s) => s.lines[1] >= s.lines[0]);
}

/* Markers in a fixture: [{type: "ruleid"|"ok", id, line (marker line), target (the line it points at)}]. A path line
 * is neither a marker nor a target. */
export function readMarkers(text, comment) {
  const marker = markerPattern(comment);
  const pathLine = pathMarkerPattern(comment);
  const all = normalizeBreaks(text).split(/\r?\n/); // a lone CR breaks a line, as in the worker
  const out = [];
  let pending = [];
  all.forEach((l, i) => {
    const m = marker.exec(l);
    if (m) { pending.push({ type: m[1], id: m[2], line: i + 1 }); return; }
    if (l.trim() === "" || pathLine.test(l)) return;
    for (const p of pending) out.push({ ...p, target: i + 1 });
    pending = [];
  });
  for (const p of pending) out.push({ ...p, target: null });
  return out;
}

/* Lines that look like a marker in any comment style or case but aren't a strict one in this language: a typo there
 * would otherwise turn a recorded case into no check at all. */
export function malformedMarkers(text, comment) {
  const strict = markerPattern(comment);
  const loose = /(?:\/\/|#|--|\/\*|<!--|^\s*\*).*?\b(?:ruleid|ok)\s*:/i;
  const out = [];
  text.split(/\r?\n/).forEach((l, i) => { if (loose.test(l) && !strict.test(l)) out.push(i + 1); });
  return out;
}

/**
 * runFixtures(dir) -> Promise<{passed, failed: [{rule_id, file, line, expected, got}]}>
 * Loads the rule set strictly (a bad rule, or one for a language with no parser here, throws), fails any malformed
 * marker (got: malformed_marker), runs each rule file's rules on its fixture file, and checks
 * every marker: a ruleid needs a match (for items: an item without its control) starting on its line, an ok needs
 * none, and every match must be marked. passed counts the checks that held. A rule set with no fixture file at all
 * throws once (code NO_FIXTURES) instead of failing every rule.
 */
export async function runFixtures(dir = DEFAULT_RULES_DIR) {
  const root = rulesRoot(dir);
  const rules = loadRules(dir, { strict: true });
  const byFile = new Map();
  for (const r of rules) { if (!byFile.has(r.file)) byFile.set(r.file, []); byFile.get(r.file).push(r); }
  const fixtureOf = (ruleFile, lang) => ruleFile.replace(/\.yml$/, `.fixtures.${FIXTURE[lang][0]}`);
  // A rule set with rule files and not one fixture (the bundle this package ships) is said once, not as a failure for
  // every rule. It is still an error: nothing was tested.
  if (byFile.size && ![...byFile].some(([f, rs]) => existsSync(join(root, ...fixtureOf(f, rs[0].language).split("/"))))) {
    throw coded(`no fixtures in this bundle: ${byFile.size} rule files and no .fixtures.* file beside them in ${root}`, "NO_FIXTURES");
  }
  let passed = 0;
  const failed = [];
  const fail = (rule_id, file, line, expected, got) => failed.push({ rule_id, file, line, expected, got });
  for (const [ruleFile, fileRules] of byFile) {
    const lang = fileRules[0].language;
    const comment = FIXTURE[lang][1];
    const fixture = fixtureOf(ruleFile, lang);
    const abs = join(root, ...fixture.split("/"));
    if (!existsSync(abs)) { for (const r of fileRules) fail(r.id, fixture, null, "a fixture file", "none"); continue; }
    const text = readFileSync(abs, "utf8");
    const markers = readMarkers(text, comment);
    for (const line of malformedMarkers(text, comment)) fail(null, fixture, line, `a marker exactly "${comment} ruleid: <id>" or "${comment} ok: <id>"`, "malformed_marker");
    const sections = fixtureSections(text, comment);
    for (const s of sections) if (s.path !== null && !PATH.test(s.path)) fail(null, fixture, s.lines[0], `a path line "${comment} path: <root-relative path>"`, "malformed_path");
    const ids = new Set(fileRules.map((r) => r.id));
    for (const m of markers) {
      if (!ids.has(m.id)) fail(m.id, fixture, m.line, `a rule ${m.id} in ${ruleFile}`, "no such rule");
      else if (m.target === null) fail(m.id, fixture, m.line, "a code line after the marker", "end of file");
    }
    for (const r of fileRules) {
      for (const type of ["ruleid", "ok"]) {
        if (!markers.some((m) => m.id === r.id && m.type === type)) fail(r.id, fixture, null, `at least one ${type} marker`, "none");
      }
    }
    // Every rule in the file runs on its fixture, whatever its frameworks. Each section runs as a file at its path,
    // with every line outside it blank, so lines keep their numbers. A section whose path no rule covers is not run.
    const lines = normalizeBreaks(text).split(/\r?\n/);
    const res = { matches: [] };
    let why = null;
    for (const s of sections) {
      if (s.path !== null && !PATH.test(s.path)) continue;
      const path = s.path ?? toPosix(fixture);
      if (!fileRules.some((r) => ruleCoversPath(r, path))) continue;
      const own = sections.length === 1 ? text : lines.map((l, i) => (i + 1 >= s.lines[0] && i + 1 <= s.lines[1] ? l : "")).join("\n");
      const one = await runRules(fileRules, [{ path, lang, text: own }], { key: FIXTURE_KEY, frameworks: RULE_FRAMEWORKS.filter((f) => f !== "generic") });
      if (one.status === "failed" || one.notAnalyzed.length) { why = one.notAnalyzed[0]?.reason ?? one.reason; break; }
      res.matches.push(...one.matches);
    }
    if (why !== null) {
      for (const r of fileRules) fail(r.id, fixture, null, "the fixture to parse and run cleanly", why);
      continue;
    }
    for (const r of fileRules) {
      // Reported lines: every match start; for items only the items without their control.
      const hits = new Set(res.matches.filter((m) => m.rule_id === r.id && (m.kind !== "item" || m.has_control === false)).map((m) => m.line_start));
      const marked = new Set();
      for (const m of markers.filter((x) => x.id === r.id && x.target !== null)) {
        if (m.type === "ruleid") {
          marked.add(m.target);
          if (hits.has(m.target)) passed++;
          else fail(r.id, fixture, m.target, r.kind === "items" ? "an item without its control" : "a match", "none");
        } else if (hits.has(m.target)) fail(r.id, fixture, m.target, "no match", r.kind === "items" ? "an item without its control" : "a match");
        else passed++;
      }
      for (const line of [...hits].sort((a, b) => a - b)) {
        if (!marked.has(line)) fail(r.id, fixture, line, "no match (no ruleid marker here)", r.kind === "items" ? "an item without its control" : "a match");
      }
    }
  }
  failed.sort((a, b) => cmp(a.file, b.file) || (a.line ?? 0) - (b.line ?? 0) || cmp(a.rule_id, b.rule_id));
  return { passed, failed };
}


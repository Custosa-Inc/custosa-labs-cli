/* Parsing for the inspector's structural rules, on @ast-grep/napi.
 *
 * Languages (rule_bundle.md 3.2): javascript, typescript and tsx are built into @ast-grep/napi. Python, PHP, Java,
 * Kotlin, Go, Ruby, YAML and JSON are registered from their @ast-grep/lang-<name> packages, which carry prebuilt
 * parsers for macOS x64/arm64, Linux x64/arm64 (glibc) and Windows x64. We locate the prebuilt parser.so ourselves
 * instead of loading the package's index.js, so the inspector never loads @ast-grep/setup-lang (its install helper,
 * which can run a build). Every other language, and any of these on a platform with no prebuilt parser, has no parser:
 * its files are not_analyzed with unsupported_language, never skipped silently.
 *
 * runRules parses and matches in a worker thread (rules-worker.mjs) under a hard per-file deadline. parseCode is the
 * parse the main thread uses (factdoc.mjs, locationkind.mjs). */
import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";

const require = createRequire(import.meta.url);

// @ast-grep/napi is loaded on first use, so a platform with no binding gets a reportable error, not a crash at import.
let napiModule = null;
let napiProblem = null;
/** The @ast-grep/napi module, or throws an Error with code ENGINE_UNAVAILABLE. */
export function engine() {
  if (napiModule) return napiModule;
  if (!napiProblem) {
    try { napiModule = require("@ast-grep/napi"); return napiModule; } catch { napiProblem = "engine_unavailable"; }
  }
  const error = new Error("@ast-grep/napi has no binding for this platform");
  error.code = "ENGINE_UNAVAILABLE";
  throw error;
}
export function engineAvailable() { try { engine(); return true; } catch { return false; } }

export const ENGINE_VERSION = (() => { try { return require("@ast-grep/napi/package.json").version; } catch { return "0.0.0"; } })();
export const TIMEOUT_MS = 5000;
export const MAX_BYTES = 2_000_000;

// Built into @ast-grep/napi.
const BUILTIN = Object.freeze({ javascript: "JavaScript", typescript: "TypeScript", tsx: "Tsx" });

/* Every file extension the inspector knows (lowercase, no dot), with its language of enums.LANGUAGES: the one table.
 * A language here with no parser is unsupported_language. The walker (files.mjs, a walked file's `lang`), languageOf
 * here, and the extensions each parser is registered with all read it. (The walker once left out cs, jsonc, toml,
 * tf and hcl, and languageOf left out pyi and rake. Every reader took the walker's language, else languageOf's, so the
 * fact document already had the union.) */
const EXTENSIONS = Object.freeze({
  js: "javascript", mjs: "javascript", cjs: "javascript", jsx: "javascript",
  ts: "typescript", mts: "typescript", cts: "typescript", tsx: "tsx",
  py: "python", pyi: "python", go: "go", java: "java", kt: "kotlin", kts: "kotlin",
  rb: "ruby", rake: "ruby", php: "php", cs: "csharp",
  sql: "sql", yml: "yaml", yaml: "yaml", json: "json", jsonc: "json",
  toml: "toml", tf: "hcl", hcl: "hcl",
  // languages with no grammar, so their files are unsupported_language, never unknown_type. .h is c always
  // (the table is by path only); .gradle is left out, since frameworks.mjs reads a Gradle build script as a manifest.
  swift: "swift", dart: "dart", m: "objc", mm: "objc", rs: "rust", scala: "scala", sc: "scala", ex: "elixir",
  exs: "elixir", vue: "vue", svelte: "svelte", astro: "astro", c: "c", h: "c", cpp: "cpp", cc: "cpp", cxx: "cpp",
  hpp: "cpp", hh: "cpp", hxx: "cpp", lua: "lua", groovy: "groovy", clj: "clojure", cljs: "clojure", cljc: "clojure",
  erl: "erlang", hrl: "erlang", hs: "haskell", lhs: "haskell", fs: "fsharp", fsi: "fsharp", fsx: "fsharp", vb: "vbnet",
});

/** enums.LANGUAGES, in the table's order. */
export const LANGUAGES = Object.freeze([...new Set(Object.values(EXTENSIONS))]);

function extensionOf(path) {
  const base = path.slice(path.lastIndexOf("/") + 1);
  const dot = base.lastIndexOf(".");
  return dot <= 0 ? null : base.slice(dot + 1).toLowerCase();
}

/** The language of a path by its extension (enums.LANGUAGES), or null for a file type with no language. */
export function languageOf(path) {
  const ext = extensionOf(path);
  return ext === null ? null : EXTENSIONS[ext] ?? null;
}

// Registered from @ast-grep/lang-* (exact pins in package.json). symbol and expando are the packages' own values for
// the pinned versions (index.js: languageSymbol, expandoChar), copied here so their index.js is never loaded. The
// extensions each is registered with are languageOf's.
const DYNAMIC = Object.freeze({
  python: { pkg: "@ast-grep/lang-python", symbol: "tree_sitter_python", expando: "µ" },
  php: { pkg: "@ast-grep/lang-php", symbol: "tree_sitter_php", expando: "$" },
  java: { pkg: "@ast-grep/lang-java", symbol: "tree_sitter_java", expando: "$" },
  kotlin: { pkg: "@ast-grep/lang-kotlin", symbol: "tree_sitter_kotlin", expando: "µ" },
  go: { pkg: "@ast-grep/lang-go", symbol: "tree_sitter_go", expando: "µ" },
  ruby: { pkg: "@ast-grep/lang-ruby", symbol: "tree_sitter_ruby", expando: "µ" },
  yaml: { pkg: "@ast-grep/lang-yaml", symbol: "tree_sitter_yaml", expando: "$" },
  json: { pkg: "@ast-grep/lang-json", symbol: "tree_sitter_json", expando: "$" },
});
const extensionsOf = (lang) => Object.keys(EXTENSIONS).filter((ext) => EXTENSIONS[ext] === lang);

const PLATFORM = { darwin: "macOS", linux: "Linux", win32: "Windows" }[process.platform];
const ARCH = { x64: "X64", arm64: "ARM64" }[process.arch];

function isMusl() {
  if (process.platform !== "linux") return false;
  try { return !process.report.getReport().header.glibcVersionRuntime; } catch { return true; }
}

let registry = null; // {available: Set<string>, unavailable: Map<string, string>}

function prebuiltParser(pkg) {
  let dir;
  try { dir = dirname(require.resolve(`${pkg}/package.json`)); } catch { return { problem: `${pkg} is not installed` }; }
  if (PLATFORM && ARCH && !isMusl()) {
    const prebuild = join(dir, "prebuilds", `prebuild-${PLATFORM}-${ARCH}`, "parser.so");
    if (existsSync(prebuild)) return { path: prebuild };
  }
  const local = join(dir, "parser.so"); // built at install time on a platform with no prebuild
  if (existsSync(local)) return { path: local };
  return { problem: `${pkg} has no parser for ${process.platform}-${process.arch}${isMusl() ? " (musl)" : ""}` };
}

function register() {
  if (registry) return registry;
  const unavailable = new Map();
  if (!engineAvailable()) {
    for (const lang of LANGUAGES) unavailable.set(lang, "@ast-grep/napi has no binding for this platform");
    registry = { available: new Set(), unavailable };
    return registry;
  }
  const napi = engine();
  const available = new Set(Object.keys(BUILTIN));
  const langs = {};
  for (const [lang, d] of Object.entries(DYNAMIC)) {
    const found = prebuiltParser(d.pkg);
    if (found.problem) { unavailable.set(lang, found.problem); continue; }
    langs[lang] = { libraryPath: found.path, extensions: extensionsOf(lang), languageSymbol: d.symbol, expandoChar: d.expando };
  }
  try {
    // Called once per process (an @ast-grep/napi rule); a failure leaves only the built-in languages.
    if (Object.keys(langs).length) napi.registerDynamicLanguage(langs);
    for (const lang of Object.keys(langs)) available.add(lang);
  } catch (error) {
    for (const lang of Object.keys(langs)) unavailable.set(lang, `could not load its parser: ${error.message}`);
  }
  for (const lang of LANGUAGES) if (!available.has(lang) && !unavailable.has(lang)) unavailable.set(lang, "no parser in this build");
  registry = { available, unavailable };
  return registry;
}

/** True when this build can parse `lang`. */
export function isSupported(lang) { return register().available.has(lang); }

/** Why `lang` can't be parsed here, or null when it can. */
export function unsupportedReason(lang) {
  const r = register();
  return r.available.has(lang) ? null : (r.unavailable.get(lang) ?? "not a known language");
}

/** The name @ast-grep/napi knows the language by. */
export function napiLang(lang) { return BUILTIN[lang] ?? lang; }

/** The character ast-grep puts in place of `$` before parsing a pattern in this language. */
export function expandoChar(lang) { return DYNAMIC[lang]?.expando ?? "$"; }

/** Parse synchronously (patterns and fixtures; small inputs). */
export function parseSync(lang, text) { register(); return engine().parse(napiLang(lang), text); }

/**
 * True when tree-sitter had to recover: an ERROR node, or a MISSING token (zero width; napi has no isMissing). A
 * recovered tree can put code in the wrong function (a missing `}` lets one handler swallow the next), so its file is
 * parse_error: its violations still count, its evidence and controls don't.
 */
export function recovered(root) {
  if (root.find({ rule: { kind: "ERROR" } }) !== null) return true;
  // Zero-width nodes, found natively (an empty-text regex visits anonymous nodes too); the root of an empty file is
  // the one expected empty node.
  return root.findAll({ rule: { regex: "^$" } }).some((n) => n.range().start.index !== 0 || n.range().end.index !== 0 || n.kind() !== root.kind());
}

/* Two valid constructs the pinned grammars, and every newer release, recover on.
 * - tsx and javascript: a bare `&` in JSX text (`<p>Plan & Services</p>`). The scanner ends jsx_text at `&`, and a `&`
 *   that starts no character reference has no token (tree-sitter-javascript#366).
 * - php: a trailing comma in a group use (`use A\{B, C,};`, PHP 7.2+). namespace_use_group is commaSep1 with no
 *   trailing `,`, so the parser inserts a MISSING namespace_use_clause.
 * A repair finds each site from a node of the recovered tree, never by a search of the whole text (a `&` or `,` in a
 * string or a comment is never a site), and turns its one character into a space, so every offset, line and column is
 * unchanged. The meaning is the same: a JSX child `&` is text either way, and the comma is optional syntax.
 * A recovered parse is still a failure: the repaired text is used only when it parses cleanly. Otherwise the file
 * keeps its first tree and stays recovered (parse_error), and nothing of the repair is used. */

/** The most repair-and-parse rounds for one file (a recovery that climbs past a JSX element can hide a later `&`). */
export const REPAIR_ROUNDS = 8;

const CHARACTER_REFERENCE = /&(?:#(?:[xX][0-9a-fA-F]{1,6}|[0-9]{1,5})|[A-Za-z]{1,30});/y; // the grammar's html_character_reference
const ERROR_RULE = { rule: { kind: "ERROR" } };
const USE_CLAUSE_RULE = { rule: { kind: "namespace_use_clause" } };
const at = (node) => node.range().start.index; // a JavaScript string index (napi counts UTF-16 units)
const zeroWidth = (node) => { const r = node.range(); return r.start.index === r.end.index; };

const bareAmpersand = (text, i) => {
  if (text[i] !== "&") return false;
  CHARACTER_REFERENCE.lastIndex = i;
  return !CHARACTER_REFERENCE.test(text);
};

// The tokens a bare `&` in JSX text is read as once the scanner stops at it (`A && B` gives `&&`, `A &= B` gives `&=`).
const AMPERSAND_TOKENS = new Set(["&", "&&", "&=", "&&="]);

/* Bare `&` at a JSX child position, from the ERROR nodes of a recovered tree. An anchor is a `&` token (or `&&`, `&=`):
 * - the first token of an ERROR that is a child of a jsx_element (between its opening and closing tags);
 * - a token right after jsx_text or a jsx_opening_element inside an ERROR (the recovery climbed: both only come before
 *   a child). After an element or an expression inside an ERROR that has climbed out of the element, the `&` could
 *   be an operator in broken code (`<p>x</p> & ;`), so not. (Inside a jsx_element, after a child element or
 *   expression, the first rule applies: that position is in the element's children.)
 * An anchor starts a run of JSX text, which goes on to the next `<`, `>`, `{` or `}` (the characters jsx_text can't
 * hold besides `&`). Every bare `&` in the run is a site: once the recovery climbs, the rest of the run reads as
 * expressions (`w1 & w2`), so finding them one round at a time would take a round each. */
function jsxAmpersands(root, text, late) {
  const sites = [];
  let seen = 0;
  for (const error of root.findAll(ERROR_RULE)) {
    if (++seen % 256 === 0 && late()) return null; // deeply nested recoveries can hold thousands of ERROR nodes
    const kids = error.children();
    kids.forEach((kid, i) => {
      if (kid.isNamed() || !AMPERSAND_TOKENS.has(kid.kind())) return;
      const inChildren = i === 0 && error.parent()?.kind() === "jsx_element";
      const afterChild = i > 0 && (kids[i - 1].kind() === "jsx_text" || kids[i - 1].kind() === "jsx_opening_element");
      if (!(inChildren || afterChild) || !bareAmpersand(text, at(kid))) return;
      for (let j = at(kid); j < text.length && !"<>{}".includes(text[j]); j++) if (bareAmpersand(text, j)) sites.push(j);
    });
  }
  return sites;
}

/* A real (not zero-width) namespace_use_clause, passing comments over backwards from `node`. */
function clauseBefore(node) {
  let prev = node;
  while (prev && prev.kind() === "comment") prev = prev.prev();
  return prev?.kind() === "namespace_use_clause" && !zeroWidth(prev);
}

/* The trailing `,` of a namespace_use_group. The parser recovers from it in one of two ways:
 * - `{B, C,}`: a MISSING namespace_use_clause between the `,` and the `}`;
 * - `{B,}` (one clause): an ERROR holding only the `,`, between the clause and the `}`.
 * Either way the comma must follow a real clause and be followed by the `}` (comments passed over): `{,}` and
 * `{B,, C}` are errors, not a trailing comma. */
function useGroupCommas(root, text) { // a few nodes per group use: no deadline check inside
  const sites = [];
  for (const clause of root.findAll(USE_CLAUSE_RULE)) {
    if (!zeroWidth(clause) || clause.parent()?.kind() !== "namespace_use_group" || clause.next()?.kind() !== "}") continue;
    let comma = clause.prev();
    while (comma && comma.kind() === "comment") comma = comma.prev();
    if (comma?.kind() !== "," || !clauseBefore(comma.prev())) continue;
    sites.push(at(comma));
  }
  for (const error of root.findAll(ERROR_RULE)) {
    const kids = error.children();
    if (error.parent()?.kind() !== "namespace_use_group" || kids.length !== 1 || kids[0].kind() !== ",") continue;
    let next = error.next();
    while (next && next.kind() === "comment") next = next.next();
    if (next?.kind() !== "}" || !clauseBefore(error.prev())) continue;
    sites.push(at(kids[0]));
  }
  return sites.filter((i) => text[i] === ",");
}

const REPAIRS = Object.freeze({ tsx: jsxAmpersands, javascript: jsxAmpersands, php: useGroupCommas });

/** The repair sites of one round in `root` (the tree of `text`), or null when late() turned true during the search;
 * [] for a language with no repair. Exported for tests (the deadline inside the JSX search). */
export function repairSites(lang, root, text, late = () => false) { return REPAIRS[lang] ? REPAIRS[lang](root, text, late) : []; }

/** True when `lang` has a repair (parseCode). */
export const hasRepair = (lang) => Object.hasOwn(REPAIRS, lang);

/* How long a repair may take on the main thread (the location kinds, the handler map), where no other limit applies. */
export const MAIN_REPAIR_MS = 1000;

/* The main thread's repair budget: MAIN_REPAIR_MS on Date.now. Its fields are a seam for tests only. */
export const mainRepair = { ms: MAIN_REPAIR_MS, clock: Date.now };

/** The {clock, deadline} for a repair on the main thread: mainRepair.ms from now, and never past `until` (epoch ms,
 * optional: the check's own deadline). A caller whose repair runs out of it gets a recovered tree, and treats it as
 * it treats any recovered tree: nothing is confirmed from it (see locationkind.codeKindAt, factdoc.handlerMap). */
export function mainRepairBudget(until = null) {
  const { ms, clock } = mainRepair;
  return { clock, deadline: Math.min(until ?? Infinity, clock() + ms) };
}

/**
 * repairRecovered(lang, text, root, {clock, deadline}) -> {root, text, recovered, repairs}
 * root: the tree of `text`, already known to be recovered. The repair rounds: the repaired root and text when one ends
 * clean, else the given root and text with recovered true and repairs 0.
 * deadline (on clock, default Date.now; null: none): checked before each round, before each parse of a repaired text
 * and during the JSX site search. Past it the repair stops and the file keeps its first tree (recovered: parse_error).
 * A repair can cost many times the parse (deeply nested JSX with `&` at every level), so every caller passes one.
 */
export function repairRecovered(lang, text, root, { clock = Date.now, deadline = null } = {}) {
  const failed = { root, text, recovered: true, repairs: 0 };
  const repair = REPAIRS[lang];
  if (!repair) return failed;
  const late = () => deadline !== null && clock() >= deadline;
  let cur = text, tree = root, repairs = 0;
  for (let round = 0; round < REPAIR_ROUNDS; round++) {
    if (late()) return failed;
    const found = repair(tree, cur, late);
    if (found === null || late()) return failed;
    const sites = [...new Set(found)].sort((a, b) => a - b);
    if (!sites.length) return failed;
    let next = "", from = 0;
    for (const i of sites) { next += `${cur.slice(from, i)} `; from = i + 1; }
    cur = next + cur.slice(from);
    repairs += sites.length;
    tree = parseSync(lang, cur).root();
    if (!recovered(tree)) return { root: tree, text: cur, recovered: false, repairs };
  }
  return failed;
}

/** repairParse(lang, text, root, budget): root, the tree of `text` already parsed, as it is when clean, else
 * repairRecovered (budget: its {clock, deadline}). */
export function repairParse(lang, text, root, budget = {}) {
  return recovered(root) ? repairRecovered(lang, text, root, budget) : { root, text, recovered: false, repairs: 0 };
}

/**
 * parseCode(lang, text) -> {root, text, recovered, repairs}: a file's text parsed as the inspector reads it. root: the
 * root SgNode; text: the text it is the tree of (the repaired text when repairs > 0, the same length as the input);
 * recovered: tree-sitter had to recover (see recovered), so the file is parse_error. budget: repairRecovered's {clock,
 * deadline}. Throws as parseSync does.
 */
export function parseCode(lang, text, budget = {}) { return repairParse(lang, text, parseSync(lang, text).root(), budget); }

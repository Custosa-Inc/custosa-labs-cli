/* Helper modules (fact schema files.helpers): JavaScript, TypeScript and Python modules whose
 * exported functions do elevated or patient-scoped work, with every file that imports them. The core gives a handlers
 * practice's helper that no file holding one of its handlers reaches a needs_review result of its own, so a helper
 * nothing observed calls (plumbing-gaps src/files.ts) is never silent once frameworks turn the practice into
 * per-handler results.
 *
 * Read lexically, with the import scan's text (comments blanked, strings kept), never parsed. A wrong hit only opens a
 * result for a person; a miss is what this guards against, so each test leans to "yes":
 * - work: elevated_client is a createClient/create_client call in a file that names a service-role or secret key (as
 *   the elevated-routes rules read it), the Firebase Admin SDK, or a local import of a module that makes such a client;
 *   storage is a Supabase storage.from(...) or an S3 object command; write is a Supabase .from(...).insert, update,
 *   upsert or delete, a Prisma create, update, upsert or delete, a Django manager write, or SQL INSERT INTO, UPDATE ...
 *   SET or DELETE FROM in a string.
 * - functions: the exported functions by name (export function, export const f = () => ..., export { f }, export
 *   default function, CommonJS exports.f = and module.exports = { f }; Python top-level def without a leading _). A
 *   module with work and no exported function is not a helper.
 * - not helpers: entry files, which the rules judge as handlers or which run on their own (Next.js route, page, layout
 *   and middleware files, the pages router, a 'use server' module of Server Actions, a supabase/functions/<name>/
 *   entry); a 'use client' file, which runs in the browser and is left to the client-side practices; tests, mocks,
 *   migrations, seeds and scripts, which no request reaches.
 * - importers: local specifiers (relative, or @/ and ~/ from the root or src/; Python relative and dotted modules from
 *   the root or src/) resolved to the walked files, then followed backwards: every file that reaches the module through
 *   local imports. A specifier that doesn't resolve reaches nothing, so the helper stays open. */

const SERVICE_KEY = /service_?role|secret_?key|sb_secret_|SUPABASE_SECRET/i;
const JS_ELEVATED_CALL = /(?:^|[^\w$.])createClient\s*(?:<[^>]*>\s*)?\(/;
const PY_ELEVATED_CALL = /(?:^|[^\w.])create_client\s*\(/;
const FIREBASE_ADMIN_JS = /["']firebase-admin(?:\/[a-z-]+)?["']/;
const FIREBASE_ADMIN_PY = /^[ \t]*(?:from|import)[ \t]+firebase_admin\b/m;
const JS_STORAGE = /\bstorage\s*\.\s*from\s*\(|\b(?:Put|Get|Delete|Copy)ObjectCommand\b/;
const PY_STORAGE = /\bstorage\s*\.\s*from_\s*\(|\.(?:put_object|upload_file|upload_fileobj|delete_object)\s*\(/;
const SQL_WRITE = /\b(?:INSERT\s+INTO|UPDATE\s+[\w."]+\s+SET|DELETE\s+FROM)\b/;
// Drizzle: insert(t).values() or .select(), update(t).set() and delete(t).where() or .returning().
const JS_WRITE = /\.from\s*\([^()]*\)\s*\.\s*(?:insert|update|upsert|delete)\s*\(|\bprisma\s*\.\s*\w+\s*\.\s*(?:create|createMany|update|updateMany|upsert|delete|deleteMany)\s*\(|\.\s*(?:insert\s*\([^()]*\)\s*\.\s*(?:values|select)|update\s*\([^()]*\)\s*\.\s*set|delete\s*\([^()]*\)\s*\.\s*(?:where|returning))\s*\(/;
// A bare Drizzle delete(t) deletes every row. On its own it reads like Map.delete(key), so it counts on a db or tx
// receiver, or in a file that imports drizzle-orm. The receiver may end a member chain, as
// NestJS's this.db and tRPC's ctx.db do, and may be read through ?.
//. Both also take an optional call, delete?.(t), and a call by bracket name,
// db["delete"](t).
const JS_DB_DELETE = /(?:^|[^\w$])(?:db|tx|trx|database)\s*(?:\??\.\s*delete|(?:\?\.)?\s*\[\s*(["'`])delete\1\s*\])\s*(?:\?\.\s*)?\(/;
const JS_ANY_DELETE = /(?:\.\s*delete|\[\s*(["'`])delete\1\s*\])\s*(?:\?\.\s*)?\(/;
const DRIZZLE = /["']drizzle-orm(?:\/[\w-]+)*["']/;
// supabase-py's table() and from_(); Django's manager writes, and QuerySet update() and delete() on one line.
const PY_WRITE = /\.(?:table|from_)\s*\([^()]*\)\s*\.\s*(?:insert|update|upsert|delete)\s*\(|\.objects\s*\.\s*(?:create|bulk_create|update|update_or_create|get_or_create)\s*\(/;
const PY_OBJECTS = /\.objects\s*\./g;
const PY_QUERYSET_WRITE = /\.\s*(?:update|delete)\s*\(/;

/** A .objects. with .update( or .delete( later on its line. Each line is searched once from its first .objects., so a
 * long line of them stays linear; a regex gap after each one was quadratic. */
function pyQuerysetWrite(code) {
  let searched = -1;
  PY_OBJECTS.lastIndex = 0;
  for (let m; (m = PY_OBJECTS.exec(code)); ) {
    const from = PY_OBJECTS.lastIndex;
    PY_OBJECTS.lastIndex = m.index + 1;
    if (from <= searched) continue;
    const nl = code.indexOf("\n", from);
    const end = nl === -1 ? code.length : nl;
    // The dot sits on the line; the space after it may run on, as in the regex this replaced.
    const hit = PY_QUERYSET_WRITE.exec(code.slice(from, end + 200));
    if (hit && hit.index < end - from) return true;
    searched = end;
  }
  return false;
}
const USE_CLIENT = /^(?:\s|;)*["']use client["']/;
const USE_SERVER = /^(?:\s|;)*["']use server["']/;
const ENTRY_FILE = new RegExp([
  "(?:^|/)(?:page|layout|route|template|default|loading|error|global-error|not-found|middleware|instrumentation)\\.[cm]?[jt]sx?$",
  "(?:^|/)pages/.+\\.[cm]?[jt]sx?$",
  "(?:^|/)supabase/functions/[^/]+/index\\.[jt]sx?$",
].join("|"));
const NOT_REQUEST_PATH = new RegExp([
  "(?:^|/)(?:__tests__|__mocks__|tests?|spec|e2e|cypress|fixtures|migrations?|seeds?|scripts)/",
  "\\.(?:test|spec|stories)\\.[cm]?[jt]sx?$",
  "(?:^|/)(?:test_[^/]*|[^/]*_test|conftest)\\.py$",
].join("|"));

export const FUNCTIONS_MAX = 50;
export const IMPORTERS_MAX = 1000;
export const HELPERS_MAX = 5000;
export const ELEVATED_IMPORTS_MAX = 500; // files.elevated_imports rows

/** {elevates, work: Set} for one file's comment-blanked text: elevates when the file itself makes an elevated client. */
export function workIn(code, lang) {
  const python = lang === "python";
  const work = new Set();
  const elevates = python
    ? (PY_ELEVATED_CALL.test(code) && SERVICE_KEY.test(code)) || FIREBASE_ADMIN_PY.test(code)
    : (JS_ELEVATED_CALL.test(code) && SERVICE_KEY.test(code)) || FIREBASE_ADMIN_JS.test(code);
  if (elevates) work.add("elevated_client");
  if ((python ? PY_STORAGE : JS_STORAGE).test(code)) work.add("storage");
  const jsWrite = () => JS_WRITE.test(code) || JS_DB_DELETE.test(code) || (JS_ANY_DELETE.test(code) && DRIZZLE.test(code));
  if ((python ? PY_WRITE.test(code) || pyQuerysetWrite(code) : jsWrite()) || SQL_WRITE.test(code)) work.add("write");
  return { elevates, work };
}

const JS_NAME = "[A-Za-z_$][\\w$]*";
// A generic arrow's type parameters, defaults included (<T = string>), never running past an arrow.
const GENERIC = "<(?:[^()=;]|=(?!>)){1,200}>";
const JS_EXPORTS = [
  new RegExp(`(?:^|[^\\w$.])export\\s+(?:default\\s+)?(?:async\\s+)?function\\s*\\*?\\s*(${JS_NAME})`, "g"),
  new RegExp(`(?:^|[^\\w$.])export\\s+(?:const|let|var)\\s+(${JS_NAME})\\s*(?::[^=;]{0,200})?=\\s*(?:async\\b\\s*)?(?:function\\b|(?:${GENERIC}\\s*)?\\([^()]*\\)\\s*(?::[^=;{]{0,100})?=>|${JS_NAME}\\s*=>)`, "g"),
  new RegExp(`(?:^|[^\\w$.])(?:module\\.)?exports\\.(${JS_NAME})\\s*=(?!=)`, "g"),
];
const JS_EXPORT_DEFAULT_ANON = /(?:^|[^\w$.])export\s+default\s+(?:async\s+)?(?:function\s*\*?\s*\(|\([^()]*\)\s*=>)/;
const JS_EXPORT_LIST = /(?:^|[^\w$.])export\s*(?:type\s+)?\{([^}]*)\}(?!\s*from\b)/g;
const CJS_EXPORT_OBJECT = /(?:^|[^\w$.])module\.exports\s*=\s*\{([^}]*)\}/g;
const PY_DEF = /^(?:async[ \t]+)?def[ \t]+([A-Za-z]\w*)[ \t]*\(/gm;

/** The exported functions' names in one file's comment-blanked text, in order of first appearance, without repeats. */
export function exportedFunctions(code, lang) {
  const names = [];
  const add = (n) => { if (n && !names.includes(n)) names.push(n); };
  if (lang === "python") {
    for (const m of code.matchAll(PY_DEF)) add(m[1]);
    return names;
  }
  const found = [];
  for (const re of JS_EXPORTS) for (const m of code.matchAll(re)) found.push([m.index, m[1]]);
  // export { a, b as c } (no from): the local names, when the file declares them as functions.
  for (const re of [JS_EXPORT_LIST, CJS_EXPORT_OBJECT]) {
    for (const m of code.matchAll(re)) {
      for (const part of m[1].split(",")) {
        const [local, alias] = part.trim().replace(/^type\s+/, "").split(/\s+as\s+|\s*:\s*/);
        if (!local || !new RegExp(`^${JS_NAME}$`).test(local)) continue;
        const fn = new RegExp(`(?:^|[^\\w$.])(?:(?:async\\s+)?function\\s*\\*?\\s*${escapeRe(local)}\\b|(?:const|let|var)\\s+${escapeRe(local)}\\s*(?::[^=;]{0,200})?=\\s*(?:async\\b\\s*)?(?:function\\b|(?:${GENERIC}\\s*)?\\([^()]*\\)\\s*(?::[^=;{]{0,100})?=>|${JS_NAME}\\s*=>))`);
        if (fn.test(code)) found.push([m.index, (alias ?? local).trim()]);
      }
    }
  }
  if (JS_EXPORT_DEFAULT_ANON.test(code)) found.push([code.search(JS_EXPORT_DEFAULT_ANON), "default"]);
  found.sort((a, b) => a[0] - b[0]);
  for (const [, n] of found) add(n);
  return names;
}

const escapeRe = (t) => t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const JS_SPECIFIERS = [
  /(?:^|[^\w$.])import\s*(?:type\s+)?(?:[\w$*{}\s,]*?\bfrom\s*)?(["'])([^"'\n]+)\1/g,
  /(?:^|[^\w$.])export\s*(?:type\s+)?(?:\*\s*(?:as\s+[\w$]+\s*)?|\{[^}]*\}\s*)from\s*(["'])([^"'\n]+)\1/g,
  /(?:^|[^\w$.])require\s*\(\s*(["'`])([^"'`\n$]+)\1\s*\)/g,
  /(?:^|[^\w$.])import\s*\(\s*(["'`])([^"'`\n$]+)\1\s*[,)]/g,
];
// A from-import's names: in parentheses across lines (the form black and isort write), or on one line with backslash
// continuations, or a star (group 3). pyNames gives the names as one comma list.
const PY_FROM = /^[ \t]*from[ \t]+(\.*[A-Za-z_][\w.]*|\.+)[ \t]+import[ \t]*(?:\(([^()]*)\)|(\*)|((?:[\w \t,]|\\\r?\n)*))/gm;
const pyNames = (m) => (m[2] ?? m[4] ?? "").replace(/\\?\r?\n/g, " ");
// importlib.import_module or __import__ of a literal string, followed like an import.
const PY_LITERAL_DYNAMIC = /(?:^|[^\w.])(?:importlib\.)?(?:import_module|__import__)\s*\(\s*(["'])([^"'\n]+)\1\s*[,)]/g;
// require( or import( (Python: import_module, __import__) whose first argument is not one literal string; a template
// literal with no ${ is a literal. The reader can't follow these.
export const JS_DYNAMIC = /(?:^|[^\w$.])(?:require|import)\s*\(\s*(?!(?:"[^"\n]*"|'[^'\n]*'|`[^`$]*`)\s*[,)])/g;
export const PY_DYNAMIC = /(?:^|[^\w.])(?:importlib\.)?(?:import_module|__import__)\s*\(\s*(?!(?:"[^"\n]*"|'[^'\n]*')\s*[,)])/g;
const PY_IMPORT = /^[ \t]*import[ \t]+([A-Za-z_][\w.]*(?:[ \t]+as[ \t]+\w+)?(?:[ \t]*,[ \t]*[A-Za-z_][\w.]*(?:[ \t]+as[ \t]+\w+)?)*)/gm;

/** The module specifiers one file's comment-blanked text imports (JS/TS: every static import, re-export, require and
 * literal import(); Python: from-import modules, with each imported name as a possible submodule, and import lines). */
export function specifiersIn(code, lang) {
  const out = [];
  if (lang === "python") {
    for (const m of code.matchAll(PY_FROM)) {
      out.push(m[1]);
      for (const n of pyNames(m).split(",")) {
        const name = n.trim().split(/\s/)[0];
        if (name) out.push(m[1].endsWith(".") ? `${m[1]}${name}` : `${m[1]}.${name}`);
      }
    }
    for (const m of code.matchAll(PY_IMPORT)) for (const mod of m[1].split(",")) out.push(mod.trim().split(/\s/)[0]);
    for (const m of code.matchAll(PY_LITERAL_DYNAMIC)) out.push(m[2]);
    return out;
  }
  for (const re of JS_SPECIFIERS) for (const m of code.matchAll(re)) out.push(m[2]);
  return out;
}

const JS_EXTENSIONS = ["", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts"];
const JS_INDEX = ["/index.ts", "/index.tsx", "/index.js", "/index.jsx", "/index.mjs", "/index.cjs"];

function normalize(parts) {
  const out = [];
  for (const p of parts) {
    if (p === "" || p === ".") continue;
    if (p === "..") { if (!out.length) return null; out.pop(); } else out.push(p);
  }
  return out.join("/");
}

const dirOf = (path) => (path.includes("/") ? path.slice(0, path.lastIndexOf("/")) : "");

/** The walked path a local specifier names, or null (a package, a URL, or nothing walked there). */
export function resolveLocal(spec, from, paths, lang) {
  if (lang === "python") {
    let bases;
    let rest = spec;
    if (spec.startsWith(".")) {
      const dots = spec.match(/^\.+/)[0].length;
      let dir = dirOf(from);
      for (let i = 1; i < dots; i++) dir = dirOf(dir);
      bases = [dir];
      rest = spec.slice(dots);
    } else bases = ["", "src"];
    const tail = rest ? rest.split(".").join("/") : "";
    for (const base of bases) {
      const stem = [base, tail].filter(Boolean).join("/");
      if (!stem) continue;
      for (const cand of [`${stem}.py`, `${stem}/__init__.py`]) if (paths.has(cand)) return cand;
    }
    return null;
  }
  let stems;
  if (spec.startsWith("./") || spec.startsWith("../") || spec === "." || spec === "..") {
    const s = normalize([...dirOf(from).split("/"), ...spec.split("/")]);
    stems = s === null ? [] : [s];
  } else if (/^[@~]\//.test(spec)) stems = [normalize(spec.slice(2).split("/")), normalize(["src", ...spec.slice(2).split("/")])];
  else return null;
  for (const stem of stems) {
    if (stem === null) continue;
    const bare = stem.replace(/\.(?:js|jsx|mjs|cjs)$/, ""); // TS ESM: ./files.js names files.ts
    for (const base of new Set([stem, bare])) {
      for (const ext of [...JS_EXTENSIONS, ...JS_INDEX]) {
        const cand = base ? `${base}${ext}` : ext.slice(1);
        if (cand && paths.has(cand)) return cand;
      }
    }
  }
  return null;
}

/** One read file's summary for helperModules and elevatedImports: {path, lang, elevates, work, specs, functions,
 * bindings, noRequest, dynamic}. code is the file's comment-blanked text; only the summary is kept, so a large walk holds no
 * file text. */
export function summarize(path, lang, code) {
  const { elevates, work } = workIn(code, lang);
  const browser = lang !== "python" && USE_CLIENT.test(code);
  const skip = browser || ENTRY_FILE.test(path) || NOT_REQUEST_PATH.test(path) || (lang !== "python" && USE_SERVER.test(code));
  return { path, lang, elevates, work, specs: specifiersIn(code, lang),
    functions: skip ? [] : exportedFunctions(code, lang).slice(0, FUNCTIONS_MAX),
    bindings: bindingsIn(code, lang), noRequest: browser || NOT_REQUEST_PATH.test(path),
    dynamic: [...code.matchAll(lang === "python" ? PY_DYNAMIC : JS_DYNAMIC)].length };
}

/* The bindings a file imports, each {specs, line}: the specifiers to try in order (a Python from-import's name may be
 * a submodule), and the first line after the import that names one of its local bindings, or null when none is named
 * (a side-effect import, a re-export, an unused binding). Type-only imports are left out: they bind no value. */
const JS_IMPORT_CLAUSE = /(?:^|[^\w$.])import\s+(?!type\s)([\w$*{}\s,]+?)\s*from\s*(["'])([^"'\n]+)\2/g;
const JS_REQUIRE_BIND = /(?:^|[^\w$.])(?:const|let|var)\s+(\{[^}]*\}|[A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?require\s*\(\s*(["'`])([^"'`\n$]+)\2\s*\)/g;
const PY_IMPORT_BIND = /^[ \t]*import[ \t]+([A-Za-z_][\w.]*(?:[ \t]+as[ \t]+\w+)?(?:[ \t]*,[ \t]*[A-Za-z_][\w.]*(?:[ \t]+as[ \t]+\w+)?)*)[ \t]*$/gm;
// A literal import() or require() that no binding form above takes: its row is the call's own line.
const JS_LITERAL_CALL = /(?:^|[^\w$.])(?:require|import)\s*\(\s*(["'`])([^"'`\n$]+)\1\s*[,)]/g;
const lineOf = (code, offset) => { let n = 1; for (let i = code.indexOf("\n"); i >= 0 && i < offset; i = code.indexOf("\n", i + 1)) n++; return n; };
function jsNames(clause) {
  const names = [];
  const braces = clause.match(/\{([^}]*)\}/);
  if (braces) for (const part of braces[1].split(",")) {
    const bits = part.trim().replace(/^type\s+/, "").split(/\s+as\s+|\s*:\s*/);
    const local = (bits[1] ?? bits[0] ?? "").trim();
    if (/^[A-Za-z_$][\w$]*$/.test(local)) names.push(local);
  }
  const rest = clause.replace(/\{[^}]*\}/, "");
  const ns = rest.match(/\*\s*as\s+([A-Za-z_$][\w$]*)/);
  if (ns) names.push(ns[1]);
  const def = rest.replace(/\*\s*as\s+[A-Za-z_$][\w$]*/, "").split(",")[0].trim();
  if (/^[A-Za-z_$][\w$]*$/.test(def)) names.push(def);
  return names;
}
function firstUse(code, from, names) {
  if (!names.length) return null;
  const re = new RegExp(`(?<![\\w$.])(?:${names.map((n) => n.replace(/\$/g, "\\$")).join("|")})(?![\\w$])`, "g");
  re.lastIndex = from;
  const m = re.exec(code);
  return m ? lineOf(code, m.index) : null;
}
// Whether a Python file has code beyond its imports, its docstrings and __all__: only such code can use a name a star
// import binds. A package that re-exports by star import has none.
// Strings and comments go in one left-to-right pass, so a `#` inside a string opens no comment. A comment uses no name.
// An f-string with a brace that is not `{{` holds code, so it counts as a use.
const PY_STRING_OR_COMMENT =
  /(?<!\w)([rRbBuUfF]{0,2})("""[\s\S]*?"""|'''[\s\S]*?'''|"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*')|#[^\n]*/g;
function pyUsesNames(code) {
  const rest = code.replace(PY_FROM, " ").replace(PY_IMPORT, " ").replace(PY_STRING_OR_COMMENT, (_, prefix, body) =>
    /f/i.test(prefix ?? "") && body.replace(/\{\{|\}\}/g, "").includes("{") ? " used " : " ");
  return /\b(?!__all__\b)[A-Za-z_]\w*/.test(rest);
}
export function bindingsIn(code, lang) {
  const out = [];
  if (lang === "python") {
    let used;
    for (const m of code.matchAll(PY_FROM)) {
      // a star import binds names the reader can't list
      if (m[3]) { out.push({ specs: [m[1]], line: null, star: true, used: (used ??= pyUsesNames(code)) }); continue; }
      for (const part of pyNames(m).split(",")) {
        const bits = part.trim().split(/[ \t]+as[ \t]+/);
        const name = bits[0]?.trim(), local = (bits[1] ?? bits[0] ?? "").trim();
        if (!/^[A-Za-z_]\w*$/.test(name ?? "") || !/^[A-Za-z_]\w*$/.test(local)) continue;
        const sub = m[1].endsWith(".") ? `${m[1]}${name}` : `${m[1]}.${name}`;
        out.push({ specs: [sub, m[1]], line: firstUse(code, m.index + m[0].length, [local]) });
      }
    }
    for (const m of code.matchAll(PY_IMPORT_BIND)) {
      for (const part of m[1].split(",")) {
        const bits = part.trim().split(/[ \t]+as[ \t]+/);
        out.push({ specs: [bits[0]], line: firstUse(code, m.index + m[0].length, [bits[1] ?? bits[0].split(".")[0]]) });
      }
    }
    for (const m of code.matchAll(PY_LITERAL_DYNAMIC)) out.push({ specs: [m[2]], line: lineOf(code, m.index + m[0].length) });
    return out;
  }
  for (const m of code.matchAll(JS_IMPORT_CLAUSE)) out.push({ specs: [m[3]], line: firstUse(code, m.index + m[0].length, jsNames(m[1])) });
  const bound = [];
  for (const m of code.matchAll(JS_REQUIRE_BIND)) {
    const names = m[1].startsWith("{") ? jsNames(m[1]) : [m[1]];
    out.push({ specs: [m[3]], line: firstUse(code, m.index + m[0].length, names) });
    bound.push([m.index, m.index + m[0].length]);
  }
  for (const m of code.matchAll(JS_LITERAL_CALL)) {
    if (bound.some(([a, b]) => m.index >= a && m.index < b)) continue;
    out.push({ specs: [m[2]], line: lineOf(code, m.index + m[0].length) });
  }
  return out;
}

/**
 * elevatedImports(summaries) -> {rows: [{path, line, module, depth}], complete} with local paths (
 * files.elevated_imports). A row: a read file (entry files included; tests, mocks, migrations, seeds, scripts and
 * 'use client' files left out) that names a binding it imports from a module reaching, through local imports, a module
 * that makes an elevated client itself (workIn elevates). module is that module; depth 1 when the binding comes from
 * it directly, more through barrels and helpers. One row per (path, module), the nearest depth, then the earliest line.
 * Sorted by path and module, cut at ELEVATED_IMPORTS_MAX (complete false). complete is false too when a request file
 * has an import the reader can't follow, or a star import of a module that reaches such a client.
 */
export function elevatedImports(summaries) {
  const paths = new Set(summaries.map((s) => s.path));
  const byPath = new Map(summaries.map((s) => [s.path, s]));
  const deps = new Map();
  for (const s of summaries) {
    const to = new Set();
    for (const spec of s.specs) { const d = resolveLocal(spec, s.path, paths, s.lang); if (d && d !== s.path) to.add(d); }
    deps.set(s.path, to);
  }
  const reachCache = new Map(); // module -> Map(elevating module -> depth from it, 1 = itself)
  const reach = (start) => {
    if (reachCache.has(start)) return reachCache.get(start);
    const found = new Map(), seen = new Set([start]);
    let level = [start], depth = 1;
    while (level.length) {
      const next = [];
      for (const p of level) {
        if (byPath.get(p)?.elevates && !found.has(p)) found.set(p, depth);
        for (const d of deps.get(p) ?? []) if (!seen.has(d)) { seen.add(d); next.push(d); }
      }
      level = next; depth++;
    }
    reachCache.set(start, found);
    return found;
  };
  const best = new Map(); // "path\0module" -> row
  // A request file with an import the reader can't follow (a non-literal import(), require(), import_module) may reach
  // an elevated client unseen, so the list is never complete then. So may a star import of a module that
  // reaches one.
  let unfollowed = summaries.some((s) => !s.noRequest && s.dynamic > 0);
  for (const s of summaries) {
    if (s.noRequest) continue;
    for (const b of s.bindings ?? []) {
      if (b.line === null && !b.star) continue;
      const target = b.specs.map((spec) => resolveLocal(spec, s.path, paths, s.lang)).find(Boolean);
      if (!target || target === s.path) continue;
      // A star import hides a binding only in a file that may use one; a summary without `used` counts.
      if (b.star) { if (b.used !== false && [...reach(target).keys()].some((m) => m !== s.path)) unfollowed = true; continue; }
      for (const [module, depth] of reach(target)) {
        if (module === s.path) continue;
        const key = `${s.path}\0${module}`, row = { path: s.path, line: b.line, module, depth };
        const had = best.get(key);
        if (!had || depth < had.depth || (depth === had.depth && b.line < had.line)) best.set(key, row);
      }
    }
  }
  const rows = [...best.values()].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : a.module < b.module ? -1 : a.module > b.module ? 1 : 0));
  return { rows: rows.slice(0, ELEVATED_IMPORTS_MAX), complete: rows.length <= ELEVATED_IMPORTS_MAX && !unfollowed };
}

/**
 * helperModules(summaries) -> [{path, language, functions, work, importers, importers_complete}] with local paths,
 * sorted by path, or null past HELPERS_MAX modules (the list is then cut, and is not sent). summaries: summarize() of
 * every read file. The caller sends the paths and names (sentPath, sentIdentifier).
 */
export function helperModules(summaries) {
  const paths = new Set(summaries.map((s) => s.path));
  const info = new Map(); // path -> its summary, with deps: the walked files it imports
  for (const s of summaries) {
    const deps = new Set();
    for (const spec of s.specs) {
      const to = resolveLocal(spec, s.path, paths, s.lang);
      if (to && to !== s.path) deps.add(to);
    }
    info.set(s.path, { ...s, deps });
  }
  const importedBy = new Map(); // path -> its direct importers
  for (const [path, f] of info) for (const d of f.deps) {
    if (!importedBy.has(d)) importedBy.set(d, new Set());
    importedBy.get(d).add(path);
  }
  const out = [];
  for (const [path, f] of [...info].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
    if (!f.functions.length) continue;
    const work = new Set(f.work);
    // A client made elsewhere: a local module this one imports makes an elevated client.
    if (!work.has("elevated_client") && [...f.deps].some((d) => info.get(d)?.elevates)) work.add("elevated_client");
    if (!work.size) continue;
    if (out.length >= HELPERS_MAX) return null;
    // Every file that reaches this one through local imports.
    const seen = new Set();
    const queue = [...(importedBy.get(path) ?? [])];
    while (queue.length) {
      const p = queue.pop();
      if (p === path || seen.has(p)) continue;
      seen.add(p);
      for (const q of importedBy.get(p) ?? []) queue.push(q);
    }
    const importers = [...seen].sort();
    out.push({ path, language: f.lang, functions: f.functions,
      work: ["elevated_client", "storage", "write"].filter((w) => work.has(w)),
      importers: importers.slice(0, IMPORTERS_MAX), importers_complete: importers.length <= IMPORTERS_MAX });
  }
  return out;
}

/* The import scan (fact schema files.imports): which SDK packages the project's JavaScript, TypeScript
 * and Python source imports, with the first path and line for each fingerprint. Evidence only: it adds to
 * files.fingerprints and never takes anything away.
 *
 * scanImports(root, files, {until}) -> {imports: [{fingerprint, package, path, line}], seen: Set<fingerprint>,
 *   frameworks: Set<framework>, dynamic: {language: count}, helpers: [...] | null}
 *   files: [{disk, path, lang, local}], disk the walk's path to read, path the one sent and local (default path) the
 *   walk's own, which helpers resolve imports against. One entry per fingerprint, from
 *   the first file in path order that imports it (lowest line there). Files over 1 MB or unreadable are skipped, and
 *   the scan stops at `until` (epoch ms): a fingerprint it didn't reach is just not listed, never "not used".
 *   frameworks are the ones the manifest tables give the imported packages (files.derived_frameworks), plus
 *   supabase for a supabase/functions/<name>/ or supabase/migrations/ path. dynamic counts, per language, the require()
 *   and import() calls whose argument isn't a literal (files.imports_dynamic): code loaded that way is invisible to the
 *   rules. A language is counted only when every file of it was read, so a skipped file or a scan cut by `until`
 *   leaves its key out, and the core then gives no coverage from a derived framework there.
 *   helpers (helpers.mjs, files.helpers) lists, with local paths, the modules whose exported functions do
 *   elevated work and every file that imports them. null unless every file was read (no skip, no cut by `until`).
 *   elevated (helpers.mjs elevatedImports, files.elevated_imports) lists the files that name a binding
 *   leading to a module that makes an elevated client, with the same null rule.
 *
 * Read lexically, not parsed: comments are blanked first (string and template text is kept, since the specifiers live
 * there), then static imports and re-exports, require() and import() of a literal, and Python import and from-import
 * lines (triple-quoted strings blanked too) are matched. Specifiers are normalised to their package name (packageOf)
 * and matched through the manifest SDK tables (frameworks.mjs). A wrong presence only keeps an item open. */
import { readWalked } from "./walkread.mjs";
import { FINGERPRINTS, frameworksOf, sdkFingerprints } from "./frameworks.mjs";
import { normalizeBreaks } from "./rules-worker.mjs";
import { elevatedImports, helperModules, summarize, JS_DYNAMIC, PY_DYNAMIC } from "./helpers.mjs";

const MAX_BYTES = 1_000_000;
const JS_LANGS = new Set(["javascript", "typescript", "tsx"]);
// The fact schema's files.imports[].package.
export const PACKAGE_PATTERN = "^(@[A-Za-z0-9][A-Za-z0-9._~-]*/)?[A-Za-z0-9][A-Za-z0-9._~-]*$";
const PACKAGE = new RegExp(PACKAGE_PATTERN);
const PACKAGE_MAX = 214;
// npm CDNs whose path starts with the package (Deno and the browser import from these).
const CDN = /^https?:\/\/(?:esm\.sh|cdn\.jsdelivr\.net\/npm|unpkg\.com|cdn\.skypack\.dev)\/(?:(?:v\d+|stable)\/)?(.+)$/;

/** A JS or TS import specifier's package name, or null for a relative path, a built-in or a URL that isn't an npm CDN.
 * `next/server` gives next, `@a/b/c` gives @a/b, `npm:openai@4` and `jsr:@std/path@1` drop the prefix and version, and
 * `https://esm.sh/openai@4?target=deno` gives openai. */
export function packageOf(spec) {
  let s = spec.trim();
  const cdn = CDN.exec(s);
  if (cdn) s = cdn[1];
  else if (/^(npm|jsr):/.test(s)) s = s.slice(4).replace(/^\/+/, "");
  else if (/^[.#/]|^[a-z][a-z0-9+.-]*:/i.test(s)) return null;
  s = s.split(/[?#]/)[0];
  const parts = s.split("/");
  const scoped = parts[0].startsWith("@");
  if (scoped && parts.length < 2) return null;
  const name = (scoped ? parts[1] : parts[0]).replace(/(.)@.*$/, "$1");
  const pkg = scoped ? `${parts[0]}/${name}` : name;
  return pkg.length <= PACKAGE_MAX && PACKAGE.test(pkg) ? pkg : null;
}

/** A Python module's package as the SDK table names it: the shortest dotted prefix, with dots and underscores read as
 * dashes and lowercased, that the table knows (google.cloud.firestore gives google-cloud-firestore, firebase_admin
 * gives firebase-admin). null when no prefix is in the table. */
export function pythonPackageOf(module) {
  const segs = module.split(".");
  for (let k = 1; k <= segs.length; k++) {
    const name = segs.slice(0, k).join("-").toLowerCase().replaceAll("_", "-");
    if (sdkFingerprints("python", name).length) return name.length <= PACKAGE_MAX && PACKAGE.test(name) ? name : null;
  }
  return null;
}

/* vector-store modules inside a package the SDK tables know by a shorter name (an AI framework's store
 * integrations, the Python weaviate module of weaviate-client). For these the longest matching prefix decides, and the
 * hit is added beside the package's own: [ecosystem, module pattern, package, fingerprints (null: the package's, from
 * the tables)]. A module the patterns don't name (langchain_community.chat_models) is only its package. */
const STORE_MODULES = [
  ["python", /^llama_index\.vector_stores\.([a-z][a-z0-9_]*)(?:\.|$)/, (m) => `llama-index-vector-stores-${m[1].replaceAll("_", "-")}`, null],
  ["python", /^llama_index\.vector_stores$/, () => "llama-index", ["vector_store_sdk"]],
  ["python", /^langchain_community\.vectorstores(?:\.|$)/, () => "langchain-community", ["vector_store_sdk"]],
  ["python", /^langchain\.vectorstores(?:\.|$)/, () => "langchain", ["vector_store_sdk"]],
  ["python", /^weaviate(?:\.|$)/, () => "weaviate-client", null],
  ["npm", /^@langchain\/community\/vectorstores\//, () => "@langchain/community", ["vector_store_sdk"]],
  ["npm", /^langchain\/vectorstores\//, () => "langchain", ["vector_store_sdk"]],
];

/** The store package of a Python module or JS specifier (STORE_MODULES, longest match), as {package, fingerprints},
 * or null. */
export function storeModuleOf(ecosystem, module) {
  let best = null;
  for (const [eco, re, pkg, fps] of STORE_MODULES) {
    const m = eco === ecosystem ? re.exec(module) : null;
    if (m && (best === null || m[0].length > best.len)) best = { len: m[0].length, package: pkg(m), fingerprints: fps };
  }
  if (best === null || best.package.length > PACKAGE_MAX || !PACKAGE.test(best.package)) return null;
  return { package: best.package, fingerprints: best.fingerprints ?? sdkFingerprints(ecosystem, best.package) };
}

/* The text with every comment's characters (not its line breaks) replaced by spaces, so offsets and lines are kept.
 * Quoted strings end at their quote or the line's end; JS template literals at their backtick. Python triple-quoted
 * strings are blanked too: they hold docstrings, not code. */
export function blankComments(text, python) {
  const out = [];
  let i = 0, from = 0;
  const n = text.length;
  const blank = (end) => { out.push(text.slice(from, i), text.slice(i, end).replace(/[^\n]/g, " ")); i = from = end; };
  while (i < n) {
    const c = text[i];
    if (python && c === "#") blank(text.indexOf("\n", i) < 0 ? n : text.indexOf("\n", i));
    else if (python && (text.startsWith('"""', i) || text.startsWith("'''", i))) {
      const close = text.indexOf(text.slice(i, i + 3), i + 3);
      blank(close < 0 ? n : close + 3);
    } else if (!python && c === "/" && text[i + 1] === "/") blank(text.indexOf("\n", i) < 0 ? n : text.indexOf("\n", i));
    else if (!python && c === "/" && text[i + 1] === "*") {
      const close = text.indexOf("*/", i + 2);
      blank(close < 0 ? n : close + 2);
    } else if (c === '"' || c === "'" || (!python && c === "`")) {
      let j = i + 1;
      while (j < n && text[j] !== c && (c === "`" || text[j] !== "\n")) j += text[j] === "\\" ? 2 : 1;
      i = Math.min(n, j + 1);
    } else i++;
  }
  out.push(text.slice(from));
  return out.join("");
}

const JS_FORMS = [
  /(?:^|[^\w$.])import\s*(?:type\s+)?(?:[\w$*{}\s,]*?\bfrom\s*)?(["'])([^"'\n]+)\1/g,
  /(?:^|[^\w$.])export\s*(?:type\s+)?(?:\*\s*(?:as\s+[\w$]+\s*)?|\{[^}]*\}\s*)from\s*(["'])([^"'\n]+)\1/g,
  /(?:^|[^\w$.])require\s*\(\s*(["'`])([^"'`\n$]+)\1\s*\)/g,
  /(?:^|[^\w$.])import\s*\(\s*(["'`])([^"'`\n$]+)\1\s*[,)]/g,
];
const PY_FORMS = [
  /^[ \t]*from[ \t]+([A-Za-z_][\w.]*)[ \t]+import[ \t]*\(?([\w \t,]*)/gm,
  /^[ \t]*import[ \t]+([A-Za-z_][\w.]*(?:[ \t]+as[ \t]+\w+)?(?:[ \t]*,[ \t]*[A-Za-z_][\w.]*(?:[ \t]+as[ \t]+\w+)?)*)/gm,
  /(?:^|[^\w.])(?:importlib\.)?import_module\(\s*["']([A-Za-z_][\w.]*)["']\s*\)/g,
];

/* [{package, fingerprints, frameworks, offset}] for every import in one file's text whose package an SDK or framework
 * table knows, in offset order. */
export function importsIn(text, lang) {
  const python = lang === "python";
  const code = blankComments(text, python);
  const found = [];
  const add = (pkg, offset, eco) => {
    if (!pkg) return;
    const fps = sdkFingerprints(eco, pkg);
    const fws = frameworksOf(eco, pkg);
    if (fps.length || fws.length) found.push({ package: pkg, fingerprints: fps, frameworks: fws, offset });
  };
  // a store module (STORE_MODULES) also counts as its store package, beside the package it belongs to
  const addStore = (modules, offset, eco) => {
    const hit = modules.map((mod) => storeModuleOf(eco, mod)).find(Boolean);
    if (hit && hit.fingerprints.length) found.push({ package: hit.package, fingerprints: hit.fingerprints, frameworks: [], offset });
  };
  // A match may start with the character before its keyword (a line break, for one): the offset is the keyword's.
  const at = (m) => m.index + (/^[\w$ \t]/.test(m[0]) ? 0 : 1);
  if (python) {
    const [fromForm, ...rest] = PY_FORMS;
    for (const m of code.matchAll(fromForm)) {
      // from google.cloud import firestore: the module alone is often no package the table knows; module.name may be.
      const pkg = pythonPackageOf(m[1]) ?? m[2].split(",").map((n) => n.trim().split(/\s/)[0]).filter(Boolean)
        .map((n) => pythonPackageOf(`${m[1]}.${n}`)).find(Boolean) ?? null;
      add(pkg ?? topPackageOf(m[1]), at(m), "python");
      const names = m[2].split(",").map((n) => n.trim().split(/\s/)[0]).filter(Boolean);
      addStore([m[1], ...names.map((n) => `${m[1]}.${n}`)], at(m), "python");
    }
    for (const re of rest) {
      for (const m of code.matchAll(re)) {
        for (const mod of m[1].split(",")) {
          const name = mod.trim().split(/\s/)[0];
          add(pythonPackageOf(name) ?? topPackageOf(name), at(m), "python");
          addStore([name], at(m), "python");
        }
      }
    }
  } else {
    for (const re of JS_FORMS) {
      for (const m of code.matchAll(re)) {
        add(packageOf(m[2]), at(m), "npm");
        addStore([m[2].trim()], at(m), "npm");
      }
    }
  }
  return found.sort((a, b) => a.offset - b.offset);
}

// A Python module's top-level package as the framework table names it (firebase_admin.auth gives firebase-admin).
const topPackageOf = (module) => module.split(".")[0].toLowerCase().replaceAll("_", "-");

/** The number of require()/import() calls (Python: import_module, __import__) in one file's text whose argument is not
 * a literal string; comments don't count. */
export function dynamicImportsIn(text, lang) {
  const python = lang === "python";
  return [...blankComments(text, python).matchAll(python ? PY_DYNAMIC : JS_DYNAMIC)].length;
}

// A folder whose presence says the project uses Supabase (design v3 2.3.2), at the root or in a package.
const SUPABASE_PATH = /(?:^|\/)supabase\/(?:functions\/[^/]+\/|migrations\/)/;

const lineAt = (text, offset) => {
  let line = 1;
  for (let i = text.indexOf("\n"); i >= 0 && i < offset; i = text.indexOf("\n", i + 1)) line++;
  return line;
};

export async function scanImports(root, files, { until = null } = {}) {
  const first = new Map(); // fingerprint -> its entry
  const frameworks = new Set(files.some((f) => SUPABASE_PATH.test(f.path)) ? ["supabase"] : []);
  const counts = new Map(); // language -> its dynamic imports, while every file of it has been read
  const unread = new Set(); // languages with a file the scan didn't read
  const summaries = []; // helpers.mjs summarize(), one per read file
  const ordered = files.filter((f) => JS_LANGS.has(f.lang) || f.lang === "python")
    .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  for (const [i, f] of ordered.entries()) {
    if (until !== null && Date.now() >= until) { for (const g of ordered.slice(i)) unread.add(g.lang); break; }
    const read = await readWalked(root, f.disk, MAX_BYTES);
    if (!read.buf) { unread.add(f.lang); continue; }
    const text = normalizeBreaks(read.buf.toString("utf8"));
    for (const hit of importsIn(text, f.lang)) {
      for (const fw of hit.frameworks) frameworks.add(fw);
      for (const fp of hit.fingerprints) {
        if (!first.has(fp)) first.set(fp, { fingerprint: fp, package: hit.package, path: f.path, line: lineAt(text, hit.offset) });
      }
    }
    counts.set(f.lang, (counts.get(f.lang) ?? 0) + dynamicImportsIn(text, f.lang));
    summaries.push(summarize(f.local ?? f.path, f.lang, blankComments(text, f.lang === "python")));
  }
  const dynamic = Object.fromEntries([...counts].filter(([lang]) => !unread.has(lang)).sort(([a], [b]) => (a < b ? -1 : 1)));
  return { imports: FINGERPRINTS.filter((fp) => first.has(fp)).map((fp) => first.get(fp)), seen: new Set(first.keys()),
    frameworks, dynamic, helpers: unread.size ? null : helperModules(summaries),
    elevated: unread.size ? null : elevatedImports(summaries) }; // absent unless every file was read
}

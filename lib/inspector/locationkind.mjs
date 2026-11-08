/* Whether an answer's confirmed location is the construct its question expects (response question.expects, the E3
 * location kind the evaluator issued), so the answer is sent with that kind (E3) instead of "other" (E4).
 *
 * kindAt(kind, {path, lang, text, start, end, key}) -> boolean
 *   true only when this module can see such a construct where the location starts. A wrong yes would grade an
 *   unproven answer E3, so every test is strict and anything else is false (the caller sends "other"):
 *   - function: a function node that starts on the location's start line (its name, def, function or arrow
 *     parameters), with the range ending inside it; never a body line;
 *   - method: the same, for a method node with a body (not a signature, an abstract declaration or a reference);
 *   - route_handler: such a function that is registered as a route: a call on a router receiver with a "/" path
 *     literal (captures.mjs's own route naming), or an HTTP-verb export of a Next.js route file;
 *   - class, call: a node of that kind starting on the location's start line; decorator: the grammar's own
 *     decorator or annotation node (never a type annotation), on that line too;
 *   - migration: under a folder named exactly migrations or migrate (db/migrate), never a test or fixtures path, and
 *     named the way a migration framework names one (a numbered or timestamped file, Flyway's V1__x.sql, Alembic's
 *     revision, Prisma's <timestamp>_x/migration.sql), or a Liquibase changelog that says databaseChangeLog;
 *   - sql_statement: a .sql file whose lines hold SQL once -- and block comments are removed;
 *   - config_key: a key node starting on the location's start line in a config file's parse tree (YAML and JSON
 *     through the yaml package; TOML, INI and .properties through a line reader that tracks strings, arrays and
 *     continuations), so array elements, scalar continuations and block scalars are never keys; not in test data.
 *   middleware and other are never confirmed. Nothing leaves this module but the boolean. */
import { FUNCTION_KINDS, Handlers } from "./captures.mjs";
import { mainRepairBudget, parseCode } from "./parse.mjs";
import { parseAllDocuments, visit } from "yaml";

// A folder named exactly migrations, migrate (db/migrate included); never under a test or fixtures folder.
const MIGRATION_DIR = /(?:^|\/)(?:migrations|migrate)\//;
const TEST_PATH = /(?:^|\/)(?:test|tests|__tests__|fixtures?|spec|specs)\//i;
const MIGRATION_FILE = [
  /^\d{3,}[_-][\w.-]+\.(?:sql|js|cjs|mjs|ts|py|rb)$/, // 20240101_init.sql, knex 2024..._x.js, Django 0001_x.py, Rails
  /^V\d+(?:[._]\d+)*__[\w.-]+\.sql$/, // Flyway
  /^[0-9a-f]{6,}_[\w.-]+\.py$/, // Alembic <revision>_x.py (migrations/versions/)
];
// Prisma and others: <folder named with a timestamp>/migration.sql (or up.sql / down.sql).
const MIGRATION_FOLDER_FILE = /(?:^|\/)\d{3,}[_-][\w.-]+\/(?:migration|up|down)\.sql$/;
const LIQUIBASE = /^(?:db\.)?changelog[\w.-]*\.(?:xml|ya?ml|json|sql)$/i;
export const CONFIG_MAX_BYTES = 256 * 1024;
export const YAML_MAX_BYTES = 32 * 1024;
const CONFIG_EXT = /\.(?:json|jsonc|ya?ml|toml|ini|cfg|conf|properties)$/i;
const HTTP = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "ALL", "ANY", "DEL"]);
const ROUTE_NAME = /^(\S+) ([A-Z]+) (\/\S*)$/;
const ROUTER_RECEIVER = /(?:^|\.)(?:[A-Za-z_$]*(?:router|routes|app|server|api)|r|e|g|mux|bp|blueprint|route|Route|fastify|hono|engine|group)$/i;
const NEXT_ROUTE_FILE = /(?:^|\/)(?:app\/(?:.*\/)?route|pages\/api\/.+)\.(?:js|jsx|ts|tsx|mjs)$/;
const DECORATORS = {
  javascript: ["decorator"], typescript: ["decorator"], tsx: ["decorator"], python: ["decorator"],
  java: ["annotation", "marker_annotation"], kotlin: ["annotation"], php: ["attribute_group", "attribute"],
};
const isMethodKind = (k) => /method/.test(k) && !/invocation|call|signature|reference|spec/.test(k);
const CLASS_KINDS = /^class(?:_declaration|_definition|_specifier)?$/;
const CALL_KINDS = /^(?:call|call_expression|method_invocation|invocation_expression|function_call_expression|member_call_expression|scoped_call_expression|method_call)$/;

/* Nodes starting on lines [start, end] (1-based), walked from the root, bounded. */
function nodesStarting(root, start, end) {
  const out = [];
  const stack = [root];
  let steps = 0;
  while (stack.length && steps++ < 200_000) {
    const n = stack.pop();
    const r = n.range();
    if (r.end.line + 1 < start || r.start.line + 1 > end) continue;
    if (r.start.line + 1 >= start) out.push(n);
    for (const c of n.children()) stack.push(c);
  }
  return out;
}

/* A function node that starts on the location's start line (where its name, def, function or arrow parameters are),
 * with the location's end inside it. Never a body line, even one its header shares nothing with (a Python block, an
 * expression-bodied arrow): conservative, since a wrong kind grades an answer E3. */
function headerHolds(node, start, end) {
  const r = node.range();
  // The line its name is on when it has one (a Java method's annotations and modifiers come first), else its start.
  const name = node.field("name");
  const first = (name ? name.range() : r).start.line + 1;
  return first === start && end <= r.end.line + 1;
}

/* The offset each line starts at, built once per file; a key's line is found by binary search. */
function lineStarts(text) {
  const starts = [0];
  for (let i = text.indexOf("\n"); i !== -1; i = text.indexOf("\n", i + 1)) starts.push(i + 1);
  return starts;
}
function lineAt(starts, offset) {
  let lo = 0, hi = starts.length - 1;
  while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (starts[mid] <= offset) lo = mid; else hi = mid - 1; }
  return lo + 1;
}

function yamlKeyLines(text) {
  const out = new Set();
  const starts = lineStarts(text);
  for (const doc of parseAllDocuments(text)) {
    if (!doc || doc.errors?.length) return new Set();
    visit(doc, { Pair(_, pair) { const r = pair.key?.range; if (Array.isArray(r)) out.add(lineAt(starts, r[0])); } });
  }
  return out;
}

const TOML_KEY = /^\s*(?:[A-Za-z0-9_-]+|"[^"\n]*"|'[^'\n]*')(?:\s*\.\s*(?:[A-Za-z0-9_-]+|"[^"\n]*"|'[^'\n]*'))*\s*=/;
const INI_KEY = /^\s*[A-Za-z0-9_.$-]+\s*[=:]/;
const TRIPLES = ['"""', "'''"];

function tomlKeyLines(text) {
  const out = new Set();
  let depth = 0, triple = null;
  text.split("\n").forEach((line, i) => {
    const trimmed = line.trim();
    if (depth === 0 && triple === null && !trimmed.startsWith("#") && !trimmed.startsWith("[") && TOML_KEY.test(line)) out.add(i + 1);
    // What this line opens or closes: strings first, then brackets outside them (a [table] header opens nothing).
    const header = depth === 0 && triple === null && trimmed.startsWith("[");
    for (let j = 0; j < line.length; j++) {
      const rest = line.slice(j);
      if (triple) {
        if (triple === '"""' && line[j] === "\\") { j++; continue; } // an escape in a basic string: \""" doesn't close it
        if (rest.startsWith(triple)) { j += 2; triple = null; }
        continue;
      }
      const t = TRIPLES.find((x) => rest.startsWith(x));
      if (t) { triple = t; j += 2; continue; }
      const c = line[j];
      if (c === "#") break;
      if (c === '"' || c === "'") { const end = line.indexOf(c, j + 1); if (end < 0) break; j = end; continue; }
      if (header) continue;
      if (c === "[") depth++;
      else if (c === "]" && depth > 0) depth--;
    }
  });
  return out;
}

function iniKeyLines(text) {
  const out = new Set();
  let continued = false;
  text.split("\n").forEach((line, i) => {
    const trimmed = line.trim();
    const comment = /^[#;!]/.test(trimmed);
    if (!continued && !comment && !trimmed.startsWith("[") && INI_KEY.test(line)) out.add(i + 1);
    continued = !comment && /\\$/.test(line); // a trailing backslash continues the value (.properties)
  });
  return out;
}

/* JSON and JSONC keys in one linear, string-aware pass: string contents are skipped (escapes respected), // and
 * block comments outside strings are skipped, trailing commas and a leading byte-order mark are tolerated, and a
 * string token followed by a colon directly inside an object is a key (recorded at the line it starts on). Anything
 * unbalanced (an unclosed string, comment or bracket, a mismatched bracket) gives no keys, so the answer goes as other.
 * tsconfig.json, devcontainer.json and .vscode/settings.json carry comments and trailing commas, so .json is read the
 * same way. */
function jsonKeyLines(input) {
  const none = new Set();
  const text = input.charCodeAt(0) === 0xfeff ? input.slice(1) : input;
  const out = new Set();
  const stack = [];
  // prev: the last token's class, to refuse what JSON doesn't allow (a doubled comma, a value with no comma before
  // it) while tolerating a trailing comma: "start", "open", "colon", "comma" or "value".
  let line = 1, pending = 0, prev = "start";
  const valueMayStart = () => prev === "start" || prev === "open" || prev === "colon" || prev === "comma";
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === "\n") { line++; continue; }
    if (c === " " || c === "\t" || c === "\r") continue;
    if (c === "/" && text[i + 1] === "/") { // a line comment: to the end of the line
      const nl = text.indexOf("\n", i);
      if (nl === -1) break;
      i = nl - 1;
      continue;
    }
    if (c === "/" && text[i + 1] === "*") { // a block comment: to its end, or no keys at all
      const close = text.indexOf("*/", i + 2);
      if (close === -1) return none;
      for (let k = i; k < close; k++) if (text.charCodeAt(k) === 10) line++;
      i = close + 1;
      continue;
    }
    if (c === ":") {
      if (!pending || stack[stack.length - 1] !== "{") return none;
      out.add(pending);
      pending = 0; prev = "colon";
      continue;
    }
    pending = 0;
    if (c === ",") { if (prev !== "value") return none; prev = "comma"; continue; }
    if (c === '"') {
      if (!valueMayStart()) return none;
      // Only a string that opens an object member can be a key: one right after `{` or a comma inside an object.
      const keyPlace = (prev === "open" || prev === "comma") && stack[stack.length - 1] === "{";
      const startLine = line;
      let j = i + 1;
      for (; j < text.length; j++) {
        const d = text[j];
        if (d === "\\") { if (text[j + 1] === "\n") return none; j++; continue; } // an escaped newline still ends the line
        if (d === '"') break;
        if (d === "\n") return none; // JSON strings don't span lines
      }
      if (j >= text.length) return none;
      i = j;
      pending = keyPlace ? startLine : 0; prev = "value";
      continue;
    }
    if (c === "{" || c === "[") { if (!valueMayStart()) return none; stack.push(c); prev = "open"; continue; }
    if (c === "}" || c === "]") {
      if (prev === "colon" || stack.pop() !== (c === "}" ? "{" : "[")) return none;
      prev = "value";
      continue;
    }
    // A number, true, false or null.
    let j = i;
    while (j < text.length && /[A-Za-z0-9.+-]/.test(text[j])) j++;
    const word = text.slice(i, j);
    if (!valueMayStart() || !/^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)$/.test(word)) return none;
    i = j - 1; prev = "value";
  }
  return stack.length === 0 ? out : none;
}

/* The 1-based lines a key starts on, from a parse tree: YAML and JSON (a YAML 1.2 superset) through the yaml package's
 * documents (each Pair's key node); TOML, INI, .properties, .cfg and .conf through a line reader that tracks
 * multi-line strings, arrays and continuations, and skips comments and [table] headers. Anything that doesn't parse
 * gives no keys. */
function configKeyLines(path, text) {
  if (/\.jsonc?$/i.test(path)) return jsonKeyLines(text);
  if (/\.ya?ml$/i.test(path)) return yamlKeyLines(text);
  if (/\.toml$/i.test(path)) return tomlKeyLines(text);
  return iniKeyLines(text);
}

/* A migration file: under a migrations or migrate folder, never a test path, named as a framework names one, or a
 * Liquibase changelog that says so in its first lines. */
function isMigration(path, text) {
  const base = path.slice(path.lastIndexOf("/") + 1);
  if (path.split("/").some((seg) => seg === ".." || seg === ".") || TEST_PATH.test(path) || !MIGRATION_DIR.test(path)
    || /\.(?:test|spec)\./i.test(base)) return false;
  if (MIGRATION_FILE.some((re) => re.test(base)) || MIGRATION_FOLDER_FILE.test(path)) return true;
  return LIQUIBASE.test(base) && /databaseChangeLog/.test(text.split("\n").slice(0, 20).join("\n"));
}

/* A .sql file whose lines start..end hold SQL once comments are removed. */
function holdsSql(path, text, start, end) {
  if (!/\.sql$/i.test(path)) return false;
  const all = text.split("\n");
  const before = all.slice(0, start - 1).join("\n").replace(/\/\*[\s\S]*?\*\//g, "");
  const inComment = before.lastIndexOf("/*") > -1; // the range starts inside an unclosed block comment
  let part = all.slice(start - 1, end).join("\n");
  if (inComment) part = part.replace(/^[\s\S]*?\*\//, "");
  part = part.replace(/\/\*[\s\S]*?(?:\*\/|$)/g, "").replace(/--[^\n]*/g, "");
  return /[A-Za-z]/.test(part);
}

/* A config file key starting on the start line, by the parse tree. Over the cap a config file isn't parsed for this
 * (a big locale JSON): the answer is sent as other. YAML's parser is the slow one, so its cap is lower. */
function configKeyAt(path, text, start) {
  if (text.length > (/\.ya?ml$/i.test(path) ? YAML_MAX_BYTES : CONFIG_MAX_BYTES)) return false;
  if (!CONFIG_EXT.test(path) || TEST_PATH.test(path) || /(?:^|\/)(?:package-lock|composer\.lock)\.json$/.test(path)) return false;
  return configKeyLines(path, text).has(start);
}

/* A function, method, route handler, class, call or decorator, from the file's syntax tree. */
function codeKindAt(kind, { path, lang, text, start, end, key }) {
  if (!lang || !["function", "method", "class", "call", "decorator", "route_handler"].includes(kind)) return false;
  // the tree the rules read (a repaired one, when it parses cleanly), with the repair bounded on this thread. A
  // tree that is still recovered (the file is parse_error, or its repair ran out of time here) confirms nothing: the
  // answer is not confirmed (other), never one read from a recovered tree, so it can't depend on this machine's speed.
  const { root, recovered } = parseCode(lang, text, mainRepairBudget());
  if (recovered) return false;
  const fnKinds = FUNCTION_KINDS[lang] ?? new Set();
  if (kind === "function" || kind === "method" || kind === "route_handler") {
    const h = new Handlers(root, lang, path, key);
    h.load();
    const here = h.fns.map((f, i) => [f, i]).filter(([f]) => headerHolds(f.node, start, end));
    if (kind === "function") return here.some(([f]) => fnKinds.has(f.node.kind()) && !isMethodKind(f.node.kind()));
    if (kind === "method") return here.some(([f]) => isMethodKind(f.node.kind()));
    return here.some(([, i]) => {
      const id = h.identity(i);
      if (!id) return false;
      const m = ROUTE_NAME.exec(id.name);
      if (m) return HTTP.has(m[2]) && ROUTER_RECEIVER.test(m[1]);
      return HTTP.has(id.name) && NEXT_ROUTE_FILE.test(path);
    });
  }
  // A class, call or decorator must start on the location's start line itself.
  const nodes = nodesStarting(root, start, start);
  if (kind === "class") return nodes.some((n) => CLASS_KINDS.test(n.kind()));
  if (kind === "call") return nodes.some((n) => CALL_KINDS.test(n.kind()));
  const decorators = DECORATORS[lang] ?? [];
  return nodes.some((n) => decorators.includes(n.kind()));
}

export function kindAt(kind, location) {
  const { path, text, start, end } = location;
  try {
    if (kind === "migration") return isMigration(path, text);
    if (kind === "sql_statement") return holdsSql(path, text, start, end);
    if (kind === "config_key") return configKeyAt(path, text, start);
    return codeKindAt(kind, location);
  } catch {
    return false; // anything this module can't read is not confirmed: the caller sends "other"
  }
}

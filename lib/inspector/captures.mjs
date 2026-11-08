/* Table and handler captures on structural rule matches (rule_bundle.md 3.3, contract v1.1,
 * with the table and handler rules as amended). Runs in the rules worker, on the
 * parsed tree; nothing leaves the machine except the two results. The principle: when attribution is uncertain, null.
 *
 * table: tableOf(node, key, lang, file) on the node a rule's `table.metavariable` captured.
 * - A string literal with no interpolation (or its content node, when the pattern put the metavariable inside the
 *   quotes) gives its decoded text, per language: C-style escapes in JS/TS, Java, Kotlin, Go, double-quoted PHP and
 *   Ruby and non-raw Python (Python \N{...} for the ASCII letter, digit and punctuation names; any other gives null);
 *   only \\ and \' in single-quoted PHP and Ruby, Ruby :'..', %q() and %s(); none in raw strings. A Java text block
 *   loses its common indentation first. A Python bytes literal gives null.
 * - An identifier is a table name only in a known position: the property of a member access (prisma.patient), a
 *   PascalCase receiver (Patient.objects, Patient.where) that is not a variable declared or assigned in the same file,
 *   a PascalCase first argument of a known ORM call (session.query(Patient), getRepository(Patient)), or a type
 *   argument (Repository<Patient>). Every other identifier and every expression gives null.
 * - The text is `schema.name` when the code writes one dot outside double quotes, else a bare name; no schema is ever
 *   added. Each part, quoted or not, is sent as written (a double-quoted part without its quotes, `""` read as `"`)
 *   when it fits pg_name, case kept, so it compares with the catalog's unhashed names; the evaluator compares all table names
 *   case-insensitively, so whether a part was quoted is not sent. A part outside pg_name is sent as `u_` plus the
 *   first 16 hex digits of HMAC-SHA256 (per-install key) over its UTF-8 bytes. A part mixing quoted and unquoted
 *   text, more than one dot, an empty part or an open quote makes the whole text one (hashed) name. A text or part
 *   that holds a secret or an email address is hashed whatever its shape .
 *
 * handler: Handlers(root, lang, path, key).of(node, range).
 * - The function a match belongs to: the matched node itself when it is a function, or the function it stands for when
 *   it wraps or marks one (a decorator or a match inside one, a decorated definition, an export, a declaration, field or
 *   assignment whose value is a function, a call wrapping one, or a reference to a function declared in this file);
 *   a registration call stands for its handler argument. Otherwise the nearest function enclosing the node.
 * - A function's identity: its declared name, or the variable, property or field it is assigned to (through TS
 *   `satisfies`, `as` and `<T>` wrappers), or `default` for a default export. An anonymous function passed to a call:
 *   - a route registration (an HTTP-method call whose first argument is a string literal starting with `/`, or any
 *     literal for Laravel's `Route::`; `.route('/p').get(cb)` chains read the path from `route`) whose handler
 *     argument it is: `<receiver> <METHOD> <path>`. The handler argument is the function argument at the highest index
 *     that is not an error handler (a JS function of 4 parameters); with none, a call argument wrapping a function; with
 *     none, an identifier naming a function declared once in this file (that function's own identity). Any other
 *     function in a route call (middleware, error handler) gets null;
 *   - any other registration-shaped call (first argument a string literal starting with `/`, or a router method:
 *     use, handle, handleFunc, on, add_url_rule, route, mount, group, ...): null;
 *   - an allowlisted non-route callback (map, forEach, then, filter, reduce, find, setTimeout, Promise.all, stream and
 *     iterator methods): the identity of the function enclosing the call; null with none;
 *   - a wrapping call (`withAuth(async () => ...)`, at any depth) at top level: the declaration or assignment holding
 *     it. Anything else: null.
 * - The id: HMAC-SHA256, keyed with the per-install key, over the UTF-8 bytes of JSON.stringify([path, name,
 *   startLine, startColumn]), lowercase hex, where the position is the start of the function the identity belongs to
 *   (line from 1, and the column as the inspector's parser reports it). For path "app/r.ts", name "GET" and a function starting
 *   at line 3 column 13 the input is `["app/r.ts","GET",3,13]`. Two functions never share an id; the readable name is
 *   only HMAC input and never sent.
 *
 * The rule this must keep: an uncontrolled item with a null handler, like a violation with one, creates a
 * per-file object of its own; and no handler object is ever judged controlled merely because no item points at it. */
import { createHmac } from "node:crypto";
import { parseSync } from "./parse.mjs";
import { hashed, holdsRecordValue, holdsSecret, letterToken } from "./ids.mjs";
import { PG_NAME as PG_NAME_PATTERN } from "./contracts.mjs";

// The function node kinds of each grammar (the tree-sitter grammars @ast-grep/napi and @ast-grep/lang-* ship).
const JS_FUNCTIONS = ["function_declaration", "generator_function_declaration", "function_expression",
  "generator_function", "arrow_function", "method_definition"];
export const FUNCTION_KINDS = Object.freeze({
  javascript: new Set(JS_FUNCTIONS),
  typescript: new Set(JS_FUNCTIONS),
  tsx: new Set(JS_FUNCTIONS),
  python: new Set(["function_definition", "lambda"]), // def and async def are both function_definition
  go: new Set(["function_declaration", "method_declaration", "func_literal"]),
  java: new Set(["method_declaration", "constructor_declaration", "compact_constructor_declaration", "lambda_expression"]),
  kotlin: new Set(["function_declaration", "anonymous_function", "lambda_literal"]),
  php: new Set(["function_definition", "method_declaration", "anonymous_function", "arrow_function"]),
  ruby: new Set(["method", "singleton_method", "lambda"]),
  // No C# parser ships today (its files are unsupported_language); listed for when one does (tree-sitter-c-sharp).
  csharp: new Set(["method_declaration", "local_function_statement", "constructor_declaration", "lambda_expression",
    "anonymous_method_expression"]),
});

const PG_NAME = new RegExp(PG_NAME_PATTERN); // fact schema $defs.pg_name (each part of a qualified_name)
const PASCAL = /^[A-Z][A-Za-z0-9_]*[a-z][A-Za-z0-9_]*$/; // a class or model name, not a variable or a CONSTANT

/** The handler id: HMAC-SHA256 over JSON.stringify([path, name, startLine, startColumn]), lowercase hex. */
export function handlerId(key, path, name, line, column) {
  return createHmac("sha256", key).update(JSON.stringify([path, name, line, column]), "utf8").digest("hex");
}

// --- shared node helpers ---------------------------------------------------------------------------------------------

const ARGUMENT_WRAPPERS = new Set(["argument", "value_argument"]); // PHP and Kotlin wrap each call argument
const ARGUMENT_LISTS = new Set(["arguments", "argument_list", "value_arguments"]);
const CALL_KINDS = new Set(["call_expression", "call", "method_invocation", "function_call_expression",
  "member_call_expression", "nullsafe_member_call_expression", "scoped_call_expression", "invocation_expression"]);
// Expressions that wrap a value without changing which function it is.
const TRANSPARENT = new Set(["parenthesized_expression", "satisfies_expression", "as_expression", "type_assertion",
  "non_null_expression"]);
const same = (a, b) => a != null && b != null && a.id() === b.id();

/* The callee of a call: its function, method or name field, else its first named child (Kotlin has no fields). */
function calleeOf(call) {
  return call.field("function") ?? call.field("method") ?? call.field("name") ?? call.namedChildren()[0] ?? null;
}

/* The name a call calls: the last identifier of its callee (`app.get` -> get, `Route::get` -> get). */
function methodName(call) {
  const callee = calleeOf(call);
  if (!callee) return null;
  const m = /([A-Za-z_][A-Za-z0-9_]*)\s*$/.exec(callee.text());
  return m ? m[1] : null;
}

/* The receiver of a method call (`app` in app.get, `Route` in Route::get), or null. */
function receiverOf(call) {
  const r = call.field("object") ?? call.field("receiver") ?? call.field("scope");
  if (r) return r;
  const callee = call.field("function");
  return callee ? callee.field("object") ?? callee.field("operand") ?? null : null;
}

/* A call's arguments, wrappers looked through; a Kotlin trailing lambda counts as the last one. */
function argumentsOf(call) {
  const out = [];
  const add = (list) => {
    for (const a of list.namedChildren()) {
      let x = a;
      while (ARGUMENT_WRAPPERS.has(x.kind()) && x.namedChildren().length === 1) x = x.namedChildren()[0];
      if (x.kind() !== "comment") out.push(x);
    }
  };
  const list = call.field("arguments");
  if (list) { add(list); return out; }
  for (const c of call.namedChildren()) {
    const k = c.kind();
    if (ARGUMENT_LISTS.has(k)) add(c);
    else if (k === "call_suffix") {
      for (const s of c.namedChildren()) {
        if (ARGUMENT_LISTS.has(s.kind())) add(s);
        else if (s.kind() === "annotated_lambda") { const l = s.namedChildren().find((x) => x.kind() === "lambda_literal"); if (l) out.push(l); }
      }
    }
  }
  return out;
}

/* The call a node is an argument of (through argument wrappers and transparent wrappers), or null. */
function callOfArgument(node) {
  let p = node.parent();
  while (p && (ARGUMENT_WRAPPERS.has(p.kind()) || TRANSPARENT.has(p.kind()) || p.kind() === "annotated_lambda")) p = p.parent();
  if (!p) return null;
  let c = null;
  if (ARGUMENT_LISTS.has(p.kind())) c = p.parent();
  else if (p.kind() === "call_suffix") c = p;
  if (c && c.kind() === "call_suffix") c = c.parent();
  return c && CALL_KINDS.has(c.kind()) ? c : null;
}

function unwrapValue(v) {
  while (v && TRANSPARENT.has(v.kind())) {
    const kids = v.namedChildren();
    v = kids.find((k) => !/type|annotation/.test(k.kind())) ?? null;
  }
  return v;
}

// --- table -----------------------------------------------------------------------------------------------------------

const STRING_KINDS = new Set(["string", "template_string", "string_literal", "interpreted_string_literal",
  "raw_string_literal", "encapsed_string", "line_string_literal", "multi_line_string_literal", "delimited_symbol"]);
const STRING_CONTENT = new Set(["string_fragment", "string_content", "interpreted_string_literal_content",
  "raw_string_literal_content", "multiline_string_fragment", "escape_sequence"]);
const STRING_DELIMITERS = new Set(["string_start", "string_end"]);

const SIMPLE_ESCAPES = { n: "\n", t: "\t", r: "\r", b: "\b", f: "\f", v: "\v", a: "\x07", e: "\x1b", s: " ",
  "\\": "\\", "'": "'", '"': '"', "`": "`", $: "$", "/": "/", "?": "?", "{": "{", "}": "}", "0": "\0" };
// Python \N{...}: the names an identifier can use without being hashed anyway. Any other name gives null (no Unicode
// name table ships here, and a wrong decode would hash to a different name).
const UNICODE_NAMES = (() => {
  const m = new Map([["LOW LINE", "_"], ["HYPHEN-MINUS", "-"], ["DOLLAR SIGN", "$"], ["FULL STOP", "."], ["SPACE", " "],
    ["QUOTATION MARK", '"']]);
  for (let c = 65; c <= 90; c++) {
    m.set(`LATIN CAPITAL LETTER ${String.fromCharCode(c)}`, String.fromCharCode(c));
    m.set(`LATIN SMALL LETTER ${String.fromCharCode(c)}`, String.fromCharCode(c + 32));
  }
  ["ZERO", "ONE", "TWO", "THREE", "FOUR", "FIVE", "SIX", "SEVEN", "EIGHT", "NINE"].forEach((d, i) => m.set(`DIGIT ${d}`, String(i)));
  return m;
})();

/* Decode C-style escapes as `lang` reads them; null when one can't be decoded with certainty. */
function unescapeC(raw, lang) {
  const hex = lang === "php" || lang === "ruby" ? "{1,2}" : "{2}";
  const dropUnknown = lang === "javascript" || lang === "typescript" || lang === "tsx" || lang === "ruby"; // \q is q
  let failed = false;
  const uu = lang === "java" ? "u+" : "u"; // Java allows \uu0069
  const re = new RegExp(`\\\\(N\\{[^}]*\\}|u\\{[0-9A-Fa-f]{1,6}\\}|${uu}[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|x[0-9A-Fa-f]${hex}|[0-7]{1,3}|\\r\\n|[\\s\\S])`, "g");
  const out = raw.replace(re, (all, e) => {
    if (e === "\n" || e === "\r\n") return ""; // a line continuation
    if (e.startsWith("N{")) {
      if (lang !== "python") return dropUnknown ? e : all;
      const ch = UNICODE_NAMES.get(e.slice(2, -1).toUpperCase());
      if (ch === undefined) failed = true;
      return ch ?? "";
    }
    let cp = null;
    if (/^u\{/.test(e)) cp = parseInt(e.slice(2, -1), 16);
    else if (/^(?:u+|U|x)[0-9A-Fa-f]/.test(e)) cp = parseInt(e.replace(/^(?:u+|U|x)/, ""), 16);
    else if (/^[0-7]/.test(e) && !(e === "0" && lang !== "go")) cp = parseInt(e, 8);
    if (cp !== null) {
      if (cp <= 0x10ffff && !(cp >= 0xd800 && cp <= 0xdfff)) return String.fromCodePoint(cp);
      failed = true;
      return all;
    }
    if (Object.hasOwn(SIMPLE_ESCAPES, e)) return SIMPLE_ESCAPES[e];
    return dropUnknown ? e : all;
  });
  return failed ? null : out;
}
const unescapeSingle = (raw) => raw.replace(/\\([\\'])/g, "$1"); // single-quoted PHP and Ruby

/* A Java text block's content: the lines after the opening delimiter, less their common indentation (the closing
 * delimiter's line counts), trailing spaces stripped. */
function javaTextBlock(raw) {
  const lines = raw.replace(/\r\n?/g, "\n").split("\n").slice(1);
  if (!lines.length) return "";
  const closingOwnLine = /^[ \t]*$/.test(lines[lines.length - 1]);
  const significant = lines.filter((l, i) => /\S/.test(l) || (i === lines.length - 1 && closingOwnLine));
  const indent = Math.min(...significant.map((l) => /^[ \t]*/.exec(l)[0].length));
  return lines.map((l) => l.slice(Math.min(indent, /^[ \t]*/.exec(l)[0].length)).replace(/[ \t]+$/, "")).join("\n");
}

/* How a string's escapes read: c, single or raw; null for a literal that isn't text (a Python bytes literal). */
function escapeMode(kind, lang, text) {
  if (kind === "raw_string_literal") return "raw";
  if (lang === "python") {
    const prefix = /^[A-Za-z]*/.exec(text)[0];
    if (/[bB]/.test(prefix)) return null;
    return /[rR]/.test(prefix) ? "raw" : "c";
  }
  if (lang === "php" && kind === "string") return "single";
  if (lang === "ruby" && /^(?:'|%q|:'|%s)/.test(text)) return "single";
  if (lang === "kotlin" && text.startsWith('"""')) return "raw";
  return "c";
}

/* The text a string literal holds, or null when it isn't one, interpolates something or can't be decoded. */
function literalText(node, lang, kind = node.kind()) {
  if (kind === "simple_symbol") return node.text().replace(/^:/, ""); // Ruby :patients
  if (kind === "concatenated_string") { // Python "pat" "ients"
    let out = "";
    for (const c of node.namedChildren()) { const t = literalText(c, lang); if (t === null) return null; out += t; }
    return out;
  }
  if (!STRING_KINDS.has(kind)) return null;
  const text = node.text();
  // Fast path: nothing that can interpolate or escape, plain delimiters, no prefix that changes the meaning.
  if (!/[\\$#{]/.test(text) && !text.startsWith('"""') && !text.startsWith("'''")) {
    const m = /^([A-Za-z]{0,2})(["'`])([\s\S]*)\2$/.exec(text);
    if (m && m[1] === "" ) return m[3];
    if (m && lang === "python" && !/[fFbB]/.test(m[1])) return m[3];
  }
  const mode = escapeMode(kind, lang, text);
  if (mode === null) return null;
  let raw = "";
  for (const c of node.namedChildren()) {
    const k = c.kind();
    if (STRING_CONTENT.has(k)) raw += c.text(); // a Python string_content holds its escape_sequence children
    else if (!STRING_DELIMITERS.has(k)) return null; // interpolation, template substitution, variable in a PHP string
  }
  if (lang === "java" && text.startsWith('"""')) raw = javaTextBlock(raw);
  return mode === "raw" ? raw : mode === "single" ? unescapeSingle(raw) : unescapeC(raw, lang);
}

/* Split `schema.name` on dots outside double quotes: [{text, quoted}], `""` in a quoted part read as `"`. Null when a
 * quote is left open or a part mixes quoted and unquoted text. */
function nameParts(text) {
  const parts = [];
  let cur = "", quoted = false, wasQuoted = false, open = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === '"') {
      if (open && text[i + 1] === '"') { cur += '"'; i++; continue; }
      if (!open && (cur !== "" || wasQuoted)) return null; // a"b
      open = !open;
      if (open) quoted = true; else wasQuoted = true;
      continue;
    }
    if (ch === "." && !open) { parts.push({ text: cur, quoted }); cur = ""; quoted = false; wasQuoted = false; continue; }
    if (wasQuoted) return null; // "a"b
    cur += ch;
  }
  if (open) return null;
  parts.push({ text: cur, quoted });
  return parts;
}

const tableNames = new WeakMap(); // key -> Map(text -> name): a file names the same few tables many times
/** The table name for a captured name (see the header: quoted and unquoted parts alike). */
export function tableName(key, text) {
  if (text === "") return null;
  let cache = typeof key === "object" ? tableNames.get(key) : null;
  if (typeof key === "object" && !cache) { cache = new Map(); tableNames.set(key, cache); }
  if (cache?.has(text)) return cache.get(text);
  const name = computeTableName(key, text);
  if (cache && cache.size < 10000) cache.set(text, name);
  return name;
}
/* A captured name is a code value (a string literal), so before it is sent it passes the same checks as a path
 * segment: a whole text or part that holds a secret (ids.holdsSecret: a known key prefix, a high-entropy run,
 * the secret scan's patterns), looks like an email address, holds a UUID or a long random-looking run of letters is hashed, never
 * sent as written. */
const UUID = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;
// letterToken (ids.mjs): a run of 24 or more letters that reads as a random token; path segments use it too.
const oddValue = (text) => text.includes("@") || UUID.test(text) || letterToken(text) || holdsSecret(text) || holdsRecordValue(text);
/* A record value is judged part by part, as the catalog hashes schema and table names one by one, so
 * public.events_123456789012 is sent as public.<hash of events_123456789012> and still matches the catalog (L-a). A
 * shape that only appears across the parts (555.234.5678) hashes the whole text. */
const oddWhole = (text) => text.includes("@") || UUID.test(text) || letterToken(text) || holdsSecret(text);
export function computeTableName(key, text) {
  if (oddWhole(text)) return hashed(key, text);
  let parts = nameParts(text);
  if (parts === null || parts.length > 2 || parts.some((p) => p.text === "")) parts = [{ text, quoted: false }];
  const out = parts.map((p) => (PG_NAME.test(p.text) && !oddValue(p.text) ? p.text : hashed(key, p.text))).join(".");
  return holdsRecordValue(out) ? hashed(key, text) : out;
}

const IDENTIFIER_KINDS = new Set(["identifier", "property_identifier", "shorthand_property_identifier", "type_identifier",
  "field_identifier", "simple_identifier", "constant", "name"]);
// Member accesses: [receiver field, property field]. A call's method name (Ruby call, Java method_invocation, PHP
// member call) is never a table, but its PascalCase receiver is a model.
const MEMBER_FIELDS = Object.freeze({
  member_expression: ["object", "property"], attribute: ["object", "attribute"], selector_expression: ["operand", "field"],
  field_access: ["object", "field"], member_access_expression: ["object", "name"],
  nullsafe_member_access_expression: ["object", "name"], scoped_property_access_expression: ["scope", "name"],
});
const RECEIVER_FIELDS = Object.freeze({ call: "receiver", method_invocation: "object", member_call_expression: "object",
  scoped_call_expression: "scope", class_constant_access_expression: null });
// ORM calls whose first argument is a model: SQLAlchemy query/select/insert/update/delete/get, TypeORM repositories and
// entity manager finders.
const ORM_CALLS = new Set(["query", "select", "insert", "update", "delete", "get", "getRepository", "getTreeRepository",
  "getMongoRepository", "getCustomRepository", "find", "findOne", "findOneBy", "findBy", "findAndCount", "count"]);

// Declarations and assignments that make a name a local variable, by grammar: [kind, field holding the target].
const VARIABLE_SITES = [["variable_declarator", "name"], ["assignment_expression", "left"], ["assignment", "left"],
  ["short_var_declaration", "left"], ["var_spec", "name"], ["assignment_statement", "left"], ["property_declaration", null]];

/** The names declared or assigned as variables anywhere in a file (a PascalCase receiver among them is no model). */
export function localVariables(root, lang) {
  const kinds = VARIABLE_SITES.filter(([k]) => validKind(lang, k));
  const names = new Set();
  if (!kinds.length) return names;
  const fieldOf = new Map(kinds);
  for (const n of root.findAll({ rule: { any: kinds.map(([kind]) => ({ kind })) } })) {
    const f = fieldOf.get(n.kind());
    const targets = f === null
      ? n.namedChildren().filter((c) => c.kind() === "variable_declaration").flatMap((v) => v.namedChildren().filter((c) => c.kind() === "simple_identifier"))
      : f === "name" && n.kind() === "var_spec" ? n.fieldChildren("name") : [n.field(f)].filter(Boolean);
    for (const t of targets) {
      if (t.kind() === "expression_list" || t.kind() === "pattern_list") { for (const c of t.namedChildren()) if (c.isNamedLeaf()) names.add(c.text()); }
      else if (t.isNamedLeaf()) names.add(t.text());
    }
  }
  return names;
}

/* An identifier names a table only in a known position (see the header). */
function identifierInTablePosition(n, text, isLocal) {
  let p = n.parent();
  while (p && ARGUMENT_WRAPPERS.has(p.kind())) p = p.parent();
  if (!p) return false;
  const pk = p.kind();
  const receiver = () => PASCAL.test(text) && !isLocal(text);
  if (Object.hasOwn(MEMBER_FIELDS, pk)) {
    const [recv, prop] = MEMBER_FIELDS[pk];
    if (same(p.field(prop), n)) return true;
    return same(p.field(recv), n) && receiver();
  }
  if (pk === "navigation_suffix") return true; // Kotlin a.b: b
  if (pk === "navigation_expression") return same(p.namedChildren()[0], n) && receiver();
  if (Object.hasOwn(RECEIVER_FIELDS, pk)) {
    const f = RECEIVER_FIELDS[pk];
    return f !== null && same(p.field(f), n) && receiver();
  }
  let t = p;
  while (t && (t.kind() === "user_type" || t.kind() === "type_projection")) t = t.parent();
  if (t && t.kind() === "type_arguments") return true;
  if (ARGUMENT_LISTS.has(pk) && PASCAL.test(text)) {
    const call = callOfArgument(n);
    if (!call || !ORM_CALLS.has(methodName(call))) return false;
    return same(argumentsOf(call)[0], n) && !isLocal(text);
  }
  return false;
}

/** matches[].table for a captured node (null when the metavariable is unbound or names no table). file: the file's
 * Handlers (for its local variables), or null to scan the node's tree. */
export function tableOf(node, key, lang = null, file = null) {
  if (!node) return null;
  let n = node;
  let kind = n.kind();
  while (ARGUMENT_WRAPPERS.has(kind) && n.namedChildren().length === 1) { n = n.namedChildren()[0]; kind = n.kind(); }
  // `db.from("$T")`: the metavariable bound the string's content; read the whole string (null if it interpolates).
  if (STRING_CONTENT.has(kind)) {
    const parent = n.parent();
    if (!parent) return null;
    const literal = literalText(parent, lang);
    return literal === null ? null : tableName(key, literal);
  }
  const literal = literalText(n, lang, kind);
  if (literal !== null) return tableName(key, literal);
  if (!IDENTIFIER_KINDS.has(kind)) return null; // an expression (subscript, call, PHP $variable, ...)
  const text = n.text();
  let locals = null;
  const isLocal = (name) => {
    if (file) return file.localVariables().has(name);
    locals ??= localVariables(n.getRoot().root(), lang);
    return locals.has(name);
  };
  return identifierInTablePosition(n, text, isLocal) ? tableName(key, text) : null;
}

// --- handler ---------------------------------------------------------------------------------------------------------

/* A name node's text; a string key (`"GET"() {}`, `{ "k": fn }`) without its quotes. */
const unquote = (node, lang) => {
  const text = node.text();
  return /^[:"'`]/.test(text) ? literalText(node, lang) ?? text : text;
};

/* The name an assignment target gives: a plain name, or the property of a member access. */
function targetName(left) {
  if (!left) return null;
  if (left.isNamedLeaf() || left.kind() === "variable_name") return left.text();
  const prop = left.field("property") ?? left.field("attribute") ?? left.field("field") ?? left.field("name") ?? left.field("method");
  if (prop && prop.isNamedLeaf()) return prop.text();
  return null;
}

/* The name a node gets from where it sits: the declaration, assignment, pair or field holding it, or default. */
function assignedName(node, lang) {
  let child = node;
  let p = node.parent();
  while (p && TRANSPARENT.has(p.kind())) { child = p; p = p.parent(); }
  if (!p) return null;
  switch (p.kind()) {
    case "variable_declarator": { // JS, Java
      if (!same(p.field("value"), child)) return null;
      const name = p.field("name");
      return name && name.isNamedLeaf() ? name.text() : null;
    }
    case "assignment_expression": // JS, Java, PHP
    case "assignment": // Python, Ruby
      return same(p.field("right"), child) ? targetName(p.field("left")) : null;
    case "pair": {
      if (!same(p.field("value"), child)) return null;
      const key = p.field("key");
      return key ? unquote(key, lang) : null;
    }
    case "array_element_initializer": { // PHP [ 'k' => fn ]
      const kids = p.namedChildren();
      return kids.length === 2 && same(kids[1], child) ? unquote(kids[0], lang) : null;
    }
    case "field_definition": case "public_field_definition": {
      const name = p.field("property") ?? p.field("name");
      return name ? unquote(name, lang) : null;
    }
    case "export_statement":
      return p.children().some((c) => c.kind() === "default") ? "default" : null;
    case "property_declaration": { // Kotlin val x = ...
      const v = p.namedChildren().find((c) => c.kind() === "variable_declaration");
      const id = v?.namedChildren().find((c) => c.kind() === "simple_identifier");
      return id ? id.text() : null;
    }
    case "expression_list": { // Go: var h = ..., h := ..., h = ...
      const owner = p.parent();
      if (!owner) return null;
      const index = p.namedChildren().findIndex((c) => same(c, child));
      if (owner.kind() === "var_spec") return owner.fieldChildren("name")[index]?.text() ?? null;
      if (owner.kind() === "short_var_declaration" || owner.kind() === "assignment_statement") {
        if (same(owner.field("left"), p)) return null;
        return targetName(owner.field("left")?.namedChildren()[index] ?? null);
      }
      return null;
    }
    default:
      return null;
  }
}

/* The function's declared name, or null. */
function declaredName(fn, lang) {
  const declared = fn.field("name");
  if (declared) return unquote(declared, lang);
  if (fn.kind() === "function_declaration") { // Kotlin: no field names
    const id = fn.namedChildren().find((c) => c.kind() === "simple_identifier");
    if (id) return id.text();
  }
  return null;
}

const HTTP_METHODS = new Set(["get", "post", "put", "patch", "delete", "del", "head", "options", "all", "any"]);
// Router methods that register a handler under another shape: their callbacks are registrations, never inherited.
const ROUTER_METHODS = new Set(["use", "handle", "handlefunc", "handler", "on", "add_url_rule", "route", "routes", "mount",
  "group", "match", "addroute", "register", "resource", "resources", "ws", "websocket", "subscribe", "listen", "middleware",
  "before", "after", "before_request", "after_request", "add_api_route", "api_route", "add_route", "connect", "trace"]);
// Non-route callbacks that run as part of the enclosing function: their bodies take its identity.
const INHERIT_CALLS = new Set(["map", "forEach", "then", "catch", "finally", "filter", "reduce", "reduceRight", "find",
  "findIndex", "findLast", "findLastIndex", "some", "every", "flatMap", "sort", "toSorted", "all", "allSettled", "race",
  "setTimeout", "setImmediate", "setInterval", "nextTick", "queueMicrotask", "anyMatch", "allMatch", "noneMatch",
  "peek", "sorted", "mapNotNull", "forEachIndexed", "mapIndexed", "filterNot", "flatMapConcat", "sortedBy",
  "computeIfAbsent", "ifPresent", "orElseGet", "thenApply", "thenAccept", "thenCompose"]);

const isFunctionLiteral = (n, kinds) => kinds.has(n.kind());
const literalStartsWithSlash = (n, lang) => { const t = n ? literalText(n, lang) : null; return t !== null && t.startsWith("/"); };
const ARRAY_KINDS = new Set(["array", "list", "array_creation_expression", "array_literal"]);
/* A route path argument: a string literal (its text), or an array of string literals with at least one starting with
 * `/` (Express router.get(["/a", "/b"], fn)): its first such path. null otherwise. */
function pathArgument(n, lang) {
  if (!n) return null;
  if (ARRAY_KINDS.has(n.kind())) {
    const items = n.namedChildren().map((c) => (c.kind() === "array_element_initializer" ? c.namedChildren()[0] : c)).filter(Boolean);
    const texts = items.map((c) => literalText(c, lang));
    if (!texts.length || texts.some((t) => t === null)) return null;
    return texts.find((t) => t.startsWith("/")) ?? null;
  }
  return literalText(n, lang);
}
const pathStartsWithSlash = (n, lang) => { const t = pathArgument(n, lang); return t !== null && t.startsWith("/"); };
// handle and handler are registrations only with a path (first, or after an HTTP method as in gin's r.Handle): Next's
// `return handler(req, ctx)` is a call.
const PATH_ONLY_ROUTER_METHODS = new Set(["handle", "handler"]);
const REQUEST_ARGS = new Set(["req", "request"]);

/* How a call reads as a registration: {route: name} for a recognised route, {registration: true} for any other
 * registration shape, null for an ordinary call. */
function registrationOf(call, lang, kinds) {
  let verbCall = call;
  const callee = calleeOf(call);
  if (callee && CALL_KINDS.has(callee.kind())) verbCall = callee; // Kotlin get("/p") { ... }
  const verb = methodName(verbCall);
  const lower = verb?.toLowerCase() ?? "";
  const args = argumentsOf(verbCall);
  const first = args[0] && !isFunctionLiteral(args[0], kinds) ? args[0] : null;
  if (HTTP_METHODS.has(lower)) {
    let receiver = receiverOf(verbCall);
    let path = first ? pathArgument(first, lang) : null;
    const laravel = verbCall.kind() === "scoped_call_expression" && /(^|\\)Route$/.test(receiver?.text() ?? "");
    if (path !== null && !path.startsWith("/") && !laravel) path = null;
    if (path === null && !first) { // app.route('/p').get(cb).post(cb2)
      let r = receiver;
      while (r && CALL_KINDS.has(r.kind()) && HTTP_METHODS.has((methodName(r) ?? "").toLowerCase())) r = receiverOf(r);
      if (r && CALL_KINDS.has(r.kind()) && methodName(r) === "route") {
        const p = argumentsOf(r)[0];
        if (literalStartsWithSlash(p, lang)) { path = literalText(p, lang); receiver = receiverOf(r); }
      }
    }
    if (path !== null) {
      const recv = receiver ? receiver.text().replace(/\s+/g, " ") : null;
      return { route: [recv, verb.toUpperCase(), path].filter((x) => x !== null && x !== "").join(" ") };
    }
  }
  if (pathStartsWithSlash(first, lang)) return { registration: true };
  // A call passing the request on (handler(req, ctx)) is never a registration.
  if (args[0] && REQUEST_ARGS.has(args[0].text())) return null;
  // handle/handler: a registration only with a path, first or after an HTTP method (gin's r.Handle("PUT", "/p", fn)).
  if (PATH_ONLY_ROUTER_METHODS.has(lower)) {
    const verb0 = args[0] ? literalText(args[0], lang) : null;
    return verb0 !== null && HTTP_METHODS.has(verb0.toLowerCase()) && pathStartsWithSlash(args[1], lang) ? { registration: true } : null;
  }
  if (ROUTER_METHODS.has(lower)) return { registration: true };
  return null;
}

/* A JS error-handling middleware: a function of four parameters. */
function isErrorHandler(fn, lang) {
  if (!["javascript", "typescript", "tsx"].includes(lang)) return false;
  const params = fn.field("parameters");
  return !!params && params.namedChildren().filter((c) => c.kind() !== "comment").length === 4;
}

const FIELD_DEFINITIONS = new Set(["public_field_definition", "field_definition"]);
const DECORATOR_LANGS = new Set(["javascript", "typescript", "tsx", "python"]);
const FREE_FUNCTION_PARENTS = new Set(["program", "source_file", "module", "export_statement", "statement_block",
  "block", "compound_statement", "function_body", "statements", "variable_declarator"]);

/* The index of the last entry of a list sorted by start whose start is at or before `index`, or -1. */
function lastStartingBy(list, index) {
  let lo = 0, hi = list.length - 1, at = -1;
  while (lo <= hi) { const mid = (lo + hi) >> 1; if (list[mid].start <= index) { at = mid; lo = mid + 1; } else hi = mid - 1; }
  return at;
}

const validKinds = new Map(); // lang -> Map(kind -> valid) (a kind matcher for another grammar throws)
function validKind(lang, kind) {
  if (!validKinds.has(lang)) {
    let empty = null;
    try { empty = parseSync(lang, "").root(); } catch { /* no parser for this language */ }
    validKinds.set(lang, { empty, known: new Map() });
  }
  const v = validKinds.get(lang);
  if (!v.empty) return false;
  if (!v.known.has(kind)) { let ok = true; try { v.empty.find({ rule: { kind } }); } catch { ok = false; } v.known.set(kind, ok); }
  return v.known.get(kind);
}

/**
 * Handlers(root, lang, path, key).of(node, range) -> matches[].handler (see the header). The functions (and
 * decorators) are found once per file with one native search and nested by range (parent() rescans from the root, so
 * walking up from every match is quadratic on a wide file). Each function's identity is worked out once, iteratively,
 * and each identity's HMAC once.
 */
export class Handlers {
  constructor(root, lang, path, key) {
    this.root = root; this.lang = lang; this.path = path; this.key = key;
    this.kinds = new Set([...(FUNCTION_KINDS[lang] ?? [])].filter((k) => validKind(lang, k)));
    this.fns = null; this.byRange = null; this.idents = new Map(); this.ids = new Map();
    this.declared = null; this.locals = null;
  }

  load() {
    const kinds = [...this.kinds];
    const nodes = kinds.length ? this.root.findAll({ rule: { any: kinds.map((kind) => ({ kind })) } }) : [];
    const fns = nodes.map((node) => {
      const { start, end } = node.range();
      return { node, start: start.index, end: end.index, line: start.line + 1, column: start.column, outer: -1 };
    });
    fns.sort((a, b) => a.start - b.start || b.end - a.end); // outer before inner at the same start
    const stack = [];
    this.byRange = new Map();
    fns.forEach((f, i) => {
      while (stack.length && fns[stack[stack.length - 1]].end < f.end) stack.pop();
      f.outer = stack.length ? stack[stack.length - 1] : -1;
      stack.push(i);
      this.byRange.set(`${f.start}:${f.end}`, i); // same range: the inner one (sorted later) wins
    });
    this.fns = fns;
    // Decorators sit outside the function they mark, so a match in one (`@app.get('/p')`, `@Get(':id')`) stands for
    // that function. Found once, only in a file that has an `@`.
    this.decorators = [];
    if (DECORATOR_LANGS.has(this.lang) && this.root.text().includes("@")) {
      this.decorators = this.root.findAll({ rule: { kind: "decorator" } })
        .map((node) => { const { start, end } = node.range(); return { node, start: start.index, end: end.index }; })
        .sort((a, b) => a.start - b.start);
    }
  }

  /** The file's local variable names (for tableOf). */
  localVariables() {
    this.locals ??= localVariables(this.root, this.lang);
    return this.locals;
  }

  /* The decorator holding [start, end], or null. */
  decoratorAt(start, end) {
    const at = lastStartingBy(this.decorators, start);
    return at !== -1 && this.decorators[at].end >= end ? this.decorators[at].node : null;
  }

  /* The index of the innermost function whose range holds [start, end], or -1. */
  innermost(start, end) {
    const fns = this.fns;
    for (let i = lastStartingBy(fns, start); i !== -1; i = fns[i].outer) if (fns[i].end >= end) return i;
    return -1;
  }

  /* The innermost function strictly enclosing a node (not the node itself). */
  enclosing(node) {
    const { start, end } = node.range();
    let i = this.innermost(start.index, end.index);
    while (i !== -1 && this.fns[i].start === start.index && this.fns[i].end === end.index) i = this.fns[i].outer;
    return i;
  }

  /* True when some function lies within [start, end]. Functions nest, so one that starts inside the range ends inside
   * it unless it starts exactly at `start` and encloses the node: those are skipped. */
  anyWithin(start, end) {
    const fns = this.fns;
    let lo = 0, hi = fns.length;
    while (lo < hi) { const mid = (lo + hi) >> 1; if (fns[mid].start < start) lo = mid + 1; else hi = mid; }
    for (let j = lo; j < fns.length && fns[j].start <= end; j++) if (fns[j].end <= end) return true;
    return false;
  }

  indexOf(fnNode) {
    const { start, end } = fnNode.range();
    return this.byRange.get(`${start.index}:${end.index}`) ?? -1;
  }

  /* Free functions declared once in this file, by name (for `app.get('/p', show)`). */
  declaredFunction(name) {
    if (!this.declared) {
      const counts = new Map();
      this.fns.forEach((f, i) => {
        let n = null;
        const k = f.node.kind();
        if (k === "method_definition" || k === "method_declaration" || k === "method" || k === "singleton_method") return;
        const parent = f.node.parent();
        if (!parent || !FREE_FUNCTION_PARENTS.has(parent.kind())) return;
        n = parent.kind() === "variable_declarator" ? (same(parent.field("value"), f.node) ? parent.field("name")?.text() ?? null : null) : declaredName(f.node, this.lang);
        if (n) counts.set(n, counts.has(n) ? -1 : i);
      });
      this.declared = counts;
    }
    const i = this.declared.get(name);
    return i === undefined || i === -1 ? null : this.fns[i].node;
  }

  /* The handler argument of a call (see the header), or null. */
  handlerArgument(call, depth = 0, byRef = true) {
    const args = argumentsOf(call).map(unwrapValue).filter(Boolean);
    const direct = args.filter((a) => this.kinds.has(a.kind()) && !isErrorHandler(a, this.lang));
    if (direct.length) return direct[direct.length - 1];
    if (depth < 64) {
      for (let i = args.length - 1; i >= 0; i--) {
        if (CALL_KINDS.has(args[i].kind())) { const f = this.handlerArgument(args[i], depth + 1, byRef); if (f) return f; }
      }
    }
    // By reference: the last argument names a function declared once in this file (`app.get('/x', show)`).
    const last = args[args.length - 1];
    if (byRef && last && (last.kind() === "identifier" || last.kind() === "simple_identifier")) return this.declaredFunction(last.text());
    return null;
  }

  /* One step of a function's identity: {done: {name, owner} | null} or {inherit: index of the enclosing function}. */
  step(i) {
    const fn = this.fns[i].node;
    const own = declaredName(fn, this.lang) ?? assignedName(fn, this.lang);
    if (own !== null && own !== "") return { done: { name: own, owner: i } };
    let call = callOfArgument(fn);
    if (!call) return { done: null };
    for (;;) {
      const reg = registrationOf(call, this.lang, this.kinds);
      if (reg?.route !== undefined) return { done: same(this.handlerArgument(call), fn) ? { name: reg.route, owner: i } : null };
      if (reg?.registration) return { done: null };
      if (INHERIT_CALLS.has(methodName(call))) return { inherit: this.enclosing(call) };
      if (!same(this.handlerArgument(call), fn)) return { done: null };
      const outer = callOfArgument(call);
      if (!outer) break;
      call = outer;
    }
    // A wrapping call: named by the declaration holding it, only at top level.
    if (this.enclosing(call) !== -1) return { done: null };
    const n = assignedName(call, this.lang);
    return { done: n ? { name: n, owner: i } : null };
  }

  /* The identity {name, owner} of function i, or null; iterative, every function on the way cached. */
  identity(i) {
    const chain = [];
    let cur = i, result = null;
    for (;;) {
      if (this.idents.has(cur)) { result = this.idents.get(cur); break; }
      chain.push(cur);
      const s = this.step(cur);
      if (!("inherit" in s)) { result = s.done; break; }
      if (s.inherit === -1) { result = null; break; }
      cur = s.inherit;
    }
    for (const c of chain) this.idents.set(c, result);
    return result;
  }

  idOfFunction(i) {
    const ident = this.identity(i);
    if (!ident) return null;
    const k = `${ident.owner}\n${ident.name}`;
    if (!this.ids.has(k)) {
      const f = this.fns[ident.owner];
      this.ids.set(k, handlerId(this.key, this.path, ident.name, f.line, f.column));
    }
    return this.ids.get(k);
  }

  /* The function a non-call node stands for (a wrapper or marker of one), or null. */
  targetFunction(node, kind) {
    if (this.kinds.has(kind)) return node;
    switch (kind) {
      case "decorated_definition": { const d = node.field("definition"); return d && this.kinds.has(d.kind()) ? d : null; }
      case "decorator": {
        const p = node.parent();
        if (!p) return null;
        const pk = p.kind();
        if (pk === "decorated_definition") return this.targetFunction(p, pk);
        if (this.kinds.has(pk)) return p;
        if (FIELD_DEFINITIONS.has(pk)) return this.valueFunction(p.field("value"));
        if (pk === "class_body") { // TypeScript: decorators are siblings before the member they decorate
          for (const s of node.nextAll()) {
            if (!s.isNamed()) continue;
            const k = s.kind();
            if (k === "decorator" || k === "comment") continue;
            if (this.kinds.has(k)) return s;
            if (FIELD_DEFINITIONS.has(k)) return this.valueFunction(s.field("value"));
            return null;
          }
        }
        return null;
      }
      case "export_statement": {
        const d = node.field("declaration") ?? node.field("value");
        return d ? this.targetFunction(d, d.kind()) : null;
      }
      case "lexical_declaration": case "variable_declaration": {
        const decls = node.namedChildren().filter((c) => c.kind() === "variable_declarator");
        return decls.length === 1 ? this.targetFunction(decls[0], decls[0].kind()) : null;
      }
      case "variable_declarator": return this.valueFunction(node.field("value"));
      case "public_field_definition": case "field_definition": return this.valueFunction(node.field("value"));
      case "assignment_expression": case "assignment": return this.valueFunction(node.field("right"));
      case "expression_statement": {
        const kids = node.namedChildren();
        return kids.length === 1 ? this.targetFunction(kids[0], kids[0].kind()) : null;
      }
      case "pair": return this.valueFunction(node.field("value"));
      default: return null;
    }
  }

  /* A value that is a function, a call wrapping one, or a reference to one declared in this file. */
  valueFunction(v) {
    v = unwrapValue(v);
    if (!v) return null;
    if (this.kinds.has(v.kind())) return v;
    if (CALL_KINDS.has(v.kind())) return this.handlerArgument(v);
    return null;
  }

  /* The handler a call stands for: undefined when it is an ordinary call (the caller falls back to the enclosing
   * function), else the id (possibly null) of its handler. */
  callHandler(call) {
    const reg = registrationOf(call, this.lang, this.kinds);
    if (reg) {
      if (reg.registration) {
        // fastify.route({ handler }) and other option objects: the `handler` property's function.
        const opts = argumentsOf(call).find((a) => a.kind() === "object");
        const prop = opts?.namedChildren().find((c) => (c.kind() === "pair" && c.field("key")?.text() === "handler") || (c.kind() === "method_definition" && c.field("name")?.text() === "handler"));
        if (prop) { const f = prop.kind() === "pair" ? this.valueFunction(prop.field("value")) : prop; const i = f ? this.indexOf(f) : -1; return i === -1 ? null : this.idOfFunction(i); }
        // By reference (`http.HandleFunc("/c", show)`): the declared function's own id. A function written in the
        // call is not recognised as a route handler: null.
        const args = argumentsOf(call).map(unwrapValue).filter(Boolean);
        const last = args[args.length - 1];
        const f = last && (last.kind() === "identifier" || last.kind() === "simple_identifier") ? this.declaredFunction(last.text()) : null;
        const i = f ? this.indexOf(f) : -1;
        return i === -1 ? null : this.idOfFunction(i);
      }
      const f = this.handlerArgument(call);
      const i = f ? this.indexOf(f) : -1;
      return i === -1 ? null : this.idOfFunction(i);
    }
    const f = this.handlerArgument(call, 0, false); // an ordinary call: only a function written in it
    if (!f) return undefined;
    const i = this.indexOf(f);
    const id = i === -1 ? null : this.idOfFunction(i);
    return id === null ? undefined : id;
  }

  /* range and text: node.range() and node.text() when the caller already has them. */
  of(node, range = null, text = null) {
    if (!this.kinds.size) return null;
    if (!this.fns) this.load();
    const { start, end } = range ?? node.range();
    // Only a node that holds a function, sits in a decorator, or may register or wrap a function by reference can
    // stand for one; any other node needs no structural look (most matches: one range lookup).
    const decorator = this.decorators.length ? this.decoratorAt(start.index, end.index) : null;
    if (decorator) {
      const fn = this.targetFunction(decorator, "decorator");
      const i = fn ? this.indexOf(fn) : -1;
      if (i !== -1) return this.idOfFunction(i);
    } else {
      const holds = this.anyWithin(start.index, end.index);
      let byRef = false;
      if (!holds) {
        const t = text ?? node.text();
        const call = /^([^(=]*?)([A-Za-z_][A-Za-z0-9_]*)\s*\(/.exec(t);
        byRef = /^(?:export\s+)?(?:const|let|var)\s|^[A-Za-z_$][\w$.]*\s*(?::[^=]*)?=[^=>]/.test(t)
          || (call !== null && (HTTP_METHODS.has(call[2].toLowerCase()) || ROUTER_METHODS.has(call[2].toLowerCase())));
      }
      if (holds || byRef) {
        const kind = node.kind();
        if (CALL_KINDS.has(kind)) {
          const id = this.callHandler(node);
          if (id !== undefined) return id;
        } else {
          const fn = this.targetFunction(node, kind);
          if (fn) { const i = this.indexOf(fn); return i === -1 ? null : this.idOfFunction(i); }
        }
      }
    }
    const i = this.innermost(start.index, end.index);
    return i === -1 ? null : this.idOfFunction(i);
  }
}

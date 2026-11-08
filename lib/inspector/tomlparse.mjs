/* A strict TOML 1.0 reader for supabase/config.toml (rule_bundle.md 3.5: a TOML parser, never a text search).
 *
 * parseToml(text) -> a plain object, or throws TomlError. It reads the whole grammar the edge_functions collector can
 * meet (tables, array tables, dotted and quoted keys, every string form, integers, floats, booleans, dates and times,
 * arrays and inline tables) and refuses anything else: a duplicate key, a table defined twice, a control character,
 * a malformed number. When in doubt it throws, so the caller reports the file as not parsed (parse_failed) instead of
 * reading part of it. Dates and times are kept as their text; nothing here evaluates anything. No dependency. */

export class TomlError extends Error {
  constructor(message, at) { super(`${message} (offset ${at})`); this.name = "TomlError"; this.at = at; }
}

const BARE = /[A-Za-z0-9_-]/;
const MAX_DEPTH = 64;
const INT = /^[+-]?(?:0|[1-9](?:_?[0-9])*)$/;
const HEX = /^0x[0-9A-Fa-f](?:_?[0-9A-Fa-f])*$/;
const OCT = /^0o[0-7](?:_?[0-7])*$/;
const BIN = /^0b[01](?:_?[01])*$/;
const FLOAT = /^[+-]?(?:0|[1-9](?:_?[0-9])*)(?:\.[0-9](?:_?[0-9])*)?(?:[eE][+-]?[0-9](?:_?[0-9])*)?$/;
const SPECIAL = /^[+-]?(?:inf|nan)$/;
const DATE = /^\d{4}-\d{2}-\d{2}$/;
const TIME = /^\d{2}:\d{2}:\d{2}(?:\.\d+)?$/;
const DATETIME = /^\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})?$/;

export function parseToml(input) {
  if (typeof input !== "string") throw new TomlError("not text", 0);
  const s = input.charCodeAt(0) === 0xfeff ? input.slice(1) : input;
  let i = 0;
  const root = {};
  const explicit = new WeakSet(); // tables opened by a [header]
  const closed = new WeakSet(); // inline tables and arrays: never extended later
  const dotted = new WeakSet(); // tables made by dotted keys: never reopened by a [header]
  const arrayTables = new WeakSet(); // arrays made by [[headers]]
  let current = root;

  const fail = (m) => { throw new TomlError(m, i); };
  const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
  const peek = (n = 0) => s[i + n];
  const ws = () => { while (peek() === " " || peek() === "\t") i++; };
  const comment = () => {
    if (peek() !== "#") return;
    while (i < s.length && peek() !== "\n") {
      const c = s.charCodeAt(i);
      if ((c < 0x20 && c !== 0x09 && c !== 0x0d) || c === 0x7f) fail("control character in a comment");
      i++;
    }
  };
  const newline = () => {
    if (peek() === "\n") { i++; return true; }
    if (peek() === "\r" && peek(1) === "\n") { i += 2; return true; }
    return false;
  };
  const blank = () => { for (;;) { ws(); comment(); if (!newline()) return; } };
  const endOfLine = () => { ws(); comment(); if (i < s.length && !newline()) fail("expected the end of the line"); };

  const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
  const set = (o, k, v) => Object.defineProperty(o, k, { value: v, enumerable: true, writable: true, configurable: true });

  function key() {
    const parts = [];
    for (;;) {
      ws();
      if (peek() === '"') parts.push(basicString());
      else if (peek() === "'") parts.push(literalString());
      else {
        const start = i;
        while (i < s.length && BARE.test(peek())) i++;
        if (i === start) fail("expected a key");
        parts.push(s.slice(start, i));
      }
      ws();
      if (peek() !== ".") return parts;
      i++;
    }
  }

  function control(c) { return (c < 0x20 && c !== 0x09) || c === 0x7f; }

  /* At a multi-line string's closing quotes: a run of four or five quotes ends with the delimiter, so the one or two
   * before it belong to the string. Returns those and moves past the run. */
  function closeMulti(quote) {
    let q = 3;
    while (s[i + q] === quote && q < 5) q++;
    i += q;
    return quote.repeat(q - 3);
  }

  function escape() {
    const c = s[i++];
    const simple = { b: "\b", t: "\t", n: "\n", f: "\f", r: "\r", '"': '"', "\\": "\\", e: "\x1b" };
    if (own(simple, c)) return simple[c];
    if (c === "u" || c === "U") {
      const n = c === "u" ? 4 : 8;
      const hex = s.slice(i, i + n);
      if (!new RegExp(`^[0-9A-Fa-f]{${n}}$`).test(hex)) fail("bad unicode escape");
      i += n;
      const cp = parseInt(hex, 16);
      if (cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) fail("bad unicode escape");
      return String.fromCodePoint(cp);
    }
    return fail("bad escape");
  }

  function basicString() {
    if (s.startsWith('"""', i)) return multiBasic();
    i++;
    let out = "";
    for (;;) {
      if (i >= s.length) fail("unterminated string");
      const ch = s[i];
      if (ch === '"') { i++; return out; }
      if (ch === "\\") { i++; out += escape(); continue; }
      if (control(s.charCodeAt(i))) fail("control character in a string");
      out += ch; i++;
    }
  }

  function multiBasic() {
    i += 3;
    newline();
    let out = "";
    for (;;) {
      if (i >= s.length) fail("unterminated string");
      if (s.startsWith('"""', i)) return out + closeMulti('"');
      const ch = s[i];
      if (ch === "\\") {
        let j = i + 1;
        while (s[j] === " " || s[j] === "\t") j++;
        if (s[j] === "\n" || (s[j] === "\r" && s[j + 1] === "\n")) { // line-ending backslash: trim to the next text
          i = j;
          while (i < s.length && (s[i] === " " || s[i] === "\t" || s[i] === "\n" || s[i] === "\r")) {
            if (s[i] === "\r" && s[i + 1] !== "\n") fail("bare carriage return");
            i++;
          }
          continue;
        }
        i++; out += escape(); continue;
      }
      if (ch === "\r" && s[i + 1] === "\n") { out += "\r\n"; i += 2; continue; }
      if (ch !== "\n" && control(s.charCodeAt(i))) fail("control character in a string");
      out += ch; i++;
    }
  }

  function literalString() {
    if (s.startsWith("'''", i)) {
      i += 3;
      newline();
      let out = "";
      for (;;) {
        if (i >= s.length) fail("unterminated string");
        if (s.startsWith("'''", i)) return out + closeMulti("'");
        if (s[i] === "\r" && s[i + 1] === "\n") { out += "\r\n"; i += 2; continue; }
        if (s[i] !== "\n" && control(s.charCodeAt(i))) fail("control character in a string");
        out += s[i++];
      }
    }
    i++;
    const start = i;
    while (i < s.length && s[i] !== "'") {
      if (s[i] === "\n" || control(s.charCodeAt(i))) fail("control character in a string");
      i++;
    }
    if (i >= s.length) fail("unterminated string");
    return s.slice(start, i++);
  }

  function scalar() {
    const start = i;
    while (i < s.length && /[0-9A-Za-z_+\-.:]/.test(s[i])) i++;
    let tok = s.slice(start, i);
    if (DATE.test(tok) && s[i] === " " && /^\d{2}:\d{2}:\d{2}/.test(s.slice(i + 1, i + 9))) { // a date-time with a space
      const j = i + 1;
      i = j;
      while (i < s.length && /[0-9.:Zz+-]/.test(s[i])) i++;
      tok = `${tok} ${s.slice(j, i)}`;
    }
    if (tok === "true") return true;
    if (tok === "false") return false;
    if (INT.test(tok) || HEX.test(tok) || OCT.test(tok) || BIN.test(tok)) {
      const n = Number(tok.replaceAll("_", ""));
      if (!Number.isSafeInteger(n)) fail("integer out of range");
      return n;
    }
    if (FLOAT.test(tok)) return Number(tok.replaceAll("_", ""));
    if (SPECIAL.test(tok)) return tok.endsWith("nan") ? NaN : tok.startsWith("-") ? -Infinity : Infinity;
    if (DATE.test(tok) || TIME.test(tok) || DATETIME.test(tok)) return tok;
    return fail("expected a value");
  }

  function value(depth) {
    if (depth > MAX_DEPTH) fail("nested too deeply");
    const c = peek();
    if (c === '"') return basicString();
    if (c === "'") return literalString();
    if (c === "[") return array(depth);
    if (c === "{") return inlineTable(depth);
    return scalar();
  }

  function array(depth) {
    i++;
    const out = [];
    for (;;) {
      blank();
      if (peek() === "]") { i++; break; }
      out.push(value(depth + 1));
      blank();
      if (peek() === ",") { i++; continue; }
      if (peek() === "]") { i++; break; }
      fail("expected , or ] in an array");
    }
    closed.add(out);
    return out;
  }

  function inlineTable(depth) {
    i++;
    const out = {};
    ws();
    if (peek() === "}") { i++; closed.add(out); return out; }
    for (;;) {
      keyValue(out, depth + 1);
      ws();
      if (peek() === ",") { i++; ws(); if (peek() === "}") fail("trailing comma in an inline table"); continue; }
      if (peek() === "}") { i++; break; }
      fail("expected , or } in an inline table");
    }
    closed.add(out);
    return out;
  }

  /* key = value, into `table`. */
  function keyValue(table, depth) {
    const k = key();
    if (peek() !== "=") fail("expected =");
    i++; ws();
    assign(table, k, value(depth));
  }

  function assign(table, keys, v) {
    let t = table;
    for (const k of keys.slice(0, -1)) {
      if (!own(t, k)) { const n = {}; dotted.add(n); set(t, k, n); t = n; continue; }
      const next = t[k];
      if (!isObj(next) || closed.has(next) || !dotted.has(next)) fail("key already defined");
      t = next;
    }
    const last = keys[keys.length - 1];
    if (own(t, last)) fail("key already defined");
    set(t, last, v);
  }

  function header() {
    const arrayTable = s.startsWith("[[", i);
    i += arrayTable ? 2 : 1;
    const keys = key();
    if (arrayTable ? !s.startsWith("]]", i) : peek() !== "]") fail("expected the end of the table header");
    i += arrayTable ? 2 : 1;
    let t = root;
    for (const k of keys.slice(0, -1)) {
      if (!own(t, k)) { const n = {}; set(t, k, n); t = n; continue; }
      let next = t[k];
      if (Array.isArray(next)) { if (!arrayTables.has(next)) fail("key already defined"); next = next[next.length - 1]; }
      if (!isObj(next) || closed.has(next)) fail("key already defined");
      t = next;
    }
    const last = keys[keys.length - 1];
    if (arrayTable) {
      if (!own(t, last)) { const a = []; arrayTables.add(a); set(t, last, a); }
      const a = t[last];
      if (!Array.isArray(a) || !arrayTables.has(a)) fail("key already defined");
      const n = {}; explicit.add(n); a.push(n); current = n;
    } else {
      if (own(t, last)) {
        const n = t[last];
        if (!isObj(n) || closed.has(n) || explicit.has(n) || dotted.has(n)) fail("table already defined");
        explicit.add(n); current = n;
      } else { const n = {}; explicit.add(n); set(t, last, n); current = n; }
    }
    endOfLine();
  }

  for (;;) {
    blank();
    if (i >= s.length) break;
    if (peek() === "[") { header(); continue; }
    keyValue(current, 0);
    endOfLine();
  }
  return root;
}

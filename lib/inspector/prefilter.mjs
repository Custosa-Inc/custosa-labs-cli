/* A cheap, sound pre-check that lets the rules worker skip a rule that cannot match a file.
 *
 * @ast-grep/napi compiles a rule object on every findAll call (there is no precompiled matcher), and compiling every
 * applicable rule costs about half a second per file whatever the file holds. Most rules can't match most files: a
 * pattern only matches code whose named leaves (identifiers, property names, keywords the grammar names) have the
 * same text as the pattern's, so a rule whose pattern names `console` and `log` can't match a file in which neither
 * word appears.
 *
 * requirement(rule, lang) -> a formula over words: true (no constraint), {w: word}, {and: [...]} or {or: [...]}.
 * satisfied(formula, new FileText(text)) -> boolean. satisfiedOnce(formula, file, memo): the same, each word looked up
 * once per file (memo: a Map kept for that file).
 *
 * Soundness (a rule skipped here could never have matched):
 * - pattern: every named leaf of the pattern (of the selected node, for the object form) must match a target leaf of
 *   the same text; that text is in the file (checked as plain containment, never as a whole word). Only leaves that look like a plain ASCII word are used
 *   (metavariables, strings with spaces, comments and anything else give no constraint), and none under the
 *   signature strictness, which ignores text.
 * - all: every sub-rule must match (and); any: one must (or); not, kind, regex, field, stopBy: no constraint.
 * - inside, has, precedes, follows: the related node must exist in the same file, so its sub-rule's words are needed.
 * - Any failure to analyse gives true (the rule runs). */
import { expandoChar, parseSync } from "./parse.mjs";

const WORD = /^[A-Za-z_][A-Za-z0-9_]*$/;
const RELATIONAL = ["inside", "has", "precedes", "follows"];
const isMap = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

/** What satisfied() needs to know about one file's text, worked out lazily once per file. */
export class FileText {
  constructor(text) { this.text = text; this._lower = null; }
  get lower() { return (this._lower ??= this.text.toLowerCase().replace(/\u017f/g, "s")); }
}

// A metavariable ($A, $$B, $$$C, $_, $$$), written with the language's expando: the subtree it stands for is free.
const METAVAR = /^\$(?:\$\$?)?(?:[A-Z_][A-Z0-9_]*)?$/;
function leafWords(node, out, expando) {
  const own = expando === "$" ? node.text() : node.text().split(expando).join("$");
  if (METAVAR.test(own)) return out;
  const kids = node.children();
  if (kids.length === 0) {
    if (node.isNamed() && !/comment/.test(node.kind())) {
      const t = node.text();
      if (WORD.test(t)) out.add(t);
    }
    return out;
  }
  for (const c of kids) leafWords(c, out, expando);
  return out;
}

function patternRequirement(p, lang) {
  let source, selector = null;
  if (typeof p === "string") source = p;
  else if (isMap(p) && typeof p.context === "string") {
    if (p.strictness === "signature") return true;
    source = p.context; selector = typeof p.selector === "string" ? p.selector : null;
  } else return true;
  const expando = expandoChar(lang);
  let node = parseSync(lang, source.split("$").join(expando)).root();
  if (selector) node = node.find({ rule: { kind: selector } });
  if (!node) return true;
  const words = [...leafWords(node, new Set(), expando)];
  return words.length ? { and: words.map((w) => ({ w })) } : true;
}

/* --- regex: the literal text a match must contain -------------------------------------------------------------------
 * ast-grep tests a rule's `regex` (Rust regex syntax) against the node's own text, a substring of the file, so any
 * literal run every match of the regex must contain is in the file too. regexRequirement returns a formula over
 * {lit, ci}: literal runs of two or more ASCII characters joined by and (a sequence) and or (an alternation); a
 * quantifier that allows zero repeats, a class, a dot, an escape class (\w, \d, \s, \p{..}), an anchor or a word
 * boundary only breaks a run. Case-insensitive (an `i` flag anywhere): the run is looked for in the lowercased text,
 * with U+017F (long s) as s and U+212A (Kelvin) as k, the two non-ASCII letters Unicode folds to ASCII. Verbose mode
 * (`x`) or anything unexpected gives no constraint. */
const ESCAPED_LITERAL = { t: "\t", n: "\n", r: "\r", f: "\f", v: "\v", a: "\x07" };
const LITERAL_ESCAPES = "\\.+*?()|[]{}^$#&-~/\"'`=:!,@%;_";

function regexRequirement(src) {
  if (typeof src !== "string") return true;
  const flags = [...src.matchAll(/\(\?([a-zA-Z-]+)[:)]/g)].map((m) => m[1].split("-")[0]).join("");
  if (/x/.test(flags)) return true;
  const ci = /i/.test(flags);
  let i = 0;
  const fail = () => { throw new Error("unparsed"); };
  // -> {f: formula, lit: string | null}: lit is the item's exact text when it is one literal character.
  function atom() {
    const c = src[i];
    if (c === "(") {
      i++;
      if (src[i] === "?") {
        const m = /^\?([a-zA-Z-]*)(:|\))/.exec(src.slice(i));
        if (!m) fail();
        i += m[0].length;
        if (m[2] === ")") return { f: true, lit: null, empty: true }; // a flag group: matches nothing
      }
      const f = alternation();
      if (src[i] !== ")") fail();
      i++;
      return { f, lit: null };
    }
    if (c === "[") { skipClass(); return { f: true, lit: null }; }
    if (c === "\\") {
      const d = src[i + 1];
      if (d === undefined) fail();
      if (d === "x") {
        const m = /^\\x(?:\{([0-9A-Fa-f]{1,6})\}|([0-9A-Fa-f]{2}))/.exec(src.slice(i));
        if (!m) fail();
        i += m[0].length;
        const ch = String.fromCodePoint(parseInt(m[1] ?? m[2], 16));
        return { f: true, lit: ch.charCodeAt(0) < 128 ? ch : null };
      }
      if (d === "p" || d === "P") {
        const m = /^\\[pP](?:\{[^}]*\}|[A-Za-z])/.exec(src.slice(i));
        if (!m) fail();
        i += m[0].length;
        return { f: true, lit: null };
      }
      i += 2;
      if (/[dDwWsS]/.test(d)) return { f: true, lit: null };
      // Zero-width: word boundaries (\b, \B, and Rust's \< and \>, start and end of a word) and text anchors.
      if (/[bBAzZ<>]/.test(d)) return { f: true, lit: null, empty: true };
      if (ESCAPED_LITERAL[d]) return { f: true, lit: ESCAPED_LITERAL[d] };
      // Only an escaped punctuation character Rust reads as itself is a literal; any other escape (a letter, a digit,
      // a space, anything non-ASCII) is one this reader doesn't know, and the regex then requires nothing.
      if (LITERAL_ESCAPES.includes(d)) return { f: true, lit: d };
      fail();
    }
    if (c === "^" || c === "$") { i++; return { f: true, lit: null, empty: true }; }
    if (c === ".") { i++; return { f: true, lit: null }; }
    if (c === ")" || c === "|" || c === undefined) fail();
    if ("*+?{".includes(c)) fail();
    i++;
    return { f: true, lit: c.charCodeAt(0) < 128 ? c : null };
  }
  function skipClass() {
    i++; // [
    if (src[i] === "^") i++;
    if (src[i] === "]") i++;
    let depth = 1;
    while (i < src.length && depth > 0) {
      if (src[i] === "\\") { i += 2; continue; }
      if (src[i] === "[") { depth++; i++; continue; }
      if (src[i] === "]") { depth--; i++; continue; }
      i++;
    }
    if (depth !== 0) fail();
  }
  // -> minimum repeat count, or null when there is no quantifier
  function quantifier() {
    const c = src[i];
    let min = null;
    if (c === "*" || c === "?") { i++; min = 0; }
    else if (c === "+") { i++; min = 1; }
    else if (c === "{") {
      const m = /^\{(\d+)(,\d*)?\}/.exec(src.slice(i));
      if (!m) return null; // a literal brace
      i += m[0].length;
      min = Number(m[1]);
    } else return null;
    if (src[i] === "?" || src[i] === "+") i++; // lazy or possessive
    return min;
  }
  function sequence() {
    const and = [];
    let run = "";
    const flush = () => { if (run.length >= 2) and.push({ lit: run, ci }); run = ""; };
    while (i < src.length && src[i] !== "|" && src[i] !== ")") {
      const a = atom();
      const min = quantifier();
      if (min === null) {
        if (a.lit !== null) { run += a.lit; continue; }
        if (a.empty) { flush(); continue; }
        flush(); and.push(a.f); continue;
      }
      // A quantified item: required only when it must repeat at least once; the run ends either way.
      if (min >= 1 && a.lit !== null) run += a.lit;
      flush();
      if (min >= 1 && a.lit === null) and.push(a.f);
    }
    flush();
    return { and };
  }
  function alternation() {
    const or = [sequence()];
    while (src[i] === "|") { i++; or.push(sequence()); }
    return or.length === 1 ? or[0] : { or };
  }
  try {
    const f = alternation();
    if (i !== src.length) return true;
    return f;
  } catch { return true; }
}

function simplify(f) {
  if (f === true || f.w || f.lit) return f;
  if (f.and) {
    const parts = f.and.map(simplify).filter((x) => x !== true);
    return parts.length === 0 ? true : parts.length === 1 ? parts[0] : { and: parts };
  }
  const parts = f.or.map(simplify);
  return parts.some((x) => x === true) ? true : parts.length === 1 ? parts[0] : { or: parts };
}

function ruleRequirement(obj, lang) {
  if (!isMap(obj)) return true;
  const and = [];
  if ("pattern" in obj) and.push(patternRequirement(obj.pattern, lang));
  if ("regex" in obj) and.push(regexRequirement(obj.regex));
  for (const r of RELATIONAL) if (isMap(obj[r])) and.push(ruleRequirement(obj[r], lang));
  if (Array.isArray(obj.all)) for (const sub of obj.all) and.push(ruleRequirement(sub, lang));
  if (Array.isArray(obj.any) && obj.any.length) and.push({ or: obj.any.map((sub) => ruleRequirement(sub, lang)) });
  return { and };
}

/** The words a file must hold for the rule to match anything in it (see the header). */
export function requirement(rule, lang) {
  try { return simplify(ruleRequirement(rule, lang)); } catch { return true; }
}

/** Whether a file (a FileText) can hold a match of a rule with this requirement. */
export function satisfied(f, file) {
  if (f === true) return true;
  // Plain containment, not whole words: a word can sit right after an escape in a string ("\nusers" holds users).
  if (f.w) return file.text.includes(f.w);
  if (f.lit) return f.ci ? file.lower.includes(f.lit.toLowerCase()) : file.text.includes(f.lit);
  if (f.and) return f.and.every((x) => satisfied(x, file));
  return f.or.some((x) => satisfied(x, file));
}

/** satisfied() with each word and literal looked up at most once per file: memo is a Map kept for that file. */
export function satisfiedOnce(f, file, memo) {
  if (f === true) return true;
  if (f.w || f.lit) {
    const k = f.w ? `w${f.w}` : `${f.ci ? "i" : "l"}${f.lit}`;
    let v = memo.get(k);
    if (v === undefined) { v = satisfied(f, file); memo.set(k, v); }
    return v;
  }
  if (f.and) return f.and.every((x) => satisfiedOnce(x, file, memo));
  return f.or.some((x) => satisfiedOnce(x, file, memo));
}

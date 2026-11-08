/* The free-text screen, written from the evaluator's screen design (docs/screen-engine.md), with its app/screen.py as
 * the reference for every reading the spec leaves open.
 *
 *   screenRaw(raw, snapshotIds, rules, previous?) -> {decision: "pass" | "refuse", hits: [{rule, start, end}]}
 *
 * refStep turns the raw note's backtick spans into `<ref:N>` placeholders (§3); screen screens the result (§2). Every
 * list, word and number comes from the rule file (contracts/screen_rules.json, §12); a hit may name only a rule the
 * file lists. The screen is pure: no clock, environment, locale or I/O, and no runtime Unicode property. The one
 * Unicode call is NFKC (§4 step 1); every other character test is an ASCII range or a rule-file set (§13 item 7).
 *
 * Offsets count code points (§4 step 3), end exclusive. JavaScript strings count UTF-16 units, so after normalising,
 * each code point above U+FFFF is read as U+FFFD: every rule below reads only ASCII classes and rule-file sets, which
 * treat any two such code points alike, and a unit is then a code point. The ref step's own hits, which come before
 * any normalising, count code points of the raw note.
 *
 * Regexes read ASCII only: \s is written [ \t\n\r\f\v], \w [A-Za-z0-9_], and case-insensitive matching uses the i
 * flag without u, which never folds a non-ASCII letter to an ASCII one (§13 item 7). */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";

export const NAME_SETS = ["safe_words", "personal_names", "ambiguous_names"];
export const SAFE = "SAFE", NAME = "NAME", AMBIG = "AMBIG", OOV = "OOV";
export const LOOKBACK_JOIN = " ; ";
const PLACEHOLDER_OPEN = "<ref:";
const PLACEHOLDER = /<ref:([0-9]+)>/g;
const PLACEHOLDER_AT = /<ref:([0-9]+)>/y;
const REF_PART_SEPS = /[._/:-]/;
const WHITESPACE = " \t";
const REF_RULES = new Set(["placeholder_spoof", "backtick_shape", "unknown_backtick_ref"]);

export class RuleFileError extends Error {}

/* ---------------------------------------------------------------- the rule file */

/** The parsed rule file from its JSON and its three name sets (each an iterable of words). Lists are lower-case
 * Sets; safePhrases are word arrays. */
export function rulesFromDoc(doc, sets) {
  const ranges = doc.unicode_ranges.map(([a, b]) => [Number(a), Number(b)]).sort((x, y) => x[0] - y[0] || x[1] - y[1]);
  const lists = {};
  for (const [k, v] of Object.entries(doc.lists)) {
    if (!NAME_SETS.includes(k) && Array.isArray(v)) lists[k] = new Set(v.map((w) => String(w).toLowerCase()));
  }
  const named = Object.fromEntries(NAME_SETS.map((k) => [k, new Set([...sets[k]].map((w) => String(w).toLowerCase()))]));
  return {
    version: doc.version, unicodeVersion: doc.unicode_version,
    rangeStarts: ranges.map((r) => r[0]), rangeEnds: ranges.map((r) => r[1]),
    charMap: new Map(Object.entries(doc.char_map)), allowNonAscii: new Set(doc.allow_non_ascii),
    leet: new Map(Object.entries(doc.leet)), lists,
    safePhrases: (doc.lists.safe_phrases ?? []).map((p) => p.toLowerCase().split(" ")),
    limits: { ...doc.limits }, ruleIds: new Set(doc.rules.map((r) => r.id)),
    safeWords: named.safe_words, personalNames: named.personal_names, ambiguousNames: named.ambiguous_names,
  };
}

/** The rule file at path, with its name sets read from the newline files beside it (§12). read(path) gives a file's
 * text; a caller may pass one that checks the bytes first. */
export function loadRules(path, read = (p) => readFileSync(p, "utf8")) {
  const doc = JSON.parse(read(path));
  const sets = {};
  for (const name of NAME_SETS) {
    const value = doc.lists[name];
    sets[name] = typeof value === "string"
      ? read(join(dirname(path), value)).split("\n").filter(Boolean) : value;
  }
  return rulesFromDoc(doc, sets);
}

function assigned(rules, cp) {
  let lo = 0, hi = rules.rangeStarts.length; // the last start <= cp (bisect_right - 1)
  while (lo < hi) { const mid = (lo + hi) >> 1; if (rules.rangeStarts[mid] <= cp) lo = mid + 1; else hi = mid; }
  const i = lo - 1;
  return i >= 0 && cp <= rules.rangeEnds[i];
}

function lookup(rules, lower) {
  if (rules.safeWords.has(lower)) return SAFE;
  if (rules.personalNames.has(lower)) return NAME;
  if (rules.ambiguousNames.has(lower)) return AMBIG;
  return OOV;
}

const list = (rules, name) => rules.lists[name] ?? new Set();
const lim = (rules, name, fallback) => rules.limits[name] ?? fallback;

/* ---------------------------------------------------------------- hits */

function hit(rules, rule, start, end) {
  if (!rules.ruleIds.has(rule)) throw new RuleFileError(`the rule file does not list ${rule}`);
  return { rule, start, end };
}

function result(hits) {
  const unique = new Map();
  for (const h of hits) unique.set(`${h.start}\u0000${h.rule}\u0000${h.end}`, h);
  const ordered = [...unique.values()].sort((a, b) =>
    a.start - b.start || (a.rule < b.rule ? -1 : a.rule > b.rule ? 1 : 0) || a.end - b.end);
  return { decision: ordered.length ? "refuse" : "pass", hits: ordered };
}

/* ---------------------------------------------------------------- ASCII character classes (§13 item 7) */

const isUpper = (c) => c >= "A" && c <= "Z" && c.length === 1;
const isLower = (c) => c >= "a" && c <= "z" && c.length === 1;
const isDigit = (c) => c >= "0" && c <= "9" && c.length === 1;
const isAlnum = (c) => isUpper(c) || isLower(c) || isDigit(c);
export const asciiLower = (s) => s.replace(/[A-Z]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 32));
const allDigits = (s) => [...s].every(isDigit);
const someDigit = (s) => [...s].some(isDigit);
const cpLength = (s) => { let n = 0; for (const _ of s) n++; return n; };
// After normalising: each code point above U+FFFF read as U+FFFD, so a UTF-16 unit is a code point (see the header).
const flatten = (s) => s.replace(/[\uD800-\uDBFF][\uDC00-\uDFFF]/g, "\uFFFD");

/* ---------------------------------------------------------------- §3 the ref step */

/** {text, refs, hits}. With any hit, the text is the raw note and refs is empty. Offsets count raw code points. */
export function refStep(raw, snapshotIds, rules) {
  const cps = Array.from(raw);
  const flat = cps.map((c) => (c.length > 1 ? "\uFFFD" : c)).join("");
  const slice = (a, b) => cps.slice(a, b).join("");
  const hits = [];
  for (let at = flat.indexOf(PLACEHOLDER_OPEN); at >= 0; at = flat.indexOf(PLACEHOLDER_OPEN, at + 1)) {
    hits.push(hit(rules, "placeholder_spoof", at, at + PLACEHOLDER_OPEN.length));
  }
  const ticks = [];
  for (let i = 0; i < flat.length; i++) if (flat[i] === "`") ticks.push(i);
  if (ticks.length % 2) return { text: raw, refs: [], hits: [...hits, hit(rules, "backtick_shape", 0, cps.length)] };
  const known = new Set(snapshotIds);
  const pairs = [];
  for (let i = 0; i < ticks.length; i += 2) pairs.push([ticks[i], ticks[i + 1]]);
  for (const [a, b] of pairs) {
    const span = slice(a + 1, b);
    if (!span || [...span].some((c) => WHITESPACE.includes(c))) hits.push(hit(rules, "backtick_shape", a, b + 1));
    else if (!known.has(span)) hits.push(hit(rules, "unknown_backtick_ref", a, b + 1));
  }
  if (hits.length) return { text: raw, refs: [], hits };
  const out = [], refs = [];
  let last = 0;
  pairs.forEach(([a, b], n) => {
    out.push(slice(last, a), `<ref:${n}>`);
    refs.push(slice(a + 1, b));
    last = b + 1;
  });
  out.push(slice(last, cps.length));
  return { text: out.join(""), refs, hits: [] };
}

/** The hotwords among a ref's name parts, split at . _ / : and - (§3.2 item 5), in order, once each. */
export function refHotwords(ref, rules) {
  const hot = list(rules, "hotwords");
  const seen = [];
  for (const part of asciiLower(ref).split(REF_PART_SEPS)) if (hot.has(part) && !seen.includes(part)) seen.push(part);
  return seen;
}

/* ---------------------------------------------------------------- §5.1 whole-note refusals and §4 normalisation */

const LINE_ENDS = new Set([0x09, 0x0a, 0x0d]); // tab, newline and carriage return are text; char_map turns \n and \r into spaces
const BIDI = new Set([0x061c, 0x200e, 0x200f, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069]);
/** A C0 or C1 control other than tab, newline and carriage return, a surrogate, or a bidi control. */
const control = (cp) => (cp < 0x20 && !LINE_ENDS.has(cp)) || (cp >= 0x7f && cp <= 0x9f) || (cp >= 0xd800 && cp <= 0xdfff)
  || BIDI.has(cp);

function wholeNote(text, rules) {
  const cps = [...text].map((c) => c.codePointAt(0));
  const found = [];
  if (cps.some(control)) found.push(hit(rules, "control_char", 0, cps.length));
  if (cps.some((cp) => !assigned(rules, cp))) found.push(hit(rules, "non_ascii_token", 0, cps.length));
  return found;
}

/** NFKC, then char_map code point by code point (§4). */
export function normalise(text, rules) {
  return Array.from(text.normalize("NFKC"), (c) => (rules.charMap.has(c) ? rules.charMap.get(c) : c)).join("");
}

const countOf = (s, sub) => { let n = 0; for (let i = s.indexOf(sub); i >= 0; i = s.indexOf(sub, i + 1)) n++; return n; };

/** A placeholder the ref step did not make: normalising made one, or one names no ref, or they are out of order. */
function spoofed(before, after, refs) {
  if (countOf(after, PLACEHOLDER_OPEN) !== countOf(before, PLACEHOLDER_OPEN)) return true;
  const found = [...after.matchAll(PLACEHOLDER)].map((m) => Number(m[1]));
  return countOf(after, PLACEHOLDER_OPEN) !== found.length || found.length !== refs.length || found.some((n, i) => n !== i);
}

/** Each run between whitespace that holds a code point above U+007F outside the allow-list (§5.2). */
function nonAscii(text, rules) {
  const found = [];
  const n = text.length;
  let i = 0;
  while (i < n) {
    if (WHITESPACE.includes(text[i])) { i++; continue; }
    let j = i, bad = false;
    while (j < n && !WHITESPACE.includes(text[j])) {
      bad = bad || (text.charCodeAt(j) > 0x7f && !rules.allowNonAscii.has(text[j]));
      j++;
    }
    if (bad) found.push(hit(rules, "non_ascii_token", i, j));
    i = j;
  }
  return found;
}

/* ---------------------------------------------------------------- §6 tokens and §7 tags */

/** Split at a lower-to-upper change and at a letter-digit change (§6). */
function splitSubs(text, start) {
  const out = [];
  let a = 0;
  for (let i = 1; i < text.length; i++) {
    const p = text[i - 1], c = text[i];
    if ((isLower(p) && isUpper(c)) || isDigit(p) !== isDigit(c)) {
      out.push({ text: text.slice(a, i), start: start + a, end: start + i, tag: OOV });
      a = i;
    }
  }
  out.push({ text: text.slice(a), start: start + a, end: start + text.length, tag: OOV });
  return out;
}

/** A token of letters and digits that folds, by the leet map, to a NAME of leet_min_letters letters or more (§7). */
function leetName(lower, rules) {
  if (!someDigit(lower) || ![...lower].some(isLower)) return false;
  const folded = [...lower].map((c) => (rules.leet.has(c) ? rules.leet.get(c) : c)).join("");
  return [...folded].filter(isLower).length >= lim(rules, "leet_min_letters", 4)
    && (rules.personalNames.has(folded) || rules.ambiguousNames.has(folded));
}

function tagOf(lower, rules) {
  const tag = lookup(rules, lower);
  if (tag !== NAME && tag !== AMBIG && leetName(lower, rules)) return NAME;
  return tag;
}

const capitalised = (t) => t.kind === "word" && isUpper(t.text[0]);

/** The normalised text's tokens, each with its separator, tag, sub-tokens and joined form (§6, §7). */
export function tokens(text, refs, rules) {
  const out = [];
  let i = 0, last = 0;
  const n = text.length;
  while (i < n) {
    PLACEHOLDER_AT.lastIndex = i;
    const m = PLACEHOLDER_AT.exec(text);
    if (m) {
      const k = Number(m[1]);
      const end = i + m[0].length;
      out.push({ text: m[0], start: i, end, kind: "ref", sep: text.slice(last, i), ref: k,
        hotwords: k < refs.length ? refHotwords(refs[k], rules) : [], lower: "", tag: OOV, subs: [], joined: null, joinedTag: null });
      i = last = end;
      continue;
    }
    if (isAlnum(text[i])) {
      let j = i;
      while (j < n && isAlnum(text[j])) j++;
      const word = text.slice(i, j), low = asciiLower(word);
      const subs = splitSubs(word, i);
      for (const s of subs) s.tag = tagOf(asciiLower(s.text), rules);
      out.push({ text: word, start: i, end: j, kind: "word", sep: text.slice(last, i), ref: null, hotwords: [], lower: low,
        tag: tagOf(low, rules), subs, joined: null, joinedTag: null });
      i = last = j;
      continue;
    }
    i++;
  }
  phrases(out, rules);
  for (let k = 0; k + 1 < out.length; k++) {
    const a = out[k], b = out[k + 1];
    if (a.kind === "word" && b.kind === "word" && (b.sep === "'" || b.sep === "-")) {
      a.joined = a.lower + b.lower;
      a.joinedTag = tagOf(a.joined, rules);
    }
  }
  return out;
}

/** A multi-word safe phrase (stevens johnson) tags each of its tokens SAFE, joined by spaces, tabs or hyphens. */
function phrases(toks, rules) {
  for (const phrase of rules.safePhrases) {
    const k = phrase.length;
    for (let i = 0; i + k <= toks.length; i++) {
      const run = toks.slice(i, i + k);
      if (run.every((t, x) => t.kind === "word" && t.lower === phrase[x])
        && run.slice(1).every((t) => t.sep && [...t.sep].every((c) => " \t-".includes(c)))) {
        for (const t of run) { t.tag = SAFE; for (const s of t.subs) s.tag = SAFE; }
      }
    }
  }
}

/** Runs of two or more word tokens joined by _ or . with no whitespace (first_name, dr_jane_smith), §6. */
export function identifiers(toks) {
  const out = [];
  let run = [];
  for (const t of toks) {
    if (run.length && t.kind === "word" && t.sep && [...t.sep].every((c) => "_.".includes(c))) { run.push(t); continue; }
    if (run.length > 1) out.push(run);
    run = t.kind === "word" ? [t] : [];
  }
  if (run.length > 1) out.push(run);
  return out;
}

/* ---------------------------------------------------------------- §2 the screen */

/** Screen a note after the ref step (§2). refs are the spans its placeholders stand for, in order. */
export function screen(text, snapshotIds, rules, refs = []) {
  const early = wholeNote(text, rules);
  if (early.length) return result(early);
  const norm = normalise(text, rules);
  if (spoofed(text, norm, refs)) return result([hit(rules, "placeholder_spoof", 0, cpLength(norm))]);
  const flat = flatten(norm);
  const hits = nonAscii(flat, rules);
  const note = { text: flat, refs: [...refs], snapshotIds: new Set(snapshotIds), toks: tokens(flat, refs, rules), claimed: [],
    hexy: [] }; // hexy: the UUID and hash claims, which a secret reads past
  for (const step of STEPS) hits.push(...step(note, rules));
  return result(hits);
}

/** The ref step, then the screen: what the server runs on a note as sent, and the vectors' entry point.
 * previous is the session's previous accepted note, as sent (§11). It is screened in front of this one, joined by
 * " ; ", and only a hit that ends inside this note counts. Offsets are this note's own; a hit that starts in the
 * previous note starts at 0. */
export function screenRaw(raw, snapshotIds, rules, previous = null) {
  if (previous === null || previous === undefined) {
    const { text, refs, hits } = refStep(raw, snapshotIds, rules);
    return hits.length ? result(hits) : screen(text, snapshotIds, rules, refs);
  }
  const own = screenRaw(raw, snapshotIds, rules);
  if (own.hits.some((h) => REF_RULES.has(h.rule))) return own;
  const { text, refs, hits } = refStep(previous + LOOKBACK_JOIN + raw, snapshotIds, rules);
  if (hits.length) return own;
  const prevText = refStep(previous, snapshotIds, rules).text;
  const offset = cpLength(normalise(prevText + LOOKBACK_JOIN, rules));
  const both = screen(text, snapshotIds, rules, refs);
  const moved = both.hits.filter((h) => h.end > offset)
    .map((h) => ({ rule: h.rule, start: Math.max(0, h.start - offset), end: h.end - offset }));
  return result([...own.hits, ...moved]);
}

/* ---------------------------------------------------------------- §8 technical passes */
// A span a pass claims is read by no value rule. The passes run in §8's order. Regexes here read the normalised text.

const B = "(?<![A-Za-z0-9])";
const E = "(?![A-Za-z0-9])";
const rx = (source, flags = "") => new RegExp(source, `g${flags}`);
const UUID = rx(`${B}[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}${E}`);
const HEX_FULL = /^[0-9a-fA-F]+$/;
const VERSION = rx(`${B}(?:v[0-9]+(?:\\.[0-9]+)*|[0-9]+(?:\\.[0-9]+){2,})(?:-[A-Za-z0-9]+(?:\\.[A-Za-z0-9]+)*)?(?![A-Za-z0-9.])`);
const FOUR_PART_FULL = /^[0-9]+(?:\.[0-9]+){3}$/;
const AFTER_VERSION = rx(`${B}versions?[ \\t:=]+([0-9]+(?:[.-][0-9]+)*)${E}`, "id");
const PORTS = rx(`${B}ports?[ \\t:=]+([0-9]+(?:[ \\t,]+[0-9]+)*)${E}`, "id");
const HOST_PORT = rx(`(?<=[A-Za-z0-9]):([0-9]{1,5})${E}`, "d");
const TYPE_SIZE = rx(`(?<![A-Za-z_])[A-Za-z_]+\\(([0-9]+(?:,[ \\t]*[0-9]+)?)\\)`, "d");
const STAMP = rx(`${B}(?:19|20)[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|3[01])(?:[01][0-9]|2[0-3])[0-5][0-9](?:[0-5][0-9])?${E}`);
const ISO_TIME = rx(`${B}[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}(?::[0-9]{2}(?:\\.[0-9]+)?)?(?:Z|[+-][0-9]{2}:?[0-9]{2})?${E}`);
const LOCAL_IP = rx(`${B}(?:0\\.0\\.0\\.0|127\\.0\\.0\\.1|255\\.255\\.255\\.255)(?:/[0-9]{1,2})?(?![0-9.])`);
const COUNTED = rx(`${B}([0-9]+(?:[.,][0-9]+)*)[ \\t]?([A-Za-z]+)${E}`, "d");
const DATE_SHAPE = rx("(?<![0-9])(?<![0-9][-/.])(?:[0-9]{4}[-/.][0-9]{1,2}[-/.][0-9]{1,2}|[0-9]{1,2}[-/.][0-9]{1,2}[-/.][0-9]{2,4})(?![0-9])(?![-/.][0-9])");
const CODE_AFTER = new RegExp(`[ \\t]*(?:code[ \\t]*)?[:#]?[ \\t]*([0-9A-Za-z]+(?:[-.][0-9A-Za-z]+)*)${E}`, "yid");
// validation.py _IPV6, read with ASCII \w
const IPV6 = rx("(?<![A-Za-z0-9_:])(?:(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,6}:(?:[0-9A-Fa-f]{1,4}:){0,5}[0-9A-Fa-f]{1,4})(?![A-Za-z0-9_:])");

const claim = (note, a, b) => { note.claimed.push([a, b]); };
const free = (note, a, b) => !note.claimed.some(([s, e]) => a < e && s < b);
const wordsOf = (note) => note.toks.filter((t) => t.kind === "word");
const all = (re, text) => { re.lastIndex = 0; return [...text.matchAll(re)]; };
const end = (m) => m.index + m[0].length;

/** A calendar date by integer arithmetic, years year_min to year_max (§9.2). */
function dateValid(y, m, d, rules) {
  if (!(lim(rules, "year_min", 1900) <= y && y <= lim(rules, "year_max", 2100)) || !(m >= 1 && m <= 12)) return false;
  const leap = y % 4 === 0 && (y % 100 !== 0 || y % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][m - 1];
  return d >= 1 && d <= days;
}

/** [year, month, day] of a date-shaped span, year first or last (month before day); a two-digit year reads 20xx up
 * to 30 and 19xx above. */
function dateParts(span) {
  const parts = span.split(/[-/.]/);
  if (parts.length !== 3) return null;
  const [a, b, c] = parts.map(Number);
  if (parts[0].length === 4) return [a, b, c];
  const year = parts[2].length === 4 ? c : (c <= 30 ? 2000 + c : 1900 + c);
  return [year, a, b];
}

/** A date by its shape that no calendar has (1900-02-29, 2023-04-31): a four-digit year in range, a month of 1 to 12
 * and a day of 1 to 31 that the month lacks. Other date-like digits (12-34-567, 1234-56-78) stay digits. */
function impossibleDate(span, rules) {
  const parts = dateParts(span);
  if (parts === null || !span.split(/[-/.]/).some((p) => p.length === 4)) return false;
  const [y, m, d] = parts;
  const inRange = lim(rules, "year_min", 1900) <= y && y <= lim(rules, "year_max", 2100);
  return inRange && m >= 1 && m <= 12 && d >= 1 && d <= 31 && !dateValid(y, m, d, rules);
}

function technicalPasses(note, rules) {
  const { text } = note, words = wordsOf(note);
  for (const t of note.toks) if (t.kind === "ref") claim(note, t.start, t.end);              // 1. placeholders
  for (const m of all(UUID, text)) {                                                        // 2. UUIDs
    claim(note, m.index, end(m));
    note.hexy.push([m.index, end(m)]);
  }
  const hashWords = list(rules, "hash_words");                                               // 3. hashes
  words.forEach((t, i) => {
    if (!HEX_FULL.test(t.text) || allDigits(t.text)) return;
    const near = words.slice(Math.max(0, i - 2), i).some((w) => hashWords.has(w.lower));
    if (t.text.length >= lim(rules, "hex_exempt_min", 32) || (near && t.text.length >= 7)) {
      claim(note, t.start, t.end);
      note.hexy.push([t.start, t.end]);
    }
  });
  const sqlWords = [...list(rules, "sqlstate_words")].map((w) => w.split(" "));              // 4. SQLSTATE
  words.forEach((t, i) => {
    if (t.text.length === 5 && sqlWords.some((p) => {
      const before = words.slice(Math.max(0, i - p.length), i).map((w) => w.lower);
      return before.length === p.length && before.every((w, k) => w === p[k]);
    })) claim(note, t.start, t.end);
  });
  for (const m of all(VERSION, text)) if (!FOUR_PART_FULL.test(m[0])) claim(note, m.index, end(m)); // 5. versions ...
  const ipv6 = all(IPV6, text).map((m) => [m.index, end(m)]);
  for (const re of [AFTER_VERSION, PORTS, HOST_PORT, TYPE_SIZE]) {
    for (const m of all(re, text)) {
      const [a, b] = m.indices[1];
      if (!ipv6.some(([s, e]) => s <= a && a < e)) claim(note, a, b);                        // an IPv6 group is no port
    }
  }
  for (const re of [STAMP, ISO_TIME, LOCAL_IP]) for (const m of all(re, text)) claim(note, m.index, end(m)); // ... 6.
  const counted = list(rules, "count_nouns");                                                // 7. counted numbers
  for (const m of all(COUNTED, text)) if (counted.has(asciiLower(m[2]))) claim(note, ...m.indices[1]);
  const numbers = list(rules, "number_words");                                               // one day, two rows
  for (let i = 0; i + 1 < words.length; i++) {
    const a = words[i], b = words[i + 1];
    if (numbers.has(a.lower) && counted.has(b.lower) && (b.sep === " " || b.sep === "\t")) claim(note, a.start, a.end);
  }
  const codeWords = list(rules, "clinical_code_words");                                      // a code beside its word
  for (const t of words) {
    if (!codeWords.has(t.lower)) continue;
    CODE_AFTER.lastIndex = t.end;
    const code = CODE_AFTER.exec(text);
    if (code) claim(note, ...code.indices[1]);
  }
  for (const m of all(DATE_SHAPE, text)) if (impossibleDate(m[0], rules)) claim(note, m.index, end(m)); // 9.
  issueRefs(note, rules);                                                                    // 10. issue references
  return [];
}

// An issue or change reference: #123 after a non-word character, or a number right after an issue word (issue 123,
// PR #12, closes #9). Its digits are claimed unless a hotword is near.
const ISSUE_HASH = rx("(?<![A-Za-z0-9_&#])#([0-9]+)(?![A-Za-z0-9]|[-./][0-9])", "d");

function issueRefs(note, rules) {
  const { toks } = note, window = lim(rules, "hotword_window", 10);
  const issueWords = list(rules, "issue_words");
  const at = new Map(toks.map((t, i) => [t.start, i]));
  const take = (i) => {
    if (!toks.slice(Math.max(0, i - window), i + window + 1).some((t) => hot(t, rules))) claim(note, toks[i].start, toks[i].end);
  };
  for (const m of all(ISSUE_HASH, note.text)) if (at.has(m.indices[1][0])) take(at.get(m.indices[1][0]));
  for (let i = 0; i + 1 < toks.length; i++) {
    const t = toks[i], n = toks[i + 1], after = toks[i + 2] ?? null;
    const grouped = after !== null && after.kind === "word" && ["-", ".", "/"].includes(after.sep) && isDigit(after.text[0]);
    if (t.kind === "word" && issueWords.has(t.lower) && allDigitToken(n) && n.sep && strip(n.sep, " \t#:") === "" && !grouped) {
      take(i + 1);
    }
  }
}

/* ---------------------------------------------------------------- §9.1 secrets */
// secret_prefix and its kin are core's detectors (validation.py _SECRET_PATTERNS), read with ASCII classes and named
// by the rule they stand for.

const SECRET_RULE = { pem_block: "pem_header", url_credentials: "user_pass_at_host",
  credentials_without_scheme: "user_pass_at_host", password_assignment: "credential_assignment",
  aws_secret_access_key: "credential_assignment" };
const NS = " \\t\\n\\r\\f\\v"; // Python's ASCII \s, inside a class
const START = "(?<![A-Za-z0-9_-])";
const UPPER_IN_RUN = "(?=[A-Za-z0-9]*[A-Z])";
const UPPER_IN_TAIL = "(?=[A-Za-z0-9_-]*[A-Z])";
const HEX_BODY = "(?:[a-z0-9]{1,8}-){0,3}(?=[0-9a-f]{0,31}[0-9])[0-9a-f]{32,}";
const TOKEN = `[^${NS}/@:="'\`()<>,;]`;
const PASSWORD = `[^${NS}@:"'\`()<>,;]`;
const PASSWORD_NO_SLASH = `[^${NS}/@:"'\`()<>,;]`;
const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\/-]/g, "\\$&");
function shape(label, markers, source, flags = "") {
  const alternation = `(?:${markers.map(escapeRe).join("|")})`;
  return { label, markers, re: rx(source.replace("<M>", alternation), flags) };
}
const SECRET_PATTERNS = [
  shape("jwt", ["eyJ"], `${START}<M>[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*`),
  shape("supabase_secret", ["sb_secret_"], `${START}<M>${UPPER_IN_TAIL}[A-Za-z0-9_-]{20,}`),
  shape("sk_key", ["sk-"], `${START}<M>(?:${UPPER_IN_TAIL}[A-Za-z0-9_-]{20,}|${HEX_BODY})`),
  shape("stripe_key", ["sk_live_", "sk_test_", "rk_live_", "rk_test_"], `${START}<M>${UPPER_IN_RUN}[A-Za-z0-9]{16,}`),
  shape("stripe_webhook_secret", ["whsec_"], `${START}<M>${UPPER_IN_RUN}[A-Za-z0-9]{16,}`),
  shape("phisc_token", ["phisc_"], `${START}<M>${UPPER_IN_TAIL}[A-Za-z0-9_-]{30,}`),
  shape("aws_access_key_id", ["AKIA", "ASIA"], "(?<![A-Za-z0-9])<M>[A-Z0-9]{16}(?![A-Za-z0-9])"),
  shape("github_token", ["ghp_", "gho_", "ghs_", "ghu_", "ghr_"], `${START}<M>${UPPER_IN_RUN}[A-Za-z0-9]{30,}`),
  shape("github_pat", ["github_pat_"], `${START}<M>(?:[A-Za-z0-9]{22}_[A-Za-z0-9]{59}|${UPPER_IN_RUN}[A-Za-z0-9]{20,})`),
  shape("url_credentials", ["://"], `<M>[^${NS}/@:]*:[^${NS}/@]*@`),
  shape("connection_string", ["://"], `(?<![A-Za-z0-9_])(?:postgres(?:ql)?|mysql|mongodb(?:\\+srv)?)<M>(?![${NS})|'"\`\\\\\\]]|$)`, "i"),
  shape("pem_block", ["-----BEGIN "], "<M>[A-Z]"),
  shape("google_api_key", ["AIza"], `${START}<M>[0-9A-Za-z_-]{35}`),
  shape("sendgrid_key", ["SG."], `${START}<M>[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}`),
  shape("aws_secret_access_key", ["aws_secret", "AWS_SECRET", "SecretAccessKey", "secret_access_key", "SECRET_ACCESS_KEY"],
    "<M>[A-Za-z_]{0,24}[\"']?[ \\t]{0,4}[=:][ \\t]{0,4}[\"']?[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"),
  shape("password_assignment", ["PASSWORD=", "PASSWORD: ", "password=", "Password="],
    `<M>(?![${NS}"'\`$<*{]|$)[^${NS}"'\`]{3,}`),
  shape("twilio_key", ["SK"], "(?<![A-Za-z0-9])<M>[0-9a-f]{32}(?![A-Za-z0-9])"),
  shape("slack_token", ["xoxb-", "xoxp-", "xoxa-", "xoxs-"], `${START}<M>[A-Za-z0-9-]{10,}`),
  shape("credentials_without_scheme", ["@"],
    `(?<!${TOKEN})(?!(?:user|serviceAccount|group|domain|principal|principalSet|deleted|[Mm][Aa][Ii][Ll][Tt][Oo]):)`
    + `(?:(?<!//)${TOKEN}+:(?!/)${PASSWORD}+|(?<=//)${TOKEN}+:${PASSWORD_NO_SLASH}+)<M>[A-Za-z0-9.-]+\\.[A-Za-z]{2,}`),
];
const NON_SPACE = /[^ \t]+/g;
const ASSIGNMENT = rx(`(?<![A-Za-z0-9_])([A-Za-z_]+)[ \\t]*[=:][ \\t]*["']?([^ \\t"'&,;]+)`, "d");
const BASE64 = rx("(?<![A-Za-z0-9+/])([A-Za-z0-9+/]+)(={0,2})(?![A-Za-z0-9+/=])");
// Two vendor shapes the screen adds to secret_prefix: a Twilio account SID (AC and 32 hex) and a Mailgun
// key (key- and 16 or more hex). Both are hex a hash pass claims, so they are read past the UUID and hash claims. They
// are the note screen's own: validation.py's shapes read every string of a request, and these stay out of that.
const NOTE_PREFIXES = [rx("(?<![A-Za-z0-9_-])AC[0-9a-fA-F]{32}(?![A-Za-z0-9])"),
  rx("(?<![A-Za-z0-9_-])key-[0-9a-fA-F]{16,}(?![A-Za-z0-9])")];
// A credential cue's value: what follows the cue and its joiners, up to a space or a quote, read at most
// CUE_VALUE_MAX characters, so cue after cue in one run stays linear. Closing punctuation is not part of it.
const CUE_VALUE_MAX = 128;
const CUE_VALUE = new RegExp(`["']?([^ \\t\\n\\r\\f\\v"'\`]{1,${CUE_VALUE_MAX}})`, "yd");
const CUE_MARKS = "=:";
const CUE_TRAIL = ".,;:!?)]}>";
const CUE_SEPS = new Set([" ", "\t", "_", "-"]);
const CUE_SPLIT = /[ _-]/;

function secretSpans(text) {
  const out = [];
  for (const { label, markers, re } of SECRET_PATTERNS) {
    if (!markers.some((mk) => text.includes(mk))) continue;
    if (label === "credentials_without_scheme") {
      for (const w of all(NON_SPACE, text)) {
        if (w[0].startsWith("arn:")) continue;
        for (const m of all(re, w[0])) out.push([label, w.index + m.index, w.index + end(m)]);
      }
    } else {
      for (const m of all(re, text)) out.push([label, m.index, end(m)]);
    }
  }
  return out;
}

function printableBase64(body, pad, rules) {
  if (body.length + pad.length < lim(rules, "base64_min", 8) || body.length % 4 === 1
    || (pad && (body.length + pad.length) % 4)) return false;
  if (![...body].some(isUpper) || ![...body].some(isLower)) return false;
  const raw = Buffer.from(body, "base64"); // the body is base64 characters only, of a length that decodes
  return raw.length > 0 && raw.every((b) => b >= 0x20 && b <= 0x7e);
}

/** An even-length hex run of base64_min or more characters, not all digits, whose bytes are printable ASCII. */
function printableHex(word, rules) {
  if (word.length < lim(rules, "base64_min", 8) || word.length % 2 || !HEX_FULL.test(word) || allDigits(word)) return false;
  const raw = Buffer.from(word, "hex");
  return raw.every((b) => b >= 0x20 && b <= 0x7e) && raw.some((b) => (b >= 0x41 && b <= 0x5a) || (b >= 0x61 && b <= 0x7a));
}

/** [a, b) is free but for UUID and hash claims (§8 passes 2 and 3), which a secret's value reads past. */
function freePastHex(note, a, b) {
  let pos = a;
  const over = note.hexy.filter(([s, e]) => s < b && a < e).sort((x, y) => x[0] - y[0] || x[1] - y[1]);
  for (const [s, e] of over) {
    if (s > pos && !free(note, pos, s)) return false;
    pos = Math.max(pos, e);
  }
  return pos >= b || free(note, pos, b);
}

// Round 2. A value that names an algorithm, a key file or a setting sends: a dotted config path whose first
// part is lower case (app.config.key2, process.env.X), or an env var reference in capitals ($TOKEN_V2, ${API_KEY}).
const CUE_DOTTED = /^[a-z_][a-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$/;
const CUE_ENV = /^\$\{?[A-Z_][A-Z0-9_]*\}?$/;
// The symbols that make a value with no digit read as a password after a strong cue; `_ - . /` are left out, since
// identifiers and paths hold them.
const CUE_SYMBOLS = "!#$%&()*+,:;<=>?@[\\]^{|}~";
const CUE_QUOTES = "\"'";
const CUE_SPACE = " \t\n\r\f\v";
// A user and password pair with no host: a name, then ` / ` or `:`, then an optional quote and the value.
const CUE_PAIR = rx(`(?<![^ \\t\\n\\r\\f\\v(])([A-Za-z0-9][A-Za-z0-9._-]{0,63})( / |:)["']?([^ \\t\\n\\r\\f\\v"'\`]{1,${CUE_VALUE_MAX}})`, "d");
const CUE_CHUNK = rx("[^ \\t\\n\\r\\f\\v]+");
const byLengthThenText = (x, y) => y.length - x.length || cmpWords(x, y);
const cmpText = (x, y) => (x < y ? -1 : x > y ? 1 : 0);
// Python's tuple order on two tuples of strings.
function cmpWords(x, y) {
  for (let i = 0; i < Math.min(x.length, y.length); i++) if (x[i] !== y[i]) return cmpText(x[i], y[i]);
  return x.length - y.length;
}
const cueSplit = (cue) => cue.split(CUE_SPLIT).filter(Boolean);

const cuePhrasesCache = new WeakMap();

/** Each cue as its words, split at a space, _ or -, keyed by its first word, longest first, with its kind: "pin" for a
 * `pin_cues` entry, "pin_caps" for a `pin_cues_caps` one (it counts only written in capitals), "strong" for a
 * `credential_strong_cues` one, else "plain". api_key, api key, API-Key and X_API_KEY read as the cues they spell. */
function cuePhrases(rules) {
  if (cuePhrasesCache.has(rules)) return cuePhrasesCache.get(rules);
  const strong = new Set([...list(rules, "credential_strong_cues")].map((c) => cueSplit(c).join(" ")));
  const seen = new Map();
  for (const [group, kind] of [[new Set([...list(rules, "credential_keys"), ...list(rules, "credential_cues")]), ""],
    [list(rules, "pin_cues"), "pin"], [list(rules, "pin_cues_caps"), "pin_caps"]]) {
    for (const c of group) {
      const words = cueSplit(c);
      if (!words.length) continue;
      const k = kind || (strong.has(words.join(" ")) ? "strong" : "plain");
      if (!seen.has(words[0])) seen.set(words[0], new Map());
      seen.get(words[0]).set(`${words.join(" ")}\u0000${k}`, [words, k]);
    }
  }
  const out = new Map();
  for (const [first, v] of seen) {
    out.set(first, [...v.values()].sort((x, y) => byLengthThenText(x[0], y[0]) || cmpText(x[1], y[1])));
  }
  cuePhrasesCache.set(rules, out);
  return out;
}

const asPhrasesCache = new WeakMap();

function asPhrases(rules) {
  if (asPhrasesCache.has(rules)) return asPhrasesCache.get(rules);
  const byKey = new Map();
  for (const c of list(rules, "credential_as_links")) {
    const words = cueSplit(c);
    if (words.length) byKey.set(words.join(" "), words);
  }
  const out = [...byKey.values()].sort(byLengthThenText);
  asPhrasesCache.set(rules, out);
  return out;
}

/** A `credential_value_names` entry, alone or with digits after it (bcrypt12, rsa4096), a dotted
 * config path or an env var reference names a setting, not a secret. */
function cueNamed(value, rules) {
  const low = asciiLower(value), names = list(rules, "credential_value_names");
  return names.has(low) || names.has(low.replace(/[0-9]+$/, "")) || CUE_DOTTED.test(value) || CUE_ENV.test(value);
}

/** Whether the value after a cue of this kind reads as a secret (§9.1). */
function cueShaped(value, rules, kind) {
  if (kind === "pin" || kind === "pin_caps") {
    return lim(rules, "pin_digits_min", 4) <= value.length && value.length <= lim(rules, "pin_digits_max", 8)
      && allDigits(value);
  }
  if (value.includes(PLACEHOLDER_OPEN) || list(rules, "placeholders").has(asciiLower(value)) || cueNamed(value, rules)) {
    return false;
  }
  const n = value.length, cs = [...value];
  const letter = cs.some((c) => isUpper(c) || isLower(c)), digit = cs.some(isDigit);
  if ((n >= lim(rules, "credential_value_min", 8) && letter && digit)
    || (n >= lim(rules, "cue_hex_min", 16) && letter && HEX_FULL.test(value))) return true;
  if (kind !== "strong") return false;
  return (n >= lim(rules, "credential_value_min_strong", 6) && letter && digit)
    || (n >= lim(rules, "credential_value_min", 8) && cs.some(isUpper) && cs.some(isLower)
      && cs.some((c) => CUE_SYMBOLS.includes(c)));
}

/** The value after a cue that ends at `at`: up to credential_cue_window joiner words and any `=` or `:` marks, an
 * optional quote, then a value that cueShaped takes. Free but for UUID and hash claims. A word that is not a joiner,
 * such as a hash word (commit, sha, digest), ends the window, so the hash exemption holds where the cue is a hash
 * word. */
function cueValue(note, rules, at, atTok, kind) {
  const { text, toks } = note;
  const joiners = list(rules, "credential_joiners");
  const window = lim(rules, "credential_cue_window", 3), n = text.length;
  let used = 0, i = at, k = atTok + 1;
  for (;;) {
    while (i < n && WHITESPACE.includes(text[i])) i++;
    if (i < n && CUE_MARKS.includes(text[i])) { i++; continue; }
    if (k < toks.length && toks[k].start === i && toks[k].kind === "word" && joiners.has(toks[k].lower) && used < window) {
      i = toks[k].end; used++; k++;
      continue;
    }
    break;
  }
  CUE_VALUE.lastIndex = i;
  const m = CUE_VALUE.exec(text);
  if (!m) return null;
  let [a, b] = m.indices[1];
  while (b > a && CUE_TRAIL.includes(text[b - 1])) b--;
  return cueShaped(text.slice(a, b), rules, kind) && freePastHex(note, a, b) ? [a, b] : null;
}

const plainSep = (sep) => Boolean(sep) && [...sep].every((c) => c === " " || c === "\t");

/** The cue, then 1 to credential_cue_gap other words, then a `credential_links` word or a `=` or `:`
 * mark, then the value as cueValue reads it. The words are joined by spaces or tabs only (a word joined by ' or - to
 * the one before is part of it), so a full stop, comma or bracket ends the scan; so do a hash word, a link with no word
 * before it, and a mark that starts `//`. */
function cueGapValue(note, rules, atTok, kind) {
  const { text, toks } = note;
  const links = list(rules, "credential_links"), hashes = list(rules, "hash_words");
  const gap = lim(rules, "credential_cue_gap", 5), n = text.length;
  let words = 0;
  for (let k = atTok + 1; k < toks.length; k++) {
    const t = toks[k];
    if (t.kind !== "word") return null;
    if (t.sep !== "'" && t.sep !== "-") {
      if (!plainSep(t.sep)) return null;
      if (links.has(t.lower)) return words ? cueValue(note, rules, t.end, k, kind) : null;
      if (hashes.has(t.lower)) return null;
      words++;
      if (words > gap) return null;
    }
    let i = t.end;
    while (i < n && (text[i] === " " || text[i] === "\t")) i++;
    if (i < n && CUE_MARKS.includes(text[i]) && !text.startsWith("//", i + 1)) return cueValue(note, rules, t.end, k, kind);
  }
  return null;
}

/** "use X as the password": a `credential_as_links` phrase right before the cue, joined by spaces or tabs, and
 * the value is the run of non-space characters before it, less an opening quote or bracket and closing quotes and
 * punctuation. */
function cueAsValue(note, rules, atTok, kind) {
  const { text, toks } = note;
  for (const words of asPhrases(rules)) {
    const p = atTok - words.length;
    if (p < 0 || words.some((w, x) => toks[p + x].kind !== "word" || toks[p + x].lower !== w)) continue;
    let plain = true;
    for (let q = p + 1; q <= atTok; q++) if (!plainSep(toks[q].sep)) { plain = false; break; }
    if (!plain) continue;
    let b = toks[p].start;
    if (b === 0 || !WHITESPACE.includes(text[b - 1])) return null;
    while (b > 0 && WHITESPACE.includes(text[b - 1])) b--;
    let a = b;
    while (a > 0 && !CUE_SPACE.includes(text[a - 1])) {
      a--;
      if (b - a > CUE_VALUE_MAX + 2) return null;
    }
    while (a < b && "\"'(".includes(text[a])) a++;
    while (b > a && (CUE_QUOTES.includes(text[b - 1]) || CUE_TRAIL.includes(text[b - 1]))) b--;
    return b > a && cueShaped(text.slice(a, b), rules, kind) && freePastHex(note, a, b) ? [a, b] : null;
  }
  return null;
}

/** A user and password pair with no host. `<name>:<value>` counts when the name is a
 * `credential_user_words` entry and the value does not start with a digit (postgres:16-alpine is an image tag);
 * `<name> / <value>` counts for a user word, or for a name with no capital letter when the value holds a mark that is
 * not a letter or digit. A user word's value is read as after a strong cue; a value holding `:` or `/` is a path or a
 * URL, not a password. */
function cuePairs(note, rules) {
  const { text } = note, users = list(rules, "credential_user_words"), out = [];
  for (const m of all(CUE_PAIR, text)) {
    let [a, b] = m.indices[3];
    while (b > a && CUE_TRAIL.includes(text[b - 1])) b--;
    const value = text.slice(a, b), name = m[1];
    if (!value || value.includes(":") || value.includes("/")) continue;
    const user = users.has(asciiLower(name));
    if (m[2] === ":" && (!user || isDigit(value[0]))) continue;
    const ok = user ? cueShaped(value, rules, "strong")
      : ![...name].some(isUpper) && [...value].some((c) => !isAlnum(c)) && cueShaped(value, rules, "plain");
    if (ok && freePastHex(note, a, b)) out.push([[m.indices[1][0], b], [a, b]]);
  }
  return out;
}

/** A `credential_flags` entry (-p) joined to its value in one run of non-space characters
 * (`mysql -pQuartz7Harbor`), with an optional quote. The value is read as after a strong cue and must also hold a
 * capital or a symbol, so -print0 and -pthread stay flags. `--password=X` is credential_assignment's. */
function cueFlags(note, rules) {
  const { text } = note, out = [];
  const flags = [...list(rules, "credential_flags")].sort((x, y) => y.length - x.length || cmpText(x, y));
  for (const m of all(CUE_CHUNK, text)) {
    const chunk = m[0];
    for (const f of flags) {
      if (!chunk.startsWith(f) || chunk.length === f.length) continue;
      let a = m.index + f.length, b = end(m);
      while (a < b && CUE_QUOTES.includes(text[a])) a++;
      while (b > a && (CUE_QUOTES.includes(text[b - 1]) || CUE_TRAIL.includes(text[b - 1]))) b--;
      const value = text.slice(a, b);
      if (b - a > 0 && b - a <= CUE_VALUE_MAX && [...value].some((c) => isUpper(c) || CUE_SYMBOLS.includes(c))
        && cueShaped(value, rules, "strong") && freePastHex(note, a, b)) out.push([[m.index, b], [a, b]]);
      break;
    }
  }
  return out;
}

/** credential_cue: a credential word or phrase and its value, as [hit span, value span]. The value
 * follows the cue (`db password is Tr0ub4dor&3`, `pw: Z7#qLm29`, `API key 9f3a2b7c...`), follows it after a few words
 * and a link (`password for the replica is ...`), or comes before it (`use hunter2 as the password`); a PIN cue takes a
 * short run of digits. User and password pairs and joined password flags count too. */
function credentialCues(note, rules) {
  const phrases = cuePhrases(rules), { toks } = note, found = [];
  toks.forEach((t, i) => {
    if (t.kind !== "word" || !phrases.has(t.lower)) return;
    for (const [words, kind] of phrases.get(t.lower)) {
      const j = i + words.length - 1;
      if (j >= toks.length || words.some((w, x) => toks[i + x].kind !== "word" || toks[i + x].lower !== w
        || (x && !CUE_SEPS.has(toks[i + x].sep)))) continue;
      if (kind === "pin_caps" && toks.slice(i, j + 1).some((tk) => [...tk.text].some(isLower))) continue;
      let span = cueValue(note, rules, toks[j].end, j, kind) ?? cueGapValue(note, rules, j, kind);
      if (span) {
        found.push([[t.start, span[1]], span]);
        break;
      }
      span = cueAsValue(note, rules, i, kind);
      if (span) {
        found.push([[span[0], toks[j].end], span]);
        break;
      }
    }
  });
  return [...found, ...cuePairs(note, rules), ...cueFlags(note, rules)];
}

function secretRules(note, rules) {
  const { text } = note, hits = [];
  for (const [label, a, b] of secretSpans(text)) if (free(note, a, b)) hits.push(hit(rules, SECRET_RULE[label] ?? "secret_prefix", a, b));
  for (const re of NOTE_PREFIXES) {
    for (const m of all(re, text)) if (freePastHex(note, m.index, end(m))) hits.push(hit(rules, "secret_prefix", m.index, end(m)));
  }
  const keys = list(rules, "credential_keys"), starts = [], ends = [];
  for (const m of all(ASSIGNMENT, text)) {
    const value = m[2], [a, b] = m.indices[2];
    if (keys.has(asciiLower(m[1])) && value.length >= lim(rules, "credential_value_min", 8) && someDigit(value) && free(note, a, b)) {
      hits.push(hit(rules, "credential_assignment", m.index, end(m)));
      starts.push(a);
      ends.push(b);
    }
  }
  const seen = new Set();                                            // one hit per value
  for (const [[s, e], [a, b]] of credentialCues(note, rules)) {
    let lo = 0, hi = starts.length;                                  // the last assignment value starting before b
    while (lo < hi) { const mid = (lo + hi) >> 1; if (starts[mid] < b) lo = mid + 1; else hi = mid; }
    const k = lo - 1;                                                // the assignment values sit in order, never overlap
    if (seen.has(`${a},${b}`) || (k >= 0 && ends[k] > a)) continue;
    seen.add(`${a},${b}`);
    hits.push(hit(rules, "credential_cue", s, e));
  }
  for (const t of wordsOf(note)) {
    if (t.text.length >= lim(rules, "mixed_run_min", 20) && someDigit(t.text) && !allDigits(t.text) && free(note, t.start, t.end)) {
      hits.push(hit(rules, "mixed_run", t.start, t.end));
    }
  }
  for (const m of all(BASE64, text)) {
    if (printableBase64(m[1], m[2], rules) && free(note, m.index, end(m))) hits.push(hit(rules, "encoded_text", m.index, end(m)));
  }
  for (const t of wordsOf(note)) {                                       // hex that decodes to printable text (g-012)
    if (printableHex(t.text, rules) && free(note, t.start, t.end)) hits.push(hit(rules, "encoded_text", t.start, t.end));
  }
  return hits;
}

/* ---------------------------------------------------------------- §9.2 record values as numbers or addresses */

const EMAIL = rx("(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)*\\.[A-Za-z]{2,})(?![A-Za-z0-9-])");
const URL_RE = rx(`${B}(?:https?|ftp)://([A-Za-z0-9.-]+)[^ \\t]*`, "i");
const IPV4 = rx("(?<![A-Za-z0-9.])(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?![A-Za-z0-9]|\\.[0-9])");
const SSN_DASHED = rx("(?<![0-9])[0-9]{3}-[0-9]{2}-[0-9]{4}(?![0-9])");
// validation.py _SSN_RUN and _KEYWORD_SSN
const SSN_RUN = rx("(?<![A-Za-z0-9.])(?!000|666|9[0-9]{2})[0-9]{3}(?!00)[0-9]{2}(?!0000)[0-9]{4}(?![A-Za-z0-9.])");
const KEYWORD_SSN = rx("(?<![A-Za-z])(?:ssn|social[ _-]?security(?:[ _-]?(?:number|no))?|ss#)[^A-Za-z0-9]{0,12}(?<![0-9])([0-9]{3} ?[0-9]{2} ?[0-9]{4})(?![0-9])", "id");
const CARD = rx("(?<![0-9])[0-9](?:[ -]?[0-9]){12,18}(?![0-9])");
const TEN = rx(`${B}[0-9]{10}${E}`);
const L = "AC-HJKMNP-RT-Y";
const MBI = rx(`${B}[1-9][${L}][${L}0-9][0-9]-?[${L}][${L}0-9][0-9]-?[${L}]{2}[0-9]{2}${E}`);
const DEA = rx(`${B}[A-Za-z][A-Za-z9]([0-9]{7})${E}`);
const PHONE = rx("(?<![0-9])(?:\\+?1[ .-]?)?(?:\\([2-9][0-9]{2}\\)[ .-]?|[2-9][0-9]{2}[ .-])[2-9][0-9]{2}[ .-][0-9]{4}(?![0-9])");
const PHONE_RUN = rx("(?<![A-Za-z0-9.])[2-9][0-9]{2}[2-9][0-9]{6}(?![A-Za-z0-9.])");
const DIGIT_GROUPS = rx("[0-9]+(?:[-.][0-9]+)*");
const FAKE_PHONE = rx("(?<![0-9])555[ .-]?01[0-9]{2}(?![0-9])");

export function luhnOk(digits) {
  let s = 0, alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (alt) { d *= 2; if (d > 9) d -= 9; }
    s += d;
    alt = !alt;
  }
  return s % 10 === 0;
}
const npiOk = (digits) => luhnOk(`80840${digits}`);
function deaOk(d) {
  const n = [...d].map((c) => c.charCodeAt(0) - 48);
  return (n[0] + n[2] + n[4] + 2 * (n[1] + n[3] + n[5])) % 10 === n[6];
}
/** A URL with userinfo (user@host) or a query string with a value (?id=7). Any other URL passes as a URL; its path and
 * fragment are still read by every other rule. */
function urlHoldsValues(url) {
  const rest = url.slice(url.indexOf("://") + 3);
  const authority = rest.split(/[/?#]/)[0];
  const q = rest.indexOf("?");
  const query = q < 0 ? "" : rest.slice(q + 1).split("#")[0];
  return authority.includes("@") || query.split("&").some((kv) => kv.includes("=") && kv.slice(kv.indexOf("=") + 1) !== "");
}
const placeholderDomains = (rules) => new Set([...list(rules, "placeholders")].filter((p) => p.includes(".") && !p.includes(" ")));

function recordNumbers(note, rules) {
  const { text } = note, hits = [];
  const add = (rule, a, b) => { if (free(note, a, b)) hits.push(hit(rules, rule, a, b)); };
  const fake = placeholderDomains(rules);
  for (const m of all(EMAIL, text)) add(fake.has(asciiLower(m[1])) ? "placeholder_value" : "email", m.index, end(m));
  for (const m of all(URL_RE, text)) {
    if (fake.has(asciiLower(m[1]))) add("placeholder_value", m.index, end(m));
    else if (urlHoldsValues(m[0])) add("url", m.index, end(m));
  }
  for (const m of all(IPV4, text)) add("ipv4", m.index, end(m));
  for (const m of all(IPV6, text)) if (someDigit(m[0])) add("ipv6", m.index, end(m));
  for (const re of [SSN_DASHED, SSN_RUN]) for (const m of all(re, text)) add("ssn", m.index, end(m));
  for (const m of all(KEYWORD_SSN, text)) add("ssn", ...m.indices[1]);
  for (const m of all(CARD, text)) {
    const digits = [...m[0]].filter(isDigit).join("");
    if (digits.length >= 13 && digits.length <= 19 && luhnOk(digits)) add("luhn", m.index, end(m));
  }
  for (const m of all(TEN, text)) if (npiOk(m[0])) add("npi", m.index, end(m));
  for (const m of all(MBI, text)) add("mbi", m.index, end(m));
  for (const m of all(DEA, text)) if (deaOk(m[1])) add("dea", m.index, end(m));
  for (const re of [PHONE, PHONE_RUN]) for (const m of all(re, text)) add("phone_nanp", m.index, end(m));
  const dates = all(DATE_SHAPE, text).filter((m) => { const ymd = dateParts(m[0]); return ymd !== null && dateValid(...ymd, rules); })
    .map((m) => [m.index, end(m)]);
  for (const m of all(DIGIT_GROUPS, text)) {
    const a = m.index, b = end(m);
    if (dates.some(([s, e]) => s <= a && b <= e)) continue;            // a date is the date rule's
    let count = 0;
    for (let i = a; i < b; i++) if (isDigit(text[i]) && free(note, i, i + 1)) count++;
    if (count >= lim(rules, "digit_run_min", 5)) hits.push(hit(rules, "digit_run", a, b));
  }
  const lowered = asciiLower(text);
  for (const p of list(rules, "placeholders")) {
    if (!p.includes(" ")) continue;                                    // john doe, john_doe, john.doe, john-doe
    const re = rx(B + p.split(" ").map(escapeRe).join("[ _.-]") + E);
    for (const m of all(re, lowered)) add("placeholder_value", m.index, end(m));
  }
  for (const m of all(FAKE_PHONE, text)) add("placeholder_value", m.index, end(m));
  return hits;
}

/* ---------------------------------------------------------------- §9.2 dates, ages, addresses and quoted values */

const NUMERIC_MD = rx("(?<![0-9/.-])([0-9]{1,2})/([0-9]{1,2})(?![0-9/.-])");
const QUOTED = rx("(?<![A-Za-z0-9])(['\"])([^'\"]{1,200}?)\\1(?![A-Za-z0-9])", "d");
const PO_BOX = rx(`(?<![A-Za-z0-9])(?:p\\.?[ \\t]?o\\.?|post[ \\t]+office)[ \\t]*box[ \\t]*#?[ \\t]*[0-9]+${E}`, "i");
const AGE_OLD = rx(`(?<![0-9])([0-9]{1,3})[ \\t-]*(?:years?|yrs?)[ \\t-]*old${E}`, "i");
const AGE_YO = rx(`(?<![0-9])([0-9]{1,3})[ \\t]*(?:y/o|yo)${E}`, "i");
const AGE_WORD = rx(`${B}(?:aged?|turned)[ \\t:]+([0-9]{1,3})${E}`, "i");

const allDigitToken = (t) => t.kind === "word" && allDigits(t.text);
/** A month word; lower-case "may" is the verb, so May counts only capitalised. */
const month = (t, rules) => t.kind === "word" && list(rules, "months").has(t.lower) && (t.lower !== "may" || capitalised(t));
/** The day a token names (14, 14th), else null. */
function day(t) {
  const digits = [...t.lower].filter(isDigit).join("");
  const rest = t.lower.slice(digits.length);
  if (!digits || digits.length > 2 || !t.lower.startsWith(digits) || !["", "st", "nd", "rd", "th"].includes(rest)) return null;
  const n = Number(digits);
  return n >= 1 && n <= 31 ? n : null;
}
const year = (t, rules) => allDigitToken(t) && t.text.length === 4
  && lim(rules, "year_min", 1900) <= Number(t.text) && Number(t.text) <= lim(rules, "year_max", 2100);
const near = (toks, i, words, window) => toks.slice(Math.max(0, i - window), i + window + 1).some((t) => t.kind === "word" && words.has(t.lower));
const strip = (s, chars) => { let a = 0, b = s.length; while (a < b && chars.includes(s[a])) a++; while (b > a && chars.includes(s[b - 1])) b--; return s.slice(a, b); };

function datesAndPlaces(note, rules) {
  const { text, toks } = note, hits = [];
  const add = (rule, a, b) => { if (free(note, a, b)) hits.push(hit(rules, rule, a, b)); };
  for (const m of all(DATE_SHAPE, text)) {                                 // date: numeric
    const parts = dateParts(m[0]);
    if (parts !== null && dateValid(...parts, rules)) add("date", m.index, end(m));
  }
  const window = lim(rules, "hotword_window", 10);
  const dateWords = list(rules, "date_hotwords");
  toks.forEach((t, i) => {                                                 // date and month_day: with a month word
    if (!month(t, rules)) return;
    const after = toks[i + 1] ?? null, before = i > 0 ? toks[i - 1] : null;
    if (after !== null && day(after) !== null && strip(after.sep, " \t.") === "") {
      const y = toks[i + 2] ?? null;
      if (y !== null && year(y, rules) && strip(y.sep, " \t,") === "") add("date", t.start, y.end);
      else add("month_day", t.start, after.end);
    } else if (before !== null && day(before) !== null && strip(t.sep, " \t") === "") {
      const y = after;
      if (y !== null && year(y, rules) && strip(y.sep, " \t,.") === "") add("date", before.start, y.end);
      else add("month_day", before.start, t.end);
    }
  });
  for (const m of all(NUMERIC_MD, text)) {                                 // m/d only near a date word
    const mo = Number(m[1]), d = Number(m[2]);
    const at = toks.findIndex((t) => t.start === m.index);
    if (mo >= 1 && mo <= 12 && d >= 1 && d <= 31 && at >= 0 && near(toks, at, dateWords, window)) add("month_day", m.index, end(m));
  }
  for (const m of all(QUOTED, text)) {                                     // quoted_literal: @, 4 digits or a NAME
    const body = m[2], [a, b] = m.indices[2];
    const named = toks.some((t) => t.kind === "word" && a <= t.start && t.end <= b
      && (t.tag === NAME || t.subs.some((x) => x.tag === NAME)));
    if (lim(rules, "quoted_min", 3) <= body.length && body.length <= lim(rules, "quoted_max", 80)
      && (body.includes("@") || [...body].filter(isDigit).length >= 4 || named)) {
      add("quoted_literal", m.index, end(m));
    }
  }
  const suffixes = list(rules, "street_suffixes");                          // street_address: N Word [Word] Suffix
  toks.forEach((t, i) => {
    if (!allDigitToken(t) || t.text.length > 6) return;
    for (const k of [1, 2, 3]) {
      const run = toks.slice(i + 1, i + 2 + k);
      if (run.length === k + 1 && run.every((w) => w.kind === "word" && capitalised(w) && (w.sep === " " || w.sep === "\t"))
        && suffixes.has(run[run.length - 1].lower) && run.every((w) => [...w.text].every((c) => isLower(c) || isUpper(c)))) {
        add("street_address", t.start, run[run.length - 1].end);
        break;
      }
    }
  });
  for (const m of all(PO_BOX, text)) add("po_box", m.index, end(m));
  const units = list(rules, "unit_words");                                  // room_bed: room 412, bed B, Apt 4B
  for (let i = 0; i + 1 < toks.length; i++) {
    const t = toks[i], nxt = toks[i + 1];
    if (t.kind === "word" && units.has(t.lower) && nxt.kind === "word" && strip(nxt.sep, " \t#") === ""
      && (someDigit(nxt.text) || (nxt.text.length === 1 && isUpper(nxt.text)))) add("room_bed", t.start, nxt.end);
  }
  const births = list(rules, "birth_words");                                // born_year
  const reach = lim(rules, "birth_window", 3);
  toks.forEach((t, i) => {
    if (year(t, rules) && free(note, t.start, t.end) && near(toks, i, births, reach)) hits.push(hit(rules, "born_year", t.start, t.end));
  });
  const ageMax = lim(rules, "age_max", 89);                                 // age_over_89; under 90 is not an identifier
  for (const re of [AGE_OLD, AGE_YO, AGE_WORD]) for (const m of all(re, text)) if (Number(m[1]) > ageMax) add("age_over_89", m.index, end(m));
  const who = new Set([...list(rules, "pronouns"), ...list(rules, "person_context")]);
  for (let i = 1; i + 1 < toks.length; i++) {
    const t = toks[i], n = toks[i + 1];
    if (t.lower === "is" && who.has(toks[i - 1].lower) && allDigitToken(n) && Number(n.text) > ageMax) add("age_over_89", toks[i - 1].start, n.end);
  }
  return hits;
}

/* ---------------------------------------------------------------- §9.3 hotword rules */

const hot = (t, rules) => (t.kind === "ref" ? t.hotwords.length > 0 : list(rules, "hotwords").has(t.lower));
function freeDigits(note, t) {
  let n = 0;
  for (let k = 0; k < t.text.length; k++) if (isDigit(t.text[k]) && free(note, t.start + k, t.start + k + 1)) n++;
  return n;
}

function hotwordRules(note, rules) {
  const { toks } = note, hits = [];
  const window = lim(rules, "hotword_window", 10);
  const numbers = list(rules, "number_words");
  const hotAt = toks.flatMap((t, i) => (hot(t, rules) ? [i] : []));
  for (const i of hotAt) {                                                  // hotword_digits
    const span = toks.slice(Math.max(0, i - window), i + window + 1).filter((t) => t.kind === "word" && freeDigits(note, t));
    if (span.reduce((s, t) => s + freeDigits(note, t), 0) >= lim(rules, "hotword_digits_min", 4)) {
      const a = Math.min(toks[i].start, ...span.map((t) => t.start));
      const b = Math.max(toks[i].end, ...span.map((t) => t.end));
      hits.push(hit(rules, "hotword_digits", a, b));
    }
  }
  const spelled = toks.flatMap((t, i) => (t.kind === "word" && numbers.has(t.lower) && free(note, t.start, t.end) ? [i] : []));
  for (const i of spelled) {                                                // spelled_digits near a hotword
    if (hotAt.some((h) => Math.abs(i - h) <= window)) hits.push(hit(rules, "spelled_digits", toks[i].start, toks[i].end));
  }
  let run = [];                                                             // ... or 5 or more in a row
  for (const i of [...spelled, -2]) {
    if (run.length && i === run[run.length - 1] + 1 && strip(toks[i].sep, " \t,-") === "") { run.push(i); continue; }
    if (run.length >= lim(rules, "spelled_digits_min", 5)) hits.push(hit(rules, "spelled_digits", toks[run[0]].start, toks[run[run.length - 1]].end));
    run = [i];
  }
  run = [];                                                                 // single_char_run: j_a_n_e, 4-8-2-9
  const ended = [...toks, { text: "", start: 0, end: 0, kind: "end", sep: " " }];
  ended.forEach((t, i) => {
    const single = t.kind === "word" && t.text.length === 1 && free(note, t.start, t.end);
    const joined = run.length > 0 && t.sep !== "" && !t.sep.includes(",") && (t.sep === " " || [...t.sep].every((c) => !" \t".includes(c)));
    if (single && joined) { run.push(i); return; }
    if (run.length >= lim(rules, "single_char_run_min", 4)) hits.push(hit(rules, "single_char_run", toks[run[0]].start, toks[run[run.length - 1]].end));
    run = single ? [i] : [];
  });
  const pronouns = list(rules, "pronouns");                                 // person_measurement
  toks.forEach((t, i) => {
    if (allDigitToken(t) && free(note, t.start, t.end) && near(toks, i, pronouns, window)) hits.push(hit(rules, "person_measurement", t.start, t.end));
  });
  return hits;
}

/* ---------------------------------------------------------------- §10 name rules */
// The rules read units: a word token, or a token and the next when only their joined form (o'brien) is a name. A unit
// is NAME, AMBIG, SAFE or OOV by §7's tags. A capitalised NAME refuses on its own (name_alone).

const PAIR_SEP = new Set(" \t,-()'\".");
const ID_SEP = new Set("_./");
const SNAPSHOT_SHAPE = /(?<![A-Za-z0-9_])[A-Za-z0-9_]+(?:[./][A-Za-z0-9_]+)+/g;

function unitsOf(note) {
  const out = [], { toks } = note;
  let i = 0;
  while (i < toks.length) {
    const t = toks[i];
    if (t.kind !== "word") {
      out.push({ start: t.start, end: t.end, lower: "", tag: "REF", capitalised: false, alphaTitle: false, sep: t.sep, kind: "ref" });
      i++;
      continue;
    }
    if (t.joined && (t.joinedTag === NAME || t.joinedTag === AMBIG) && t.tag !== NAME && i + 1 < toks.length) {
      const n = toks[i + 1];
      out.push({ start: t.start, end: n.end, lower: t.joined, tag: t.joinedTag, capitalised: capitalised(t), alphaTitle: capitalised(t), sep: t.sep, kind: "word" });
      i += 2;
      continue;
    }
    const title = capitalised(t) && t.text.length > 1 && [...t.text.slice(1)].every(isLower);
    out.push({ start: t.start, end: t.end, lower: t.lower, tag: t.tag, capitalised: capitalised(t), alphaTitle: title, sep: t.sep, kind: "word" });
    i++;
  }
  return out;
}

/** How a separator joins two units: "id" (_ . / with no space), "pair" (spaces, commas, hyphens, brackets, quotes,
 * dots), or null. */
function joins(sep) {
  if (!sep || sep.length > 3) return null;
  if ([...sep].every((c) => ID_SEP.has(c)) && ![...sep].every((c) => c === ".")) return "id";
  return [...sep].every((c) => PAIR_SEP.has(c)) ? "pair" : null;
}

const initial = (u) => u.kind === "word" && u.lower.length === 1 && u.capitalised;

function nameRules(note, rules) {
  const units = unitsOf(note), hits = [];
  const titles = list(rules, "titles"), particles = list(rules, "particles"), context = list(rules, "person_context");
  const onlyBefore = list(rules, "before_name_only"), heads = list(rules, "clinical_heads");
  const window = lim(rules, "context_window", 5);
  const skip = all(SNAPSHOT_SHAPE, note.text).filter((m) => note.snapshotIds.has(m[0])).map((m) => [m.index, end(m)]);
  const freeU = (u) => !skip.some(([a, b]) => a <= u.start && u.end <= b) && free(note, u.start, u.end);
  const oovWord = (u) => u.tag === OOV && u.alphaTitle;
  const add = (rule, a, b, byId) => hits.push(hit(rules, byId && rule !== "title_name" ? "name_in_identifier" : rule, a.start, b.end));

  units.forEach((a, i) => {
    if (a.kind !== "word" || !freeU(a)) return;
    // the partner of a: the next unit past up to two initials and two particles
    let j = i + 1, inits = 0, parts = 0;
    const how = new Set();
    while (j < units.length) {
      const u = units[j], join = joins(u.sep);
      if (join === null || u.kind !== "word" || !freeU(u)) break;
      how.add(join);
      if (initial(u) && inits < 2) { inits++; j++; continue; }
      if (particles.has(u.lower) && parts < 2 && !u.capitalised) { parts++; j++; continue; }
      break;
    }
    let b = j < units.length && joins(units[j].sep) !== null && units[j].kind === "word" ? units[j] : null;
    if (b !== null && !freeU(b)) b = null;
    const byId = how.size === 1 && how.has("id");
    const after = b !== null && j + 1 < units.length ? units[j + 1] : null;
    const headNext = after !== null && heads.has(after.lower) && joins(after.sep) === "pair";
    const before = i > 0 ? units[i - 1] : null;
    const led = before !== null && (titles.has(before.lower) || context.has(before.lower));
    if (b !== null && !headNext) {
      const tags = new Set([a.tag, b.tag]);
      if ((a.tag === NAME && b.tag === NAME) || (tags.size === 2 && tags.has(NAME) && tags.has(AMBIG))) {
        add("name_pair", a, b, byId);
      } else if (a.tag === AMBIG && b.tag === AMBIG && a.capitalised && b.capitalised && led && !byId
        && !(i > 1 && units[i - 2].capitalised) && !(after !== null && after.capitalised)) {
        add("ambig_pair", a, b, false);
      } else if (!byId && ((a.tag === NAME && a.capitalised && oovWord(b)) || (oovWord(a) && b.tag === NAME && b.capitalised)
        || (oovWord(a) && oovWord(b) && i > 0))) {
        add("name_oov", a, b, false);
      }
    }
    // title_name: a title then a NAME; a title then a capitalised OOV is name_oov
    const nxt = i + 1 < units.length ? units[i + 1] : null;
    if (titles.has(a.lower) && nxt !== null && nxt.kind === "word" && joins(nxt.sep) !== null && freeU(nxt)) {
      if (nxt.tag === NAME) hits.push(hit(rules, "title_name", a.start, nxt.end));
      else if (oovWord(nxt) && joins(nxt.sep) === "pair") hits.push(hit(rules, "name_oov", a.start, nxt.end));
    }
    // initial_name: one or two initials, then a NAME
    if (initial(a) && (before === null || !initial(before))) {
      let k = i + 1;
      if (k < units.length && initial(units[k]) && units[k].sep.includes(".")) k++;
      if (k < units.length && units[k].tag === NAME && units[k].sep.includes(".") && freeU(units[k])) {
        hits.push(hit(rules, "initial_name", a.start, units[k].end));
      }
    }
    // context_name: a person_context word, then a NAME within context_window tokens; by, for and ask only right before
    if (context.has(a.lower)) {
      const reach = onlyBefore.has(a.lower) ? 1 : window;
      const heading = before !== null && before.capitalised;               // The Patient Will Grant: a title-case run
      const naming = list(rules, "naming_words").has(a.lower) && !heading;
      for (const u of units.slice(i + 1, i + 1 + reach)) {
        if (u.kind === "word" && (u.tag === NAME || (u.tag === AMBIG && u.capitalised && naming)) && freeU(u)) {
          hits.push(hit(rules, "context_name", a.start, u.end));
          break;
        }
      }
      if (!onlyBefore.has(a.lower) && nxt !== null && oovWord(nxt) && joins(nxt.sep) === "pair" && freeU(nxt)) {
        hits.push(hit(rules, "name_oov", a.start, nxt.end));
      }
    }
    // name_alone: a capitalised strong NAME on its own, anywhere; not an all-caps token (a title
    // or particle is not one); an eponym before a clinical head word (Apgar score) is not one either
    if (a.tag === NAME && a.alphaTitle && freeU(a) && !titles.has(a.lower) && !particles.has(a.lower) && !beforeHead(units, i, heads)) {
      hits.push(hit(rules, "name_alone", a.start, a.end));
    }
    // an ambiguous word with a name signal (item 2): a title before it, a possessive, a person verb right after it, or
    // a person cue within cue_window words either side
    if (a.tag === AMBIG && a.alphaTitle && freeU(a)) {
      if (before !== null && titles.has(before.lower) && joins(a.sep) === "pair") hits.push(hit(rules, "title_name", before.start, a.end));
      else if (nameSignal(units, i, rules)) hits.push(hit(rules, "ambig_name", a.start, a.end));
    }
  });
  for (const t of note.toks) {                                              // camelCase parts: janeSmith
    if (t.kind === "word" && t.subs.length > 1 && free(note, t.start, t.end)
      && t.subs.slice(1).some((y, k) => t.subs[k].tag === NAME && y.tag === NAME)) {
      hits.push(hit(rules, "name_in_identifier", t.start, t.end));
    }
  }
  return hits;
}

/** A clinical head word one or two units after units[i], joined as a pair (Apgar score, Glasgow Coma Scale). */
function beforeHead(units, i, heads) {
  for (const u of units.slice(i + 1, i + 3)) {
    if (u.kind !== "word" || joins(u.sep) !== "pair") return false;
    if (heads.has(u.lower)) return true;
  }
  return false;
}

/** A possessive ('s), a person verb right after the word (one or more words, as listed), or a person cue within
 * cue_window units either side. */
function nameSignal(units, i, rules) {
  const nxt = i + 1 < units.length ? units[i + 1] : null;
  if (nxt !== null && nxt.sep === "'" && nxt.lower === "s") return true;
  for (const verb of list(rules, "person_verbs")) {
    const words = verb.split(" ");
    const run = units.slice(i + 1, i + 1 + words.length);
    if (run.length === words.length && run.every((u, k) => u.kind === "word" && u.lower === words[k] && u.sep
      && strip(u.sep, " \t") === "")) return true;
  }
  const cues = list(rules, "person_cues"), reach = lim(rules, "cue_window", 3);
  const from = Math.max(0, i - reach);
  return units.slice(from, i + reach + 1).some((u, k) => from + k !== i && u.kind === "word" && cues.has(u.lower));
}

// The rule steps after tagging, in §2's order. Each takes the note and the rules and returns hits; a technical pass
// adds to note.claimed instead.
const STEPS = [technicalPasses, secretRules, recordNumbers, datesAndPlaces, hotwordRules, nameRules];

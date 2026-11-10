/* T29 line item h, h2 (T29-P3-C85, decided in C87; P2 C63 point 2): the inspector's check of the citation the
 * assistant gives for a fact. The fact document carries only the result (cited_facts[].cite: ok, failed or none) and,
 * for ok, the file and line; the token never leaves the machine.
 *
 * ok needs all of: a file this root's walk listed (`files`, the walk's own entries by path, looked up NFC-normalised
 * and read by their disk form, as factdoc's answers are), read through readWalked (a regular file, no symlink, its
 * realpath inside the root, no larger than the walk reads); text with no NUL byte; a line number that is a whole number
 * from 1 to the line count, lines counted on \n alone with one CR before it stripped (U+2028, U+0085 and a form feed
 * are not line breaks here, as they are not in an editor); a file with no lone CR (one not before \n: old Mac line ends,
 * which would make the file one line here and so let a token match anywhere; T29-P1-C73); and a token of at least MIN_CITE_TOKEN_CHARS characters,
 * with no CR or LF, found on that line. Anything else given is failed. No citation (no file) is none.
 *
 * A path leaves the machine only through ids.sentPath, as every walked path does, so a name-like folder or file name is
 * hashed. */
import { readFileSync } from "node:fs";
import { holdsRecordValue, sentPath } from "./ids.mjs";
import { readWalked } from "./walkread.mjs";

export const MIN_CITE_TOKEN_CHARS = 3; // core enums.MIN_CITE_TOKEN_CHARS
export const CITE_MAX_BYTES = 2_000_000; // the walk's own maxBytes (files.mjs walk), so a cited file is one it reads

/* The lines of `text` as an editor counts them: split on \n, each line's trailing \r dropped. */
export function citeLines(text) {
  return text.split("\n").map((line) => (line.endsWith("\r") ? line.slice(0, -1) : line));
}

/* The walk's entry for a path the assistant gave, or null. */
const walkedFile = (files, path) => (typeof path === "string" ? files.get(path.normalize("NFC")) ?? null : null);

const LONE_CR = /\r(?!\n)/;

/* The cited file's lines, or null when it can't be read as text or has a lone CR. `cache` (path -> lines) is one
 * call's, so a file many records cite is read once. */
async function fileLines(root, f, cache = null) {
  if (cache?.has(f.path)) return cache.get(f.path);
  const read = await readWalked(root, f.disk ?? f.path, CITE_MAX_BYTES);
  const text = read.buf && !read.buf.includes(0) ? read.buf.toString("utf8") : null;
  const lines = text === null || LONE_CR.test(text) ? null : citeLines(text);
  cache?.set(f.path, lines);
  return lines;
}

/* -> {cite: "ok" | "failed" | "none", file} with the walk's entry for ok. */
export async function checkCitation(root, files, cite, cache = null) {
  if (!cite || typeof cite !== "object" || cite.file === undefined || cite.file === null) return { cite: "none" };
  const { line, token } = cite;
  const f = walkedFile(files, cite.file);
  if (!f) return { cite: "failed" };
  if (!Number.isInteger(line) || line < 1) return { cite: "failed" };
  if (typeof token !== "string" || [...token].length < MIN_CITE_TOKEN_CHARS || /[\r\n]/.test(token)) return { cite: "failed" };
  const lines = await fileLines(root, f, cache);
  if (!lines || line > lines.length) return { cite: "failed" };
  return lines[line - 1].includes(token) ? { cite: "ok", file: f } : { cite: "failed" };
}

/* The contract's rules, fields and values, from the synced contracts/fact_schema.json (core enums.FACT_*). */
const FACT_SCHEMA = JSON.parse(readFileSync(new URL("./contracts/fact_schema.json", import.meta.url), "utf8"));
const DOC_SCHEMA = JSON.parse(readFileSync(new URL("./contracts/fact_document.schema.json", import.meta.url), "utf8"));
export const FACT_FIELDS = Object.freeze(Object.fromEntries(Object.entries(FACT_SCHEMA.rules)
  .map(([rule, spec]) => [rule, Object.freeze(Object.keys(spec.fields))])));
export const FACT_VALUES = Object.freeze(Object.fromEntries(Object.values(FACT_SCHEMA.rules)
  .flatMap((spec) => Object.entries(spec.fields).map(([field, about]) => [field, Object.freeze([...about.values])]))));
const LIST_FIELDS = new Set(Object.values(FACT_SCHEMA.rules)
  .flatMap((spec) => Object.entries(spec.fields).filter(([, about]) => "columns" in about).map(([field]) => field)));
const UNKNOWN = "unknown";
const ROW = DOC_SCHEMA.properties.cited_facts;
const MAX_ROWS = ROW.maxItems;
const MAX_COLUMNS = ROW.items.properties.column_names.maxItems;
const LOCATION = new RegExp(ROW.items.properties.candidate.anyOf[0].pattern);
const LOCATION_MAX = ROW.items.properties.candidate.anyOf[0].maxLength;
const PG_NAME = new RegExp(ROW.items.properties.column_names.items.pattern);
const plainName = (n) => typeof n === "string" && PG_NAME.test(n) && !holdsRecordValue(n);
const located = (s) => s.length <= LOCATION_MAX && LOCATION.test(s);

/* A candidate as the row carries it, or null to drop the record. An authz or write_fields candidate is a handler's
 * path:line in a walked file, the line inside it, sent through sentPath; an rls candidate is schema.table, each part
 * a plain catalog name (no hashed form fits the row, so any other name drops the record). */
async function sentCandidate(root, files, key, rule, c, cache) {
  if (typeof c !== "string") return null;
  if (rule === "rls") {
    const parts = c.split(".");
    return parts.length === 2 && parts.every(plainName) ? c : null;
  }
  const m = /^(.*):([1-9][0-9]{0,6})$/.exec(c);
  const f = m ? walkedFile(files, m[1]) : null;
  if (!f) return null;
  const lines = await fileLines(root, f, cache);
  if (!lines || Number(m[2]) > lines.length) return null;
  const sent = `${sentPath(key, f.path)}:${m[2]}`;
  return located(sent) ? sent : null;
}

/* One field's value as the row carries it: [value, column_names]. Off the list, or a column that isn't a plain
 * catalog name (or reads as a record value), is unknown: never in the project's favour. */
function rowValue(field, given) {
  if (LIST_FIELDS.has(field)) {
    if (!Array.isArray(given) || given.length > MAX_COLUMNS || !given.every(plainName)) return [UNKNOWN, []];
    return [FACT_VALUES[field][0], [...new Set(given)]];
  }
  return [typeof given === "string" && FACT_VALUES[field].includes(given) ? given : UNKNOWN, []];
}

/* cited_facts' share of the fact document (T29-P1-C73, P3 C96, P2 C70). The section is built before fitToSize, which
 * cuts matches to fit MAX_DOCUMENT_BYTES, so without a share a long facts list could push out the inspector's own
 * matches. Matches come first. */
export const CITED_FACTS_MAX_BYTES = 1_000_000;

/* The assistant's fact records -> {rows, dropped}: cited_facts rows in record and field order. A record whose rule or
 * candidate the contract doesn't allow is dropped as bad (not counted). Whole candidates are kept in record order while
 * their rows fit both maxBytes (the rows' JSON) and maxRows (the schema's maxItems); from the first that doesn't fit,
 * every later record is dropped and counted in `dropped`, never cut part way, so the same input keeps the same rows.
 * `root` is the walked root's absolute path, `files` its walk entries by path, `key` the install key. */
export async function citedFacts(root, files, key, records, { maxBytes = CITED_FACTS_MAX_BYTES, maxRows = MAX_ROWS } = {}) {
  const rows = [];
  const list = Array.isArray(records) ? records : [];
  const cache = new Map();
  let rowBytes = 0; // the kept rows' JSON, without the array's brackets and commas
  for (let i = 0; i < list.length; i += 1) {
    const rec = list[i];
    if (!rec || typeof rec !== "object" || !Object.hasOwn(FACT_FIELDS, rec.rule)) continue;
    const candidate = await sentCandidate(root, files, key, rec.rule, rec.candidate, cache);
    if (candidate === null) continue;
    const own = [];
    for (const field of FACT_FIELDS[rec.rule]) {
      const fact = rec[field] && typeof rec[field] === "object" ? rec[field] : {};
      const [value, columnNames] = rowValue(field, fact.value);
      let { cite, file } = value === UNKNOWN ? { cite: "none" } : await checkCitation(root, files, fact, cache);
      const at = cite === "ok" ? `${sentPath(key, file.path)}:${fact.line}` : null;
      if (at !== null && !located(at)) cite = "failed"; // a sent path too long for a location
      own.push({ rule: rec.rule, candidate, field, value, column_names: columnNames, cited_at: cite === "ok" ? at : null, cite });
    }
    const ownBytes = own.reduce((n, r) => n + Buffer.byteLength(JSON.stringify(r), "utf8"), 0);
    const n = rows.length + own.length;
    if (n > maxRows || 2 + rowBytes + ownBytes + (n - 1) > maxBytes) return { rows, dropped: list.length - i };
    rows.push(...own);
    rowBytes += ownBytes;
  }
  return { rows, dropped: 0 };
}

/* The rows alone (citedFacts' rows). */
export async function citedFactRows(root, files, key, records, limits) {
  return (await citedFacts(root, files, key, records, limits)).rows;
}

/* The local note for candidates dropped past the share: a count, no names, never sent. */
export const droppedFactsNote = (n) => `${n} fact record${n === 1 ? " was" : "s were"} left out of the fact document: `
  + "the facts sent were over their 1,000,000-byte share, so the inspector kept whole records in the order given while "
  + "they fit. Custosa reads each left-out candidate as a missing fact.";

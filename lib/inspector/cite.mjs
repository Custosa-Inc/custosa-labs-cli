/* T29 line item h, h2 (T29-P3-C85, decided in C87; P2 C63 point 2): the inspector's check of the citation the
 * assistant gives for a fact. The fact document carries only the result (cited_facts[].cite: ok, failed or none) and,
 * for ok, the file and line; the token never leaves the machine.
 *
 * ok needs all of: a file the walk analysed (`walked`, the walk's own relative paths, so a skipped, missing or
 * unlisted file is failed), read through readWalked (a regular file, no symlink, its realpath inside the root, no
 * larger than the walk reads); text with no NUL byte; a line number that is a whole number from 1 to the line count,
 * lines counted on \n alone with one CR before it stripped (U+2028, U+0085 and a form feed are not line breaks here,
 * as they are not in an editor); and a token of at least MIN_CITE_TOKEN_CHARS characters, with no CR or LF, found on
 * that line. Anything else given is failed. No citation (no file) is none. */
import { readFileSync } from "node:fs";
import { holdsRecordValue } from "./ids.mjs";
import { readWalked } from "./walkread.mjs";

export const MIN_CITE_TOKEN_CHARS = 3; // core enums.MIN_CITE_TOKEN_CHARS
export const CITE_MAX_BYTES = 2_000_000; // the walk's own maxBytes (files.mjs walk), so a cited file is one it reads

/* The lines of `text` as an editor counts them: split on \n, each line's trailing \r dropped. */
export function citeLines(text) {
  return text.split("\n").map((line) => (line.endsWith("\r") ? line.slice(0, -1) : line));
}

/* -> "ok" | "failed" | "none" */
export async function checkCitation(root, walked, cite) {
  if (!cite || typeof cite !== "object" || cite.file === undefined || cite.file === null) return "none";
  const { file, line, token } = cite;
  if (typeof file !== "string" || !walked.has(file)) return "failed";
  if (!Number.isInteger(line) || line < 1) return "failed";
  if (typeof token !== "string" || [...token].length < MIN_CITE_TOKEN_CHARS || /[\r\n]/.test(token)) return "failed";
  const read = await readWalked(root, file, CITE_MAX_BYTES);
  if (!read.buf || read.buf.includes(0)) return "failed";
  const lines = citeLines(read.buf.toString("utf8"));
  if (line > lines.length) return "failed";
  return lines[line - 1].includes(token) ? "ok" : "failed";
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
const QUALIFIED = new RegExp(ROW.items.properties.candidate.anyOf[1].pattern);
const PG_NAME = new RegExp(ROW.items.properties.column_names.items.pattern);
const LOCATION_MAX = ROW.items.properties.candidate.anyOf[0].maxLength;

const candidateOk = (rule, c) => typeof c === "string"
  && (rule === "rls" ? QUALIFIED.test(c) : c.length <= LOCATION_MAX && LOCATION.test(c));

/* One field's value as the row carries it: [value, column_names]. Off the list, or a column that isn't a plain
 * catalog name (or reads as a record value), is unknown: never in the project's favour. */
function rowValue(field, given) {
  if (LIST_FIELDS.has(field)) {
    if (!Array.isArray(given) || given.length > MAX_COLUMNS) return [UNKNOWN, []];
    if (!given.every((c) => typeof c === "string" && PG_NAME.test(c) && !holdsRecordValue(c))) return [UNKNOWN, []];
    return [FACT_VALUES[field][0], [...new Set(given)]];
  }
  return [typeof given === "string" && FACT_VALUES[field].includes(given) ? given : UNKNOWN, []];
}

/* The assistant's fact records -> cited_facts rows, in record and field order, at most the schema's maxItems. */
export async function citedFactRows(root, walked, records) {
  const rows = [];
  for (const rec of Array.isArray(records) ? records : []) {
    if (!rec || typeof rec !== "object" || !Object.hasOwn(FACT_FIELDS, rec.rule) || !candidateOk(rec.rule, rec.candidate)) continue;
    for (const field of FACT_FIELDS[rec.rule]) {
      const fact = rec[field] && typeof rec[field] === "object" ? rec[field] : {};
      const [value, columnNames] = rowValue(field, fact.value);
      let cite = value === UNKNOWN ? "none" : await checkCitation(root, walked, fact);
      const at = cite === "ok" ? `${fact.file}:${fact.line}` : null;
      if (at !== null && !(at.length <= LOCATION_MAX && LOCATION.test(at))) cite = "failed"; // a path no location can name
      rows.push({ rule: rec.rule, candidate: rec.candidate, field, value, column_names: columnNames,
        cited_at: cite === "ok" ? at : null, cite });
      if (rows.length >= MAX_ROWS) return rows;
    }
  }
  return rows;
}

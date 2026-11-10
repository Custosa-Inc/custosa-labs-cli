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

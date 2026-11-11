/* T29-P1-C192 item 3 (P2 C198 item 1): a person question or a fix that names a handler names it by its 64-hex id
 * (rule_bundle.md 3.3, an HMAC over its path, name and place), which nobody can read: 405 of 2,081 decisions on the 20
 * sweep repos. The check's own handler map (factdoc.handlerMap: id -> {path, name, line}) is kept on this machine for
 * each session, and an answer shown to the assistant names each handler it knows as "GET at src/app/x/route.ts:6".
 * Nothing new is sent, and the map never leaves this process.
 * - Only prose is rewritten. A field the assistant sends back (an object or finding id, a session, a select) keeps
 *   the id as core wrote it, so every later call still names the same object.
 * - An id the map doesn't hold (the map stops at the check's deadline) stays as it is.
 * - The answer stays under the client's limit: if the names would take it past CLIENT_OUTPUT_CHARS less NOTE_ROOM,
 *   it is shown as core wrote it. */
import { CLIENT_OUTPUT_CHARS } from "./concerns.mjs";

const NOTE_ROOM = 2_000;
const HANDLER_ID = /(?<![0-9a-f])(?:([a-z0-9][a-z0-9-]{0,63})@)?([0-9a-f]{64})(?![0-9a-f])/g;
// Keys whose values the assistant echoes back, or that core matches on: never rewritten.
const KEPT_KEY = /(?:^|_)(?:id|ids|session|select|object|objects|finding|findings|handler|fingerprint|digest|key|ref|refs)$/;

/* "GET at src/app/x/route.ts:6"; a handler with no name is "a handler at <path>:<line>". */
export function handlerLabel(entry) {
  if (!entry || typeof entry.path !== "string" || !Number.isInteger(entry.line)) return null;
  return `${typeof entry.name === "string" && entry.name ? entry.name : "a handler"} at ${entry.path}:${entry.line}`;
}

function rewriteText(text, handlers) {
  return text.replace(HANDLER_ID, (whole, _practice, id) => handlerLabel(handlers[id]) ?? whole);
}

function walk(value, handlers, key) {
  if (typeof value === "string") return key !== null && KEPT_KEY.test(key) ? value : rewriteText(value, handlers);
  if (Array.isArray(value)) {
    // a list under a kept key (finding_ids) is kept whole; a list of objects is walked
    return value.map((v) => (typeof v === "string" && key !== null && KEPT_KEY.test(key) ? v : walk(v, handlers, typeof v === "string" ? key : null)));
  }
  if (value && typeof value === "object") {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = walk(v, handlers, k);
    return out;
  }
  return value;
}

/** `answer` with each handler id in its prose named from `handlers` (id -> {path, name, line}); the same object when
 * there is nothing to name or the names don't fit. */
export function withHandlerNames(answer, handlers) {
  if (!answer || typeof answer !== "object" || !handlers || !Object.keys(handlers).length) return answer;
  const out = walk(answer, handlers, null);
  const size = JSON.stringify(out).length;
  if (size === JSON.stringify(answer).length && JSON.stringify(out) === JSON.stringify(answer)) return answer;
  return size > CLIENT_OUTPUT_CHARS - NOTE_ROOM ? answer : out;
}

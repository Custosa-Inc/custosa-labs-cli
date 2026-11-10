/* The assistant's concern texts (contract 2.4, evaluator_api.md 1.11), kept only on this computer in
 * <project root>/.custosa/local/concerns.json, which .custosa/.gitignore leaves out of git.
 *
 * A concern's text goes to the evaluator once, in the call that raises it. The evaluator keeps only its metadata and
 * never sends the text back, so the inspector keeps its own copy by the concern's server id and shows it beside the
 * concern in later responses (local_text). It is never sent again: no later body carries it.
 *
 * rememberRaised(root, sent, answer) -> {note, pending}
 *   after a raising call: the response's raised_now concerns come first, newest first (respond.concerns_block), so
 *   they map to the sent concerns in reverse order. Each listed raise is saved when its metadata matches; whether the
 *   evaluator kept the raises is read from those entries, not from concerns_saved, which a losing decision also sets.
 *   `answer.concerns` is every concern of the call: the index's, or the grouped ones the CLI read through get_result
 *   (T29 o2, T29-P1-C116), so nothing waits for a later call and `pending` is always null. A note says which texts
 *   weren't kept; none when the call lists no raise and concerns_saved is false (the evaluator's next step says to
 *   send them again), and one when the call ended in an error after which the evaluator may have kept the raises.
 * forgetRefused(root, answer) -> void
 *   ids the evaluator answered unknown_concern (never raised, expired or pruned) are dropped here too.
 * withTexts(answer, root, { from }) -> answer
 *   each listed concern whose id is kept gets local_text, cut to MAX_TEXT: the evaluation answer's index.concerns lines
 *   (from "index", the default; T29-P1-C127 (a)), at most MAX_INDEX_TEXTS of them, or a get_result read's results
 *   (from "results"). Texts stop once the next one would take the answer past CLIENT_OUTPUT_CHARS, less NOTE_ROOM, and
 *   the answer's local_notes then say how many were left out and that get_result shows them (T29-P1-C136): a text is
 *   never dropped without saying so. A line with no kept text gets none. The response's own object is never changed.
 * The file is written whole through a temp file and a rename, never through a symlink, mode 0600. A file that is there
 * but can't be read (unreadable, too large, not JSON, another version) shows nothing and is never rewritten, since that
 * would drop the texts it held (T29 conventions audit B4): a raise says concern_texts_unread instead. */
import { lstatSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { GITIGNORE, isLink, STATE_DIR } from "./state.mjs";

export const LOCAL_DIR = "local";
export const CONCERNS_FILE = "concerns.json";
export const MAX_KEPT = 1000; // texts kept per project; the oldest go first past it
export const MAX_TEXT = 500; // a concern's note, as the tool's input takes it
export const MAX_INDEX_TEXTS = 50; // texts shown on an answer's index.concerns lines: the concerns one call may raise
// The client's tool-output limit, as core's result_store.client_output_chars() gives it for an unknown client (the
// smallest it knows: Claude Code's MAX_MCP_OUTPUT_TOKENS default, 25,000 tokens at 4 characters each). Core sizes the
// answer to fit it, so the texts added here must fit in what is left.
export const CLIENT_OUTPUT_CHARS = 100_000;
const NOTE_ROOM = 2_000; // kept free under the limit for local_notes: this one and the call's other fixed notes
const TEXT_KEY = ',"local_text":'.length;
const MAX_BYTES = 4 * 1024 * 1024;
const TMP_SUFFIX = ".custosa-tmp";
const ID = /^cn_[0-9a-f]{16}$/;
const META = ["category", "area", "file_kind", "practice_id", "proposed_severity"];

export const CONCERN_NOTES = Object.freeze({
  concern_texts_not_kept: "concern_texts_not_kept: the evaluator's list of the concerns this call raised didn't match "
    + "what was sent, so their texts weren't kept on this computer. The concerns are listed without them.",
  concern_texts_unanswered: "concern_texts_unanswered: the evaluator didn't answer the call that sent these concerns, so "
    + "their texts weren't kept on this computer. If its next_step says the concern changes were kept, read the concerns "
    + "first and raise again only those that aren't listed.",
  concern_texts_unread: "concern_texts_unread: .custosa/local/concerns.json is there but couldn't be read, so it was left "
    + "as it is and the texts of the concerns this call raised aren't kept on this computer. The concerns are listed "
    + "without them. Move that file aside, or .custosa/local itself, if it is a file, to start a new one.",
  concern_texts_unwritable: "concern_texts_unwritable: .custosa/local/concerns.json couldn't be written, so the texts of "
    + "the concerns this call raised aren't kept on this computer. The concerns are listed without them.",
  concern_texts_left_out: "concern_texts_left_out: {n} kept concern texts aren't shown on this answer: an evaluation "
    + "answer shows at most 50, and none past the client's output limit. They are still kept on this computer. get_result with "
    + "select {\"list\": \"concerns.<status>\"}, or one entry of it (\"concerns.<status>#<n>\"), shows each concern with "
    + "its kept text.",
});

const pathsOf = (root) => {
  const dir = join(root, STATE_DIR);
  const local = join(dir, LOCAL_DIR);
  return { dir, local, file: join(local, CONCERNS_FILE) };
};

/* The kept texts by id, oldest first; empty when the file is missing or can't be read. */
export function readTexts(root) {
  return loadTexts(root) ?? new Map();
}

/* The kept texts, empty when there is no file yet or a symlink is in the way (never read, and writeTexts refuses it),
 * null when the file is there and can't be read: unreadable, too large, not JSON or not this shape. */
function loadTexts(root) {
  const { dir, local, file } = pathsOf(root);
  if (isLink(dir) || isLink(local) || isLink(file)) return new Map();
  try {
    if (lstatSync(file).size > MAX_BYTES) return null;
    const data = JSON.parse(readFileSync(file, "utf8"));
    if (data?.version !== 1 || !data.concerns || typeof data.concerns !== "object" || Array.isArray(data.concerns)) return null;
    const out = new Map();
    for (const [id, e] of Object.entries(data.concerns)) {
      if (ID.test(id) && typeof e?.text === "string") out.set(id, e);
    }
    return out;
  } catch (err) {
    return err?.code === "ENOENT" ? new Map() : null;
  }
}

function writeTexts(root, texts) {
  const { dir, local, file } = pathsOf(root);
  if (isLink(dir) || isLink(local) || isLink(file)) return false;
  const kept = [...texts].slice(-MAX_KEPT);
  const text = `${JSON.stringify({ version: 1, concerns: Object.fromEntries(kept) }, null, 2)}\n`;
  const tmp = `${file}${TMP_SUFFIX}`;
  try {
    mkdirSync(local, { recursive: true, mode: 0o700 });
    if (isLink(dir) || isLink(local)) return false;
    try { writeFileSync(join(dir, ".gitignore"), GITIGNORE, { flag: "wx" }); } catch (err) { if (err.code !== "EEXIST") throw err; }
    rmSync(tmp, { force: true }); // a left-over or planted temp file; "wx" then never follows a link
    writeFileSync(tmp, text, { flag: "wx", mode: 0o600 });
    renameSync(tmp, file);
    return true;
  } catch {
    rmSync(tmp, { force: true });
    return false;
  }
}

// Errors after which the evaluator may have kept the raises: their own messages say the call may
// have run. Errors refused before any work (bad_request, update_inspector and the like) keep nothing, so say nothing.
const MAY_HAVE_RUN = new Set(["unavailable", "internal_error", "evaluator_response_invalid", "evaluator_connection_lost",
  "evaluator_response_incomplete"]);
const sameMeta = (sent, listed) => META.every((k) => (sent[k] ?? null) === (listed[k] ?? null));

export function rememberRaised(root, sent, answer) {
  const none = { note: null, pending: null };
  if (!root || !Array.isArray(sent) || !sent.length || !answer || typeof answer !== "object") return none;
  if (answer.error) return MAY_HAVE_RUN.has(answer.error) ? { note: CONCERN_NOTES.concern_texts_unanswered, pending: null } : none;
  return matchPage({ root, left: sent, quiet: answer.concerns_saved === false }, answer);
}

/* The call's concerns against the ones it sent, oldest first: its raises are the newest of them. */
function matchPage({ root, left, quiet }, answer) {
  const listed = Array.isArray(answer.concerns) ? answer.concerns : [];
  const raised = listed.filter((c) => c?.raised_now === true);
  // Matched by order and metadata only: core 1ea2abf8 has no path that reorders a call's raises, and a
  // count or metadata mismatch keeps no text at all rather than a wrong one.
  const at = (i) => left[left.length - 1 - i];
  if (raised.length > left.length || !raised.every((c, i) => ID.test(c.concern_id) && sameMeta(at(i), c))) {
    return { note: CONCERN_NOTES.concern_texts_not_kept, pending: null };
  }
  let note = null;
  if (raised.length) {
    const texts = loadTexts(root);
    if (!texts) note = CONCERN_NOTES.concern_texts_unread;
    else {
      for (let i = raised.length - 1; i >= 0; i--) {
        const c = raised[i], sent = at(i);
        const entry = { text: sent.note }; // the note, kept under the file's text key
        for (const k of META) if (sent[k] !== undefined) entry[k] = sent[k];
        texts.delete(c.concern_id); // a raise replayed by its key moves to the newest end
        texts.set(c.concern_id, entry);
      }
      if (!writeTexts(root, texts)) note = CONCERN_NOTES.concern_texts_unwritable;
    }
  }
  const rest = left.slice(0, left.length - raised.length);
  if (!rest.length) return { note, pending: null };
  // T29 o2 (T29-P1-C116): the answer's concerns are every concern of the call (the CLI read any grouped ones), so a
  // raise not listed is one the evaluator didn't keep. quiet: concerns_saved false and no raise listed.
  return { note: note ?? (quiet && !raised.length ? null : CONCERN_NOTES.concern_texts_not_kept), pending: null };
}

export function forgetRefused(root, answer) {
  const gone = (Array.isArray(answer?.concern_outcomes) ? answer.concern_outcomes : [])
    .filter((o) => o?.outcome === "refused" && o.reason === "unknown_concern").map((o) => o.concern_id);
  if (!root || !gone.length) return;
  const texts = loadTexts(root);
  if (texts && gone.some((id) => texts.delete(id))) writeTexts(root, texts);
}

export function withTexts(answer, root, { from = "index" } = {}) {
  const list = from === "results" ? answer?.results
    : answer?.index && typeof answer.index === "object" ? answer.index.concerns : undefined;
  if (!root || !Array.isArray(list) || !list.length) return answer;
  const texts = readTexts(root);
  if (!texts.size) return answer;
  // The answer as core sized it, plus each text's key and value, stays under the limit (T29-P1-C136 low 1). The first
  // text that doesn't fit stops the rest, so the texts shown are always the first lines'.
  let room = CLIENT_OUTPUT_CHARS - NOTE_ROOM - JSON.stringify(answer).length;
  const cap = from === "results" ? Infinity : MAX_INDEX_TEXTS;
  let shown = 0, left = 0;
  const lines = list.map((c) => {
    const kept = texts.get(c?.concern_id);
    if (!kept) return c;
    const text = kept.text.slice(0, MAX_TEXT);   // both branches cut (low 2): a hand-edited file may hold more
    const cost = TEXT_KEY + JSON.stringify(text).length;
    if (left || shown >= cap || cost > room) { left += 1; return c; }
    room -= cost;
    shown += 1;
    return { ...c, local_text: text };
  });
  let out = answer;
  if (shown) out = from === "results" ? { ...out, results: lines } : { ...out, index: { ...answer.index, concerns: lines } };
  if (left) {
    const notes = Array.isArray(out.local_notes) ? out.local_notes : [];
    out = { ...out, local_notes: [...notes, CONCERN_NOTES.concern_texts_left_out.replace("{n}", String(left))] };
  }
  return out;
}

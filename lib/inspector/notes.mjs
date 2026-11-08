/* The note screen in check_schema (screening design §4, §8, §13 items 8 and 18).
 *
 * Before anything is sent, each verdict and concern note is screened with screen.mjs on the snapshot ids of the first
 * root's fact document, with the session's previous accepted note in front of it (§13 item 18). A refused call sends
 * nothing: the refusal names each refused note and its rule ids, never the note. A session has MAX_REFUSED_CALLS
 * refused calls; after that, each note still refused is withheld: the item goes out with note_withheld: true in place
 * of the note, and the note is kept only in .custosa/local/withheld.jsonl. The counts and the previous note are kept
 * in memory by session, never in .custosa/state.json (§13 item 8), at most MAX_NOTE_SESSIONS sessions.
 *
 * makeNoteScreen(rules) -> screenNotes(args, document, {session, root, now})
 *   -> {refused: [{field, rules}], left} | {args, withheld: [{field, rules}]}
 *   args is the call's own when nothing is withheld, else a copy with each withheld note replaced. */
import { screenRaw } from "../screen.mjs";
import { snapshotIds } from "./snapshot.mjs";
import { keepWithheld } from "./withheld.mjs";

export const MAX_REFUSED_CALLS = 2;
export const MAX_NOTE_SESSIONS = 100;

/* The notes a call carries, in the order they are screened: verdicts, then concerns. */
function notesOf(args) {
  const out = [];
  for (const [kind, items] of [["verdicts", args.verdicts], ["concerns", args.concerns]]) {
    for (const [i, item] of (Array.isArray(items) ? items : []).entries()) {
      if (typeof item?.note === "string" && item.note_kept_local !== true) out.push({ kind, i, field: `${kind}[${i}].note`, note: item.note, practice_id: item.practice_id });
    }
  }
  return out;
}

const withheldItem = ({ note, ...item }) => ({ ...item, note_withheld: true });

export function makeNoteScreen(rules) {
  const sessions = new Map(); // key -> {refused, previous}
  return function screenNotes(args, document, { session = null, root = null, now = Date.now() } = {}) {
    const notes = notesOf(args);
    if (!notes.length) return { args, withheld: [] };
    const key = session ?? `root:${root}`;
    const state = sessions.get(key) ?? { refused: 0, previous: null };
    sessions.delete(key);
    sessions.set(key, state);
    while (sessions.size > MAX_NOTE_SESSIONS) sessions.delete(sessions.keys().next().value);
    const ids = [...snapshotIds(document)];
    let previous = state.previous;
    const refused = [];
    for (const n of notes) {
      const { decision, hits } = screenRaw(n.note, ids, rules, previous);
      if (decision === "pass") { previous = n.note; continue; }
      refused.push({ ...n, rules: [...new Set(hits.map((h) => h.rule))] });
    }
    if (refused.length && state.refused < MAX_REFUSED_CALLS) {
      state.refused += 1;
      return { refused: refused.map(({ field, rules: r }) => ({ field, rules: r })), left: MAX_REFUSED_CALLS - state.refused };
    }
    state.previous = previous;
    if (!refused.length) return { args, withheld: [] };
    const out = { ...args };
    for (const kind of ["verdicts", "concerns"]) {
      const mine = refused.filter((r) => r.kind === kind);
      if (mine.length) out[kind] = args[kind].map((item, i) => (mine.some((r) => r.i === i) ? withheldItem(item) : item));
    }
    keepWithheld(root, refused.map((r) => ({ session, field: r.field, ...(r.practice_id ? { practice_id: r.practice_id } : {}),
      rules: r.rules, note: r.note })), { now });
    return { args: out, withheld: refused.map(({ field, rules: r }) => ({ field, rules: r })) };
  };
}

/* T28-P1-C3: the file refs (a path, or path:line) of the call's verdicts and concerns that none of the documents' snapshot
 * ids name, in order: {field, why}, why line_uncited when the path alone is an id (the document names the file but cites
 * no such line) and not_read otherwise. Object ids (with "@"), practice ids and names without "/" or a line are left to
 * the evaluator's own binding. Never the ref itself. */
const LINE = /:[1-9][0-9]{0,6}(?:-[1-9][0-9]{0,6})?$/;
export function refsRefused(args, documents) {
  const ids = new Set();
  for (const d of documents) for (const id of snapshotIds(d)) ids.add(id);
  const out = [];
  for (const kind of ["verdicts", "concerns"]) {
    for (const [i, item] of (Array.isArray(args[kind]) ? args[kind] : []).entries()) {
      for (const [j, ref] of (Array.isArray(item?.refs) ? item.refs : []).entries()) {
        if (typeof ref !== "string" || ref.includes("@") || ids.has(ref)) continue;
        const line = LINE.exec(ref);
        if (!line && !ref.includes("/")) continue;
        const path = line ? ref.slice(0, line.index) : null;
        out.push({ field: `${kind}[${i}].refs[${j}]`, why: path !== null && ids.has(path) ? "line_uncited" : "not_read" });
      }
    }
  }
  return out;
}

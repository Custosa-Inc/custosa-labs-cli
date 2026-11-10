/* The notes the CLI withholds, kept only on this computer in
 * <project root>/.custosa/local/withheld.jsonl, which .custosa/.gitignore leaves out of git.
 *
 * When a note is still refused on a session's third refused call, the item goes out with note_withheld: true and the
 * note stays here, so the developer can read what was held back. Nothing here is ever sent or shown to the assistant.
 *
 * keepWithheld(root, entries, {now}) -> boolean
 *   appends each {session, field, practice_id?, rules, note} with its time (at), then drops entries older than
 *   WITHHELD_DAYS and the oldest past MAX_WITHHELD. false when the file couldn't be written.
 *   A file that is there but can't be read whole (unreadable, too large) is left as it is, and that is false too (T29
 *   conventions audit B4): rewriting it from nothing would drop what it held.
 * readWithheld(root) -> [{at, ...entry}]
 *   oldest first; a line that isn't a JSON object with a string at and note is skipped. [] when there is no file or it
 *   can't be read.
 * The file is written whole through a temp file and a rename, never through a symlink, mode 0600 (as concerns.mjs). */
import { lstatSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { GITIGNORE, isLink, STATE_DIR } from "./state.mjs";
import { LOCAL_DIR } from "./concerns.mjs";

export const WITHHELD_FILE = "withheld.jsonl";
export const MAX_WITHHELD = 200;
export const WITHHELD_DAYS = 30;
const MAX_BYTES = 4 * 1024 * 1024;
const TMP_SUFFIX = ".custosa-tmp";
const DAY_MS = 86_400_000;

const pathsOf = (root) => {
  const dir = join(root, STATE_DIR);
  const local = join(dir, LOCAL_DIR);
  return { dir, local, file: join(local, WITHHELD_FILE) };
};

export function readWithheld(root) {
  return load(root) ?? [];
}

/* The entries, [] when there is no file yet, null when it is there and can't be read whole. */
function load(root) {
  const { dir, local, file } = pathsOf(root);
  if (isLink(dir) || isLink(local) || isLink(file)) return null;
  try {
    if (lstatSync(file).size > MAX_BYTES) return null;
    const out = [];
    for (const line of readFileSync(file, "utf8").split("\n")) {
      if (!line.trim()) continue;
      try {
        const e = JSON.parse(line);
        if (e && typeof e === "object" && !Array.isArray(e) && typeof e.at === "string" && typeof e.note === "string") out.push(e);
      } catch { /* a line that isn't JSON is skipped */ }
    }
    return out;
  } catch (err) {
    return err?.code === "ENOENT" ? [] : null;
  }
}

export function keepWithheld(root, entries, { now = Date.now() } = {}) {
  const { dir, local, file } = pathsOf(root);
  if (!root || isLink(dir) || isLink(local) || isLink(file)) return false;
  const held = load(root);
  if (!held) return false;
  const at = new Date(now).toISOString();
  const cutoff = now - WITHHELD_DAYS * DAY_MS;
  const kept = [...held, ...entries.map((e) => ({ at, ...e }))]
    .filter((e) => Date.parse(e.at) >= cutoff).slice(-MAX_WITHHELD);
  const text = kept.map((e) => `${JSON.stringify(e)}\n`).join("");
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

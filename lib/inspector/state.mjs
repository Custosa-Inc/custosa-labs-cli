/* The committed state file, <project root>/.custosa/state.json.
 *
 * It holds a person's decisions, suppressions and grant baselines, sealed by the core, and the project's content key.
 * Teammates and CI read the same file from git. Only this CLI writes it, never in CI, and only from entries the core
 * issued in report.state.to_commit. It never runs git.
 *
 * readState(root)                 -> {status: "missing"} | {status: "ok", state} | {status: "unreadable", reason}
 *   Strict: not UTF-8, a BOM, bad JSON or a duplicate key (parse); state_version missing or not 1 (version); over a
 *   cap (size); the schema or a rule it can't state (schema); .custosa or state.json a symlink (symlink). An
 *   unreadable file is ignored whole: nothing is sent, nothing is salvaged, and it is never written over.
 * blockOf(state)                  -> the body's committed block: only the fields the core reads, never the audit or
 *                                    the content key.
 * contentKeyOf(read)              -> the content key (64 hex) of a readState result, or null with no file or an unreadable one.
 * ciMode(env, {ci})               -> the CI variable found (or "--ci"), else null.
 * ignoredByGit(root)              -> whether git ignores .custosa/state.json, by the inspector's own ignore reading
 *                                    (gitread.mjs, which runs no program). No git repository, or an error: false.
 * writeState(root, read, adds, {env, ci}) -> {written, note?, variable?}
 *   Merges `adds` ({decisions?, suppressions?, grants_baseline?}, file-shaped entries) by key, sorts, validates and
 *   writes .custosa/state.json.custosa-tmp, then renames it into place. No backup, no symlink followed. Creates the
 *   content key on the first write (note state_key_created), and .custosa/.gitignore only when it is missing. */
import { randomBytes } from "node:crypto";
import { lstatSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import Ajv2020Module from "ajv/dist/2020.js";
import { FACT_SCHEMA } from "./schema.mjs";
import { isIgnored, locateGitdir } from "./gitread.mjs";

const Ajv2020 = Ajv2020Module.default ?? Ajv2020Module;
export const STATE_SCHEMA = JSON.parse(readFileSync(new URL("./contracts/state.schema.json", import.meta.url), "utf8"));
export const STATE_VERSION = 1;
export const STATE_MAX_BYTES = 2 * 1024 * 1024;
export const STATE_CAPS = { decisions: 1000, suppressions: 500, grants_baseline: 1000 };
export const MAX_COMMITTED_BYTES = 1_048_576;   // the body block's cap (contract 2.3 section 3.4)
/* Local notes, said by this inspector: the code first, then plain words. Never the file's content. */
export const STATE_NOTES = Object.freeze({
  state_unreadable: "state_unreadable: .custosa/state.json was not read ({reason}), so no committed decision was sent and every item shows Custosa's own state. The file is never written over; fix or remove it.",
  seal_mismatch: "seal_mismatch: the committed {kind} for {subject} in .custosa/state.json was changed by hand, so it was not used. Custosa never repairs it; record the decision again.",
  state_block_too_large: "state_block_too_large: the committed decisions in .custosa/state.json come to more than 1 MiB, so none were sent. Items show Custosa's own states.",
  state_ignored_by_git: "state_ignored_by_git: git ignores .custosa/state.json in this project, so teammates and CI won't read the decisions in it. Remove the ignore rule and commit the file.",
});
export const STATE_DIR = ".custosa";
export const STATE_FILE = "state.json";
const TMP_SUFFIX = ".custosa-tmp";
export const GITIGNORE = "local/\n*.custosa-tmp\n";
// Contract 2.3 section 1.1: CI mode is any of these set to anything but false or 0.
export const CI_VARIABLES = ["CI", "GITHUB_ACTIONS", "GITLAB_CI", "BUILDKITE", "CIRCLECI", "JENKINS_URL", "TF_BUILD",
  "CODEBUILD_BUILD_ID", "TEAMCITY_VERSION"];
const LISTS = ["decisions", "suppressions", "grants_baseline"];
const MADE_SENT = ["account_tag", "made_on", "fact_token", "seal"];

const ajv = new Ajv2020({ strict: false, allErrors: false });
ajv.addSchema(FACT_SCHEMA);   // the grant table's qualified_name is the fact schema's
const validate = ajv.compile(STATE_SCHEMA);

const keyOf = (list, entry) => list === "grants_baseline" ? `${entry.table}\u0000${entry.grantee}` : entry.subject;
const byCodePoint = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

/* Whether a JSON text, already parsed, repeats a key in any object. A small scanner over the text: strings are
 * skipped whole, and each object's keys are the strings followed by ":" at its own depth. */
function hasDuplicateKey(text) {
  const stack = [];
  let i = 0;
  while (i < text.length) {
    const c = text[i];
    if (c === "\"") {
      let j = i + 1;
      while (text[j] !== "\"") j += text[j] === "\\" ? 2 : 1;
      const raw = text.slice(i, j + 1);
      let k = j + 1;
      while (k < text.length && /\s/.test(text[k])) k += 1;
      const top = stack[stack.length - 1];
      if (text[k] === ":" && top instanceof Set) {
        const key = JSON.parse(raw);
        if (top.has(key)) return true;
        top.add(key);
      }
      i = j + 1;
      continue;
    }
    if (c === "{") stack.push(new Set());
    else if (c === "[") stack.push(null);
    else if (c === "}" || c === "]") stack.pop();
    i += 1;
  }
  return false;
}

export function isLink(path) {
  try {
    return lstatSync(path).isSymbolicLink();
  } catch {
    return false;
  }
}

/* The rules the schema can't state (contract section 2.3), on an object the schema accepted. */
function rulesHold(state) {
  for (const list of LISTS) {
    const keys = state[list].map((e) => keyOf(list, e));
    for (let n = 1; n < keys.length; n += 1) if (byCodePoint(keys[n - 1], keys[n]) >= 0) return false;
  }
  for (const list of ["decisions", "suppressions"]) {
    if (state[list].some((e) => e.practice_id !== e.subject.split("@")[0])) return false;
  }
  return state.grants_baseline.every((g) => g.privileges === null
    || g.privileges.every((p, n) => n === 0 || byCodePoint(g.privileges[n - 1], p) < 0));
}

export function readState(root) {
  const dir = join(root, STATE_DIR);
  const path = join(dir, STATE_FILE);
  if (isLink(dir) || isLink(path)) return { status: "unreadable", reason: "symlink" };
  let bytes;
  try {
    bytes = readFileSync(path);
  } catch (err) {
    if (err.code === "ENOENT" || err.code === "ENOTDIR") return { status: "missing" };
    return { status: "unreadable", reason: "parse" };
  }
  const bad = (reason) => ({ status: "unreadable", reason });
  if (bytes.length > STATE_MAX_BYTES) return bad("size");
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return bad("parse");
  }
  if (text.charCodeAt(0) === 0xfeff) return bad("parse");
  let state;
  try {
    state = JSON.parse(text);
  } catch {
    return bad("parse");
  }
  if (hasDuplicateKey(text)) return bad("parse");
  if (state === null || typeof state !== "object" || Array.isArray(state) || state.state_version !== STATE_VERSION) {
    return bad("version");
  }
  for (const list of LISTS) {
    if (Array.isArray(state[list]) && state[list].length > STATE_CAPS[list]) return bad("size");
  }
  if (!validate(state) || !rulesHold(state)) return bad("schema");
  return { status: "ok", state };
}

export function blockOf(state) {
  const made = (e) => Object.fromEntries(MADE_SENT.map((k) => [k, e.made[k]]));
  return {
    state_version: STATE_VERSION,
    decisions: state.decisions.map((d) => ({ object_id: d.subject, option: d.option, expires_on: d.expires_on,
      max_age_on: d.max_age_on, ...made(d) })),
    suppressions: state.suppressions.map((s) => ({ object_id: s.subject, reason: s.reason, expires_on: s.expires_on,
      ...made(s) })),
    grants: state.grants_baseline.map((g) => ({ table: g.table, grantee: g.grantee, privileges: g.privileges,
      expires_on: g.expires_on, ...made(g) })),
  };
}

export function ciMode(env = process.env, { ci = false } = {}) {
  if (ci) return "--ci";
  for (const name of CI_VARIABLES) {
    const value = env[name];
    if (value !== undefined && value !== "" && value !== "false" && value !== "0") return name;
  }
  return null;
}

export async function ignoredByGit(root) {
  try {
    if (!(await locateGitdir(root)).gitdir) return false;
    return await isIgnored(root, `${STATE_DIR}/${STATE_FILE}`);
  } catch {
    return false;
  }
}

export function contentKeyOf(read) {
  return read.status === "ok" ? read.state.content_key : null;
}

export const newContentKey = () => randomBytes(32).toString("hex");
export const emptyState = (contentKey) => ({ state_version: STATE_VERSION, content_key: contentKey, decisions: [],
  suppressions: [], grants_baseline: [] });

export function mergeEntries(state, adds) {
  const out = { ...state };
  for (const list of LISTS) {
    const byKey = new Map(state[list].map((e) => [keyOf(list, e), e]));
    for (const e of adds[list] ?? []) {
      const entry = list === "grants_baseline" && Array.isArray(e.privileges)
        ? { ...e, privileges: [...e.privileges].sort(byCodePoint) } : e;
      byKey.set(keyOf(list, entry), entry);
    }
    out[list] = [...byKey.keys()].sort(byCodePoint).map((k) => byKey.get(k));
  }
  return out;
}

/* Keys sorted at every level, 2-space indent, LF, a final newline: diffs and merges stay line-stable. */
function layout(value) {
  const sorted = (v) => Array.isArray(v) ? v.map(sorted) : v !== null && typeof v === "object"
    ? Object.fromEntries(Object.keys(v).sort(byCodePoint).map((k) => [k, sorted(v[k])])) : v;
  return `${JSON.stringify(sorted(value), null, 2)}\n`;
}

export function writeState(root, read, adds, { env = process.env, ci = false } = {}) {
  if (read.status === "unreadable") return { written: false, note: "state_unreadable" };
  const variable = ciMode(env, { ci });
  if (variable) return { written: false, note: "no_person_in_ci", variable };
  const dir = join(root, STATE_DIR);
  const path = join(dir, STATE_FILE);
  if (isLink(dir) || isLink(path)) return { written: false, note: "state_unreadable" };
  const created = read.status !== "ok";
  const state = mergeEntries(created ? emptyState(newContentKey()) : read.state, adds);
  if (LISTS.some((list) => state[list].length > STATE_CAPS[list])) return { written: false, note: "state_full" };
  const text = layout(state);
  if (Buffer.byteLength(text) > STATE_MAX_BYTES) return { written: false, note: "state_full" };
  if (!validate(state) || !rulesHold(state)) return { written: false, note: "state_subject_not_committable" };
  mkdirSync(dir, { recursive: true });
  if (isLink(dir)) return { written: false, note: "state_unreadable" };
  const tmp = `${path}${TMP_SUFFIX}`;
  try {
    rmSync(tmp, { force: true });   // a left-over or planted temp file; "wx" then never follows a link
    writeFileSync(tmp, text, { flag: "wx", mode: 0o644 });
    renameSync(tmp, path);
  } catch (err) {
    rmSync(tmp, { force: true });
    throw err;
  }
  try {
    writeFileSync(join(dir, ".gitignore"), GITIGNORE, { flag: "wx" });
  } catch (err) {
    if (err.code !== "EEXIST") throw err;
  }
  return created ? { written: true, note: "state_key_created" } : { written: true };
}

/* --- Writing what the core issued (contract 2.3 sections 2.3 and 5.2) ---------------------------------------------- */
const HASHES = /(?<![0-9A-Za-z])(?:[0-9a-f]{64}|u_[0-9a-f]{16})(?![0-9A-Za-z])/;
const LINE_END = /:[0-9]+(?:-[0-9]+)?$/;
const SECRETS_PRACTICES = new Set(["no-committed-secrets"]);   // results resting on content fingerprints

/* Whether a subject may go in a committed file: no per-install hash, no line ending, no value or secret in its name,
 * and not a practice whose result rests on content fingerprints. `screen` is the CLI's value screen (ids.mjs). */
export function committable(subject, screen) {
  if (HASHES.test(subject) || LINE_END.test(subject)) return false;
  const [practice, name = ""] = subject.split(/@(.*)/s);
  if (SECRETS_PRACTICES.has(practice)) return false;
  return !name || !screen(name);
}

/* The file entries for report.state.to_commit, with the local audit. Entries that may not be committed are left out
 * and counted (state_subject_not_committable): the decision stays in the session only. */
export function entriesFrom(toCommit, { client = null, at = new Date(), screen = () => false } = {}) {
  const audit = { decided_by: "person", relayed_by: "assistant", client,
    decided_at: `${at.toISOString().slice(0, 19)}Z` };
  const adds = { decisions: [], suppressions: [], grants_baseline: [] };
  let refused = 0;
  for (const e of toCommit ?? []) {
    const made = { account_tag: e.account_tag, made_on: e.made_on, ruleset_id: e.ruleset_id,
      registry_id: e.registry_id, fact_token: e.fact_token, seal: e.seal };
    if (e.kind === "grant") {
      if (HASHES.test(e.table) || screen(e.table)) { refused += 1; continue; }
      adds.grants_baseline.push({ table: e.table, grantee: e.grantee, privileges: e.privileges ?? null,
        expires_on: e.expires_on, made, audit });
      continue;
    }
    if (!committable(e.object_id, screen)) { refused += 1; continue; }
    if (e.kind === "decision") {
      adds.decisions.push({ subject: e.object_id, practice_id: e.practice_id, option: e.option,
        expires_on: e.expires_on, max_age_on: e.max_age_on ?? null, reasons: e.reasons, f4_class: e.f4_class,
        why_asked: e.why_asked, made, audit });
    } else {
      adds.suppressions.push({ subject: e.object_id, practice_id: e.practice_id, reason: e.reason,
        expires_on: e.expires_on, made, audit });
    }
  }
  return { adds, refused };
}

export const WRITE_NOTES = Object.freeze({
  written: "Custosa recorded the person's decisions in .custosa/state.json: commit it, so teammates and CI read them.",
  state_key_created: "Custosa created .custosa/state.json with a new content key. Commit .custosa/state.json before others record decisions.",
  no_person_in_ci: "no_person_in_ci: decisions are not taken here because {variable} is set; unset it if a person is at this machine.",
  state_full: "state_full: .custosa/state.json is at its limit, so these decisions were not recorded. They apply in this session only.",
  state_unreadable: "state_unreadable: .custosa/state.json could not be read, so it was not written over. These decisions apply in this session only.",
  state_subject_not_committable: "state_subject_not_committable: {n} decisions name something that is never committed (a per-install id, a line, a value-shaped name or a secret), so they apply in this session only.",
  state_entries_not_read: "state_entries_not_read: {n} more decisions to record could not be read from this result, so they were not recorded. They will be asked again next time.",
  state_root_unknown: "state_root_unknown: this result's decisions were not recorded, because the inspector restarted since the check that made them. They will be asked again.",
});

/* Writes the entries of one response's report.state into the root's file, and says what happened, as local notes. */
export function recordIssued(root, state, { env = process.env, ci = false, client = null, screen, at } = {}) {
  if (!state || typeof state !== "object") return [];
  const toCommit = Array.isArray(state.to_commit) ? state.to_commit : [];
  const needKey = Array.isArray(state.not_committed) && state.not_committed.some((n) => n?.reason === "no_content_key");
  if (!toCommit.length && !needKey) return [];
  const { adds, refused } = entriesFrom(toCommit, { client, at, screen });
  const notes = refused ? [WRITE_NOTES.state_subject_not_committable.replace("{n}", String(refused))] : [];
  const read = readState(root);
  if (read.status === "ok" && !LISTS.some((l) => adds[l].length)) return notes;   // has its key, nothing new
  const res = writeState(root, read, adds, { env, ci });
  if (!res.written) {
    const text = WRITE_NOTES[res.note] ?? WRITE_NOTES.state_unreadable;
    return [...notes, text.replace("{variable}", res.variable ?? "")];
  }
  return [...notes, res.note === "state_key_created" ? WRITE_NOTES.state_key_created : WRITE_NOTES.written];
}

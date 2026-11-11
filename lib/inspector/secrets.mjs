/* Secret detection in memory.
 *
 * scanSecrets(files, {envFiles, historyBlobs, patterns, configDir}) -> {secrets: Secret[], truncated: Truncated[]}
 *   files:        [{path, text}]           working-tree files the caller already read (string or Buffer). A .env file
 *                                          (isEnvFile, the walker's predicate: basename .env, .env.<x> or <x>.env, any letter
 *                                          case, so .env.example in any folder too) does not belong here: it goes
 *                                          through envFiles, and one passed here is reported as bad_input, unscanned.
 *   envFiles:     [{path, tracked, text}]  every .env file by name, tracked strictly true or false. Only tracked
 *                                          (committed) ones are scanned, and only from the text the caller passes;
 *                                          an untracked one's text is ignored and the caller should not read it.
 *   historyBlobs: [{path, text, commit}]   optional blobs read from git history; findings get in_history: true.
 *   Each list must be an array when given (envFiles and historyBlobs may be left out); anything else throws
 *   BadInputError, never an empty, clean result.
 *   patterns:     [{rule_id, regex, validate?, normalize?, placeholders?}]  defaults to DEFAULT_SECRET_PATTERNS
 *                 (secret-patterns.mjs explains the fields). Text may be a string or bytes: UTF-8, or UTF-16 with
 *                 a byte-order mark. Bytes without a byte-order mark are read as UTF-8; UTF-16 or UTF-32 read that
 *                 way leaves NULs between ASCII characters, and those runs are scanned with the NULs removed
 *                 (readableText), so ASCII secrets in them are found. Other non-UTF-8 encodings are the caller's
 *                 to decode.
 *   configDir:    where install.key lives; defaults to $CUSTOSA_CONFIG_DIR, then ~/.config/custosa.
 *
 * A Secret is exactly {rule_id, path, line, fingerprint, in_history}. No part of a secret leaves this module: no
 * snippet, prefix, suffix or length, and no error message or log line carries matched text (this module logs nothing).
 * The fingerprint is HMAC-SHA256 keyed with the per-install key (install.key) over the domain-separated message
 * "custosa-secret-fingerprint-v1\0" + secret (UTF-8), as the full 64 lowercase hex characters (the contract's hash).
 * The same secret is recognised across runs on one machine and is not comparable across installs. A location pattern
 * (config-password and the like) is fingerprinted on its rule, path and line instead (locationFingerprint), so
 * nothing about a human-chosen value goes in. For a PEM private
 * key, "secret" is the first 4096 characters of its base64 body (secret-patterns.mjs, PEM_FINGERPRINT_BODY), so the
 * fingerprint does not depend on where the key sits in a file.
 *
 * A Truncated is {path, in_history, reason}: input that was not scanned in full, which the caller must report as
 * such, never as clean. A file may have more than one. Reasons:
 *   "unreadable"           text was neither a string nor bytes, or is binary: more than 10% NUL characters with no
 *                          run of NUL-interleaved ASCII. (UTF-16 or UTF-32 without a byte-order mark is not
 *                          unreadable: its interleaved ASCII runs are scanned with the NULs removed, see readableText.)
 *   "match_cut_at_window"  a match (in practice a PEM key over about 12 KB, or one past the pattern's line bound) ran
 *                          into the end of a scan window, or a PEM key has no END line after it (cut or incomplete);
 *   "joined_view_budget"   the file has too many string literals for the joined view (JOINED_MAX_FRAGMENTS,
 *                          JOINED_MAX_CHARS): the plain scan ran, the joined view did not;
 *   "scan_error"           an unexpected error while scanning this file (no message is kept: it might hold text);
 *   "bad_input"            a malformed entry: null, a path that is not a string, envFiles tracked not a boolean, or
 *                          a .env file passed in files. The path is the entry's path, or files[i] / envFiles[i] /
 *                          historyBlobs[i] when it has none.
 *
 * Writes: only install.key (and its directory) under the config dir. No child processes, no network. */

import { createHmac, randomBytes } from "node:crypto";
import * as realFs from "node:fs";
import { homedir } from "node:os";
import { basename, join } from "node:path";
import { isEnvFile } from "./gitread.mjs";
import {
  DEFAULT_SECRET_PATTERNS, isClearPlaceholder, isShapePlaceholder, isWordPlaceholder,
} from "./secret-patterns.mjs";

export { DEFAULT_SECRET_PATTERNS };

export const KEY_FILE = "install.key";
const KEY_BYTES = 32;
const FINGERPRINT_CONTEXT = "custosa-secret-fingerprint-v1\0";
const LOCATION_CONTEXT = "custosa-secret-location-v1\0";

export class InstallKeyError extends Error {
  constructor(message) {
    super(message);
    this.name = "InstallKeyError";
  }
}

/* The caller passed a list that is not an array (null, an object, a string, a Set): nonsense input is an error,
 * never an empty, clean result. */
export class BadInputError extends Error {
  constructor(message) {
    super(message);
    this.name = "BadInputError";
  }
}

export class SecretPatternError extends Error {
  constructor(message) {
    super(message);
    this.name = "SecretPatternError";
  }
}

/* The one config folder rule (setup, doctor, the platform token and the inspector all use it): CUSTOSA_CONFIG_DIR when
   it is set and not empty, else ~/.config/custosa. */
export function defaultConfigDir({ env = process.env, home = homedir() } = {}) {
  return env.CUSTOSA_CONFIG_DIR || join(home, ".config", "custosa");
}

export function configDirFor({ configDir } = {}) {
  return configDir || defaultConfigDir();
}

const isWindows = process.platform === "win32";
const ownedByOther = (st) => typeof process.getuid === "function" && st.uid !== process.getuid();

/* Why the config folder can't hold our private files: "missing", a reason to show, or null when it is fine. Shared by
 * the sign-in and the environment mark. */
export function dirProblem(dir) {
  let st;
  try { st = realFs.statSync(dir); } catch (err) { return err.code === "ENOENT" ? "missing" : "the config folder can't be read"; }
  if (!st.isDirectory()) return "the config folder is not a folder";
  if (!isWindows && (st.mode & 0o022)) return "the config folder is writable by other users (run chmod 700 on it)";
  if (!isWindows && ownedByOther(st)) return "the config folder belongs to another user";
  return null;
}

/* One private file of ours, read through a single open: O_NOFOLLOW, then fstat on the descriptor, so a file swapped
 * after a check is never the one read. -> {text} | {missing: true} | {refused: "not_regular" |
 * "open_to_others" | "other_owner" | "too_large" | "unreadable"}. open_to_others: any group or other bit. */
export function readPrivateFile(path, maxBytes) {
  const { constants } = realFs;
  let fd;
  try { fd = realFs.openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0)); }
  catch (err) {
    if (err.code === "ENOENT") return { missing: true };
    return { refused: err.code === "ELOOP" || err.code === "EMLINK" ? "not_regular" : "unreadable" };
  }
  let text;
  try {
    const st = realFs.fstatSync(fd);
    if (!st.isFile()) return { refused: "not_regular" };
    if (!isWindows && (st.mode & 0o077)) return { refused: "open_to_others" };
    if (!isWindows && ownedByOther(st)) return { refused: "other_owner" };
    if (st.size > maxBytes) return { refused: "too_large" };
    const buf = Buffer.alloc(maxBytes + 1);
    const n = realFs.readSync(fd, buf, 0, buf.length, 0);
    if (n > maxBytes) return { refused: "too_large" };
    text = buf.subarray(0, n).toString("utf8");
  } catch { return { refused: "unreadable" }; }
  finally { realFs.closeSync(fd); }
  if (isWindows) {
    // No O_NOFOLLOW on Windows: a symlink is refused by name after the read.
    try { if (realFs.lstatSync(path).isSymbolicLink()) return { refused: "not_regular" }; } catch { /* raced away */ }
  }
  return { text };
}
const failure = (what, err) => new InstallKeyError(`${what}: ${(err && err.code) || "error"}.`);

const checkPrivate = (st, what) => {
  if (isWindows) return;
  if (st.mode & 0o077) {
    throw new InstallKeyError(
      `Refusing to use ${what}: it is group or world readable (mode ${(st.mode & 0o777).toString(8)}). ` +
      `Run chmod 600 on it, or delete it to create a new key.`);
  }
  if (ownedByOther(st)) throw new InstallKeyError(`Refusing to use ${what}: it is owned by another user.`);
};

/* The config dir must be a directory of ours that nobody else can write to (someone who can write it can swap the
 * key). A missing dir is fine: it is created 0700. */
function checkDir(fs, dir) {
  let st;
  try {
    st = fs.statSync(dir);
  } catch (err) {
    if (err.code === "ENOENT") return false;
    throw failure(`Cannot read the config dir ${dir}`, err);
  }
  if (!st.isDirectory()) throw new InstallKeyError(`Refusing to use ${dir}: it is not a directory.`);
  if (isWindows) return true;
  if (st.mode & 0o022) {
    throw new InstallKeyError(
      `Refusing to use ${dir}: it is group or world writable (mode ${(st.mode & 0o777).toString(8)}). ` +
      `Run chmod 700 on it.`);
  }
  if (ownedByOther(st)) throw new InstallKeyError(`Refusing to use ${dir}: it is owned by another user.`);
  return true;
}

function readKey(fs, path) {
  let st;
  try {
    st = fs.lstatSync(path);
  } catch (err) {
    if (err.code === "ENOENT") return null;
    throw failure(`Cannot read the install key ${path}`, err);
  }
  if (!st.isFile()) throw new InstallKeyError(`Refusing to use ${path}: it is not a regular file.`);
  checkPrivate(st, path);
  let fd;
  try {
    fd = fs.openSync(path, "r");
  } catch (err) {
    throw failure(`Cannot read the install key ${path}`, err);
  }
  try {
    checkPrivate(fs.fstatSync(fd), path);
    const buf = Buffer.alloc(KEY_BYTES + 1);
    let n;
    try {
      n = fs.readSync(fd, buf, 0, buf.length, 0);
    } catch (err) {
      throw failure(`Cannot read the install key ${path}`, err);
    }
    if (n !== KEY_BYTES) {
      throw new InstallKeyError(`Refusing to use ${path}: it is not a ${KEY_BYTES}-byte key. Delete it to create a new one.`);
    }
    return buf.subarray(0, KEY_BYTES);
  } finally {
    try { fs.closeSync(fd); } catch { /* nothing to do */ }
  }
}

/* Write the key bytes to a new file (O_EXCL, 0600). If writing fails partway the file is removed. */
function writeNew(fs, file, bytes) {
  const fd = fs.openSync(file, "wx", 0o600);
  try {
    let off = 0;
    while (off < bytes.length) off += fs.writeSync(fd, bytes, off, bytes.length - off);
    fs.closeSync(fd);
  } catch (err) {
    try { fs.closeSync(fd); } catch { /* already closed */ }
    try { fs.unlinkSync(file); } catch { /* already gone */ }
    throw err;
  }
}

const LINK_UNSUPPORTED = new Set(["EPERM", "ENOTSUP", "EOPNOTSUPP", "ENOSYS", "EXDEV"]);

/* The per-install key: read it, or create it (0600, 32 random bytes) on first run. The new key is written to a
 * temporary file and hard-linked into place, so a concurrent run never sees a half-written key. Where hard links are
 * not supported, it is written with O_EXCL straight to the final name. Every failure is an InstallKeyError, so the
 * caller reports secret collection as failed, never as "no secrets".
 * options.fsOverrides replaces individual fs functions (tests only). */
export function loadInstallKey(options = {}) {
  const fs = { ...realFs, ...(options.fsOverrides || {}) };
  const dir = configDirFor(options);
  const path = join(dir, KEY_FILE);
  if (checkDir(fs, dir)) {
    const existing = readKey(fs, path);
    if (existing) return existing;
  } else {
    try {
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    } catch (err) {
      throw failure(`Cannot create the config dir ${dir}`, err);
    }
    checkDir(fs, dir);
  }
  const bytes = randomBytes(KEY_BYTES);
  const tmp = join(dir, `.${KEY_FILE}.${process.pid}.${randomBytes(6).toString("hex")}`);
  try {
    writeNew(fs, tmp, bytes);
  } catch (err) {
    throw failure(`Cannot create the install key ${path}`, err);
  }
  try {
    fs.linkSync(tmp, path);
  } catch (err) {
    if (LINK_UNSUPPORTED.has(err.code)) {
      try {
        writeNew(fs, path, bytes);
      } catch (err2) {
        if (err2.code !== "EEXIST") throw failure(`Cannot create the install key ${path}`, err2);
      }
    } else if (err.code !== "EEXIST") {
      throw failure(`Cannot create the install key ${path}`, err);
    }
  } finally {
    try { fs.unlinkSync(tmp); } catch { /* already gone */ }
  }
  const key = readKey(fs, path);
  if (!key) throw new InstallKeyError(`Cannot create the install key ${path}.`);
  return key;
}

export function fingerprint(key, secret) {
  return createHmac("sha256", key).update(FINGERPRINT_CONTEXT).update(secret, "utf8").digest("hex");
}

/* A location pattern's fingerprint: HMAC-SHA256 with the same key over the domain-separated message
 * "custosa-secret-location-v1\0" + rule_id + "\0" + path + "\0" + line. Nothing about the value goes in. */
export function locationFingerprint(key, ruleId, path, line) {
  return createHmac("sha256", key).update(LOCATION_CONTEXT).update(`${ruleId}\0${path}\0${line}`, "utf8").digest("hex");
}

/* A pattern's optional fields: null or undefined means none. Checked in this order; the first bad one is named. */
const isFunction = (v) => typeof v === "function";
const OPTIONAL_FIELDS = [["validate", "a validate that is not a function", isFunction],
  ["normalize", "a normalize that is not a function", isFunction],
  ["fileContext", "a fileContext that is not a regex", (v) => v instanceof RegExp],
  ["ending", "an ending that is not a function", isFunction],
  ["pathContext", "a pathContext that is not a regex", (v) => v instanceof RegExp],
  ["location", "a location that is not a boolean", (v) => typeof v === "boolean"]];

function compile(patterns) {
  if (!Array.isArray(patterns)) throw new SecretPatternError("patterns must be an array of {rule_id, regex}.");
  return patterns.map((p, i) => {
    if (!p || typeof p.rule_id !== "string" || !p.rule_id) {
      throw new SecretPatternError(`Secret pattern ${i} has no rule_id.`);
    }
    let regex;
    try {
      // g to scan; y would anchor and d (match indices) makes V8 several times slower, so both are dropped.
      const flagsOf = (flags) => [...new Set((flags + "g").replace(/[yd]/g, ""))].join("");
      if (p.regex instanceof RegExp) regex = new RegExp(p.regex.source, flagsOf(p.regex.flags));
      else if (typeof p.regex === "string" && p.regex) regex = new RegExp(p.regex, "g");
      else throw new Error("missing");
    } catch {
      throw new SecretPatternError(`Secret pattern ${p.rule_id} has an invalid regex.`);
    }
    for (const [field, problem, ok] of OPTIONAL_FIELDS) {
      if (p[field] != null && !ok(p[field])) throw new SecretPatternError(`Secret pattern ${p.rule_id} has ${problem}.`);
    }
    const stateless = (re) => (re ? new RegExp(re.source, re.flags.replace(/[gy]/g, "")) : null);
    return { rule_id: p.rule_id, regex, validate: p.validate || null, normalize: p.normalize || null,
      placeholders: p.placeholders === true, fileContext: stateless(p.fileContext), fallback: p.fallback === true,
      ending: p.ending || null, pathContext: stateless(p.pathContext), location: p.location === true };
  });
}

const lineStarts = (text) => {
  const starts = [0];
  for (let i = text.indexOf("\n"); i !== -1; i = text.indexOf("\n", i + 1)) starts.push(i + 1);
  return starts;
};

const lineOf = (starts, index) => {
  let lo = 0, hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid] <= index) lo = mid; else hi = mid - 1;
  }
  return lo + 1;
};

/* A validate that throws counts as a finding: failing closed is safer than dropping a possible secret, and no value
 * is output either way. The error itself is discarded unseen, since it might carry the value. */
const accepts = (validate, secret, context) => {
  if (!validate) return true;
  try {
    return validate(secret, context) === true;
  } catch {
    return true;
  }
};

const canonical = (normalize, secret, context) => {
  if (!normalize) return secret;
  try {
    const out = normalize(secret, context);
    return typeof out === "string" && out ? out : secret;
  } catch {
    return secret;
  }
};

/* Text from a string or bytes. Bytes honour a UTF-8, UTF-16 LE or UTF-16 BE byte-order mark; otherwise UTF-8. */
export function decodeText(text) {
  if (typeof text === "string") return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
  if (!(Buffer.isBuffer(text) || text instanceof Uint8Array)) return null;
  const buf = Buffer.from(text.buffer, text.byteOffset, text.byteLength);
  if (buf.length >= 3 && buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf) return buf.subarray(3).toString("utf8");
  if (buf.length >= 2 && buf[0] === 0xff && buf[1] === 0xfe) return buf.subarray(2).toString("utf16le");
  if (buf.length >= 2 && buf[0] === 0xfe && buf[1] === 0xff) {
    const body = Buffer.from(buf.subarray(2, 2 + ((buf.length - 2) & ~1)));
    return body.swap16().toString("utf16le");
  }
  return buf.toString("utf8");
}

/* Structural caps, so no input can make a scan slow whatever the patterns do:
 * - text is scanned in windows of WINDOW characters that start every STEP characters. Each window owns the matches
 *   that START in its first STEP characters (the last window owns the rest) and sees WINDOW - STEP (12 KB) more, so
 *   every match up to 12 KB long is seen whole. The search in each window starts at the window's own start; the LEAD
 *   characters before it are visible only to lookbehinds, so a match starting there can never hide one starting in
 *   the window. Each match start belongs to exactly one window, so nothing is found twice.
 * - A match that runs into the end of its window (only a PEM key over about 12 KB can) may be cut: the file is then
 *   reported as truncated, never as scanned and clean.
 * - validate sees at most CONTEXT characters on each side of the secret, and the line text is cut to that too.
 * - The joined view is one text scanned with the same windows, so it needs no size cap of its own, and the literal
 *   scanner is a linear hand-written loop. */
const WINDOW = 24 * 1024;
const STEP = 12 * 1024;
const LEAD = 256;
const CONTEXT = 4096;
const ENDING_CONTEXT = 1024; // text an ending() check sees after a match (eight blank lines of 64 spaces fit)

const lineTextAt = (text, index) => {
  const lo = Math.max(0, index - CONTEXT / 2), hi = Math.min(text.length, index + CONTEXT / 2);
  const before = text.slice(lo, index), after = text.slice(index, hi);
  const nl = before.lastIndexOf("\n"), end = after.indexOf("\n");
  return before.slice(nl + 1) + (end === -1 ? after : after.slice(0, end));
};

// An ending function that throws counts as "incomplete" (fail closed: the file is reported truncated).
const safeEnding = (ending, after) => {
  try {
    const how = ending(after);
    return how === "complete" || how === "quote" ? how : "incomplete";
  } catch {
    return "incomplete";
  }
};

/* What validate sees, computed on first use (prototype getters: no per-match closures). memo(name, fn) runs
 * fn(whole file text) once per file and caches the result (for file-wide facts such as the hosts a file names). */
class MatchContext {
  constructor(text, index, length, groups, file) {
    this.text = text; this.index = index; this.length = length; this.groups = groups; this.file = file;
  }
  get line() { return lineTextAt(this.text, this.index); }
  get path() { return this.file.path; }
  get before() { return this.text.slice(Math.max(0, this.index - CONTEXT), this.index); }
  get after() { const end = this.index + this.length; return this.text.slice(end, end + CONTEXT); }
  memo(name, fn) {
    const { cache, text } = this.file;
    if (!cache.has(name)) cache.set(name, fn(text));
    return cache.get(name);
  }
}

/* Run every pattern over text in windows, calling emit(rule_id, value, line, fallback, start, end, how, location) for each
 * accepted match, where value is the secret's canonical form (normalize(secret, context), or the secret), line =
 * lineAt(secret index), [start, end) is the secret's span in text and how its ending ("complete", "quote",
 * "incomplete"). A secret
 * already accepted on that line by the same pattern is not validated or emitted again (it would give the same
 * finding), so a line repeating one secret thousands of times stays cheap. onCut() is called when a match runs into
 * the end of a window that is not the last. */
function runPatterns(text, compiled, emit, lineAt, file, onCut) {
  for (const { rule_id, regex, validate, normalize, placeholders, fallback, ending, location } of compiled) {
    const accepted = new Set();
    for (let s = 0; ; s += STEP) {
      const last = s + WINDOW >= text.length;
      const lead = Math.min(LEAD, s);
      const base = s - lead;
      const slice = text.slice(base, s + WINDOW);
      regex.lastIndex = lead; // search from the window start; the lead is only for lookbehinds
      let m;
      while ((m = regex.exec(slice)) !== null) {
        if (m[0].length === 0) { regex.lastIndex++; continue; }
        const start = base + m.index;
        if (!last && start >= s + STEP) break; // owned by the next window
        const end = start + m[0].length;
        // Cut: the match ends near the end of a window that is not the last (a regex may back off a few characters
        // to an earlier line end), or the pattern says the secret is incomplete. "quote" is resolved by the caller.
        const how = ending ? safeEnding(ending, text.slice(end, end + ENDING_CONTEXT)) : "complete";
        if ((!last && m.index + m[0].length >= slice.length - LEAD) || how === "incomplete") onCut();
        const hasGroup = m.groups && typeof m.groups.secret === "string";
        const secret = hasGroup ? m.groups.secret : m[0];
        if (!secret) continue;
        // The secret group ends the match in every default pattern (anything after it is a lookahead), so its
        // position is exact; for a pattern that does not follow that rule, the last occurrence in the match is used.
        const offset = !hasGroup ? 0 : m[0].endsWith(secret) ? m[0].length - secret.length : m[0].lastIndexOf(secret);
        const index = start + Math.max(0, offset);
        const line = lineAt(index);
        // A pattern with an ending check (PEM keys) is kept per match start: two identical keys on one line are two
        // matches to resolve (a partial and a whole one, or one key split twice).
        const done = ending ? `${line}\0${secret}\0${start}` : `${line}\0${secret}`;
        if (accepted.has(done)) continue;
        if (placeholders && (isClearPlaceholder(secret) || isShapePlaceholder(secret) ||
          isWordPlaceholder(secret))) continue;
        if (validate &&
          !accepts(validate, secret, new MatchContext(text, index, secret.length, { ...m.groups }, file))) {
          continue;
        }
        accepted.add(done);
        const value = normalize
          ? canonical(normalize, secret, new MatchContext(text, index, secret.length, { ...m.groups }, file)) : secret;
        emit(rule_id, value, line, fallback, index, index + secret.length, how, location);
      }
      if (last) break;
    }
  }
}

/* The joined view: string literals that continue one another (joined by +, adjacent as in Python's implicit
 * concatenation, or items of a JSON or Python array) are concatenated, with escaped \n and \\n turned into newlines,
 * so a PEM key or URL split across literals is seen whole. Array items are joined with a newline. Each group keeps
 * where its fragments start, so a finding maps back to the line of the fragment holding it. Only groups of two or
 * more fragments are kept (a single literal is already covered by the plain scan). */
/* One escape at raw[i] (a backslash): [output, width]. Newline escapes (\n, \r\n, the double-escaped \\n and \\r\\n,
 * \u000a, \x0a, \012) give a newline; \r gives nothing; any other \X gives X. unescapeLiteral and literalOffsetMap
 * share this, so the joined text and the offset map always agree. */
function escapeToken(raw, i) {
  if (raw.startsWith("\\\\r\\\\n", i)) return ["\n", 6];
  if (raw.startsWith("\\\\n", i)) return ["\n", 3];
  if (raw.startsWith("\\r\\n", i)) return ["\n", 4];
  if (raw.startsWith("\\n", i)) return ["\n", 2];
  const c1 = raw[i + 1];
  if ((c1 === "u" || c1 === "U") && raw.slice(i + 2, i + 6).toLowerCase() === "000a") return ["\n", 6];
  if ((c1 === "x" || c1 === "X") && raw.slice(i + 2, i + 4).toLowerCase() === "0a") return ["\n", 4];
  if (c1 === "0" && raw.slice(i + 1, i + 4) === "012") return ["\n", 4];
  if (c1 === "r") return ["", 2];
  if (c1 !== undefined) return [c1, 2];
  return ["\\", 1];
}

function unescapeLiteral(raw) {
  if (!raw.includes("\\")) return raw;
  const parts = [];
  let i = 0, last = 0;
  while ((i = raw.indexOf("\\", i)) !== -1) {
    parts.push(raw.slice(last, i));
    const [out, width] = escapeToken(raw, i);
    parts.push(out);
    i += width;
    last = i;
  }
  parts.push(raw.slice(last));
  return parts.join("");
}

/* For each raw offset r in a literal's content (0..raw.length), the offset in unescapeLiteral(raw) where the
 * character at r lands: a plain character maps one to one; every offset inside an escape maps to where that escape's
 * output starts. One linear pass. */
function literalOffsetMap(raw) {
  const map = new Int32Array(raw.length + 1);
  let r = 0, out = 0;
  while (r < raw.length) {
    if (raw.charCodeAt(r) !== 92) { map[r++] = out++; continue; }
    const [o, width] = escapeToken(raw, r);
    for (let k = 0; k < width && r + k < raw.length; k++) map[r + k] = out;
    r += width;
    out += o.length;
  }
  map[raw.length] = out;
  return map;
}

/* Quoted literals as [start, end) pairs, in one linear pass: a quote opens a literal that ends at the same unescaped
 * quote on the same line; an unclosed one (newline or end of text) is skipped up to where the search stopped, so no
 * character is examined more than twice. There is no length limit on a literal, so nothing is cut; past max literals
 * the scan stops and returns null (the joined view's budget). */
function literalSpans(text, max) {
  const spans = [];
  const n = text.length;
  let i = 0;
  while (i < n) {
    const q = text.charCodeAt(i);
    if (q !== 34 && q !== 39) { i++; continue; }
    let j = i + 1, closed = false;
    while (j < n) {
      const c = text.charCodeAt(j);
      if (c === 92) { j += 2; continue; }
      if (c === 10 || c === 13) break;
      if (c === q) { closed = true; break; }
      j++;
    }
    if (closed) {
      if (spans.length >= max) return null;
      spans.push([i, j + 1]);
      i = j + 1;
    } else {
      i = Math.max(j, i + 1);
    }
  }
  return spans;
}

/* The gap between two literals joins them when it is only whitespace with at most one + or , : returns "", "+" or
 * ",", or null when the gap is anything else. */
function joinerBetween(text, from, to) {
  let op = "";
  for (let i = from; i < to; i++) {
    const c = text.charCodeAt(i);
    if (c === 32 || c === 9 || c === 10 || c === 13) continue;
    if ((c === 43 || c === 44) && op === "") { op = c === 43 ? "+" : ","; continue; }
    return null;
  }
  return op;
}

/* All joined groups in one text, separated by BARRIER (a newline, NUL, newline: no pattern's value or separator
 * crosses a NUL), so the joined view is one windowed scan however many groups a file has and however long a group
 * is. frags maps offsets in that text back to source lines. */
const BARRIER = "\n\u0000\n";

/* Per-file budget for the joined view: past it, the joined view is skipped for that file (and the file reported as
 * truncated with reason joined_view_budget) while the plain scan still runs. */
export const JOINED_MAX_FRAGMENTS = 200000;
export const JOINED_MAX_CHARS = 8 * 1024 * 1024;

function joinedView(text, starts) {
  const spans = literalSpans(text, JOINED_MAX_FRAGMENTS);
  if (spans === null) return "over_budget";
  let chars = 0;
  for (const [from, to] of spans) chars += to - from;
  if (chars > JOINED_MAX_CHARS) return "over_budget";
  const out = [], frags = [];
  let length = 0, cur = null;
  // Pieces are collected and joined once (repeated += and endsWith on a growing string is quadratic).
  const flush = () => {
    if (cur && cur.frags.length > 1) {
      out.push(BARRIER);
      length += BARRIER.length;
      for (const f of cur.frags) frags.push({ start: length + f.start, line: f.line, from: f.from, to: f.to });
      for (const piece of cur.pieces) out.push(piece); // never push(...pieces): it overflows the stack on large groups
      length += cur.length;
    }
    cur = null;
  };
  for (const [from, to] of spans) {
    const value = unescapeLiteral(text.slice(from + 1, to - 1));
    const line = lineOf(starts, from);
    const joiner = cur && from - cur.end <= 256 ? joinerBetween(text, cur.end, from) : null;
    if (joiner !== null) {
      if (joiner === "," && !cur.endsWithNewline) { cur.pieces.push("\n"); cur.length += 1; }
    } else {
      flush();
      cur = { pieces: [], frags: [], length: 0 };
    }
    cur.frags.push({ start: cur.length, line, from: from + 1, to: to - 1 }); // from, to: the literal's content in text
    cur.pieces.push(value);
    cur.length += value.length;
    if (value.length) cur.endsWithNewline = value.endsWith("\n");
    cur.end = to;
  }
  flush();
  return frags.length ? { text: out.join(""), frags } : null;
}

/* The joined-view offset of a plain-text offset inside a joined literal: the literal's joined start plus where that
 * raw offset lands in its unescaped content (literalOffsetMap, built once per literal and cached). null when the
 * offset is in no joined literal. */
function toJoinedOffset(text, frags, offset, maps) {
  let lo = 0, hi = frags.length - 1, k = -1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (frags[mid].from <= offset) { k = mid; lo = mid + 1; } else hi = mid - 1;
  }
  if (k === -1 || offset > frags[k].to) return null;
  let map = maps.get(k);
  if (!map) { map = literalOffsetMap(text.slice(frags[k].from, frags[k].to)); maps.set(k, map); }
  return frags[k].start + map[offset - frags[k].from];
}

const fragLine = (frags, index) => {
  let lo = 0, hi = frags.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (frags[mid].start <= index) lo = mid; else hi = mid - 1;
  }
  return frags[lo].line;
};

/* Text that did not decode cleanly. UTF-16 or UTF-32 without a byte-order mark, read as UTF-8, leaves NUL characters
 * between ASCII characters: one per character for UTF-16, three for UTF-32, before or after it by byte order. Each such
 * run of NUL-interleaved ASCII (8 or more characters) loses its NULs, which recovers ASCII secrets and keeps line
 * breaks. Every other NUL becomes a space (one for one), so NUL-separated fields stay separate tokens. A text that has
 * no interleaved run and is more than 10% NUL (binary) cannot be scanned: null, reported as unreadable. */
const INTERLEAVED_RUN = /(?:[\x09\x0a\x0d\x20-\x7e]\x00{1,3}){8,}|(?:\x00{1,3}[\x09\x0a\x0d\x20-\x7e]){8,}/g;
function readableText(text) {
  if (!text.includes("\0")) return text;
  let interleaved = false;
  const stripped = text.replace(INTERLEAVED_RUN, (run) => { interleaved = true; return run.replace(/\x00/g, ""); });
  if (!interleaved) {
    let nul = 0;
    for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 0) nul++;
    if (nul / text.length > 0.1) return null;
  }
  return stripped.replace(/\x00/g, " ");
}

/* Plain scan first, then the joined view, which adds only what the plain scan did not already find in this file.
 * A fallback pattern's finding (the generic app secret) is dropped when a specific rule's hit on the same line has
 * the same fingerprint, or when their secrets overlap without the generic one strictly containing the specific one
 * (STRIPE_SECRET_KEY=sk_live_...: same value). When the generic value strictly contains the specific one (a longer
 * value around a provider token), both are reported: the specific rule id with the token's fingerprint, and the
 * generic rule with the whole value's. Returns the set of truncation reasons for this file (empty when it was
 * scanned in full). */
function scanText(text, path, inHistory, compiled, key, out) {
  const reasons = new Set();
  text = decodeText(text);
  if (text !== null) text = readableText(text);
  if (text === null) return reasons.add("unreadable");
  // A lone CR is a line break, as \n and \r\n are; replaced one for one, so offsets stay put.
  if (text.includes("\r")) text = text.replace(/\r(?!\n)/g, "\n");
  const onCut = () => reasons.add("match_cut_at_window");
  const starts = lineStarts(text);
  const hits = [];
  const file = { text, cache: new Map(), path: String(path) };
  // pathContext and fileContext are tested once per file, not once per window or joined group.
  const name = basename(String(path));
  compiled = compiled.filter((c) => (!c.pathContext || c.pathContext.test(name)) && (!c.fileContext || c.fileContext.test(text)));
  // One HMAC per distinct secret, and one hit per rule, line, fingerprint and view (a line repeating one secret
  // thousands of times costs little).
  const fps = new Map(), seenHits = new Set();
  const fpOf = (value) => {
    let fp = fps.get(value);
    if (fp === undefined) { fp = fingerprint(key, value); fps.set(value, fp); }
    return fp;
  };
  // A hit keeps its canonical value in memory (never output) only when it ended at a quote, for the check below.
  // Every complete joined match by rule and start, kept before deduplication (the same key joined twice on one line
  // has two starts).
  const completeJoined = new Map();
  const add = (rule_id, line, value, fallback, view, start, end, how, location) => {
    if (view === "joined" && how === "complete") completeJoined.set(`${rule_id}\0${start}`, value);
    const fp = location ? locationFingerprint(key, rule_id, String(path), line) : fpOf(value);
    const id = `${rule_id}\0${line}\0${fp}\0${view}\0${how === "quote" ? start : ""}`;
    if (seenHits.has(id)) return;
    seenHits.add(id);
    hits.push({ rule_id, line, fp, fallback, view, start, end, how, value: how === "quote" ? value : null });
  };
  runPatterns(text, compiled, (rule_id, value, line, fallback, start, end, how, location) =>
    add(rule_id, line, value, fallback, "plain", start, end, how, location),
  (index) => lineOf(starts, index), file, onCut);
  const joined = joinedView(text, starts);
  if (joined === "over_budget") {
    reasons.add("joined_view_budget");
  } else if (joined) {
    // Location patterns read config lines as they stand, so they don't run on the joined view.
    runPatterns(joined.text, compiled.filter((c) => !c.location), (rule_id, value, line, fallback, start, end, how) =>
      add(rule_id, line, value, fallback, "joined", start, end, how),
    (index) => fragLine(joined.frags, index), file, onCut);
  }
  /* A match that ends at a closing quote with no END line ("quote"): in the plain view it may be the first part of a
   * key split across string literals. It is dropped only when the SAME key was found whole by the joined view: its
   * start maps, through the fragment map, to the start of a complete joined match of the same rule, and its value
   * (for a PEM key, the normalised body) is a prefix of that match's value. Otherwise the key is incomplete (a string
   * that closes with no END line, a Python """ block) and the file is flagged. In the joined view a quote is just a
   * character, so "quote" there is incomplete. */
  const offsetMaps = new Map();
  const sameKeyJoined = (h) => {
    const at = joined && joined !== "over_budget" ? toJoinedOffset(text, joined.frags, h.start, offsetMaps) : null;
    const whole = at === null ? undefined : completeJoined.get(`${h.rule_id}\0${at}`);
    return whole !== undefined && whole.startsWith(h.value);
  };
  const resolved = [];
  for (const h of hits) {
    if (h.how === "quote") {
      if (h.view === "plain" && sameKeyJoined(h)) continue;
      onCut();
    }
    resolved.push(h);
  }
  hits.length = 0;
  for (const h of resolved) hits.push(h);
  const plain = new Set(hits.filter((h) => h.view === "plain").map((h) => `${h.rule_id}\0${h.fp}`));
  const specificByLine = new Map();
  for (const h of hits) {
    if (h.fallback) continue;
    if (!specificByLine.has(h.line)) specificByLine.set(h.line, []);
    specificByLine.get(h.line).push(h);
  }
  const strictlyContains = (g, s) => g.start <= s.start && g.end >= s.end && g.end - g.start > s.end - s.start;
  const coveredBySpecific = (h) => (specificByLine.get(h.line) || []).some((s) => s.fp === h.fp ||
    (s.view === h.view && s.start < h.end && h.start < s.end && !strictlyContains(h, s)));
  for (const h of hits) {
    if (h.view === "joined" && plain.has(`${h.rule_id}\0${h.fp}`)) continue;
    if (h.fallback && coveredBySpecific(h)) continue;
    out.push({ rule_id: h.rule_id, path: String(path), line: h.line, fingerprint: h.fp, in_history: inHistory });
  }
  return reasons;
}

/* The order secrets are sent in: path, line, rule, fingerprint, then in_history. Also used by factdoc.mjs. */
export const compareSecrets = (a, b) =>
  (a.path < b.path ? -1 : a.path > b.path ? 1 : 0) || a.line - b.line ||
  (a.rule_id < b.rule_id ? -1 : a.rule_id > b.rule_id ? 1 : 0) ||
  (a.fingerprint < b.fingerprint ? -1 : a.fingerprint > b.fingerprint ? 1 : 0) ||
  Number(a.in_history) - Number(b.in_history);

const compareTruncated = (a, b) =>
  (a.path < b.path ? -1 : a.path > b.path ? 1 : 0) || Number(a.in_history) - Number(b.in_history) ||
  (a.reason < b.reason ? -1 : a.reason > b.reason ? 1 : 0);

export function scanSecrets(files = [], options = {}) {
  const { envFiles, historyBlobs, patterns = DEFAULT_SECRET_PATTERNS } = options;
  const compiled = compile(patterns);
  // options.key: a key given directly (ids.mjs checks path segments, whose fingerprints it never uses).
  const key = options.key ?? loadInstallKey(options);
  const found = [], truncated = [];
  const report = (path, inHistory, reason) => truncated.push({ path: String(path), in_history: inHistory, reason });
  /* One file: any unexpected error drops only this file's findings and reports it as scan_error (the message is
   * never kept, since it could hold text), so the other files still return. */
  const scan = (text, path, inHistory) => {
    const mine = [];
    let reasons;
    try {
      reasons = scanText(text, path, inHistory, compiled, key, mine);
    } catch {
      report(path, inHistory, "scan_error");
      return;
    }
    for (const m of mine) found.push(m); // a loop: spreading a huge array into push() overflows the stack
    for (const reason of reasons) report(path, inHistory, reason);
  };
  /* Each entry is read inside its own try: a null entry, a non-string path, a getter or Proxy that throws, or (for
   * envFiles) a tracked that is not a boolean is bad_input for that entry alone. */
  const each = (list, label, inHistory, handle) => {
    if (list === undefined) return;
    let length;
    try {
      if (!Array.isArray(list)) throw new Error();
      length = list.length; // an array Proxy whose length throws is bad input too
      if (!Number.isSafeInteger(length) || length < 0) throw new Error();
    } catch {
      throw new BadInputError(`${label} must be an array.`);
    }
    for (let i = 0; i < length; i++) {
      let path = `${label}[${i}]`, fields;
      try {
        const entry = list[i];
        if (!entry || typeof entry !== "object") throw new Error();
        const p = entry.path;
        if (typeof p !== "string") throw new Error();
        path = p;
        fields = { text: entry.text, tracked: label === "envFiles" ? entry.tracked : undefined };
      } catch {
        report(path, inHistory, "bad_input");
        continue;
      }
      handle(path, fields);
    }
  };
  each(files, "files", false, (path, { text }) => {
    if (isEnvFile(basename(path))) report(path, false, "bad_input"); // a .env file by name, in any folder
    else scan(text, path, false);
  });
  each(envFiles, "envFiles", false, (path, { text, tracked }) => {
    if (typeof tracked !== "boolean") report(path, false, "bad_input");
    else if (tracked) scan(text, path, false);
  });
  each(historyBlobs, "historyBlobs", true, (path, { text }) => scan(text, path, true));
  const seen = new Set();
  const secrets = found.sort(compareSecrets).filter((s) => {
    const id = `${s.rule_id}\0${s.path}\0${s.line}\0${s.fingerprint}\0${s.in_history}`;
    if (seen.has(id)) return false;
    seen.add(id);
    return true;
  });
  const seenCut = new Set();
  return {
    secrets,
    truncated: truncated.sort(compareTruncated).filter((t) => {
      const id = `${t.path}\0${t.in_history}\0${t.reason}`;
      if (seenCut.has(id)) return false;
      seenCut.add(id);
      return true;
    }),
  };
}

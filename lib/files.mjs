/* Careful edits to other tools' settings files: keep everything that isn't ours, back the file up first, write
   through a temporary file (synced to disk) so a crash never leaves half a file, and refuse to touch anything we can't
   rewrite exactly: a file with comments or trailing commas (they would be lost), duplicate keys (one would be lost), a
   number that wouldn't be written back the same (it would change), a read-only file, or a symbolic link to nothing. Line endings
   and a byte-order mark stay as the file has them. */
import { accessSync, closeSync, constants, copyFileSync, existsSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, realpathSync, renameSync, statSync, unlinkSync, writeSync } from "node:fs";
import { dirname } from "node:path";

export class Unreadable extends Error {
  constructor(file, why) { super(`${file}: ${why}`); this.file = file; }
}

/** The text without // and /* comments (strings kept as they are). */
export function stripComments(text) {
  let out = "", i = 0, inString = false;
  while (i < text.length) {
    const c = text[i], n = text[i + 1];
    if (inString) {
      out += c;
      if (c === "\\") { out += n ?? ""; i += 2; continue; }
      if (c === '"') inString = false;
      i++;
    } else if (c === '"') { inString = true; out += c; i++; }
    else if (c === "/" && n === "/") { while (i < text.length && text[i] !== "\n") i++; }
    else if (c === "/" && n === "*") { i += 2; while (i < text.length && !(text[i] === "*" && text[i + 1] === "/")) i++; i += 2; }
    else { out += c; i++; }
  }
  return out;
}

/** The text without a comma that only whitespace separates from the next ] or }, outside strings. */
function stripTrailingCommas(text) {
  let out = "", inString = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inString) {
      out += c;
      if (c === "\\") { out += text[i + 1] ?? ""; i++; } else if (c === '"') inString = false;
      continue;
    }
    if (c === '"') inString = true;
    else if (c === ",") {
      let j = i + 1;
      while (/\s/.test(text[j] ?? "")) j++;
      if (text[j] === "]" || text[j] === "}") continue;
    }
    out += c;
  }
  return out;
}

/** JSON with comments and trailing commas, as VS Code and Gemini CLI allow. Only for reading. */
export function parseJsonc(text) {
  return JSON.parse(stripTrailingCommas(stripComments(text)));
}

/* A number literal as sign, significant digits and the exponent of its first digit: "30.0", "3e1" and "3E+1" agree. */
function canonical(text) {
  const m = /^(-?)(\d+)(?:\.(\d+))?(?:[eE]([+-]?\d+))?$/.exec(text);
  const all = m[2] + (m[3] ?? "");
  const digits = all.replace(/^0+/, "");
  if (!digits) return "0";
  const lead = all.length - digits.length; // leading zeros
  const exp = Number(m[4] ?? 0) + m[2].length - 1 - lead;
  return `${m[1]}${digits.replace(/0+$/, "")}e${exp}`;
}
/* Whether rewriting the file would change a number's value: it isn't finite as a double (1e400), it rounds (1e-400 to 0,
   12345678901234567890), or it is -0 (written back as 0). 30.0, 1E2 and 1e+21 keep their value and are allowed. */
export function numberChanges(text) {
  const n = Number(text);
  if (!Number.isFinite(n) || Object.is(n, -0)) return true;
  return canonical(text) !== canonical(String(n).replace(/^(-?)(\d+(?:\.\d+)?)e/, "$1$2e"));
}

/* What JSON.parse would silently lose: a key given twice in one object, or a number whose value would change when it is
   written back (numberChanges). The text is valid JSON already. */
export function lossyJson(text) {
  let i = 0;
  const ws = () => { while (/\s/.test(text[i] ?? "")) i++; };
  const str = () => { const start = i++; while (text[i] !== '"') i += text[i] === "\\" ? 2 : 1; i++; return JSON.parse(text.slice(start, i)); };
  const value = () => {
    ws();
    const c = text[i];
    if (c === "{") {
      i++; ws();
      const seen = new Set();
      if (text[i] === "}") { i++; return null; }
      for (;;) {
        ws(); const k = str();
        if (seen.has(k)) return `has the key "${k}" twice in one object`;
        seen.add(k);
        ws(); i++; // :
        const bad = value(); if (bad) return bad;
        ws(); if (text[i++] === "}") return null;
      }
    }
    if (c === "[") {
      i++; ws();
      if (text[i] === "]") { i++; return null; }
      for (;;) { const bad = value(); if (bad) return bad; ws(); if (text[i++] === "]") return null; }
    }
    if (c === '"') { str(); return null; }
    const m = /^-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|^(?:true|false|null)/.exec(text.slice(i));
    i += m[0].length;
    if (/^-?\d/.test(m[0]) && numberChanges(m[0])) return `has the number ${m[0]}, whose value would change if setup rewrote the file`;
    return null;
  };
  return value();
}

const BOM = "﻿";
export function readText(file) {
  return existsSync(file) ? readFileSync(file, "utf8") : null;
}

/** A settings object, or {} when the file is missing or empty. Comments are allowed (we only read). */
export function readSettings(file) {
  const text = readText(file);
  if (text === null || !text.trim()) return {};
  try {
    const value = parseJsonc(text.startsWith(BOM) ? text.slice(BOM.length) : text); // a leading BOM only, as editJson
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("not an object");
    return value;
  } catch { throw new Unreadable(file, "isn’t valid JSON"); }
}

function stamp(now) {
  return now.toISOString().replace(/[-:]/g, "").replace(/\..*$/, "").replace("T", "-");
}

/** Refuses a file setup must not write: a symbolic link to nothing, or a file (or link target) that is read-only. */
export function checkWritable(file) {
  let link;
  try { link = lstatSync(file); } catch { return; }
  if (link.isSymbolicLink() && !existsSync(file)) throw new Unreadable(file, "is a symbolic link to a file that doesn’t exist, so it was left as it is");
  try { accessSync(file, constants.W_OK); } catch { throw new Unreadable(file, "is read-only, so it was left as it is"); }
}

/** Write `text` to `file` safely. Returns the backup's path when an existing file was replaced. */
export function writeSafely(file, text, { now = new Date() } = {}) {
  checkWritable(file);
  const exists = existsSync(file);
  // write where a symlinked settings file really lives, so the link survives
  const target = exists ? realpathSync(file) : file;
  mkdirSync(dirname(target), { recursive: true });
  let backup = null;
  if (exists) {
    // never over an earlier backup, even one made in the same second
    const base = `${file}.custosa-backup-${stamp(now)}`;
    backup = base;
    for (let n = 1; existsSync(backup); n++) backup = `${base}-${n}`;
    copyFileSync(target, backup, constants.COPYFILE_EXCL);
  }
  const temp = `${target}.custosa-${process.pid}.tmp`;
  const fd = openSync(temp, "w", exists ? statSync(target).mode & 0o777 : 0o644);
  try {
    writeSync(fd, text);
    fsyncSync(fd);
  } finally { closeSync(fd); }
  try { renameSync(temp, target); } catch (error) { try { unlinkSync(temp); } catch { /* gone */ } throw error; }
  return backup;
}

/** Change one JSON settings file. `change` edits the parsed object and returns false when nothing needs to change. */
export function editJson(file, change, { dryRun = false, now } = {}) {
  checkWritable(file);
  const raw = readText(file);
  // a byte-order mark, as some Windows editors save, is kept as it was
  const bom = raw?.startsWith(BOM) ? BOM : "";
  const text = raw === null ? null : raw.slice(bom.length);
  let value = {};
  if (text !== null && text.trim()) {
    try { value = JSON.parse(text); }
    catch {
      // comments or trailing commas: readable, but rewriting would drop them
      try { parseJsonc(text); } catch { throw new Unreadable(file, "isn’t valid JSON"); }
      throw new Unreadable(file, stripComments(text) !== text ? "has comments, so it was left as it is" : "has a trailing comma, so it was left as it is");
    }
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Unreadable(file, "isn’t a JSON object");
    const lossy = lossyJson(text);
    if (lossy) throw new Unreadable(file, `${lossy}, so it was left as it is`);
  }
  if (change(value) === false) return { changed: false, backup: null };
  if (dryRun) return { changed: true, backup: null };
  const indent = text?.match(/^[ \t]+(?=")/m)?.[0] ?? "  ";
  const eol = text?.includes("\r\n") ? "\r\n" : "\n";
  const out = (JSON.stringify(value, null, indent) + "\n").replace(/\n/g, eol);
  return { changed: true, backup: writeSafely(file, bom + out, { now }) };
}

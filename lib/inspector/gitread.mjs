/* Safe git reading for the inspector: which paths are tracked (from the index only) and which are ignored.
 *
 * Nothing here runs git or any other program, and nothing interprets git config, so no hook, fsmonitor, filter
 * driver, pager, external diff or textconv can run. The index and the ignore files are parsed here, in plain JS, and
 * every file is read through readInside: inside the realpath'd root, no symlink at any step of the path (a symlinked
 * .gitignore, info/exclude, index or `.git` file is refused, never followed, so it can't make us read a .env file),
 * a regular file with one link (a hard link could be a .env under another name) opened with O_NOFOLLOW and checked
 * again on the open handle, under a size cap, and never a file whose name is an env file name.
 *
 * Why not isomorphic-git (which the first walker used): it parses index version 2 only and ignores the split-index
 * `link` extension (so a split index loses every tracked file in the shared index), its ignore matching is always
 * case-insensitive (so on a case-sensitive disk it ignores files git doesn't), and it reads through whatever fs it is
 * given, following symlinks. The `ignore` package (tried next) disagrees with git on syntax (trailing tabs, backslash
 * escapes, a trailing "**" + "/", parent rules applied to children), so git's own matching is ported below and
 * checked against real git by a differential test.
 *
 * The git directory is located here:
 *  - `.git` is a directory: used.
 *  - `.git` is a file (a gitlink, as in worktrees and submodules): followed only when the gitdir it names resolves
 *    inside the root AND is a pure git directory (only git's own names, see isPureGitdir); otherwise not followed:
 *    `gitlink_outside_root` (a worktree's `<main>/.git/worktrees/<name>`, a submodule's `../.git/modules/x`, anything
 *    else outside), or `gitlink_into_source` (it names a folder that also holds other files, such as `gitdir: src`;
 *    that folder is walked as source). Not followed means no tracked set and no info/exclude.
 *  - `.git` is a symlink: never followed, reported as `git_dir_symlink`.
 *  - no `.git`, but the root itself is a pure bare repository (HEAD, objects/, refs/ and only git's own names):
 *    layout `bare`, the root is the git directory, there is no working tree. Its config and hooks are never
 *    interpreted. A root with that layout plus other files is not bare (layout `none`) and is walked as source.
 *  - none of these, at a top-level root (no boundary): the nearest folder above the root with a `.git` folder or a
 *    trusted worktree gitlink is the enclosing repository (T29 (u)), layout `enclosing`, when its git directory is
 *    the user's own (same uid) on the root's disk. Its index is read inside the git directory only, and only the
 *    paths under the root are kept, relative to it; a repository tracking nothing under the root isn't the root's
 *    (a home folder kept in git, say), so git stays `no_git_dir`. Its info/exclude and the .gitignore files above
 *    the root are not read, which only walks more files, never fewer. The root's own .gitignore files now apply
 *    (files.mjs applyIgnore, as in any repository), so untracked ignored files there are skipped where before (u)
 *    they were walked; a tracked file never is.
 *  - otherwise: layout `none`, nothing tracked.
 * A gitlink outside the root is followed only when it is a worktree of a repository the user owns on the same disk
 * (`trustedWorktree`: `<common>/worktrees/<name>`, whose `gitdir` file names this very `.git` and whose `commondir`
 * names `<common>`); any other stays `gitlink_outside_root`.
 * Every path leaving here is NFC (Unicode normalisation form C), as the walker's are, so the two compare equal. */
import { constants, lstat, open, readdir, realpath, stat } from "node:fs/promises";
import { createHash } from "node:crypto";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

const MAX_INDEX_BYTES = 256 * 1024 * 1024; // the index of a very large repository; anything bigger is refused
const MAX_IGNORE_BYTES = 8 * 1024 * 1024;
const MAX_GITLINK_BYTES = 4096;
const MAX_NAME_BYTES = 4096;

const inside = (realRoot, p) => p === realRoot || p.startsWith(realRoot.endsWith(sep) ? realRoot : realRoot + sep);

/* An env file's name: `.env`, `.env.<anything>`, or `<anything>.env` (letter case ignored). `.envrc`,
 * `.environment.ts` and `.envoy.yaml` are not env files. Such a file is listed by name and never opened. */
export function isEnvFile(name) {
  const n = name.toLowerCase();
  return n === ".env" || n.startsWith(".env.") || n.endsWith(".env");
}

/* Read `abs` (absolute, inside realRoot) only when every step of its path below realRoot is a real directory or, for
 * the last step, a regular file with a single link: no symlink anywhere, no hard link (a hard-linked .gitignore could
 * be a .env file under another name), re-checked on the open handle (O_NOFOLLOW, same device and inode as the lstat,
 * still one link). Never a file with an env file name.
 * -> {buf} or {refused}: missing | symlink | not_regular | hard_link | too_large | env_name | outside | unreadable */
export async function readInsideEx(realRoot, abs, maxBytes) {
  if (typeof abs !== "string" || !isAbsolute(abs)) return { refused: "outside" };
  const lexical = resolve(abs);
  if (lexical === realRoot || !inside(realRoot, lexical)) return { refused: "outside" };
  const steps = relative(realRoot, lexical).split(sep);
  if (isEnvFile(steps[steps.length - 1])) return { refused: "env_name" };
  let cur = realRoot, st;
  try {
    for (let i = 0; i < steps.length; i++) {
      cur = join(cur, steps[i]);
      st = await lstat(cur);
      if (st.isSymbolicLink()) return { refused: "symlink" };
      if (i < steps.length - 1 ? !st.isDirectory() : !st.isFile()) return { refused: i < steps.length - 1 ? "missing" : "not_regular" };
    }
  } catch (err) { return { refused: err?.code === "ENOENT" || err?.code === "ENOTDIR" ? "missing" : "unreadable" }; }
  if (st.nlink > 1) return { refused: "hard_link" };
  if (st.size > maxBytes) return { refused: "too_large" };
  let fh;
  try {
    fh = await open(lexical, constants.O_RDONLY | constants.O_NOFOLLOW | (constants.O_NONBLOCK ?? 0));
    const fst = await fh.stat();
    if (!fst.isFile() || fst.ino !== st.ino || fst.dev !== st.dev) return { refused: "unreadable" };
    if (fst.nlink > 1) return { refused: "hard_link" };
    if (fst.size > maxBytes) return { refused: "too_large" };
    return { buf: await fh.readFile() };
  } catch { return { refused: "unreadable" }; } finally { await fh?.close().catch(() => {}); }
}

/* readInsideEx's bytes, or null when refused or missing. */
export async function readInside(realRoot, abs, maxBytes) {
  return (await readInsideEx(realRoot, abs, maxBytes)).buf ?? null;
}

/* A relative path as the walker returns it: forward-slash separated, no empty, "." or ".." segment (so no leading "/"
 * or "./"), no NUL. Odd names (spaces, Unicode, backslashes, colons, very long) are kept: the document builder
 * replaces any segment that doesn't fit the fact schema's path pattern with its keyed hash, so no file is dropped for
 * its name. */
export function isRelPath(p) {
  if (typeof p !== "string" || p.length === 0 || p.includes("\0")) return false;
  return p.split("/").every((seg) => seg !== "" && seg !== "." && seg !== "..");
}

/* Names git keeps at the top of a git directory. A folder whose top-level names are all of these (and has HEAD) is a
 * pure git directory: skipped by the walker, never interpreted. One with any other name is treated as source. */
export const GIT_NAMES = Object.freeze(new Set([
  "HEAD", "config", "config.worktree", "description", "index", "packed-refs", "shallow", "commondir", "gitdir",
  "COMMIT_EDITMSG", "TAG_EDITMSG", "NOTES_EDITMSG", "EDIT_DESCRIPTION", "MERGE_MSG", "MERGE_MODE", "MERGE_RR",
  "BISECT_LOG", "BISECT_START", "BISECT_TERMS", "BISECT_NAMES", "BISECT_EXPECTED_REV", "BISECT_ANCESTORS_OK",
  "gitk.cache", "objects", "refs", "logs", "hooks", "info", "modules", "worktrees", "lfs", "rr-cache",
  "rebase-merge", "rebase-apply", "sequencer", "branches", "remotes", "fsmonitor--daemon", "fsmonitor--daemon.ipc",
]));
export const isGitName = (name) => GIT_NAMES.has(name) || /^[A-Z][A-Z_]*_HEAD$/.test(name) || name.endsWith(".lock")
  || /^sharedindex\.[0-9a-f]{40,64}$/.test(name);
export function isPureGitdir(names) {
  return names.includes("HEAD") && names.every(isGitName);
}

const nfc = (p) => p.normalize("NFC");
const hasGitSegment = (p) => p.split("/").some((seg) => seg.toLowerCase() === ".git");

async function isBareLayout(dir, { pure = true } = {}) {
  try {
    const [head, objects, refs] = await Promise.all(["HEAD", "objects", "refs"].map((n) => lstat(join(dir, n))));
    return head.isFile() && objects.isDirectory() && refs.isDirectory() && (!pure || isPureGitdir(await readdir(dir)));
  } catch { return false; }
}

/* The gitdir a `.git` file names, read safely. -> the raw target string, or null (unreadable, not a gitlink). */
async function gitlinkTarget(realRoot, abs) {
  const buf = await readInside(realRoot, abs, MAX_GITLINK_BYTES);
  if (!buf) return null;
  const m = /^gitdir:\s*(.+)$/.exec(buf.toString("utf8").trim().split(/\r?\n/)[0] ?? "");
  return m ? m[1].trim() : null;
}

/* Whether a git directory is the user's own and on the root's disk (T29 (u)): same uid as this process, same device as
 * the root. Where there is no uid (Windows), only the device is compared. */
async function ownGitdir(realRoot, dir) {
  try {
    const [r, d] = await Promise.all([stat(realRoot), lstat(dir)]);
    const uid = typeof process.getuid === "function" ? process.getuid() : null;
    return d.isDirectory() && d.dev === r.dev && (uid === null || d.uid === uid);
  } catch { return false; }
}

/* T29 (u): whether `realTarget` (a real path outside the root) is a worktree git directory of a repository the user
 * owns, for the root's `.git` file: `<common>/worktrees/<name>`, its `gitdir` file naming `<realRoot>/.git`, its
 * `commondir` naming `<common>` (relative to it, as git writes it, or absolute), both read inside it. */
async function trustedWorktree(realRoot, realTarget) {
  const common = dirname(realTarget);
  if (basename(common) !== "worktrees") return false;
  const commonGit = dirname(common);
  if (!(await ownGitdir(realRoot, realTarget)) || !(await ownGitdir(realRoot, commonGit))) return false;
  const line = async (name) => {
    const buf = await readInside(realTarget, join(realTarget, name), MAX_GITLINK_BYTES);
    return buf ? buf.toString("utf8").split(/\r?\n/)[0].trim() : null;
  };
  const [back, named] = await Promise.all([line("gitdir"), line("commondir")]);
  if (!back || !named) return false;
  try {
    return (await realpath(resolve(realTarget, back))) === join(realRoot, ".git")
      && (await realpath(resolve(realTarget, named))) === commonGit;
  } catch { return false; }
}

/* T29 (u): the nearest folder above `realRoot` holding a `.git` folder, or a `.git` file that is a trusted worktree
 * gitlink, as {top, gitdir} (the work tree's folder and its real git directory); null when the first `.git` found is anything else, isn't the user's own, or there is
 * none up to the file system's root. */
async function enclosingRepository(realRoot) {
  for (let dir = dirname(realRoot); ; dir = dirname(dir)) {
    const dotgit = join(dir, ".git");
    let st = null;
    try { st = await lstat(dotgit); } catch { st = null; }
    if (st) {
      if (st.isDirectory()) return (await ownGitdir(realRoot, dotgit)) ? { top: dir, gitdir: await realpath(dotgit) } : null;
      if (!st.isFile() || st.size > MAX_GITLINK_BYTES) return null;
      const named = await gitlinkTarget(dir, dotgit);
      if (named === null) return null;
      let target;
      try { target = await realpath(resolve(dir, named)); } catch { return null; }
      return (await trustedWorktree(dir, target)) ? { top: dir, gitdir: target } : null;
    }
    if (dirname(dir) === dir) return null;
  }
}

/* Where the git directory is, decided without running anything and without leaving the root.
 * -> {layout: "dir"|"gitlink"|"bare"|"none", gitdir: absolute path or null, gitdirRel: rel path inside root or null,
 *     reason: null or an identifier saying why git data is unavailable} */
export async function locateGitdir(root, { boundary = null } = {}) {
  const realRoot = await realpath(root);
  // A nested root (a submodule or nested clone walked as its own root) may use a git directory anywhere inside the
  // outermost root, such as <top>/.git/modules/<name>; never outside it.
  const realBoundary = boundary ? await realpath(boundary) : realRoot;
  if (!inside(realBoundary, realRoot)) throw new Error("root outside its boundary");
  const found = (layout, gitdir, gitdirRel = null) => ({ realBoundary, realRoot, layout, gitdir, gitdirRel, reason: null });
  const unavailable = (layout, reason) => ({ realBoundary, realRoot, layout, gitdir: null, gitdirRel: null, reason });
  const dotgit = join(realRoot, ".git");
  let st;
  try { st = await lstat(dotgit); } catch { st = null; }
  if (!st) {
    if (await isBareLayout(realRoot)) return found("bare", realRoot);
    const enclosing = boundary ? null : await enclosingRepository(realRoot);
    if (enclosing) {
      const prefix = nfc(relative(enclosing.top, realRoot).split(sep).join("/"));
      return { ...found("enclosing", enclosing.gitdir), gitRoot: enclosing.gitdir, prefix };
    }
    return unavailable("none", "no_git_dir");
  }
  if (st.isSymbolicLink()) return unavailable("none", "git_dir_symlink");
  if (st.isDirectory()) return found("dir", dotgit);
  if (!st.isFile() || st.size > MAX_GITLINK_BYTES) return unavailable("none", "git_entry_unreadable");
  const named = await gitlinkTarget(realBoundary, dotgit);
  if (named === null) return unavailable("gitlink", "gitlink_unreadable");
  const target = resolve(realRoot, named);
  let realTarget = null;
  if (inside(realBoundary, target)) { try { realTarget = await realpath(target); } catch { realTarget = null; } }
  if (!inside(realBoundary, target) && !boundary) {
    // T29 (u): a worktree checkout, its git directory under the main repository, outside the root
    let outside = null;
    try { outside = await realpath(target); } catch { outside = null; }
    if (outside && !inside(realRoot, outside) && (await trustedWorktree(realRoot, outside))) {
      return { ...found("gitlink", outside), gitRoot: outside };
    }
  }
  if (!realTarget || !inside(realBoundary, realTarget) || realTarget === realRoot || inside(realTarget, realRoot)) {
    return unavailable("gitlink", realTarget === null && inside(realBoundary, target) ? "gitlink_missing" : "gitlink_outside_root");
  }
  if (!(await stat(realTarget)).isDirectory()) return unavailable("gitlink", "gitlink_missing");
  if (!isPureGitdir(await readdir(realTarget))) return unavailable("gitlink", "gitlink_into_source");
  const gitdirRel = inside(realRoot, realTarget) ? nfc(realTarget.slice(realRoot.length + 1).split(sep).join("/")) : null;
  return found("gitlink", realTarget, gitdirRel);
}

/* What a `.git` entry inside a folder below the root makes of that folder. `ancestors` are the real paths of the git
 * directories of this root and the roots above it: a `.git` file or symlink naming one of them ("gitlink_to_ancestor")
 * is not another repository but a second door into ours, so the folder stays part of the walk. Otherwise (a submodule, a nested clone, a nested
 * worktree), decided without following anything out of the root:
 *  - "embedded_git_dir": the folder is another repository's working tree (the `.git` is a git directory, a symlink,
 *    or a gitlink to a git directory or to somewhere we don't follow). Its tracked set is not ours, so the walker
 *    reports the folder and doesn't walk it (walking it with our ignore rules and tracked set could drop its files).
 *  - "gitlink_into_source": a gitlink naming a folder inside the root that holds other files (that folder is walked
 *    where it is); this folder is still another working tree, reported the same way.
 *  - null: not a repository marker (a `.git` folder holding other files is source, walked as such). */
export async function nestedGitReason(realRoot, dotgitAbs, ancestors = [], { caseInsensitive = false } = {}) {
  let st;
  try { st = await lstat(dotgitAbs); } catch { return null; }
  // Real paths on both sides (the caller realpaths each ancestor once), NFC, and case folded on a case-insensitive
  // disk, so `gitdir: ../.GIT` or a `.Git` spelling can't pass for another repository.
  const key = (p) => { const n = p.normalize("NFC"); return caseInsensitive ? n.toLowerCase() : n; };
  const known = new Set(ancestors.map(key));
  const isAncestor = async (p) => {
    try { return known.has(key(await realpath(p))); } catch { return false; }
  };
  if (st.isSymbolicLink()) return (await isAncestor(dotgitAbs)) ? "gitlink_to_ancestor" : "embedded_git_dir";
  if (st.isDirectory()) {
    let names;
    try { names = await readdir(dotgitAbs); } catch { return "embedded_git_dir"; }
    return isPureGitdir(names) || (await isBareLayout(dotgitAbs, { pure: false })) ? "embedded_git_dir" : null;
  }
  if (!st.isFile()) return null;
  const named = await gitlinkTarget(realRoot, dotgitAbs);
  if (named === null) return "embedded_git_dir"; // a `.git` file is a gitlink to git, whatever it says
  const target = resolve(join(dotgitAbs, ".."), named);
  if (await isAncestor(target)) return "gitlink_to_ancestor";
  if (!inside(realRoot, target)) return "embedded_git_dir";
  try {
    const realTarget = await realpath(target);
    if (inside(realRoot, realTarget) && (await stat(realTarget)).isDirectory() && !isPureGitdir(await readdir(realTarget))) {
      return "gitlink_into_source";
    }
  } catch { /* missing: a submodule whose gitdir isn't there */ }
  return "embedded_git_dir";
}

/* ---- The index ---------------------------------------------------------------------------------------------------
 * Versions 2, 3 and 4 (v4 prefix-compressed names), SHA-1 or SHA-256 object ids, a zero trailer (index.skipHash), and
 * the split index (`link`: entries from `sharedindex.<id>` minus the delete bitmap, plus this file's additions).
 * A sparse index (`sdir`, directory entries) and any unknown required extension are refused: the tracked set is then
 * unknown, never guessed. */

class IndexError extends Error {}

function decodeVarint(buf, pos) {
  let c = buf[pos++];
  if (c === undefined) throw new IndexError("varint");
  let val = c & 127;
  while (c & 128) {
    c = buf[pos++];
    if (c === undefined || val > 2 ** 40) throw new IndexError("varint");
    val = (val + 1) * 128 + (c & 127);
  }
  return [val, pos];
}

/* EWAH bitmap (git's ewah/ewah_io.c layout) -> sorted bit positions, and the byte length read. Every set bit names a
 * shared-index entry, so the bitmap can't be longer than `limit` (the shared entry count); a longer one, or a run
 * reaching past it, is refused before any loop runs over it. */
function decodeEwah(buf, pos, limit) {
  if (pos + 8 > buf.length) throw new IndexError("ewah");
  const bitSize = buf.readUInt32BE(pos), wordCount = buf.readUInt32BE(pos + 4);
  if (bitSize > limit) throw new IndexError("ewah larger than the shared index");
  const end = pos + 8 + wordCount * 8 + 4;
  if (end > buf.length || wordCount > Math.ceil(bitSize / 64) * 2 + 2) throw new IndexError("ewah");
  const span = Math.ceil(bitSize / 64) * 64;
  const bits = [];
  let at = 0;
  for (let i = 0; i < wordCount;) {
    const rlw = buf.readBigUInt64BE(pos + 8 + i * 8);
    const running = Number(rlw & 1n), runLen = Number((rlw >> 1n) & 0xffffffffn), literals = Number(rlw >> 33n);
    if (i + literals >= wordCount) throw new IndexError("ewah");
    if (at + (runLen + literals) * 64 > span) throw new IndexError("ewah run past its size");
    if (running) for (let b = 0; b < runLen * 64; b++) bits.push(at + b);
    at += runLen * 64;
    for (let k = 1; k <= literals; k++) {
      const w = buf.readBigUInt64BE(pos + 8 + (i + k) * 8);
      for (let b = 0; b < 64; b++) if ((w >> BigInt(b)) & 1n) bits.push(at + b);
      at += 64;
    }
    i += 1 + literals;
  }
  return { bits: bits.filter((b) => b < bitSize), end };
}

/* The split index's delete and replace bitmaps, bounded by the shared index's entry count. */
function bitmaps(link, sharedCount) {
  if (!link.bitmaps) return { deleted: [], replaced: [] };
  const del = decodeEwah(link.bitmaps, 0, sharedCount);
  const rep = decodeEwah(link.bitmaps, del.end, sharedCount);
  if (rep.end !== link.bitmaps.length) throw new IndexError("link");
  return { deleted: del.bits, replaced: rep.bits };
}

function parseIndexWith(buf, hashLen) {
  if (buf.length < 12 + hashLen || buf.toString("latin1", 0, 4) !== "DIRC") throw new IndexError("magic");
  const version = buf.readUInt32BE(4), count = buf.readUInt32BE(8);
  if (version < 2 || version > 4) throw new IndexError(`version ${version}`);
  const bodyEnd = buf.length - hashLen;
  const fixed = 40 + hashLen + 2;
  const entries = [];
  // A v4 name is the previous one, cut, plus a suffix: crafted, each could add a byte to an ever longer name. Names
  // are capped (no file system takes a path over 4096 bytes) and so is the total decoded, at 4x the index size.
  const maxDecoded = 4 * buf.length + 65536;
  let decoded = 0;
  let pos = 12, prev = Buffer.alloc(0);
  for (let i = 0; i < count; i++) {
    if (pos + fixed > bodyEnd) throw new IndexError("entry");
    const mode = buf.readUInt32BE(pos + 24);
    const flags = buf.readUInt16BE(pos + 40 + hashLen);
    let nameAt = pos + fixed;
    if (flags & 0x4000) { if (version < 3) throw new IndexError("extended flag"); nameAt += 2; }
    let name;
    if (version === 4) {
      const [strip, after] = decodeVarint(buf, nameAt);
      if (strip > prev.length) throw new IndexError("prefix");
      const nul = buf.indexOf(0, after);
      if (nul < 0 || nul >= bodyEnd) throw new IndexError("name");
      if (prev.length - strip + (nul - after) > MAX_NAME_BYTES) throw new IndexError("name too long");
      name = Buffer.concat([prev.subarray(0, prev.length - strip), buf.subarray(after, nul)]);
      pos = nul + 1;
    } else {
      const nul = buf.indexOf(0, nameAt);
      if (nul < 0 || nul >= bodyEnd) throw new IndexError("name");
      name = buf.subarray(nameAt, nul);
      if (name.length > MAX_NAME_BYTES) throw new IndexError("name too long");
      pos = pos + ((nameAt - pos + name.length + 8) & ~7);
    }
    decoded += name.length;
    if (decoded > maxDecoded) throw new IndexError("names too large");
    prev = name;
    entries.push({ name: name.toString("utf8"), mode });
  }
  let link = null, sparse = false;
  while (pos < bodyEnd) {
    if (pos + 8 > bodyEnd) throw new IndexError("extension");
    const sig = buf.toString("latin1", pos, pos + 4), size = buf.readUInt32BE(pos + 4);
    const data = pos + 8, end = data + size;
    if (end > bodyEnd) throw new IndexError("extension");
    if (sig === "link") {
      if (size < hashLen) throw new IndexError("link");
      const oid = buf.toString("hex", data, data + hashLen);
      // The bitmaps are decoded once the shared index's entry count is known (see bitmaps below).
      link = { oid, bitmaps: size > hashLen ? buf.subarray(data + hashLen, end) : null };
    } else if (sig === "sdir") sparse = true;
    else if (sig[0] < "A" || sig[0] > "Z") throw new IndexError(`required extension ${JSON.stringify(sig)}`);
    pos = end;
  }
  if (pos !== bodyEnd) throw new IndexError("trailing bytes");
  return { version, entries, link, sparse, hashLen };
}

/* Parse an index buffer. The trailer must be the SHA-1 (or SHA-256) of the rest, or all zeros (index.skipHash). */
export function parseIndex(buf) {
  for (const [hashLen, algo] of [[20, "sha1"], [32, "sha256"]]) {
    if (buf.length < 12 + hashLen) continue;
    const trailer = buf.subarray(buf.length - hashLen);
    const zero = trailer.every((b) => b === 0);
    if (!zero && !createHash(algo).update(buf.subarray(0, buf.length - hashLen)).digest().equals(trailer)) continue;
    try { return parseIndexWith(buf, hashLen); } catch (err) { if (!zero || hashLen === 32) throw err; }
  }
  throw new IndexError("checksum");
}

const MODE_TYPE = (mode) => (mode >>> 12) & 0o17;
const GITLINK = 0o16, DIRECTORY = 0o4;

/* The tracked paths with how they were read.
 * -> {paths: Set<string>, gitlinks: Set<string>, status: "ok"|"empty"|"failed"|"not_run", reason, known, layout,
 *     gitdir, gitdirRel, realRoot}
 * paths are the tracked files and symlinks; gitlinks are the submodule paths (mode 160000), which the walker reports
 * as embedded_git_dir folders. status `not_run` means there is no git directory we may read (none, outside the root,
 * a symlink); `empty` means a readable git directory with no index or an empty one; `failed` means the index exists
 * but couldn't be read (a symlink, a bad checksum, a missing shared index, a sparse index, a crafted entry). `known`
 * is true only for ok and empty: then the set is the real tracked set. */
export async function readTracked(root, loc = null) {
  loc ??= await locateGitdir(root);
  const base = { layout: loc.layout, gitdir: loc.gitdir, gitdirRel: loc.gitdirRel, realRoot: loc.realRoot };
  const none = (status, reason, known) => ({ ...base, paths: new Set(), gitlinks: new Set(), status, reason, known });
  if (!loc.gitdir) return none("not_run", loc.reason, false);
  const indexPath = join(loc.gitdir, "index");
  let st;
  try { st = await lstat(indexPath); } catch { return none("empty", "no_index", true); }
  if (st.isSymbolicLink()) return none("failed", "index_symlink", false);
  if (!st.isFile() || st.size > MAX_INDEX_BYTES) return none("failed", "index_unreadable", false);
  if (st.size === 0) return none("empty", "no_index", true);
  const readRoot = loc.gitRoot ?? loc.realBoundary ?? loc.realRoot; // T29 (u): a git directory outside the root
  const read = await readInsideEx(readRoot, indexPath, MAX_INDEX_BYTES);
  if (!read.buf) return none("failed", read.refused === "hard_link" ? "index_hard_link" : "index_unreadable", false);
  const buf = read.buf;
  let entries;
  try {
    const index = parseIndex(buf);
    if (index.sparse) return none("failed", "sparse_index", false);
    entries = index.entries;
    if (index.link && !/^0+$/.test(index.link.oid)) {
      const sharedRead = await readInsideEx(readRoot, join(loc.gitdir, `sharedindex.${index.link.oid}`), MAX_INDEX_BYTES);
      if (!sharedRead.buf) return none("failed", sharedRead.refused === "hard_link" ? "shared_index_hard_link" : "shared_index_missing", false);
      const sharedBuf = sharedRead.buf;
      const shared = parseIndex(sharedBuf);
      if (shared.link || shared.sparse || shared.hashLen !== index.hashLen) return none("failed", "index_unreadable", false);
      const bm = bitmaps(index.link, shared.entries.length);
      const deleted = new Set(bm.deleted);
      const replacements = bm.replaced.length;
      if (replacements > entries.length
        || entries.slice(0, replacements).some((e) => e.name !== "") || entries.slice(replacements).some((e) => e.name === "")) {
        return none("failed", "index_unreadable", false);
      }
      entries = [
        ...shared.entries.filter((_, i) => !deleted.has(i)),
        ...entries.slice(replacements),
      ];
    }
  } catch {
    return none("failed", "index_unreadable", false);
  }
  const paths = new Set(), gitlinks = new Set();
  // T29 (u): an enclosing repository's entries under the root only, relative to it
  const under = loc.layout === "enclosing" ? `${loc.prefix}/` : "";
  for (const e of entries) {
    const full = nfc(e.name);
    if (under && !full.startsWith(under)) continue;
    const p = full.slice(under.length);
    // A crafted index can list anything. An entry climbing out ("..") makes the whole set unreadable, as it did with
    // isomorphic-git; one that isn't otherwise a clean relative path (absolute, "." or empty segments), or sits
    // inside a .git folder, is dropped (the walker never meets such a path, so nothing it covers changes).
    if (p.split("/").includes("..")) return none("failed", "index_unreadable", false);
    if (!isRelPath(p) || hasGitSegment(p)) continue;
    const type = MODE_TYPE(e.mode);
    if (type === DIRECTORY) return none("failed", "sparse_index", false);
    (type === GITLINK ? gitlinks : paths).add(p);
  }
  // A repository tracking nothing under the root is not the root's (a home folder kept in git, say): no git data.
  if (under && !paths.size && !gitlinks.size) return none("not_run", "no_git_dir", false);
  return { ...base, paths, gitlinks, status: paths.size || gitlinks.size ? "ok" : "empty", reason: null, known: true };
}

/* ---- Ignore rules ------------------------------------------------------------------------------------------------ */

const swapCase = (s) => [...s].map((c) => (c === c.toLowerCase() ? c.toUpperCase() : c.toLowerCase())).join("");

/* Whether names under realRoot compare case-insensitively (macOS and Windows defaults). Probed on an entry of the
 * root, then on the root's own path; the platform default only when no name has a letter. */
export async function isCaseInsensitive(realRoot) {
  const probe = async (dir, name) => {
    const other = swapCase(name);
    if (other === name) return undefined;
    try {
      const [a, b] = await Promise.all([lstat(join(dir, name)), lstat(join(dir, other))]);
      return a.ino === b.ino && a.dev === b.dev;
    } catch { return false; }
  };
  try {
    for (const name of await readdir(realRoot)) { const r = await probe(realRoot, name); if (r !== undefined) return r; }
  } catch { /* fall through */ }
  const parts = realRoot.split(sep);
  for (let i = parts.length - 1; i > 0; i--) {
    const r = await probe(parts.slice(0, i).join(sep) || sep, parts[i]);
    if (r !== undefined) return r;
  }
  return process.platform === "darwin" || process.platform === "win32";
}

/* ---- Ignore rules: git's own semantics, ported ---------------------------------------------------------------------
 * A port of git's dir.c (add_patterns_from_buffer, trim_trailing_spaces, parse_path_pattern, match_basename,
 * match_pathname, last_matching_pattern) and wildmatch.c (dowild), over UTF-8 bytes, so the files we skip as ignored
 * are exactly the ones `git ls-files -o --exclude-standard` doesn't show (checked by a differential test against real
 * git). Not read: git config (core.excludesFile, core.ignorecase) and the global excludes; leaving rules out can only
 * show more files, never fewer, except a negation in a file we refuse, which makes the result unverified (below).
 *
 * The answer for a path is "ignored", false, or "unverified" (the walker then reports the path as ignored_unverified
 * instead of skipping it):
 *  - git folds case only when core.ignorecase is true, which we never read. On a case-insensitive disk git sets
 *    it by default, but a repository can turn it off, so a path is "ignored" only when the rules match both with and
 *    without case folding; a match one way only is "unverified". On a case-sensitive disk it is off by default, but
 *    any config (the repository's, the user's, the system's) can turn it on, so the answer is the exact one, except
 *    that a path the exact rules ignore but the folded rules don't (a negation such as "!*.txt" that only folding
 *    makes re-include "Foo.TXT", or a class such as "[!a]" that folding stops matching "A") is "unverified": git
 *    may show it. The other way round (folding would ignore it) the path is shown, which git does too by default.
 *    A caller that knows core.ignorecase passes ignoreCase (true or false) and gets git's answer for it exactly.
 *  - an ignore file that applies to the path but that we couldn't read the way git would (hard-linked, too large,
 *    unreadable, a line over 4096 bytes) turns an "ignored" into "unverified": a negation in it might have shown the
 *    path. A symlinked .gitignore is not such a case: git doesn't read those either. */

const WM_MATCH = 0, WM_NOMATCH = 1, WM_ABORT_ALL = -1, WM_ABORT_TO_STARSTAR = -2;
const isUpperC = (c) => c >= 65 && c <= 90;
const isLowerC = (c) => c >= 97 && c <= 122;
const isDigitC = (c) => c >= 48 && c <= 57;
const isAlphaC = (c) => isUpperC(c) || isLowerC(c);
const isSpaceC = (c) => c === 32 || c === 9 || c === 10 || c === 13; // git's sane ctype isspace
const isPrintC = (c) => c >= 32 && c <= 126;
const isPunctC = (c) => isPrintC(c) && c !== 32 && !isAlphaC(c) && !isDigitC(c);
const toLowerC = (c) => (isUpperC(c) ? c + 32 : c);
const toUpperC = (c) => (isLowerC(c) ? c - 32 : c);
const isGlobSpecial = (c) => c === 42 || c === 63 || c === 91 || c === 92; // * ? [ \
const CLASSES = {
  alnum: (c) => isAlphaC(c) || isDigitC(c), alpha: isAlphaC, blank: (c) => c === 32 || c === 9,
  cntrl: (c) => c < 32 || c === 127, digit: isDigitC, graph: (c) => isPrintC(c) && c !== 32, lower: isLowerC,
  print: isPrintC, punct: isPunctC, space: isSpaceC, xdigit: (c) => isDigitC(c) || (c >= 65 && c <= 70) || (c >= 97 && c <= 102),
};

/* A backstop on matching work and time: matching spends the budget in ctx.work (set just before each synchronous
 * match). Past it, or past its deadline, matching stops and the answer is "unverified" (ignoreStateAt), never a guess.
 * The estimate is at ignoreBudget; the deadline bounds the time whatever the rate. */
export const IGNORE_WORK_MAX = 1_000_000_000; // see the estimate at ignoreBudget
export const IGNORE_DEADLINE_MS = 60_000;
const WORK_EXCEEDED = Object.freeze({ workExceeded: true });
let WORK = { left: Infinity, deadline: Infinity, tick: 0 };

/* Spend n units of the budget (the caller's ctx.work, which walkAll shares across every root). Every 4096 units the
 * wall clock is checked against the deadline too. */
function spend(n) {
  WORK.left -= n;
  if (WORK.left < 0) throw WORK_EXCEEDED;
  WORK.tick += n;
  if (WORK.tick >= 4096) { WORK.tick = 0; if (Date.now() > WORK.deadline) throw WORK_EXCEEDED; }
}

/* A budget for ignore matching: `left` units of work (each dowild step, each byte a class or slash search scans, each
 * byte a literal comparison reads) and an absolute wall-clock deadline. Measured on this machine (re-review probes):
 * 70M to 90M units a second, so the default 1e9 is roughly 11 to 15 s of matching; a 20k-file tree with 61 patterns
 * spent about 33M. The rate varies by machine and pattern, so the deadline (60 s) is what bounds the time. */
export function ignoreBudget({ workMax = IGNORE_WORK_MAX, deadlineMs = IGNORE_DEADLINE_MS } = {}) {
  return { left: workMax, max: workMax, deadline: Date.now() + deadlineMs, tick: 0 };
}

/* git's dowild, line for line. P and T are byte arrays (P a whole pattern or a suffix of one; its start is index 0). */
function dowild(P, pi, T, ti, fold, pathname) {
  const at = (A, i) => (i < A.length ? A[i] : 0);
  for (; pi < P.length; ti++, pi++) {
    spend(1);
    let pCh = P[pi], tCh = at(T, ti);
    if (tCh === 0 && pCh !== 42) return WM_ABORT_ALL;
    if (fold && isUpperC(tCh)) tCh = toLowerC(tCh);
    if (fold && isUpperC(pCh)) pCh = toLowerC(pCh);
    switch (pCh) {
      case 92: // backslash: the next pattern byte, literally (not folded, as in git)
        pCh = at(P, ++pi);
        if (tCh !== pCh) return WM_NOMATCH;
        continue;
      default:
        if (tCh !== pCh) return WM_NOMATCH;
        continue;
      case 63: // ?
        if (pathname && tCh === 47) return WM_NOMATCH;
        continue;
      case 42: { // *
        let matchSlash;
        if (at(P, ++pi) === 42) {
          const prev = pi - 2;
          while (at(P, ++pi) === 42) { /* skip */ }
          if ((prev < 0 || P[prev] === 47) && (pi >= P.length || P[pi] === 47 || (P[pi] === 92 && at(P, pi + 1) === 47))) {
            if (P[pi] === 47 && dowild(P, pi + 1, T, ti, fold, pathname) === WM_MATCH) return WM_MATCH;
            matchSlash = true;
          } else matchSlash = false;
        } else matchSlash = !pathname;
        if (pi >= P.length) {
          if (!matchSlash) { spend(T.length - ti); if (T.indexOf(47, ti) >= 0) return WM_ABORT_TO_STARSTAR; }
          return WM_MATCH;
        } else if (!matchSlash && P[pi] === 47) {
          spend(T.length - ti);
          const slash = T.indexOf(47, ti);
          if (slash < 0) return WM_ABORT_ALL;
          ti = slash;
          break; // the slash is consumed by the loop
        }
        for (;;) {
          if (tCh === 0) break;
          if (!isGlobSpecial(P[pi])) {
            let lit = P[pi];
            if (fold && isUpperC(lit)) lit = toLowerC(lit);
            while ((tCh = at(T, ti)) !== 0 && (matchSlash || tCh !== 47)) {
              spend(1);
              if (fold && isUpperC(tCh)) tCh = toLowerC(tCh);
              if (tCh === lit) break;
              ti++;
            }
            if (tCh !== lit) return matchSlash ? WM_ABORT_ALL : WM_ABORT_TO_STARSTAR; // as git: no exponential retries
          }
          const matched = dowild(P, pi, T, ti, fold, pathname);
          if (matched !== WM_NOMATCH) {
            if (!matchSlash || matched !== WM_ABORT_TO_STARSTAR) return matched;
          } else if (!matchSlash && tCh === 47) return WM_ABORT_TO_STARSTAR;
          tCh = at(T, ++ti);
        }
        return WM_ABORT_ALL;
      }
      case 91: { // [
        pCh = at(P, ++pi);
        if (pCh === 94) pCh = 33; // ^ means !
        const negated = pCh === 33 ? 1 : 0;
        if (negated) pCh = at(P, ++pi);
        let prevCh = 0, matched = 0;
        do {
          spend(1);
          if (!pCh) return WM_ABORT_ALL;
          if (pCh === 92) {
            pCh = at(P, ++pi);
            if (!pCh) return WM_ABORT_ALL;
            if (tCh === pCh) matched = 1;
          } else if (pCh === 45 && prevCh && at(P, pi + 1) && P[pi + 1] !== 93) {
            pCh = P[++pi];
            if (pCh === 92) { pCh = at(P, ++pi); if (!pCh) return WM_ABORT_ALL; }
            if (tCh <= pCh && tCh >= prevCh) matched = 1;
            else if (fold && isLowerC(tCh)) { const up = toUpperC(tCh); if (up <= pCh && up >= prevCh) matched = 1; }
            pCh = 0;
          } else if (pCh === 91 && at(P, pi + 1) === 58) {
            const start = (pi += 2);
            while ((pCh = at(P, pi)) && pCh !== 93) { spend(1); pi++; }
            if (!pCh) return WM_ABORT_ALL;
            const len = pi - start - 1;
            if (len < 0 || P[pi - 1] !== 58) { // no ":]": a plain "["
              pi = start - 2; pCh = 91;
              if (tCh === pCh) matched = 1;
              continue;
            }
            const name = Buffer.from(P.subarray(start, start + len)).toString("latin1");
            if (name === "upper") { if (isUpperC(tCh) || (fold && isLowerC(tCh))) matched = 1; }
            else if (Object.hasOwn(CLASSES, name)) { if (CLASSES[name](tCh)) matched = 1; }
            else return WM_ABORT_ALL;
            pCh = 0;
          } else if (tCh === pCh) matched = 1;
        } while ((prevCh = pCh, (pCh = at(P, ++pi)) !== 93));
        if (matched === negated || (pathname && tCh === 47)) return WM_NOMATCH;
        continue;
      }
    }
  }
  return ti < T.length ? WM_NOMATCH : WM_MATCH;
}

const wildmatch = (P, T, fold, pathname) => dowild(P, 0, T, 0, fold, pathname) === WM_MATCH;
const simpleLength = (P) => { let i = 0; while (i < P.length && !isGlobSpecial(P[i])) i++; return i; };
function bytesEqual(a, b, fold) {
  if (a.length !== b.length) return false;
  spend(a.length);
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i] && !(fold && toLowerC(a[i]) === toLowerC(b[i]))) return false;
  return true;
}

const MAX_PATTERN_BYTES = 4096;

/* git's trim_trailing_spaces: drop trailing unescaped spaces (only spaces). */
function trimTrailingSpaces(line) {
  let lastSpace = -1;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === 32) { if (lastSpace < 0) lastSpace = i; continue; }
    if (c === 92) { i++; if (i >= line.length) return line; }
    lastSpace = -1;
  }
  return lastSpace >= 0 ? line.subarray(0, lastSpace) : line;
}

/* An ignore file's bytes -> {patterns (in file order), uncertain}. */
export function parseIgnore(buf) {
  let b = buf;
  if (b.length >= 3 && b[0] === 0xef && b[1] === 0xbb && b[2] === 0xbf) b = b.subarray(3);
  const patterns = [];
  let uncertain = false, entry = 0;
  for (let i = 0; i <= b.length; i++) {
    if (i < b.length && b[i] !== 10) continue;
    if (i === b.length && entry === i) break;
    let line = b.subarray(entry, i);
    entry = i + 1;
    if (line.length === 0 || line[0] === 35) continue; // empty, or a # comment
    if (line[line.length - 1] === 13) line = line.subarray(0, -1);
    const nul = line.indexOf(0);
    if (nul >= 0) line = line.subarray(0, nul); // git handles the line as a C string
    line = trimTrailingSpaces(line);
    if (line.length > MAX_PATTERN_BYTES) { uncertain = true; continue; }
    let p = line, negative = false, mustBeDir = false;
    if (p[0] === 33) { negative = true; p = p.subarray(1); }
    if (p.length && p[p.length - 1] === 47) { mustBeDir = true; p = p.subarray(0, -1); }
    const noDir = p.indexOf(47) < 0;
    const nowild = Math.min(simpleLength(p), p.length);
    const endsWith = p[0] === 42 && simpleLength(p.subarray(1)) === p.length - 1;
    // A literal prefix that runs straight into "**" (not after a "/"): git 2.52 matches it differently from older
    // git (match_pathname), and we can't know which git the user has; such a pattern is checked both ways.
    const lead = p[0] === 47 ? 1 : 0, pre = nowild - lead;
    const versioned = !noDir && pre > 0 && p[lead + pre] === 42 && p[lead + pre + 1] === 42 && p[lead + pre - 1] !== 47;
    patterns.push({ p, negative, mustBeDir, noDir, nowild, endsWith, versioned });
  }
  return { patterns, uncertain };
}

function matchBasename(base, pat, fold) {
  const { p, nowild, endsWith } = pat;
  if (nowild === p.length) return bytesEqual(p, base, fold);
  if (endsWith) return p.length - 1 <= base.length && bytesEqual(p.subarray(1), base.subarray(base.length - (p.length - 1)), fold);
  return wildmatch(p, base, fold, false);
}

function matchPathname(name, pat, fold, legacy = false) {
  let p = pat.p, prefix = pat.nowild;
  if (p[0] === 47) { p = p.subarray(1); prefix--; }
  if (prefix > 0) {
    if (prefix > name.length) return false;
    if (!bytesEqual(p.subarray(0, prefix), name.subarray(0, prefix), fold)) return false;
    if (p.length === prefix && name.length === prefix) return true;
    // One byte of the matched prefix stays, so wildmatch knows the rest is not the start of a path: "foo**/bar"
    // must not match "foobar" (git 2.52, match_pathname; older git matched it, ignoring a file git now shows).
    // Before 2.52 the whole prefix was cut, so "**" right after it counted as the start of a path (legacy).
    const keep = legacy ? prefix : prefix - 1;
    p = p.subarray(keep); name = name.subarray(keep);
    if (legacy && !p.length && !name.length) return true;
  }
  return wildmatch(p, name, fold, true);
}

/* The last pattern of one file that matches (name: the path relative to the file's folder), or null. sem: {legacy
 * (pre-2.52 prefix semantics), versioned (set when a version-dependent pattern was tried)}. */
function lastMatching(file, name, base, isDir, fold, sem = { legacy: false, versioned: false }) {
  for (let i = file.patterns.length - 1; i >= 0; i--) {
    const pat = file.patterns[i];
    if (pat.mustBeDir && !isDir) continue;
    if (pat.versioned) sem.versioned = true;
    if (pat.noDir ? matchBasename(base, pat, fold) : matchPathname(name, pat, fold, sem.legacy && pat.versioned)) return pat;
  }
  return null;
}

/* What isIgnored needs, built once per walk: the root, the git directory (for info/exclude; null when it can't be
 * used), whether the disk folds case, how case folding is checked (foldCheck, below), and a cache of parsed ignore
 * files. ignoreCase: git's core.ignorecase when the caller knows it (tests; the product never reads git config).
 * foldCheck: "both" (a case-insensitive disk: a match one way only is unverified), "reinclude" (a case-sensitive
 * disk: exact, unless only folding would show the path), "exact" or "folded" (ignoreCase known). gitVersion
 * ([major, minor], tests only): the git whose "prefix**" semantics to use; unknown, a pattern git 2.52 changed
 * (see parseIgnore's versioned) decides a path only when old and new semantics agree, else it is unverified. */
export async function ignoreContext(root, loc = null, { caseInsensitive, ignoreCase, gitVersion = null, workMax = IGNORE_WORK_MAX, budget = null } = {}) {
  loc ??= await locateGitdir(root);
  caseInsensitive ??= await isCaseInsensitive(loc.realRoot);
  const foldCheck = ignoreCase === true ? "folded" : ignoreCase === false ? "exact" : caseInsensitive ? "both" : "reinclude";
  const prefixSemantics = !gitVersion ? null : gitVersion[0] > 2 || (gitVersion[0] === 2 && gitVersion[1] >= 52) ? "2.52" : "legacy";
  return {
    realRoot: loc.realRoot, realBoundary: loc.realBoundary ?? loc.realRoot, gitdir: loc.gitdir, caseInsensitive, foldCheck, prefixSemantics,
    files: new Map(), work: budget ?? ignoreBudget({ workMax }), workExceeded: false,
  };
}

/* One ignore file, read once: {patterns, uncertain, refused}. `dir` is the folder (relative, "" for the root) of a
 * .gitignore, or null for info/exclude. A refusal other than missing or symlink (git reads neither) is uncertain. */
export function ignoreFile(ctx, dir) {
  const key = dir === null ? "\0exclude" : dir;
  if (!ctx.files.has(key)) {
    ctx.files.set(key, (async () => {
      const abs = dir === null ? (ctx.gitdir ? join(ctx.gitdir, "info", "exclude") : null)
        : join(ctx.realRoot, ...(dir ? dir.split("/") : []), ".gitignore");
      if (!abs) return { patterns: [], uncertain: false, refused: "missing" };
      const read = await readInsideEx(ctx.realBoundary, abs, MAX_IGNORE_BYTES);
      if (!read.buf) {
        // info/exclude has the lowest precedence: leaving it out never hides a file git shows.
        const uncertain = dir !== null && read.refused !== "missing" && read.refused !== "symlink";
        return { patterns: [], uncertain, refused: read.refused };
      }
      return { ...parseIgnore(read.buf), refused: null };
    })());
  }
  return ctx.files.get(key);
}

/* git's precedence: the .gitignore files from the path's own folder up to the root, the first file with a matching
 * pattern deciding, then info/exclude. -> {ignored: boolean, uncertain: boolean} */
async function decide(ctx, segs, isDir, fold) {
  // Git 2.52 or later, older, or unknown (both: a disagreement is reported as such).
  if (ctx.prefixSemantics === "2.52") return decideOnce(ctx, segs, isDir, fold, false);
  if (ctx.prefixSemantics === "legacy") return decideOnce(ctx, segs, isDir, fold, true);
  const now = await decideOnce(ctx, segs, isDir, fold, false);
  if (!now.versioned) return now;
  const old = await decideOnce(ctx, segs, isDir, fold, true);
  return { ...now, versionDiffers: old.ignored !== now.ignored };
}

async function decideOnce(ctx, segs, isDir, fold, legacy) {
  const sem = { legacy, versioned: false };
  const enc = segs.map((s) => Buffer.from(s, "utf8"));
  const base = enc[enc.length - 1];
  const join2 = (from) => Buffer.from(segs.slice(from).join("/"), "utf8");
  let uncertain = false;
  for (let k = segs.length - 1; k >= 0; k--) {
    const file = await ignoreFile(ctx, segs.slice(0, k).join("/"));
    uncertain ||= file.uncertain;
    WORK = ctx.work;
    const pat = lastMatching(file, join2(k), base, isDir, fold, sem);
    if (pat) return { ignored: !pat.negative, uncertain, versioned: sem.versioned };
  }
  const exclude = await ignoreFile(ctx, null);
  WORK = ctx.work;
  const pat = lastMatching(exclude, join2(0), base, isDir, fold, sem);
  return { ignored: Boolean(pat && !pat.negative), uncertain, versioned: sem.versioned };
}

/* The ignore state of `path` itself (relative, NFC; a folder when isDir), given that no folder above it is ignored:
 * "ignored", false, or "unverified". The walker calls this for each entry of a folder it walks. */
export async function ignoreStateAt(ctx, path, isDir) {
  const segs = path.split("/");
  if (segs.some((s) => s.toLowerCase() === ".git")) return "ignored"; // git never shows a .git entry
  if (ctx.work.left <= 0 || Date.now() > ctx.work.deadline) { ctx.workExceeded = true; return "unverified"; }
  const mode = ctx.foldCheck ?? (ctx.caseInsensitive ? "both" : "reinclude");
  let exact, folded;
  try {
    exact = await decide(ctx, segs, isDir, mode === "folded");
    // Folded too: always on a case-insensitive disk; on a case-sensitive one only when the exact rules ignore it.
    if (mode === "both" || (mode === "reinclude" && exact.ignored)) folded = await decide(ctx, segs, isDir, true);
  } catch (err) {
    if (err !== WORK_EXCEEDED) throw err;
    ctx.work.left = 0;
    ctx.workExceeded = true;
    return "unverified";
  }
  const state = exact.ignored;
  // A pattern older git and git 2.52 read differently decides the path one way under each: git may show it.
  if (exact.versionDiffers || folded?.versionDiffers) return "unverified";
  if (folded && folded.ignored !== exact.ignored) return "unverified";
  if (state && exact.uncertain) return "unverified";
  return state ? "ignored" : false;
}

/* The ignore state of `path` (relative to root; a trailing "/" names a folder), folders above it included: a path
 * under an ignored folder is ignored (git can't re-include it). It reads the path's NFC form only. With
 * core.precomposeunicode off, git matches a name's on-disk bytes, so for a non-ASCII name stored in another form this
 * can say "ignored" where git shows the file; the walker checks both forms (files.mjs). Its one caller,
 * state.ignoredByGit, asks about an ASCII path (a test pins it), where the two forms are the same. */
export async function ignoreState(root, path, ctx = null) {
  if (typeof path === "string") path = nfc(path);
  const isDir = typeof path === "string" && path.endsWith("/");
  const p = isDir ? path.slice(0, -1) : path;
  if (!isRelPath(p)) throw new TypeError("isIgnored: path must be relative, with forward slashes and no '..'");
  ctx ??= await ignoreContext(root);
  const segs = p.split("/");
  for (let i = 1; i < segs.length; i++) {
    const s = await ignoreStateAt(ctx, segs.slice(0, i).join("/"), true);
    if (s) return s;
  }
  return ignoreStateAt(ctx, p, isDir);
}

/* Whether `path` is ignored for certain (see ignoreState; "unverified" is not ignored here). */
export async function isIgnored(root, path, ctx = null) {
  return (await ignoreState(root, path, ctx)) === "ignored";
}

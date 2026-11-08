/* The inspector's file walker: which files under a project root are in scope, with their size and launch language.
 *
 * The rule: every file the walk meets is either in `files` or in `notAnalyzed` with a reason (or in `envFiles`, or
 * skipped as an untracked ignored file when the tracked set is known), and the status is never ok or empty when work
 * was dropped.
 *
 * It reads directory listings and file metadata, and the only files it opens are git's own (the `.git` file, the
 * index and shared index, info/exclude, .gitignore files), always through gitread's readInside, which refuses any
 * path with a symlink in it and any env file name; source files and `.env*` files are never opened (env files are
 * listed by name). A symlinked ignore file is reported as a symlink and its rules are not applied (git doesn't read
 * one either); a hard-linked, too large or unreadable one is reported as `ignore_file_unreadable` and the answers it
 * could change become unverified. It follows no symlink, and re-checks containment as it goes: just before each
 * directory is listed it must still be a real directory (not a symlink) whose realpath is inside the root, and just
 * after it must still be the same directory (device and inode), or the listing is discarded and the folder reported;
 * each file's realpath must be inside the root before the file is listed.
 *
 * walk(root, {maxFiles, maxBytes}) -> {
 *   files: [{path, size, lang, nlink?, disk?}]
 *       lang: a launch language id (the fact schema's `languages` values), or null for any other file.
 *       nlink: present when the file has more than one hard link. Kept, not skipped: we can't see where the other
 *              links are, skipping would let a hard link hide source, and nothing it holds leaves the machine.
 *       disk: present when the on-disk name differs from the NFC `path` (open the file with this one).
 *   notAnalyzed: [{path, kind, reason, tracked}]
 *       kind: file | directory (a directory entry covers everything under it; nothing under it is walked)
 *       tracked (contract v1.1): on a directory entry yes (git tracks something under it), no, or not_checked (the
 *       tracked set couldn't be read); null on a file entry
 *       reasons: too_large, unreadable, symlink_outside_root, file_limit, and the decided contract additions
 *       excluded_directory, embedded_git_dir, symlink, symlink_broken, not_regular_file, gitlink_into_source,
 *       ignored_unverified, ignore_file_unreadable, submodule (a nested root, with embedded_git_dir and
 *       gitlink_into_source), and gitlink_to_ancestor (ours: a nested `.git` naming this root's or an ancestor
 *       root's git directory, refused; the folder is walked as part of this root)
 *   envFiles: [{path, git}]   `.env`, `.env.*`, `*.env` files by name; git: tracked | untracked | ignored | not_checked
 *   status: ok | empty | truncated | failed     (not_run is the caller's, for a walk not run)
 *   reason: null for ok and empty; else file_limit | item_limit (contract) or tracked_set_unknown |
 *           ignore_unverified | unreadable_directory | root_unreadable (ours)
 *   nestedRoots: [{path, disk, reason, parentTracked}]   folders that are other repositories (reason submodule,
 *       embedded_git_dir or gitlink_into_source; also listed in notAnalyzed): not walked here, each is a root of its
 *       own, walked by walkAll. The files this root tracks inside one stay this root's (listed here, parentTracked
 *       names them for the nested walk to skip), so the nested root's ignore rules never drop them. At most
 *       nestedRootsMax per walk; past it the walk is truncated (item_limit).
 *   drops: every reason work was dropped, in priority order (reason is the first)
 *   count: files.length
 *   counts: {listed, total, totalExact, limit, ignored, notAnalyzedDropped, envFilesDropped, coveredByParent,
 *            ignoreWork, nestedRootsDropped}
 *       total: files that would have been listed with no limit (listed plus file_limit ones); totalExact is false
 *       when the walk stopped counting at 10 x maxFiles.
 *       coveredByParent: files skipped here because a root above lists them (it tracks them).
 *       ignoreWork: ignore-matching work units this walk spent (gitread.ignoreBudget).
 *       nestedRootsDropped: nested roots past nestedRootsMax, listed in notAnalyzed but not in nestedRoots.
 *   git: {layout, status, reason, tracked, known}   how the tracked set was read (gitread.mjs)
 *   gitdirAbs: the real absolute path of this root's git directory, or null. Local only: walkAll uses it to tell a
 *       gitlink into an ancestor's git directory; it must never be put in the fact document or sent anywhere.
 * }
 * Paths are relative to the realpath'd root, NFC, forward slashes, no "." or ".." segment, no leading "./". Odd names
 * (spaces, Unicode, colons, very long) are returned as they are, never dropped: the fact document hashes segments that don't fit the
 * fact schema's path pattern. The order is fixed (sorted by path), so the same tree gives the same result.
 *
 * Tracked set and ignore rules:
 *  - ignore answers are git's own (gitread's port of dir.c and wildmatch.c): "ignored", not, or "unverified" (a match
 *    only with case folding on a case-insensitive disk, where core.ignorecase may be off; or an ignore file we
 *    refused). An unverified path is reported as `ignored_unverified` and the status is truncated (ignore_unverified).
 *  - known tracked set (a readable index, or none at all): tracked files are included even when ignored; untracked
 *    ignored files and folders are skipped (counted in counts.ignored). An ignored folder holding tracked files is
 *    entered for those only (git shows nothing else in it).
 *  - unknown tracked set (a gitlink we don't follow, such as a worktree; a sparse index; a bad index): ignored
 *    paths are not dropped silently: each is reported as `ignored_unverified` (an ignored folder once, not entered),
 *    and the status is truncated with reason tracked_set_unknown.
 *  - no git directory at all: .gitignore means nothing without a repository, so no ignore rule is applied and every
 *    file is walked; env files are not_checked.
 * Case: on a case-insensitive disk an index path matches a disk path in any letter case (git's core.ignorecase
 * default there), and so does the .gitignore name; on a case-sensitive disk neither does.
 * Excluded folders follow the contract's lists (ALWAYS_EXCLUDED_DIRS, BUILD_DIRS): a dependency, environment or tool
 * cache folder is never walked and is reported once; a build-output or vendored folder is reported (tracked no, or
 * not_checked with the walk truncated) unless git tracks something in it, and then it is walked like source.
 * Ignore matching has one budget of work units (ignoreWorkMax, default 1e9) and one wall-clock deadline
 * (ignoreDeadlineMs, default 60 s), shared by every root of a walkAll (or passed in as ignoreBudget): past either, the
 * remaining ignore answers are unverified (ignored_unverified) and the walk is truncated (ignore_unverified).
 * Git directories: the root's own .git is listed as excluded_directory and never entered. A
 * nested folder that is a pure git directory (a bare-repository layout) is reported as `embedded_git_dir` and not
 * walked. A folder that is another repository's working tree (it holds a `.git` git directory, symlink or gitlink
 * file, or the index lists it as a submodule) goes to nestedRoots and is walked by walkAll as a root of its own, with
 * its own index and ignore rules (its git directory may be in the outer root's .git/modules). Any other `.git` folder
 * is listed as embedded_git_dir and never entered. */
import { access, constants, lstat, readdir, readlink, realpath, stat } from "node:fs/promises";
import { dirname, join, resolve, sep } from "node:path";
import {
  IGNORE_DEADLINE_MS, IGNORE_WORK_MAX, ignoreBudget, ignoreContext, ignoreFile, ignoreStateAt, isCaseInsensitive, isEnvFile, isGitName, isPureGitdir,
  isRelPath, locateGitdir, nestedGitReason, readTracked,
} from "./gitread.mjs";
import { languageOf as parseLanguageOf } from "./parse.mjs";

export { isEnvFile };

/* Dependency and build-output folders, as the contract lists them (enums.DEPENDENCY_DIRECTORIES, contract v2.1; names
 * compared exactly, at any depth). Only these may be reported as excluded_directory.
 *  - ALWAYS_EXCLUDED_DIRS (installed dependencies, environments, tool caches): never walked; reported as one folder
 *    with whether git tracks anything under it.
 *  - BUILD_DIRS (build output, vendored code): skipped only when git tracks nothing under them (tracked no) or the
 *    tracked set can't be read (tracked not_checked, and the walk is truncated); a tracked one is walked like source.
 * `.git` in any letter case is a git directory, handled apart. */
export const ALWAYS_EXCLUDED_DIRS = Object.freeze(new Set([
  "node_modules", "bower_components", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache",
  ".ruff_cache", ".gradle", ".terraform", ".turbo", ".dart_tool", "Pods",
]));
export const BUILD_DIRS = Object.freeze(new Set([".yarn", ".pnpm-store", ".cache", "vendor", "dist", "build", "target", "coverage",
  ".next", ".nuxt", ".svelte-kit", ".output", "out"]));
/* Version-control metadata (enums.VCS_METADATA_DIRECTORIES): never walked, listed as excluded_directory. .git and .hg
 * count only as the root's own (enums.ROOT_ONLY_VCS_DIRECTORIES): a nested .hg is another repository, listed as
 * embedded_git_dir (git directories are handled apart); .svn counts anywhere (Subversion before 1.7 kept one in every
 * directory). */
export const VCS_METADATA_DIRS = Object.freeze(new Set([".git", ".hg", ".svn"]));
export const EXCLUDED_DIRS = Object.freeze(new Set([...VCS_METADATA_DIRS, ...ALWAYS_EXCLUDED_DIRS, ...BUILD_DIRS]));
export const NESTED_ROOTS_MAX = 1_000; // per walk, and for walkAll in all

export const NOT_ANALYZED_MAX = 20_000; // the fact schema's files.not_analyzed maxItems
export const ENV_FILES_MAX = 1_000; // the fact schema's files.env_files maxItems
const COUNT_CEILING_FACTOR = 10; // past the limit, keep counting up to 10 x maxFiles
const BATCH = 64;
const DROP_ORDER = ["file_limit", "item_limit", "tracked_set_unknown", "ignore_unverified", "unreadable_directory"];

/* A path's launch language id (the fact schema's `languages` values, spec 3.2), from parse.mjs's one extension table. */
export const languageOf = parseLanguageOf;

const nfc = (p) => p.normalize("NFC");
const inside = (realRoot, p) => p.startsWith(realRoot.endsWith(sep) ? realRoot : realRoot + sep);
const byPath = (a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
const isDotGit = (name) => name.toLowerCase() === ".git";
/* Adds every parent folder of `path` ("a" and "a/b" for "a/b/c") to `set`. */
const addParentDirs = (set, path) => {
  for (let i = path.indexOf("/"); i >= 0; i = path.indexOf("/", i + 1)) set.add(path.slice(0, i));
};

export class OutsideRootError extends Error {
  constructor(rel, why) { super(`${why}: ${rel}`); this.name = "OutsideRootError"; this.code = "OUTSIDE_ROOT"; }
}

/* Call before opening a walked file: `rel` (a walked path, or its `disk` form) must name a regular file that
 * is not a symlink and whose realpath is inside the realpath'd root. Returns {abs, dev, ino, size}: open `abs`, then
 * compare the open handle's fstat dev and ino with these to close the gap between check and open. Throws
 * OutsideRootError (code OUTSIDE_ROOT) otherwise, and the fs error when the file is gone. */
export async function assertInside(root, rel) {
  if (!isRelPath(rel)) throw new OutsideRootError(String(rel), "not a relative path");
  const realRoot = await realpath(root);
  const abs = join(realRoot, ...rel.split("/"));
  const st = await lstat(abs);
  if (st.isSymbolicLink()) throw new OutsideRootError(rel, "a symlink");
  if (!st.isFile()) throw new OutsideRootError(rel, "not a regular file");
  const real = await realpath(abs);
  if (!inside(realRoot, real)) throw new OutsideRootError(rel, "outside the root");
  return { abs: real, dev: st.dev, ino: st.ino, size: st.size };
}

/* A symlink, never followed: why, and whether it names a folder (known only for a target inside the root; anything
 * else is decided without touching the target). -> {reason, kind} */
async function symlinkReason(realRoot, abs) {
  let target;
  try { target = await readlink(abs); } catch { return { reason: "symlink_broken", kind: "file" }; }
  const lexical = resolve(dirname(abs), target);
  if (lexical !== realRoot && !inside(realRoot, lexical)) return { reason: "symlink_outside_root", kind: "file" };
  let real;
  try { real = await realpath(lexical); } catch { return { reason: "symlink_broken", kind: "file" }; }
  if (real !== realRoot && !inside(realRoot, real)) return { reason: "symlink_outside_root", kind: "file" };
  const isDir = await stat(real).then((st) => st.isDirectory(), () => false);
  return { reason: "symlink", kind: isDir ? "directory" : "file" };
}

function hasBareLayout(entries) {
  const byName = new Map(entries.map((e) => [e.name, e]));
  return Boolean(byName.get("HEAD")?.isFile() && byName.get("objects")?.isDirectory() && byName.get("refs")?.isDirectory());
}

/* The first index in sorted `arr` whose value is >= key. */
function lowerBound(arr, key) {
  let lo = 0, hi = arr.length;
  while (lo < hi) { const mid = (lo + hi) >> 1; if (arr[mid] < key) lo = mid + 1; else hi = mid; }
  return lo;
}

/* notAnalyzedMax and envFilesMax default to the fact schema's caps; tests lower them. caseInsensitive defaults to a
 * probe of the disk under the root; tests set it to check the other behaviour on the same machine. boundary is set
 * by walkAll for a nested root: its git directory may sit anywhere inside the outermost root (a submodule's
 * <top>/.git/modules/<name>), never outside it. */
export async function walk(root, {
  maxFiles = 100_000, maxBytes = 2_000_000, notAnalyzedMax = NOT_ANALYZED_MAX, envFilesMax = ENV_FILES_MAX,
  caseInsensitive: caseOverride, boundary = null, ancestorGitdirs = [], coveredByParent = null,
  ignoreWorkMax = IGNORE_WORK_MAX, ignoreDeadlineMs = IGNORE_DEADLINE_MS, ignoreBudget: sharedBudget = null,
  nestedRootsMax = NESTED_ROOTS_MAX,
} = {}) {
  const files = [], notAnalyzed = [], envFiles = [], nestedRoots = [];
  const drops = new Set();
  const counts = {
    listed: 0, total: 0, totalExact: true, limit: maxFiles, ignored: 0, notAnalyzedDropped: 0, envFilesDropped: 0,
    coveredByParent: 0, ignoreWork: 0, nestedRootsDropped: 0,
  };
  let gitdirAbs = null;
  // A directory entry says whether git tracks anything under it (contract v1.1): set once the tracked set is read.
  let trackedOf = () => "not_checked";
  const finish = (git, failedReason = null) => {
    files.sort(byPath); notAnalyzed.sort(byPath); envFiles.sort(byPath); nestedRoots.sort(byPath);
    counts.listed = files.length;
    counts.total += files.length;
    const ordered = DROP_ORDER.filter((d) => drops.has(d));
    let status, reason = null;
    if (failedReason) { status = "failed"; reason = failedReason; }
    else if (ordered.length) { status = "truncated"; reason = ordered[0]; }
    else status = files.length || notAnalyzed.length || envFiles.length ? "ok" : "empty";
    return { files, notAnalyzed, envFiles, nestedRoots, status, reason, drops: ordered, count: files.length, counts, git, gitdirAbs };
  };
  const report = (path, reason, kind = "file") => {
    if (notAnalyzed.length < notAnalyzedMax) notAnalyzed.push({ path, kind, reason, tracked: kind === "directory" ? trackedOf(path) : null });
    else { counts.notAnalyzedDropped++; drops.add("item_limit"); }
  };
  // A folder that could not be listed: reported, and the walk is truncated.
  const unreadableDir = (path) => { report(path, "unreadable", "directory"); drops.add("unreadable_directory"); };
  const env = (path, standing) => {
    if (envFiles.length < envFilesMax) envFiles.push({ path, git: standing });
    else { counts.envFilesDropped++; drops.add("item_limit"); }
  };
  // The invariant: every entry the walk meets has exactly one outcome. It is listed (files), reported (notAnalyzed,
  // or counted past its cap with the walk truncated), an env file, skipped as ignored (counted; git doesn't show it
  // either, or it is reported as ignored_unverified), covered by a root above (which lists it), or a folder walked in
  // turn. A miscount is a bug that could hide a file: the walk throws (the files collector then fails) rather than
  // return a result that is silently short.
  let ignoredReported = 0; // ignored paths that are also reported (ignored_unverified): one outcome, counted twice
  const outcomes = () => files.length + notAnalyzed.length + counts.notAnalyzedDropped + envFiles.length + counts.envFilesDropped
    + counts.ignored + counts.coveredByParent - ignoredReported;
  const accounted = (got, want, where) => {
    if (got !== want) { const e = new Error(`walk: ${want} entries but ${got} outcomes (${where})`); e.code = "WALK_UNACCOUNTED"; throw e; }
  };

  let loc;
  try {
    loc = await locateGitdir(root, { boundary });
    if (!(await lstat(loc.realRoot)).isDirectory()) throw new Error("not a directory");
  } catch {
    return finish({ layout: "none", status: "not_run", reason: "root_unreadable", tracked: 0, known: false }, "root_unreadable");
  }
  const { realRoot } = loc;
  const tracked = await readTracked(root, loc);
  const known = tracked.known;
  const git = { layout: tracked.layout, status: tracked.status, reason: tracked.reason, tracked: tracked.paths.size, known };
  const applyIgnore = loc.layout !== "none" || loc.reason !== "no_git_dir"; // no repository: .gitignore means nothing
  // On a case-insensitive disk (macOS, Windows) the index may spell a path in another case than the disk does (a
  // rename that changed only case); git matches them, so we do too, or a tracked file could pass for untracked.
  const caseInsensitive = caseOverride ?? (await isCaseInsensitive(realRoot));
  const fold = caseInsensitive ? (p) => p.toLowerCase() : (p) => p;
  const isIgnoreFileName = (name) => fold(name) === ".gitignore"; // git opens ".gitignore"; the disk may fold it
  const trackedSet = new Set([...tracked.paths].map(fold));
  const gitlinks = new Set([...tracked.gitlinks].map(fold));
  const sortedTracked = [...tracked.paths].map((p) => [fold(p), p]).sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  const sortedKeys = sortedTracked.map(([k]) => k);
  const trackedDirs = new Set();
  // A submodule inside an ignored folder still keeps that folder walked.
  for (const p of [...sortedKeys, ...gitlinks]) addParentDirs(trackedDirs, p);
  const isTrackedPath = (path) => trackedSet.has(fold(path));
  const isTrackedDir = (path) => trackedDirs.has(fold(path));
  // On a case-sensitive disk an index path in another letter case is a different file, unless core.ignorecase is
  // on (any git config can turn it on; we never read config). Then git counts it as tracked and shows it, so an
  // ignored path that matches a tracked one only with case folded is never skipped as ignored: it is unverified.
  let foldedTracked = null;
  const tracksFolded = (path, isDir) => {
    if (caseInsensitive || !tracked.paths.size) return false;
    if (!foldedTracked) {
      foldedTracked = { files: new Set(), dirs: new Set() };
      for (const p of [...tracked.paths, ...tracked.gitlinks]) {
        const k = p.toLowerCase();
        foldedTracked.files.add(k);
        addParentDirs(foldedTracked.dirs, k);
      }
    }
    const k = path.toLowerCase();
    return isDir ? foldedTracked.dirs.has(k) || foldedTracked.files.has(k) : foldedTracked.files.has(k);
  };
  gitdirAbs = loc.gitdir ? await realpath(loc.gitdir).catch(() => loc.gitdir) : null;
  trackedOf = (path) => (!known ? "not_checked" : isTrackedDir(path) || gitlinks.has(fold(path)) ? "yes" : "no");
  // Files a root above lists (it tracks them): never listed again here, and handed on to any root nested below.
  const skippedList = coveredByParent ? [...coveredByParent] : [];
  const skipped = new Set(skippedList.map(fold));
  const isSkipped = (path) => skipped.size > 0 && skipped.has(fold(path));
  // The git directories of this root and every root above, as real paths (gitlink_to_ancestor compares real paths).
  const ancestors = (await Promise.all([...ancestorGitdirs, ...(gitdirAbs ? [gitdirAbs] : [])]
    .map((a) => realpath(a).catch(() => null)))).filter(Boolean);
  const trackedUnder = (dir) => {
    const out = [], prefix = `${fold(dir)}/`;
    for (let i = lowerBound(sortedKeys, prefix); i < sortedKeys.length && sortedKeys[i].startsWith(prefix); i++) out.push(sortedTracked[i][1]);
    return out;
  };
  const ctx = await ignoreContext(root, loc, {
    caseInsensitive, budget: sharedBudget ?? ignoreBudget({ workMax: ignoreWorkMax, deadlineMs: ignoreDeadlineMs }),
  });
  const workAtStart = ctx.work.left;
  let excludeRules = false;
  if (loc.gitdir) {
    try { excludeRules = (await lstat(join(loc.gitdir, "info", "exclude"))).isFile(); } catch { excludeRules = false; }
  }
  // The ignore state of an entry of a folder being walked: "ignored", false or "unverified" (gitread.ignoreStateAt).
  // In a folder that is itself ignored (entered only because it holds tracked files), every untracked entry is
  // ignored, as git doesn't look inside an ignored folder.
  // A name stored in another form than NFC (disk): git matches its raw bytes when core.precomposeunicode is unset or
  // false, and its NFC form when true. "ignored" holds only when both forms say so; else it is unverified, never a
  // silent drop of a file git shows.
  const stateOf = async (frame, path, isDir, disk = path) => {
    if (frame.dirState) return frame.dirState;
    const s = await ignoreStateAt(ctx, path, isDir).catch(() => false);
    if (s !== "ignored" || disk === path) return s;
    return (await ignoreStateAt(ctx, disk, isDir).catch(() => false)) === "ignored" ? s : "unverified";
  };
  const standing = async (frame, path, disk = path) => {
    if (!known || !applyIgnore) return "not_checked";
    if (isTrackedPath(path)) return "tracked";
    if (frame.noIgnore || !frame.rulesHere) return "untracked";
    const s = await stateOf(frame, path, false, disk);
    return s === "ignored" ? "ignored" : s === "unverified" ? "not_checked" : "untracked";
  };
  // An ignored path: skipped when the tracked set is known and the rules are sure, reported when not.
  const dropIgnored = (path, state, kind = "file") => {
    if (state === "ignored" && known && tracksFolded(path, kind === "directory")) state = "unverified";
    counts.ignored++;
    if (state === "unverified") { ignoredReported++; report(path, "ignored_unverified", kind); drops.add("ignore_unverified"); }
    else if (!known) { ignoredReported++; report(path, "ignored_unverified", kind); drops.add("tracked_set_unknown"); }
  };

  // Files: size, readability and containment, a batch at a time, never past the limit; the rest are file_limit. A
  // `deep` candidate (a file this root tracks inside a nested root's folder) must also have no symlink on its way:
  // its realpath must be its own path; one no longer on disk has nothing to cover.
  const checkCandidates = async (candidates) => {
    const before = outcomes();
    let next = 0, gone = 0;
    while (next < candidates.length && files.length < maxFiles) {
      const batch = candidates.slice(next, next + Math.min(BATCH, maxFiles - files.length));
      next += batch.length;
      const checked = await Promise.all(batch.map(async (c) => {
        try {
          const st = await lstat(c.abs);
          if (st.isSymbolicLink()) return { c, ...(await symlinkReason(realRoot, c.abs)) };
          if (!st.isFile()) return { c, reason: "not_regular_file" };
          const real = await realpath(c.abs);
          if (!inside(realRoot, real)) return { c, reason: "symlink_outside_root" }; // a parent swapped mid-walk
          // NFC on both sides: the index path is NFC, a macOS realpath may be NFD.
          if (c.deep && fold(real.normalize("NFC")) !== fold(c.abs.normalize("NFC"))) return { c, reason: "symlink" };
          try { await access(c.abs, constants.R_OK); } catch { return { c, reason: "unreadable" }; }
          return { c, st };
        } catch (err) {
          if (c.deep && (err?.code === "ENOENT" || err?.code === "ENOTDIR")) return { c, gone: true };
          return { c, reason: "unreadable" };
        }
      }));
      for (const { c, st, reason, kind, gone: vanished } of checked) {
        if (vanished) { gone++; continue; }
        if (reason) report(c.path, reason, kind);
        else if (st.size > maxBytes) report(c.path, "too_large");
        else {
          const f = { path: c.path, size: st.size, lang: languageOf(c.path) };
          if (st.nlink > 1) f.nlink = st.nlink;
          if (c.disk !== c.path) f.disk = c.disk;
          files.push(f);
        }
      }
    }
    for (; next < candidates.length; next++) {
      counts.total++;
      drops.add("file_limit");
      report(candidates[next].path, "file_limit");
    }
    accounted(outcomes() - before, candidates.length - gone, "candidates");
  };

  const rootDotGit = await lstat(join(realRoot, ".git")).catch(() => null);
  const ceiling = maxFiles * COUNT_CEILING_FACTOR;
  // Each frame: disk (the on-disk relative path, for fs calls), path (NFC), rules (ignore rules can apply here),
  // ownGitdir (the root's own git directory: skip git's names, walk the rest), noIgnore (inside a `.git`-named folder
  // that holds source: git never looks there, so its ignore rules say nothing; walked without them), dirState (the
  // folder is ignored or unverified but holds tracked files).
  const bare = loc.layout === "bare";
  const stack = [{ disk: "", path: "", rules: excludeRules && !bare, ownGitdir: bare, noIgnore: bare, dirState: false }];
  while (stack.length) {
    if (counts.total + files.length >= ceiling) { counts.totalExact = false; break; }
    const frame = stack.pop();
    const abs = frame.disk ? join(realRoot, ...frame.disk.split("/")) : realRoot;

    // Containment, re-checked just before listing: a real directory, not a symlink, realpath inside the root.
    let before;
    try { before = await lstat(abs); } catch { before = null; }
    if (frame.disk) {
      let real;
      if (!before) { unreadableDir(frame.path); continue; }
      // It was a folder when its parent was listed; swapped for a symlink since.
      if (before.isSymbolicLink()) { const s = await symlinkReason(realRoot, abs); report(frame.path, s.reason, "directory"); continue; }
      if (!before.isDirectory()) { report(frame.path, "not_regular_file"); continue; }
      try { real = await realpath(abs); } catch { unreadableDir(frame.path); continue; }
      if (!inside(realRoot, real)) { report(frame.path, "symlink_outside_root", "directory"); continue; }
    }
    let entries;
    try {
      entries = await readdir(abs, { withFileTypes: true });
    } catch {
      if (!frame.disk) return finish(git, "root_unreadable");
      unreadableDir(frame.path);
      continue;
    }
    // And again after listing: the same folder (device and inode), still not a symlink, still inside. A folder
    // swapped between the check and the listing gives a listing of something else, which is discarded.
    {
      let after = null, real = null;
      try { after = await lstat(abs); real = await realpath(abs); } catch { after = null; }
      const same = after && before && !after.isSymbolicLink() && after.isDirectory() && after.dev === before.dev && after.ino === before.ino
        && (frame.disk ? inside(realRoot, real) : real === realRoot);
      if (!same) {
        if (!frame.disk) return finish(git, "root_unreadable");
        unreadableDir(frame.path);
        continue;
      }
    }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    if (frame.ownGitdir) entries = entries.filter((e) => !isGitName(e.name));
    if (frame.disk && !frame.ownGitdir && !frame.noIgnore) {
      // A pure bare-repository layout below the root is git metadata, not source.
      if (hasBareLayout(entries) && isPureGitdir(entries.map((e) => e.name)) && !isTrackedDir(frame.path)) {
        report(frame.path, "embedded_git_dir", "directory");
        continue;
      }
      // Another repository's working tree (a submodule, a nested clone or worktree): its tracked set isn't ours, so
      // it is walked as a root of its own, with its own index (walkAll), never with ours.
      let nested = null;
      for (const e of entries) {
        if (!isDotGit(e.name)) continue;
        const why = await nestedGitReason(realRoot, join(abs, e.name), ancestors, { caseInsensitive });
        if (why === "gitlink_to_ancestor") {
          // A second door into this repository (or one above): refused, reported, and the folder stays ours.
          frame.refusedDotGit = e.name;
          report(frame.disk ? nfc(`${frame.disk}/${e.name}`) : e.name, "gitlink_to_ancestor");
        } else nested ??= why;
      }
      if (nested || gitlinks.has(fold(frame.path))) {
        // Another root: listed here as not analysed (its own walk covers it, walkAll), except the files this root
        // tracks inside it, which stay ours: the nested root's rules must never drop what we track.
        const reason = gitlinks.has(fold(frame.path)) ? "submodule" : nested; // a gitlink in our index is a submodule
        report(frame.path, reason, "directory");
        const ours = (known ? trackedUnder(frame.path) : []).filter((t) => !isSkipped(t));
        // Handed down: what we list here, plus what a root above lists under this folder (listed once, by the
        // outermost root that tracks it).
        const prefix = `${frame.path}/`;
        const above = skippedList.filter((t) => fold(t).startsWith(fold(prefix)));
        if (nestedRoots.length < nestedRootsMax) {
          nestedRoots.push({ path: frame.path, disk: frame.disk, reason, parentTracked: [...ours, ...above].map((t) => t.slice(prefix.length)) });
        } else { counts.nestedRootsDropped++; drops.add("item_limit"); }
        const cands = [];
        for (const t of ours) {
          if (isEnvFile(t.slice(t.lastIndexOf("/") + 1))) env(t, "tracked");
          else cands.push({ disk: t, path: t, abs: join(realRoot, ...t.split("/")), deep: true });
        }
        await checkCandidates(cands);
        continue;
      }
    }

    const rulesHere = applyIgnore && !frame.noIgnore
      && (frame.rules || Boolean(frame.dirState) || entries.some((e) => isIgnoreFileName(e.name) && (e.isFile() || e.isSymbolicLink())));
    frame.rulesHere = rulesHere;
    const subdirs = [], candidates = [];
    const tallyStart = outcomes();
    let elsewhere = 0; // entries whose outcome is outside this loop: a refused .git (reported above), the root's .git file
    const child = (disk, path, extra = {}) => ({ disk, path, rules: rulesHere, ownGitdir: false, noIgnore: frame.noIgnore, dirState: false, ...extra });
    for (const e of entries) {
      const disk = frame.disk ? `${frame.disk}/${e.name}` : e.name;
      const path = nfc(disk);
      if (!isRelPath(path)) continue; // unreachable: readdir never yields "", "." or ".." (the tally would throw)
      const isTracked = isTrackedPath(path);
      const check = !isTracked && rulesHere;
      if (isSkipped(path) && !e.isDirectory()) { counts.coveredByParent++; continue; }
      if (e.name === frame.refusedDotGit) { elsewhere++; continue; } // reported above as gitlink_to_ancestor
      // the inspector's own local files (concerns.mjs): the concern texts in .custosa/local and the .gitignore
      // that keeps them out of git. Not the project's, so never listed, read or reported.
      // a nested project's .custosa too.
      // a local folder that git tracks something in is the project's, walked like any other.
      if ((frame.disk === ".custosa" || frame.disk.endsWith("/.custosa")) &&
        (e.name === ".gitignore" || (e.name === "local" && !(known && isTrackedDir(path))))) { elsewhere++; continue; }

      if (isDotGit(e.name)) {
        // The root's own .git entry (the one locateGitdir found; on a case-insensitive disk it may be spelt .GIT).
        if (!frame.disk && rootDotGit && (await lstat(join(abs, e.name)).then((st) => st.ino === rootDotGit.ino, () => false))) {
          // Listed, never read : nothing under the root's .git is walked, opened or scanned;
          // only gitread reads git's own files (the index, info/exclude) to learn the tracked set.
          // Spelt .git whatever case the disk shows (on a case-insensitive disk .GIT is the same folder): the name the
          // contract lists.
          if (e.isDirectory()) report(".git", "excluded_directory", "directory");
          else elsewhere++; // a .git file or symlink at the root is described by git.layout and git.reason
          continue;
        }
        // Any other .git entry (a nested repository's is handled above; this is say .GIT beside .git on a
        // case-sensitive disk, or a .git folder holding source). git never shows one, so no ignore rule is applied
        // to it or below it: it is reported or walked, never skipped as ignored.
        if (e.isSymbolicLink()) { const s = await symlinkReason(realRoot, join(abs, e.name)); report(path, s.reason, s.kind); continue; }
        if (e.isFile()) { report(path, "embedded_git_dir"); continue; } // a gitlink
        // A .git folder anywhere else is another repository's (or a stray) git directory: listed, never entered.
        if (e.isDirectory()) { report(path, "embedded_git_dir", "directory"); continue; }
      }
      if (e.isSymbolicLink()) {
        if (isEnvFile(e.name)) { env(path, await standing(frame, path, disk)); continue; }
        // A symlinked ignore file is never read (git doesn't read one either); it is reported like any symlink.
        if (check && !isIgnoreFileName(e.name)) {
          const st = await stateOf(frame, path, false, disk);
          if (st) { dropIgnored(path, st); continue; }
        }
        const s = await symlinkReason(realRoot, join(abs, e.name));
        report(path, s.reason, s.kind);
        continue;
      }
      if (e.isDirectory()) {
        // The root's git directory under another name (a .git file naming a folder inside the root): never entered.
        if (path === loc.gitdirRel) { report(path, "embedded_git_dir", "directory"); continue; }
        if (e.name === ".svn" || (e.name === ".hg" && path === ".hg")) { report(path, "excluded_directory", "directory"); continue; }
        if (e.name === ".hg") { report(path, "embedded_git_dir", "directory"); continue; } // a nested Mercurial repository
        // a dependency folder git tracks something in is walked like any other (enums.py
        // DEPENDENCY_DIRECTORIES); otherwise it is reported as one folder, tracked no or not_checked.
        if (ALWAYS_EXCLUDED_DIRS.has(e.name) && !(known && isTrackedDir(path))) {
          report(path, "excluded_directory", "directory");
          continue;
        }
        if (BUILD_DIRS.has(e.name) && !(known && isTrackedDir(path))) {
          report(path, "excluded_directory", "directory"); // tracked no, or not_checked
          if (!known) drops.add("tracked_set_unknown");
          continue;
        }
        if (rulesHere && !gitlinks.has(fold(path))) {
          const st = await stateOf(frame, path, true, disk);
          if (st) {
            if (!isTrackedDir(path)) { dropIgnored(path, st, "directory"); continue; }
            subdirs.push(child(disk, path, { dirState: st })); // holds tracked files: walked for them only
            continue;
          }
        }
        subdirs.push(child(disk, path));
        continue;
      }
      if (!e.isFile()) { report(path, "not_regular_file"); continue; }
      if (isEnvFile(e.name)) { env(path, await standing(frame, path, disk)); continue; } // name only, never opened
      if (check) {
        const st = await stateOf(frame, path, false, disk);
        if (st) { dropIgnored(path, st); continue; }
      }
      if (isIgnoreFileName(e.name) && !frame.noIgnore && applyIgnore) {
        // An ignore file we refused to read (hard-linked, too large, unreadable): reported, and its folder's ignore
        // answers become unverified rather than trusted.
        const f = await ignoreFile(ctx, frame.path);
        if (f.refused && f.refused !== "missing" && f.refused !== "symlink") { report(path, "ignore_file_unreadable"); continue; }
      }
      candidates.push({ disk, path, abs: join(abs, e.name) });
    }

    accounted(outcomes() - tallyStart + candidates.length + subdirs.length, entries.length - elsewhere, frame.path || ".");
    await checkCandidates(candidates);
    for (let i = subdirs.length - 1; i >= 0; i--) stack.push(subdirs[i]);
  }
  if (!counts.totalExact) drops.add("file_limit");
  counts.ignoreWork = workAtStart - Math.max(0, ctx.work.left);
  if (ctx.workExceeded) drops.add("ignore_unverified"); // matching stopped at the work cap: answers since are unverified
  return finish(git);
}

/* Walk a root and every nested repository under it (submodules, nested clones and worktrees), each as a root of its
 * own: its own tracked set and ignore rules, its own paths (relative to it) and, in the fact document, its own
 * root_id (an HMAC of its absolute path). A parent lists each nested root in notAnalyzed (reason submodule,
 * embedded_git_dir or gitlink_into_source) and in nestedRoots, and keeps the files it tracks inside it; here each is
 * walked in turn, breadth first, skipping those parent-tracked files. Past maxRoots in all, the rest are not walked:
 * they stay in their parent's notAnalyzed, leave its nestedRoots, and the parent is truncated (item_limit).
 * -> {roots: [{abs, rel, reason, result, skipped?}]}: rel is "" and reason null for the outermost root; rel is
 *    relative to it, and reason says why the folder is a root (submodule, embedded_git_dir, gitlink_into_source).
 *    options.walkNested(abs, rel): when it returns false the nested root is listed with result null and skipped true,
 *    and isn't walked (nor are roots nested inside it). */
export async function walkAll(root, options = {}) {
  const { maxRoots = NESTED_ROOTS_MAX, walkNested: _walkNested, ...rest } = options;
  // One budget and one deadline for all ignore matching across every root.
  const walkOptions = { ...rest, ignoreBudget: rest.ignoreBudget ?? ignoreBudget({ workMax: rest.ignoreWorkMax, deadlineMs: rest.ignoreDeadlineMs }) };
  const top = await realpath(root).catch(() => null);
  const first = await walk(root, walkOptions);
  const roots = [{ abs: top ?? String(root), rel: "", reason: null, result: first, ancestors: [] }];
  if (!top) return { roots: roots.map(strip) };
  const queue = first.nestedRoots.map((n) => ({ parent: roots[0], n, rel: n.path }));
  while (queue.length) {
    const { parent, n, rel } = queue.shift();
    if (roots.length >= maxRoots) {
      const r = parent.result;
      r.nestedRoots = r.nestedRoots.filter((x) => x !== n); // listed in notAnalyzed already; not walked
      if (!r.drops.includes("item_limit")) {
        r.drops = DROP_ORDER.filter((d) => d === "item_limit" || r.drops.includes(d));
        if (r.status !== "failed") { r.status = "truncated"; r.reason = r.drops[0]; }
      }
      continue;
    }
    const ancestors = [...parent.ancestors, ...(parent.result.gitdirAbs ? [parent.result.gitdirAbs] : [])];
    const abs = join(parent.abs, ...n.disk.split("/"));
    // walkNested(abs, rel) false: listed as a root of its own but not walked (result null, skipped true); what lies
    // inside it is the caller's to find (the tool lists nested roots without walking the ones it won't send).
    if (options.walkNested && !options.walkNested(abs, rel)) {
      roots.push({ abs, rel, reason: n.reason, result: null, ancestors, skipped: true });
      continue;
    }
    const result = await walk(abs, { ...walkOptions, boundary: top, ancestorGitdirs: ancestors, coveredByParent: n.parentTracked });
    const entry = { abs, rel, reason: n.reason, result, ancestors };
    roots.push(entry);
    for (const m of result.nestedRoots) queue.push({ parent: entry, n: m, rel: `${rel}/${m.path}` });
  }
  return { roots: roots.map(strip) };
}
const strip = ({ abs, rel, reason, result, skipped }) => ({ abs, rel, reason, result, ...(skipped ? { skipped: true } : {}) });

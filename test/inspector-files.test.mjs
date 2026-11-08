/* Smoke test for the inspector's file walker and safe git reading: lib/inspector/files.mjs and gitread.mjs.
 *
 * Finding (plan step 1): nothing in the inspector runs a config-defined command. gitread.mjs no longer calls
 * isomorphic-git at all (second review): it parses the index itself (versions 2 to 4, SHA-1 or SHA-256, the split
 * index) and ports git's own ignore matching (dir.c, wildmatch.c; checked against real git by the differential test
 * below), and imports no child_process (checked at the end of this file). Only that differential test runs git, in
 * throwaway repositories with no global or system config. It never reads git config, so core.fsmonitor, filters, hooksPath, pager, textconv, excludesFile and
 * include.path are inert. Earlier finding, kept for the record: isomorphic-git 1.43.0 also runs no command (no
 * child_process anywhere in the package; listFiles reads only <gitdir>/index, version 2 only, and isIgnored reads
 * only info/exclude and .gitignore files), but it ignores the split-index `link` extension, rejects index versions 3
 * and 4, folds case in ignore matching on every disk, and reads through whatever fs it is given (so a symlinked
 * .gitignore pointing at a .env was read). Those were second-review findings 1, 2 and 4.
 *
 * Every file gitread opens goes through readInside: inside the realpath'd root, no symlink at any step, a regular
 * file opened with O_NOFOLLOW, and never an env file name. The tests below record every open and check that.
 * Gitlink choice: a `.git` file is followed only when its gitdir resolves inside the root and is a pure git directory.
 * Otherwise it is not followed: `gitlink_outside_root` (worktrees, submodules, anything outside) or
 * `gitlink_into_source` (it names a folder that holds other files, which is walked as source). A `.git` symlink is
 * never followed (git_dir_symlink). With no usable tracked set, ignored paths are reported as ignored_unverified and
 * the files collector is truncated (tracked_set_unknown); nothing is dropped silently. A folder below the root that is
 * another repository's working tree (submodule, nested clone) is reported whole, kind directory.
 *
 * This test builds hostile repositories with isomorphic-git or by hand (never the git binary, which would run their
 * config). Several cases come from the reviewers' probe scripts (probes 1 to 17 and the readdir race) and the
 * second review's four findings. */
import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import { createHash } from "node:crypto";
import { createRequire, syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import git from "isomorphic-git";
import { ALWAYS_EXCLUDED_DIRS, BUILD_DIRS, EXCLUDED_DIRS, OutsideRootError, assertInside, isEnvFile, languageOf, walk, walkAll } from "../lib/inspector/files.mjs";
import {
  ignoreBudget, ignoreContext, ignoreState, ignoreStateAt, isCaseInsensitive, isIgnored, isRelPath, locateGitdir,
  parseIndex, readTracked,
} from "../lib/inspector/gitread.mjs";
import { PATH, PATH_MAX } from "../lib/inspector/contracts.mjs";

const { mkdirSync, mkdtempSync, realpathSync, writeFileSync, symlinkSync, chmodSync, existsSync, readFileSync } = fs;
const temp = (prefix) => realpathSync(mkdtempSync(join(tmpdir(), prefix)));
const put = (path, text = "") => { mkdirSync(join(path, ".."), { recursive: true }); writeFileSync(path, text); };
const require = createRequire(import.meta.url);

/* Every way a process could be started, counted: the walker must start none. */
const cp = require("node:child_process");
const spawned = [];
for (const name of ["spawn", "spawnSync", "exec", "execSync", "execFile", "execFileSync", "fork"]) {
  const real = cp[name];
  cp[name] = (...args) => { spawned.push([name, String(args[0])]); return real(...args); };
}
syncBuiltinESMExports();

/* A marker script: if anything runs it, MARKER appears. */
function markerScript(dir) {
  const marker = join(dir, "MARKER");
  const script = join(dir, "evil.sh");
  writeFileSync(script, `#!/bin/sh\ntouch '${marker}'\ncat\n`);
  chmodSync(script, 0o755);
  return { marker, script };
}

function hostileConfig(script) {
  return [
    "[core]", `\tfsmonitor = ${script}`, `\tpager = ${script}`, `\thooksPath = hooks`, `\tsshCommand = ${script}`,
    `\tworktree = /etc`, `\texcludesFile = /etc/passwd`,
    '[filter "evil"]', `\tclean = ${script}`, `\tsmudge = ${script}`, `\tprocess = ${script}`, "\trequired = true",
    '[diff "evil"]', `\ttextconv = ${script}`, `\tcommand = ${script}`,
    "[diff]", `\texternal = ${script}`,
    "[pager]", `\tstatus = ${script}`,
    "[include]", "\tpath = /etc/gitconfig",
    "",
  ].join("\n");
}

function plantHooks(gitdir, script) {
  for (const hook of ["post-index-change", "pre-commit", "post-checkout", "fsmonitor-watchman", "reference-transaction"]) {
    put(join(gitdir, "hooks", hook), `#!/bin/sh\n'${script}'\n`);
    chmodSync(join(gitdir, "hooks", hook), 0o755);
  }
}

async function initRepo(dir, files, { bare = false } = {}) {
  await git.init({ fs, dir, bare, defaultBranch: "main" });
  for (const [path, text] of Object.entries(files)) put(join(dir, path), text);
  if (Object.keys(files).length) await git.add({ fs, dir, filepath: Object.keys(files), force: true });
}

/* A hand-built index listing `entries` ([path, mode?]), as the reviewer's probe built it: version 2 by default, or 4
 * (prefix-compressed names), with optional extensions ([signature, Buffer]). An empty path is a split-index
 * replacement entry. Returns the bytes; the SHA-1 trailer is the shared-index id when used as one. */
function buildIndex(entries, { version = 2, extensions = [] } = {}) {
  const parts = [];
  const head = Buffer.alloc(12); head.write("DIRC"); head.writeUInt32BE(version, 4); head.writeUInt32BE(entries.length, 8);
  parts.push(head);
  let prev = Buffer.alloc(0);
  for (const [p, mode] of entries) {
    const e = Buffer.alloc(62); e.writeUInt32BE(mode || 0o100644, 24); e.writeUInt16BE(Math.min(Buffer.byteLength(p), 0xfff), 60);
    const pb = Buffer.from(p);
    if (version === 4) {
      let common = 0;
      while (common < prev.length && common < pb.length && prev[common] === pb[common]) common++;
      const strip = prev.length - common;
      if (strip > 127) throw new Error("test helper: strip > 127");
      parts.push(e, Buffer.from([strip]), pb.subarray(common), Buffer.alloc(1));
    } else {
      let pad = 8 - ((62 + pb.length) % 8); if (pad === 0) pad = 8;
      parts.push(e, pb, Buffer.alloc(pad));
    }
    prev = pb;
  }
  for (const [sig, data] of extensions) {
    const h = Buffer.alloc(8); h.write(sig, 0, "latin1"); h.writeUInt32BE(data.length, 4);
    parts.push(h, data);
  }
  const body = Buffer.concat(parts);
  return Buffer.concat([body, createHash("sha1").update(body).digest()]);
}
const handIndex = (entries) => buildIndex(entries);

/* An EWAH bitmap (git's on-disk layout) with the given bits set, out of bitSize. */
function ewah(bitSize, bits) {
  const words = new Array(Math.ceil(bitSize / 64)).fill(0n);
  for (const b of bits) words[b >> 6] |= 1n << BigInt(b & 63);
  const out = Buffer.alloc(8 + (words.length + 1) * 8 + 4);
  out.writeUInt32BE(bitSize, 0); out.writeUInt32BE(words.length + 1, 4);
  out.writeBigUInt64BE(BigInt(words.length) << 33n, 8); // one marker word: no run, then the literal words
  words.forEach((w, i) => out.writeBigUInt64BE(w, 16 + i * 8));
  out.writeUInt32BE(0, 8 + (words.length + 1) * 8);
  return out;
}

/* A split index: `shared` entries go to sharedindex.<id>, the index holds the link extension, `replaced` empty-named
 * entries, then `added`. */
function writeSplitIndex(gitdir, { shared, deleted = [], replaced = [], added = [], version = 2 }) {
  const sharedBuf = buildIndex(shared);
  const oid = sharedBuf.subarray(sharedBuf.length - 20);
  writeFileSync(join(gitdir, `sharedindex.${oid.toString("hex")}`), sharedBuf);
  const link = Buffer.concat([oid, ewah(shared.length, deleted), ewah(shared.length, replaced)]);
  const entries = [...replaced.map(() => [""]), ...added.map((p) => (Array.isArray(p) ? p : [p]))];
  writeFileSync(join(gitdir, "index"), buildIndex(entries, { version, extensions: [["link", link]] }));
  return oid.toString("hex");
}

/* Every file the code under test opens or reads by path, while `fn` runs. */
async function recordOpens(fn) {
  const fsp = require("node:fs/promises");
  const real = { open: fsp.open, readFile: fsp.readFile };
  const opened = [];
  fsp.open = async (p, ...a) => { opened.push(String(p)); return real.open(p, ...a); };
  fsp.readFile = async (p, ...a) => { if (typeof p === "string" || p instanceof URL) opened.push(String(p)); return real.readFile(p, ...a); };
  syncBuiltinESMExports();
  try { return { result: await fn(), opened }; } finally { Object.assign(fsp, real); syncBuiltinESMExports(); }
}

/* Each opened path is inside root, has no symlink at any step below it, and is not an env file. */
function assertSafeOpens(root, opened) {
  for (const p of opened) {
    assert.ok(p.startsWith(`${root}/`), `opened outside the root: ${p}`);
    assert.ok(!isEnvFile(p.slice(p.lastIndexOf("/") + 1)), `opened an env file: ${p}`);
    let cur = root;
    for (const seg of p.slice(root.length + 1).split("/")) {
      cur = join(cur, seg);
      assert.ok(!fs.lstatSync(cur).isSymbolicLink(), `opened through a symlink: ${p}`);
    }
  }
}

const paths = (r) => r.files.map((f) => f.path);
const reasonsOf = (r) => Object.fromEntries(r.notAnalyzed.map((n) => [n.path, n.reason]));
function assertSafePaths(r) {
  for (const p of [...paths(r), ...r.notAnalyzed.map((n) => n.path), ...r.envFiles.map((n) => n.path)]) {
    assert.ok(isRelPath(p), `unsafe path ${JSON.stringify(p)}`);
    assert.ok(!p.startsWith("/") && !p.startsWith("./") && !p.split("/").includes(".."), p);
    assert.equal(p, p.normalize("NFC"), `not NFC: ${JSON.stringify(p)}`);
  }
}

test("hostile repository: no command runs, nothing outside the root, and the walk still reports", async () => {
  const outside = temp("custosa-a2-outside-");
  const { marker, script } = markerScript(outside);
  writeFileSync(join(outside, "secret.ts"), "export const x = 1;\n");
  const root = temp("custosa-a2-hostile-");

  await initRepo(root, {
    "src/app.ts": "export const a = 1;\n",
    "generated/bundle.js": "tracked even though generated/ is ignored\n",
    ".gitignore": "generated/\ntmp/\n*.log\n.env\n",
    ".gitattributes": "* filter=evil diff=evil\n",
  });
  // The hostile parts are added after the index is written, so nothing (not even isomorphic-git's add) saw them.
  writeFileSync(join(root, ".git", "config"), hostileConfig(script));
  plantHooks(join(root, ".git"), script);
  put(join(root, "generated", "other.js"), "untracked and ignored\n");
  put(join(root, "tmp", "scratch.ts"), "untracked and ignored\n");
  put(join(root, "debug.log"), "ignored\n");
  put(join(root, "src", "new.py"), "untracked, not ignored\n");
  put(join(root, "src", "view.tsx"), "");
  put(join(root, ".env"), "SHOULD_NEVER_BE_READ=1\n");
  put(join(root, "config", ".env.production"), "SHOULD_NEVER_BE_READ=1\n");
  put(join(root, "node_modules", "pkg", "index.js"), "");
  put(join(root, "dist", "out.js"), "");
  put(join(root, "big.json"), "x".repeat(5000));
  symlinkSync("/etc", join(root, "link-etc"));
  symlinkSync(join(outside, "secret.ts"), join(root, "src", "link-out.ts"));
  symlinkSync("../../../../../../../../etc/passwd", join(root, "src", "link-up.ts"));
  symlinkSync("app.ts", join(root, "src", "link-in.ts"));
  symlinkSync(join(root, "nope"), join(root, "src", "link-broken.ts"));
  // An embedded pure bare repository with its own hostile config and hooks.
  const bare = join(root, "sub-bare");
  put(join(bare, "HEAD"), "ref: refs/heads/main\n");
  mkdirSync(join(bare, "objects"), { recursive: true });
  mkdirSync(join(bare, "refs", "heads"), { recursive: true });
  writeFileSync(join(bare, "config"), `[core]\n\tbare = true\n${hostileConfig(script)}`);
  plantHooks(bare, script);

  const r = await walk(root, { maxBytes: 1000 });
  const tracked = (await readTracked(root)).paths;

  assert.equal(existsSync(marker), false, "the marker script ran");
  assert.deepEqual(spawned, [], "a child process was started");
  assertSafePaths(r);
  assert.equal(r.status, "ok");
  assert.equal(r.reason, null);
  assert.deepEqual(r.git, { layout: "dir", status: "ok", reason: null, tracked: 4, known: true });
  assert.deepEqual([...tracked].sort(), [".gitattributes", ".gitignore", "generated/bundle.js", "src/app.ts"]);

  assert.deepEqual(paths(r), [".gitattributes", ".gitignore", "generated/bundle.js", "src/app.ts", "src/new.py", "src/view.tsx"]);
  assert.deepEqual(r.files.find((f) => f.path === "src/app.ts"), { path: "src/app.ts", size: 20, lang: "typescript" });
  assert.equal(r.files.find((f) => f.path === "src/view.tsx").lang, "tsx");
  assert.equal(r.files.find((f) => f.path === ".gitignore").lang, null);
  assert.equal(r.counts.ignored, 3); // generated/other.js, tmp/, debug.log: untracked and ignored, tracked set known

  assert.deepEqual(reasonsOf(r), {
    ".git": "excluded_directory",
    "big.json": "too_large",
    "dist": "excluded_directory",
    "link-etc": "symlink_outside_root",
    "node_modules": "excluded_directory",
    "src/link-broken.ts": "symlink_broken",
    "src/link-in.ts": "symlink",
    "src/link-out.ts": "symlink_outside_root",
    "src/link-up.ts": "symlink_outside_root",
    "sub-bare": "embedded_git_dir",
  });
  assert.deepEqual(r.envFiles, [{ path: ".env", git: "ignored" }, { path: "config/.env.production", git: "untracked" }]);

  assert.equal(await isIgnored(root, "generated/"), true);
  assert.equal(await isIgnored(root, "generated/bundle.js"), true);
  assert.equal(await isIgnored(root, "src/app.ts"), false);
  await assert.rejects(isIgnored(root, "../etc/passwd"), TypeError);
  await assert.rejects(isIgnored(root, "/etc/passwd"), TypeError);
  assert.equal(existsSync(marker), false);
  assert.deepEqual(spawned, []);
});

// Contract v2.1: version-control metadata. The root's .hg and any .svn are listed as excluded_directory and never read;
// a nested .hg is another repository (embedded_git_dir).
test("version-control metadata: root .hg and any .svn are excluded, a nested .hg is a nested repository", async () => {
  const root = temp("custosa-vcs-");
  await initRepo(root, { "a.js": "" });
  put(join(root, ".hg", "store", "data.i")); put(join(root, ".svn", "entries"));
  put(join(root, "lib", ".svn", "wc.db")); put(join(root, "lib", "b.js"));
  put(join(root, "vendored", ".hg", "hgrc")); put(join(root, "vendored", "c.js"));
  const r = await walk(root);
  assert.deepEqual(paths(r), ["a.js", "lib/b.js", "vendored/c.js"]);
  assert.deepEqual(r.notAnalyzed, [
    { path: ".git", kind: "directory", reason: "excluded_directory", tracked: "no" },
    { path: ".hg", kind: "directory", reason: "excluded_directory", tracked: "no" },
    { path: ".svn", kind: "directory", reason: "excluded_directory", tracked: "no" },
    { path: "lib/.svn", kind: "directory", reason: "excluded_directory", tracked: "no" },
    { path: "vendored/.hg", kind: "directory", reason: "embedded_git_dir", tracked: "no" },
  ]);
});

// Review 5: tracked files under excluded folders are listed one by one; a tracked .env there is an env file.
// Contract (enums.py DEPENDENCY_DIRECTORIES): dependency, build-output and vendored folders are skipped only when git
// tracks nothing in them; a tracked one is walked like any other folder (a committed Pods/ or
// node_modules was skipped, and blocked every coverage pass). Directory entries carry tracked.
test("excluded folders: skipped when untracked; tracked dependency, build and vendor folders walked like source", async () => {
  const root = temp("custosa-a2-excluded-");
  await initRepo(root, { "vendor/app/handler.js": "", "dist/.env": "K=1", "build/config/secret.yml": "", "a.js": "", "node_modules/t/i.js": "" });
  put(join(root, "node_modules", "x", "index.js"));
  put(join(root, "vendor", "untracked.js"));
  put(join(root, "target", "out.js")); put(join(root, "coverage", "lcov.json")); // untracked build output
  put(join(root, ".venv", "lib", "site.py"));
  const r = await walk(root);
  assert.equal(r.status, "ok");
  assert.deepEqual(paths(r), ["a.js", "build/config/secret.yml", "node_modules/t/i.js", "node_modules/x/index.js",
    "vendor/app/handler.js", "vendor/untracked.js"]);
  assert.deepEqual(r.notAnalyzed, [
    { path: ".git", kind: "directory", reason: "excluded_directory", tracked: "no" },
    { path: ".venv", kind: "directory", reason: "excluded_directory", tracked: "no" },
    { path: "coverage", kind: "directory", reason: "excluded_directory", tracked: "no" },
    { path: "target", kind: "directory", reason: "excluded_directory", tracked: "no" },
  ]);
  assert.deepEqual(r.envFiles, [{ path: "dist/.env", git: "tracked" }]);

  // With no readable tracked set a build folder is skipped as not_checked, and the walk is truncated; a dependency
  // folder is skipped either way.
  fs.rmSync(join(root, ".git", "index"));
  writeFileSync(join(root, ".git", "index"), "broken");
  const u = await walk(root);
  assert.deepEqual([u.status, u.reason], ["truncated", "tracked_set_unknown"]);
  assert.deepEqual(u.notAnalyzed.find((n) => n.path === "vendor"), { path: "vendor", kind: "directory", reason: "excluded_directory", tracked: "not_checked" });
  assert.deepEqual(u.notAnalyzed.find((n) => n.path === "node_modules"), { path: "node_modules", kind: "directory", reason: "excluded_directory", tracked: "not_checked" });
});

// an ignored dependency folder that holds a tracked file is walked for that file only, like vendor.
test("excluded folders: an ignored Pods folder with a committed file is walked for the tracked file", async () => {
  const root = temp("custosa-t27-pods-");
  await initRepo(root, { ".gitignore": "Pods/\n", "Pods/Lib/a.m": "", "a.js": "" });
  put(join(root, "Pods", "Lib", "b.m"));
  const r = await walk(root);
  assert.equal(r.status, "ok");
  assert.deepEqual(paths(r), [".gitignore", "Pods/Lib/a.m", "a.js"]);
  assert.equal(r.notAnalyzed.some((n) => n.path === "Pods"), false);
});

// .custosa/local is the inspector's own only while git tracks nothing in it. A tracked file there is the
// project's: walked and scanned, never dropped with no outcome. The .gitignore the inspector writes stays skipped,
// tracked or not: committing it is the normal case, and it holds only the inspector's two patterns.
test("a tracked file under .custosa/local is walked; untracked ones are still skipped", async () => {
  const root = temp("custosa-t27-local-");
  await initRepo(root, { "pkg/.custosa/local/creds.js": "", ".custosa/.gitignore": "", "app.js": "" });
  put(join(root, ".custosa", "local", "concerns.json"), "{}");
  put(join(root, "pkg", ".custosa", "local", "untracked.js"));
  const r = await walk(root);
  assert.equal(r.status, "ok");
  // pkg's local holds a tracked file, so it is the project's folder, walked whole like a tracked vendor folder; the
  // root's local holds nothing tracked, so its concerns.json stays the inspector's own.
  assert.deepEqual(paths(r), ["app.js", "pkg/.custosa/local/creds.js", "pkg/.custosa/local/untracked.js"]);
  assert.deepEqual(r.notAnalyzed.filter((n) => n.path.includes(".custosa")), []);
});

// Review 4 and 5: a git worktree (the .git file points outside the root) has no usable tracked set.
test("worktree gitlink outside the root: not followed; ignored paths reported; truncated", async () => {
  const outside = temp("custosa-a2-gitdir-");
  const { marker, script } = markerScript(outside);
  const main = join(outside, "main");
  await initRepo(main, { "a.js": "", ".gitignore": "generated/\n", "generated/api.ts": "", ".env": "K=1" });
  writeFileSync(join(main, ".git", "config"), hostileConfig(script));
  plantHooks(join(main, ".git"), script);
  const wtGit = join(main, ".git", "worktrees", "w");
  mkdirSync(wtGit, { recursive: true });
  writeFileSync(join(wtGit, "HEAD"), "ref: refs/heads/main\n");
  writeFileSync(join(wtGit, "commondir"), "../..\n");
  fs.copyFileSync(join(main, ".git", "index"), join(wtGit, "index"));

  const root = temp("custosa-a2-worktree-");
  writeFileSync(join(root, ".git"), `gitdir: ${wtGit}\n`);
  for (const p of ["a.js", ".gitignore", "generated/api.ts", ".env", "vendor/lib.js"]) {
    put(join(root, p), p === ".gitignore" ? "generated/\n" : "");
  }

  const loc = await locateGitdir(root);
  assert.deepEqual([loc.layout, loc.gitdir, loc.reason], ["gitlink", null, "gitlink_outside_root"]);
  assert.deepEqual([...((await readTracked(root)).paths)], []);
  const r = await walk(root);
  assert.deepEqual(r.git, { layout: "gitlink", status: "not_run", reason: "gitlink_outside_root", tracked: 0, known: false });
  assert.equal(r.status, "truncated");
  assert.equal(r.reason, "tracked_set_unknown");
  assert.deepEqual(paths(r), [".gitignore", "a.js"]);
  assert.deepEqual(reasonsOf(r), { "generated": "ignored_unverified", "vendor": "excluded_directory" });
  assert.deepEqual(r.envFiles, [{ path: ".env", git: "not_checked" }]);
  assertSafePaths(r);

  // A relative gitlink climbing out of the root is refused the same way; a .git symlink is never followed.
  writeFileSync(join(root, ".git"), "gitdir: ../../../../../../../../tmp\n");
  assert.equal((await locateGitdir(root)).reason, "gitlink_outside_root");
  fs.rmSync(join(root, ".git"));
  symlinkSync(join(main, ".git"), join(root, ".git"));
  const s = await walk(root);
  assert.equal(s.git.reason, "git_dir_symlink");
  assert.equal(s.status, "truncated");
  assert.equal(existsSync(marker), false);
  assert.deepEqual(spawned, []);
});

// Review 3: a gitlink naming a source folder never hides it.
test("gitlink into a source folder: not followed, the folder is walked", async () => {
  const root = temp("custosa-a2-gitlink-src-");
  put(join(root, "src", "app.js"), "secret()");
  put(join(root, "main.js"));
  writeFileSync(join(root, ".git"), "gitdir: src\n");
  const loc = await locateGitdir(root);
  assert.equal(loc.reason, "gitlink_into_source");
  const r = await walk(root);
  assert.equal(r.git.reason, "gitlink_into_source");
  assert.deepEqual(paths(r), ["main.js", "src/app.js"]);
  assert.equal(r.status, "ok"); // nothing ignored, nothing dropped
});

test("gitlink to a pure git directory inside the root: followed, and that directory is not walked", async () => {
  const root = temp("custosa-a2-gitlink-in-");
  const store = join(root, "store");
  await initRepo(store, { "keep.ts": "export {};\n" });
  fs.renameSync(join(store, ".git"), join(root, ".gitstore"));
  fs.rmSync(store, { recursive: true });
  writeFileSync(join(root, ".git"), "gitdir: .gitstore\n");
  put(join(root, "keep.ts"), "export {};\n");
  put(join(root, ".gitignore"), "keep.ts\n");
  const r = await walk(root);
  assert.deepEqual([r.git.layout, r.git.status, r.git.known], ["gitlink", "ok", true]);
  assert.deepEqual([...((await readTracked(root)).paths)], ["keep.ts"]);
  assert.deepEqual(paths(r), [".gitignore", "keep.ts"]);
  // The root's git directory under another name: listed, never entered.
  assert.deepEqual(r.notAnalyzed, [{ path: ".gitstore", kind: "directory", reason: "embedded_git_dir", tracked: "no" }]);
});

// Reviewer G2: a crafted index in an in-root gitdir. Bad entries never become paths.
test("crafted index entries are filtered, and nothing outside the root is returned", async () => {
  const root = temp("custosa-a2-crafted-");
  put(join(root, "a.js"));
  symlinkSync("/etc", join(root, "link"));
  mkdirSync(join(root, "meta", "gd"), { recursive: true });
  writeFileSync(join(root, "meta", "gd", "HEAD"), "ref: refs/heads/main\n");
  writeFileSync(join(root, "meta", "gd", "commondir"), "/etc\n");
  writeFileSync(join(root, "meta", "gd", "index"), handIndex([["/etc/passwd"], ["a.js"], ["link", 0o120000], ["x/./y"], [".git/config"]]));
  put(join(root, "meta", "other.js"));
  writeFileSync(join(root, ".git"), "gitdir: meta/gd\n");
  const t = await readTracked(root);
  assert.deepEqual([...t.paths].sort(), ["a.js", "link"]);
  const r = await walk(root);
  assert.deepEqual(paths(r), ["a.js", "meta/other.js"]);
  assert.deepEqual(reasonsOf(r), { link: "symlink_outside_root", "meta/gd": "embedded_git_dir" });
  assertSafePaths(r);
});

test("bare repository root: handled without running anything", async () => {
  const root = temp("custosa-a2-bare-");
  const { marker, script } = markerScript(temp("custosa-a2-bare-marker-"));
  await git.init({ fs, dir: root, bare: true, defaultBranch: "main" });
  writeFileSync(join(root, "config"), `[core]\n\tbare = true\n${hostileConfig(script)}`);
  plantHooks(root, script);
  assert.equal((await locateGitdir(root)).layout, "bare");
  assert.deepEqual([...((await readTracked(root)).paths)], []);
  const r = await walk(root);
  assert.deepEqual([r.status, r.reason, r.git.layout], ["empty", null, "bare"]);
  assert.deepEqual([r.files, r.notAnalyzed], [[], []]);
  assert.equal(existsSync(marker), false);
  assert.deepEqual(spawned, []);
});

// Review 4 (P4, G3): an index we can't read means an unknown tracked set, never silently dropped ignored files.
test("unreadable index (a broken checksum, a ../ entry, a symlink): failed git, ignored paths reported, truncated", async () => {
  const root = temp("custosa-a2-index-");
  await initRepo(root, { "a.go": "package a\n", ".gitignore": "generated/\n", "generated/api.ts": "" });
  put(join(root, ".env"));
  const index = join(root, ".git", "index");
  const good = readFileSync(index);
  const v4 = Buffer.from(good); v4.writeUInt32BE(4, 4); // the version changed under an unchanged checksum
  writeFileSync(index, v4);
  let r = await walk(root);
  assert.deepEqual([r.git.status, r.git.reason, r.git.known], ["failed", "index_unreadable", false]);
  assert.deepEqual([r.status, r.reason], ["truncated", "tracked_set_unknown"]);
  assert.deepEqual(paths(r), [".gitignore", "a.go"]);
  assert.deepEqual(reasonsOf(r), { ".git": "excluded_directory", generated: "ignored_unverified" });
  assert.deepEqual(r.envFiles, [{ path: ".env", git: "not_checked" }]);

  writeFileSync(index, handIndex([["../../etc/passwd"], ["generated/api.ts"]]));
  r = await walk(root);
  assert.deepEqual([r.git.status, r.status], ["failed", "truncated"]);

  const outsideIndex = join(temp("custosa-a2-index-out-"), "index");
  writeFileSync(outsideIndex, good);
  fs.rmSync(index);
  symlinkSync(outsideIndex, index);
  r = await walk(root);
  assert.deepEqual([r.git.status, r.git.reason], ["failed", "index_symlink"]);
});

// Review 8 (P17): git layouts never hide source. Second review: a folder that is another repository's working tree
// is reported whole (kind directory), not walked with our tracked set.
test("embedded git directories: nested repositories are roots of their own, git layouts holding other files listed, never walked", async () => {
  const root = temp("custosa-a2-embedded-");
  put(join(root, "src", "HEAD")); mkdirSync(join(root, "src", "objects")); mkdirSync(join(root, "src", "refs"));
  put(join(root, "src", "handler.js"));
  put(join(root, "lib", ".git", "hidden.js"));
  put(join(root, "pure", ".git", "HEAD")); mkdirSync(join(root, "pure", ".git", "objects"));
  put(join(root, "pure", ".git", "config"), "[core]\n\tfsmonitor = /bin/false\n");
  put(join(root, "pure", "code.py"));
  put(join(root, "sub", ".git"), "gitdir: ../.git/modules/sub\n");
  put(join(root, "sub", "x.go"));
  const r = await walk(root);
  assert.equal(r.status, "ok");
  assert.deepEqual(paths(r), ["src/HEAD", "src/handler.js"]);
  // Listed as not analysed here (contract v1.1: nested roots are reported), and walked as roots of their own. A .git
  // folder that is no repository is listed and never entered.
  assert.deepEqual(r.notAnalyzed, [
    { path: "lib/.git", kind: "directory", reason: "embedded_git_dir", tracked: "not_checked" },
    { path: "pure", kind: "directory", reason: "embedded_git_dir", tracked: "not_checked" },
    { path: "sub", kind: "directory", reason: "embedded_git_dir", tracked: "not_checked" },
  ]);
  assert.deepEqual(r.nestedRoots.map((n) => [n.path, n.reason]), [["pure", "embedded_git_dir"], ["sub", "embedded_git_dir"]]);
  const all = await walkAll(root);
  assert.deepEqual(all.roots.map((x) => [x.rel, x.result.git.layout, x.result.git.reason, paths(x.result)]), [
    ["", "none", "no_git_dir", ["src/HEAD", "src/handler.js"]],
    ["pure", "dir", "no_index", ["code.py"]],
    ["sub", "gitlink", "gitlink_missing", ["x.go"]],
  ]);
  assert.equal(all.roots[1].abs, join(root, "pure"));
});

test("a root .git directory spelt in another case is still the git directory, not source", async () => {
  const root = temp("custosa-a2-case-");
  await initRepo(root, { "a.js": "" });
  fs.renameSync(join(root, ".git"), join(root, ".GIT"));
  const caseInsensitive = existsSync(join(root, ".git"));
  const r = await walk(root);
  if (caseInsensitive) {
    assert.equal(r.git.layout, "dir");
    assert.deepEqual(paths(r), ["a.js"]);
    assert.deepEqual(r.notAnalyzed, [{ path: ".git", kind: "directory", reason: "excluded_directory", tracked: "no" }]); // listed under the name the contract knows
  } else {
    assert.deepEqual(paths(r), ["a.js"]);
    assert.deepEqual(reasonsOf(r), { ".GIT": "embedded_git_dir" });
  }
});

// Review 2: NFC on both sides.
test("Unicode: paths are NFC on both sides, so a tracked file in an ignored folder is kept", async () => {
  const root = temp("custosa-a2-nfc-");
  const nfcName = "café", nfdName = "café";
  await initRepo(root, { ".gitignore": "gen/\n", [`gen/${nfcName}.ts`]: "" });
  fs.rmSync(join(root, "gen", `${nfcName}.ts`));
  writeFileSync(join(root, "gen", `${nfdName}.ts`), "");
  writeFileSync(join(root, `${nfdName}-top.py`), "");
  const r = await walk(root);
  assert.deepEqual(paths(r), [".gitignore", `${nfcName}-top.py`, `gen/${nfcName}.ts`]);
  assertSafePaths(r);
  for (const f of r.files) if (f.disk) assert.ok(existsSync(join(root, ...f.disk.split("/"))), f.disk);
  assert.equal(await isIgnored(root, `gen/${nfdName}.ts`), true);
});

// Review 1 (P11): hard links are kept with a note.
test("a hard-linked file is listed with its link count", async () => {
  const root = temp("custosa-a2-hardlink-");
  const out = join(temp("custosa-a2-hardlink-out-"), "secret.txt");
  writeFileSync(out, "TOPSECRET");
  fs.linkSync(out, join(root, "looks-local.js"));
  const r = await walk(root);
  assert.deepEqual(r.files, [{ path: "looks-local.js", size: 9, lang: "javascript", nlink: 2 }]);
});

// Review 1 (P13): unreadable files and folders are reported; a folder we couldn't list truncates.
test("unreadable file and folder", { skip: process.getuid?.() === 0 }, async () => {
  const root = temp("custosa-a2-unreadable-");
  put(join(root, "ok.js")); put(join(root, "u.js")); put(join(root, "ud", "x.js"));
  chmodSync(join(root, "u.js"), 0); chmodSync(join(root, "ud"), 0);
  try {
    const r = await walk(root);
    assert.deepEqual(paths(r), ["ok.js"]);
    assert.deepEqual(reasonsOf(r), { "u.js": "unreadable", ud: "unreadable" });
    assert.deepEqual([r.status, r.reason], ["truncated", "unreadable_directory"]);
  } finally { chmodSync(join(root, "ud"), 0o755); chmodSync(join(root, "u.js"), 0o644); }
});

// Review 1 (reviewer's race probe): a folder swapped for a symlink to outside between listing its parent and itself.
test("containment race: a folder swapped for a symlink mid-walk is reported, not entered", async () => {
  const root = temp("custosa-a2-race-");
  put(join(root, "a", "x.js"), "1");
  const out = temp("custosa-a2-race-out-");
  writeFileSync(join(out, "id_rsa"), "PRIVATE"); writeFileSync(join(out, "other.py"), "1");
  const fsp = require("node:fs/promises");
  const real = fsp.readdir;
  let swapped = false;
  fsp.readdir = async (p, ...a) => {
    const result = await real(p, ...a);
    if (!swapped && String(p) === root && a[0]?.withFileTypes) { // the walk's listing, not the case probe
      swapped = true; fs.rmSync(join(root, "a"), { recursive: true }); symlinkSync(out, join(root, "a")); }
    return result;
  };
  syncBuiltinESMExports();
  try {
    const r = await walk(root);
    assert.ok(swapped);
    assert.deepEqual(r.files, []);
    assert.deepEqual(r.notAnalyzed, [{ path: "a", kind: "directory", reason: "symlink_outside_root", tracked: "not_checked" }]);
  } finally { fsp.readdir = real; syncBuiltinESMExports(); }
});

test("assertInside: a walked file passes; symlinks, outside paths and '..' are refused", async () => {
  const root = temp("custosa-a2-assert-");
  put(join(root, "src", "a.ts"), "x");
  symlinkSync("/etc/hosts", join(root, "src", "out.ts"));
  symlinkSync("a.ts", join(root, "src", "in.ts"));
  const ok = await assertInside(root, "src/a.ts");
  assert.equal(ok.abs, join(root, "src", "a.ts"));
  assert.equal(ok.size, 1);
  await assert.rejects(assertInside(root, "src/out.ts"), OutsideRootError);
  await assert.rejects(assertInside(root, "src/in.ts"), OutsideRootError);
  await assert.rejects(assertInside(root, "../etc/hosts"), OutsideRootError);
  await assert.rejects(assertInside(root, "/etc/hosts"), OutsideRootError);
  await assert.rejects(assertInside(root, "src"), OutsideRootError);
  const alias = join(temp("custosa-a2-assert-alias-"), "p");
  symlinkSync(root, alias);
  assert.equal((await assertInside(alias, "src/a.ts")).abs, join(root, "src", "a.ts"));
});

// Review 9 (P15, reviewer's p5): env names, and a .env folder is a venv.
// A .env folder is not in the contract's dependency lists (v1.1), so it is walked like any folder.
test("env files by name; a .env folder is walked like any folder", async () => {
  const root = temp("custosa-a2-env-");
  await initRepo(root, { ".env.example": "" });
  for (const n of [".env", ".envrc", ".environment.ts", ".envoy.yaml", "env.ts", ".env.local", "production.env"]) put(join(root, n));
  put(join(root, ".gitignore"), ".env.local\n");
  put(join(root, "py", ".env", "lib", "site.py"));
  const r = await walk(root);
  assert.deepEqual(r.envFiles, [
    { path: ".env", git: "untracked" }, { path: ".env.example", git: "tracked" }, { path: ".env.local", git: "ignored" },
    { path: "production.env", git: "untracked" },
  ]);
  assert.deepEqual(paths(r), [".environment.ts", ".envoy.yaml", ".envrc", ".gitignore", "env.ts", "py/.env/lib/site.py"]);
  assert.deepEqual(r.notAnalyzed, [{ path: ".git", kind: "directory", reason: "excluded_directory", tracked: "no" }]);
  for (const [n, want] of [[".env", true], [".ENV", true], [".env.prod", true], ["a.env", true], [".envrc", false], [".environment.ts", false], ["env", false]]) {
    assert.equal(isEnvFile(n), want, n);
  }
});

test("no git directory: no ignore rule applies, env files not_checked", async () => {
  const root = temp("custosa-a2-nogit-");
  put(join(root, ".gitignore"), "*.log\n"); put(join(root, "x.log")); put(join(root, ".env"));
  const r = await walk(root);
  assert.deepEqual(paths(r), [".gitignore", "x.log"]);
  assert.deepEqual(r.envFiles, [{ path: ".env", git: "not_checked" }]);
  assert.equal(r.status, "ok");
});

// Review 6 and 7: item limits truncate; empty only for a tree with no files.
test("item limits and the empty status", async () => {
  const root = temp("custosa-a2-items-");
  for (let i = 0; i < 12; i++) put(join(root, `f${i}.js`), "12345");
  for (let i = 0; i < 4; i++) put(join(root, `e${i}.env`));
  let r = await walk(root, { maxBytes: 1, notAnalyzedMax: 10, envFilesMax: 3 });
  assert.deepEqual([r.status, r.reason], ["truncated", "item_limit"]);
  assert.equal(r.notAnalyzed.length, 10);
  assert.equal(r.counts.notAnalyzedDropped, 2);
  assert.equal(r.envFiles.length, 3);
  assert.equal(r.counts.envFilesDropped, 1);

  const one = temp("custosa-a2-none-analysable-");
  put(join(one, "big.js"), "123");
  r = await walk(one, { maxBytes: 1 });
  assert.deepEqual([r.status, r.files.length, r.notAnalyzed.length], ["ok", 0, 1]);

  const empty = temp("custosa-a2-empty-");
  r = await walk(empty);
  assert.deepEqual([r.status, r.reason, r.count], ["empty", null, 0]);
  const gone = await walk(join(empty, "does-not-exist"));
  assert.deepEqual([gone.status, gone.reason], ["failed", "root_unreadable"]);
});

// Review focus 3 (P14).
test("truncation: file_limit entries, exact totals, the exact-fit case, and the counting ceiling", async () => {
  const root = temp("custosa-a2-trunc-");
  for (const s of ["a", "b", "c"]) for (let i = 0; i < 4; i++) put(join(root, s, `f${i}.js`));
  let r = await walk(root, { maxFiles: 5 });
  assert.deepEqual([r.status, r.reason, r.count], ["truncated", "file_limit", 5]);
  assert.deepEqual([r.counts.listed, r.counts.total, r.counts.totalExact, r.counts.limit], [5, 12, true, 5]);
  assert.equal(r.notAnalyzed.filter((n) => n.reason === "file_limit").length, 7);
  assert.deepEqual(paths(r), ["a/f0.js", "a/f1.js", "a/f2.js", "a/f3.js", "b/f0.js"]);
  r = await walk(root, { maxFiles: 4 });
  assert.deepEqual([r.status, r.counts.total], ["truncated", 12]);
  r = await walk(root, { maxFiles: 12 });
  assert.deepEqual([r.status, r.count, r.counts.total], ["ok", 12, 12]);

  const wide = temp("custosa-a2-wide-");
  for (let d = 0; d < 10; d++) for (let f = 0; f < 30; f++) put(join(wide, `d${d}`, `f${f}.ts`));
  r = await walk(wide, { maxFiles: 5 });
  assert.equal(r.status, "truncated");
  assert.equal(r.counts.totalExact, false);
  assert.ok(r.counts.total >= 50 && r.counts.total < 300, String(r.counts.total));
  const again = await walk(wide, { maxFiles: 5 });
  assert.deepEqual(again, r); // deterministic
});

test("odd names are returned with their real relative path, never dropped", async () => {
  const root = temp("custosa-a2-odd-");
  const long = "l".repeat(200);
  const names = ["has space.ts", "ünïcødé.py", "co:lon.js", "back\\slash.go", `${long}/${long}/${long}.ts`];
  for (const n of names) put(join(root, ...n.split("/")), "");
  const r = await walk(root);
  assert.equal(r.status, "ok");
  assert.deepEqual(paths(r), [...names].sort((a, b) => (a < b ? -1 : 1)));
  assertSafePaths(r);
});

test("a root given through a symlink is resolved first", async () => {
  const real = temp("custosa-a2-realroot-");
  put(join(real, "src", "a.ts"), "");
  symlinkSync("../src/a.ts", join(real, "src", "rel-in.ts"));
  const alias = join(temp("custosa-a2-alias-"), "proj");
  symlinkSync(real, alias);
  const r = await walk(alias);
  assert.deepEqual(paths(r), ["src/a.ts"]);
  assert.deepEqual(r.notAnalyzed, [{ path: "src/rel-in.ts", kind: "file", reason: "symlink", tracked: null }]);
});

// Review 10: the contract's exact path pattern.
// the inspector's one copy of the path rule is contracts.mjs PATH (checked against the shipped schema in
// inspector-catalog-v2.test.mjs); gitread's duplicate and its fitsSchemaPath wrapper, used only here, are gone.
test("contracts.mjs PATH is the fact schema's path rule", () => {
  // Copied from the evaluator's app/contracts/fact_document.schema.json
  // $defs.path.pattern, maxLength 512.
  const contract = "^(?!/)(?!.*//)(?!.*/$)(?!(?:.*/)?\\.\\.?(?:/|$))[A-Za-z0-9_.@+$\\[\\]()~/-]{1,512}$";
  assert.equal(PATH, contract);
  assert.equal(PATH_MAX, 512);
  const fits = (p) => typeof p === "string" && p.length <= PATH_MAX && new RegExp(PATH).test(p);
  const re = new RegExp(contract);
  const cases = ["src/my file.js", "café.ts", "a#b.js", "a,b.js", "x/{id}.ts", "a'b.js", "a=b.ts", "x/%20.js",
    "a!.js", "a&b.js", "a\\b.js", "a/b.ts", "app/[id]/page.tsx", "(group)/x.ts", "a/./b", "./a", "a//b", "a/", "..",
    "x".repeat(512), "x".repeat(513), "@scope/pkg+v~1.js"];
  for (const p of cases) assert.equal(fits(p), re.test(p) && p.length <= 512, p);
  assert.equal(fits("app/[id]/page.tsx"), true);
  assert.equal(fits("src/my file.js"), false);
  assert.equal(fits("x".repeat(512)), true);
  assert.equal(fits("x".repeat(513)), false);
});

test("languages and excluded directories", () => {
  const cases = {
    "a.ts": "typescript", "a.tsx": "tsx", "a.js": "javascript", "a.jsx": "javascript", "a.mjs": "javascript",
    "a.py": "python", "a.php": "php", "A.Java": "java", "a.kt": "kotlin", "a.go": "go", "a.rb": "ruby",
    "db/x.sql": "sql", "c.yml": "yaml", "c.yaml": "yaml", "p.json": "json", "README.md": null, "Makefile": null, ".ts": null,
  };
  for (const [p, lang] of Object.entries(cases)) assert.equal(languageOf(p), lang, p);
  for (const d of ["node_modules", "vendor", "dist", "build", "target", ".next", "__pycache__", ".venv"]) assert.ok(EXCLUDED_DIRS.has(d), d);
  // Together, exactly the contract's list (enums.DEPENDENCY_DIRECTORIES, contract v2.1).
  assert.deepEqual([...ALWAYS_EXCLUDED_DIRS].sort(), ["node_modules", "bower_components", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", ".gradle", ".terraform", ".turbo", ".dart_tool", "Pods"].sort());
  assert.deepEqual([...BUILD_DIRS].sort(), [".yarn", ".pnpm-store", ".cache", "vendor", "dist", "build", "target", "coverage", ".next",
    ".nuxt", ".svelte-kit", ".output", "out"].sort());
  assert.deepEqual([...EXCLUDED_DIRS].sort(), [".git", ".hg", ".svn", "node_modules", "bower_components", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", ".gradle", ".terraform", ".turbo", ".dart_tool", "Pods", ".yarn", ".pnpm-store", ".cache",
    "vendor", "dist", "build", "target", "coverage", ".next", ".nuxt", ".svelte-kit", ".output", "out"].sort());
  for (const p of ["a", "a/b.ts", ".env", "a..b/c", "a b/c:d.ts", "x".repeat(600)]) assert.equal(isRelPath(p), true, p);
  for (const p of ["", "/a", "./a", "a/../b", "..", "a//b", "a/", "a\0b"]) assert.equal(isRelPath(p), false, p);
});

/* About three minutes on a slow disk (creating and deleting 100k files dominates; the walk itself took about 8 s),
 * so it runs only with CUSTOSA_TEST_100K=1; the truncation tests above cover the same code on every run. */
test("truncation: a real 100k-file tree with the default limit", { timeout: 600_000, skip: process.env.CUSTOSA_TEST_100K !== "1" }, async () => {
  const root = temp("custosa-a2-100k-");
  for (let d = 0; d < 201; d++) {
    const dir = join(root, `pkg${String(d).padStart(3, "0")}`);
    mkdirSync(dir);
    for (let f = 0; f < 500; f++) writeFileSync(join(dir, `m${f}.js`), "");
  }
  const r = await walk(root);
  assert.deepEqual([r.status, r.reason, r.count, r.counts.total, r.counts.totalExact], ["truncated", "file_limit", 100_000, 100_500, true]);
  assert.equal(r.notAnalyzed.length, 500);
  fs.rmSync(root, { recursive: true, force: true });
});

test("the inspector modules import no child_process", () => {
  for (const f of ["files.mjs", "gitread.mjs"]) {
    const src = readFileSync(new URL(`../lib/inspector/${f}`, import.meta.url), "utf8");
    assert.ok(!/child_process|\bexecSync\b|\bspawn\b/.test(src), f);
  }
});

/* ---- Second review findings ------------------------------------------------------------------------------------ */

// Finding 1: a symlinked .gitignore (or info/exclude) pointing at a .env file made the walker read the .env as ignore
// rules. Ignore files are now read only with no symlink at any step; the symlink is reported, its rules not applied.
test("a symlinked .gitignore or info/exclude is never read, so it can't expose a .env file", async () => {
  const root = temp("custosa-a2-ignore-link-");
  await initRepo(root, { "keep.ts": "" });
  // If this .env were read as ignore rules, src/, secret.ts, pkg/ and lib/ would vanish from the walk.
  put(join(root, ".env"), "src/\nsecret.ts\npkg/\nlib/\n");
  put(join(root, "src", "app.ts")); put(join(root, "secret.ts")); put(join(root, "pkg", "x.ts")); put(join(root, "lib", "y.ts"));
  symlinkSync(".env", join(root, ".gitignore"));
  symlinkSync("../.env", join(root, "pkg", ".gitignore"));
  const out = temp("custosa-a2-ignore-link-out-");
  put(join(out, ".env"), "*\n");
  symlinkSync(join(out, ".env"), join(root, "lib", ".gitignore"));
  mkdirSync(join(root, ".git", "info"), { recursive: true });
  try { fs.rmSync(join(root, ".git", "info", "exclude")); } catch { /* none */ }
  symlinkSync("../../.env", join(root, ".git", "info", "exclude"));

  const { result: r, opened } = await recordOpens(() => walk(root));
  assertSafeOpens(root, opened);
  assert.deepEqual(paths(r), ["keep.ts", "lib/y.ts", "pkg/x.ts", "secret.ts", "src/app.ts"]);
  assert.deepEqual(r.notAnalyzed, [
    { path: ".git", kind: "directory", reason: "excluded_directory", tracked: "no" },
    { path: ".gitignore", kind: "file", reason: "symlink", tracked: null },
    { path: "lib/.gitignore", kind: "file", reason: "symlink_outside_root", tracked: null },
    { path: "pkg/.gitignore", kind: "file", reason: "symlink", tracked: null },
  ]);
  assert.deepEqual(r.envFiles, [{ path: ".env", git: "untracked" }]);
  assert.equal(r.status, "ok");
  const { result: ign, opened: opened2 } = await recordOpens(() => isIgnored(root, "src/app.ts"));
  assert.equal(ign, false);
  assertSafeOpens(root, opened2);
});

// Finding 2: a split index (core.splitIndex) keeps most entries in sharedindex.<id>; reading only the index file lost
// them, so a tracked file in an ignored folder vanished. Both are read now (version 2 and version 4).
test("a split index: tracked files in the shared index are kept, deletions and replacements applied", async () => {
  for (const version of [2, 4]) {
    const root = temp(`custosa-a2-split-v${version}-`);
    await initRepo(root, {});
    for (const p of ["a.ts", "c.ts", "gen/b.ts", "gen/untracked.ts", "d.ts", "e.ts"]) put(join(root, p));
    put(join(root, ".gitignore"), "gen/\n");
    const gitdir = join(root, ".git");
    // Shared: .gitignore, a.ts, c.ts, e.ts, gen/b.ts. c.ts deleted, e.ts replaced (still tracked), d.ts added.
    writeSplitIndex(gitdir, { shared: [[".gitignore"], ["a.ts"], ["c.ts"], ["e.ts"], ["gen/b.ts"]], deleted: [2], replaced: [3], added: ["d.ts"], version });
    const t = await readTracked(root);
    assert.deepEqual([t.status, t.known], ["ok", true], `v${version}`);
    assert.deepEqual([...t.paths].sort(), [".gitignore", "a.ts", "d.ts", "e.ts", "gen/b.ts"]);
    const r = await walk(root);
    assert.deepEqual([r.status, r.git.status], ["ok", "ok"]);
    assert.deepEqual(paths(r), [".gitignore", "a.ts", "c.ts", "d.ts", "e.ts", "gen/b.ts"]);
    assert.equal(r.counts.ignored, 1); // gen/untracked.ts: untracked and ignored

    // The shared index missing: the tracked set is unknown, never just the split part; nothing ignored is dropped.
    for (const f of fs.readdirSync(gitdir)) if (f.startsWith("sharedindex.")) fs.rmSync(join(gitdir, f));
    const m = await walk(root);
    assert.deepEqual([m.git.status, m.git.reason, m.status, m.reason], ["failed", "shared_index_missing", "truncated", "tracked_set_unknown"]);
    assert.deepEqual(m.notAnalyzed, [{ path: ".git", kind: "directory", reason: "excluded_directory", tracked: "not_checked" }, { path: "gen", kind: "directory", reason: "ignored_unverified", tracked: "not_checked" }]);
  }
});

// Finding 3: a submodule's files were walked with the parent's tracked set, so its own tracked-but-ignored files
// vanished. A folder that is another repository's working tree is now reported whole, kind directory.
// Fix round 1 (product decision): each nested repository is walked as a root of its own, with its own index.
test("submodules and nested repositories are walked as roots of their own, never silently thinned", async () => {
  const root = temp("custosa-a2-submodule-");
  await initRepo(root, {});
  put(join(root, "app.ts")); put(join(root, ".gitignore"), "*.log\next/\n");
  // A submodule inside an ignored folder: still tracked, so still reported.
  put(join(root, "ext", "mod", ".git"), "gitdir: ../../.git/modules/ext/mod\n"); put(join(root, "ext", "mod", "m.ts"));
  // An initialised submodule: gitlink in the index, .git file pointing into .git/modules, its own .gitignore.
  put(join(root, ".git", "modules", "libs", "sub", "HEAD"), "ref: refs/heads/main\n");
  mkdirSync(join(root, ".git", "modules", "libs", "sub", "objects")); mkdirSync(join(root, ".git", "modules", "libs", "sub", "refs"));
  put(join(root, "libs", "sub", ".git"), "gitdir: ../../.git/modules/libs/sub\n");
  put(join(root, "libs", "sub", ".gitignore"), "gen/\n");
  put(join(root, "libs", "sub", "gen", "api.ts")); put(join(root, "libs", "sub", "main.ts")); put(join(root, "libs", "sub", "gen", "scratch.ts"));
  // The submodule's own index tracks gen/api.ts although its own .gitignore ignores gen/.
  writeFileSync(join(root, ".git", "modules", "libs", "sub", "index"), handIndex([[".gitignore"], ["gen/api.ts"], ["main.ts"]]));
  // An uninitialised submodule folder that still holds a file.
  put(join(root, "libs", "uninit", "stray.ts"));
  // A nested clone (a real .git directory) and a nested gitlink naming a source folder inside the root.
  await initRepo(join(root, "tools", "clone"), { "tool.py": "" });
  put(join(root, "tools", "clone", ".gitignore"), "out/\n"); put(join(root, "tools", "clone", "out", "x.py"));
  put(join(root, "src", "real.ts"));
  put(join(root, "other", ".git"), "gitdir: ../src\n"); put(join(root, "other", "o.ts"));
  writeFileSync(join(root, ".git", "index"), handIndex([[".gitignore"], ["app.ts"], ["ext/mod", 0o160000], ["libs/sub", 0o160000], ["libs/uninit", 0o160000]]));

  const t = await readTracked(root);
  assert.deepEqual([...t.gitlinks].sort(), ["ext/mod", "libs/sub", "libs/uninit"]);
  const r = await walk(root);
  assert.equal(r.status, "ok");
  assert.deepEqual(paths(r), [".gitignore", "app.ts", "src/real.ts"]);
  assert.deepEqual(r.notAnalyzed.map((n) => [n.path, n.reason, n.tracked]), [
    [".git", "excluded_directory", "no"], ["ext/mod", "submodule", "yes"], ["libs/sub", "submodule", "yes"], ["libs/uninit", "submodule", "yes"],
    ["other", "gitlink_into_source", "no"], ["tools/clone", "embedded_git_dir", "no"],
  ]);
  assert.deepEqual(r.nestedRoots.map((n) => [n.path, n.reason]), [
    ["ext/mod", "submodule"], ["libs/sub", "submodule"], ["libs/uninit", "submodule"],
    ["other", "gitlink_into_source"], ["tools/clone", "embedded_git_dir"],
  ]);
  const all = await walkAll(root);
  const byRel = Object.fromEntries(all.roots.map((x) => [x.rel, x.result]));
  assert.deepEqual(Object.keys(byRel), ["", "ext/mod", "libs/sub", "libs/uninit", "other", "tools/clone"]);
  // The submodule is read with its own index, from the top root's .git/modules: its tracked gen/api.ts is kept,
  // its untracked gen/scratch.ts is ignored by its own rules.
  assert.deepEqual([byRel["libs/sub"].git.layout, byRel["libs/sub"].git.status], ["gitlink", "ok"]);
  assert.deepEqual(paths(byRel["libs/sub"]), [".gitignore", "gen/api.ts", "main.ts"]);
  assert.equal(byRel["libs/sub"].counts.ignored, 1);
  assert.deepEqual(paths(byRel["libs/uninit"]), ["stray.ts"]);
  assert.deepEqual(paths(byRel["ext/mod"]), ["m.ts"]);
  assert.deepEqual([byRel.other.git.reason, paths(byRel.other)], ["gitlink_into_source", ["o.ts"]]);
  assert.deepEqual([byRel["tools/clone"].git.status, paths(byRel["tools/clone"])], ["ok", [".gitignore", "tool.py"]]);
  for (const x of all.roots.slice(1)) assert.ok(x.abs.startsWith(`${root}/`), x.abs);
});

// Finding 4: on a case-insensitive disk the index can spell a path in another case than the disk (a case-only
// rename); exact matching made a tracked file look untracked, and an ignore rule then dropped it. On a case-sensitive
// disk, ignore patterns must not fold case (they always did, so `Secret.ts` hid `secret.ts`).
test("case folding follows the disk: index and ignore matching", async () => {
  const root = temp("custosa-a2-case-fold-");
  await initRepo(root, {});
  put(join(root, ".gitignore"), "gen/\napp.ts\nSecret.ts\n");
  put(join(root, "gen", "api.ts")); put(join(root, "src", "app.ts")); put(join(root, "src", "other.ts")); put(join(root, "secret.ts"));
  writeFileSync(join(root, ".git", "index"), handIndex([[".gitignore"], ["Gen/API.ts"], ["src/App.ts"]]));

  const insensitive = await walk(root, { caseInsensitive: true });
  // gen/api.ts and src/app.ts are the tracked Gen/API.ts and src/App.ts. secret.ts matches Secret.ts only when case
  // folds; a repository with core.ignorecase=false on this disk would show it, so it is reported, not skipped (I-4).
  assert.deepEqual(paths(insensitive), [".gitignore", "gen/api.ts", "src/app.ts", "src/other.ts"]);
  assert.deepEqual(insensitive.notAnalyzed, [{ path: ".git", kind: "directory", reason: "excluded_directory", tracked: "no" }, { path: "secret.ts", kind: "file", reason: "ignored_unverified", tracked: null }]);
  assert.deepEqual([insensitive.status, insensitive.reason], ["truncated", "ignore_unverified"]);
  assert.equal(insensitive.counts.ignored, 1);

  const sensitive = await walk(root, { caseInsensitive: false });
  // Different files on a case-sensitive disk: gen/ and src/app.ts are untracked and ignored; secret.ts is not ignored.
  assert.deepEqual(paths(sensitive), [".gitignore", "secret.ts", "src/other.ts"]);
  assert.equal(sensitive.counts.ignored, 2);

  // Left to itself the walker probes the disk.
  const probed = await walk(root);
  const diskFolds = existsSync(join(root, "GEN"));
  assert.deepEqual(paths(probed), paths(diskFolds ? insensitive : sensitive));
});

test("index formats: version 4 names, SHA-1 trailer checked, a zero trailer accepted, sparse index refused", async () => {
  const root = temp("custosa-a2-index-formats-");
  await initRepo(root, {});
  const names = ["src/a/one.ts", "src/a/two.ts", "src/b.ts", "zz.ts"];
  writeFileSync(join(root, ".git", "index"), buildIndex(names.map((n) => [n]), { version: 4 }));
  assert.deepEqual([...((await readTracked(root)).paths)].sort(), names);
  const zero = buildIndex(names.map((n) => [n])); zero.fill(0, zero.length - 20);
  writeFileSync(join(root, ".git", "index"), zero);
  assert.deepEqual([...((await readTracked(root)).paths)].sort(), names);
  const bad = buildIndex(names.map((n) => [n])); bad[bad.length - 1] ^= 1;
  writeFileSync(join(root, ".git", "index"), bad);
  assert.deepEqual([(await readTracked(root)).status, (await readTracked(root)).known], ["failed", false]);
  writeFileSync(join(root, ".git", "index"), buildIndex([["src/"], ["zz.ts"]].map(([n], i) => [n, i ? 0o100644 : 0o040000]), { extensions: [["sdir", Buffer.alloc(0)]] }));
  assert.deepEqual([(await readTracked(root)).reason], ["sparse_index"]);
});

/* ---- The whole picture ----------------------------------------------------------------------------------------- */

/* Every non-directory entry on disk under root (files, symlinks, FIFOs), never following a symlink, leaving out the
 * root's own .git directory. */
function diskEntries(root, roots = [""]) {
  const out = [];
  const own = new Set(roots.map((r) => (r ? `${r}/.git` : ".git"))); // each root's own .git, described by its git field
  const visit = (rel) => {
    for (const d of fs.readdirSync(join(root, rel), { withFileTypes: true })) {
      const p = rel ? `${rel}/${d.name}` : d.name;
      if (own.has(p.normalize("NFC"))) continue;
      if (d.isDirectory()) visit(p); else out.push(p.normalize("NFC"));
    }
  };
  visit("");
  return out.sort();
}

/* The entries of `disk` the walk accounts for nowhere: not in files or envFiles, not in notAnalyzed, and not under a
 * notAnalyzed folder. */
function unaccounted(r, disk) {
  const listed = new Set([...paths(r), ...r.envFiles.map((e) => e.path), ...r.notAnalyzed.map((n) => n.path)]);
  const folders = r.notAnalyzed.filter((n) => n.kind === "directory").map((n) => `${n.path}/`);
  return disk.filter((p) => !listed.has(p) && !folders.some((f) => p.startsWith(f)));
}

/* The same across every root of a walkAll: each root's paths are relative to it. A parent's entry for a nested root
 * that was walked doesn't count as covering it: that root's own result must. */
function unaccountedAll(all, disk) {
  const listed = new Set(), folders = [];
  const walked = new Set(all.roots.map((x) => x.rel));
  for (const { rel, result: r } of all.roots) {
    const pre = rel ? `${rel}/` : "";
    const entries = r.notAnalyzed.filter((n) => !(n.kind === "directory" && walked.has(pre + n.path)));
    for (const p of [...paths(r), ...r.envFiles.map((e) => e.path), ...entries.map((n) => n.path)]) listed.add(pre + p);
    for (const n of entries) if (n.kind === "directory") folders.push(`${pre}${n.path}/`);
  }
  return disk.filter((p) => !listed.has(p) && !folders.some((f) => p.startsWith(f)));
}

const REASONS = new Set(["too_large", "unreadable", "symlink_outside_root", "file_limit", "excluded_directory",
  "embedded_git_dir", "symlink", "symlink_broken", "not_regular_file", "gitlink_into_source", "ignored_unverified",
  "ignore_file_unreadable", "submodule", "gitlink_to_ancestor"]);

test("hostile repository, whole picture: every file is analysed or listed (or truncated), nothing outside or behind a symlink read", async () => {
  const outside = temp("custosa-a2-final-out-");
  const { marker, script } = markerScript(outside);
  put(join(outside, ".env"), "OUTSIDE_SECRET=1\n");
  put(join(outside, "secret.ts"), "export const s = 1;\n");
  const root = temp("custosa-a2-final-");
  await initRepo(root, {});
  const gitdir = join(root, ".git");
  writeFileSync(join(gitdir, "config"), hostileConfig(script));
  plantHooks(gitdir, script);

  const nfd = "café".normalize("NFD");
  const long = "l".repeat(200);
  const tree = {
    ".gitattributes": "* filter=evil diff=evil\n",
    "src/app.ts": "export const a = 1;\n", "src/view.tsx": "", "src/new.py": "",
    "generated/bundle.js": "", "generated/other.js": "", "tmp/scratch.ts": "", "debug.log": "",
    "Gen/api.ts": "", // the index says GEN/API.ts (a case-only rename)
    "big.json": "x".repeat(5000),
    ".env": "src/\ngenerated/\n", "config/.env.production": "K=1\n",
    "node_modules/pkg/index.js": "", "vendor/tracked.js": "", "vendor/untracked.js": "",
    "has space.ts": "", [`${nfd}.py`]: "", "co:lon.js": "", [`deep/${long}/${long}.ts`]: "",
    "libs/sub/.git": "gitdir: ../../.git/modules/libs/sub\n", "libs/sub/.gitignore": "gen/\n", "libs/sub/gen/api.ts": "", "libs/sub/main.ts": "",
    "libs/uninit/stray.ts": "",
    "other/.git": "gitdir: ../src\n", "other/o.ts": "",
    "pkg/x.ts": "",
  };
  for (const [p, text] of Object.entries(tree)) put(join(root, ...p.split("/")), text);
  put(join(root, ".gitignore"), "generated/\ntmp/\n*.log\n.env\ngen/\n");
  put(join(gitdir, "modules", "libs", "sub", "HEAD"), "ref: refs/heads/main\n");
  mkdirSync(join(gitdir, "modules", "libs", "sub", "objects")); mkdirSync(join(gitdir, "modules", "libs", "sub", "refs"));
  await initRepo(join(root, "tools", "clone"), { "tool.py": "" });
  // A nested pure bare repository with its own hostile config.
  const bare = join(root, "sub-bare");
  put(join(bare, "HEAD"), "ref: refs/heads/main\n"); mkdirSync(join(bare, "objects")); mkdirSync(join(bare, "refs"));
  writeFileSync(join(bare, "config"), `[core]\n\tbare = true\n${hostileConfig(script)}`);
  // Symlinks: out, up, in, broken, to /etc, a folder link, an ignore file pointing at the .env, info/exclude too.
  symlinkSync("/etc", join(root, "link-etc"));
  symlinkSync(join(outside, "secret.ts"), join(root, "src", "link-out.ts"));
  symlinkSync("../../../../../../../../etc/passwd", join(root, "src", "link-up.ts"));
  symlinkSync("app.ts", join(root, "src", "link-in.ts"));
  symlinkSync(join(root, "nope"), join(root, "src", "link-broken.ts"));
  symlinkSync("src", join(root, "link-src-dir"));
  symlinkSync("../.env", join(root, "pkg", ".gitignore"));
  symlinkSync(join(outside, ".env"), join(root, "src", ".gitignore"));
  mkdirSync(join(gitdir, "info"), { recursive: true });
  try { fs.rmSync(join(gitdir, "info", "exclude")); } catch { /* none */ }
  symlinkSync("../../.env", join(gitdir, "info", "exclude"));
  // A FIFO: listed, never opened (opening one would block).
  cp.execFileSync("mkfifo", [join(root, "src", "pipe.ts")]);
  spawned.length = 0;
  // The index: a split index whose shared part holds most entries, with gitlinks for the submodules.
  writeSplitIndex(gitdir, {
    shared: [[".gitattributes"], [".gitignore"], ["GEN/API.ts"], ["generated/bundle.js"], ["libs/sub", 0o160000],
      ["libs/uninit", 0o160000], ["src/app.ts"], ["src/gone.ts"], ["vendor/tracked.js"]],
    deleted: [7], replaced: [6], version: 4,
  });
  writeFileSync(join(gitdir, "modules", "libs", "sub", "index"), handIndex([[".gitignore"], ["gen/api.ts"], ["main.ts"]]));

  const { result: all, opened } = await recordOpens(() => walkAll(root, { maxBytes: 1000 }));
  const r = all.roots[0].result;
  assert.equal(existsSync(marker), false, "the marker script ran");
  assert.deepEqual(spawned, [], "a child process was started");
  assertSafeOpens(root, opened);
  assert.deepEqual(all.roots.map((x) => x.rel), ["", "libs/sub", "libs/uninit", "other", "tools/clone"]);
  for (const { rel, result: x } of all.roots) {
    assertSafePaths(x);
    assert.deepEqual([x.status, x.reason], ["ok", null], `root ${rel}`); // nothing may hide behind truncation here
    for (const n of x.notAnalyzed) {
      assert.ok(REASONS.has(n.reason), n.reason);
      assert.ok(n.kind === "file" || n.kind === "directory", n.kind);
    }
  }
  assert.deepEqual([r.git.status, r.git.known], ["ok", true]);
  const folds = await isCaseInsensitive(root);
  // Untracked and ignored files are skipped by design; exactly these, and each really is ignored and untracked.
  // Gen/api.ts is not among them on either disk (git agrees): on a case-insensitive one it is the tracked GEN/API.ts;
  // on a case-sensitive one it is untracked, and "gen/" doesn't match "Gen" with core.ignorecase off (its default
  // there), so git shows it and the walk lists it.
  const expectedIgnored = ["debug.log", "generated/other.js", "tmp/scratch.ts"];
  const tracked = (await readTracked(root)).paths;
  for (const p of expectedIgnored) {
    assert.equal(await isIgnored(root, p), true, p);
    assert.ok(!tracked.has(p), p);
  }
  const disk = diskEntries(root, all.roots.map((x) => x.rel));
  assert.deepEqual(unaccountedAll(all, disk), expectedIgnored.sort());
  assert.equal(r.counts.ignored, expectedIgnored.length);
  // Spot checks across the findings.
  const na = Object.fromEntries(r.notAnalyzed.map((n) => [n.path, `${n.kind}:${n.reason}`]));
  assert.deepEqual(r.nestedRoots.map((n) => `${n.path}:${n.reason}`), [
    "libs/sub:submodule", "libs/uninit:submodule", "other:gitlink_into_source", "tools/clone:embedded_git_dir",
  ]);
  assert.deepEqual(paths(all.roots[1].result), [".gitignore", "gen/api.ts", "main.ts"]); // the submodule's own index
  assert.equal(na["sub-bare"], "directory:embedded_git_dir");
  assert.equal(na["pkg/.gitignore"], "file:symlink");
  assert.equal(na["src/.gitignore"], "file:symlink_outside_root");
  assert.equal(na["link-src-dir"], "directory:symlink");
  assert.equal(na["src/pipe.ts"], "file:not_regular_file");
  assert.equal(na["node_modules"], "directory:excluded_directory");
  assert.ok(paths(r).includes("vendor/tracked.js") && paths(r).includes("vendor/untracked.js")); // a tracked vendor folder is source
  assert.equal(na["big.json"], "file:too_large");
  assert.ok(paths(r).includes("generated/bundle.js")); // tracked in the shared index, inside an ignored folder
  assert.ok(paths(r).includes("src/app.ts")); // a replaced shared entry; src/ named in the .env, which is never read
  assert.ok(paths(r).includes("Gen/api.ts")); // the case-renamed tracked file (or, case-sensitive, an untracked one)
  assert.equal(await isIgnored(root, "Gen/api.ts"), false);
  if (!folds) assert.ok(!tracked.has("Gen/api.ts"));
  assert.deepEqual(r.envFiles, [{ path: ".env", git: "ignored" }, { path: "config/.env.production", git: "untracked" }]);

  // The same tree with an unreadable index: nothing is skipped as ignored any more; every file is accounted for.
  writeFileSync(join(gitdir, "index"), Buffer.from("DIRC broken"));
  const ua = await walkAll(root, { maxBytes: 1000 });
  const u = ua.roots[0].result;
  assert.deepEqual([u.git.known, u.status, u.reason], [false, "truncated", "tracked_set_unknown"]);
  assert.deepEqual(unaccountedAll(ua, diskEntries(root, ua.roots.map((x) => x.rel))), []);
  assert.ok(u.envFiles.every((e) => e.git === "not_checked"));

  // Tight limits: whatever doesn't fit makes the walk truncated, never silently short.
  const t = await walk(root, { maxBytes: 1000, maxFiles: 3, notAnalyzedMax: 4, envFilesMax: 1 });
  assert.equal(t.status, "truncated");
  assert.ok(t.drops.includes("file_limit") && t.drops.includes("item_limit"), t.drops.join());
  assert.equal(existsSync(marker), false);
  assert.deepEqual(spawned, []);
});


/* ---- Fix round 1 ----------------------------------------------------------------------------------------------- */

// C-1: the ignore rules are git's own. A standing differential test against real git: for every pattern set, with
// core.ignorecase on and off, on whatever disk the test runs on (case-insensitive on macOS, case-sensitive on Linux),
// the files git shows (`git ls-files -o --exclude-standard`) are all accounted for by the walk, isIgnored never says
// ignored for one of them, and told core.ignorecase the answers are exactly git's. The test runs
// git (in throwaway repositories with no global or system config); the product never does. The pattern sets and file
// names start from the reviewer's reproduction (difftest/diff.mjs) and add git's other corners.
const DIFF_FILES = ["a.log","b.txt","keep.log","dir/a.log","dir/keep.log","dir/b.txt","dir/sub/a.log","dir/sub/deep/x.txt",
 "foo","foo2/foo","bar/foo/baz.txt","docs/foo","Foo.TXT","foo.txt","FOO2/x","sp ace.txt","trail.txt","#hash","!bang",
 "x[1].txt","x1.txt","a*b","a?b","axb","back\\slash","a/b/c/d/e.txt","a/e.txt","abc/def/ghi.txt","abc/ghi.txt","x/node/y.js",
 "deep/a/b/foo/c.txt","logs/today/a.log","logs/keep/b.log","doc/frotz/x","a/doc/frotz/y",".hidden","dir/.hidden",
 "caf\u00e9.txt","z.log","ab.log","Dir2/A.LOG","dir2/x","a.log.bak","foo.log/inner","sub/x.txt","q/sub/x.txt","t\tab.txt",
 "e.TXT","A.log","dir/sub/keep.log","x/y/z/w.md","m/n/o.md"];
const DIFF_SETS = [
 {r:"*.log\n!keep.log"},
 {r:"dir/\n!dir/keep.log"},
 {r:"dir/*\n!dir/sub/"},
 {r:"/foo"},{r:"foo/"},{r:"**/foo"},{r:"foo/**"},{r:"**/foo/**"},
 {r:"a/**/e.txt"},{r:"abc/**/ghi.txt"},
 {r:"\\#hash\n\\!bang"},{r:"#hash\n!bang"},
 {r:"trail.txt   "},{r:"trail.txt\\ "},{r:"trail.txt\t"},
 {r:"x[1].txt"},{r:"x\\[1\\].txt"},{r:"a\\*b"},{r:"a\\?b"},{r:"a?b"},
 {r:"*.TXT"},{r:"*.txt"},{r:"FOO.txt"},
 {r:"doc/frotz/"},{r:"doc/frotz"},
 {r:"logs/\n!logs/keep/"},{r:"logs/**\n!logs/keep/"},{r:"logs/**\n!logs/keep/\n!logs/keep/**"},{r:"logs/*\n!logs/keep"},
 {r:"*.txt", g:{"dir/.gitignore":"!*.txt"}},
 {r:"", g:{"dir/.gitignore":"/sub"}},
 {r:"", g:{"dir/.gitignore":"sub/deep/"}},
 {r:"!b.txt", x:"*.txt"},
 {r:"[!a]*.txt"},{r:"[^a]*.txt"},
 {r:"*\n!*/\n!*.txt"},
 {r:"/*\n!/dir"},
 {r:"#comment\n\n   \n*.log # comment"},
 {r:"a/b/"},{r:"a/b"},{r:"*/"},{r:"dir/**/"},{r:" foo"},{r:"foo\\"},
 {r:"**/sub/**/x.txt"},{r:"deep/**/c.txt"},{r:"?.log"},{r:"a.log/"},{r:"[a-c]*.log"},{r:"[z-a]*.log"},
 {r:"**foo"},{r:"foo**"},{r:"*.log\r\n!keep.log\r\n"},
 {r:"dir/", g:{"dir/.gitignore":"!keep.log"}},
 {r:"dir\n!dir/keep.log"},
 {r:"*\n!dir/\n!dir/**"},
 {r:"dir2/"},{r:"Dir2/"},{r:"*.LOG"},
 {r:"sub/"},{r:"/sub/"},{r:"sub/x.txt"},
 {r:"", g:{"q/.gitignore":"sub"}},
 {r:"", g:{"a/.gitignore":"doc/frotz"}},
 {r:"", g:{"a/.gitignore":"/b/c"}},
 {r:"", g:{"a/b/.gitignore":"*\n!c/"}},
 {r:"a/*/\n"},{r:"a/*/c"},{r:"x/**/w.md"},{r:"**/*.md\n!m/**"},{r:"m/\n!m/n/o.md"},{r:"!*.log\n*.log"},
 {r:"*.log\n!/dir/*.log"},{r:"*.log\n!dir/*.log"},{r:"[[:alpha:]].log"},{r:"[[:digit:]]*"},{r:"\\a.log"},
 {r:"*.log", g:{"dir/.gitignore":"!sub/a.log"}},{r:"dir/sub", g:{"dir/.gitignore":"!sub"}},
 {r:"**/"},{r:"**"},{r:"/**/a.log"},{r:"a/**"},{r:"a/**/"},{r:"***.log"},{r:"dir/***"},{r:"*.log/"},
 {r:"caf\u0065\u0301.txt"},{r:"caf\u00e9.txt"},{r:"\\!bang\n!\\!bang"},{r:"a.log\\\\"},{r:"[\\]].log"},{r:"x[!]].txt"},
 {r:"t?ab.txt"},{r:"t\\tab.txt"},
 // More of git's corners: a prefix that ends right before "**", escapes, odd brackets, trailing spaces, comments.
 {r:"foo**/baz.txt"},{r:"bar/foo**"},{r:"a/**/b/"},{r:"a/b**/e.txt"},{r:"trail.txt\\\\ "},{r:"*.[ch]"},{r:"x[]1].txt"},
 {r:"x["},{r:"[a-]*.log"},{r:"[!]a]*.log"},{r:"\\ foo"},{r:"sp\\ ace.txt"},{r:"sp ace.txt  "},{r:"  # not a comment"},
 {r:"*.log\n!dir/**/keep.log"},{r:"/dir/sub/\n!/dir/sub/keep.log"},{r:"[[:upper:]]*"},{r:"[[:space:]]*"},{r:"[[:bogus:]]*"},
 {r:"\ufeff*.log"},{r:"a.log\u0000junk"},
 // Patterns git 2.52 reads differently from older git ("prefix**"), negated so a difference would hide a file git shows.
 {r:"*.txt\n!a/b**/e.txt"},{r:"*.TXT\n!abc**/*.txt"},{r:"*\n!*/\n!/foo**"},{r:"*\n!*/\n!foo**/**"},{r:"*.log\n!dir**/*.log"},
];

function gitAvailable() {
  try { cp.execFileSync("git", ["--version"], { stdio: "ignore" }); return true; } catch { return false; }
}

const HAS_GIT = gitAvailable();
/* The installed git's [major, minor], or null: the exactness check tells ignoreContext which git's "prefix**"
 * semantics to use (2.52 changed them); the product doesn't know and checks both. */
function gitVersion() {
  try {
    const m = /(\d+)\.(\d+)/.exec(cp.execFileSync("git", ["--version"], { encoding: "utf8" }));
    return m ? [Number(m[1]), Number(m[2])] : null;
  } catch { return null; }
}
const GIT_VERSION = HAS_GIT ? gitVersion() : null;
spawned.length = 0; // that probe ran at load time; the tests that check for spawned processes run later

test("ignore rules: differential test against git ls-files -o --exclude-standard", { skip: !HAS_GIT, timeout: 600_000 }, async () => {
  const env = { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1", HOME: tmpdir() };
  const runGit = (cwd, ...args) => cp.execFileSync("git", args, { cwd, env, encoding: "utf8" });
  const ls = (root, ...extra) => new Set(runGit(root, "ls-files", "-z", ...extra).split("\0").filter(Boolean).map((p) => p.normalize("NFC")));
  const problems = [];
  for (const ignorecase of [true, false]) {
    for (let n = 0; n < DIFF_SETS.length; n++) {
      const set = DIFF_SETS[n];
      const root = temp(`custosa-a2-diff-${ignorecase ? "ci" : "cs"}${n}-`);
      runGit(root, "init", "-q");
      runGit(root, "config", "core.ignorecase", String(ignorecase));
      for (const f of DIFF_FILES) put(join(root, ...f.split("/")), "x");
      if (set.r) put(join(root, ".gitignore"), set.r);
      for (const [k, v] of Object.entries(set.g ?? {})) put(join(root, ...k.split("/")), v);
      writeFileSync(join(root, ".git", "info", "exclude"), set.x ?? "");
      runGit(root, "add", "-f", "--", "dir/a.log", "logs/today/a.log"); // tracked though maybe ignored: always kept
      const shown = ls(root, "-o", "--exclude-standard");
      const ignored = ls(root, "-o", "-i", "--exclude-standard");
      const tracked = ls(root);
      const disk = diskEntries(root);
      const label = `${ignorecase ? "ci" : "cs"} #${n} ${JSON.stringify(set)}`;
      // The walk, on this disk as it is: every file git shows or tracks is accounted for.
      const w = await walk(root);
      const miss = unaccounted(w, disk).filter((p) => shown.has(p) || tracked.has(p));
      if (miss.length) problems.push(`${label}: walk dropped ${JSON.stringify(miss)}`);
      // isIgnored never calls a shown file ignored.
      const ctx = await ignoreContext(root);
      for (const f of disk) {
        if (shown.has(f) && (await isIgnored(root, f, ctx))) problems.push(`${label}: isIgnored(${JSON.stringify(f)}) but git shows it`);
      }
      // Told core.ignorecase and the git version, exactly git's answers (the port is exact, not just safe).
      if (GIT_VERSION) {
        const exact = await ignoreContext(root, null, { ignoreCase: ignorecase, gitVersion: GIT_VERSION });
        for (const f of disk) {
          if (!shown.has(f) && !ignored.has(f)) continue; // tracked
          if ((await isIgnored(root, f, exact)) !== ignored.has(f)) problems.push(`${label}: isIgnored(${JSON.stringify(f)}) differs from git`);
        }
      }
    }
  }
  spawned.length = 0;
  assert.deepEqual(problems, []);
});

// C-2: a `.git`-named folder that holds source is walked without the ignore check (git never looks inside one, so
// its rules say nothing), never skipped as ignored.
test("a .git folder holding source: listed as embedded_git_dir, never walked", async () => {
  const root = temp("custosa-a2-dotgit-src-");
  await initRepo(root, { "app.js": "" });
  put(join(root, ".git", "info", "exclude"), "# git ls-files --others --exclude-from=.git/info/exclude\n");
  put(join(root, ".gitignore"), "*.log\n");
  put(join(root, "fixtures", ".git", "config")); put(join(root, "fixtures", ".git", "handler.js"));
  put(join(root, "fixtures", ".git", "debug.log")); put(join(root, "fixtures", "other.js"));
  const r = await walk(root);
  assert.equal(r.status, "ok");
  assert.deepEqual(paths(r), [".gitignore", "app.js", "fixtures/other.js"]); // nothing under a .git folder is walked
  assert.deepEqual(reasonsOf(r), { ".git": "excluded_directory", "fixtures/.git": "embedded_git_dir" });
  assert.equal(r.counts.ignored, 0);
});

// I-1: a crafted v4 index can't make the parser decode unbounded names.
test("index parser: v4 names over 4096 bytes and oversized decoded totals are refused quickly", async () => {
  const fixedEntry = () => Buffer.alloc(62, 0).fill(0);
  const v4 = (names) => {
    const head = Buffer.alloc(12); head.write("DIRC"); head.writeUInt32BE(4, 4); head.writeUInt32BE(names.length, 8);
    const parts = [head];
    for (const [strip, suffix] of names) { const e = fixedEntry(); e.writeUInt32BE(0o100644, 24); parts.push(e, Buffer.from([strip]), Buffer.from(suffix), Buffer.alloc(1)); }
    const body = Buffer.concat(parts);
    return Buffer.concat([body, createHash("sha1").update(body).digest()]);
  };
  // Each entry adds one byte to the previous name: names grow past 4096.
  let t0 = Date.now();
  assert.throws(() => parseIndex(v4(Array.from({ length: 20_000 }, () => [0, "a"]))), /name too long|names too large/);
  assert.ok(Date.now() - t0 < 2000, "slow");
  assert.throws(() => parseIndex(v4([[0, "n".repeat(4097)]])), /name too long/);
  assert.throws(() => parseIndex(buildIndex([["n".repeat(4097)]])), /name too long/);
  // Names stay under 4096 but each decodes to ~4000 bytes from 3 bytes on disk: the total is refused.
  const long = "d".repeat(4000);
  t0 = Date.now();
  assert.throws(() => parseIndex(v4([[0, long], ...Array.from({ length: 5_000 }, (_, i) => [1, String.fromCharCode(97 + (i % 26))])])), /names too large/);
  assert.ok(Date.now() - t0 < 2000, "slow");
  // Through readTracked, the set is unknown.
  const root = temp("custosa-a2-v4-bomb-");
  await initRepo(root, {});
  writeFileSync(join(root, ".git", "index"), v4(Array.from({ length: 5_000 }, () => [0, "a"])));
  assert.deepEqual([(await readTracked(root)).status], ["failed"]);
});

// I-2: the split-index bitmaps are bounded by the shared index's entry count before any loop runs.
test("split index: a bitmap larger than the shared index is refused quickly", async () => {
  const root = temp("custosa-a2-ewah-bomb-");
  await initRepo(root, {});
  put(join(root, "x.ts"));
  const gitdir = join(root, ".git");
  const shared = buildIndex([["x.ts"]]);
  const oid = shared.subarray(shared.length - 20);
  writeFileSync(join(gitdir, `sharedindex.${oid.toString("hex")}`), shared);
  // The reviewer's bitmap: bit size 2^32-1, one run word of 2^32-1 set words.
  const bomb = Buffer.alloc(20); bomb.writeUInt32BE(0xffffffff, 0); bomb.writeUInt32BE(1, 4); bomb.writeBigUInt64BE((0xffffffffn << 1n) | 1n, 8);
  writeFileSync(join(gitdir, "index"), buildIndex([], { extensions: [["link", Buffer.concat([oid, bomb, ewah(0, [])])]] }));
  let t0 = Date.now();
  const t = await readTracked(root);
  assert.ok(Date.now() - t0 < 1000, `took ${Date.now() - t0} ms`);
  assert.deepEqual([t.status, t.known], ["failed", false]);
  // A bit size within the count but a run reaching past it: refused the same way.
  const run = Buffer.alloc(20); run.writeUInt32BE(1, 0); run.writeUInt32BE(1, 4); run.writeBigUInt64BE((1000n << 1n) | 1n, 8);
  writeFileSync(join(gitdir, "index"), buildIndex([], { extensions: [["link", Buffer.concat([oid, run, ewah(0, [])])]] }));
  t0 = Date.now();
  assert.deepEqual([(await readTracked(root)).status], ["failed"]);
  assert.ok(Date.now() - t0 < 1000);
});

// I-3: a hard link is a file under another name: a hard-linked .gitignore, .git file or index is never read.
test("hard-linked .gitignore, index and .git file are refused; the .gitignore is reported", async () => {
  const root = temp("custosa-a2-hardlink-ignore-");
  await initRepo(root, { "keep.ts": "" });
  put(join(root, ".env"), "SYNTHETIC_PATTERN_LINE\n");
  fs.linkSync(join(root, ".env"), join(root, ".gitignore"));
  put(join(root, "SYNTHETIC_PATTERN_LINE"));
  // A refused file with a negation: root ignores *.log, sub/.gitignore (hard-linked) would re-include keep.log.
  put(join(root, "sub-rules"), "!keep.log\n");
  put(join(root, "sub", "keep.log")); fs.linkSync(join(root, "sub-rules"), join(root, "sub", ".gitignore"));
  const { result: r, opened } = await recordOpens(() => walk(root));
  assertSafeOpens(root, opened);
  assert.ok(paths(r).includes("SYNTHETIC_PATTERN_LINE"));
  assert.deepEqual(r.notAnalyzed.filter((n) => n.reason === "ignore_file_unreadable"), [
    { path: ".gitignore", kind: "file", reason: "ignore_file_unreadable", tracked: null },
    { path: "sub/.gitignore", kind: "file", reason: "ignore_file_unreadable", tracked: null },
  ]);
  assert.equal(await isIgnored(root, "SYNTHETIC_PATTERN_LINE"), false);

  const r2 = temp("custosa-a2-hardlink-neg-");
  await initRepo(r2, {});
  put(join(r2, ".gitignore"), "*.log\n");
  put(join(r2, "rules"), "!keep.log\n");
  put(join(r2, "sub", "keep.log")); fs.linkSync(join(r2, "rules"), join(r2, "sub", ".gitignore"));
  const w = await walk(r2);
  assert.deepEqual(reasonsOf(w)["sub/keep.log"], "ignored_unverified"); // never silently skipped
  assert.equal(w.status, "truncated");

  // The index and the .git file.
  const r3 = temp("custosa-a2-hardlink-index-");
  await initRepo(r3, { "a.ts": "" });
  fs.linkSync(join(r3, ".git", "index"), join(r3, "index-copy"));
  assert.deepEqual([(await readTracked(r3)).status, (await readTracked(r3)).reason], ["failed", "index_hard_link"]);
  const r4 = temp("custosa-a2-hardlink-gitfile-");
  await initRepo(join(r4, "store"), { "a.ts": "" });
  fs.renameSync(join(r4, "store", ".git"), join(r4, ".gitstore")); fs.rmSync(join(r4, "store"), { recursive: true });
  put(join(r4, "gitlink-text"), "gitdir: .gitstore\n");
  fs.linkSync(join(r4, "gitlink-text"), join(r4, ".git"));
  assert.equal((await locateGitdir(r4)).reason, "gitlink_unreadable");
});

// I-4: core.ignorecase=false on a case-insensitive disk (the reviewer's walk2 case): git shows secret.ts although
// .gitignore says Secret.ts. A match only when case folds is reported, never skipped.
test("ignorecase off on a case-insensitive disk: a fold-only match is ignored_unverified", async () => {
  const root = temp("custosa-a2-ignorecase-");
  await initRepo(root, {});
  put(join(root, ".gitignore"), "Secret.ts\n"); put(join(root, "secret.ts")); put(join(root, "Other.ts"));
  const r = await walk(root, { caseInsensitive: true });
  assert.deepEqual(paths(r), [".gitignore", "Other.ts"]);
  assert.deepEqual(r.notAnalyzed, [{ path: ".git", kind: "directory", reason: "excluded_directory", tracked: "no" }, { path: "secret.ts", kind: "file", reason: "ignored_unverified", tracked: null }]);
  assert.deepEqual([r.status, r.reason], ["truncated", "ignore_unverified"]);
  assert.equal(await ignoreState(root, "secret.ts", await ignoreContext(root, null, { caseInsensitive: true })), "unverified");
});

// L-1 (Linux CI): on a case-sensitive disk core.ignorecase is off by default, but any git config can turn it on, and
// then git shows what only folding re-includes ("!*.txt" re-including Foo.TXT, "[!]a]" no longer matching A.log).
// Those paths are reported as ignored_unverified, never skipped; told core.ignorecase, the answer is git's. A path
// folding would ignore but the exact rules don't is shown (git's default there). An ignored path that matches a
// tracked one only with case folded is reported too (git with core.ignorecase on counts it as tracked).
test("case-sensitive disk: a path only case folding would show is ignored_unverified, never skipped", async () => {
  const root = temp("custosa-a2-cs-reinclude-");
  await initRepo(root, {});
  put(join(root, ".gitignore"), "*\n!*/\n!*.txt\n!.gitignore\n"); put(join(root, "Foo.TXT")); put(join(root, "b.txt")); put(join(root, "c.log"));
  const r = await walk(root, { caseInsensitive: false });
  assert.deepEqual(paths(r), [".gitignore", "b.txt"]);
  assert.deepEqual(reasonsOf(r), { ".git": "excluded_directory", "Foo.TXT": "ignored_unverified" });
  assert.deepEqual([r.status, r.reason, r.counts.ignored], ["truncated", "ignore_unverified", 2]);
  const ctx = await ignoreContext(root, null, { caseInsensitive: false });
  assert.deepEqual([await ignoreState(root, "Foo.TXT", ctx), await ignoreState(root, "c.log", ctx)], ["unverified", "ignored"]);
  assert.equal(await ignoreState(root, "Foo.TXT", await ignoreContext(root, null, { ignoreCase: false })), "ignored");
  assert.equal(await ignoreState(root, "Foo.TXT", await ignoreContext(root, null, { ignoreCase: true })), false);

  const r2 = temp("custosa-a2-cs-fold-ignored-");
  await initRepo(r2, {});
  put(join(r2, ".gitignore"), "[!]a]*.log\n*.TMP\n"); put(join(r2, "A.log")); put(join(r2, "b.log")); put(join(r2, "x.tmp"));
  const w2 = await walk(r2, { caseInsensitive: false });
  assert.deepEqual(paths(w2), [".gitignore", "x.tmp"]); // only folding would ignore x.tmp: shown
  assert.deepEqual(reasonsOf(w2), { ".git": "excluded_directory", "A.log": "ignored_unverified" });
  assert.equal(w2.counts.ignored, 2);

  // A tracked SRC/A.ts on a case-sensitive disk holding src/a.ts under an ignored src/: reported, not skipped.
  const r3 = temp("custosa-a2-cs-fold-tracked-");
  await initRepo(r3, {});
  put(join(r3, ".gitignore"), "src/\n"); put(join(r3, "src", "a.ts")); put(join(r3, "lib", "b.ts"));
  writeFileSync(join(r3, ".git", "index"), buildIndex([[".gitignore"], ["SRC/A.ts"]]));
  const w3 = await walk(r3, { caseInsensitive: false });
  assert.deepEqual(paths(w3), [".gitignore", "lib/b.ts"]);
  assert.deepEqual(reasonsOf(w3), { ".git": "excluded_directory", src: "ignored_unverified" });
});

// L-2: git 2.52 keeps one byte of a pattern's literal prefix when matching the rest, so "a/b**/e.txt" no longer
// matches a/b/c/d/e.txt and "foo**/bar" no longer matches foobar ("**" there is not at the start of a component).
// Older git (Apple's 2.39, Debian 12, Ubuntu 24.04) still does. Not knowing the user's git, a path the two read
// differently is unverified: a negated "!src**/*.ts" re-includes srcx.ts for older git only, so it is never skipped.
test("ignore patterns: a literal prefix before ** differs by git version; a difference is unverified", async () => {
  const root = temp("custosa-a2-prefix-starstar-");
  await initRepo(root, {});
  put(join(root, ".gitignore"), "a/b**/e.txt\nfoo**/bar\n");
  const paths6 = ["a/b/c/d/e.txt", "a/bx/e.txt", "a/b/e.txt", "foobar", "foox/bar", "foo/bar"];
  const statesFor = async (gitVersion) => {
    const ctx = await ignoreContext(root, null, { ignoreCase: false, gitVersion });
    const out = {};
    for (const p of paths6) out[p] = await ignoreState(root, p, ctx);
    return out;
  };
  assert.deepEqual(await statesFor([2, 52]), { "a/b/c/d/e.txt": false, "a/bx/e.txt": "ignored", "a/b/e.txt": "ignored", foobar: false, "foox/bar": "ignored", "foo/bar": "ignored" });
  assert.deepEqual(await statesFor([2, 39]), { "a/b/c/d/e.txt": "ignored", "a/bx/e.txt": "ignored", "a/b/e.txt": "ignored", foobar: "ignored", "foox/bar": "ignored", "foo/bar": "ignored" });
  assert.deepEqual(await statesFor(null), { "a/b/c/d/e.txt": "unverified", "a/bx/e.txt": "ignored", "a/b/e.txt": "ignored", foobar: "unverified", "foox/bar": "ignored", "foo/bar": "ignored" });

  // The reviewer's repro: srcx.ts is shown by git before 2.52 and must never be skipped.
  const r2 = temp("custosa-a2-prefix-negated-");
  await initRepo(r2, {});
  put(join(r2, ".gitignore"), "*.ts\n!src**/*.ts\n"); put(join(r2, "src", "phi.ts")); put(join(r2, "srcx.ts")); put(join(r2, "other.ts"));
  for (const caseInsensitive of [false, true]) {
    const w = await walk(r2, { caseInsensitive });
    assert.deepEqual(paths(w), [".gitignore", "src/phi.ts"]);
    assert.equal(reasonsOf(w)["srcx.ts"], "ignored_unverified");
    assert.deepEqual([w.status, w.reason], ["truncated", "ignore_unverified"]);
  }
});

// M-1: a folder swapped between its check and its listing: the listing is discarded, the folder reported.
test("containment race: a folder replaced after it was listed gives no entries from the stale listing", async () => {
  const root = temp("custosa-a2-race2-");
  put(join(root, "a", "x.js"), "1"); put(join(root, "b.js"));
  const fsp = require("node:fs/promises");
  const real = fsp.readdir;
  let swapped = false;
  fsp.readdir = async (p, ...a) => {
    const result = await real(p, ...a);
    if (!swapped && String(p) === join(root, "a") && a[0]?.withFileTypes) {
      swapped = true;
      fs.renameSync(join(root, "a"), join(root, "a-old")); mkdirSync(join(root, "a")); writeFileSync(join(root, "a", "y.js"), "");
    }
    return result;
  };
  syncBuiltinESMExports();
  try {
    const r = await walk(root);
    assert.ok(swapped);
    assert.ok(!paths(r).some((p) => p.startsWith("a/")), JSON.stringify(paths(r)));
    assert.deepEqual(reasonsOf(r).a, "unreadable");
    assert.deepEqual([r.status, r.reason], ["truncated", "unreadable_directory"]);
  } finally { fsp.readdir = real; syncBuiltinESMExports(); }
});

// a folder removed after its parent was listed but before its own turn is reported unreadable, and truncates.
test("a folder gone before it is listed is reported unreadable and truncates the walk", async () => {
  const root = temp("custosa-a2-gone-");
  put(join(root, "a", "x.js"), "1"); put(join(root, "b.js"));
  const fsp = require("node:fs/promises");
  const real = fsp.readdir;
  let removed = false;
  fsp.readdir = async (p, ...a) => {
    const result = await real(p, ...a);
    if (!removed && String(p) === root && a[0]?.withFileTypes) {
      removed = true;
      fs.rmSync(join(root, "a"), { recursive: true });
    }
    return result;
  };
  syncBuiltinESMExports();
  try {
    const r = await walk(root);
    assert.ok(removed);
    assert.deepEqual(paths(r), ["b.js"]);
    assert.deepEqual(r.notAnalyzed, [{ path: "a", kind: "directory", reason: "unreadable", tracked: "not_checked" }]);
    assert.deepEqual([r.status, r.reason, r.drops], ["truncated", "unreadable_directory", ["unreadable_directory"]]);
  } finally { fsp.readdir = real; syncBuiltinESMExports(); }
});

// M-4: on a case-insensitive disk git opens ".gitignore" whatever its on-disk case, so a .GITIGNORE applies.
test(".gitignore name case follows the disk", async () => {
  const root = temp("custosa-a2-ignore-name-case-");
  await initRepo(root, {});
  put(join(root, "sub", ".GITIGNORE"), "*.log\n"); put(join(root, "sub", "a.log")); put(join(root, "sub", "b.ts"));
  const folds = await isCaseInsensitive(root);
  const r = await walk(root);
  if (folds) {
    assert.deepEqual(paths(r), ["sub/.GITIGNORE", "sub/b.ts"]);
    assert.equal(r.counts.ignored, 1);
  } else {
    assert.deepEqual(paths(r), ["sub/.GITIGNORE", "sub/a.log", "sub/b.ts"]);
  }
  // Forced either way on this machine.
  assert.equal((await walk(root, { caseInsensitive: false })).counts.ignored, 0);
});

// Product decision: nested roots are capped; past the cap the rest are reported and the parent is truncated.
test("walkAll: nested roots past the cap are reported, never silently dropped", async () => {
  const root = temp("custosa-a2-many-roots-");
  for (const n of ["a", "b", "c"]) await initRepo(join(root, n), { "x.ts": "" });
  const all = await walkAll(root, { maxRoots: 2 });
  assert.deepEqual(all.roots.map((x) => x.rel), ["", "a"]);
  const top = all.roots[0].result;
  assert.deepEqual(top.notAnalyzed.map((n) => n.path), ["a", "b", "c"]); // sorted, every nested root listed
  assert.deepEqual(top.nestedRoots.map((n) => n.path), ["a"]); // only the walked ones
  assert.deepEqual([top.status, top.reason], ["truncated", "item_limit"]);
  // One walk's own nestedRoots are capped too: the rest stay listed, and the walk is truncated.
  const one = await walk(root, { nestedRootsMax: 1 });
  assert.deepEqual([one.nestedRoots.length, one.notAnalyzed.length, one.status, one.reason], [1, 3, "truncated", "item_limit"]);
});

/* ---- Fix round 2 ----------------------------------------------------------------------------------------------- */

// Critical: on a missed literal after "*", git's wildmatch aborts (ABORT_ALL past "**", ABORT_TO_STARSTAR before a
// slash) instead of trying the next position; without that, these took up to 55 s against git's ~50 ms.
test("wildmatch: git's abort codes keep starstar patterns fast", async () => {
  const deep = (n, seg = "a") => `${Array(n).fill(seg).join("/")}/c`;
  const cases = [
    ["**/".repeat(8) + "b", deep(40)], ["a/**/".repeat(8) + "b", deep(40)], ["**/*a".repeat(6) + "/b", deep(40)],
    ["**/".repeat(12) + "b", deep(200)], ["**/" + "*a".repeat(20) + "*b", deep(100, "a".repeat(40))],
    ["**" + "/**a".repeat(20) + "/b", deep(300)], ["**/a**".repeat(20) + "/b", deep(300)], ["*?".repeat(40) + "b", "a".repeat(2000)],
  ];
  const root = temp("custosa-a2-wildmatch-");
  await initRepo(root, {});
  for (const [pattern, path] of cases) {
    writeFileSync(join(root, ".gitignore"), `${pattern}\n`);
    for (const caseInsensitive of [false, true]) {
      const ctx = await ignoreContext(root, null, { caseInsensitive });
      // CPU time of this process, not wall time: matching is synchronous CPU work, and on a loaded machine (a full
      // parallel test run) wall time grows with the scheduler's queue, not with the matcher. These use under 100 ms
      // of CPU; with the abort codes removed the slowest cases use 5 to 17 s each, so 500 ms still catches it.
      const cpu0 = process.cpuUsage();
      const state = await ignoreStateAt(ctx, path, false);
      const { user, system } = process.cpuUsage(cpu0);
      const ms = (user + system) / 1000;
      assert.ok(ms < 500, `${pattern.slice(0, 30)} on ${path.length} bytes used ${Math.round(ms)} ms of CPU`);
      assert.equal(state, false, pattern);
    }
  }
});

// Backstop: a pattern git itself can't finish (it timed out at 60 s) hits the walk's matching budget: the paths it
// would have decided are ignored_unverified and the walk is truncated, quickly.
test("wildmatch: a total-work cap per walk makes the rest unverified, never a guess", async () => {
  const root = temp("custosa-a2-workcap-");
  await initRepo(root, {});
  const dir = Array(300).fill("a").join("/");
  put(join(root, ...dir.split("/"), "c")); put(join(root, "top.ts"));
  writeFileSync(join(root, ".gitignore"), `${"**/".repeat(30)}b\n`);
  const t0 = Date.now();
  const r = await walk(root, { ignoreWorkMax: 2_000_000 });
  assert.ok(Date.now() - t0 < 5000, `took ${Date.now() - t0} ms`);
  assert.deepEqual([r.status, r.reason], ["truncated", "ignore_unverified"]);
  assert.ok(r.notAnalyzed.some((n) => n.reason === "ignored_unverified"), JSON.stringify(r.notAnalyzed.slice(0, 3)));
  assert.ok(r.counts.ignoreWork >= 2_000_000);
  const ctx = await ignoreContext(root, null, { caseInsensitive: false, workMax: 1_000_000 });
  assert.equal(await ignoreStateAt(ctx, `${dir}/c`, false), "unverified");
});

// Important: the root's own .git folder holding source beside a .git/.gitignore: walked without ignore rules.
test("the root's own .git folder: listed as excluded_directory, never walked, whatever it holds", async () => {
  const root = temp("custosa-a2-own-gitdir-src-");
  await initRepo(root, { "app.js": "" });
  put(join(root, ".git", "mysrc.js")); put(join(root, ".git", ".gitignore"), "nothing\n");
  put(join(root, ".git", "extra", "h.js")); put(join(root, ".git", "extra", ".gitignore"), "zzz\n");
  const r = await walk(root);
  assert.deepEqual(paths(r), ["app.js"]); // the root's .git is listed, never walked
  assert.deepEqual(r.notAnalyzed, [{ path: ".git", kind: "directory", reason: "excluded_directory", tracked: "no" }]);
  assert.equal(r.counts.ignored, 0);
  assert.equal(r.status, "ok");
});

// Important (a): files the parent tracks inside a nested root's folder stay the parent's; the nested root's own
// ignore rules can't drop them.
test("nested roots: the parent keeps the files it tracks inside them", async () => {
  const root = temp("custosa-a2-parent-tracked-");
  await initRepo(root, { "lib/secret.ts": "", "lib/ok.ts": "", "lib/.env.local": "" });
  await git.init({ fs, dir: join(root, "lib"), defaultBranch: "main" }); // lib becomes a nested clone with no index
  put(join(root, "lib", ".gitignore"), "secret.ts\nnew.ts\n"); put(join(root, "lib", "new.ts")); put(join(root, "lib", "own.ts"));
  const all = await walkAll(root);
  const [top, lib] = all.roots.map((x) => x.result);
  assert.deepEqual(all.roots.map((x) => x.rel), ["", "lib"]);
  assert.deepEqual(paths(top), ["lib/ok.ts", "lib/secret.ts"]); // ours, whatever lib's rules say
  assert.deepEqual(top.envFiles, [{ path: "lib/.env.local", git: "tracked" }]);
  assert.deepEqual(top.notAnalyzed, [{ path: ".git", kind: "directory", reason: "excluded_directory", tracked: "no" }, { path: "lib", kind: "directory", reason: "embedded_git_dir", tracked: "yes" }]);
  assert.deepEqual(paths(lib), [".gitignore", "own.ts"]); // lib/new.ts: untracked and ignored in lib
  assert.equal(lib.counts.coveredByParent, 3);
  assert.deepEqual(unaccountedAll(all, diskEntries(root, ["", "lib"])), ["lib/new.ts"]);
});

// Important (b): a nested .git file naming an ancestor's git directory is a second door into the same repository,
// not another root: it is refused and reported, and the folder is walked as ours.
test("a nested .git pointing at an ancestor's git directory is refused, the folder stays in the parent", async () => {
  const root = temp("custosa-a2-gitlink-ancestor-");
  await initRepo(root, { "n/hidden.ts": "" });
  put(join(root, "n", ".gitignore"), "hidden.ts\nscratch.ts\n"); put(join(root, "n", "scratch.ts"));
  writeFileSync(join(root, "n", ".git"), "gitdir: ../.git\n");
  put(join(root, "m", "x.ts")); symlinkSync("../.git", join(root, "m", ".git"));
  const all = await walkAll(root);
  assert.deepEqual(all.roots.map((x) => x.rel), [""]);
  const r = all.roots[0].result;
  assert.deepEqual(paths(r), ["m/x.ts", "n/.gitignore", "n/hidden.ts"]);
  assert.deepEqual(r.notAnalyzed, [
    { path: ".git", kind: "directory", reason: "excluded_directory", tracked: "no" },
    { path: "m/.git", kind: "file", reason: "gitlink_to_ancestor", tracked: null },
    { path: "n/.git", kind: "file", reason: "gitlink_to_ancestor", tracked: null },
  ]);
  assert.equal(r.counts.ignored, 1); // n/scratch.ts
});

test("a hard-linked shared index is reported as a hard link", async () => {
  const root = temp("custosa-a2-shared-hardlink-");
  await initRepo(root, {});
  put(join(root, "a.ts"));
  writeSplitIndex(join(root, ".git"), { shared: [["a.ts"]], added: [] });
  const shared = fs.readdirSync(join(root, ".git")).find((f) => f.startsWith("sharedindex."));
  fs.linkSync(join(root, ".git", shared), join(root, "copy"));
  assert.deepEqual([(await readTracked(root)).status, (await readTracked(root)).reason], ["failed", "shared_index_hard_link"]);
});

/* ---- Fix round 3 ----------------------------------------------------------------------------------------------- */

// 3a: a file the parent tracks inside a nested root, with an NFD name on disk (macOS keeps names as written): the
// index path is NFC, the realpath NFD; compared as NFC it is the same file, analysed, not a "symlink".
test("parent-tracked file with an NFD name inside a nested root is analysed (L2)", { skip: process.platform !== "darwin" }, async () => {
  const root = temp("custosa-a2-nfd-nested-");
  await initRepo(root, {});
  const nfcName = "é.ts", nfdName = "é.ts";
  put(join(root, "lib", nfdName), "real content");
  writeFileSync(join(root, ".git", "index"), handIndex([[`lib/${nfcName}`]]));
  await git.init({ fs, dir: join(root, "lib"), defaultBranch: "main" });
  const all = await walkAll(root);
  const top = all.roots[0].result;
  assert.deepEqual(paths(top), [`lib/${nfcName}`]);
  assert.deepEqual(top.notAnalyzed.map((n) => n.reason), ["excluded_directory", "embedded_git_dir"]);
  assert.equal(all.roots[1].result.counts.coveredByParent, 1);
});

// 3b: the ancestor check compares real paths, case folded per the disk: `gitdir: ../.Git` with the top's git
// directory really named .Git is still a door into the top repository (I2).
test("gitlink_to_ancestor holds when the git directory is spelt in another case (I2)", async () => {
  const root = temp("custosa-a2-ancestor-case-");
  await initRepo(root, { "n/hidden.ts": "" });
  put(join(root, "n", ".gitignore"), "hidden.ts\n");
  fs.renameSync(join(root, ".git"), join(root, ".Git"));
  if (!existsSync(join(root, ".git"))) return; // a case-sensitive disk: .Git is not a git directory at all
  writeFileSync(join(root, "n", ".git"), "gitdir: ../.Git\n");
  put(join(root, "m", "x.ts")); writeFileSync(join(root, "m", ".git"), "gitdir: ../.GIT\n");
  const all = await walkAll(root);
  assert.deepEqual(all.roots.map((x) => x.rel), [""]);
  const r = all.roots[0].result;
  assert.deepEqual(paths(r), ["m/x.ts", "n/.gitignore", "n/hidden.ts"]);
  assert.deepEqual(r.notAnalyzed.map((n) => [n.path, n.reason]), [[".git", "excluded_directory"], ["m/.git", "gitlink_to_ancestor"], ["n/.git", "gitlink_to_ancestor"]]);
});

// cap: class scans and slash searches count as work, so a long bracket class can't run unbudgeted.
test("ignore budget: class scans count as work", async () => {
  const root = temp("custosa-a2-class-work-");
  await initRepo(root, {});
  writeFileSync(join(root, ".gitignore"), `*[${"x".repeat(4000)}a]b\n`);
  const ctx = await ignoreContext(root, null, { caseInsensitive: false, workMax: 100_000 });
  assert.equal(await ignoreState(root, "a".repeat(3000), ctx), "unverified");
  assert.equal(ctx.workExceeded, true);
});

// cap: one wall-clock deadline for all ignore work across walkAll; past it, answers are unverified in every root.
test("ignore budget: one deadline and one budget across walkAll", async () => {
  const root = temp("custosa-a2-deadline-");
  await initRepo(root, {});
  put(join(root, ".gitignore"), "*.log\n"); put(join(root, "a.ts")); put(join(root, "x.log"));
  await initRepo(join(root, "n"), {});
  put(join(root, "n", ".gitignore"), "*.log\n"); put(join(root, "n", "b.ts")); put(join(root, "n", "y.log"));
  writeFileSync(join(root, ".git", "index"), handIndex([[".gitignore"], ["a.ts"], ["n", 0o160000]])); // n: a submodule
  const late = await walkAll(root, { ignoreDeadlineMs: -1 });
  assert.deepEqual(late.roots.map((x) => x.rel), ["", "n"]);
  for (const { rel, result } of late.roots) {
    assert.deepEqual([result.status, result.reason], ["truncated", "ignore_unverified"], rel);
    assert.ok(result.notAnalyzed.some((e) => e.reason === "ignored_unverified"), rel);
  }
  // A budget spent by the top root is spent for the nested one too.
  const budget = ignoreBudget({ workMax: 0 });
  const shared = await walkAll(root, { ignoreBudget: budget });
  assert.deepEqual(shared.roots.map((x) => x.result.reason), ["ignore_unverified", "ignore_unverified"]);
  // With time and work to spare, nothing is unverified.
  const fine = await walkAll(root);
  assert.deepEqual(fine.roots.map((x) => x.result.status), ["ok", "ok"]);
});

// A file the top tracks inside a nested-of-nested root is listed once, by the top.
test("nested roots: a file tracked by the top inside a nested-of-nested root is listed once", async () => {
  const root = temp("custosa-a2-nested-twice-");
  await initRepo(root, { "a/b/x.ts": "" });
  await initRepo(join(root, "a"), {});
  await initRepo(join(root, "a", "b"), {});
  put(join(root, "a", "b", "y.ts"));
  const all = await walkAll(root);
  assert.deepEqual(all.roots.map((x) => x.rel), ["", "a", "a/b"]);
  const listed = all.roots.flatMap(({ rel, result }) => paths(result).map((p) => (rel ? `${rel}/${p}` : p)));
  assert.deepEqual(listed.filter((p) => p === "a/b/x.ts"), ["a/b/x.ts"]);
  assert.deepEqual(paths(all.roots[2].result), ["y.ts"]);
  assert.equal(all.roots[2].result.counts.coveredByParent, 1);
});

// a name stored NFD on disk, with core.precomposeunicode unset or false (a repository made on Linux or by
// another tool), is matched by git as its raw bytes: an NFC pattern doesn't ignore it. The walk matches NFC, so on
// its own it would drop a file git shows. Both forms must say ignored; else the path is ignored_unverified, kept.
test("an NFD name an NFC pattern matches only after normalising is never dropped as ignored", async () => {
  const root = temp("custosa-nfd-ignore-");
  await initRepo(root, { "a.ts": "" });
  const nfd = (s) => s.normalize("NFD");
  put(join(root, ".gitignore"), "café\nnfc-dir/\n");
  put(join(root, "d", ".gitignore"), "é*/\n");
  put(join(root, nfd("café")), "x\n");
  put(join(root, "d", nfd("éq"), "f.ts"), "x\n");
  put(join(root, "plain.log"), "");
  const r = await walk(root);
  const seen = new Set([...paths(r), ...r.notAnalyzed.map((n) => n.path)]);
  for (const p of ["café", "d/éq"]) {
    assert.ok([...seen].some((s) => s === p || s.startsWith(p + "/")), `${p} is listed or analysed, not dropped: ${[...seen]}`);
  }
  assert.ok(paths(r).includes("a.ts"));
});

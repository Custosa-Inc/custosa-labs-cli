/* T29 (u), from P3's C125 low 1 (T29-P1-C99): the inspector read `.git` only at the scan root, so a package inside a
 * monorepo (`apps/web` in a repository) and a `git worktree` checkout (its `.git` file names
 * `<main>/.git/worktrees/<name>`, outside the root) both gave git `not_run`. Core's no-committed-secrets and
 * repo-no-data-dumps then hold, a false hold real users hit.
 *
 * The fix: read the tracked set from the enclosing repository, limited to the scan root's subtree, paths relative to
 * the root. For a worktree, follow the `.git` file only when its gitdir is a worktree of a repository the user owns
 * on the same disk (its `gitdir` file points back at this `.git`, and its `commondir` names the main git directory);
 * otherwise git stays `not_run`. A tracked file outside the subtree is never listed. Real git builds the fixtures;
 * the product never runs it. */
import { test } from "node:test";
import assert from "node:assert/strict";
import * as cp from "node:child_process";
import { mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { locateGitdir, readTracked } from "../lib/inspector/gitread.mjs";
import { walk } from "../lib/inspector/files.mjs";

const HAS_GIT = (() => { try { cp.execFileSync("git", ["--version"], { stdio: "ignore" }); return true; } catch { return false; } })();
const env = { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1", HOME: tmpdir(),
  GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@example.com", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@example.com" };
const git = (cwd, ...args) => cp.execFileSync("git", args, { cwd, env, encoding: "utf8" });
const temp = () => realpathSync(mkdtempSync(join(tmpdir(), "custosa-u-")));
const put = (file, text = "x\n") => { mkdirSync(dirname(file), { recursive: true }); writeFileSync(file, text); };

/* A repository with a package at apps/web and a tracked file elsewhere that must never reach the package's set. */
function monorepo() {
  const top = temp();
  git(top, "init", "-q");
  put(join(top, "apps", "web", "package.json"), "{}\n");
  put(join(top, "apps", "web", "src", "app.js"), "export const a = 1;\n");
  put(join(top, "other", "keys.txt"), "not part of the package\n");
  put(join(top, "README.md"));
  git(top, "add", "-A");
  git(top, "commit", "-qm", "init");
  return { top, pkg: join(top, "apps", "web") };
}

test("(u) a monorepo package: the enclosing repository's tracked set, limited to the package, relative to it", { skip: !HAS_GIT }, async () => {
  const { pkg } = monorepo();
  const t = await readTracked(pkg);
  assert.equal(t.status, "ok", JSON.stringify({ ...t, paths: [...t.paths] }));
  assert.deepEqual([...t.paths].sort(), ["package.json", "src/app.js"]);
  assert.equal(t.known, true);
});

test("(u) a monorepo package: the walk counts the package's tracked files and git is ok", { skip: !HAS_GIT }, async () => {
  const { pkg } = monorepo();
  const r = await walk(pkg);
  assert.equal(r.git.status, "ok", JSON.stringify(r.git));
  assert.equal(r.git.tracked, 2);
  assert.ok(!r.files.some((f) => f.path.includes("keys.txt")), "a file outside the package is never walked");
});

test("(u) a worktree checkout: its gitdir under the main repository is followed, and its index read", { skip: !HAS_GIT }, async () => {
  const { top } = monorepo();
  const wt = join(temp(), "wt");
  git(top, "worktree", "add", "-q", wt);
  const loc = await locateGitdir(wt);
  assert.equal(loc.reason, null, JSON.stringify(loc));
  assert.equal(loc.gitdir, join(top, ".git", "worktrees", "wt"));
  const t = await readTracked(wt, loc);
  assert.equal(t.status, "ok");
  assert.deepEqual([...t.paths].sort(), ["README.md", "apps/web/package.json", "apps/web/src/app.js", "other/keys.txt"]);
});

test("(u) a gitlink outside the root that is no worktree of that repository stays not_run", { skip: !HAS_GIT }, async () => {
  const { top } = monorepo();
  const wt = join(temp(), "wt");
  git(top, "worktree", "add", "-q", wt);
  // another checkout that points its .git at the same worktree gitdir: the gitdir's back-pointer names wt, not it
  const other = temp();
  put(join(other, "a.js"));
  writeFileSync(join(other, ".git"), `gitdir: ${join(top, ".git", "worktrees", "wt")}\n`);
  assert.equal((await locateGitdir(other)).reason, "gitlink_outside_root");
  assert.equal((await readTracked(other)).status, "not_run");
  // a gitlink to a plain folder outside with git's names but no commondir
  const fake = join(temp(), "fakegit");
  for (const d of ["objects", "refs"]) mkdirSync(join(fake, d), { recursive: true });
  writeFileSync(join(fake, "HEAD"), "ref: refs/heads/main\n");
  const third = temp();
  put(join(third, "a.js"));
  writeFileSync(join(third, ".git"), `gitdir: ${fake}\n`);
  assert.equal((await locateGitdir(third)).reason, "gitlink_outside_root");
});

test("(u) a folder in no repository is still no_git_dir", async () => {
  const lone = temp();
  put(join(lone, "a.js"));
  assert.equal((await locateGitdir(lone)).reason, "no_git_dir");
  assert.equal((await readTracked(lone)).status, "not_run");
});

test("(u) a repository above that tracks nothing under the root (a home folder in git) is not the root's", { skip: !HAS_GIT }, async () => {
  const home = temp();
  git(home, "init", "-q");
  put(join(home, ".bashrc"));
  git(home, "add", ".bashrc");
  git(home, "commit", "-qm", "dotfiles");
  const project = join(home, "code", "app");
  put(join(project, "a.js"));
  const t = await readTracked(project);
  assert.equal(t.status, "not_run");
  assert.equal(t.reason, "no_git_dir");
  const r = await walk(project);
  assert.equal(r.git.status, "not_run", JSON.stringify(r.git));
});

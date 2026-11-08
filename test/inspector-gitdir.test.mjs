/* locateGitdir: the whole result for every layout and every reason git data is unavailable, so a change to how the
 * result is built can't drop or swap a field. Fake git directories only (HEAD, objects, refs); git never runs. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { locateGitdir } from "../lib/inspector/gitread.mjs";

const temp = () => realpathSync(mkdtempSync(join(tmpdir(), "custosa-gitdir-")));
const gitdir = (dir) => {
  mkdirSync(join(dir, "objects"), { recursive: true });
  mkdirSync(join(dir, "refs"), { recursive: true });
  writeFileSync(join(dir, "HEAD"), "ref: refs/heads/main\n");
};
const none = (root, reason) => ({ realBoundary: root, realRoot: root, layout: "none", gitdir: null, gitdirRel: null, reason });
const gitlink = (root, reason, extra = {}) => ({ realBoundary: root, realRoot: root, layout: "gitlink", gitdir: null, gitdirRel: null, reason, ...extra });

test("locateGitdir: no .git, a bare repository, a .git folder", async () => {
  const empty = temp();
  assert.deepEqual(await locateGitdir(empty), none(empty, "no_git_dir"));
  const bare = temp();
  gitdir(bare);
  assert.deepEqual(await locateGitdir(bare), { realBoundary: bare, realRoot: bare, layout: "bare", gitdir: bare, gitdirRel: null, reason: null });
  const plain = temp();
  gitdir(join(plain, ".git"));
  assert.deepEqual(await locateGitdir(plain), { realBoundary: plain, realRoot: plain, layout: "dir", gitdir: join(plain, ".git"), gitdirRel: null, reason: null });
});

test("locateGitdir: a .git symlink, and a .git file too big to be a gitlink", async () => {
  const linked = temp();
  gitdir(join(linked, "real"));
  symlinkSync(join(linked, "real"), join(linked, ".git"));
  assert.deepEqual(await locateGitdir(linked), none(linked, "git_dir_symlink"));
  const big = temp();
  writeFileSync(join(big, ".git"), `gitdir: x\n${"#".repeat(5000)}`);
  assert.deepEqual(await locateGitdir(big), none(big, "git_entry_unreadable"));
});

test("locateGitdir: every gitlink outcome", async () => {
  const cases = [
    ["not a gitlink\n", "gitlink_unreadable"],
    ["gitdir: missing\n", "gitlink_missing"],
    ["gitdir: ../../../../../../../../tmp\n", "gitlink_outside_root"],
    ["gitdir: .\n", "gitlink_outside_root"], // the root itself
    ["gitdir: file.txt\n", "gitlink_missing"], // not a folder
    ["gitdir: src\n", "gitlink_into_source"],
  ];
  for (const [text, reason] of cases) {
    const root = temp();
    mkdirSync(join(root, "src"));
    writeFileSync(join(root, "src", "app.js"), "");
    writeFileSync(join(root, "file.txt"), "");
    writeFileSync(join(root, ".git"), text);
    assert.deepEqual(await locateGitdir(root), gitlink(root, reason), text);
  }
  const ok = temp();
  gitdir(join(ok, "store"));
  writeFileSync(join(ok, ".git"), "gitdir: store\n");
  assert.deepEqual(await locateGitdir(ok), gitlink(ok, null, { gitdir: join(ok, "store"), gitdirRel: "store" }));
});

test("locateGitdir: a nested root's gitlink into the outer root's .git/modules", async () => {
  const top = temp();
  gitdir(join(top, ".git"));
  gitdir(join(top, ".git", "modules", "sub"));
  const sub = join(top, "sub");
  mkdirSync(sub);
  writeFileSync(join(sub, ".git"), "gitdir: ../.git/modules/sub\n");
  assert.deepEqual(await locateGitdir(sub, { boundary: top }),
    { realBoundary: top, realRoot: sub, layout: "gitlink", gitdir: join(top, ".git", "modules", "sub"), gitdirRel: null, reason: null });
  assert.deepEqual(await locateGitdir(sub), gitlink(sub, "gitlink_outside_root")); // without the boundary
});

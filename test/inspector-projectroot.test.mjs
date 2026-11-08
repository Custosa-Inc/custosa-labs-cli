/* Which folders may be a project root. The disk, the home folder (and above it) and a folder of repositories
 * are refused with a message; a repository, a folder inside one, and a plain folder of files are allowed. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { projectRootProblem, ROOT_PROBLEMS } from "../lib/inspector/projectroot.mjs";

const temp = () => realpathSync(mkdtempSync(join(tmpdir(), "custosa-root-")));
const code = async (dir, home) => (await projectRootProblem(dir, { home }))?.code ?? null;

test("the filesystem root, the home folder and folders above it are refused", async () => {
  const base = temp();
  const home = join(base, "Users", "me");
  mkdirSync(join(home, "app", ".git"), { recursive: true });
  assert.equal(await code("/", home), "filesystem_root");
  assert.equal(await code(home, home), "home_folder");
  assert.equal(await code(join(base, "Users"), home), "above_home");
  assert.equal(await code(base, home), "above_home");
  // A dotfiles repository in the home folder doesn't make the home folder, or a plain folder of projects in it, a project.
  mkdirSync(join(home, ".git"));
  assert.equal(await code(home, home), "home_folder");
  mkdirSync(join(home, "code", "one", ".git"), { recursive: true });
  assert.equal(await code(join(home, "code"), home), "above_repositories");
  for (const c of Object.keys(ROOT_PROBLEMS)) assert.match(ROOT_PROBLEMS[c], /project's own folder/);
});

test("a repository, a folder in one, and a plain folder of files are projects; a folder of repositories is not", async () => {
  const base = temp();
  const home = join(base, "home");
  mkdirSync(home);
  const repo = join(base, "repo");
  mkdirSync(join(repo, ".git"), { recursive: true });
  mkdirSync(join(repo, "packages", "web"), { recursive: true });
  mkdirSync(join(repo, "vendor", "lib", ".git"), { recursive: true }); // a nested repository inside a project is fine
  assert.equal(await code(repo, home), null);
  assert.equal(await code(join(repo, "packages", "web"), home), null);
  const plain = join(base, "plain");
  mkdirSync(join(plain, "src"), { recursive: true });
  writeFileSync(join(plain, "src", "a.js"), "x\n");
  assert.equal(await code(plain, home), null);
  const projects = join(base, "projects");
  mkdirSync(join(projects, "a", "deep", ".git"), { recursive: true });
  assert.equal(await code(projects, home), "above_repositories");
});

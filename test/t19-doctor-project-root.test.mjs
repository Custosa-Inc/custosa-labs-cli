// T19 (P2): doctor's "Project root" line had no test. It must judge CUSTOSA_PROJECT_ROOT the way the inspector does
// at call time (server.mjs: an existing folder given as an absolute path, then projectRootProblem), so a root that
// doctor passes is one the inspector reads, and one it fails is one the inspector refuses.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runDoctor } from "../lib/doctor.mjs";
import { ROOT_PROBLEMS } from "../lib/inspector/projectroot.mjs";

/* doctor's Project root line (or undefined when it prints none), for CUSTOSA_PROJECT_ROOT = root under `home` */
async function projectRootLine(home, root) {
  const lines = [];
  const env = { CUSTOSA_CONFIG_DIR: join(home, ".config", "custosa"), CUSTOSA_EVALUATOR_URL: "http://127.0.0.1:9",
    PGSERVICEFILE: "/nonexistent", npm_config_cache: join(home, ".npm") };
  if (root !== undefined) env.CUSTOSA_PROJECT_ROOT = root;
  await runDoctor({ env, home, out: (l) => lines.push(l), offline: true, which: () => null, run: () => ({ status: 1, stdout: "" }) });
  const found = lines.filter((l) => /^\w+ +Project root:/.test(l));
  assert.ok(found.length <= 1, found.join("\n"));
  return found[0];
}

const newHome = () => mkdtempSync(join(tmpdir(), "custosa-doctor-root-"));
const NOT_A_FOLDER = "it is not an existing folder given as an absolute path";

test("doctor project root: no line when CUSTOSA_PROJECT_ROOT is unset or empty", async () => {
  const home = newHome();
  assert.equal(await projectRootLine(home, undefined), undefined);
  assert.equal(await projectRootLine(home, ""), undefined);
});

test("doctor project root: a repository folder passes, and the line names it", async () => {
  const home = newHome();
  const app = join(home, "work", "app");
  mkdirSync(join(app, ".git"), { recursive: true });
  assert.equal(await projectRootLine(home, app),
    `PASS  Project root: CUSTOSA_PROJECT_ROOT is ${app}; it takes precedence over the assistant's roots`);
  // A folder inside the repository is a project too.
  mkdirSync(join(app, "packages", "api"), { recursive: true });
  assert.match(await projectRootLine(home, join(app, "packages", "api")), /^PASS  Project root:/);
});

test("doctor project root: a missing folder, a file or a relative path fails as not an existing absolute folder", async () => {
  const home = newHome();
  const missing = join(home, "gone");
  assert.equal(await projectRootLine(home, missing),
    `FAIL  Project root: CUSTOSA_PROJECT_ROOT is set to ${missing}, which can't be used: ${NOT_A_FOLDER}`);
  const file = join(home, "notes.txt");
  writeFileSync(file, "x");
  assert.match(await projectRootLine(home, file), new RegExp(`^FAIL  Project root: .*: ${NOT_A_FOLDER}$`));
  // "." is an existing folder, but not an absolute path: the inspector refuses it too.
  assert.match(await projectRootLine(home, "."), new RegExp(`^FAIL  Project root: CUSTOSA_PROJECT_ROOT is set to \\., .*: ${NOT_A_FOLDER}$`));
});

test("doctor project root: the home folder, a folder above it and a filesystem root fail with the inspector's own reason", async () => {
  const home = newHome();
  const line = (root, code) => `FAIL  Project root: CUSTOSA_PROJECT_ROOT is set to ${root}, which can't be used: ${ROOT_PROBLEMS[code]}`;
  assert.equal(await projectRootLine(home, home), line(home, "home_folder"));
  const above = join(home, "..");
  assert.equal(await projectRootLine(home, above), line(above, "above_home"));
  assert.equal(await projectRootLine(home, "/"), line("/", "filesystem_root"));
});

test("doctor project root: a plain folder that holds repositories fails as a folder of projects; an empty one passes", async () => {
  const home = newHome();
  // Outside the home folder and outside any repository, as a tmp folder is.
  const outside = mkdtempSync(join(tmpdir(), "custosa-doctor-projects-"));
  mkdirSync(join(outside, "one", ".git"), { recursive: true });
  mkdirSync(join(outside, "two"), { recursive: true });
  assert.equal(await projectRootLine(home, outside),
    `FAIL  Project root: CUSTOSA_PROJECT_ROOT is set to ${outside}, which can't be used: ${ROOT_PROBLEMS.above_repositories}`);
  assert.match(await projectRootLine(home, join(outside, "two")), /^PASS  Project root:/);
});

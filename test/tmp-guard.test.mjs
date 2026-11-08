/* The test run leaves nothing in TMPDIR. scripts/tmp-guard.mjs runs node in a fresh TMPDIR and fails when
 * anything is left there; test/tmp-sandbox.mjs, preloaded into each test file's process, gives that process its own
 * TMPDIR and removes it at exit, pass or fail. Who it serves: anyone running the suite. On one machine about 3 GB of leaked
 * test folders filled a /tmp quota and failed a gate. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { removeTree } from "../scripts/tmp-guard.mjs";

const CLI_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const GUARD = join(CLI_DIR, "scripts", "tmp-guard.mjs");
const SANDBOX = join(CLI_DIR, "test", "tmp-sandbox.mjs");

// A leak that a real test could make: a temp folder, a nested folder chmod 000 (rmSync can't empty it), and a folder
// made by a child process, which reads TMPDIR from its env.
const LEAK = `
const fs = require("node:fs"), os = require("node:os"), path = require("node:path"), cp = require("node:child_process");
const d = fs.mkdtempSync(path.join(os.tmpdir(), "fp-repo-"));
fs.mkdirSync(path.join(d, "locked", "inner"), { recursive: true });
fs.chmodSync(path.join(d, "locked"), 0);
cp.execFileSync(process.execPath, ["-e", "require('node:fs').mkdtempSync(require('node:path').join(require('node:os').tmpdir(), 'a7-cfg-'))"]);
`;

/** Run the guard with `args`, under an outer TMPDIR of its own, and return the result plus what the outer TMPDIR holds
 *  afterwards (the guard must leave its own folder behind there either). */
function runGuard(args) {
  const outer = mkdtempSync(join(tmpdir(), "custosa-guard-test-"));
  try {
    const r = spawnSync(process.execPath, [GUARD, ...args], {
      cwd: CLI_DIR, encoding: "utf8", env: { ...process.env, TMPDIR: outer, TMP: outer, TEMP: outer },
    });
    return { status: r.status, stderr: r.stderr, outerLeft: readdirSync(outer) };
  } finally {
    removeTree(outer);
  }
}

test("the guard fails a run that leaves a folder in TMPDIR, names it, and still removes it", () => {
  const r = runGuard(["-e", LEAK]);
  assert.equal(r.status, 1, r.stderr);
  assert.match(r.stderr, /left 2 entries in TMPDIR/);
  assert.match(r.stderr, /^ {2}fp-repo-/m);
  assert.match(r.stderr, /^ {2}a7-cfg-/m);
  assert.deepEqual(r.outerLeft, [], "the guard's folder, locked subfolder included, is gone");
});

test("the guard passes a clean run and keeps a failing run's own exit code", () => {
  const clean = runGuard(["-e", "require('node:fs').rmSync(require('node:fs').mkdtempSync(require('node:path').join(require('node:os').tmpdir(), 'x-')), { recursive: true })"]);
  assert.equal(clean.status, 0, clean.stderr);
  assert.equal(clean.stderr, "");
  assert.deepEqual(clean.outerLeft, []);
  const failed = runGuard(["-e", "process.exit(3)"]);
  assert.equal(failed.status, 3);
  assert.deepEqual(failed.outerLeft, []);
});

test("under the sandbox the same leak leaves nothing, whether the process ends normally, exits or throws", () => {
  for (const end of ["", "process.exit(5)", "throw new Error('boom')"]) {
    const r = runGuard(["--import", SANDBOX, "-e", LEAK + end]);
    assert.doesNotMatch(r.stderr, /tmp-guard: the run left/, `ending: ${end || "normal"}\n${r.stderr}`);
    assert.equal(r.status, end ? (end.startsWith("throw") ? 1 : 5) : 0, `ending: ${end || "normal"}\n${r.stderr}`);
    assert.deepEqual(r.outerLeft, []);
  }
});

test("the sandbox points TMPDIR, TMP and TEMP at one fresh folder per process", () => {
  const show = "console.log(JSON.stringify([require('node:os').tmpdir(), process.env.TMPDIR, process.env.TMP, process.env.TEMP]))";
  const one = spawnSync(process.execPath, ["--import", SANDBOX, "-e", show], { encoding: "utf8" });
  const two = spawnSync(process.execPath, ["--import", SANDBOX, "-e", show], { encoding: "utf8" });
  assert.equal(one.status, 0, one.stderr);
  const [a, b] = [JSON.parse(one.stdout), JSON.parse(two.stdout)];
  assert.equal(new Set(a).size, 1, one.stdout);
  assert.notEqual(a[0], b[0]);
  assert.match(a[0], /custosa-t-[^/\\]+$/);
});

test("an interrupted run is cleaned up too: the guard passes SIGTERM on to node and then removes its folder", async () => {
  const outer = mkdtempSync(join(tmpdir(), "custosa-guard-test-"));
  try {
    // the child leaks, says so, then waits to be stopped
    const child = spawn(process.execPath, [GUARD, "-e", LEAK + "console.log('ready'); setInterval(() => {}, 1000);"], {
      cwd: CLI_DIR, env: { ...process.env, TMPDIR: outer, TMP: outer, TEMP: outer }, stdio: ["ignore", "pipe", "pipe"],
    });
    let stderr = "";
    child.stderr.on("data", (b) => { stderr += b; });
    await new Promise((ok) => child.stdout.on("data", (b) => { if (String(b).includes("ready")) ok(); }));
    assert.equal(readdirSync(outer).length, 1, "the guard's folder exists while node runs");
    child.kill("SIGTERM");
    const status = await new Promise((ok) => child.on("exit", (code) => ok(code)));
    assert.notEqual(status, 0);
    assert.match(stderr, /node stopped on SIGTERM/);
    assert.deepEqual(readdirSync(outer), []);
  } finally {
    removeTree(outer);
  }
});

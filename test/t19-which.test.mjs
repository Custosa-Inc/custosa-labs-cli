/* cli.mjs which(): the command's path in the first PATH folder that has it as a file this user can run, else null.
 * Every other test stubs which, so it never found a command (lines 79-80). PATH points at temp folders only. */
import { afterEach, test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { which } from "../lib/cli.mjs";

const win = process.platform === "win32";
const NAME = "t19-which-cmd";
const saved = { PATH: process.env.PATH, PATHEXT: process.env.PATHEXT };
afterEach(() => { for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; } });

const folder = () => realpathSync(mkdtempSync(join(tmpdir(), "t19-which-")));
/* A file named the command (with .cmd on Windows), runnable or not. */
function command(dir, { runnable = true } = {}) {
  const file = join(dir, NAME + (win ? ".cmd" : ""));
  writeFileSync(file, win ? "@echo off\r\n" : "#!/bin/sh\n");
  if (!win) chmodSync(file, runnable ? 0o755 : 0o644);
  return file;
}
const path = (...dirs) => { process.env.PATH = dirs.join(delimiter); if (win) process.env.PATHEXT = ".EXE;.CMD"; };

test("finds the command in a PATH folder, and the first folder that has it wins", () => {
  const a = folder(), b = folder(), c = folder();
  const inB = command(b);
  command(c);
  path(a, b, c);
  assert.equal(which(NAME), inB);
});

test("an empty PATH entry is skipped, never read as the current folder", () => {
  const here = folder(), a = folder(), cwd = process.cwd();
  command(here);
  process.chdir(here);
  try {
    path("", folder(), "");
    assert.equal(which(NAME), null);
    const file = command(a);
    path("", a, "");
    assert.equal(which(NAME), file);
  } finally { process.chdir(cwd); }
});

test("a folder named like the command is passed over", () => {
  const a = folder(), b = folder();
  mkdirSync(join(a, NAME + (win ? ".cmd" : "")));
  const file = command(b);
  path(a, b);
  assert.equal(which(NAME), file);
});

test("a file this user can't run is passed over", { skip: win || process.getuid?.() === 0 }, () => {
  const a = folder(), b = folder();
  command(a, { runnable: false });
  const file = command(b);
  path(a, b);
  assert.equal(which(NAME), file);
  path(a);
  assert.equal(which(NAME), null);
});

test("no PATH folder has it, or no PATH at all: null", () => {
  path(folder(), folder());
  assert.equal(which(NAME), null);
  delete process.env.PATH;
  assert.equal(which(NAME), null);
});

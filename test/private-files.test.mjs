/* the sign-in files are read as the environment mark is: one open with O_NOFOLLOW, then fstat on
   that descriptor. The old reader checked the path with lstat, then read it again by path, so a file swapped for a
   symlink in between was followed. The swap is stood in for here by an lstat that still sees the regular file. */
import { test, mock } from "node:test";
import assert from "node:assert/strict";
import fs, { chmodSync, mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readToken } from "../lib/inspector/auth.mjs";

const TOKEN = "a".repeat(40);
const OTHER = "b".repeat(40);
const HOST = "https://evaluator.custosa.com";

function signedIn() {
  const base = mkdtempSync(join(tmpdir(), "custosa-private-"));
  const dir = join(base, "config");
  mkdirSync(dir, { mode: 0o700 });
  chmodSync(dir, 0o700);
  writeFileSync(join(dir, "token"), `${TOKEN}\n`, { mode: 0o600 });
  writeFileSync(join(dir, "token.host"), `${HOST}\n`, { mode: 0o600 });
  writeFileSync(join(base, "elsewhere"), `${OTHER}\n`, { mode: 0o600 });
  writeFileSync(join(base, "elsewhere.host"), "https://evil.example\n", { mode: 0o600 });
  return { base, dir };
}

/* lstat answers as if the file at `path` were still the regular file it replaced. */
function staleLstat(paths, stand) {
  const real = fs.lstatSync;
  mock.method(fs, "lstatSync", (p, ...rest) => (paths.includes(p) ? real(stand, ...rest) : real(p, ...rest)));
  syncBuiltinESMExports();
  return () => { mock.restoreAll(); syncBuiltinESMExports(); };
}

test("a sign-in file swapped for a symlink after its check is refused, not followed", { skip: process.platform === "win32" }, () => {
  const { base, dir } = signedIn();
  try {
    assert.deepEqual(readToken({ configDir: dir }), { token: TOKEN, host: HOST });
    rmSync(join(dir, "token"));
    symlinkSync(join(base, "elsewhere"), join(dir, "token"));
    const restore = staleLstat([join(dir, "token")], join(base, "elsewhere"));
    try {
      assert.deepEqual(readToken({ configDir: dir }), { refused: "the sign-in file is not a regular file" });
    } finally { restore(); }
  } finally { rmSync(base, { recursive: true, force: true }); }
});

test("a host file swapped for a symlink after its check is refused, not followed", { skip: process.platform === "win32" }, () => {
  const { base, dir } = signedIn();
  try {
    rmSync(join(dir, "token.host"));
    symlinkSync(join(base, "elsewhere.host"), join(dir, "token.host"));
    const restore = staleLstat([join(dir, "token.host")], join(base, "elsewhere.host"));
    try {
      assert.deepEqual(readToken({ configDir: dir }),
        { refused: "the sign-in has no record of the evaluator it was made for (sign in again)" });
    } finally { restore(); }
  } finally { rmSync(base, { recursive: true, force: true }); }
});

test("the sign-in refusals keep their messages", { skip: process.platform === "win32" }, () => {
  const { base, dir } = signedIn();
  try {
    chmodSync(join(dir, "token"), 0o644);
    assert.deepEqual(readToken({ configDir: dir }),
      { refused: "the sign-in file is readable by other users (run chmod 600 on it, or sign in again)" });
    chmodSync(join(dir, "token"), 0o600);
    writeFileSync(join(dir, "token"), "x".repeat(9000), { mode: 0o600 });
    assert.deepEqual(readToken({ configDir: dir }), { refused: "the sign-in file is not a sign-in token" });
    rmSync(join(dir, "token"));
    symlinkSync(join(base, "elsewhere"), join(dir, "token"));
    assert.deepEqual(readToken({ configDir: dir }), { refused: "the sign-in file is not a regular file" });
    rmSync(join(dir, "token"));
    assert.deepEqual(readToken({ configDir: dir }), { missing: true });
    chmodSync(dir, 0o777);
    assert.deepEqual(readToken({ configDir: dir }),
      { refused: "the config folder is writable by other users (run chmod 700 on it)" });
  } finally { chmodSync(join(base, "config"), 0o700); rmSync(base, { recursive: true, force: true }); }
});

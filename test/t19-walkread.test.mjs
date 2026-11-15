/* T19 (P2): lib/inspector/walkread.mjs readWalked, tested directly. rules-read.test.mjs covers a symlink out of the
 * root and inspector-factdoc-env-files.test.mjs the env-name refusal and the size limit through the fact document.
 * These cover the rest: the size limit at its edge, an empty file, a folder, a path that climbs out of the root, a FIFO
 * (refused without blocking), and the two checks after the open, through a mocked handle: a file swapped between the
 * check and the open (another dev or ino) is unreadable, and a file that grew past maxBytes after the check is
 * too_large, never a cut buffer. */
import { test, mock } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import fsp from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readWalked } from "../lib/inspector/walkread.mjs";

function tree(t) {
  const base = realpathSync(mkdtempSync(join(tmpdir(), "t19-walkread-")));
  t.after(() => rmSync(base, { recursive: true, force: true }));
  const root = join(base, "repo");
  mkdirSync(join(root, "src", "dir"), { recursive: true });
  writeFileSync(join(base, "outside.js"), "x\n");
  return root;
}

test("a file of exactly maxBytes is read whole; one byte more is too_large", async (t) => {
  const root = tree(t);
  writeFileSync(join(root, "src", "ten.js"), "0123456789");
  const read = await readWalked(root, "src/ten.js", 10);
  assert.equal(read.buf.toString("utf8"), "0123456789");
  assert.deepEqual(await readWalked(root, "src/ten.js", 9), { refused: "too_large" });
});

test("an empty file reads as an empty buffer", async (t) => {
  const root = tree(t);
  writeFileSync(join(root, "src", "empty.js"), "");
  const read = await readWalked(root, "src/empty.js", 10);
  assert.equal(read.buf.length, 0);
});

test("a folder, a path out of the root, a missing file and an absolute path are unreadable", async (t) => {
  const root = tree(t);
  for (const rel of ["src/dir", "../outside.js", "src/../../outside.js", "src/missing.js", join(root, "src", "dir")]) {
    assert.deepEqual(await readWalked(root, rel, 1000), { refused: "unreadable" }, rel);
  }
});

test("a FIFO is unreadable and the read doesn't block on it", { skip: process.platform === "win32" }, async (t) => {
  const root = tree(t);
  execFileSync("mkfifo", [join(root, "src", "pipe.js")]);
  assert.deepEqual(await readWalked(root, "src/pipe.js", 1000), { refused: "unreadable" });
});

// The open handle's checks, through fs/promises.open mocked to hand back a handle that differs from the checked file.
function mockOpen(t, change) {
  const real = fsp.open;
  mock.method(fsp, "open", async (...args) => {
    const handle = await real(...args);
    return change(handle);
  });
  syncBuiltinESMExports();
  t.after(() => { mock.restoreAll(); syncBuiltinESMExports(); });
}

test("a file swapped between the check and the open (another inode) is unreadable", async (t) => {
  const root = tree(t);
  writeFileSync(join(root, "src", "a.js"), "abc\n");
  mockOpen(t, (handle) => {
    const stat = handle.stat.bind(handle);
    handle.stat = async () => { const st = await stat(); st.ino += 1; return st; };
    return handle;
  });
  assert.deepEqual(await readWalked(root, "src/a.js", 1000), { refused: "unreadable" });
});

test("a file that grew past maxBytes after the check is too_large, never a cut buffer", async (t) => {
  const root = tree(t);
  writeFileSync(join(root, "src", "grow.js"), "0123456789");
  mockOpen(t, (handle) => {
    // the size still reads as checked, but the reads keep returning bytes: more than maxBytes arrive
    handle.read = async (buf, offset, length) => { buf.fill(0x61, offset, offset + length); return { bytesRead: length, buffer: buf }; };
    return handle;
  });
  assert.deepEqual(await readWalked(root, "src/grow.js", 10), { refused: "too_large" });
});

test("readWalked closes the handle it opened, also when it refuses", async (t) => {
  const root = tree(t);
  writeFileSync(join(root, "src", "a.js"), "abc\n");
  let closed = 0;
  mockOpen(t, (handle) => {
    const close = handle.close.bind(handle);
    handle.close = async () => { closed += 1; return close(); };
    const stat = handle.stat.bind(handle);
    handle.stat = async () => { const st = await stat(); st.dev += 1; return st; };
    return handle;
  });
  assert.deepEqual(await readWalked(root, "src/a.js", 1000), { refused: "unreadable" });
  assert.equal(closed, 1);
});

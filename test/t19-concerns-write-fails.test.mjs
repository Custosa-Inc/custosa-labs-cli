/* concerns.mjs writeTexts when the write itself fails (inspector-concerns covers a symlinked .custosa/local): a
 * .custosa/local it can't write, a .custosa it can't add .gitignore to, and a rename that fails (lines 109 to 111).
 * Each gives the concern_texts_unwritable note, keeps the texts already held and leaves no temp file. A left-over or
 * planted temp file is replaced, never followed. Called through rememberRaised and forgetRefused with a made-up
 * answer; temp folders only. */
import { test, mock } from "node:test";
import assert from "node:assert/strict";
import fs, { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CONCERN_NOTES, forgetRefused, readTexts, rememberRaised } from "../lib/inspector/concerns.mjs";

const temp = () => realpathSync(mkdtempSync(join(tmpdir(), "t19-concerns-")));
const noPermissions = process.platform === "win32" || process.getuid?.() === 0; // chmod doesn't stop root or Windows
const META = { category: "phi_exposure", area: "logging", file_kind: "code", practice_id: "no-phi-in-app-logs", proposed_severity: "high" };
const id = (n) => `cn_${String(n).padStart(16, "0")}`;
/* Raise one concern n: the sent entry, and an answer that lists it as raised now. */
const raise = (root, n) => rememberRaised(root, [{ ...META, note: `text ${n}` }],
  { concerns: [{ ...META, concern_id: id(n), raised_now: true }] });
const held = (root) => [...readTexts(root)].map(([k, e]) => [k, e.text]);
const local = (root) => join(root, ".custosa/local");
const temps = (root) => readdirSync(local(root)).filter((f) => f.endsWith(".custosa-tmp"));

/* A root that already holds concern 1. */
function heldRoot() {
  const root = temp();
  assert.deepEqual(raise(root, 1), { note: null, pending: null });
  assert.deepEqual(held(root), [[id(1), "text 1"]]);
  return root;
}
const UNWRITABLE = { note: CONCERN_NOTES.concern_texts_unwritable, pending: null };

test("a .custosa/local it can't write: the unwritable note, the held text stays, no temp file", { skip: noPermissions }, () => {
  const root = heldRoot();
  chmodSync(local(root), 0o500);
  try {
    assert.deepEqual(raise(root, 2), UNWRITABLE);
  } finally { chmodSync(local(root), 0o700); }
  assert.deepEqual(held(root), [[id(1), "text 1"]]);
  assert.deepEqual(temps(root), []);
});

test("a .custosa it can't add .gitignore to: the unwritable note, and nothing is written", { skip: noPermissions }, () => {
  const root = temp();
  mkdirSync(local(root), { recursive: true });
  chmodSync(join(root, ".custosa"), 0o500);
  try {
    assert.deepEqual(raise(root, 1), UNWRITABLE);
  } finally { chmodSync(join(root, ".custosa"), 0o700); }
  assert.equal(existsSync(join(root, ".custosa/.gitignore")), false);
  assert.deepEqual(readdirSync(local(root)), []);
});

test("a rename that fails: the unwritable note, the held text stays, the temp file is removed, and the next write works", () => {
  const root = heldRoot();
  const real = fs.renameSync;
  mock.method(fs, "renameSync", (from, to) => {
    if (String(from).endsWith(".custosa-tmp")) throw Object.assign(new Error("forced"), { code: "EIO" });
    return real(from, to);
  });
  syncBuiltinESMExports();
  try {
    assert.deepEqual(raise(root, 2), UNWRITABLE);
    // forgetRefused writes the same way: a failed write leaves the file as it was, and throws nothing.
    forgetRefused(root, { concern_outcomes: [{ concern_id: id(1), outcome: "refused", reason: "unknown_concern" }] });
  } finally { mock.restoreAll(); syncBuiltinESMExports(); }
  assert.deepEqual(held(root), [[id(1), "text 1"]]);
  assert.deepEqual(temps(root), []);
  assert.deepEqual(raise(root, 3), { note: null, pending: null });
  assert.deepEqual(held(root), [[id(1), "text 1"], [id(3), "text 3"]]);
});

test("a left-over temp file, or one planted as a link, is replaced and never written through", () => {
  const root = heldRoot();
  const tmp = join(local(root), "concerns.json.custosa-tmp");
  writeFileSync(tmp, "left over");
  assert.deepEqual(raise(root, 2), { note: null, pending: null });
  assert.deepEqual(held(root), [[id(1), "text 1"], [id(2), "text 2"]]);
  assert.deepEqual(temps(root), []);
  if (process.platform !== "win32") {
    const outside = join(temp(), "outside.txt");
    writeFileSync(outside, "outside");
    symlinkSync(outside, tmp);
    assert.deepEqual(raise(root, 3), { note: null, pending: null });
    assert.equal(readFileSync(outside, "utf8"), "outside");
    assert.deepEqual(held(root).map(([k]) => k), [id(1), id(2), id(3)]);
    assert.deepEqual(temps(root), []);
  }
});

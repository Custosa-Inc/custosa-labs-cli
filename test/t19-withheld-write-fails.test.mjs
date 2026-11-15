/* keepWithheld when the write itself fails (withheld-notes.test.mjs covers links and bounds): a folder it can't write,
 * a .gitignore it can't add, and a rename that fails. Each returns false, keeps the notes already held, and leaves no
 * temp file. The rename failure is forced with a node:test mock on fs. Temp folders only. */
import { test, mock } from "node:test";
import assert from "node:assert/strict";
import fs, { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, realpathSync } from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { keepWithheld, readWithheld } from "../lib/inspector/withheld.mjs";

const temp = () => realpathSync(mkdtempSync(join(tmpdir(), "t19-withheld-")));
const T0 = Date.parse("2026-11-06T18:00:00Z");
const entry = (i) => ({ session: "ps_abcdefghijklmnopqrstuv", field: `verdicts[${i}].note`, practice_id: "rls-forced",
  rules: ["name_pair"], note: `note ${i}` });
const noPermissions = process.platform === "win32" || process.getuid?.() === 0; // chmod doesn't stop root or Windows

/* A root that already holds one note. */
function heldRoot() {
  const root = temp();
  assert.equal(keepWithheld(root, [entry(0)], { now: T0 }), true);
  return root;
}
const local = (root) => join(root, ".custosa/local");
const temps = (root) => readdirSync(local(root)).filter((f) => f.endsWith(".custosa-tmp"));

test("a .custosa/local it can't write: false, the held note stays, no temp file", { skip: noPermissions }, () => {
  const root = heldRoot();
  chmodSync(local(root), 0o500);
  try {
    assert.equal(keepWithheld(root, [entry(1)], { now: T0 + 1000 }), false);
  } finally { chmodSync(local(root), 0o700); }
  assert.deepEqual(readWithheld(root).map((e) => e.note), ["note 0"]);
  assert.deepEqual(temps(root), []);
});

test("a .custosa it can't add .gitignore to: false, and nothing is written", { skip: noPermissions }, () => {
  const root = temp();
  mkdirSync(local(root), { recursive: true });
  chmodSync(join(root, ".custosa"), 0o500);
  try {
    assert.equal(keepWithheld(root, [entry(0)], { now: T0 }), false);
  } finally { chmodSync(join(root, ".custosa"), 0o700); }
  assert.equal(existsSync(join(root, ".custosa/.gitignore")), false);
  assert.deepEqual(readdirSync(local(root)), []);
});

test("a rename that fails: false, the held note stays, and the temp file is removed", () => {
  const root = heldRoot();
  const real = fs.renameSync;
  mock.method(fs, "renameSync", (from, to) => {
    if (String(from).endsWith(".custosa-tmp")) throw Object.assign(new Error("forced"), { code: "EIO" });
    return real(from, to);
  });
  syncBuiltinESMExports();
  try {
    assert.equal(keepWithheld(root, [entry(1)], { now: T0 + 1000 }), false);
  } finally { mock.restoreAll(); syncBuiltinESMExports(); }
  assert.deepEqual(readWithheld(root).map((e) => e.note), ["note 0"]);
  assert.deepEqual(temps(root), []);
  // The next write works and keeps both.
  assert.equal(keepWithheld(root, [entry(1)], { now: T0 + 2000 }), true);
  assert.deepEqual(readWithheld(root).map((e) => e.note), ["note 0", "note 1"]);
});

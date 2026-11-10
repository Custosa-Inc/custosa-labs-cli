/* T29 conventions audit row B4: a failed read never rewrites a record. .custosa/local/withheld.jsonl and concerns.json
 * are read, added to and written whole, so a read that fails must leave the file as it is, not replace it with only
 * this call's entries. No file yet is not a failed read. Temp folders only. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { keepWithheld, readWithheld, WITHHELD_FILE } from "../lib/inspector/withheld.mjs";
import { CONCERN_NOTES, CONCERNS_FILE, forgetRefused, readTexts, rememberRaised } from "../lib/inspector/concerns.mjs";

const temp = () => realpathSync(mkdtempSync(join(tmpdir(), "local-state-")));
const T0 = Date.parse("2026-11-10T09:00:00Z");
const entry = { session: "ps_abcdefghijklmnopqrstuv", field: "verdicts[0].note", rules: ["name_pair"], note: "new note" };
const OLD = `${JSON.stringify({ at: "2026-11-09T09:00:00.000Z", session: "ps_abcdefghijklmnopqrstuv", field: "concerns[0].note",
  rules: ["name_pair"], note: "kept earlier" })}\n`;
const META = { category: "logging", area: "logging", file_kind: "server_module", proposed_severity: "medium" };
const ID = "cn_00000000000000c3";
const RAISED = { concerns: [{ concern_id: ID, ...META, raised_now: true }] };
const SENT = [{ ...META, note: "Failed sign-ins are not recorded anywhere the team can read." }];

function local(root, name, body) {
  mkdirSync(join(root, ".custosa/local"), { recursive: true });
  const file = join(root, ".custosa/local", name);
  writeFileSync(file, body);
  return file;
}

test("withheld: a file that can't be read is left as it is, and keepWithheld says false", { skip: process.getuid?.() === 0 }, () => {
  const root = temp();
  const file = local(root, WITHHELD_FILE, OLD);
  chmodSync(file, 0o200);
  try {
    assert.equal(keepWithheld(root, [entry], { now: T0 }), false);
  } finally { chmodSync(file, 0o600); }
  assert.equal(readFileSync(file, "utf8"), OLD);
});

test("withheld: a file past the size cap is not rewritten from nothing", () => {
  const root = temp();
  const big = OLD.repeat(Math.ceil((4 * 1024 * 1024 + 1) / OLD.length));
  const file = local(root, WITHHELD_FILE, big);
  assert.deepEqual(readWithheld(root), []);
  assert.equal(keepWithheld(root, [entry], { now: T0 }), false);
  assert.equal(readFileSync(file, "utf8"), big);
});

test("withheld: a folder in the file's place is not replaced", () => {
  const root = temp();
  mkdirSync(join(root, ".custosa/local", WITHHELD_FILE), { recursive: true });
  assert.equal(keepWithheld(root, [entry], { now: T0 }), false);
});

test("withheld: no file yet is written, and a readable one keeps what it held", () => {
  const root = temp();
  assert.equal(keepWithheld(root, [entry], { now: T0 }), true);
  const other = temp();
  local(other, WITHHELD_FILE, OLD);
  assert.equal(keepWithheld(other, [entry], { now: T0 }), true);
  assert.deepEqual(readWithheld(other).map((e) => e.note), ["kept earlier", "new note"]);
});

for (const [name, body] of [
  ["not JSON", "{\"version\":1,\"concerns\":{\"cn_00000000000000a1\":{\"text\":\"cut off"],
  ["another version", `${JSON.stringify({ version: 2, concerns: { cn_00000000000000a1: { text: "kept earlier" } } })}\n`],
  ["past the size cap", `${JSON.stringify({ version: 1, concerns: {}, pad: "x".repeat(4 * 1024 * 1024) })}\n`],
]) {
  test(`concerns: a file that is ${name} is left as it is, and the call says so`, () => {
    const root = temp();
    const file = local(root, CONCERNS_FILE, body);
    const out = rememberRaised(root, SENT, RAISED);
    assert.deepEqual(out, { note: CONCERN_NOTES.concern_texts_unread, pending: null });
    assert.equal(readFileSync(file, "utf8"), body);
    forgetRefused(root, { concern_outcomes: [{ concern_id: ID, outcome: "refused", reason: "unknown_concern" }] });
    assert.equal(readFileSync(file, "utf8"), body);
    assert.equal(readTexts(root).size, 0);
  });
}

test("concerns: a file that can't be read is left as it is", { skip: process.getuid?.() === 0 }, () => {
  const root = temp();
  const body = `${JSON.stringify({ version: 1, concerns: { cn_00000000000000a1: { text: "kept earlier" } } })}\n`;
  const file = local(root, CONCERNS_FILE, body);
  chmodSync(file, 0o200);
  try {
    assert.equal(rememberRaised(root, SENT, RAISED).note, CONCERN_NOTES.concern_texts_unread);
  } finally { chmodSync(file, 0o600); }
  assert.equal(readFileSync(file, "utf8"), body);
});

test("concerns: no file yet is written, and a readable one keeps what it held", () => {
  const root = temp();
  assert.deepEqual(rememberRaised(root, SENT, RAISED), { note: null, pending: null });
  assert.deepEqual([...readTexts(root).keys()], [ID]);
  const other = temp();
  local(other, CONCERNS_FILE, `${JSON.stringify({ version: 1, concerns: { cn_00000000000000a1: { text: "kept earlier" } } })}\n`);
  assert.deepEqual(rememberRaised(other, SENT, RAISED), { note: null, pending: null });
  assert.deepEqual([...readTexts(other).keys()], ["cn_00000000000000a1", ID]);
});

test("concerns: when .custosa/local is a plain file, the note says to move it, and it is left as it is", () => {
  const root = temp();
  mkdirSync(join(root, ".custosa"));
  const file = join(root, ".custosa/local");
  writeFileSync(file, "not a folder\n");
  const out = rememberRaised(root, SENT, RAISED);
  assert.deepEqual(out, { note: CONCERN_NOTES.concern_texts_unread, pending: null });
  assert.match(out.note, /\.custosa\/local itself, if it is a file/);
  assert.equal(readFileSync(file, "utf8"), "not a folder\n");
});

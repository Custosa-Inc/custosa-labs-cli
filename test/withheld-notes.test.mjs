/* Screening design §8 and §13 item 16: a note the CLI withholds on the third refusal is kept only on this
 * computer, in .custosa/local/withheld.jsonl: mode 0600, at most 200 entries and none older than 30 days (the oldest go
 * first), written whole through a temp file and a rename, never through a symlink. Temp folders only. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { lstatSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { keepWithheld, readWithheld, WITHHELD_FILE, MAX_WITHHELD, WITHHELD_DAYS } from "../lib/inspector/withheld.mjs";

const temp = () => realpathSync(mkdtempSync(join(tmpdir(), "withheld-")));
const DAY = 86_400_000;
const T0 = Date.parse("2026-11-06T18:00:00Z");
const entry = (i, extra = {}) => ({ session: "ps_abcdefghijklmnopqrstuv", field: `verdicts[${i}].note`, practice_id: "rls-forced",
  rules: ["name_pair"], note: `note ${i}`, ...extra });

test("the bounds are the design's", () => {
  assert.equal(WITHHELD_FILE, "withheld.jsonl");
  assert.equal(MAX_WITHHELD, 200);
  assert.equal(WITHHELD_DAYS, 30);
});

test("a withheld note is kept as one JSON line with its time, mode 0600, and .custosa/.gitignore leaves it out of git", () => {
  const root = temp();
  assert.equal(keepWithheld(root, [entry(0), entry(1)], { now: T0 }), true);
  const file = join(root, ".custosa/local", WITHHELD_FILE);
  assert.equal(lstatSync(file).mode & 0o777, 0o600);
  assert.equal(readFileSync(join(root, ".custosa/.gitignore"), "utf8"), "local/\n*.custosa-tmp\n");
  const lines = readFileSync(file, "utf8").trimEnd().split("\n");
  assert.equal(lines.length, 2);
  assert.deepEqual(JSON.parse(lines[0]), { at: "2026-11-06T18:00:00.000Z", ...entry(0) });
  assert.deepEqual(readWithheld(root).map((e) => e.note), ["note 0", "note 1"]);
});

test("past 200 entries the oldest go first, and an entry older than 30 days is dropped at the next write", () => {
  const root = temp();
  keepWithheld(root, [entry(0, { note: "old" })], { now: T0 - 31 * DAY });
  keepWithheld(root, [entry(1, { note: "recent" })], { now: T0 - 29 * DAY });
  keepWithheld(root, Array.from({ length: 199 }, (_, i) => entry(i, { note: `n${i}` })), { now: T0 });
  const kept = readWithheld(root);
  assert.equal(kept.length, 200);
  assert.equal(kept[0].note, "recent");
  assert.ok(!kept.some((e) => e.note === "old"));
  keepWithheld(root, [entry(0, { note: "newest" })], { now: T0 + 1 });
  const again = readWithheld(root);
  assert.equal(again.length, 200);
  assert.equal(again[0].note, "n0");
  assert.equal(again.at(-1).note, "newest");
});

test("a symlinked .custosa/local or file is never written through, and an unreadable file reads as empty", () => {
  const root = temp();
  const elsewhere = temp();
  mkdirSync(join(root, ".custosa"), { recursive: true });
  symlinkSync(elsewhere, join(root, ".custosa/local"));
  assert.equal(keepWithheld(root, [entry(0)], { now: T0 }), false);
  assert.deepEqual(readWithheld(root), []);
  const other = temp();
  mkdirSync(join(other, ".custosa/local"), { recursive: true });
  writeFileSync(join(other, ".custosa/local", WITHHELD_FILE), "not json\n{\"at\":1}\n");
  assert.deepEqual(readWithheld(other), []);
  assert.equal(keepWithheld(other, [entry(0)], { now: T0 }), true);
  assert.deepEqual(readWithheld(other).map((e) => e.note), ["note 0"]);
});

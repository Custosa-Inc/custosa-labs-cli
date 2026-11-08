/* Screening design §13 items 1 and 19 (docs/screen-engine.md §3.1): the CLI reads a fact document's snapshot
 * ids as core's app.core.snapshot.ids reads them, so a backticked name the CLI moves into refs is one core binds.
 * fixtures/snapshot-ids.json holds a hand-made document that reaches each branch, and three corpus documents, each with
 * the ids the evaluator gave for it. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { snapshotIds } from "../lib/inspector/snapshot.mjs";

const FIXTURE = JSON.parse(readFileSync(new URL("./fixtures/snapshot-ids.json", import.meta.url), "utf8"));

test("snapshot ids equal core's on each fixture document", () => {
  assert.equal(FIXTURE.cases.length, 4);
  for (const c of FIXTURE.cases) assert.deepEqual([...snapshotIds(c.document)].sort(), c.ids, c.name);
});

test("a setting's value and a non-string are never ids; a line range of one line reads as that line", () => {
  const ids = snapshotIds({ platform: { settings: { jwt_expiry: "3600" } }, matches: [{ path: "a.ts", line_start: 5, line_end: 5 },
    { path: "b.ts", line: 2.5 }, { path: "c.ts", line_start: 1, line_end: null }] });
  assert.ok(!ids.has("3600"));
  assert.ok(ids.has("a.ts:5") && !ids.has("a.ts:5-5"));
  assert.ok(!ids.has("b.ts:2.5") && !ids.has("c.ts:1"));
});

/* npm run test:blackbox: resources.test.mjs runs on its own after the other black-box files, so its
 * time-limit cases don't share the CPU with the database tests. Under --test-concurrency=2 on a CI runner, its 20,000
 * match case once ran only 9 files before its time limit (run 41812409438, attempt 1). */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { blackboxRuns } from "../scripts/test-blackbox.mjs";

const DIR = fileURLToPath(new URL("./blackbox/", import.meta.url));
const FILES = readdirSync(DIR).filter((f) => f.endsWith(".test.mjs"));

test("resources.test.mjs runs alone, after every other black-box file", () => {
  const runs = blackboxRuns(FILES);
  assert.equal(runs.length, 2);
  assert.deepEqual(runs[1].files, ["test/blackbox/resources.test.mjs"]);
  assert.ok(!runs[0].files.includes("test/blackbox/resources.test.mjs"));
  assert.deepEqual(runs.map((r) => r.concurrency), [2, 1]);
});

test("every black-box file is in exactly one run", () => {
  const all = blackboxRuns(FILES).flatMap((r) => r.files).sort();
  assert.deepEqual(all, FILES.map((f) => `test/blackbox/${f}`).sort());
});

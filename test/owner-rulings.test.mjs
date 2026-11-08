import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

/* Owner rulings the website's tests checked in this CLI's files before the split. They hold here now. */
const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
const shared = JSON.parse(read("lib/shared.json"));

/* D10: check first, fix on request. The try prompt runs the check and asks before any change. */
test("the try prompt is the check-first one (D10)", () => {
  assert.equal(
    shared.tryPrompt,
    "Use PHI Schema Check to review how this app handles patient data. Run the check through to the end on your own and answer the questions you can from the code. Then show me the readiness score, the findings and the decisions only I can make, and ask me before you change any code or database.",
  );
});

/* D8: no line that sells letting the check run without stopping for permission. */
test("setup output and README drop the run-without-stopping pitch (D8)", () => {
  for (const path of ["lib/setup.mjs", "README.md"]) {
    assert.doesNotMatch(read(path), /without stopping for permission/i, path);
  }
});

/* D7: a call costs the units its work used, top-ups start at $5 with no maximum, and no estimate is shown. */
test("the price has a $5 minimum top-up and no per-call minimum, maximum or estimate (D7)", () => {
  assert.equal(shared.price.minTopUpUsd, 5);
  for (const gone of ["minUnits", "maxTopUpUsd", "typicalLowUsd", "typicalHighUsd"]) {
    assert.equal(Object.hasOwn(shared.price, gone), false, gone);
  }
});

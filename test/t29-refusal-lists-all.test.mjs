/* T29-P1-C204 item 4 (P2 live look 1, L2). A refusal now names every refused field the assistant wrote: the first in
 * at, the rest in also. This inspector reads such an answer and passes it on whole, never as unreadable. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { checkEvaluateAnswer } from "../lib/inspector/client.mjs";

const BASE = { error: "invalid_fact_document", next_step: "x", correlation_id: "corr_12345678", at: "/verdicts/0/reason_code" };
const ALSO = [{ at: "/verdicts/1/practice_id", next_step: "y" }, { at: "/verdicts/3/refs/0", next_step: "z" }];

test("a refusal with also is read and passed on whole", () => {
  const body = { ...BASE, also: ALSO };
  assert.deepEqual(checkEvaluateAnswer(400, structuredClone(body)), { ok: false, body });
});

test("also needs at, at most 20 entries, and only at and next_step in each", () => {
  const { at, ...noAt } = BASE;
  assert.equal(checkEvaluateAnswer(400, { ...noAt, error: "internal_error", also: ALSO }), null);
  assert.equal(checkEvaluateAnswer(400, { ...BASE, also: Array(21).fill(ALSO[0]) }), null);
  assert.equal(checkEvaluateAnswer(400, { ...BASE, also: [{ ...ALSO[0], value: "v" }] }), null);
  assert.equal(checkEvaluateAnswer(400, { ...BASE, also: [] }), null);
});

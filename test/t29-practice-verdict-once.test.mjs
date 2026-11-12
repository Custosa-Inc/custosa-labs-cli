/* T29 practice-verdict-once (LL5 L1, T29-P1-C271 (a)). An assistant verdict is practice-level, so one fail verdict
 * fails every line of its practice; on POLABDC one verdict on phi-responses-not-cached made 32 of 50 fails. The counts
 * stay per line. Core's index names each practice whose fails are all that one verdict, in
 * result_counts.fail_by_practice_verdict, and the text the assistant reads says so, as the headline does.
 * T29-P1-C287 item 2: the failing count counts each such verdict once (result_counts.fail_counting_verdicts_once), and
 * the text says how many lines that is; every line is still listed. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { textFor } from "../lib/inspector/server.mjs";
import { validateResponse } from "../lib/inspector/schema.mjs";
import { EVALUATE_OK } from "./stub-evaluator.mjs";

const COUNTS = (extra = {}) => ({
  by_state: { pass: 0, fail: 50, not_applicable: 0, needs_review: 0, unknown: 0, error: 0 }, by_severity: { high: 50 },
  by_state_and_severity: [{ state: "fail", severity: "high", count: 50 }], ...extra });
const INDEX = (counts) => ({ result_counts: counts, practices: [], fails: [], open: [], questions: [], concerns: [],
  fixes: [], lists: [] });
const NAMED = [{ practice_id: "phi-responses-not-cached", count: 32 }, { practice_id: "rls-enabled", count: 5 }];

test("the failing count counts each verdict once, and the text names each one and its lines", () => {
  const text = textFor({ ...EVALUATE_OK, index: INDEX(COUNTS({ fail_by_practice_verdict: NAMED,
    fail_counting_verdicts_once: 15 })) }, { full: false });
  assert.match(text, /15 failing \(50 lines\)/);
  assert.match(text, /^Failing counts each assistant verdict once: 32 lines are one verdict on phi-responses-not-cached, 5 one verdict on rls-enabled \(fail_by_practice_verdict\)\. All 50 failing lines are listed\.$/m);
});

test("an older index without the counted-once total keeps the per-line count", () => {
  const text = textFor({ ...EVALUATE_OK, index: INDEX(COUNTS({ fail_by_practice_verdict: NAMED })) }, { full: false });
  assert.match(text, /50 failing,/);
  assert.match(text, /^Of the 50 failing, 32 are one verdict on phi-responses-not-cached, 5 one verdict on rls-enabled: the assistant's one verdict on a practice, counted on each of its lines \(fail_by_practice_verdict\)\.$/m);
});

test("with none named, the text says nothing of verdicts", () => {
  const text = textFor({ ...EVALUATE_OK, index: INDEX(COUNTS()) }, { full: false });
  assert.doesNotMatch(text, /one verdict|fail_by_practice_verdict/);
});

test("the response schema takes fail_by_practice_verdict, and refuses a count under 2 or an empty list", () => {
  const body = (named) => ({ ...EVALUATE_OK, index: INDEX(COUNTS({ fail_by_practice_verdict: named })) });
  assert.equal(validateResponse(body(NAMED)), null);
  assert.notEqual(validateResponse(body([{ practice_id: "rls-enabled", count: 1 }])), null);
  assert.notEqual(validateResponse(body([])), null);
  assert.notEqual(validateResponse(body([{ practice_id: "rls-enabled", count: 2, lines: [] }])), null);
  const once = (n) => ({ ...EVALUATE_OK, index: INDEX(COUNTS({ fail_by_practice_verdict: NAMED, fail_counting_verdicts_once: n })) });
  assert.equal(validateResponse(once(15)), null);
  assert.notEqual(validateResponse(once(0)), null);
});

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

// T29-P1-C310 item 7: each named practice's own fail lines, which the CLI checks the named counts against
const PRACTICE = (practice_id, fail) => ({ practice_id, state: "fail", severity: "high", counts: { fail } });
const OWN = [PRACTICE("phi-responses-not-cached", 32), PRACTICE("rls-enabled", 5), PRACTICE("audit-log", 13)];
const COUNTS = (extra = {}) => ({
  by_state: { pass: 0, fail: 50, not_applicable: 0, needs_review: 0, unknown: 0, error: 0 }, by_severity: { high: 50 },
  by_state_and_severity: [{ state: "fail", severity: "high", count: 50 }], ...extra });
const INDEX = (counts, practices = OWN) => ({ result_counts: counts, practices, fails: [], open: [], questions: [],
  concerns: [], fixes: [], lists: [] });
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
  const body = (named) => ({ ...EVALUATE_OK, index: INDEX(COUNTS({ fail_by_practice_verdict: named, fail_counting_verdicts_once: 3 })) });
  assert.equal(validateResponse(body(NAMED)), null);
  assert.notEqual(validateResponse(body([{ practice_id: "rls-enabled", count: 1 }])), null);
  assert.notEqual(validateResponse(body([])), null);
  assert.notEqual(validateResponse(body([{ practice_id: "rls-enabled", count: 2, lines: [] }])), null);
  // T29-P1-C299 item 9: the two fields come as a pair
  assert.notEqual(validateResponse({ ...EVALUATE_OK, index: INDEX(COUNTS({ fail_by_practice_verdict: NAMED })) }), null);
  assert.notEqual(validateResponse({ ...EVALUATE_OK, index: INDEX(COUNTS({ fail_counting_verdicts_once: 15 })) }), null);
  const once = (n) => ({ ...EVALUATE_OK, index: INDEX(COUNTS({ fail_by_practice_verdict: NAMED, fail_counting_verdicts_once: n })) });
  assert.equal(validateResponse(once(15)), null);
  assert.notEqual(validateResponse(once(0)), null);
});

// T29-P1-C299 item 9: the CLI checks the counted-once total against the lines it names, and says so when they differ.
test("a counted-once total that doesn't match its lines keeps the per-line count and says why", () => {
  const text = textFor({ ...EVALUATE_OK, index: INDEX(COUNTS({ fail_by_practice_verdict: NAMED,
    fail_counting_verdicts_once: 14 })) }, { full: false });
  assert.match(text, /50 failing,/);
  assert.doesNotMatch(text, /14 failing/);
  assert.match(text, /^The evaluator's counted-once total \(fail_counting_verdicts_once 14\) doesn't match its lines: 50 failing lines less 31 and 4 for the verdicts named is 15\. Read failing per line\.$/m);
});

test("a counted-once total with no verdict named keeps the per-line count", () => {
  const text = textFor({ ...EVALUATE_OK, index: INDEX(COUNTS({ fail_counting_verdicts_once: 15 })) }, { full: false });
  assert.match(text, /50 failing,/);
  assert.match(text, /doesn't match its lines/);
});

// T29-P1-C299 item 10: with the fails grouped, the text says where the lines are and how to read them.
test("grouped fails say the lines are in fails_grouped, read by each group's selector", () => {
  const index = { ...INDEX(COUNTS({ fail_by_practice_verdict: NAMED, fail_counting_verdicts_once: 15 })),
    fails_grouped: [{ practice_id: "phi-responses-not-cached", count: 32, select: { practice_id: "phi-responses-not-cached", state: "fail" } }] };
  const text = textFor({ ...EVALUATE_OK, index }, { full: false });
  assert.doesNotMatch(text, /All 50 failing lines are listed\./);
  assert.match(text, /All 50 failing lines are listed by practice in fails_grouped: read each group's lines with get_result and its select\./);
});

// T29-P1-C310 item 7: the total is taken only when each named practice's count is its own fail lines, and no practice is
// named twice; the lines arithmetic alone can't tell a count that belongs to another practice.
test("a named count that differs from its practice's own fail lines keeps the per-line count and says why", () => {
  const own = [PRACTICE("phi-responses-not-cached", 8), PRACTICE("rls-enabled", 5), PRACTICE("audit-log", 37)];
  const text = textFor({ ...EVALUATE_OK, index: INDEX(COUNTS({ fail_by_practice_verdict: NAMED,
    fail_counting_verdicts_once: 15 }), own) }, { full: false });
  assert.match(text, /50 failing,/);
  assert.doesNotMatch(text, /15 failing/);
  assert.match(text, /^The evaluator's counted-once total \(fail_counting_verdicts_once 15\) names verdicts whose lines aren't their practice's own: phi-responses-not-cached names 32, has 8\. Read failing per line\.$/m);
});

test("a practice named twice keeps the per-line count", () => {
  const twice = [{ practice_id: "rls-enabled", count: 5 }, { practice_id: "rls-enabled", count: 5 }];
  const text = textFor({ ...EVALUATE_OK, index: INDEX(COUNTS({ fail_by_practice_verdict: twice,
    fail_counting_verdicts_once: 42 })) }, { full: false });
  assert.match(text, /50 failing,/);
  assert.match(text, /rls-enabled is named twice/);
});

test("with no practice list, the fails listed by practice are its own lines", () => {
  const fails = [...Array(32)].map((_, i) => ({ finding: `f${i}`, practice_id: "phi-responses-not-cached", object: `o${i}` }))
    .concat([...Array(5)].map((_, i) => ({ finding: `r${i}`, practice_id: "rls-enabled", object: `p${i}` })))
    .concat([...Array(13)].map((_, i) => ({ finding: `a${i}`, practice_id: "audit-log", object: `q${i}` })));
  const index = { ...INDEX(COUNTS({ fail_by_practice_verdict: NAMED, fail_counting_verdicts_once: 15 }), []), fails };
  assert.match(textFor({ ...EVALUATE_OK, index }, { full: false }), /15 failing \(50 lines\)/);
  const none = INDEX(COUNTS({ fail_by_practice_verdict: NAMED, fail_counting_verdicts_once: 15 }), []);
  assert.match(textFor({ ...EVALUATE_OK, index: none }, { full: false }), /50 failing,/);
});

/* T29-P1-C204 item 3 (P2 live look 1, L3). The evaluator names each decided verdict that settled nothing
 * (verdicts_unsettled); the response schema takes it, and the text the assistant reads says so before the index. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { textFor } from "../lib/inspector/server.mjs";
import { validateResponse } from "../lib/inspector/schema.mjs";
import { EVALUATE_OK } from "./stub-evaluator.mjs";

const HOW = "Your assistant's verdict didn't settle this: a pass or not applicable needs refs naming the file, line, table or setting it rests on, one the check gave out or cited. It stays open, with the verdict beside it.";
const ITEM = { practice_id: "audit-log", state: "not_applicable", reason: "No such feature in this project.", why: "no_bound_ref", lines: 3, how: HOW };

test("the response schema takes verdicts_unsettled and refuses an unknown why", () => {
  assert.equal(validateResponse({ ...EVALUATE_OK, verdicts_unsettled: [ITEM] }), null);
  assert.notEqual(validateResponse({ ...EVALUATE_OK, verdicts_unsettled: [{ ...ITEM, why: "other" }] }), null);
  assert.notEqual(validateResponse({ ...EVALUATE_OK, verdicts_unsettled: [] }), null);
});

test("the text names each unsettled verdict with why and the lines' words", () => {
  const text = textFor({ ...EVALUATE_OK, verdicts_unsettled: [ITEM, { ...ITEM, practice_id: "mfa", state: "pass", why: "rules_saw_nothing", lines: 1 }] }, { full: false });
  assert.match(text, /2 verdicts settled nothing \(verdicts_unsettled\), by why:\n- no_bound_ref, 1 practice: audit-log not_applicable \(3 lines\)\. Your assistant's verdict/); // one line per why since T29-P1-C211 item 2
  assert.match(text, /^- rules_saw_nothing, 1 practice: mfa pass \(1 line\)\./m);
  assert.doesNotMatch(textFor(EVALUATE_OK, { full: false }), /settled nothing/);
});

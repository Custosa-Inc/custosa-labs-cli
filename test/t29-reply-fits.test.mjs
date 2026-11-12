/* T29-P1-C253 (live look 5 M1). After its verdict call, delivery-ticket-os's check replies were about 65,000
 * characters, past what the MCP client shows whole, so the assistant never read them. Core now sends
 * verdicts_unsettled only on the reply to the call that sent verdicts, its entries without their how, and each how
 * once by why in unsettled_how; the whole entries are the named list verdicts_unsettled, which get_result reads. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { textFor } from "../lib/inspector/server.mjs";
import { RESULT_INPUT_SCHEMA } from "../lib/inspector/tool.mjs";
import { EVALUATE_OK } from "./stub-evaluator.mjs";

const SAW_NOTHING = "Your assistant's verdict didn't settle this: Custosa's rules matched nothing here, or never ran.";
const REFUSED = "Your assistant's verdict didn't settle this: what the check observed here contradicts it.";
const ENTRIES = [
  { practice_id: "access-audit-log", state: "pass", reason: "In place.", why: "rules_saw_nothing", lines: 2 },
  { practice_id: "ai-log-encryption", state: "not_applicable", reason: "Not used.", why: "rules_saw_nothing", lines: 1 },
  { practice_id: "mobile-keychain-storage", state: "not_applicable", reason: "Not used.", why: "refused", lines: 1 },
];
const count = (text, s) => text.split(s).length - 1;

test("the text takes each how from unsettled_how, once per why, with every practice under it", () => {
  const text = textFor({ ...EVALUATE_OK, verdicts_unsettled: ENTRIES,
    unsettled_how: { refused: REFUSED, rules_saw_nothing: SAW_NOTHING } }, { full: false });
  assert.match(text, /3 verdicts settled nothing \(verdicts_unsettled\), by why:/);
  assert.match(text, /^- rules_saw_nothing, 2 practices: access-audit-log pass \(2 lines\), ai-log-encryption not_applicable \(1 line\)\. Your assistant's verdict didn't settle this: Custosa's rules/m);
  assert.match(text, /^- refused, 1 practice: mobile-keychain-storage not_applicable \(1 line\)\. Your assistant's verdict didn't settle this: what the check/m);
  for (const how of [SAW_NOTHING, REFUSED]) assert.equal(count(text, how), 1, how);
  assert.doesNotMatch(text, /undefined/);
});

test("an entry that still carries its own how reads as before", () => {
  const text = textFor({ ...EVALUATE_OK, verdicts_unsettled: [{ ...ENTRIES[2], how: REFUSED }] }, { full: false });
  assert.match(text, /^- refused, 1 practice: mobile-keychain-storage not_applicable \(1 line\)\. Your assistant's verdict/m);
});

test("get_result takes the list verdicts_unsettled and one entry of it", () => {
  const pattern = new RegExp(RESULT_INPUT_SCHEMA.properties.select.properties.list.pattern);
  for (const name of ["verdicts_unsettled", "verdicts_unsettled#12"]) assert.ok(pattern.test(name), name);
  assert.ok(!pattern.test("verdicts_unsettled.x"));
});

/* T29-P1-C211 item 2 (P2's C216 low 1). The text the assistant reads named each unsettled verdict with its how,
 * so one how was repeated for every practice it held: 9 times for rules_saw_nothing on delivery-ticket-os, about
 * 4 KB of an 8 KB summary. Each how is said once per why now, with the practices under it.
 * The shape below is that replay's last call (P2 C216): 13 verdicts, 9 rules_saw_nothing, 3 refused and
 * 1 fail_observed, 12 not_applicable and 1 pass. Five practice ids are the replay's; the other eight stand in for
 * ids P2 did not list. The hows are core's words (app/core/respond.py UNSETTLED_WHY). */
import { test } from "node:test";
import assert from "node:assert/strict";
import { textFor } from "../lib/inspector/server.mjs";
import { EVALUATE_OK } from "./stub-evaluator.mjs";

const SAW_NOTHING = "Your assistant's verdict didn't settle this: Custosa's rules matched nothing here, or never ran, so nothing it read stands behind a pass or not applicable. A not applicable verdict whose refs name the file, line or table it rests on settles as your assistant's word. Otherwise a person decides, sending their option with decider_ref, a listed role or the CLI's local reference, never a name. It stays open, with the verdict beside it.";
const REFUSED = "Your assistant's verdict didn't settle this: what the check observed here contradicts it, or its code couldn't be checked. It stays open, with the verdict beside it.";
const FAIL_OBSERVED = "Your assistant's verdict didn't change this: the check observed this fail, and an assistant's word never clears an observed fail. It stays a fail, with the verdict beside it.";
const HOW = { rules_saw_nothing: SAW_NOTHING, refused: REFUSED, fail_observed: FAIL_OBSERVED };

const ROWS = [
  ["access-audit-log", "not_applicable", "rules_saw_nothing", 2],
  ["ai-agent-tools-least-privilege", "not_applicable", "refused", 1],
  ["ai-log-encryption", "not_applicable", "rules_saw_nothing", 1],
  ["ai-log-retention", "not_applicable", "rules_saw_nothing", 1],
  ["audit-log-append-only", "not_applicable", "rules_saw_nothing", 3],
  ["break-glass-access", "not_applicable", "rules_saw_nothing", 1],
  ["client-storage-no-phi", "pass", "rules_saw_nothing", 1],
  ["embedding-text-copies", "not_applicable", "rules_saw_nothing", 1],
  ["firestore-rules-owner-scoped", "not_applicable", "refused", 2],
  ["mobile-keychain-storage", "not_applicable", "refused", 1],
  ["mobile-screen-privacy", "not_applicable", "rules_saw_nothing", 1],
  ["no-phi-in-ai-metadata", "not_applicable", "rules_saw_nothing", 1],
  ["rag-retrieval-scoped", "not_applicable", "fail_observed", 1],
];
const UNSETTLED = ROWS.map(([practice_id, state, why, lines]) => ({
  practice_id, state, reason: state === "pass" ? "Stored client data holds no PHI." : "No such feature in this project.",
  why, lines, how: HOW[why],
}));

const count = (text, s) => text.split(s).length - 1;
const unsettledPart = (text) => text.split("\n").filter((l) => /settled nothing|^- (rules_saw_nothing|refused|fail_observed)/.test(l)).join("\n");

test("delivery-ticket-os's 13 unsettled verdicts: each how once, every practice named under its why", () => {
  const text = textFor({ ...EVALUATE_OK, verdicts_unsettled: UNSETTLED }, { full: false });
  for (const how of [SAW_NOTHING, REFUSED, FAIL_OBSERVED]) assert.equal(count(text, how), 1, how.slice(0, 60));
  assert.match(text, /13 verdicts settled nothing \(verdicts_unsettled\), by why:/);
  assert.match(text, /^- rules_saw_nothing, 9 practices: .*access-audit-log not_applicable \(2 lines\).*client-storage-no-phi pass \(1 line\)/m);
  assert.match(text, /^- refused, 3 practices: .*firestore-rules-owner-scoped not_applicable \(2 lines\)/m);
  assert.match(text, /^- fail_observed, 1 practice: rag-retrieval-scoped not_applicable \(1 line\)\. Your assistant's verdict didn't change this/m);
  for (const [id] of ROWS) assert.equal(count(text, `${id} `), 1, id);
  // the old text spent about 5 KB here (9 x 434 characters for rules_saw_nothing alone); one how per why is under 2 KB
  assert.ok(unsettledPart(text).length < 2000, `${unsettledPart(text).length} characters`);
});

test("two hows under one why stay two groups, so no how is dropped", () => {
  const other = "Some other words for the same why.";
  const text = textFor({ ...EVALUATE_OK, verdicts_unsettled: [UNSETTLED[0], { ...UNSETTLED[2], how: other }] }, { full: false });
  assert.equal(count(text, SAW_NOTHING), 1);
  assert.equal(count(text, other), 1);
  assert.match(text, /^- rules_saw_nothing, 1 practice: access-audit-log not_applicable \(2 lines\)\./m);
  assert.match(text, /^- rules_saw_nothing, 1 practice: ai-log-encryption not_applicable \(1 line\)\. Some other words/m);
});

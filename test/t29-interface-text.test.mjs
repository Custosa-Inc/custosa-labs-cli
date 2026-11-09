// T29-P1-C7 (harmony brief ranks 2 and 8, the owner's yes of 2026-11-08). Under the HIPAA configuration every word of
// the server instructions and the tool descriptions loads on every turn, and tool choice rides on the description.
// So they are short, say first what the check gives that grep and psql don't, and carry no person-gated imperative:
// consent to change code belongs to the person and the harness, not to text from a tool. In the fullhp rerun "make no
// fixes yet" and "never apply part of it" were ignored every time, and goal fix was never reached.
import { test } from "node:test";
import assert from "node:assert/strict";
import { INSTRUCTIONS, DESCRIPTION, GUIDANCE_DESCRIPTION, PAGE_DESCRIPTION, INPUT_SCHEMA } from "../lib/inspector/tool.mjs";

// Well under the 4,096 characters the brief names, with room for page 1's lines (T29 item 2) beside them.
const BUDGET = 3600;
const GATED = /make no fixes|ask the person|ask before|do you want me to|only after the person|after the person (says|asks)|the person says yes|never apply part|each whole|not your own summary|fixes only after/i;
const flat = (text) => text.replace(/\s+/g, " ");
const firstSentence = (text) => flat(text).split(/(?<=\.) /)[0];

test("the server instructions and the three descriptions fit the budget together", () => {
  const total = INSTRUCTIONS.length + DESCRIPTION.length + GUIDANCE_DESCRIPTION.length + PAGE_DESCRIPTION.length;
  assert.ok(total <= BUDGET, `${total} characters, over ${BUDGET}`);
});

test("no person-gated imperative in the instructions or a description", () => {
  for (const text of [INSTRUCTIONS, DESCRIPTION, GUIDANCE_DESCRIPTION, PAGE_DESCRIPTION]) {
    assert.doesNotMatch(flat(text), GATED);
  }
});

test("the check's description and the instructions open with what grep and psql don't give", () => {
  for (const text of [DESCRIPTION, INSTRUCTIONS.split("\n").slice(1).join("\n")]) {
    const first = firstSentence(text);
    assert.match(first, /grep/, first);
    assert.match(first, /psql/, first);
  }
});

test("a fix is information the assistant may apply in whole or in part", () => {
  assert.match(flat(INSTRUCTIONS), /in whole or in part/);
  // the safety line stays: fixes go to a development database
  assert.match(flat(INSTRUCTIONS), /development database/);
});

test("goal fix takes a finding of the assistant's own, by practice and file location", () => {
  const ids = INPUT_SCHEMA.properties.finding_ids;
  assert.match(ids.description, /practice_id@path:line/);
  assert.match("authz-every-handler@app/api/notes/[id]/route.ts:12", new RegExp(ids.items.pattern));
});

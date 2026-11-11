// T29 line item h, h5 (T29-P3-C305 point 3, P2 C224): the server instructions say the assistant sends facts when
// next_step asks for them. Live look 1 (C208): with the instructions saying "send only the goal, session, answers,
// verdicts and concerns", Claude never sent cited facts, so the cited-fact judge never ran. The core's next step asks
// once per session by candidate and field; the facts input's own description says how to send them.
import { test } from "node:test";
import assert from "node:assert/strict";
import { INSTRUCTIONS, INPUT_SCHEMA } from "../lib/inspector/tool.mjs";

const flat = (text) => text.replace(/\s+/g, " ");

test("the instructions name facts among what check_schema takes, when next_step asks", () => {
  assert.match(flat(INSTRUCTIONS), /send the goal, session, answers, verdicts, concerns, and facts when next_step asks\./);
  assert.doesNotMatch(flat(INSTRUCTIONS), /send only the goal/);
});

test("the facts input still says it is for the lines that name facts_needed", () => {
  assert.match(flat(INPUT_SCHEMA.properties.facts.description), /for the practices whose line names facts_needed/);
});

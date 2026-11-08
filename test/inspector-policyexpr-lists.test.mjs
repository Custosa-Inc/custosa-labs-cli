import test from "node:test";
import assert from "node:assert/strict";
import { policyFields, UNTRUSTED_OWNER_SOURCES, NON_RESTRICTING_OPERATORS } from "../lib/inspector/policyexpr.mjs";

const owner = (using) => {
  const r = policyFields({ command: "select", using, check: null });
  return [r.owner_using, r.owner_source_untrusted];
};

test("every published untrusted owner source reads as the user with unknown trust, in any case", () => {
  assert.deepEqual(UNTRUSTED_OWNER_SOURCES, ["CURRENT_USER", "CURRENT_ROLE", "SESSION_USER", "USER"]);
  for (const s of UNTRUSTED_OWNER_SOURCES) {
    assert.deepEqual(owner(`(owner = ${s})`), [true, "not_read"], s);
    assert.deepEqual(owner(`(owner = ${s.toLowerCase()})`), [true, "not_read"], s.toLowerCase());
  }
  assert.deepEqual(owner("(owner = auth.uid())"), [true, false]); // a trusted source, for contrast
});

test("every published non-restricting operator relates the row to the user without restricting it", () => {
  assert.deepEqual(NON_RESTRICTING_OPERATORS, ["<>", "IS DISTINCT FROM", "<", ">", "<=", ">="]);
  for (const op of [...NON_RESTRICTING_OPERATORS, "!="]) { // != is Postgres's other spelling of <>
    assert.deepEqual(owner(`(user_id ${op} auth.uid())`), [false, false], op);
    if (op !== "IS DISTINCT FROM") assert.deepEqual(owner(`(user_id ${op} ANY (ARRAY[auth.uid()]))`), [false, false], `${op} ANY`);
  }
  assert.deepEqual(owner("(user_id = auth.uid())"), [true, false]);
  assert.deepEqual(owner("(user_id IS NOT DISTINCT FROM auth.uid())"), [true, false]);
  assert.deepEqual(owner("(NOT (user_id IS DISTINCT FROM auth.uid()))"), [true, false]);
});

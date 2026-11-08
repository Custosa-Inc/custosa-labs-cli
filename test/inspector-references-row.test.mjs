/* The evaluator's enums.RLS_PARSED_FIELDS, references_row: whether every expression a policy's command is
 * judged by reads a column of the row. false only for a bare presence or role test, a constant comparison, true, or an
 * absent check; not_read for a subquery or a function whose body isn't read that names no row column, or anything
 * unparsed; true when a row column is read outside them. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { policyFields, POLICY_FIELDS } from "../lib/inspector/policyexpr.mjs";

const T = true, F = false, N = "not_read";

test("references_row is the last parsed field", () => {
  assert.equal(POLICY_FIELDS.at(-1), "references_row");
});

// [name, command, using, check, references_row]
const CASES = [
  ["signed in", "select", "(auth.uid() IS NOT NULL)", null, F],
  ["role test", "select", "(auth.role() = 'authenticated'::text)", null, F],
  ["jwt present", "select", "(auth.jwt() IS NOT NULL)", null, F],
  ["true", "select", "true", null, F],
  ["constant comparison", "select", "(1 = 1)", null, F],
  ["role keyword", "select", "(CURRENT_USER = 'web'::name)", null, F],
  ["owner", "select", "(auth.uid() = user_id)", null, T],
  ["presence and a row filter", "select", "((auth.uid() IS NOT NULL) AND (status = 'open'::text))", null, T],
  ["presence or owner", "select", "((auth.uid() IS NOT NULL) OR (auth.uid() = user_id))", null, T],
  ["a row column in a function's arguments", "select", "public.can_read(id)", null, T],
  ["staff lookup", "select", "(EXISTS ( SELECT 1 FROM staff WHERE (staff.user_id = auth.uid())))", null, N],
  ["unread function, no row column", "select", "public.is_staff()", null, N],
  ["unread function with presence", "select", "((auth.uid() IS NOT NULL) AND public.is_staff())", null, N],
  ["insert check ignores the row", "insert", null, "(auth.uid() IS NOT NULL)", F],
  ["insert owner check", "insert", null, "(auth.uid() = user_id)", T],
  ["all: owner USING, bare check", "all", "(auth.uid() = user_id)", "(auth.uid() IS NOT NULL)", F],
  ["update: owner USING, no check reads USING", "update", "(auth.uid() = user_id)", null, T],
  ["delete: bare USING", "delete", "(auth.uid() IS NOT NULL)", null, F],
  ["unparsed", "select", "((((", null, N],
];

for (const [name, command, using, check, want] of CASES) {
  test(`references_row: ${name}`, () => {
    const got = policyFields({ command, using, check });
    assert.equal(got.references_row, want, `${using} / ${check}`);
    // A comparison is a row column against the session: none can be true where no row column is read. With two
    // expressions, <x>_comparison is their OR, so the other one may still hold it.
    if (got.references_row === F && (using === null || check === null)) for (const f of ["owner_comparison", "tenant_comparison"]) assert.notEqual(got[f], T, f);
  });
}

test("references_row is not_read when no cast can be trusted, and on an unknown command", () => {
  assert.equal(policyFields({ command: "select", using: "(auth.uid() IS NOT NULL)", check: null }, { casts: "unread" }).references_row, N);
  assert.equal(policyFields({ command: "truncate", using: "true", check: null }).references_row, N);
});

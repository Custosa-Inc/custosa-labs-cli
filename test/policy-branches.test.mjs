/* T29 h4b (T29-P3-C215): the scope of each top-level OR branch of a policy's USING, as pg_get_expr prints it, so the
 * evaluator can tell d7 (an owner check OR'd with a condition every signed-in user meets) and d9 (a membership EXISTS
 * that never names the caller) from t4 (the owner, or a listed staff member). The 160-item key's three policies are
 * quoted as Postgres prints them. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { usingBranches, BRANCH_KINDS, MAX_BRANCHES } from "../lib/inspector/policyexpr.mjs";

const D7 = "((author_id = (current_setting('app.current_user_id'::text, true))::uuid) OR ((current_setting('app.current_user_id'::text, true))::uuid IS NOT NULL))";
const D9 = "(EXISTS ( SELECT 1 FROM private.clinic_members m WHERE (m.clinic_id = treatment_photos.clinic_id)))";
const T4 = "((patient_id = (current_setting('app.current_user'::text, true))::uuid) OR (EXISTS ( SELECT 1 FROM private.staff_members s WHERE (s.user_id = (current_setting('app.current_user'::text, true))::uuid))))";

test("the key's d7, d9 and t4 policies", () => {
  assert.deepEqual(usingBranches(D7, "lab_annotations"), ["owner", "signed_in"]);
  assert.deepEqual(usingBranches(D9, "treatment_photos"), ["any_member"]);
  // app.current_user isn't a setting the parser reads as a user id (policyFields doesn't either), so not_read
  assert.deepEqual(usingBranches(T4, "dentist_reviews"), ["not_read", "member"]);
});

test("a membership that names the caller and ties to the row is member_row", () => {
  const e = "(EXISTS ( SELECT 1 FROM private.clinic_members m WHERE ((m.clinic_id = visits.clinic_id) AND (m.member_id = auth.uid()))))";
  assert.deepEqual(usingBranches(e, "visits"), ["member_row"]);
});

test("Supabase's signed-in checks and plain true, as branches", () => {
  assert.deepEqual(usingBranches("((user_id = auth.uid()) OR (auth.uid() IS NOT NULL))", "notes"), ["owner", "signed_in"]);
  assert.deepEqual(usingBranches("((user_id = auth.uid()) OR (auth.role() = 'authenticated'::text))", "notes"), ["owner", "signed_in"]);
  assert.deepEqual(usingBranches("((user_id = auth.uid()) OR true)", "notes"), ["owner", "none"]);
  assert.deepEqual(usingBranches("true", "notes"), ["none"]);
  assert.deepEqual(usingBranches(null, "notes"), ["none"]); // no USING reads as true
});

test("a branch that reads the row but not the caller is row", () => {
  assert.deepEqual(usingBranches("((user_id = auth.uid()) OR (status = 'published'::text))", "posts"), ["owner", "row"]);
});

test("an OR nested under AND is one branch, and no OR is one branch", () => {
  const e = "((user_id = auth.uid()) AND ((status = 'a'::text) OR (status = 'b'::text)))";
  assert.deepEqual(usingBranches(e, "posts"), ["owner"]);
  assert.deepEqual(usingBranches("(user_id = auth.uid())", "posts"), ["owner"]);
});

test("an OR under AND is one branch: never owner unless the owner check is required, and not_read when it may open rows (P1 C155 point 1)", () => {
  // the owner check sits under the inner OR beside a branch every signed-in user meets: not required, so not owner
  const weak = "((clinic_id IS NOT NULL) AND ((user_id = auth.uid()) OR (auth.uid() IS NOT NULL)))";
  assert.deepEqual(usingBranches(weak, "notes"), ["not_read"]);
  // the owner check is required on the AND path: the inner OR only narrows the owner's own rows
  const narrow = "((user_id = auth.uid()) AND ((status = 'a'::text) OR (auth.uid() IS NOT NULL)))";
  assert.deepEqual(usingBranches(narrow, "notes"), ["owner"]);
});

test("more than MAX_BRANCHES branches, or text that doesn't parse, is null", () => {
  assert.equal(MAX_BRANCHES, 8);
  const many = Array.from({ length: 9 }, (_, i) => `(status = '${i}'::text)`).join(" OR ");
  assert.equal(usingBranches(`(${many})`, "posts"), null);
  assert.equal(usingBranches("((user_id = ", "posts"), null);
});

test("every kind is one of the listed words", () => {
  assert.deepEqual([...BRANCH_KINDS], ["owner", "member_row", "member", "any_member", "signed_in", "row", "none", "not_read"]);
  for (const e of [D7, D9, T4]) for (const k of usingBranches(e, "x")) assert.ok(BRANCH_KINDS.includes(k), k);
});

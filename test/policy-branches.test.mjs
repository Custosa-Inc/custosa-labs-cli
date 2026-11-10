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

test("a membership that calls a function it doesn't read, and names no caller, is not_read, never any_member", () => {
  // public.current_user_id() may return the session user: reading it as any_member would fail a scoped policy
  const e = "(EXISTS ( SELECT 1 FROM private.clinic_members m WHERE ((m.clinic_id = visits.clinic_id) AND (m.member_id = public.current_user_id()))))";
  assert.deepEqual(usingBranches(e, "visits"), ["not_read"]);
  const quoted = "(EXISTS ( SELECT 1 FROM private.clinic_members m WHERE ((m.clinic_id = visits.clinic_id) AND (m.member_id = \"my_uid\"()))))";
  assert.deepEqual(usingBranches(quoted, "visits"), ["not_read"]);
  // keywords before a parenthesis are not calls: d9's tie in extra parentheses stays any_member
  const parens = "(EXISTS ( SELECT 1 FROM private.clinic_members m WHERE ((m.clinic_id = visits.clinic_id))))";
  assert.deepEqual(usingBranches(parens, "visits"), ["any_member"]);
  // a test beside the tie narrows the rows it opens (P2 T29-C167 finding 3): not_read, a hold
  const nested = "(EXISTS ( SELECT 1 FROM private.clinic_members m WHERE ((m.clinic_id = visits.clinic_id) AND (m.active OR (m.role IN ( SELECT 'a'::text))))))";
  assert.deepEqual(usingBranches(nested, "visits"), ["not_read"]);
});

test("P2 C163 false-fail guard: a trusted source in a scalar subquery or a jwt claim is owner or member_row, a helper call not_read", () => {
  // Supabase's performance advice wraps auth.uid() in a scalar subquery; it must read as the caller, never as row
  assert.deepEqual(usingBranches("(user_id = ( SELECT auth.uid() AS uid))", "notes"), ["owner"]);
  assert.deepEqual(usingBranches("(user_id = ((auth.jwt() ->> 'sub'::text))::uuid)", "notes"), ["owner"]);
  const member = "(EXISTS ( SELECT 1 FROM clinic_members m WHERE ((m.clinic_id = notes.clinic_id) AND (m.user_id = ( SELECT auth.uid() AS uid)))))";
  assert.deepEqual(usingBranches(member, "notes"), ["member_row"]);
  assert.deepEqual(usingBranches("is_member(clinic_id)", "notes"), ["not_read"]);
  // an IN list over a member table is not read either way, so it is held, never any_member
  assert.deepEqual(usingBranches("(clinic_id IN ( SELECT m.clinic_id FROM clinic_members m))", "notes"), ["not_read"]);
});

test("P2 C163 point 2: the owner AND a signed-in check is one branch and stays owner", () => {
  assert.deepEqual(usingBranches("((user_id = auth.uid()) AND (auth.uid() IS NOT NULL))", "notes"), ["owner"]);
  assert.deepEqual(usingBranches("((user_id = ( SELECT auth.uid() AS uid)) OR (auth.uid() IS NOT NULL))", "notes"), ["owner", "signed_in"]);
});

test("P2 C167 finding 1: a helper call outside the session ones is not_read, never none (is_admin() may check the caller)", () => {
  assert.deepEqual(usingBranches("((user_id = auth.uid()) OR is_admin())", "notes"), ["owner", "not_read"]);
  assert.deepEqual(usingBranches("is_admin()", "notes"), ["not_read"]);
  assert.deepEqual(usingBranches("((user_id = auth.uid()) OR (coalesce(is_public, false)))", "notes"), ["owner", "not_read"]);
  assert.deepEqual(usingBranches("((user_id = auth.uid()) OR true)", "notes"), ["owner", "none"]); // no call: still none
});

test("P2 C167 finding 2: signed_in is a presence or role test only; any other session claim against a constant is not_read", () => {
  for (const e of ["(auth.uid() IS NOT NULL)", "(auth.jwt() IS NOT NULL)", "(auth.uid() IS NULL)",
    "(auth.role() = 'authenticated'::text)", "(auth.role() = 'anon'::text)"]) {
    assert.deepEqual(usingBranches(`((user_id = auth.uid()) OR ${e})`, "notes"), ["owner", "signed_in"], e);
  }
  for (const e of ["(((auth.jwt() -> 'app_metadata'::text) ->> 'role'::text) = 'admin'::text)",
    "((auth.jwt() ->> 'user_role'::text) = 'admin'::text)", "(auth.role() = 'service_role'::text)",
    "(auth.email() ~~ '%@clinic.org'::text)", "(auth.uid() = '00000000-0000-0000-0000-000000000001'::uuid)"]) {
    assert.deepEqual(usingBranches(`((user_id = auth.uid()) OR ${e})`, "notes"), ["owner", "not_read"], e);
  }
  assert.deepEqual(usingBranches(D7, "lab_annotations"), ["owner", "signed_in"]); // d7's setting IS NOT NULL
});

test("P2 C167 finding 3: any_member only when the EXISTS holds nothing but column ties; a parent's property is not_read", () => {
  assert.deepEqual(usingBranches("(EXISTS ( SELECT 1 FROM posts p WHERE ((p.id = notes.post_id) AND (p.published = true))))", "notes"), ["not_read"]);
  assert.deepEqual(usingBranches("(EXISTS ( SELECT 1 FROM posts p WHERE ((p.id = notes.post_id) AND p.published)))", "notes"), ["not_read"]);
  assert.deepEqual(usingBranches("((user_id = auth.uid()) OR (EXISTS ( SELECT 1 FROM appointments a WHERE ((a.id = notes.appointment_id) AND (a.status = 'shared'::text)))))", "notes"), ["owner", "not_read"]);
  assert.deepEqual(usingBranches(D9, "treatment_photos"), ["any_member"]); // d9: the tie alone
});

test("P2 C171 low 1: a filter in a JOIN's ON narrows the rows like one in the WHERE, so it is not_read", () => {
  const joined = (on) => `(EXISTS ( SELECT 1 FROM (posts p JOIN authors a ON (${on})) WHERE (p.id = notes.post_id)))`;
  assert.deepEqual(usingBranches(joined("(a.id = p.author_id) AND a.public"), "notes"), ["not_read"]);
  assert.deepEqual(usingBranches(joined("(a.id = p.author_id) AND (a.status = 'active'::text)"), "notes"), ["not_read"]);
  assert.deepEqual(usingBranches(`(EXISTS ( SELECT 1 FROM ((posts p JOIN authors a ON ((a.id = p.author_id))) LEFT JOIN teams t ON ((t.id = a.team_id) AND t.open)) WHERE (p.id = notes.post_id)))`, "notes"), ["not_read"]);
  // ties alone in every ON stay any_member, as d9's tie does
  assert.deepEqual(usingBranches(joined("a.id = p.author_id"), "notes"), ["any_member"]);
  assert.deepEqual(usingBranches(`(EXISTS ( SELECT 1 FROM (posts p JOIN authors a USING (author_id)) WHERE (p.id = notes.post_id)))`, "notes"), ["any_member"]);
});

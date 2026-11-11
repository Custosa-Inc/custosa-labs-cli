/* T29 K041/K090 (T29-P3-C259, T29-P1-C181 item 2): current_setting('app.current_user', true) names the user, like
 * app.current_user_id and app.user_id. Before, the parser didn't read it as a user at all, so a table whose select
 * policy compares patient_id with it didn't read as per-user rows, and an always-true insert on it held. The setting's
 * last key is what counts; the SQL keyword CURRENT_USER (the database role name) is a different thing and stays
 * unknown. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseExpression, policyFields, sessionValue, usingBranches } from "../lib/inspector/policyexpr.mjs";

const setting = (key) => `current_setting('${key}'::text, true)`;
const shapes = (s) => [
  `(patient_id = (${s})::uuid)`,
  `(patient_id = ${s})`,
  `((patient_id = (${s})::uuid) OR (EXISTS ( SELECT 1 FROM private.staff_members m WHERE (m.user_id = (${s})::uuid))))`,
  `((clinic_id IS NOT NULL) AND (patient_id = (${s})::uuid))`,
  `(patient_id <> (${s})::uuid)`,
];

test("app.current_user reads as app.current_user_id does, in policy fields and branches", () => {
  for (const [a, b] of [["app.current_user", "app.current_user_id"], ["current_user", "current_user_id"]]) {
    const as = shapes(setting(a)), bs = shapes(setting(b));
    for (let i = 0; i < as.length; i++) {
      for (const command of ["SELECT", "INSERT", "UPDATE", "ALL"]) {
        const using = command === "INSERT" ? null : as[i], check = command === "SELECT" ? null : as[i];
        const usingB = command === "INSERT" ? null : bs[i], checkB = command === "SELECT" ? null : bs[i];
        assert.deepEqual(policyFields({ command, using, check }), policyFields({ command, using: usingB, check: checkB }), `${a} ${command} ${as[i]}`);
      }
      assert.deepEqual(usingBranches(as[i], "patients"), usingBranches(bs[i], "patients"), as[i]);
    }
  }
});

test("the key's t4 policy: the owner, or a listed staff member", () => {
  const T4 = "((patient_id = (current_setting('app.current_user'::text, true))::uuid) OR (EXISTS ( SELECT 1 FROM private.staff_members s WHERE (s.user_id = (current_setting('app.current_user'::text, true))::uuid))))";
  assert.deepEqual(usingBranches(T4, "dentist_reviews"), ["owner", "member"]);
  assert.deepEqual(usingBranches("(patient_id = (current_setting('app.current_user'::text, true))::uuid)", "patients"), ["owner"]);
});

test("the setting is a user of unknown trust; the role keyword CURRENT_USER is unchanged", () => {
  assert.deepEqual(sessionValue(parseExpression(setting("app.current_user"))), { kind: "user", trust: "unknown" });
  assert.deepEqual(sessionValue(parseExpression("current_user")), { kind: "user", trust: "unknown" });
  // a request header or cookie of that name is the caller's own
  assert.deepEqual(sessionValue(parseExpression(setting("request.header.current_user"))), { kind: "user", trust: "untrusted" });
  // a longer key that only starts with it names nothing
  assert.equal(sessionValue(parseExpression(setting("app.current_user_role"))), null);
});

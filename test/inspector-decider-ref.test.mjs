/* Contract 2.5 decider_ref: on a line Custosa's rules saw nothing of, a person's pass or
 * not_applicable option settles only with decider_ref, an opaque role reference for who decided. The tool takes it
 * from the assistant and never makes one up; when an option goes without one and the line stays open there, a local
 * note says a person's role is needed. Stub evaluator and temp folders only. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import AjvModule from "ajv";
import { INPUT_SCHEMA, makeRunCheck, decisionsProblem, concernsProblem, verdictsProblem, DECISION_NOTES } from "../lib/inspector/tool.mjs";
import { writeToken } from "../lib/inspector/auth.mjs";
import { loadRules } from "../lib/inspector/rules.mjs";
import { EVALUATE_OK, stub } from "./stub-evaluator.mjs";

const Ajv = AjvModule.default ?? AjvModule;
const validateArgs = new Ajv({ strict: true }).compile(INPUT_SCHEMA);
const RULESET = { id: "2026-10-20.0123abcd", rules: loadRules(fileURLToPath(new URL("./fixtures/rules/", import.meta.url))), queries: [] };
const TOKEN = `phisc_${"t".repeat(43)}`;
const temp = (prefix) => realpathSync(mkdtempSync(join(tmpdir(), prefix)));
const quiet = {
  ruleset: RULESET,
  collectCatalog: async () => ({ status: "not_run", count: 0, reason: "service_missing", preflight: null, queries: [] }),
  collectPlatform: async () => ({ provider: null, status: "not_run", reason: "no_token", settings: {} }),
};
function repo() {
  const root = temp("decider-ref-");
  mkdirSync(join(root, "src"), { recursive: true });
  writeFileSync(join(root, "src/db.ts"), 'export async function save(p) { await db.from("patients").insert(p); }\n');
  return root;
}
async function setup(handler) {
  const configDir = join(temp("decider-ref-cfg-"), "custosa");
  const s = await stub(handler);
  writeToken(TOKEN, { configDir, host: new URL(s.url).origin });
  const runCheck = makeRunCheck({ configDir, localOnly: false, buildOptions: quiet,
    evaluatorUrl: () => ({ url: s.url, origin: new URL(s.url).origin }), clientOptions: { sleep: async () => {} } });
  return { s, runCheck };
}
const OPTIONS = [
  { id: "not_applicable", label: "This doesn't apply", settles_as: "not_applicable", readiness: "decided by a person" },
  { id: "pass", label: "It is in place", settles_as: "pass", readiness: "decided by a person" },
  { id: "fail", label: "It isn't in place", settles_as: "fail", readiness: "blocks (fail)" },
  { id: "unsure", label: "Not sure", settles_as: null, readiness: "stays open" },
];
const line = (object_id, reason, sawNothing = true) => ({ object_id, practice_id: object_id.split("@")[0], title: "t", severity: "medium", area: "access",
  state: "needs_review", grade: "E5", reason, objects: [], evidence: [], how: "h",
  decision: { object_id, question: "q?", why_asked: "assistant_could_not_decide", scope: "s", evidence: [], options: OPTIONS,
    ...(sawNothing ? { saw: { matched: "nothing", stack_count: 1, files_covered: 3 } } : {}) } });

test("decider_ref: a decision takes a listed role or local:<8 hex>, and the body sends it as written", async () => {
  assert.ok(validateArgs({ goal: "check", session: EVALUATE_OK.session, decisions: [{ object_id: "a-b", option: "pass", decider_ref: "security-lead" }] }));
  for (const ref of ["", "jane doe", "jane@clinic.example", "x".repeat(65), "owner/1", "cto", "dpo.2", "team-1234"]) {
    assert.ok(!validateArgs({ goal: "check", decisions: [{ object_id: "a-b", option: "pass", decider_ref: ref }] }), ref);
  }
  const root = repo();
  const { s, runCheck } = await setup(() => ({ status: 200, json: EVALUATE_OK }));
  try {
    await runCheck({ goal: "check", session: EVALUATE_OK.session, decisions: [{ object_id: "a-b", option: "pass", decider_ref: "owner" },
      { object_id: "c-d", option: "fail" }] }, { roots: [root] });
    assert.deepEqual(s.calls[0].body.decisions, [{ object_id: "a-b", option: "pass", decider_ref: "owner", decided_by: "person" },
      { object_id: "c-d", option: "fail", decided_by: "person" }]);
  } finally { await s.close(); }
});

test("decider_ref: the tool never makes one up; an option left open on a line seen nothing of (decision.saw) gets a note", async () => {
  const root = repo();
  // as 1ea2abf8 answers it: a refused pass keeps the line's own reason (no_rule_for_stack here) beside decision.saw
  const answer = { ...EVALUATE_OK, findings: [line("a-b", "no_rule_for_stack"), line("c-d", "rules_saw_nothing"), line("e-f", "person_must_decide", false)] };
  const { s, runCheck } = await setup(() => ({ status: 200, json: answer }));
  try {
    const out = await runCheck({ goal: "check", session: EVALUATE_OK.session, decisions: [{ object_id: "a-b", option: "pass" },
      { object_id: "c-d", option: "fail" }, { object_id: "e-f", option: "not_applicable" }] }, { roots: [root] });
    assert.ok(s.calls[0].body.decisions.every((d) => d.decider_ref === undefined));
    assert.deepEqual(out.local_notes, [DECISION_NOTES.decider_ref_needed.replace("{ids}", "a-b")]);
    // with a decider_ref sent, no note
    const sent = await runCheck({ goal: "check", session: EVALUATE_OK.session, decisions: [{ object_id: "a-b", option: "pass", decider_ref: "owner" }] }, { roots: [root] });
    assert.equal(sent.local_notes, undefined);
  } finally { await s.close(); }
});

test("decider_ref: one shaped like a secret or a record value is not a role, so it never leaves", () => {
  assert.ok(!validateArgs({ goal: "check", decisions: [{ object_id: "a-b", option: "pass", decider_ref: "sk\x5flive_4eC39HqLyjWDarjtT1zdp7dc" }] }));
  assert.equal(decisionsProblem({ decisions: [{ object_id: "a-b", option: "pass", decider_ref: "security-lead" }] }, { env: {} }), null);
});

/* T29 o2 (T29-P1-C116 (a)): the lines are in the call's store. The CLI reads the line of each decision that may need
 * a decider_ref through get_result ({finding}, part detail) in the same call, so the note comes with the check. */
const INDEX = { result_counts: { by_state: { pass: 0, fail: 0, not_applicable: 0, needs_review: 1, unknown: 0, error: 0 },
  by_severity: {}, by_state_and_severity: [] }, practices: [], fails: [], open: [], questions: [], concerns: [], fixes: [], lists: [] };
const lineRead = (body, detail) => ({ goal: body.goal, session: body.session, select: body.select, part: "detail", matched: 1,
  results: [{ finding: detail.object_id, practice_id: detail.practice_id, object: detail.object_id, state: detail.state,
    severity: detail.severity, detail }], is_fetch_only: true, charged_units: 0, correlation_id: "corr_12345678" });

test("decider_ref: the open line read from the store adds the note in the same call (T29 o2)", async () => {
  const root = repo();
  const { s, runCheck } = await setup((call) => ({ status: 200, json: call.body.select
    ? lineRead(call.body, line("a-b", "no_rule_for_stack")) : { ...EVALUATE_OK, index: INDEX } }));
  try {
    const out = await runCheck({ goal: "check", session: EVALUATE_OK.session, decisions: [{ object_id: "a-b", option: "pass" }] }, { roots: [root] });
    assert.deepEqual(s.calls[1].body, { goal: "check", session: EVALUATE_OK.session, select: { finding: "a-b" } });
    assert.deepEqual(out.local_notes, [DECISION_NOTES.decider_ref_needed.replace("{ids}", "a-b")]);
  } finally { await s.close(); }
});

test("A bare 10-digit number never leaves in a verdict note, a concern note or a decider_ref", () => {
  // 4151234567 and 1234567890 aren't NANP-shaped, so the evaluator's screen passes them; 9 and 11 digits were refused
  for (const n of ["1234567890", "4151234567", "0123456789"]) {
    assert.ok(!validateArgs({ goal: "check", decisions: [{ object_id: "a-b", option: "pass", decider_ref: `owner-${n}` }] }), n);
    assert.match(concernsProblem({ concerns: [{ note: `Texts go to ${n} with no consent check.` }] }) ?? "", /concerns\[0\]\.note/, n);
    assert.match(verdictsProblem({ verdicts: [{ practice_id: "p", state: "pass", reason_code: "control_at", note: `The handler calls ${n}.` }] }) ?? "", /note/, n);
  }
  // shorter runs in free text still pass, and a role stays a role
  assert.equal(concernsProblem({ concerns: [{ note: "The 2024 upload keeps 3 copies for 30 days." }] }), null);
  assert.equal(verdictsProblem({ verdicts: [{ practice_id: "p", state: "pass", reason_code: "control_at", note: "Checked 1200 lines in 14 files." }] }), null);
});

test("A decider_ref is a listed role or local:<8 hex>, so a run of digits, a UUID, a date or a free label is refused", () => {
  for (const ref of ["MRN123456", "user12345", "12345", "6f1c2a7e-3b4d-4e5f-8a9b-0c1d2e3f4a5b", "2026-11-03", "03.11.2026", "lead-2026-11-03",
    "cto", "dpo.2", "team-1234", "security_lead_eu"]) {
    assert.ok(!validateArgs({ goal: "check", decisions: [{ object_id: "a-b", option: "pass", decider_ref: ref }] }), ref);
  }
  for (const ref of ["owner", "security-lead", "clinical-lead", "local:0a1b2c3d"]) {
    assert.ok(validateArgs({ goal: "check", decisions: [{ object_id: "a-b", option: "pass", decider_ref: ref }] }), ref);
    assert.equal(decisionsProblem({ decisions: [{ object_id: "a-b", option: "pass", decider_ref: ref }] }, { env: {} }), null, ref);
  }
});

test("A legacy {decision: not_applicable} on a line seen nothing of gets the decider_ref_needed note", async () => {
  const root = repo();
  const answer = { ...EVALUATE_OK, findings: [line("a-b", "rules_saw_nothing"), line("c-d", "rules_saw_nothing"), line("e-f", "person_must_decide", false)] };
  const { s, runCheck } = await setup(() => ({ status: 200, json: answer }));
  try {
    const out = await runCheck({ goal: "check", session: EVALUATE_OK.session, decisions: [{ object_id: "a-b", decision: "not_applicable" },
      { object_id: "c-d", decision: "declined" }, { object_id: "e-f", decision: "not_applicable" }] }, { roots: [root] });
    assert.deepEqual(out.local_notes, [DECISION_NOTES.decider_ref_needed.replace("{ids}", "a-b")]);
    const sent = await runCheck({ goal: "check", session: EVALUATE_OK.session, decisions: [{ object_id: "a-b", decision: "not_applicable", decider_ref: "owner" }] }, { roots: [root] });
    assert.equal(sent.local_notes, undefined);
  } finally { await s.close(); }
});

test("A legacy not_applicable's open line read from the store adds the note in the same call (T29 o2)", async () => {
  const root = repo();
  const { s, runCheck } = await setup((call) => ({ status: 200, json: call.body.select
    ? lineRead(call.body, line("a-b", "rules_saw_nothing")) : { ...EVALUATE_OK, index: INDEX } }));
  try {
    const out = await runCheck({ goal: "check", session: EVALUATE_OK.session, decisions: [{ object_id: "a-b", decision: "not_applicable" }] }, { roots: [root] });
    assert.deepEqual(out.local_notes, [DECISION_NOTES.decider_ref_needed.replace("{ids}", "a-b")]);
  } finally { await s.close(); }
});

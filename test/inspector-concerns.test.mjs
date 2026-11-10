/* Concerns, the tool half (contract 2.4, evaluator_api.md 1.11): the assistant raises concerns and decides them through
 * check_schema. A concern's text goes out once, in the raising call, and is kept only in .custosa/local/concerns.json;
 * later responses show it from there and no later body carries it. Every test uses a stub evaluator and temp
 * folders. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import AjvModule from "ajv";
import { INPUT_SCHEMA, makeRunCheck, decisionsProblem, concernsProblem, verdictsProblem, TOOL_ERRORS } from "../lib/inspector/tool.mjs";
import { writeToken } from "../lib/inspector/auth.mjs";
import { loadRules } from "../lib/inspector/rules.mjs";
import { CONCERN_NOTES, readTexts } from "../lib/inspector/concerns.mjs";
import { holdsRecordValue, sentIdentifier, sentPath } from "../lib/inspector/ids.mjs";
import { EVALUATE_OK, stub } from "./stub-evaluator.mjs";

const Ajv = AjvModule.default ?? AjvModule;
const validateArgs = new Ajv({ strict: true }).compile(INPUT_SCHEMA);
const RULES = loadRules(fileURLToPath(new URL("./fixtures/rules/", import.meta.url)));
const RULESET = { id: "2026-10-20.0123abcd", rules: RULES, queries: [] };
const TOKEN = `phisc_${"t".repeat(43)}`;
const temp = (prefix) => realpathSync(mkdtempSync(join(tmpdir(), prefix)));
const quiet = {
  ruleset: RULESET,
  collectCatalog: async () => ({ status: "not_run", count: 0, reason: "service_missing", preflight: null, queries: [] }),
  collectPlatform: async () => ({ provider: null, status: "not_run", reason: "no_token", settings: {} }),
};
function repo() {
  const root = temp("b51-tool-");
  mkdirSync(join(root, "src"), { recursive: true });
  writeFileSync(join(root, "src/db.ts"), 'export async function save(p) { await db.from("patients").insert(p); }\n');
  return root;
}
async function setup(handler, deps = {}) {
  const configDir = join(temp("b51-tool-cfg-"), "custosa");
  const s = await stub(handler);
  writeToken(TOKEN, { configDir, host: new URL(s.url).origin });
  const runCheck = makeRunCheck({ configDir, localOnly: false, buildOptions: quiet,
    evaluatorUrl: () => ({ url: s.url, origin: new URL(s.url).origin }), clientOptions: { sleep: async () => {} }, ...deps });
  return { s, runCheck };
}

const A = { category: "access", area: "access", file_kind: "route_handler", practice_id: "authz-every-handler", proposed_severity: "high" };
const B = { category: "logging", area: "logging", file_kind: "server_module", proposed_severity: "medium" };
const TEXT_A = "The notes handler loads a note by its id without checking that the caller owns it.";
const TEXT_B = "Failed sign-ins are not recorded anywhere the team can read.";
const ID_A = "cn_00000000000000a1", ID_B = "cn_00000000000000b2";
const OPTIONS = { real_problem: "It's a real problem", not_a_problem: "It isn't a problem", not_sure: "Not sure" };
const listed = (id, meta, extra = {}) => ({ concern_id: id, ...meta, severity: meta.proposed_severity, status: "unconfirmed",
  label: "waits for a confirm", raised_now: false, next: { awaiting: "confirm", options: [{ id: "real_problem" }, { id: "not_a_problem" }, { id: "not_sure" }] }, ...extra });
// The evaluator lists this call's raises first, newest first (respond.concerns_block): B, then A, for [A, B] sent.
const RAISED = { ...EVALUATE_OK, concerns: [listed(ID_B, B, { raised_now: true }), listed(ID_A, A, { raised_now: true })], concern_options: OPTIONS };

test("Concerns and concern_decisions are in check_schema's input schema, closed as contract 2.4 has them", () => {
  assert.ok(validateArgs({ goal: "check", concerns: [{ ...A, note: TEXT_A }, { ...B, note: TEXT_B }] }), JSON.stringify(validateArgs.errors));
  assert.ok(validateArgs({ goal: "check", concern_decisions: [{ concern_id: ID_A, option: "real_problem", decided_by: "assistant" }] }));
  const bad = [
    { concerns: [{ ...A, note: TEXT_A, id: "x" }] },                          // closed
    { concerns: [{ ...A, note: "two\nlines" }] },                            // one line
    { concerns: [{ ...A, note: "x".repeat(501) }] },                         // MAX_CONCERN_TEXT
    { concerns: [{ ...A, category: "billing", note: TEXT_A }] },             // CONCERN_CATEGORIES
    { concerns: Array.from({ length: 51 }, () => ({ ...A, note: TEXT_A })) }, // MAX_BODY_CONCERNS
    { concern_decisions: [{ concern_id: "cn_xyz", option: "real_problem", decided_by: "assistant" }] },
    { concern_decisions: [{ concern_id: ID_A, option: "maybe", decided_by: "assistant" }] },
    { concern_decisions: [{ concern_id: ID_A, option: "fixed", decided_by: "assistant", text: TEXT_A }] }, // no text
    { concern_decisions: Array.from({ length: 101 }, () => ({ concern_id: ID_A, option: "keep", decided_by: "assistant" })) },
  ];
  for (const args of bad) assert.ok(!validateArgs({ goal: "check", ...args }), JSON.stringify(args).slice(0, 120));
});

test("A raising call sends the concerns once, keeps each text by its id in .custosa/local, and shows it", async () => {
  const root = repo();
  const { s, runCheck } = await setup((call, n) => ({ status: 200, json: n === 1 ? RAISED
    : { ...EVALUATE_OK, concerns: [listed(ID_A, A), listed(ID_B, B)], concern_options: OPTIONS } }));
  try {
    const first = await runCheck({ goal: "check", concerns: [{ ...A, note: TEXT_A }, { ...B, note: TEXT_B }] }, { roots: [root] });
    // no response has said learning: on, so the notes stay here and the concerns say so.
    assert.deepEqual(s.calls[0].body.concerns, [{ ...A, note_kept_local: true }, { ...B, note_kept_local: true }]);
    assert.deepEqual(first.concerns.map((c) => [c.concern_id, c.local_text]), [[ID_B, TEXT_B], [ID_A, TEXT_A]]);
    const file = join(root, ".custosa/local/concerns.json");
    assert.equal(statSync(file).mode & 0o777, 0o600);
    assert.equal(readFileSync(join(root, ".custosa/.gitignore"), "utf8"), "local/\n*.custosa-tmp\n");
    assert.deepEqual([...readTexts(root)].map(([id, e]) => [id, e.text]), [[ID_A, TEXT_A], [ID_B, TEXT_B]]);
    // The next call decides one: no text leaves, in the body or the fact document, and the texts still show.
    const second = await runCheck({ goal: "check", session: EVALUATE_OK.session,
      concern_decisions: [{ concern_id: ID_A, option: "real_problem", decided_by: "assistant" }] }, { roots: [root] });
    const sent = JSON.stringify(s.calls[1].body);
    assert.ok(!sent.includes(TEXT_A) && !sent.includes(TEXT_B) && !sent.includes("concerns\":"), "no concern text after the raising call");
    assert.deepEqual(s.calls[1].body.concern_decisions, [{ concern_id: ID_A, option: "real_problem", decided_by: "assistant" }]);
    assert.deepEqual(second.concerns.map((c) => c.local_text), [TEXT_A, TEXT_B]);
  } finally { await s.close(); }
});

test("Texts are not kept when the evaluator's raised list doesn't match what was sent, or it lists no raise (concerns_saved false)", async () => {
  for (const [answer, note] of [
    [{ ...RAISED, concerns: [listed(ID_A, A, { raised_now: true })] }, CONCERN_NOTES.concern_texts_not_kept], // one of two
    [{ ...RAISED, concerns: [listed(ID_A, A, { raised_now: true }), listed(ID_B, B, { raised_now: true })] }, CONCERN_NOTES.concern_texts_not_kept], // order
    [{ ...RAISED, concerns: [listed(ID_A, A)], concerns_saved: false }, null], // the raises were dropped (the cap)
  ]) {
    const root = repo();
    const { s, runCheck } = await setup(() => ({ status: 200, json: answer }));
    try {
      const out = await runCheck({ goal: "check", concerns: [{ ...A, note: TEXT_A }, { ...B, note: TEXT_B }] }, { roots: [root] });
      assert.equal(existsSync(join(root, ".custosa/local/concerns.json")), false);
      assert.deepEqual(out.local_notes ?? [], note ? [note] : []);
      assert.ok(out.concerns.every((c) => c.local_text === undefined));
    } finally { await s.close(); }
  }
});

test("An id the evaluator answers unknown_concern is dropped locally; refused for another reason it stays", async () => {
  const root = repo();
  const { s, runCheck } = await setup((call, n) => ({ status: 200, json: n === 1 ? RAISED : { ...EVALUATE_OK,
    concern_outcomes: [{ concern_id: ID_A, option: "fixed", decided_by: "assistant", outcome: "refused", reason: "unknown_concern" },
      { concern_id: ID_B, option: "lower", decided_by: "assistant", outcome: "refused", reason: "not_an_option" }] } }));
  try {
    await runCheck({ goal: "check", concerns: [{ ...A, note: TEXT_A }, { ...B, note: TEXT_B }] }, { roots: [root] });
    await runCheck({ goal: "check", concern_decisions: [{ concern_id: ID_A, option: "fixed", decided_by: "assistant" },
      { concern_id: ID_B, option: "lower", decided_by: "assistant" }] }, { roots: [root] });
    assert.deepEqual([...readTexts(root).keys()], [ID_B]);
  } finally { await s.close(); }
});

test("A get_result read of the concerns shows the kept texts of the session's root (T29 o2)", async () => {
  const root = repo();
  const { s, runCheck } = await setup((call, n) => ({ status: 200, json: n === 1 ? RAISED
    : RESULT(call.body.select, [listed(ID_A, A)]) }));
  try {
    await runCheck({ goal: "check", concerns: [{ ...A, note: TEXT_A }, { ...B, note: TEXT_B }] }, { roots: [root] });
    const read = await runCheck({ goal: "check", session: EVALUATE_OK.session, select: { list: "concerns.unconfirmed" } }, { roots: [root] });
    assert.equal(s.calls[1].body.concerns, undefined);
    assert.deepEqual(read.results.map((c) => c.local_text), [TEXT_A]);
  } finally { await s.close(); }
});

test("A retried raising call sends identical body bytes with the same Idempotency-Key (keyed raise ids)", async () => {
  const root = repo();
  const { s, runCheck } = await setup((call, n) => (n === 1
    ? { status: 503, json: { error: "unavailable", next_step: "Try again shortly.", retry_after_seconds: 1, correlation_id: "corr_12345678" } }
    : { status: 200, json: RAISED }));
  try {
    const out = await runCheck({ goal: "check", concerns: [{ ...A, note: TEXT_A }, { ...B, note: TEXT_B }] }, { roots: [root] });
    assert.equal(s.calls.length, 2);
    assert.deepEqual(s.calls[1].body, s.calls[0].body);
    assert.ok(s.calls[0].headers["idempotency-key"]);
    assert.equal(s.calls[1].headers["idempotency-key"], s.calls[0].headers["idempotency-key"]);
    assert.deepEqual(out.concerns.map((c) => c.local_text), [TEXT_B, TEXT_A]);
  } finally { await s.close(); }
});

test("Concerns go only with an evaluation goal; a person's concern decision is refused in CI; a secret-shaped text never leaves", async () => {
  const root = repo();
  const { s, runCheck } = await setup(() => ({ status: 200, json: EVALUATE_OK }));
  try {
    const read = await runCheck({ goal: "check", session: EVALUATE_OK.session, select: { state: "fail" }, concerns: [{ ...A, note: TEXT_A }] }, { roots: [root] });
    assert.equal(read.next_step, TOOL_ERRORS.concerns_need_evaluation);
    const advice = await runCheck({ goal: "explain", practice_id: "rls-enabled", concern_decisions: [{ concern_id: ID_A, option: "keep", decided_by: "assistant" }] }, { roots: [root] });
    assert.equal(advice.next_step, TOOL_ERRORS.concerns_need_evaluation);
    assert.equal(s.calls.length, 0);
  } finally { await s.close(); }
  const person = { concern_decisions: [{ concern_id: ID_A, option: "false_alarm", decided_by: "person" }] };
  assert.match(decisionsProblem(person, { env: { CI: "true" } }), /CI/);
  assert.equal(decisionsProblem(person, { env: {} }), null);
  assert.equal(decisionsProblem({ concern_decisions: [{ concern_id: ID_A, option: "keep", decided_by: "assistant" }] }, { env: { CI: "1" } }), null);
  assert.match(concernsProblem({ concerns: [{ ...A, note: "The key sk\x5flive_4eC39HqLyjWDarjtT1zdp7dc is in the client." }] }), /^concerns\[0\]\.note/);
  assert.equal(concernsProblem({ concerns: [{ ...A, note: TEXT_A }] }), null);
});

test("A symlinked .custosa/local is never written through", async () => {
  const root = repo();
  const elsewhere = temp("b51-elsewhere-");
  mkdirSync(join(root, ".custosa"));
  symlinkSync(elsewhere, join(root, ".custosa/local"));
  const { s, runCheck } = await setup(() => ({ status: 200, json: RAISED }));
  try {
    const out = await runCheck({ goal: "check", concerns: [{ ...A, note: TEXT_A }, { ...B, note: TEXT_B }] }, { roots: [root] });
    assert.equal(existsSync(join(elsewhere, "concerns.json")), false);
    assert.deepEqual(out.local_notes, [CONCERN_NOTES.concern_texts_unwritable]);
  } finally { await s.close(); }
});

test("The text summary counts the index's concerns and the unresolved ones; the output schema lists concerns", async () => {
  const { textFor } = await import("../lib/inspector/server.mjs");
  const { OUTPUT_SCHEMA } = await import("../lib/inspector/tool.mjs");
  const closed = listed(ID_B, B, { status: "dismissed", next: { awaiting: null, options: [] } });
  assert.match(textFor({ ...EVALUATE_OK, index: INDEX([listed(ID_A, A), closed]) }, { full: false }), /, 0 fixes, 2 concerns \(1 unresolved\),/);
  assert.ok(!/concerns/.test(textFor(EVALUATE_OK, { full: false })));
  assert.equal(OUTPUT_SCHEMA.anyOf[0].properties.concerns.type, "array");
});

test("A concern text of whitespace only is refused locally, as core refuses it", () => {
  for (const text of [" ", "\t", "   \t  "]) assert.match(concernsProblem({ concerns: [{ ...A, note: text }] }), /^concerns\[0\]\.note/);
});

test("Record ids, a date of birth and a titled name are refused in a concern text and a verdict reason", () => {
  const refused = ["Row MRN 00123456 is in the log.", "The page shows MRN-884213 to anyone.", "member id 4471920 is printed",
    "patient #5566778 shows in the URL", "account number 12345678 is logged", "dob 1984-03-12 is in the export",
    "The fixture has born 03/12/1984 in it.", "date of birth: Mar 12, 1984 sits in the seed file",
    "A note names Dr. Jane Smith in the template.", "Mrs Ana Lopez is in a test fixture."];
  for (const text of refused) {
    assert.match(concernsProblem({ concerns: [{ ...A, note: text }] }) ?? "", /^concerns\[0\]\.note holds something shaped/, text);
    assert.match(verdictsProblem({ verdicts: [{ note: text }] }) ?? "", /^verdicts\[0\]\.note holds something shaped/, text);
  }
  const kept = [TEXT_A, TEXT_B, "The dob column is stored without encryption.", "The member table has no row level security.",
    "Patient ids go to the log on every request.", "The account page has no MFA.", "A migration on 2026-10-20 dropped the audit table.",
    "Dr. visits are listed without a check.", "The Mr. Smith fixture is fine."];
  for (const text of kept) assert.equal(concernsProblem({ concerns: [{ ...A, note: text }] }), null, text);
});

/* T29 o2 (T29-P1-C116): the pending-raise tests (raises spilling to a later page) went with the pending logic; a raise
 * is matched in the call that sent it (the T29 o2 cases at the end of this file). */
test("concerns_saved false from a losing decision keeps the texts of the raises the evaluator lists", async () => {
  const root = repo();
  const { s, runCheck } = await setup(() => ({ status: 200, json: { ...RAISED, concerns_saved: false,
    concern_outcomes: [{ concern_id: "cn_00000000000000c3", option: "fixed", decided_by: "assistant", outcome: "refused", reason: "changed_meanwhile" }] } }));
  try {
    const out = await runCheck({ goal: "check", concerns: [{ ...A, note: TEXT_A }, { ...B, note: TEXT_B }],
      concern_decisions: [{ concern_id: "cn_00000000000000c3", option: "fixed", decided_by: "assistant" }] }, { roots: [root] });
    assert.deepEqual([...readTexts(root)].map(([id, e]) => [id, e.text]), [[ID_A, TEXT_A], [ID_B, TEXT_B]]);
    assert.deepEqual(out.concerns.map((c) => c.local_text), [TEXT_B, TEXT_A]);
    assert.equal(out.local_notes, undefined);
  } finally { await s.close(); }
});

test("A raising call whose retries run out on 503 says its texts weren't kept", async () => {
  const root = repo();
  const { s, runCheck } = await setup(() => ({ status: 503, json: { error: "unavailable", retry_after_seconds: 1, correlation_id: "corr_12345678",
    next_step: "The evaluator couldn't finish this call, but its concern changes were already kept." } }));
  try {
    const out = await runCheck({ goal: "check", concerns: [{ ...A, note: TEXT_A }, { ...B, note: TEXT_B }] }, { roots: [root] });
    assert.equal(out.error, "unavailable");
    assert.ok(s.calls.length >= 2, "retried first");
    assert.deepEqual(out.local_notes, [CONCERN_NOTES.concern_texts_unanswered]);
    assert.equal(existsSync(join(root, ".custosa/local/concerns.json")), false);
  } finally { await s.close(); }
});

test("The walk skips .custosa/local and .custosa/.gitignore, so the next fact document never names them", async () => {
  const root = repo();
  const { s, runCheck } = await setup(() => ({ status: 200, json: RAISED }));
  try {
    await runCheck({ goal: "check", concerns: [{ ...A, note: TEXT_A }, { ...B, note: TEXT_B }] }, { roots: [root] });
    assert.ok(existsSync(join(root, ".custosa/local/concerns.json")) && existsSync(join(root, ".custosa/.gitignore")));
    await runCheck({ goal: "check" }, { roots: [root] });
    const doc = JSON.stringify(s.calls[1].body.fact_document);
    assert.equal(doc.includes(".custosa/local"), false, doc.slice(0, 400));
    assert.equal(doc.includes(".custosa/.gitignore"), false);
  } finally { await s.close(); }
});

test("Grouped ids, compact and two-digit-year birth dates and fuller titled names are refused", () => {
  const refused = ["MRN 0012-3456 is in the log.", "MRN 1234 5678 shows on the page.", "MRN: 00 12 34 56 is printed.",
    "MRN: 12-34-567 is in the seed.", "account no. 1234-5678 is logged.", "patient 123-4567 shows in the URL.",
    "birth date: March 12, 1984 is in the export.", "dob=19840312 sits in the fixture.", "DOB 19840312 is in a test.",
    "d.o.b. 03-12-84 is in the seed file.", "dob: 3/12/84 is in the template.",
    "Dr. Jean-Luc Picard is in the template.", "Dr. Mary-Jane Watson is named in a note.", "Dr. JANE SMITH is in a fixture.",
    "Dr Jane van der Berg is in the seed."];
  for (const text of refused) {
    assert.match(concernsProblem({ concerns: [{ ...A, note: text }] }) ?? "", /^concerns\[0\]\.note holds something shaped/, text);
    assert.match(verdictsProblem({ verdicts: [{ note: text }] }) ?? "", /^verdicts\[0\]\.note holds something shaped/, text);
  }
  // The twelve over-refusal probes, and the kept list, still pass
  const kept = ["The dob column is unencrypted.", "patient_id has no index.", "Dr. Who is a fixture name.",
    "The member table has no row level security.", "Patient ids go to the log on every request.", "The account page has no MFA.",
    "A migration on 2026-10-20 dropped the audit table.", "Dr. visits are listed without a check.", "The Mr. Smith fixture is fine.",
    "The birth date column has no check.", "Accounts 1 to 20 are seeded.", "Dr. API Gateway is a joke name in a comment."];
  for (const text of kept) assert.equal(concernsProblem({ concerns: [{ ...A, note: text }] }), null, text);
});

test("The free-text shapes never change how a table, file or migration name is sent", () => {
  const key = Buffer.alloc(32, 7);
  for (const name of ["patient_20240101", "account_20240101", "member_00001"]) {
    assert.equal(sentIdentifier(key, name), name);
    assert.equal(holdsRecordValue(name), false, name);
  }
  for (const path of ["src/patient12345.ts", "supabase/migrations/20240312000000_account_12345.sql"]) assert.equal(sentPath(key, path), path);
});

test("A raising call that may have run but got no readable answer says its texts weren't kept", async () => {
  for (const reply of [{ status: 500, json: { error: "internal_error", next_step: "x", correlation_id: "corr_12345678" } },
    { status: 200, raw: "{not json" }]) {
    const root = repo();
    const { s, runCheck } = await setup(() => reply);
    try {
      const out = await runCheck({ goal: "check", concerns: [{ ...A, note: TEXT_A }] }, { roots: [root] });
      assert.ok(out.error, JSON.stringify(out).slice(0, 200));
      assert.deepEqual(out.local_notes, [CONCERN_NOTES.concern_texts_unanswered], out.error);
    } finally { await s.close(); }
  }
});

test("A nested project's .custosa/local and .custosa/.gitignore are skipped too", async () => {
  const root = repo();
  mkdirSync(join(root, "apps/web/.custosa/local"), { recursive: true });
  writeFileSync(join(root, "apps/web/.custosa/local/concerns.json"), '{"version":1,"concerns":{}}\n');
  writeFileSync(join(root, "apps/web/.custosa/.gitignore"), "local/\n");
  writeFileSync(join(root, "apps/web/.custosa/keep.txt"), "the user's own file\n");
  const { s, runCheck } = await setup(() => ({ status: 200, json: EVALUATE_OK }));
  try {
    await runCheck({ goal: "check" }, { roots: [root] });
    const doc = JSON.stringify(s.calls[0].body.fact_document);
    assert.equal(doc.includes("apps/web/.custosa/local"), false);
    assert.equal(doc.includes("apps/web/.custosa/.gitignore"), false);
  } finally { await s.close(); }
});

test("Core's prose shapes (record numbers, id codes, street addresses, a name beside a condition) are refused", () => {
  const refused = ["MRN 0012–3456 is in the log.", "MRN 0012—3456 is in the log.", "MRN 0012.3456 is in the log.",
    "MRN 0012 - 3456 is in the log.", "mrn: 1234 is in the seed.", "patient # 1234 shows in the URL.",
    "chart no. 1234 is printed.", "policy number 1234 is in a fixture.", "insurance 98765 is logged.",
    "record no. 55555 is in the export.", "W123456789 is in the seed.", "ticket ABC1234567 is in a comment.",
    "code 4471-882-19 is in the template.", "see PR 1234-56-78 for the dump.", "lives at 12 Oak Tree Lane is in a fixture.",
    "Jane Smith has diabetes is in the seed."];
  for (const text of refused) {
    assert.match(concernsProblem({ concerns: [{ ...A, note: text }] }) ?? "", /^concerns\[0\]\.note holds something shaped/, text);
    assert.match(verdictsProblem({ verdicts: [{ note: text }] }) ?? "", /^verdicts\[0\]\.note holds something shaped/, text);
  }
  // searched roots are read with core's prose_value_spans too
  for (const root of ["exports/W123456789", "notes/code 4471-882-19", "seed/12 Oak Tree Lane"]) {
    assert.match(verdictsProblem({ verdicts: [{ searched: [{ pattern_id: "p", roots: [root] }] }] }) ?? "",
      /^verdicts\[0\]\.searched\[0\]\.roots\[0\] holds/, root);
  }
  const kept = ["The dob column is DATE.", "born_at timestamptz has no check.", "Version 1.2.3 adds it.", "Commit 1a2b3c4 adds it.",
    "Migration 2024 03 12 adds index.", "The insurance table has no row level security.", "Diabetes Care is the app name."];
  for (const text of kept) assert.equal(concernsProblem({ concerns: [{ ...A, note: text }] }), null, text);
  for (const root of ["supabase/migrations", "src/app/patients", "supabase/migrations/20240312000000_account_12345.sql"]) {
    assert.equal(verdictsProblem({ verdicts: [{ searched: [{ pattern_id: "p", roots: [root] }] }] }), null, root);
  }
});

test("A title before names with accented letters is refused", () => {
  for (const text of ["Dr. José García is in the template.", "Dr. Siobhán Murphy is named in a note.", "Dr. Zoë Kim is in the seed.",
    "Dr. ÉLODIE DURAND is in a fixture."]) {
    assert.match(concernsProblem({ concerns: [{ ...A, note: text }] }) ?? "", /^concerns\[0\]\.note holds something shaped/, text);
  }
  for (const text of ["Dr. Who is a fixture name.", "Dr. visits are listed without a check."]) {
    assert.equal(concernsProblem({ concerns: [{ ...A, note: text }] }), null, text);
  }
});

test("A note screened after another never changes how it is read (decider_ref has no screen left)", () => {
  for (const text of ["Jane Roe 1981-04-05 was in the seed file.", "Mary Major 1983-02-03 in export.", "12 Oak Tree Lane is in the seed. 14 Elm Road too."]) {
    assert.match(verdictsProblem({ verdicts: [{ note: text }] }) ?? "", /^verdicts\[0\]\.note holds something shaped/, text);
    assert.match(concernsProblem({ concerns: [{ ...A, note: text }] }) ?? "", /^concerns\[0\]\.note holds something shaped/, text);
  }
});

test("Dotless and dotted i, control-character spaces and hash-shaped runs read as core reads them", () => {
  for (const text of ["ınsurance 98765 is logged.", "patıent # 1234 shows in the URL.", "Jane Smith has dıabetes is in the seed.",
    "socıal security 123 45 6789 is in a fixture.", "İnsurance 98765 is logged.", "mrn\x1c1234 is in the seed.", "mrn\x851234 is in the seed.",
    "u_5551234567890123 is in the log.", `${"1".repeat(64)} is in the log.`]) {
    assert.match(concernsProblem({ concerns: [{ ...A, note: text }] }) ?? "", /^concerns\[0\]\.note holds something shaped/, JSON.stringify(text));
    assert.match(verdictsProblem({ verdicts: [{ note: text }] }) ?? "", /^verdicts\[0\]\.note holds something shaped/, JSON.stringify(text));
  }
  for (const root of ["logs/u_5551234567890123", `logs/${"1".repeat(64)}`]) {
    assert.match(verdictsProblem({ verdicts: [{ searched: [{ pattern_id: "p", roots: [root] }] }] }) ?? "",
      /^verdicts\[0\]\.searched\[0\]\.roots\[0\] holds/, root);
  }
  // names and paths keep the hash masking
  const key = Buffer.alloc(32, 7);
  assert.equal(sentIdentifier(key, "u_5551234567890123"), "u_5551234567890123");
});

/* T29 o2 step 2 (T29-P1-C116 (a)): core's response is one body with its index, and concerns past the client limit are
 * grouped by status. The CLI matches a call's raises in the same call: from index.concerns, or by reading each grouped
 * status through get_result (free, never shown to Claude). Nothing waits for a later call. */
const INDEX = (concerns, grouped) => ({
  result_counts: { by_state: { pass: 0, fail: 0, not_applicable: 0, needs_review: 0, unknown: 0, error: 0 }, by_severity: {},
    by_state_and_severity: [] },
  practices: [], fails: [], open: [], questions: [], concerns, fixes: [], lists: [],
  ...(grouped ? { concerns_grouped: grouped } : {}),
});
const RESULT = (select, results) => ({ goal: "check", session: EVALUATE_OK.session, select, part: "detail",
  matched: results.length, results, is_fetch_only: true, charged_units: 0, correlation_id: "corr_12345678" });

test("T29 o2: a raise listed in index.concerns keeps its text in the same call, with no other call", async () => {
  const root = repo();
  const { s, runCheck } = await setup(() => ({ status: 200, json: { ...EVALUATE_OK, concern_options: OPTIONS,
    index: INDEX([listed(ID_B, B, { raised_now: true }), listed(ID_A, A, { raised_now: true })]) } }));
  try {
    const out = await runCheck({ goal: "check", concerns: [{ ...A, note: TEXT_A }, { ...B, note: TEXT_B }] }, { roots: [root] });
    assert.equal(s.calls.length, 1);
    assert.deepEqual(new Set(readTexts(root).keys()), new Set([ID_A, ID_B]));
    assert.equal(out.local_notes, undefined);
  } finally { await s.close(); }
});

test("T29 o2: a raise grouped past the client limit is read through get_result and keeps its text in the same call", async () => {
  const root = repo();
  const select = { list: "concerns.unconfirmed" };
  const { s, runCheck } = await setup((call) => ({ status: 200, json: call.body.select
    ? RESULT(call.body.select, [listed(ID_B, B, { raised_now: true }), listed(ID_A, A, { raised_now: true })])
    : { ...EVALUATE_OK, concern_options: OPTIONS, index: INDEX([], [{ status: "unconfirmed", count: 2, select }]) } }));
  try {
    const out = await runCheck({ goal: "check", concerns: [{ ...A, note: TEXT_A }, { ...B, note: TEXT_B }] }, { roots: [root] });
    assert.equal(s.calls.length, 2);
    assert.deepEqual(s.calls[1].body, { goal: "check", session: EVALUATE_OK.session, select });
    assert.equal(JSON.stringify(s.calls[1].body).includes(TEXT_A), false, "a get_result read carries no text");
    assert.deepEqual(new Set(readTexts(root).keys()), new Set([ID_A, ID_B]));
    assert.equal(out.local_notes, undefined);
    assert.ok(!("results" in out) && !("matched" in out), "the read is the CLI's own, not shown in the answer");
  } finally { await s.close(); }
});

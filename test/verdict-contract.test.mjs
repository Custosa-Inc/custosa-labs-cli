/* The verdict contract, the CLI half: a verdict sends
 * reason_code, refs and an optional note, never the free reason or the old code; a concern sends refs and a note, never
 * the free text; a decision's decider_ref is one of the nine roles or local:<8 hex>, never a free name. Each body item
 * the tool builds fits core's request.schema.json when that checkout is at hand. Stub evaluator and temp folders only. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import AjvModule from "ajv";
import Ajv2020Module from "ajv/dist/2020.js";
import { INPUT_SCHEMA, makeRunCheck, concernsProblem, decisionsProblem, verdictsProblem, REASON_CODES, DECIDER_ROLES } from "../lib/inspector/tool.mjs";
import { readTexts } from "../lib/inspector/concerns.mjs";
import { writeToken } from "../lib/inspector/auth.mjs";
import { loadRules } from "../lib/inspector/rules.mjs";
import { EVALUATE_OK, stub } from "./stub-evaluator.mjs";
import { coreSkip, requireCore } from "./core-checkout.mjs";

const Ajv = AjvModule.default ?? AjvModule;
const Ajv2020 = Ajv2020Module.default ?? Ajv2020Module;
const validateArgs = new Ajv({ strict: true }).compile(INPUT_SCHEMA);
const RULESET = { id: "2026-10-20.0123abcd", rules: loadRules(fileURLToPath(new URL("./fixtures/rules/", import.meta.url))), queries: [] };
const TOKEN = `phisc_${"t".repeat(43)}`;
const SESSION = "ps_abcdefghijklmnopqrstuv";
const temp = (prefix) => realpathSync(mkdtempSync(join(tmpdir(), prefix)));
const quiet = {
  ruleset: RULESET,
  collectCatalog: async () => ({ status: "not_run", count: 0, reason: "service_missing", preflight: null, queries: [] }),
  collectPlatform: async () => ({ provider: null, status: "not_run", reason: "no_token", settings: {} }),
};
function repo() {
  const root = temp("verdict-");
  mkdirSync(join(root, "src"), { recursive: true });
  writeFileSync(join(root, "src/db.ts"), 'export async function save(p) { await db.from("patients").insert(p); }\n');
  return root;
}
async function setup(handler = () => ({ status: 200, json: EVALUATE_OK })) {
  const configDir = join(temp("verdict-cfg-"), "custosa");
  const s = await stub(handler);
  writeToken(TOKEN, { configDir, host: new URL(s.url).origin });
  // learning on, so notes leave (the gate has its own tests, learning-gate). The note screen is off here: this
  // file checks the request body, and the screen has its own tests (note-screen). With the shipped rule file
  // the notes' backtick refs name tables this temp root doesn't have, so they refuse.
  const runCheck = makeRunCheck({ configDir, localOnly: false, buildOptions: quiet, learningFor: () => true, noteRules: null,
    evaluatorUrl: () => ({ url: s.url, origin: new URL(s.url).origin }), clientOptions: { sleep: async () => {} } });
  return { s, runCheck };
}

// The evaluator's enums.REASON_CODES and enums.DECIDER_ROLES.
const CORE_REASON_CODES = ["control_at", "control_missing", "control_partial", "handled_by_platform", "not_used",
  "firebase_not_used", "no_edge_functions", "no_inbound_webhooks", "no_mobile_client", "no_model_use", "no_retrieval",
  "no_tool_calls", "retrieval_filtered_at", "tools_scoped_at"];
const CORE_ROLES = ["owner", "admin", "developer", "engineering-lead", "security-lead", "privacy-officer",
  "compliance-officer", "clinical-lead", "other"];

const verdict = { practice_id: "rls-forced", state: "pass", reason_code: "control_at", refs: ["public.patients", "db/migrations/001.sql:4-9"],
  note: "`public.patients` has row level security forced because the migration turns it on." };
const concern = { category: "logging", area: "logging", file_kind: "route_handler", proposed_severity: "high",
  refs: ["src/api/intake.ts:12"], note: "`src/api/intake.ts` logs the whole request body because it calls console.log on it." };

test("the tool's reason codes and roles are core's, in core's order", () => {
  assert.deepEqual([...REASON_CODES], CORE_REASON_CODES);
  assert.deepEqual([...DECIDER_ROLES], CORE_ROLES);
});

test("a verdict takes reason_code, refs and note; the free reason, the old code and note_withheld are refused", () => {
  assert.equal(validateArgs({ goal: "check", verdicts: [verdict] }), true);
  assert.equal(validateArgs({ goal: "check", verdicts: [{ practice_id: "rls-forced", state: "fail", reason_code: "control_missing" }] }), true);
  for (const code of CORE_REASON_CODES) assert.equal(validateArgs({ goal: "check", verdicts: [{ ...verdict, reason_code: code }] }), true, code);
  const bad = [
    { ...verdict, reason_code: "no_patient_tables" },
    { ...verdict, reason_code: undefined },
    { ...verdict, reason: "No table holds patient rows." },
    { ...verdict, code: "not_used" },
    { ...verdict, note_withheld: true },
    { ...verdict, note: "two\nlines" },
    { ...verdict, note: "x".repeat(301) },
    { ...verdict, note: "" },
    { ...verdict, refs: Array.from({ length: 11 }, (_, i) => `t${i}`) },
    { ...verdict, refs: ["public.patients", "public.patients"] },
    { ...verdict, refs: ["/etc/passwd:1"] },
    { ...verdict, refs: ["has space"] },
  ];
  for (const v of bad) assert.equal(validateArgs({ goal: "check", verdicts: [JSON.parse(JSON.stringify(v))] }), false, JSON.stringify(v));
  assert.equal(validateArgs({ goal: "check", verdicts: [{ ...verdict, note: "x".repeat(300) }] }), true);
});

test("a concern takes refs and a note; the free text is refused, and the note is required", () => {
  assert.equal(validateArgs({ goal: "check", concerns: [concern] }), true);
  const { refs, ...noRefs } = concern;
  assert.equal(validateArgs({ goal: "check", concerns: [noRefs] }), true);
  const { note, ...noNote } = concern;
  for (const c of [noNote, { ...concern, text: "a text" }, { ...concern, note_withheld: true }, { ...concern, note: "x".repeat(501) },
    { ...concern, note: "a\nb" }, { ...concern, kind: "access" }]) {
    assert.equal(validateArgs({ goal: "check", concerns: [c] }), false, JSON.stringify(c));
  }
  assert.equal(validateArgs({ goal: "check", concerns: [{ ...concern, note: "x".repeat(500) }] }), true);
});

test("decider_ref is one of the nine roles or local:<8 hex>, never a free name", () => {
  const d = { object_id: "rls-forced@public.patients", option: "pass" };
  for (const role of CORE_ROLES) assert.equal(validateArgs({ goal: "check", decisions: [{ ...d, decider_ref: role }] }), true, role);
  assert.equal(validateArgs({ goal: "check", decisions: [{ ...d, decider_ref: "local:0a1b2c3d" }] }), true);
  for (const ref of ["lead-dentist-1", "role.security-lead", "Owner", "local:0A1B2C3D", "local:0a1b2c3", "local:0a1b2c3d4", "Jane Smith", "jane"]) {
    assert.equal(validateArgs({ goal: "check", decisions: [{ ...d, decider_ref: ref }] }), false, ref);
  }
  assert.equal(decisionsProblem({ decisions: [{ ...d, decider_ref: "security-lead" }] }, { env: {} }), null); // no CI here, as on a person's machine
});

test("a verdict's note and refs and a concern's note and refs are screened locally before anything is sent", () => {
  assert.equal(verdictsProblem({ verdicts: [verdict] }), null);
  assert.match(verdictsProblem({ verdicts: [{ ...verdict, note: "The admin is jane.doe@example.com" }] }), /verdicts\[0\]\.note holds something shaped like a record value or a secret/);
  assert.match(verdictsProblem({ verdicts: [{ ...verdict, refs: ["patients/jane.doe@example.com:1"] }] }), /verdicts\[0\]\.refs\[0\] holds something shaped like a record value or a secret/);
  assert.equal(concernsProblem({ concerns: [concern] }), null);
  assert.match(concernsProblem({ concerns: [{ ...concern, note: "   " }] }), /concerns\[0\]\.note is blank/);
  assert.match(concernsProblem({ concerns: [{ ...concern, note: "Patient MRN 4471-882-19 is logged" }] }), /concerns\[0\]\.note holds something shaped like a record value or a secret/);
  assert.match(concernsProblem({ concerns: [{ ...concern, refs: ["seeds/jane.doe@example.com:2"] }] }), /concerns\[0\]\.refs\[0\] holds something shaped like a record value or a secret/);
});

test("the body sends a verdict's reason_code, refs and note and a concern's refs and note as written; the note is kept locally", async () => {
  const root = repo();
  const raised = { concern_id: "cn_0123456789abcdef", raised_now: true, category: concern.category, area: concern.area,
    file_kind: concern.file_kind, proposed_severity: concern.proposed_severity, severity: concern.proposed_severity, status: "unconfirmed",
    label: "waits for a confirm", next: { awaiting: "confirm", options: [{ id: "real_problem" }, { id: "not_a_problem" }, { id: "not_sure" }] } };
  // o1b 3d-3: the concern is a line of the answer's index (core sends no top-level concerns since 3d-1).
  const { s, runCheck } = await setup(() => ({ status: 200, json: { ...EVALUATE_OK, index: { result_counts: { by_state: { pass: 0, fail: 0, not_applicable: 0, needs_review: 0, unknown: 0,
    error: 0 }, by_severity: {}, by_state_and_severity: [] }, practices: [], fails: [], open: [], questions: [], concerns: [raised],
    fixes: [], lists: [] }, concern_options: { real_problem: "It's a real problem", not_a_problem: "It isn't a problem", not_sure: "Not sure" } } }));
  try {
    const bare = { practice_id: "audit-log", state: "fail", reason_code: "control_missing" };
    await runCheck({ goal: "check", session: SESSION, verdicts: [verdict, bare], concerns: [concern],
      decisions: [{ object_id: "rls-forced@public.patients", option: "pass", decider_ref: "local:0a1b2c3d" }] }, { roots: [root] });
    const body = s.calls[0].body;
    assert.deepEqual(body.verdicts, [verdict, bare]);
    assert.deepEqual(body.concerns, [concern]);
    assert.equal(body.decisions[0].decider_ref, "local:0a1b2c3d");
    assert.ok(body.verdicts.every((v) => !("reason" in v) && !("code" in v)), "no free reason or old code is sent");
    assert.ok(body.concerns.every((c) => !("text" in c)), "no free text is sent");
    assert.equal(readTexts(root).get("cn_0123456789abcdef")?.text, concern.note);
  } finally { await s.close(); }
});

// Core's request schema, from CUSTOSA_CORE_CONTRACTS (its app/contracts folder) or a checkout next to this one.
const CORE_DIR = process.env.CUSTOSA_CORE_CONTRACTS ?? "";
const REQUEST = join(CORE_DIR, "request.schema.json");

test("each verdict, concern and decision the tool sends fits core's request.schema.json",
  { skip: coreSkip(existsSync(REQUEST), "no core request.schema.json (set CUSTOSA_CORE_CONTRACTS)") }, async () => {
    requireCore("CUSTOSA_CORE_CONTRACTS", existsSync(REQUEST));
    const schema = JSON.parse(readFileSync(REQUEST, "utf8"));
    const ajv = new Ajv2020({ strict: false, allErrors: true });
    ajv.addSchema(JSON.parse(readFileSync(join(CORE_DIR, "fact_document.schema.json"), "utf8")));
    ajv.addSchema(schema, "request");
    const fits = (def, item) => {
      const ok = ajv.validate({ $ref: `request#/$defs/${def}` }, item);
      assert.ok(ok, `${def} ${JSON.stringify(item)}: ${ajv.errorsText()}`);
    };
    assert.deepEqual(schema.$defs.verdict.properties.reason_code.enum, CORE_REASON_CODES);
    assert.deepEqual(schema.$defs.decider_ref.oneOf[0].enum, CORE_ROLES);
    const root = repo();
    const { s, runCheck } = await setup();
    try {
      await runCheck({ goal: "check", session: SESSION, verdicts: [verdict, { practice_id: "audit-log", state: "fail", reason_code: "control_missing" }],
        concerns: [concern], decisions: [{ object_id: "rls-forced@public.patients", option: "pass", decider_ref: "clinical-lead" }] }, { roots: [root] });
      const body = s.calls[0].body;
      for (const v of body.verdicts) fits("verdict", v);
      for (const c of body.concerns) fits("concern", c);
      for (const d of body.decisions) fits("decision", d);
    } finally { await s.close(); }
  });

test("a blank verdict note is refused locally, as a blank concern note is", () => {
  for (const note of [" ", "\t", "   \t  "]) {
    assert.match(verdictsProblem({ verdicts: [{ ...verdict, note }] }) ?? "", /^verdicts\[0\]\.note is blank/, JSON.stringify(note));
  }
  assert.equal(verdictsProblem({ verdicts: [verdict] }), null);
});

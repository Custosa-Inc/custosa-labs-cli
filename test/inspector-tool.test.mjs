/* check_schema wired end to end: the handler runs the collectors, builds and validates the fact documents, sends
 * them to a local stub evaluator and returns its answer unchanged; nothing is collected or sent before sign-in;
 * advice, page and resend calls collect nothing; local-only mode builds without sending. No real service, no real
 * config folder: every test uses a temporary one. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { makeRunCheck, TOOL_ERRORS, ANNOTATIONS, INSTRUCTIONS, DESCRIPTION } from "../lib/inspector/tool.mjs";
import { LOCAL } from "../lib/inspector/client.mjs";
import { writeToken } from "../lib/inspector/auth.mjs";
import { loadRules } from "../lib/inspector/rules.mjs";
import { validateFactDocument } from "../lib/inspector/schema.mjs";
import { hashed } from "../lib/inspector/ids.mjs";
import { EVALUATE_OK, stub } from "./stub-evaluator.mjs";

const RULES = loadRules(fileURLToPath(new URL("./fixtures/rules/", import.meta.url)));
const RULESET = { id: "2026-10-20.0123abcd", rules: RULES, queries: [] };
const TOKEN = `phisc_${"t".repeat(43)}`;
const temp = (prefix) => realpathSync(mkdtempSync(join(tmpdir(), prefix)));
const quiet = {
  ruleset: RULESET,
  collectCatalog: async () => ({ status: "not_run", count: 0, reason: "service_missing", preflight: null, queries: [] }),
  collectPlatform: async () => ({ provider: null, status: "not_run", reason: "no_token", settings: {} }),
};

function repo(files = {}) {
  const root = temp("a7-tool-");
  const all = { "src/db.ts": 'export async function save(p) { await db.from("patients").insert(p); }\n', ...files };
  for (const [p, t] of Object.entries(all)) { mkdirSync(join(root, p, ".."), { recursive: true }); writeFileSync(join(root, p), t); }
  return root;
}

async function setup(handler = () => ({ status: 200, json: EVALUATE_OK }), { signedIn = true, ...deps } = {}) {
  const configDir = join(temp("a7-tool-cfg-"), "custosa");
  const s = await stub(handler);
  if (signedIn) writeToken(TOKEN, { configDir, host: new URL(s.url).origin });
  const builds = [];
  const runCheck = makeRunCheck({
    configDir, localOnly: false, buildOptions: quiet,
    evaluatorUrl: () => ({ url: s.url, origin: new URL(s.url).origin }), clientOptions: { sleep: async () => {} },
    build: async (roots, opts) => { builds.push(opts); return (await import("../lib/inspector/factdoc.mjs")).buildFactDocuments(roots, opts); },
    ...deps,
  });
  return { s, runCheck, configDir, builds };
}

test("PC6: the annotations say a call sends data out and is charged: not read-only, not idempotent, open-world", () => {
  assert.deepEqual({ ...ANNOTATIONS }, { title: "PHI Schema Check", readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true });
});

test("check: collects, builds a valid document, sends it, and returns the evaluator's answer unchanged", async () => {
  const root = repo();
  const { s, runCheck } = await setup();
  try {
    const out = await runCheck({ goal: "check" }, { roots: [root], log: () => {} });
    assert.deepEqual(out, EVALUATE_OK);
    assert.equal(s.calls.length, 1);
    const [call] = s.calls;
    assert.equal(call.url, "/v1/evaluate");
    assert.equal(call.headers.authorization, `Bearer ${TOKEN}`);
    assert.deepEqual(Object.keys(call.body).sort(), ["fact_document", "goal"]);
    assert.equal(call.body.goal, "check");
    assert.equal(validateFactDocument(call.body.fact_document), null);
    assert.ok(!JSON.stringify(call.body).includes(root));
  } finally { await s.close(); }
});

test("nothing is collected or sent before sign-in", async () => {
  const root = repo();
  const { s, runCheck, builds } = await setup(undefined, { signedIn: false });
  try {
    for (const args of [{ goal: "check" }, { goal: "explain", practice_id: "rls-forced" }, { goal: "check", session: "ps_abcdefghijklmnopqrstuv", page: 2 }]) {
      const out = await runCheck(args, { roots: [root] });
      assert.equal(out.error, "sign_in_required");
      assert.equal(out.next_step, LOCAL.sign_in_required);
    }
    assert.equal(builds.length, 0);
    assert.equal(s.calls.length, 0);
  } finally { await s.close(); }
});

test("a check carrying the answers, with the location confirmed and its path hashed where needed", async () => {
  const root = repo({ "odd dir/a.ts": "line1\nline2\nline3\n" });
  const { s, runCheck, configDir } = await setup();
  try {
    await runCheck({ goal: "check", session: "ps_abcdefghijklmnopqrstuv", answers: [
      { object_id: "audit-log@src/db.ts", question_id: "location", answer: "here", location: "odd dir/a.ts:2-3" },
      { object_id: "audit-log@src/x.ts", question_id: "location", answer: "here", location: "src/missing.ts:1" },
      { object_id: "audit-log@src/db.ts", question_id: "location", answer: "here", location: "src/db.ts:40" },
      { object_id: "rls-forced", question_id: "purpose", answer: "phi" },
    ] }, { roots: [root] });
    const [call] = s.calls;
    assert.equal(call.body.goal, "check");
    assert.equal(call.body.session, "ps_abcdefghijklmnopqrstuv");
    const doc = call.body.fact_document;
    assert.equal(doc.session, "ps_abcdefghijklmnopqrstuv");
    const { readFileSync } = await import("node:fs");
    const key = readFileSync(join(configDir, "install.key"));
    assert.deepEqual(doc.answers, [
      { object_id: "audit-log@src/db.ts", question_id: "location", answer: "here", location: `${hashed(key, "odd dir")}/a.ts:2-3`, location_kind: "other" },
      { object_id: "audit-log@src/x.ts", question_id: "location", answer: "here", location: null, location_kind: "not_found" },
      { object_id: "audit-log@src/db.ts", question_id: "location", answer: "here", location: null, location_kind: "not_found" },
      { object_id: "rls-forced", question_id: "purpose", answer: "phi", location: null, location_kind: null },
    ]);
  } finally { await s.close(); }
});

test("fix sends finding_ids; verify sends none and refuses them; advice, page and resend collect nothing", async () => {
  const root = repo();
  const { s, runCheck, builds } = await setup();
  try {
    await runCheck({ goal: "fix", finding_ids: ["rls-forced@public-patients", "rls-enabled@public.care_messages"] }, { roots: [root] });
    assert.deepEqual(s.calls[0].body.finding_ids, ["rls-forced@public-patients", "rls-enabled@public.care_messages"]);
    // verify takes no finding_ids (the contract's verify checks every fix of the session): refused, nothing sent.
    const refused = await runCheck({ goal: "verify", finding_ids: ["rls-forced@public-patients"] }, { roots: [root] });
    assert.equal(refused.error, "finding_ids_need_fix");
    assert.equal(refused.next_step, TOOL_ERRORS.finding_ids_need_fix);
    assert.equal(s.calls.length, 1, "a refused verify sends nothing");
    await runCheck({ goal: "verify" }, { roots: [root] });
    assert.equal(s.calls[1].body.goal, "verify");
    assert.equal(s.calls[1].body.finding_ids, undefined);
    const n = builds.length;
    await runCheck({ goal: "check", session: "ps_abcdefghijklmnopqrstuv", page: 2 }, { roots: [root] });
    assert.deepEqual(s.calls[2].body, { goal: "check", session: "ps_abcdefghijklmnopqrstuv", page: 2 });
    await runCheck({ goal: "check", session: "ps_abcdefghijklmnopqrstuv", resend: ["all"] }, { roots: [root] });
    assert.deepEqual(s.calls[3].body, { goal: "check", session: "ps_abcdefghijklmnopqrstuv", resend: "all" });
    await runCheck({ goal: "pattern", stack: "nextjs-supabase", need: "audit-log" }, { roots: [root] });
    assert.deepEqual(s.calls[4].body, { goal: "pattern", stack: "nextjs-supabase", need: "audit-log" });
    await runCheck({ goal: "plan", entities: [{ name: "patients", columns: [{ name: "dob" }, { name: "first name" }] }] }, { roots: [root] });
    assert.equal(s.calls[5].body.goal, "plan");
    assert.equal(s.calls[5].body.entities[0], "patients");
    assert.equal(s.calls[5].body.entities[1], "patients.dob");
    assert.match(s.calls[5].body.entities[2], /^patients\.u_[0-9a-f]{16}$/);
    assert.equal(builds.length, n, "no facts collected for page, resend or advice");
    // Missing inputs are answered locally, nothing sent.
    const before = s.calls.length;
    assert.equal((await runCheck({ goal: "check", page: 2 }, { roots: [root] })).next_step, TOOL_ERRORS.needs_session);
    assert.equal((await runCheck({ goal: "check", session: "ps_abcdefghijklmnopqrstuv", resend: ["nope"] }, { roots: [root] })).next_step, TOOL_ERRORS.bad_resend);
    assert.equal((await runCheck({ goal: "explain" }, { roots: [root] })).next_step, TOOL_ERRORS.explain_needs_input);
    assert.equal(s.calls.length, before);
  } finally { await s.close(); }
});

test("nested repositories: listed and not sent by default; include_other_roots sends every one, with nothing of the parent's (review p12)", async () => {
  const files = {};
  for (let i = 0; i < 12; i++) { files[`fixtures/repo${i}/.git/HEAD`] = "ref: refs/heads/main\n"; files[`fixtures/repo${i}/x.ts`] = "export const y = 2;\n"; }
  const root = repo(files);
  mkdirSync(join(root, ".git"), { recursive: true });
  writeFileSync(join(root, ".git", "HEAD"), "ref: refs/heads/main\n");
  const catalogCalls = [];
  const deps = { buildOptions: { ...quiet, collectCatalog: async (q) => { catalogCalls.push(q.length); return quiet.collectCatalog(); } } };
  let { s, runCheck } = await setup(undefined, deps);
  try {
    const out = await runCheck({ goal: "fix", session: "ps_abcdefghijklmnopqrstuv", finding_ids: ["rls-forced"],
      answers: [{ object_id: "rls-forced", question_id: "purpose", answer: "phi" }] }, { roots: [root] });
    assert.equal(s.calls.length, 1, "one charged evaluation: the project root's");
    assert.deepEqual(out.results.map((r) => [r.root, r.nested]), [[0, ""]]);
    assert.equal(out.other_roots.count, 12);
    assert.equal(out.other_roots.checked, 0);
    assert.equal(out.other_roots.not_checked_root_ids.length, 12);
    assert.ok(out.other_roots.not_checked_root_ids.every((id) => /^[0-9a-f]{64}$/.test(id)));
    assert.match(out.other_roots.note, /include_other_roots/);
    assert.ok(!JSON.stringify(out.other_roots).includes("fixtures"));
    assert.deepEqual(s.calls[0].body.finding_ids, ["rls-forced"]);
  } finally { await s.close(); }
  ({ s, runCheck } = await setup(undefined, deps));
  try {
    const out = await runCheck({ goal: "fix", session: "ps_abcdefghijklmnopqrstuv", finding_ids: ["rls-forced"], include_other_roots: true,
      answers: [{ object_id: "rls-forced", question_id: "purpose", answer: "phi" }] }, { roots: [root] });
    // no cap of 10; the call's time budget is the only bound.
    assert.equal(s.calls.length, 13, "the project root and all 12 nested");
    assert.equal(out.other_roots.checked, 12);
    assert.equal(out.other_roots.not_checked_root_ids.length, 0);
    const [first, ...nested] = s.calls;
    assert.equal(first.body.session, "ps_abcdefghijklmnopqrstuv");
    for (const c of nested) {
      assert.equal(c.body.session, undefined);
      assert.equal(c.body.finding_ids, undefined);
      const doc = c.body.fact_document;
      assert.equal(validateFactDocument(doc), null);
      assert.equal(doc.session, null);
      assert.deepEqual(doc.answers, []);
      for (const name of ["catalog", "platform"]) assert.deepEqual(doc.collection.find((x) => x.collector === name), { collector: name, status: "not_run", count: 0, reason: "not_configured" });
      assert.notEqual(doc.root_id, first.body.fact_document.root_id);
    }
    assert.equal(catalogCalls.length, 2, "the catalog is read once per call, for the project root only");
  } finally { await s.close(); }
});

test("a document that fails its checks is never sent; a package without a rule bundle says so", async () => {
  const root = repo();
  let { s, runCheck } = await setup(undefined, {
    build: async () => ({ documents: [{ project: 0, label: "", nested: false, document: { schema_version: 2 }, problem: { at: "/inspector_version", keyword: "required" } }] }),
  });
  try {
    const out = await runCheck({ goal: "check" }, { roots: [root], log: () => {} });
    assert.equal(out.error, "document_invalid");
    assert.equal(out.at, "/inspector_version");
    assert.equal(s.calls.length, 0);
  } finally { await s.close(); }
  // a document too large for the contract's limit is the project's size, never "update the inspector".
  ({ s, runCheck } = await setup(undefined, {
    build: async () => ({ documents: [{ project: 0, label: "", nested: false, document: { schema_version: 2 }, problem: { at: "", keyword: "too_large" } }] }),
  }));
  try {
    const out = await runCheck({ goal: "check" }, { roots: [root], log: () => {} });
    assert.equal(out.error, "document_too_large");
    assert.equal(out.next_step, TOOL_ERRORS.document_too_large);
    assert.ok(!/setup|update/i.test(out.next_step) && /narrower folder/.test(out.next_step));
    assert.equal(s.calls.length, 0);
  } finally { await s.close(); }
  ({ s, runCheck } = await setup(undefined, { buildOptions: { ...quiet, ruleset: undefined, bundleDir: temp("a7-nobundle-") } }));
  try {
    const out = await runCheck({ goal: "check" }, { roots: [root] });
    assert.equal(out.error, "inspector_incomplete");
    assert.equal(s.calls.length, 0);
  } finally { await s.close(); }
});

test("local-only mode builds and validates without signing in or sending", async () => {
  const root = repo({ "supabase/config.toml": "[functions.a]\nverify_jwt = true\n" });
  const runCheck = makeRunCheck({ localOnly: true, configDir: join(temp("a7-local-"), "custosa"), buildOptions: quiet,
    evaluate: async () => assert.fail("sent"), readToken: () => assert.fail("read the sign-in") });
  const out = await runCheck({ goal: "check" }, { roots: [root] });
  assert.equal(out.local_only, true);
  assert.equal(out.documents.length, 1);
  assert.equal(validateFactDocument(out.documents[0].document), null);
  assert.equal(out.documents[0].document.supabase.edge_functions.status, "ok");
});

test("user-facing words follow the copy rules", () => {
  const words = [...Object.values(TOOL_ERRORS), ...Object.values(LOCAL), INSTRUCTIONS, DESCRIPTION].join("\n");
  assert.ok(!/—/.test(words), "no em dashes");
  for (const banned of [/\bcompliant\b/i, /\bcertified\b/i, /\bguarantee/i, /\bsecure\b/i, /HIPAA (compliant|ready)/i]) assert.ok(!banned.test(words), String(banned));
  assert.ok(!/\bfree\b/i.test(words), "never \"free\" (next to a price or anywhere in these words)");
});

test("TU4: the description is factual: what it does, what it sends, what it costs; no promotion, no orders to the agent", () => {
  for (const banned of [/\bexpert\b/i, /never stop/i, /without waiting/i, /\bmust\b/i, /\byou should\b/i, /\balways\b/i]) {
    assert.ok(!banned.test(DESCRIPTION), String(banned));
    assert.ok(!/\bexpert\b/i.test(INSTRUCTIONS) && !/never stop/i.test(INSTRUCTIONS), "instructions too");
  }
  assert.match(DESCRIPTION, /readiness score/);
  assert.match(DESCRIPTION, /never sends source code, table rows or secret values/);
  assert.match(DESCRIPTION, /\$0\.003 per work unit/);   // it was $0.006
});

// prices have one home (shared.json); the tool descriptions are built from it and the README says the
// same, including that every result is charged.
test("prices in the descriptions and the README come from shared.json; every result is charged", async () => {
  const { readFileSync } = await import("node:fs");
  const { SHARED } = await import("../lib/shared.mjs");
  const { GUIDANCE_DESCRIPTION } = await import("../lib/inspector/tool.mjs");
  const { unitUsd } = SHARED.price;
  const readme = readFileSync(new URL("../README.md", import.meta.url), "utf8").replace(/\s+/g, " ");
  assert.ok(readme.includes(`$${unitUsd} per work unit, prepaid, with no per-check cap.`));
  for (const text of [DESCRIPTION, GUIDANCE_DESCRIPTION, readme]) {
    assert.ok(text.includes(`$${unitUsd} per work unit`));
    // no per-call minimum; a call costs exactly the units its work used.
    assert.doesNotMatch(text, /at least \d+ units/);
    assert.ok(text.includes("exactly the work units it used"), "states the exact charge");
    // No per-check estimate: the price is per work unit with no cap .
    assert.doesNotMatch(text, /usually costs|a whole check is usually|\$2 to \$6/i);
  }
  assert.ok(!("minUnits" in SHARED.price));
  // Guidance costs 1 unit per started 1,000 characters (it was 5); fix keeps 5.
  // The $10 sign-up credit.
  const { guidanceUnitsPer1000Chars, signupCreditUsd } = SHARED.price;
  for (const text of [GUIDANCE_DESCRIPTION, readme]) {
    assert.ok(text.includes(`${guidanceUnitsPer1000Chars} unit per started 1,000 characters`), "states the guidance rate");
  }
  assert.doesNotMatch(GUIDANCE_DESCRIPTION, /5 units per started/);
  assert.ok(readme.includes(`New accounts start with $${signupCreditUsd} of credit at the first sign-in`), "states the sign-up credit");
  const charged = "Every result is charged, including unknown results and practices with no rule for the project's stack.";
  assert.ok(DESCRIPTION.includes(charged));
  assert.ok(readme.includes(charged));
});

test("the token goes only to the evaluator that issued it", async () => {
  const root = repo();
  const { s, runCheck } = await setup(undefined, { evaluatorUrl: () => ({ url: "https://other.example.test", origin: "https://other.example.test" }) });
  try {
    const out = await runCheck({ goal: "check" }, { roots: [root] });
    assert.equal(out.error, "sign_in_other_host");
    assert.equal(s.calls.length, 0);
  } finally { await s.close(); }
});

test("The token's evaluator is read from the url when the answer gives no origin", async () => {
  const root = repo();
  for (const [where, error] of [
    [(s) => ({ url: s.url }), undefined],                                           // the same origin, read from the url
    [(s) => ({ url: `${s.url}/base` }), undefined],                                 // a path doesn't change it
    [() => ({ url: "https://other.example.test/base" }), "sign_in_other_host"],     // another origin
    // a given origin wins over the url's: the token check passes, then the call goes to the url
    [(s) => ({ url: "https://other.example.test", origin: new URL(s.url).origin }), "evaluator_unreachable"],
  ]) {
    let stubbed = null;
    const { s, runCheck } = await setup(undefined, { evaluatorUrl: () => where(stubbed) });
    stubbed = s;
    try {
      const out = await runCheck({ goal: "check" }, { roots: [root], log: () => {} });
      assert.equal(out.error, error);
      assert.equal(s.calls.length, error ? 0 : 1);
    } finally { await s.close(); }
  }
});

test("decisions: the person's, passed through on the project root's document only, decided_by fixed to person", async () => {
  const { default: AjvModule } = await import("ajv");
  const { INPUT_SCHEMA, PAGE_INPUT_SCHEMA } = await import("../lib/inspector/tool.mjs");
  const validate = new (AjvModule.default ?? AjvModule)({ strict: true }).compile(INPUT_SCHEMA);
  const validatePage = new (AjvModule.default ?? AjvModule)({ strict: true }).compile(PAGE_INPUT_SCHEMA); // TU1: pages are get_result_page's
  assert.equal(validate({ goal: "check", decisions: [{ object_id: "phi-columns@public.patients:dob", decision: "accepted", decided_by: "assistant" }] }), false);
  assert.equal(validate({ goal: "check", decisions: [{ object_id: "phi-columns@public.patients:dob", decision: "pass" }] }), false);
  // final review I1: the evaluator's object ids, practice@object (table, file path, handler id, project), and pages to 1000.
  for (const id of ["rls-enabled@public.care_messages", "edge-function-auth@supabase/functions/x/index.ts", "audit-log@project", "rls-forced"]) {
    assert.equal(validate({ goal: "fix", finding_ids: [id] }), true, id);
  }
  assert.equal(validate({ goal: "fix", finding_ids: ["Not An Id"] }), false);
  assert.equal(validatePage({ goal: "check", session: "ps_abcdefghijklmnopqrstuv", page: 1000 }), true);
  assert.equal(validatePage({ goal: "check", session: "ps_abcdefghijklmnopqrstuv", page: 1001 }), false);
  assert.equal(validate({ goal: "check", session: "ps_abcdefghijklmnopqrstuv", page: 2 }), false, "check_schema takes no page");
  const { decisionsProblem } = await import("../lib/inspector/tool.mjs");
  assert.match(decisionsProblem({ decisions: [{ object_id: "x", decision: "accepted", decided_by: "person" }] }), /decided_by/);
  assert.equal(decisionsProblem({ decisions: [{ object_id: "x", decision: "accepted" }] }), null);
  // In CI no person is at the machine: a decision carrying an option is refused, naming the variable (contract 2.3
  // section 1.1). Outside CI the input schema refuses option until a later release adds it.
  const opt = { decisions: [{ object_id: "x", option: "not_used" }] };
  for (const [env, name] of [[{ CI: "true" }, "CI"], [{ GITLAB_CI: "1" }, "GITLAB_CI"], [{ JENKINS_URL: "https://j" }, "JENKINS_URL"]]) {
    const said = decisionsProblem(opt, { env });
    assert.ok(said?.startsWith("no_person_in_ci") && said.includes(name), name);
  }
  assert.equal(decisionsProblem(opt, { env: { CI: "false", GITHUB_ACTIONS: "0" } }), null);
  assert.equal(decisionsProblem({ decisions: [{ object_id: "x", decision: "accepted" }] }, { env: { CI: "true" } }), null);
  const root = repo();
  const { s, runCheck } = await setup();
  try {
    await runCheck({ goal: "check", session: "ps_abcdefghijklmnopqrstuv", decisions: [{ object_id: "phi-columns@public.patients:dob", decision: "not_applicable" }] }, { roots: [root] });
    assert.deepEqual(s.calls[0].body.decisions, [{ object_id: "phi-columns@public.patients:dob", decision: "not_applicable", decided_by: "person" }]);
    const out = await runCheck({ goal: "explain", practice_id: "rls-forced", decisions: [{ object_id: "x", decision: "accepted" }] }, { roots: [root] });
    assert.equal(out.next_step, TOOL_ERRORS.decisions_need_evaluation);
    assert.equal(s.calls.length, 1);
  } finally { await s.close(); }
});

test("verdicts carry reason_code and searched: closed shapes, roots screened locally, sent as written", async () => {
  const { default: AjvModule } = await import("ajv");
  const { INPUT_SCHEMA, verdictsProblem } = await import("../lib/inspector/tool.mjs");
  const validate = new (AjvModule.default ?? AjvModule)({ strict: true }).compile(INPUT_SCHEMA);
  const v = { practice_id: "rls-forced", state: "not_applicable", reason_code: "not_used",
    searched: [{ pattern_id: "create_table", roots: ["db/migrations", "src"] }, { pattern_id: "orm_model", roots: [] }] };
  assert.equal(validate({ goal: "check", verdicts: [v] }), true);
  assert.equal(validate({ goal: "check", verdicts: [{ ...v, reason_code: "No-Tables" }] }), false);
  assert.equal(validate({ goal: "check", verdicts: [{ ...v, code: "not_used" }] }), false);
  assert.equal(validate({ goal: "check", verdicts: [{ ...v, searched: [{ pattern_id: "create_table" }] }] }), false);
  assert.equal(validate({ goal: "check", verdicts: [{ ...v, searched: [{ ...v.searched[0], extra: 1 }] }] }), false);
  assert.equal(validate({ goal: "check", verdicts: [{ ...v, searched: [{ pattern_id: "Bad id", roots: [] }] }] }), false);
  assert.equal(validate({ goal: "check", verdicts: [{ ...v, searched: [{ pattern_id: "p", roots: ["/etc"] }] }] }), false);
  assert.equal(validate({ goal: "check", verdicts: [{ ...v, searched: [{ pattern_id: "p", roots: ["a/../b"] }] }] }), false);
  const many = (n, f) => Array.from({ length: n }, (_, i) => f(i));
  assert.equal(validate({ goal: "check", verdicts: [{ ...v, searched: many(20, () => ({ pattern_id: "p", roots: many(20, (i) => `d${i}`) })) }] }), true);
  assert.equal(validate({ goal: "check", verdicts: [{ ...v, searched: many(21, () => ({ pattern_id: "p", roots: [] })) }] }), false);
  assert.equal(validate({ goal: "check", verdicts: [{ ...v, searched: [{ pattern_id: "p", roots: many(21, (i) => `d${i}`) }] }] }), false);
  assert.equal(verdictsProblem({ verdicts: [v] }), null);
  assert.match(verdictsProblem({ verdicts: [{ ...v, searched: [{ pattern_id: "p", roots: ["patients/jane.doe@example.com"] }] }] }),
    /verdicts\[0\]\.searched\[0\]\.roots\[0\] holds something shaped like a record value or a secret/);
  const root = repo();
  const { s, runCheck } = await setup();
  try {
    await runCheck({ goal: "check", session: "ps_abcdefghijklmnopqrstuv", verdicts: [v, { practice_id: "audit-log", state: "fail", reason_code: "control_missing" }] }, { roots: [root] });
    assert.deepEqual(s.calls[0].body.verdicts, [v, { practice_id: "audit-log", state: "fail", reason_code: "control_missing" }]);
  } finally { await s.close(); }
});

test("verdicts: the assistant's, sent with the session on check and verify only, the note screened locally", async () => {
  const { default: AjvModule } = await import("ajv");
  const { INPUT_SCHEMA, verdictsProblem } = await import("../lib/inspector/tool.mjs");
  const validate = new (AjvModule.default ?? AjvModule)({ strict: true }).compile(INPUT_SCHEMA);
  const v = { practice_id: "rls-forced", state: "not_applicable", reason_code: "not_used", note: "No table holds patient rows." };
  assert.equal(validate({ goal: "check", verdicts: [v] }), true);
  assert.equal(validate({ goal: "check", verdicts: [{ ...v, state: "unknown" }] }), false);
  assert.equal(validate({ goal: "check", verdicts: [{ ...v, note: "two\nlines" }] }), false);
  assert.equal(validate({ goal: "check", verdicts: [{ ...v, note: "x".repeat(301) }] }), false);
  assert.equal(validate({ goal: "check", verdicts: [{ ...v, location: "a.ts:1" }] }), false);
  assert.match(verdictsProblem({ verdicts: [{ ...v, note: "The admin is jane.doe@example.com" }] }), /record value or a secret/);
  assert.equal(verdictsProblem({ verdicts: [v] }), null);
  const root = repo();
  const { s, runCheck } = await setup(undefined, { learningFor: () => true }); // learning on, so the note leaves
  try {
    await runCheck({ goal: "check", session: "ps_abcdefghijklmnopqrstuv", verdicts: [v] }, { roots: [root] });
    assert.deepEqual(s.calls[0].body.verdicts, [v]);
    assert.equal((await runCheck({ goal: "fix", session: "ps_abcdefghijklmnopqrstuv", verdicts: [v] }, { roots: [root] })).next_step, TOOL_ERRORS.verdicts_need_check);
    assert.equal((await runCheck({ goal: "check", verdicts: [v] }, { roots: [root] })).next_step, TOOL_ERRORS.verdicts_need_session);
    assert.equal(s.calls.length, 1);
  } finally { await s.close(); }
});

test("plan entities holding a secret are hashed", async () => {
  const root = repo();
  const { s, runCheck } = await setup();
  try {
    await runCheck({ goal: "plan", entities: [{ name: "sk\x5flive_51Habcdefghijklmnopqrstuv0123456789", columns: [{ name: "A\x4bIAQWERTYUIOPASDFGH" }] }] }, { roots: [root] });
    const sent = JSON.stringify(s.calls[0].body);
    assert.ok(!sent.includes("sk\x5flive_51H") && !sent.includes("A\x4bIAQWERTYUIOPASDFGH"), sent);
  } finally { await s.close(); }
});

// the plan takes only what is sent: table and column names. app_description and the older, richer entity shape
// (schema, holds, column type and nullable, references) are refused by the schema; nothing is kept for old prompts.
test("plan entities: names only, strict objects; app_description and the older shape are refused", async () => {
  const { default: AjvModule } = await import("ajv");
  const { GUIDANCE_INPUT_SCHEMA } = await import("../lib/inspector/tool.mjs");
  const validate = new (AjvModule.default ?? AjvModule)({ strict: true }).compile(GUIDANCE_INPUT_SCHEMA);
  const items = GUIDANCE_INPUT_SCHEMA.properties.entities.items;
  assert.deepEqual(Object.keys(items.properties), ["name", "columns"]);
  assert.equal(items.additionalProperties, false);
  assert.deepEqual(Object.keys(items.properties.columns.items.properties), ["name"]);
  assert.equal(items.properties.columns.items.additionalProperties, false);
  assert.equal(Object.hasOwn(GUIDANCE_INPUT_SCHEMA.properties, "app_description"), false);
  const names = [{ name: "patients", columns: [{ name: "dob" }, { name: "clinic_id" }] }];
  assert.equal(validate({ goal: "plan", entities: names }), true);
  assert.equal(validate({ goal: "plan", entities: names, app_description: "A clinic app" }), false, "app_description is no argument");
  const older = [{ name: "patients", schema: "clinical", holds: "patients",
    columns: [{ name: "dob", type: "date", nullable: false }, { name: "clinic_id", type: "uuid", nullable: true }],
    references: [{ column: "clinic_id", to: "public.clinics.id", on_delete: "cascade" }] }];
  assert.equal(validate({ goal: "plan", entities: older }), false, "the older entity shape is refused");
  assert.equal(validate({ goal: "plan", entities: [{ name: "patients", schema: "clinical", columns: [{ name: "dob" }] }] }), false, "an extra entity field");
  assert.equal(validate({ goal: "plan", entities: [{ name: "patients", columns: [{ name: "dob", type: "date" }] }] }), false, "an extra column field");
  assert.equal(validate({ goal: "plan", entities: [{ name: "patients" }] }), false, "columns are required");
  assert.equal(validate({ goal: "plan", entities: [{ name: "patients", columns: [{ type: "date" }] }] }), false, "a column needs its name");
  const root = repo();
  const { s, runCheck } = await setup();
  try {
    await runCheck({ goal: "plan", entities: names }, { roots: [root] });
    assert.deepEqual(s.calls[0].body, { goal: "plan", entities: ["patients", "patients.dob", "patients.clinic_id"] });
    assert.equal((await runCheck({ goal: "plan" }, { roots: [root] })).next_step, TOOL_ERRORS.plan_needs_input);
    assert.equal(s.calls.length, 1, "a plan without entities sends nothing");
  } finally { await s.close(); }
});

test("refused roots the host shared are named in local_notes and never sent", async () => {
  const root = repo();
  const { s, runCheck } = await setup();
  try {
    const out = await runCheck({ goal: "check" }, { roots: [root], refused: [{ root: "/", code: "filesystem_root" }, { root: "/Users/me", code: "home_folder" }] });
    assert.equal(out.local_notes.length, 2);
    assert.match(out.local_notes[0], /also shared \/, which was not checked: it is a filesystem root/);
    assert.match(out.local_notes[1], /\/Users\/me, which was not checked: it is your home folder/);
    assert.ok(!JSON.stringify(s.calls.at(-1).body).includes("/Users/me"));
  } finally { await s.close(); }
});

test("several client roots: only the first is sent by default; the others are listed (merge review 4)", async () => {
  const a = repo(), b = repo(), c = repo();
  let { s, runCheck } = await setup();
  try {
    const out = await runCheck({ goal: "check", session: "ps_abcdefghijklmnopqrstuv" }, { roots: [a, b, c] });
    assert.equal(s.calls.length, 1);
    assert.deepEqual(out.results.map((r) => r.root), [0]);
    assert.equal(out.other_roots.count, 2);
    assert.equal(out.other_roots.not_checked_root_ids.length, 2);
  } finally { await s.close(); }
  ({ s, runCheck } = await setup());
  try {
    const out = await runCheck({ goal: "check", session: "ps_abcdefghijklmnopqrstuv", include_other_roots: true }, { roots: [a, b, c] });
    assert.equal(s.calls.length, 3);
    assert.deepEqual(out.results.map((r) => r.root), [0, 1, 2]);
    assert.equal(s.calls[1].body.session, undefined);
    for (const name of ["catalog", "platform"]) assert.equal(s.calls[2].body.fact_document.collection.find((x) => x.collector === name).status, "not_run");
  } finally { await s.close(); }
});

test("decisions with no session are refused locally (merge review 4)", async () => {
  const { s, runCheck } = await setup();
  try {
    const out = await runCheck({ goal: "check", decisions: [{ object_id: "rls-forced", decision: "accepted" }] }, { roots: [repo()] });
    assert.equal(out.error, "decisions_need_session");
    assert.equal(s.calls.length, 0);
  } finally { await s.close(); }
});

test("include_other_roots takes a list of root ids from an earlier listing; every project root is counted", async () => {
  const files = {};
  for (let i = 0; i < 3; i++) { files[`libs/repo${i}/.git/HEAD`] = "ref: refs/heads/main\n"; files[`libs/repo${i}/x.ts`] = "export const y = 2;\n"; }
  const a = repo(files);
  mkdirSync(join(a, ".git"), { recursive: true });
  writeFileSync(join(a, ".git", "HEAD"), "ref: refs/heads/main\n");
  const b = repo({ "inner/.git/HEAD": "ref: refs/heads/main\n", "inner/x.ts": "x\n" });
  const { s, runCheck } = await setup(); // one install key: root ids are per install
  try {
    let out = await runCheck({ goal: "check", session: "ps_abcdefghijklmnopqrstuv" }, { roots: [a, b] });
    const listing = out.other_roots;
    assert.equal(s.calls.length, 1);
    assert.equal(listing.count, 5, "3 nested in a, b itself and its nested one: walked, so counted exactly");
    const chosen = [listing.not_checked_root_ids[1], listing.not_checked_root_ids[4]];
    const unknown = "f".repeat(64);
    out = await runCheck({ goal: "check", session: "ps_abcdefghijklmnopqrstuv", include_other_roots: [...chosen, unknown] }, { roots: [a, b] });
    const calls = s.calls.slice(1);
    assert.equal(calls.length, 3, "the first root once, then exactly the two chosen");
    assert.deepEqual(calls.slice(1).map((c) => c.body.fact_document.root_id).sort(), [...chosen].sort());
    assert.equal(calls.filter((c) => c.body.fact_document.root_id === calls[0].body.fact_document.root_id).length, 1);
    assert.deepEqual(out.other_roots.unknown_root_ids, [unknown]);
    assert.equal(out.other_roots.checked, 2);
  } finally { await s.close(); }
});

/* The environment marked at setup (environment.mjs): sent when valid and the phisc entry still matches; else
 * unknown, with a local note saying why. Temp config folder and a temp service file only. */
test("sends the environment marked at setup, or unknown with a local note when the mark can't be used", async () => {
  const { writeEnvironment, serviceFingerprint, environmentFor } = await import("../lib/inspector/environment.mjs");
  const { chmodSync } = await import("node:fs");
  const root = repo();
  const home = temp("a7-env-home-");
  const service = join(home, "pg_service.conf");
  writeFileSync(service, "[phisc]\nhost=db.internal\ndbname=app\nuser=phisc_ro\n");
  const env = { PGSERVICEFILE: service };
  const { s, runCheck, configDir } = await setup(undefined, { environmentFor: (o) => environmentFor({ ...o, env, home }) });
  try {
    // missing: unknown, no note
    let out = await runCheck({ goal: "check" }, { roots: [root] });
    assert.deepEqual(s.calls.at(-1).body.fact_document.environment, { value: "unknown", source: "setup" });
    assert.equal(out.local_notes, undefined);
    assert.deepEqual(out, EVALUATE_OK);

    // valid and matching: production from setup
    writeEnvironment("production", { configDir, service: serviceFingerprint({ env, home }) });
    out = await runCheck({ goal: "check" }, { roots: [root] });
    assert.deepEqual(s.calls.at(-1).body.fact_document.environment, { value: "production", source: "setup" });
    assert.equal(out.local_notes, undefined);

    // the entry changed: unknown, and the assistant is told why
    writeFileSync(service, "[phisc]\nhost=db.internal\ndbname=other\nuser=phisc_ro\n");
    out = await runCheck({ goal: "check" }, { roots: [root] });
    assert.deepEqual(s.calls.at(-1).body.fact_document.environment, { value: "unknown", source: "setup" });
    assert.match(out.local_notes[0], /changed since it was marked production at setup/);
    assert.equal(out.headline, EVALUATE_OK.headline);

    // refused (other users can read it): unknown, with the reason
    writeEnvironment("production", { configDir, service: serviceFingerprint({ env, home }) });
    chmodSync(join(configDir, "environment.json"), 0o644);
    out = await runCheck({ goal: "check" }, { roots: [root] });
    assert.deepEqual(s.calls.at(-1).body.fact_document.environment, { value: "unknown", source: "setup" });
    assert.match(out.local_notes[0], /can't be used \(the environment file is readable or writable by other users/);
  } finally { await s.close(); }
});

test("with the shipped bundle (rules) check_schema sends the manifest's ruleset_id, never inspector_incomplete", async () => {
  const { loadRuleset } = await import("../lib/inspector/factdoc.mjs");
  const { readFileSync } = await import("node:fs");
  const manifest = JSON.parse(readFileSync(new URL("../rules/manifest.json", import.meta.url), "utf8"));
  assert.equal(loadRuleset().id, manifest.ruleset_id);
  const root = repo();
  const { s, runCheck } = await setup(undefined, { buildOptions: { ...quiet, ruleset: undefined } });
  try {
    const out = await runCheck({ goal: "check" }, { roots: [root] });
    assert.notEqual(out.error, "inspector_incomplete");
    assert.equal(s.calls.length, 1);
    assert.equal(s.calls[0].body.fact_document.ruleset_id, manifest.ruleset_id);
    assert.equal(validateFactDocument(s.calls[0].body.fact_document), null);
  } finally { await s.close(); }
});

test("location answers carry the E3 kind the question issued when the construct is there, else other", async () => {
  const root = repo({ "app/api/x/route.ts": "export async function POST(req) {\n  return Response.json({});\n}\n",
    "supabase/migrations/20240101_init.sql": "create table patients (id uuid);\n" });
  // expects is one kind or a list of kinds (the evaluator's _expects): every kind in a list is read, not only the first.
  const q = (object_id, expects) => ({ question_id: "location", object_id, practice_id: "a-b", ask: "Where is it?", answers: ["here", "not_found", "not_present"], expects });
  const first = { ...EVALUATE_OK, session: "ps_abcdefghijklmnopqrstuv", questions: [q("a-b@one", "function"), q("a-b@two", ["migration", "route_handler"]),
    q("a-b@three", ["class", "route_handler"]), q("a-b@four", ["class", "sql_statement", "migration"])] };
  const { s, runCheck } = await setup((call, n) => ({ status: 200, json: n === 1 ? first : EVALUATE_OK }));
  try {
    await runCheck({ goal: "check" }, { roots: [root] });
    await runCheck({ goal: "check", session: "ps_abcdefghijklmnopqrstuv", answers: [
      { object_id: "a-b@one", question_id: "location", answer: "here", location: "src/db.ts:1" },
      { object_id: "a-b@two", question_id: "location", answer: "here", location: "app/api/x/route.ts:1-3" },
      { object_id: "a-b@three", question_id: "location", answer: "here", location: "src/db.ts:1" }, // not a class there
      { object_id: "a-b@four", question_id: "location", answer: "here", location: "supabase/migrations/20240101_init.sql:1" },
      { object_id: "a-b@never", question_id: "location", answer: "here", location: "src/db.ts:1" }, // never issued
    ] }, { roots: [root] });
    const answers = s.calls[1].body.fact_document.answers;
    assert.deepEqual(answers.map((a) => a.location_kind), ["function", "route_handler", "other", "sql_statement", "other"]);
    assert.equal(validateFactDocument(s.calls[1].body.fact_document), null);
  } finally { await s.close(); }
});

test("a location answer on an object listed in a brief carries the brief's E3 kind", async () => {
  const root = repo({ "app/api/x/route.ts": "export async function POST(req) {\n  return Response.json({});\n}\n" });
  const brief = { practice_id: "audit-patient-recorded", question_id: "location", ask: "Find where each handler records patient access.",
    answers: ["here", "not_found", "not_present"], expects: "route_handler", object_ids: ["audit-patient-recorded@h1", "audit-patient-recorded@h2"] };
  const first = { ...EVALUATE_OK, session: "ps_abcdefghijklmnopqrstuv", questions: [], briefs: [brief] };
  const { s, runCheck } = await setup((call, n) => ({ status: 200, json: n === 1 ? first : EVALUATE_OK }));
  try {
    await runCheck({ goal: "check" }, { roots: [root] });
    await runCheck({ goal: "check", session: "ps_abcdefghijklmnopqrstuv", answers: [
      { object_id: "audit-patient-recorded@h1", question_id: "location", answer: "here", location: "app/api/x/route.ts:1-3" },
      { object_id: "audit-patient-recorded@h2", question_id: "location", answer: "not_present" },
      { object_id: "audit-patient-recorded@h3", question_id: "location", answer: "here", location: "app/api/x/route.ts:1-3" }, // not in the brief
    ] }, { roots: [root] });
    const answers = s.calls[1].body.fact_document.answers;
    assert.deepEqual(answers.map((a) => a.location_kind), ["route_handler", null, "other"]);
    assert.equal(validateFactDocument(s.calls[1].body.fact_document), null);
  } finally { await s.close(); }
});

test("Issued questions are kept for the last 100 sessions; the oldest is dropped first", async () => {
  const root = repo();
  const session = (i) => `ps_${"x".repeat(19)}${String(i).padStart(3, "0")}`;
  const q = { question_id: "location", object_id: "a-b@one", practice_id: "a-b", ask: "Where is it?", answers: ["here", "not_found", "not_present"], expects: ["call", "function"] };
  // Each page answer issues the same question in its own session: 101 sessions in all.
  const { s, runCheck, builds } = await setup((call) => ({ status: 200,
    json: call.body.page ? { ...EVALUATE_OK, session: call.body.session, questions: [q] } : EVALUATE_OK }));
  try {
    for (let i = 0; i <= 100; i++) await runCheck({ goal: "check", session: session(i), page: 2 }, { roots: [root] });
    const answer = { object_id: "a-b@one", question_id: "location", answer: "here", location: "src/db.ts:1" };
    for (const i of [0, 1, 100]) await runCheck({ goal: "check", session: session(i), answers: [answer] }, { roots: [root] });
    assert.deepEqual(builds.map((b) => b.answers[0].expects), [undefined, ["call", "function"], ["call", "function"]]);
    assert.equal(s.calls.length, 104);
  } finally { await s.close(); }
});

test("include_nested (an unreleased alias) is gone; include_other_roots checks the other roots; goal doubts is refused", async () => {
  const { default: AjvModule } = await import("ajv");
  const { INPUT_SCHEMA } = await import("../lib/inspector/tool.mjs");
  const validate = new (AjvModule.default ?? AjvModule)({ strict: true }).compile(INPUT_SCHEMA);
  assert.equal(Object.hasOwn(INPUT_SCHEMA.properties, "include_nested"), false);
  assert.equal(validate({ goal: "check", include_nested: true }), false);
  assert.equal(validate({ goal: "check", include_other_roots: true }), true);
  assert.equal(validate({ goal: "doubts" }), false, "doubts is no goal: the product is in development, nothing to keep");
  assert.doesNotMatch(INPUT_SCHEMA.properties.goal.description, /doubts/);
  const files = { "libs/r0/.git/HEAD": "ref: refs/heads/main\n", "libs/r0/x.ts": "x\n" };
  const root = repo(files);
  mkdirSync(join(root, ".git"), { recursive: true });
  writeFileSync(join(root, ".git", "HEAD"), "ref: refs/heads/main\n");
  const { s, runCheck } = await setup();
  try {
    const out = await runCheck({ goal: "check", include_other_roots: true }, { roots: [root] });
    assert.equal(s.calls.length, 2);
    assert.equal(out.other_roots.checked, 1);
  } finally { await s.close(); }
});

test("roots that won't be sent are not walked: a cheap scan lists them; the first root's own id is never unknown", async () => {
  const { walkAll } = await import("../lib/inspector/files.mjs");
  const mk = () => {
    const files = {};
    for (let i = 0; i < 2; i++) { files[`pkgs/r${i}/.git/HEAD`] = "ref: refs/heads/main\n"; files[`pkgs/r${i}/x.ts`] = "x\n"; }
    const r = repo(files);
    mkdirSync(join(r, ".git"), { recursive: true });
    writeFileSync(join(r, ".git", "HEAD"), "ref: refs/heads/main\n");
    return r;
  };
  const roots = [mk(), mk(), mk()];
  const walkedTops = [];
  let nestedWalked = 0;
  const spy = (abs, opts) => { walkedTops.push(abs); const inner = opts.walkNested; return walkAll(abs, { ...opts, walkNested: inner && ((a, r) => { const ok = inner(a, r); if (ok) nestedWalked++; return ok; }) }); };
  const { s, runCheck } = await setup(undefined, { buildOptions: { ...quiet, walkAll: spy } });
  try {
    let out = await runCheck({ goal: "check", session: "ps_abcdefghijklmnopqrstuv" }, { roots });
    assert.equal(s.calls.length, 1);
    assert.deepEqual(walkedTops, [roots[0]], "only the first project root is walked");
    assert.equal(nestedWalked, 0);
    assert.equal(out.other_roots.count, 8, "2 nested in the first, 2 other project roots and their 4 nested repositories");
    const firstId = s.calls[0].body.fact_document.root_id;
    const pick = out.other_roots.not_checked_root_ids[5];
    walkedTops.length = 0;
    out = await runCheck({ goal: "check", session: "ps_abcdefghijklmnopqrstuv", include_other_roots: [firstId, pick] }, { roots });
    assert.equal(s.calls.length, 3, "the first root once, then the one chosen");
    assert.equal(s.calls[2].body.fact_document.root_id, pick);
    assert.deepEqual(out.other_roots.unknown_root_ids, []);
  } finally { await s.close(); }
});

test("the environment marked at setup goes in the document; a mark it can't use comes back as a local note", async () => {
  const root = repo();
  const { s, runCheck } = await setup(undefined, { environmentFor: () => ({ environment: { value: "unknown", source: "setup" }, note: "The environment mark couldn't be used." }) });
  try {
    const out = await runCheck({ goal: "check" }, { roots: [root] });
    assert.deepEqual(s.calls[0].body.fact_document.environment, { value: "unknown", source: "setup" });
    assert.deepEqual(out.local_notes, ["The environment mark couldn't be used."]);
  } finally { await s.close(); }
});

test("a bucket list row-level security may have filtered comes back as a local note", async () => {
  const { STORAGE_FILTERED_NOTE } = await import("../lib/inspector/factdoc.mjs");
  const root = repo();
  const { judgePreflight } = await import("../lib/inspector/catalog.mjs");
  const preflight = judgePreflight({ role: "phisc_ro", session_role: "phisc_ro", database: "postgres", system_identifier: "7", settings_mismatched: [],
    superuser: false, bypassrls: false, replication: false, createrole: false, readable_tables: 0, writable_tables: 0,
    extension_relations_readable: [], catalog_tables: [], predefined_roles: [], dangerous_functions: [], catalog_extensions: [], owned_objects: 0,
    definer_functions_executable: 0, readable_large_objects: 0, lo_compat_privileges: false, write_relations: 0, write_large_objects: 0,
    write_schemas: 0, write_database: 0, write_default_privileges: 0, write_createdb: 0, write_foreign_servers: 0, write_fdw: 0,
    user_casts: 0, user_casts_implicit: 0, user_operators: 0 });
  const bucket = { bucket: "scans", public: true, open_read_policies: [], owner_scoped_read: false, open_for_all: [], unconfirmed_read_policies: [],
    owner_by_app_setting: false, objects_rls_on: true, file_size_limit: null, allowed_mime_types_set: false };
  const { s, runCheck } = await setup(undefined, { buildOptions: { ...quiet, collectCatalog: async () => ({ status: "truncated", count: 1, reason: null, preflight,
    queries: [{ query_id: "storage_buckets", status: "truncated", reason: "row_security_filtered", rows: [bucket] }] }) } });
  try {
    const out = await runCheck({ goal: "check" }, { roots: [root] });
    assert.deepEqual(out.local_notes, [STORAGE_FILTERED_NOTE]);
    const q = s.calls[0].body.fact_document.catalog.queries.find((x) => x.query_id === "storage_buckets");
    assert.deepEqual([q.status, q.reason], ["truncated", "not_permitted"]);
    assert.ok(!JSON.stringify(s.calls[0].body).includes(STORAGE_FILTERED_NOTE));
  } finally { await s.close(); }
});

// --- Fact schema 2.2: code, span lists, expects lists ------------
test("the tool takes code and a span list at on a here answer only, each span in path:line form", async () => {
  const { default: AjvModule } = await import("ajv");
  const { INPUT_SCHEMA } = await import("../lib/inspector/tool.mjs");
  const validate = new (AjvModule.default ?? AjvModule)({ strict: true }).compile(INPUT_SCHEMA);
  const here = (o) => ({ goal: "check", session: "ps_abcdefghijklmnopqrstuv",
    answers: [{ object_id: "a-b@one", question_id: "location", answer: "here", location: "src/a.ts:1", ...o }] });
  assert.equal(validate(here({ code: "tool_scoped_at", at: ["src/a.ts:2-3", "src/b.ts:4"] })), true);
  assert.equal(validate(here({ code: "tool_scoped_at" })), true);
  assert.equal(validate(here({ at: Array.from({ length: 50 }, (_, i) => `src/a.ts:${i + 1}`) })), true);
  assert.equal(validate(here({ at: Array.from({ length: 51 }, (_, i) => `src/a.ts:${i + 1}`) })), false);
  assert.equal(validate(here({ at: [] })), false);
  assert.equal(validate(here({ at: ["src/a.ts"] })), false, "a span needs a line");
  assert.equal(validate(here({ code: "Not_A_Code" })), false);
  assert.equal(validate({ goal: "check", session: "ps_abcdefghijklmnopqrstuv", answers: [
    { object_id: "a-b@one", question_id: "location", answer: "not_found", location: null, code: "x_at" }] }), false);
  assert.equal(validate({ goal: "check", session: "ps_abcdefghijklmnopqrstuv", answers: [
    { object_id: "a-b@one", question_id: "location", answer: "not_found", location: null, at: ["src/a.ts:1"] }] }), false);
  const { locationProblem } = await import("../lib/inspector/tool.mjs");
  assert.match(locationProblem(here({ at: ["src/a.ts:2", "src/a.ts:9-3"] })), /answers\[0\]\.at\[1\]/);
  // 1-30 is 30 lines and is accepted, so the message says "at most 30".
  assert.match(locationProblem(here({ at: ["src/a.ts:1-40"] })), /span at most 30 lines/);
  assert.equal(locationProblem(here({ at: ["src/a.ts:1-30"] })), null);
  assert.match(locationProblem(here({ at: ["src/a.ts:1-31"] })), /span at most 30 lines/);
  // The tool's limits are the fact schema's.
  const { FACT_SCHEMA } = await import("../lib/inspector/schema.mjs");
  const { ANSWER_CODE, SPANS_MAX } = await import("../lib/inspector/contracts.mjs");
  const facts = FACT_SCHEMA.properties.answers.items.properties;
  assert.equal(facts.code.pattern, ANSWER_CODE);
  assert.equal(facts.at.anyOf[1].maxItems, SPANS_MAX);
});

test("every span is confirmed and hashed like location; one span that can't be confirmed sends none of them", async () => {
  const root = repo({ "odd dir/a.ts": "line1\nline2\nline3\n", "src/b.ts": "one\ntwo\nthree\n" });
  const { s, runCheck, configDir } = await setup();
  try {
    await runCheck({ goal: "check", session: "ps_abcdefghijklmnopqrstuv", answers: [
      { object_id: "a-b@one", question_id: "location", answer: "here", location: "odd dir/a.ts:1", code: "tool_scoped_at",
        at: ["odd dir/a.ts:2-3", "src/b.ts:2", "odd dir/a.ts:2-3"] },
      { object_id: "a-b@two", question_id: "location", answer: "here", location: "src/b.ts:1", code: "x_at", at: ["src/missing.ts:1"] },
      { object_id: "a-b@three", question_id: "location", answer: "here", location: "src/b.ts:1", at: ["src/b.ts:9"] },
      { object_id: "a-b@four", question_id: "location", answer: "here", location: "src/missing.ts:1", code: "x_at", at: ["src/b.ts:1"] },
    ] }, { roots: [root] });
    const doc = s.calls[0].body.fact_document;
    const { readFileSync } = await import("node:fs");
    const key = readFileSync(join(configDir, "install.key"));
    const odd = hashed(key, "odd dir");
    assert.deepEqual(doc.answers, [
      { object_id: "a-b@one", question_id: "location", answer: "here", location: `${odd}/a.ts:1`, location_kind: "other",
        code: "tool_scoped_at", at: [`${odd}/a.ts:2-3`, "src/b.ts:2"] },
      { object_id: "a-b@two", question_id: "location", answer: "here", location: null, location_kind: "not_found" },
      { object_id: "a-b@three", question_id: "location", answer: "here", location: null, location_kind: "not_found" },
      { object_id: "a-b@four", question_id: "location", answer: "here", location: null, location_kind: "not_found" },
    ]);
    assert.equal(validateFactDocument(doc), null);
  } finally { await s.close(); }
});

test("a question's expects list is kept, and a location answer gets the first listed kind seen there", async () => {
  const root = repo({ "app/api/x/route.ts": "export async function POST(req) {\n  return Response.json({});\n}\n" });
  const q = (object_id, expects) => ({ question_id: "location", object_id, practice_id: "a-b", ask: "Where is it?", answers: ["here", "not_found", "not_present"], expects });
  const first = { ...EVALUATE_OK, session: "ps_abcdefghijklmnopqrstuv",
    questions: [q("a-b@one", ["class", "route_handler", "function"]), q("a-b@two", ["class", "migration"])] };
  const { s, runCheck } = await setup((call, n) => ({ status: 200, json: n === 1 ? first : EVALUATE_OK }));
  try {
    await runCheck({ goal: "check" }, { roots: [root] });
    await runCheck({ goal: "check", session: "ps_abcdefghijklmnopqrstuv", answers: [
      { object_id: "a-b@one", question_id: "location", answer: "here", location: "app/api/x/route.ts:1-3" },
      { object_id: "a-b@two", question_id: "location", answer: "here", location: "app/api/x/route.ts:1-3" },
    ] }, { roots: [root] });
    const answers = s.calls[1].body.fact_document.answers;
    assert.deepEqual(answers.map((a) => a.location_kind), ["route_handler", "other"]);
    assert.equal(validateFactDocument(s.calls[1].body.fact_document), null);
  } finally { await s.close(); }
});

test("a decision may name one of the item's options instead of a decision; the body sends it as the person's", async () => {
  const { default: AjvModule } = await import("ajv");
  const { INPUT_SCHEMA } = await import("../lib/inspector/tool.mjs");
  const validate = new (AjvModule.default ?? AjvModule)({ strict: true }).compile(INPUT_SCHEMA);
  const one = (d) => validate({ goal: "check", session: "ps_abcdefghijklmnopqrstuv", decisions: [{ object_id: "a-b@one", ...d }] });
  assert.equal(one({ option: "not_used" }), true);
  assert.equal(one({ decision: "accepted" }), true);
  assert.equal(one({ decision: "accepted", option: "not_used" }), true);
  assert.equal(one({}), false, "a decision or an option");
  assert.equal(one({ option: "Not Used" }), false);
  assert.equal(one({ option: "x".repeat(65) }), false);
  const { OPTION } = await import("../lib/inspector/contracts.mjs");
  assert.equal(OPTION, "^[a-z][a-z0-9_]{0,63}$");   // enums.OPTION_PATTERN in the core
  const root = repo();
  const { s, runCheck } = await setup();
  try {
    await runCheck({ goal: "check", session: "ps_abcdefghijklmnopqrstuv", decisions: [
      { object_id: "a-b@one", option: "not_used" }, { object_id: "a-b@two", decision: "declined" }] }, { roots: [root] });
    assert.deepEqual(s.calls[0].body.decisions, [{ object_id: "a-b@one", option: "not_used", decided_by: "person" },
      { object_id: "a-b@two", decision: "declined", decided_by: "person" }]);
  } finally { await s.close(); }
});

test("a span equal to location is dropped from at, a code with no at keeps no at, and both decision and option are sent", async () => {
  const root = repo({ "src/b.ts": "one\ntwo\nthree\n" });
  const { s, runCheck } = await setup();
  try {
    await runCheck({ goal: "check", session: "ps_abcdefghijklmnopqrstuv", answers: [
      { object_id: "a-b@one", question_id: "location", answer: "here", location: "src/b.ts:1", code: "x_at", at: ["src/b.ts:1", "src/b.ts:1"] },
      { object_id: "a-b@two", question_id: "location", answer: "here", location: "src/b.ts:2", code: "x_at" },
      { object_id: "a-b@three", question_id: "location", answer: "here", location: "src/b.ts:1", at: ["src/b.ts:1", "src/b.ts:3", "src/b.ts:3"] },
    ] }, { roots: [root] });
    const doc = s.calls[0].body.fact_document;
    assert.deepEqual(doc.answers.map(({ object_id, location, code, at }) => ({ object_id, location, code, at })), [
      { object_id: "a-b@one", location: "src/b.ts:1", code: "x_at", at: undefined },
      { object_id: "a-b@two", location: "src/b.ts:2", code: "x_at", at: undefined },
      { object_id: "a-b@three", location: "src/b.ts:1", code: undefined, at: ["src/b.ts:3"] },
    ]);
    assert.equal(validateFactDocument(doc), null);
    await runCheck({ goal: "check", session: "ps_abcdefghijklmnopqrstuv",
      decisions: [{ object_id: "a-b@one", decision: "accepted", option: "not_used" }] }, { roots: [root] });
    assert.deepEqual(s.calls[1].body.decisions, [{ object_id: "a-b@one", decision: "accepted", option: "not_used", decided_by: "person" }]);
  } finally { await s.close(); }
});

test("the texts name codes, spans, options and guidance, and how to word free text", async () => {
  assert.match(INSTRUCTIONS, /guidance/);
  assert.match(INSTRUCTIONS, /answer_with/);
  // a note is worded in terms of code and configuration, names in backticks, and never holds data.
  assert.match(INSTRUCTIONS.replace(/\s+/g, " "), /reason_code is one of those codes/);
  assert.match(INSTRUCTIONS.replace(/\s+/g, " "), /in terms of code and configuration, with table, column, setting and file names in backticks/);
  assert.match(INSTRUCTIONS.replace(/\s+/g, " "), /never record values, example rows, people's names, dates, ids or quotes from data or logs/);
  const { decisionsProblem } = await import("../lib/inspector/tool.mjs");
  const said = decisionsProblem({ decisions: [{ object_id: "a-b@x", option: "keep", decided_by: "person" }] }, { env: {} });
  assert.match(said, /\{object_id, decision\} or \{object_id, option\}/);
});

// a database past the evaluator's table limit is the database's size, never "update the inspector".
test("a document with too many catalog tables is never sent, and says why", async () => {
  const root = repo();
  const { s, runCheck } = await setup(undefined, {
    build: async () => ({ documents: [{ project: 0, label: "", nested: false, document: { schema_version: 2 }, problem: { at: "/catalog/queries/0/rows", keyword: "too_many_tables" } }] }),
  });
  try {
    const out = await runCheck({ goal: "check" }, { roots: [root], log: () => {} });
    assert.equal(out.error, "database_too_large");
    assert.equal(out.next_step, TOOL_ERRORS.database_too_large);
    assert.ok(!/setup|update/i.test(out.next_step) && /2,500 tables/.test(out.next_step));
    assert.equal(s.calls.length, 0);
  } finally { await s.close(); }
});

// T28-P1-C4: on fullhp the agent read "run the check through to the end" as "the check is the audit" and missed
// issues outside it. Both texts say what the check covers, what it doesn't, and that the agent's own review goes on.
test("the instructions and the description say what the check covers, what it doesn't, and that the agent's review goes on", () => {
  const flat = (text) => text.replace(/\s+/g, " ");
  // T29-P1-C7 (brief rank 8): both load on every turn, so the full scope is in the description and the instructions
  // point to it, naming what is out
  for (const text of [flat(DESCRIPTION)]) {
    assert.match(text, /covers the data side: the schema, database settings, row-level security and roles, sign-in and session settings, and the code paths that read, write, log or send patient data, plus secrets in the code or the client bundle, dependency scanning and MFA on platform accounts/);
    assert.match(text, /doesn't cover app-wide security beyond that \(such as HTTP headers other than HSTS\), business logic, app features such as a patient's record export or an accounting of disclosures, or how an AI feature answers people/);
  }
  // T28-P3-C16: four shipped practices are app-wide; the text names them so the agent doesn't read them as outside
  assert.match(flat(INSTRUCTIONS), /Your own review of the rest of the app goes on alongside the check: the check never stands in for it\./);
  assert.match(flat(DESCRIPTION), /It never stands in for the assistant's own review of the rest of the app\./);
  // near the top, so a client that shortens long server instructions still shows it
  assert.ok(INSTRUCTIONS.indexOf("Scope:") > 0 && INSTRUCTIONS.indexOf("Scope:") < 400, "the scope statement opens the instructions");
  assert.match(flat(INSTRUCTIONS), /Scope: as check_schema's description says\./);
  // the agent's findings from outside the check are shown beside the check's list, as its own
  assert.match(flat(INSTRUCTIONS), /findings from your own review go beside the check's, marked as yours\./);
});

// T27 D10's "Make fixes only after the person asks for them." is gone: the owner's yes in T29-P1-C7 (brief rank 2) puts
// consent with the person and the harness, and test/t29-interface-text.test.mjs checks no line gates on the person.

test("T29-P1-C6: get_result_page sends a target (practice, table or file) as a fetch, and collects nothing", async () => {
  const root = repo();
  const { s, runCheck, builds } = await setup();
  try {
    const n = builds.length;
    for (const target of [{ practice_id: "rls-forced" }, { table: "public.care_messages" }, { file: "app/api/notes/route.ts" }]) {
      await runCheck({ goal: "check", session: "ps_abcdefghijklmnopqrstuv", target }, { roots: [root] });
      assert.deepEqual(s.calls.at(-1).body, { goal: "check", session: "ps_abcdefghijklmnopqrstuv", target });
    }
    assert.equal(builds.length, n, "a target fetch builds no fact document");
    assert.equal((await runCheck({ goal: "check", target: { table: "public.t" } }, { roots: [root] })).next_step,
      TOOL_ERRORS.needs_session);
  } finally {
    await s.close();
  }
});

/* T29 (o) o2, red first: get_result replaces get_result_page (core o1b: the response is one body with its index, and
 * get_result is the only fetch). The tool count stays 3; no tool takes page, resend or target. */
test("T29 o2: get_result replaces get_result_page, and no tool takes page, resend or target", async () => {
  const { TOOLS } = await import("../lib/inspector/tool.mjs");
  assert.deepEqual(TOOLS.map((t) => t.name), ["check_schema", "schema_guidance", "get_result"]);
  for (const t of TOOLS) {
    for (const k of ["page", "resend", "target"]) assert.ok(!Object.hasOwn(t.inputSchema.properties, k), `${t.name} takes ${k}`);
  }
  const input = TOOLS[2].inputSchema;
  assert.deepEqual([...input.required].sort(), ["select", "session"]);
  const select = input.properties.select;
  assert.deepEqual(Object.keys(select.properties).sort(),
    ["advice", "file", "finding", "list", "practice", "severity", "state", "table"]);
  assert.equal(select.minProperties, 1);
  assert.equal(select.maxProperties, 1);
  assert.deepEqual(input.properties.part.enum, ["detail", "guidance", "fix", "proof", "reference"]);
});

test("T29 o2: get_result sends goal, session, select and part as a fetch, and collects nothing", async () => {
  const root = repo();
  const { s, runCheck, builds } = await setup();
  try {
    const n = builds.length;
    const session = "ps_abcdefghijklmnopqrstuv";
    await runCheck({ goal: "check", session, select: { practice: "rls-forced" }, part: "guidance" }, { roots: [root] });
    assert.deepEqual(s.calls.at(-1).body, { goal: "check", session, select: { practice: "rls-forced" }, part: "guidance" });
    await runCheck({ goal: "fix", session, select: { list: "fixes.own" } }, { roots: [root] });
    assert.deepEqual(s.calls.at(-1).body, { goal: "fix", session, select: { list: "fixes.own" } });
    assert.equal(builds.length, n, "a get_result fetch builds no fact document");
    assert.equal((await runCheck({ goal: "check", select: { state: "fail" } }, { roots: [root] })).next_step,
      TOOL_ERRORS.needs_session);
  } finally {
    await s.close();
  }
});

test("T29 o2: result_missing replaces page_missing, and no shipped text names pages", async () => {
  const { ERROR_STATUS } = await import("../lib/inspector/client.mjs");
  assert.equal(ERROR_STATUS.result_missing, 404);
  assert.ok(!Object.hasOwn(ERROR_STATUS, "page_missing"));
  const { readdirSync, readFileSync } = await import("node:fs");
  const lib = fileURLToPath(new URL("../lib/", import.meta.url));
  const files = readdirSync(lib, { recursive: true }).filter((f) => /\.(mjs|json)$/.test(f) && !f.startsWith(`inspector${"/"}contracts`));
  const PAGING = /get_result_page|page_missing|later page|page 1\b|page\.next|page\.of|\bresend\b/i;
  const hits = files.filter((f) => PAGING.test(readFileSync(join(lib, f), "utf8")));
  hits.push(...["../README.md"].filter((f) => PAGING.test(readFileSync(fileURLToPath(new URL(f, import.meta.url)), "utf8"))));
  assert.deepEqual(hits, []);
});

/* Screening design §4, §8, §13 items 8 and 18: before anything is sent, check_schema screens each verdict and
 * concern note with screen.mjs, on the snapshot ids of the first root's fact document and the session's previous
 * accepted note. A refused call sends nothing and names each refused note and its rules, never the note itself. A
 * session has two refused calls; on the third, each note still refused is withheld (note_withheld: true) and kept only
 * in .custosa/local/withheld.jsonl, and the call goes on. Rules here are S3's made-up parity rule file, since the
 * shipped one waits on the evaluator's rule file. Stub evaluator and temp folders only. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { makeRunCheck, NOTE_REFUSED } from "../lib/inspector/tool.mjs";
import { writeToken } from "../lib/inspector/auth.mjs";
import { loadRules } from "../lib/inspector/rules.mjs";
import { rulesFromDoc } from "../lib/screen.mjs";
import { snapshotIds } from "../lib/inspector/snapshot.mjs";
import { readWithheld } from "../lib/inspector/withheld.mjs";
import { EVALUATE_OK, stub } from "./stub-evaluator.mjs";

const FIXTURE = JSON.parse(readFileSync(new URL("./fixtures/screen-parity.5e907cf8.json", import.meta.url), "utf8"));
const NOTE_RULES = rulesFromDoc(FIXTURE.doc, FIXTURE.sets);
const RULESET = { id: "2026-10-20.0123abcd", rules: loadRules(fileURLToPath(new URL("./fixtures/rules/", import.meta.url))), queries: [] };
const TOKEN = `phisc_${"t".repeat(43)}`;
const SESSION = EVALUATE_OK.session;
const temp = (prefix) => realpathSync(mkdtempSync(join(tmpdir(), prefix)));
const quiet = {
  ruleset: RULESET,
  collectCatalog: async () => ({ status: "not_run", count: 0, reason: "service_missing", preflight: null, queries: [] }),
  collectPlatform: async () => ({ provider: null, status: "not_run", reason: "no_token", settings: {} }),
};
function repo() {
  const root = temp("notes-");
  mkdirSync(join(root, "src"), { recursive: true });
  writeFileSync(join(root, "src/db.ts"), 'export async function save(p) { await db.from("patients").insert(p); }\n');
  return root;
}
async function setup({ noteRules = NOTE_RULES, now, respond = () => ({ status: 200, json: EVALUATE_OK }) } = {}) {
  const configDir = join(temp("notes-cfg-"), "custosa");
  const s = await stub(respond);
  writeToken(TOKEN, { configDir, host: new URL(s.url).origin });
  const builds = [];
  // learning on, so notes leave and are screened (the gate has its own tests, learning-gate)
  const runCheck = makeRunCheck({ configDir, localOnly: false, buildOptions: quiet, noteRules, learningFor: () => true, ...(now ? { now } : {}),
    evaluatorUrl: () => ({ url: s.url, origin: new URL(s.url).origin }), clientOptions: { sleep: async () => {} },
    build: async (roots, opts) => { builds.push(opts); return (await import("../lib/inspector/factdoc.mjs")).buildFactDocuments(roots, opts); } });
  return { s, runCheck, builds };
}

const NAMED = "The notes for Jane Smith are logged.";
const MRN = "Patient MRN 4471-882-19 is logged.";
const CLEAN = "The insert has no owner check.";
const verdict = (note) => ({ practice_id: "authz-every-handler", state: "fail", reason_code: "control_missing", ...(note ? { note } : {}) });
const concern = (note) => ({ category: "logging", area: "logging", file_kind: "server_module", proposed_severity: "high", note });

test("the first root's document has the snapshot ids a note may name in backticks", async () => {
  const root = repo();
  const { s, runCheck } = await setup();
  try {
    await runCheck({ goal: "check" }, { roots: [root] });
    assert.ok(snapshotIds(s.calls[0].body.fact_document).has("src/db.ts"));
  } finally { await s.close(); }
});

test("a refused note sends nothing, and the refusal names each refused note and its rules, never the note", async () => {
  const root = repo();
  const { s, runCheck } = await setup();
  try {
    const out = await runCheck({ goal: "check", session: SESSION, verdicts: [verdict(CLEAN), verdict(NAMED)], concerns: [concern(MRN)] }, { roots: [root] });
    assert.equal(s.calls.length, 0);
    assert.equal(out.error, "note_refused");
    assert.match(out.next_step, /verdicts\[1\]\.note \(context_name, name_alone, name_pair, placeholder_value\)/);
    assert.match(out.next_step, /concerns\[0\]\.note \(hotword_digits, digit_run\)/);
    assert.ok(!out.next_step.includes("verdicts[0]"));
    assert.ok(!out.next_step.includes("Jane") && !out.next_step.includes("4471"));
    assert.ok(out.next_step.startsWith(NOTE_REFUSED.split("{")[0]));
    assert.match(out.next_step, /1 more refused call/);
  } finally { await s.close(); }
});

test("a note with a backticked snapshot name passes and is sent as written; an unknown backticked name is refused", async () => {
  const root = repo();
  const { s, runCheck } = await setup();
  try {
    const ok = "`src/db.ts` inserts rows without an owner check.";
    await runCheck({ goal: "check", session: SESSION, verdicts: [verdict(ok)], concerns: [concern(CLEAN)] }, { roots: [root] });
    assert.equal(s.calls.length, 1);
    assert.deepEqual(s.calls[0].body.verdicts, [verdict(ok)]);
    assert.deepEqual(s.calls[0].body.concerns, [concern(CLEAN)]);
    const out = await runCheck({ goal: "check", session: SESSION, verdicts: [verdict("`nope.ts` is open.")] }, { roots: [root] });
    assert.equal(s.calls.length, 1);
    assert.match(out.next_step, /verdicts\[0\]\.note \(unknown_backtick_ref\)/);
  } finally { await s.close(); }
});

test("on a session's third refused call, each note still refused is withheld and kept locally, and the call goes on", async () => {
  const root = repo();
  const { s, runCheck } = await setup();
  try {
    const args = { goal: "check", session: SESSION, verdicts: [verdict(CLEAN), verdict(NAMED)], concerns: [concern(MRN)] };
    assert.equal((await runCheck(args, { roots: [root] })).error, "note_refused");
    const second = await runCheck(args, { roots: [root] });
    assert.equal(second.error, "note_refused");
    assert.match(second.next_step, /withheld/);
    assert.equal(s.calls.length, 0);
    await runCheck(args, { roots: [root] });
    assert.equal(s.calls.length, 1);
    const body = s.calls[0].body;
    assert.deepEqual(body.verdicts, [verdict(CLEAN), { ...verdict(), note_withheld: true }]);
    assert.deepEqual(body.concerns, [{ ...concern(), note: undefined, note_withheld: true }].map(({ note, ...c }) => c));
    assert.ok(!JSON.stringify(body).includes("Jane") && !JSON.stringify(body).includes("4471"));
    const kept = readWithheld(root);
    assert.deepEqual(kept.map((e) => [e.session, e.field, e.note, e.rules]), [
      [SESSION, "verdicts[1].note", NAMED, ["context_name", "name_alone", "name_pair", "placeholder_value"]],
      [SESSION, "concerns[0].note", MRN, ["hotword_digits", "digit_run"]],
    ]);
  } finally { await s.close(); }
});

test("refused calls are counted per session, so another session starts again at two", async () => {
  const root = repo();
  const { s, runCheck } = await setup();
  try {
    const args = { goal: "check", session: SESSION, verdicts: [verdict(NAMED)] };
    await runCheck(args, { roots: [root] });
    await runCheck(args, { roots: [root] });
    const other = await runCheck({ ...args, session: "ps_zyxwvutsrqponmlkjihgfe" }, { roots: [root] });
    assert.equal(other.error, "note_refused");
    assert.equal(s.calls.length, 0);
  } finally { await s.close(); }
});

test("with no note rule file, notes go out as before (the local value screens still run first)", async () => {
  const root = repo();
  const { s, runCheck } = await setup({ noteRules: null });
  try {
    await runCheck({ goal: "check", session: SESSION, verdicts: [verdict(NAMED)] }, { roots: [root] });
    assert.equal(s.calls.length, 1);
  } finally { await s.close(); }
});

test("a rewrite after a refused call reuses the document already built, never rescans (§13 item 8)", async () => {
  const root = repo();
  let skew = 0; // the client's deadlines are real time, so the clock is too, moved on by skew
  const { s, runCheck, builds } = await setup({ now: () => Date.now() + skew });
  try {
    const refused = { goal: "check", session: SESSION, verdicts: [verdict(NAMED)] };
    assert.equal((await runCheck(refused, { roots: [root] })).error, "note_refused");
    assert.equal(builds.length, 1);
    writeFileSync(join(root, "src/later.ts"), "export const x = 1;\n"); // a rescan would see this file
    await runCheck({ ...refused, verdicts: [verdict(CLEAN)] }, { roots: [root] });
    assert.equal(builds.length, 1, "the rewrite reused the built document");
    assert.equal(s.calls.length, 1);
    assert.ok(!JSON.stringify(s.calls[0].body.fact_document).includes("src/later.ts"));
    // used once: the next call builds anew
    await runCheck({ ...refused, verdicts: [verdict(CLEAN)] }, { roots: [root] });
    assert.equal(builds.length, 2);
  } finally { await s.close(); }
});

test("a built document is reused only by the same session, roots and answers, and only for 10 minutes", async () => {
  const root = repo();
  let skew = 0; // the client's deadlines are real time, so the clock is too, moved on by skew
  const { s, runCheck, builds } = await setup({ now: () => Date.now() + skew });
  try {
    const refused = { goal: "check", session: SESSION, verdicts: [verdict(NAMED)] };
    await runCheck(refused, { roots: [root] });
    await runCheck({ ...refused, session: "ps_zyxwvutsrqponmlkjihgfe", verdicts: [verdict(CLEAN)] }, { roots: [root] });
    assert.equal(builds.length, 2, "another session builds anew");
    await runCheck({ ...refused, verdicts: [verdict(CLEAN)], include_other_roots: true }, { roots: [root] });
    assert.equal(builds.length, 3, "other arguments to the build build anew");
    await runCheck(refused, { roots: [root] });
    assert.equal(builds.length, 3, "a second refusal reuses the first call's document and keeps it again");
    skew += 10 * 60_000 + 1;
    await runCheck({ ...refused, verdicts: [verdict(CLEAN)] }, { roots: [root] });
    assert.equal(builds.length, 4, "an old document is never reused");
  } finally { await s.close(); }
});

test("a get_result read that issues new expects for the answers between a refused call and its rewrite makes the rewrite build anew", async () => {
  // The build reads the session's issued expects, so the kept document is reused only while they hold.
  const root = repo();
  let skew = 0;
  const q = { question_id: "location", object_id: "a-b@one", practice_id: "a-b", ask: "Where is it?", answers: ["here", "not_found", "not_present"], expects: ["call", "function"] };
  const { s, runCheck, builds } = await setup({ now: () => Date.now() + skew,
    respond: (call) => ({ status: 200, json: call.body.select ? { goal: "check", session: call.body.session, select: call.body.select,
      part: "detail", matched: 1, results: [q], is_fetch_only: true, charged_units: 0, correlation_id: "corr_12345678" } : EVALUATE_OK }) });
  try {
    const answer = { object_id: "a-b@one", question_id: "location", answer: "here", location: "src/db.ts:1" };
    const refused = { goal: "check", session: SESSION, answers: [answer], verdicts: [verdict(NAMED)] };
    assert.equal((await runCheck(refused, { roots: [root] })).error, "note_refused");
    await runCheck({ goal: "check", session: SESSION, select: { list: "questions.a-b" } }, { roots: [root] });
    await runCheck({ ...refused, verdicts: [verdict(CLEAN)] }, { roots: [root] });
    assert.deepEqual(builds.map((b) => b.answers[0]?.expects), [undefined, ["call", "function"]], "the rewrite built anew, with the new expects");
    assert.ok(s.calls.at(-1).body.fact_document, "the rewrite was sent");
  } finally { await s.close(); }
});

// the note screen's default rule file is the copy sync-rules makes from core's manifest contracts,
// lib/inspector/contracts/screen_rules.json, which the package ships. With it, a full name in a note refuses; the tool
// never falls back to no note screen.
test("the default note rules are the synced contracts copy, and they refuse a full name", async () => {
  const tool = await import("../lib/inspector/tool.mjs");
  const { screenRaw } = await import("../lib/screen.mjs");
  assert.equal(fileURLToPath(tool.NOTE_RULES_FILE), fileURLToPath(new URL("../lib/inspector/contracts/screen_rules.json", import.meta.url)));
  const rules = tool.defaultNoteRules();
  assert.ok(rules, "the shipped rule file loads");
  assert.equal(tool.defaultNoteRules(), rules, "loaded once");
  assert.equal(screenRaw("Windy Okafor was admitted", [], rules).decision, "refuse");
  assert.equal(screenRaw("rename foo to baz in settle.py", [], rules).decision, "pass");
});

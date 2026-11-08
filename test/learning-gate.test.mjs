/* The learning gate (screening design §13 items 10 and 16): notes go out only while the
 * session's last response said learning: on. No field, off, an error answer, or no session yet counts as off. While
 * off, a verdict goes without its note, and a concern goes with note_kept_local: true in place of its note, which is
 * still kept on this computer and shown as local_text. Stub evaluator and temp folders only. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { makeRunCheck, keepNotesLocal, LearningBySession } from "../lib/inspector/tool.mjs";
import { readTexts } from "../lib/inspector/concerns.mjs";
import { writeToken } from "../lib/inspector/auth.mjs";
import { loadRules } from "../lib/inspector/rules.mjs";
import { rulesFromDoc } from "../lib/screen.mjs";
import { EVALUATE_OK, stub } from "./stub-evaluator.mjs";

const FIXTURE = JSON.parse(readFileSync(new URL("./fixtures/screen-parity.5e907cf8.json", import.meta.url), "utf8"));
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
  const root = temp("gate-");
  mkdirSync(join(root, "src"), { recursive: true });
  writeFileSync(join(root, "src/db.ts"), 'export async function save(p) { await db.from("patients").insert(p); }\n');
  return root;
}
const META = { category: "logging", area: "logging", file_kind: "server_module", proposed_severity: "high" };
const NOTE = "`src/db.ts` logs the whole row because it calls console.log on it.";
const ID = "cn_00000000000000a1";
const RAISED = { ...EVALUATE_OK, concerns: [{ concern_id: ID, ...META, severity: "high", status: "unconfirmed", label: "waits for a confirm",
  raised_now: true, next: { awaiting: "confirm", options: [{ id: "real_problem" }, { id: "not_a_problem" }, { id: "not_sure" }] } }],
  concern_options: { real_problem: "It's a real problem", not_a_problem: "It isn't a problem", not_sure: "Not sure" } };
const verdict = { practice_id: "authz-every-handler", state: "fail", reason_code: "control_missing", note: "The insert has no owner check." };

test("keepNotesLocal drops a verdict's note and marks a concern's note kept local, leaving the call's own args as they are", () => {
  const args = { goal: "check", verdicts: [verdict, { ...verdict, note: undefined }], concerns: [{ ...META, note: NOTE }] };
  const out = keepNotesLocal(args);
  assert.deepEqual(out.verdicts, [{ practice_id: verdict.practice_id, state: "fail", reason_code: "control_missing" },
    { practice_id: verdict.practice_id, state: "fail", reason_code: "control_missing", note: undefined }].map(({ note, ...v }) => v));
  assert.deepEqual(out.concerns, [{ ...META, note: NOTE, note_kept_local: true }]);
  assert.equal(args.verdicts[0].note, verdict.note);
  assert.equal(args.concerns[0].note_kept_local, undefined);
});

test("learning is on for a session only while its last answer said learning: on", () => {
  const gate = new LearningBySession();
  assert.equal(gate.on(SESSION), false);
  assert.equal(gate.on(null), false);
  gate.note(SESSION, { session: SESSION, learning: "on" });
  assert.equal(gate.on(SESSION), true);
  gate.note(SESSION, { session: SESSION });
  assert.equal(gate.on(SESSION), false, "no field is off");
  gate.note(SESSION, { learning: "on" });
  gate.note(SESSION, { error: "unavailable" });
  assert.equal(gate.on(SESSION), false, "an error answer is off");
  gate.note(SESSION, { learning: "off" });
  assert.equal(gate.on(SESSION), false);
});

test("while learning is off, no note leaves; a concern sends note_kept_local and its note is still kept and shown", async () => {
  const root = repo();
  const configDir = join(temp("gate-cfg-"), "custosa");
  const s = await stub(() => ({ status: 200, json: RAISED }));
  writeToken(TOKEN, { configDir, host: new URL(s.url).origin });
  const runCheck = makeRunCheck({ configDir, localOnly: false, buildOptions: quiet, noteRules: rulesFromDoc(FIXTURE.doc, FIXTURE.sets),
    evaluatorUrl: () => ({ url: s.url, origin: new URL(s.url).origin }), clientOptions: { sleep: async () => {} } });
  try {
    const out = await runCheck({ goal: "check", session: SESSION, verdicts: [verdict], concerns: [{ ...META, note: NOTE }] }, { roots: [root] });
    const body = s.calls[0].body;
    assert.deepEqual(body.verdicts, [{ practice_id: verdict.practice_id, state: "fail", reason_code: "control_missing" }]);
    assert.deepEqual(body.concerns, [{ ...META, note_kept_local: true }]);
    assert.ok(!JSON.stringify(body).includes("console.log") && !JSON.stringify(body).includes("owner check"));
    assert.equal(readTexts(root).get(ID)?.text, NOTE);
    assert.equal(out.concerns[0].local_text, NOTE);
  } finally { await s.close(); }
});

test("End to end: an answer that says learning: on lets the session's next notes leave, and one that says off stops them again", async () => {
  // No learningFor here: the gate reads the stub's answers, which the client checks against the synced response schema.
  const root = repo();
  const configDir = join(temp("gate-cfg-"), "custosa");
  const said = ["on", "on", "off", "off"];
  const s = await stub(() => ({ status: 200, json: { ...RAISED, learning: said.shift() } }));
  writeToken(TOKEN, { configDir, host: new URL(s.url).origin });
  const runCheck = makeRunCheck({ configDir, localOnly: false, buildOptions: quiet, noteRules: rulesFromDoc(FIXTURE.doc, FIXTURE.sets),
    evaluatorUrl: () => ({ url: s.url, origin: new URL(s.url).origin }), clientOptions: { sleep: async () => {} } });
  const PLAIN = "The handler logs the whole row.";
  const call = () => runCheck({ goal: "check", session: SESSION, verdicts: [verdict], concerns: [{ ...META, note: PLAIN }] }, { roots: [root] });
  try {
    await call();
    assert.deepEqual(s.calls[0].body.concerns, [{ ...META, note_kept_local: true }], "no answer yet is off");
    assert.equal(s.calls[0].body.verdicts[0].note, undefined);
    await call();
    assert.deepEqual(s.calls[1].body.concerns, [{ ...META, note: PLAIN }], "the last answer said on");
    assert.equal(s.calls[1].body.verdicts[0].note, verdict.note);
    await call();
    await call();
    assert.deepEqual(s.calls[3].body.concerns, [{ ...META, note_kept_local: true }], "the last answer said off");
    assert.equal(s.calls[3].body.verdicts[0].note, undefined);
  } finally { await s.close(); }
});

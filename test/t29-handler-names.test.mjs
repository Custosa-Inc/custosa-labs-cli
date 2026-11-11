/* T29-P1-C192 item 3 (P2 C198 item 1): a person question and a fix that name a handler show "GET at
 * src/app/x/route.ts:6", never the 64-character id. The check's own handler map is kept on this machine for the
 * session; nothing new is sent. The ids the assistant sends back (object and finding ids, the session) stay as core
 * wrote them. Stub evaluator and temp folders only. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { makeRunCheck } from "../lib/inspector/tool.mjs";
import { handlerLabel, withHandlerNames } from "../lib/inspector/handlernames.mjs";
import { writeToken } from "../lib/inspector/auth.mjs";
import { EVALUATE_OK, stub } from "./stub-evaluator.mjs";

const TOKEN = `phisc_${"t".repeat(43)}`;
const SESSION = EVALUATE_OK.session;
const temp = (prefix) => realpathSync(mkdtempSync(join(tmpdir(), prefix)));
const H = "3afb101e".padEnd(64, "0");
const OTHER = "9".repeat(64); // a handler the map doesn't hold (past the map's deadline)
const OBJ = `audit-patient-recorded@${H}`;
const HANDLERS = { [H]: { path: "src/app/x/route.ts", name: "GET", line: 6, column: 0 } };
const QUESTION = `Does each access record in ${H} name the patient it is about?`;
const HOW = `Add the patient id to the audit write in ${OBJ}. See also ${OTHER}.`;
// a get_result match with its detail, as core sends it (response.schema.json get_result_response)
const DETAIL = { object_id: OBJ, practice_id: "audit-patient-recorded", title: QUESTION, severity: "high", area: "audit",
  state: "needs_review", grade: "E5", reason: "person_must_decide", objects: [H], evidence: [], how: HOW };
const MATCH = { finding: OBJ, practice_id: "audit-patient-recorded", object: H, state: "needs_review", severity: "high", detail: DETAIL };

const STATE = { state_version: 1, sent: { decisions: 0, suppressions: 0, grants: 0 }, by_outcome: {}, to_commit_total: 0 };
const INDEX = { result_counts: { by_state: { pass: 0, fail: 0, not_applicable: 0, needs_review: 1, unknown: 0, error: 0 },
  by_severity: {}, by_state_and_severity: [] }, practices: [], fails: [], open: [],
  questions: [], concerns: [], fixes: [], lists: [] };
const read = (body, results) => ({ goal: body.goal, session: SESSION, select: body.select, part: body.part ?? "detail",
  matched: results.length, results, is_fetch_only: true, charged_units: 0, correlation_id: "corr_12345678" });
function answer(call) {
  const b = call.body;
  if (!b.select) return { status: 200, json: { ...EVALUATE_OK, next_step: QUESTION, state: STATE, index: INDEX } };
  if (b.select.finding === OBJ) return { status: 200, json: read(b, [MATCH]) };
  return { status: 200, json: read(b, []) };
}

async function withRun(handlers, fn) {
  const root = temp("custosa-hn-");
  mkdirSync(join(root, "src/app/x"), { recursive: true });
  writeFileSync(join(root, "src/app/x/route.ts"), "export async function GET() {}\n");
  const configDir = join(temp("custosa-hn-cfg-"), "custosa");
  const s = await stub(answer);
  writeToken(TOKEN, { configDir, host: new URL(s.url).origin });
  let asked = null;
  const runCheck = makeRunCheck({ configDir, localOnly: false, stateEnv: {},
    evaluatorUrl: () => ({ url: s.url, origin: new URL(s.url).origin }), clientOptions: { sleep: async () => {} },
    environmentFor: () => ({ environment: { value: "unknown", source: "setup" }, note: null }),
    build: async (roots, opts) => { asked = opts; return { notes: [], documents: [{ project: 0, label: "", nested: false, other: false,
      skipped: false, root_id: "0".repeat(64), abs: root, document: { session: null }, ...(handlers ? { handlers } : {}) }] }; } });
  try { await fn(runCheck, root, () => asked, s); } finally { await s.close(); }
}

test("C192 item 3: a check's answer names the handler as GET at its path and line; its object id stays", async () => {
  await withRun(HANDLERS, async (runCheck, root, asked) => {
    const out = await runCheck({ goal: "check" }, { roots: [root] });
    assert.equal(asked().handlerMap, true, "the handler map is built for an evaluation");
    assert.equal(out.next_step, "Does each access record in GET at src/app/x/route.ts:6 name the patient it is about?");
    assert.equal(out.session, SESSION);
  });
});

test("C192 item 3: a later get_result read names the handler in its text, keeps every id, and leaves an unknown id", async () => {
  await withRun(HANDLERS, async (runCheck, root) => {
    await runCheck({ goal: "check" }, { roots: [root] });
    const out = await runCheck({ goal: "check", session: SESSION, select: { finding: OBJ }, part: "detail" }, { roots: [root] });
    const [r] = out.results;
    assert.deepEqual([r.finding, r.object, r.detail.object_id, r.detail.objects], [OBJ, H, OBJ, [H]]);
    assert.equal(r.detail.title, "Does each access record in GET at src/app/x/route.ts:6 name the patient it is about?");
    assert.equal(r.detail.how, `Add the patient id to the audit write in audit-patient-recorded: GET at src/app/x/route.ts:6. See also ${OTHER}.`);
  });
});

test("C192 item 3: nothing new is sent: the request bodies carry no handler path or name", async () => {
  await withRun(HANDLERS, async (runCheck, root, _asked, s) => {
    await runCheck({ goal: "check" }, { roots: [root] });
    await runCheck({ goal: "check", session: SESSION, select: { finding: OBJ }, part: "detail" }, { roots: [root] });
    for (const call of s.calls) assert.ok(!JSON.stringify(call.body).includes("src/app/x/route.ts"), JSON.stringify(call.body));
  });
});

test("C192 item 3: with no map (a local-only or older build) the answer is as core wrote it", async () => {
  await withRun(null, async (runCheck, root) => {
    const out = await runCheck({ goal: "check" }, { roots: [root] });
    assert.equal(out.next_step, QUESTION);
  });
});

test("C192 item 3: the label, and an answer the names would push past the client's limit", () => {
  assert.equal(handlerLabel(HANDLERS[H]), "GET at src/app/x/route.ts:6");
  assert.equal(handlerLabel({ path: "a.py", name: null, line: 3 }), "a handler at a.py:3");
  assert.equal(handlerLabel({ name: "GET" }), null);
  const long = { [H]: { path: `src/${"d/".repeat(200)}r.ts`, name: "GET", line: 1 } };
  const big = { text: Array.from({ length: 300 }, () => H).join(" ") };
  assert.equal(withHandlerNames(big, long), big);
});

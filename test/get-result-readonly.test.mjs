/* T29-P1-C119: get_result is marked readOnlyHint true, because no path of it writes on this computer. A get_result
 * call, finished or cancelled, leaves state.json, the local store (.custosa/local) and every other file under the
 * project root and the config folder byte for byte the same, with the same modes. The writes come only from an
 * evaluation (state.json's to_commit, the raise texts), as P2's C116 says. Stub evaluator and temp folders only. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { makeRunCheck, RESULT_ANNOTATIONS } from "../lib/inspector/tool.mjs";
import { writeToken } from "../lib/inspector/auth.mjs";
import { readTexts } from "../lib/inspector/concerns.mjs";
import { readState } from "../lib/inspector/state.mjs";
import { EVALUATE_OK, stub } from "./stub-evaluator.mjs";

const TOKEN = `phisc_${"t".repeat(43)}`;
const SESSION = EVALUATE_OK.session;
const temp = (prefix) => realpathSync(mkdtempSync(join(tmpdir(), prefix)));

/* Every file and folder under `dir`: its path, type, mode, and the sha256 of a file's bytes. */
function snapshot(dir) {
  const out = {};
  const walk = (d) => {
    for (const name of readdirSync(d).sort()) {
      const p = join(d, name);
      const st = lstatSync(p);
      out[p] = st.isDirectory() ? `dir ${st.mode}` : st.isSymbolicLink() ? `link ${st.mode}`
        : `file ${st.mode} ${createHash("sha256").update(readFileSync(p)).digest("hex")}`;
      if (st.isDirectory()) walk(p);
    }
  };
  walk(dir);
  return out;
}

const MADE = { account_tag: "0123456789abcdef", made_on: "2026-10-30", ruleset_id: "2026-10-31.90bf3c76",
  registry_id: "2026-10-30.1234abcd", fact_token: "a".repeat(32), seal: "b".repeat(32) };
const issued = (object_id) => ({ kind: "decision", object_id, option: "not_used", expires_on: null, max_age_on: "2027-01-28",
  practice_id: object_id.split("@")[0], reasons: ["person_must_decide"], f4_class: "coverage_gap",
  why_asked: "assistant_could_not_decide", ...MADE });
const A = { category: "access", area: "access", file_kind: "route_handler", practice_id: "authz-every-handler", proposed_severity: "high" };
const TEXT_A = "The notes handler loads a note by its id without checking that the caller owns it.";
const ID_A = "cn_00000000000000a1";
const CONCERN = { concern_id: ID_A, ...A, severity: "high", status: "unconfirmed", label: "waits for a confirm", raised_now: true,
  next: { awaiting: "confirm", options: [{ id: "real_problem" }, { id: "not_a_problem" }, { id: "not_sure" }] } };
const STATE = { state_version: 1, sent: { decisions: 0, suppressions: 0, grants: 0 }, by_outcome: {}, to_commit_total: 1 };
const INDEX = { result_counts: { by_state: { pass: 0, fail: 0, not_applicable: 0, needs_review: 0, unknown: 0, error: 0 },
  by_severity: {}, by_state_and_severity: [] }, practices: [], fails: [], open: [], questions: [], concerns: [CONCERN], fixes: [], lists: [] };
const read = (body, results) => ({ goal: body.goal, session: SESSION, select: body.select, part: body.part ?? "detail",
  matched: results.length, results, is_fetch_only: true, charged_units: 0, correlation_id: "corr_12345678" });
function answer(call) {
  const b = call.body;
  if (!b.select) return { status: 200, json: { ...EVALUATE_OK, state: STATE, index: INDEX,
    concern_options: { real_problem: "It's a real problem", not_a_problem: "It isn't a problem", not_sure: "Not sure" } } };
  if (b.select.list === "state.to_commit") return { status: 200, json: read(b, [issued("rls-enabled@public.a")]) };
  if (b.select.list?.startsWith("concerns.")) return { status: 200, json: read(b, [CONCERN]) };
  return { status: 200, json: read(b, []) };
}

test("C119: get_result is marked read-only, and stays idempotent and open-world", () => {
  assert.equal(RESULT_ANNOTATIONS.readOnlyHint, true);
  assert.equal(RESULT_ANNOTATIONS.idempotentHint, true);
  assert.equal(RESULT_ANNOTATIONS.destructiveHint, false);
  assert.equal(RESULT_ANNOTATIONS.openWorldHint, true);
});

test("C119: get_result calls, finished or cancelled, leave every file under the root and the config folder the same", async () => {
  const root = temp("custosa-ro-");
  mkdirSync(join(root, "src"), { recursive: true });
  writeFileSync(join(root, "src/db.ts"), "export const x = 1;\n");
  const configDir = join(temp("custosa-ro-cfg-"), "custosa");
  const s = await stub(answer);
  writeToken(TOKEN, { configDir, host: new URL(s.url).origin });
  const runCheck = makeRunCheck({ configDir, localOnly: false, stateEnv: {},
    evaluatorUrl: () => ({ url: s.url, origin: new URL(s.url).origin }), clientOptions: { sleep: async () => {} },
    environmentFor: () => ({ environment: { value: "unknown", source: "setup" }, note: null }),
    build: async () => ({ notes: [], documents: [{ project: 0, label: "", nested: false, other: false, skipped: false,
      root_id: "0".repeat(64), abs: root, document: { session: null } }] }) });
  try {
    // an evaluation first: it writes state.json and the raise's text, and links the session to this root
    await runCheck({ goal: "check", concerns: [{ ...A, note: TEXT_A }] }, { roots: [root] });
    assert.equal(readState(root).state.decisions.length, 1);
    assert.equal(readTexts(root).get(ID_A).text, TEXT_A);
    const before = { root: snapshot(root), config: snapshot(configDir) };
    for (const [select, part] of [[{ list: "concerns.unconfirmed" }, undefined], [{ list: "state.to_commit" }, undefined],
      [{ finding: "rls-enabled@public.a" }, "detail"], [{ practice: "rls-enabled" }, "proof"], [{ list: "questions.x" }, undefined]]) {
      const out = await runCheck({ goal: "check", session: SESSION, select, ...(part ? { part } : {}) }, { roots: [root] });
      assert.equal(out.error, undefined, JSON.stringify(out));
    }
    const c = new AbortController();
    c.abort();
    await assert.rejects(runCheck({ goal: "check", session: SESSION, select: { list: "state.to_commit" } }, { roots: [root], signal: c.signal }));
    assert.deepEqual(snapshot(root), before.root);
    assert.deepEqual(snapshot(configDir), before.config);
  } finally { await s.close(); }
});

/* T29 o2, P2's C115 med 1: a cancel after an evaluation was sent must not lose that call's local record. The call ends
 * at once (H1), and the evaluation goes on in the background. Its answer's lists are read through get_result (free,
 * never charged), and those reads go out without the cancelled call's signal, so the background run still writes
 * state.json's to_commit entries and keeps the texts of the call's raises. They still stop at the call's deadline.
 * A local server that answers the evaluation after 200 ms, a cancel at 50 ms, and the real client. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtempSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { makeRunCheck } from "../lib/inspector/tool.mjs";
import { writeToken } from "../lib/inspector/auth.mjs";
import { readState } from "../lib/inspector/state.mjs";
import { readTexts } from "../lib/inspector/concerns.mjs";
import { EVALUATE_OK } from "./stub-evaluator.mjs";

const TOKEN = `phisc_${"t".repeat(43)}`;
const SESSION = EVALUATE_OK.session;
const temp = (prefix) => realpathSync(mkdtempSync(join(tmpdir(), prefix)));
const MADE = { account_tag: "0123456789abcdef", made_on: "2026-10-30", ruleset_id: "2026-10-31.90bf3c76",
  registry_id: "2026-10-30.1234abcd", fact_token: "a".repeat(32), seal: "b".repeat(32) };
const issued = (object_id) => ({ kind: "decision", object_id, option: "not_used", expires_on: null, max_age_on: "2027-01-28",
  practice_id: object_id.split("@")[0], reasons: ["person_must_decide"], f4_class: "coverage_gap",
  why_asked: "assistant_could_not_decide", ...MADE });
const INDEX = (more = {}) => ({ result_counts: { by_state: { pass: 0, fail: 0, not_applicable: 0, needs_review: 0, unknown: 0, error: 0 },
  by_severity: {}, by_state_and_severity: [] }, practices: [], fails: [], open: [], questions: [], concerns: [], fixes: [], lists: [], ...more });
const read = (body, results) => ({ goal: body.goal, session: SESSION, select: body.select, part: "detail", matched: results.length,
  results, is_fetch_only: true, charged_units: 0, correlation_id: "corr_12345678" });

/* `answer(body)` -> the json for one request; an evaluation (no select) is answered after `delayMs`. */
async function server(answer, delayMs = 200) {
  const calls = [];
  const srv = createServer((req, res) => {
    let raw = ""; req.on("data", (d) => { raw += d; });
    req.on("end", () => {
      const body = JSON.parse(raw);
      calls.push(body);
      const send = () => { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify(answer(body))); };
      if (body.select) send(); else setTimeout(send, delayMs);
    });
  });
  await new Promise((ok) => srv.listen(0, "127.0.0.1", ok));
  const url = `http://127.0.0.1:${srv.address().port}`;
  return { url, calls, close: () => new Promise((ok) => srv.close(ok)) };
}
function wired(url, root) {
  const configDir = join(temp("custosa-cancel-cfg-"), "custosa");
  writeToken(TOKEN, { configDir, host: new URL(url).origin });
  return makeRunCheck({ configDir, localOnly: false, stateEnv: {}, evaluatorUrl: () => ({ url, origin: new URL(url).origin }),
    environmentFor: () => ({ environment: { value: "unknown", source: "setup" }, note: null }),
    build: async () => ({ notes: [], documents: [{ project: 0, label: "", nested: false, other: false, skipped: false,
      root_id: "0".repeat(64), abs: root, document: { session: null } }] }) });
}
const until = async (ok, ms = 3000) => { const end = Date.now() + ms; while (!ok() && Date.now() < end) await new Promise((r) => setTimeout(r, 20)); return ok(); };
async function cancelled(runCheck, args) {
  const c = new AbortController();
  setTimeout(() => c.abort(), 50);
  await assert.rejects(runCheck(args, { roots: ["A"], signal: c.signal }), { name: "AbortError" });
}

test("C115 med 1: a cancel after send still writes the to_commit entries read from the store", async () => {
  const root = temp("custosa-cancel-");
  const entries = [issued("rls-enabled@public.a"), issued("rls-enabled@public.b")];
  const state = { state_version: 1, sent: { decisions: 0, suppressions: 0, grants: 0 }, by_outcome: {}, to_commit_total: 2 };
  const s = await server((body) => {
    if (!body.select) return { ...EVALUATE_OK, state, index: INDEX() }; // in progress: the top-level state only (contract 2.3)
    return read(body, body.select.list === "state.to_commit" ? entries : []);
  });
  try {
    await cancelled(wired(s.url, root), { goal: "check" });
    const written = () => readState(root).state?.decisions?.map((d) => d.subject) ?? [];
    assert.ok(await until(() => written().length === 2), `state.json holds ${JSON.stringify(written())}`);
    assert.deepEqual(written(), ["rls-enabled@public.a", "rls-enabled@public.b"]);
  } finally { await s.close(); }
});

test("C115 med 1: a cancel after send still keeps the texts of the call's raises read from the store", async () => {
  const root = temp("custosa-cancel-");
  const A = { category: "access", area: "access", file_kind: "route_handler", practice_id: "authz-every-handler", proposed_severity: "high" };
  const TEXT_A = "The notes handler loads a note by its id without checking that the caller owns it.";
  const ID_A = "cn_00000000000000a1";
  const listed = { concern_id: ID_A, ...A, severity: "high", status: "unconfirmed", label: "waits for a confirm", raised_now: true,
    next: { awaiting: "confirm", options: [{ id: "real_problem" }, { id: "not_a_problem" }, { id: "not_sure" }] } };
  const select = { list: "concerns.unconfirmed" };
  const s = await server((body) => (body.select ? read(body, [listed])
    : { ...EVALUATE_OK, concern_options: { real_problem: "It's a real problem", not_a_problem: "It isn't a problem", not_sure: "Not sure" },
      index: INDEX({ concerns_grouped: [{ status: "unconfirmed", count: 1, select }] }) }));
  try {
    await cancelled(wired(s.url, root), { goal: "check", concerns: [{ ...A, note: TEXT_A }] });
    assert.ok(await until(() => readTexts(root).has(ID_A)), "the raise's text was not kept");
    assert.equal(readTexts(root).get(ID_A).text, TEXT_A);
    assert.ok(s.calls.some((b) => b.select?.list === "concerns.unconfirmed"));
  } finally { await s.close(); }
});

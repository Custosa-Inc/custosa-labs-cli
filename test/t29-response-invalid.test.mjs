/* T29-P1-C204 item 2 (P2 live look 1, L1). Two of three live sessions ended on evaluator_response_invalid, and the
 * CLI kept no trace of why. Now the error's local_notes say what was wrong with the reply (its HTTP status and the
 * schema rule it broke, never a value from it), and when the reply speaks this inspector's own contract the words no
 * longer ask the user to update the inspector: they say the call may have run and what to send next. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { evaluate, CONTRACT_VERSION, MAX_RESPONSE_BYTES } from "../lib/inspector/client.mjs";
import { EVALUATE_OK, stub } from "./stub-evaluator.mjs";

const TOKEN = `phisc_${"a".repeat(43)}`;
const SESSION = "ps_abcdefghijklmnopqrstuv";
const SECRET = "VALUE-NEVER-SHOWN-7f3a";

async function call(out, body = { goal: "check" }) {
  const s = await stub(() => out);
  try {
    const got = await evaluate(body, { token: TOKEN, baseUrl: s.url, sleep: async () => {} });
    assert.equal(got.ok, false);
    assert.equal(got.body.error, "evaluator_response_invalid", JSON.stringify(got));
    assert.equal(s.calls.length, 1);
    return got.body;
  } finally { await s.close(); }
}

test("the local note names what was wrong with the reply, and never a value from it", async () => {
  const cases = [
    [{ status: 200, json: { ...EVALUATE_OK, extra: SECRET } }, /^The evaluator's reply \(HTTP 200\) failed this inspector's response schema at "\/" \(rule: additionalProperties\)\.$/],
    [{ status: 200, json: { ...EVALUATE_OK, headline: 7 } }, /failed this inspector's response schema at "\/headline" \(rule: type\)\.$/],
    [{ status: 500, raw: `Internal Server Error ${SECRET}` }, /^The evaluator's reply \(HTTP 500\) was not a JSON object\.$/],
    [{ status: 401, json: { error: "rate_limited", next_step: SECRET, correlation_id: "corr_12345678", retry_after_seconds: 1 } },
      /^The evaluator's reply \(HTTP 401\) was an error whose code doesn't match its HTTP status\.$/],
  ];
  for (const [out, note] of cases) {
    const body = await call(out);
    assert.equal(body.local_notes.length, 1, JSON.stringify(body));
    assert.match(body.local_notes[0], note);
    assert.ok(!JSON.stringify(body).includes(SECRET), JSON.stringify(body));
  }
});

test("a reply over the size cap says so", async () => {
  const body = await call({ status: 200, raw: `"${"x".repeat(MAX_RESPONSE_BYTES + 10)}"` });
  assert.match(body.local_notes[0], new RegExp(`^The evaluator's reply \\(HTTP 200\\) was over ${MAX_RESPONSE_BYTES} bytes`));
});

test("an evaluator on this inspector's contract: no update asked, the call may have run, read the session first", async () => {
  assert.match(CONTRACT_VERSION, /^[0-9]+\.[0-9]+$/);
  const reply = { status: 200, json: { ...EVALUATE_OK, contract_version: CONTRACT_VERSION, extra: 1 } };
  const body = await call(reply, { goal: "verify", session: SESSION, verdicts: [] });
  assert.doesNotMatch(body.next_step, /custosa@latest setup|to update the inspector/);
  assert.match(body.next_step, /updating it won't help/);
  assert.match(body.next_step, /may have run and may have been charged/);
  assert.match(body.next_step, /Don't send the same call again/);
  assert.ok(body.next_step.includes(`{"goal": "verify", "session": "${SESSION}", "select": {"state": "fail"}}`), body.next_step);
  // a first check has no session of its own; the reply's is used when it is a session id
  const first = await call({ status: 200, json: { ...EVALUATE_OK, contract_version: CONTRACT_VERSION, headline: 7 } });
  assert.ok(first.next_step.includes(`"session": "${EVALUATE_OK.session}"`), first.next_step);
  const none = await call({ status: 200, json: { ...EVALUATE_OK, contract_version: CONTRACT_VERSION, session: 7 } });
  assert.match(none.next_step, /check their usage on their account page/);
  assert.doesNotMatch(none.next_step, /custosa@latest setup/);
});

test("a get_result read on this inspector's contract may be made once more, with no update asked", async () => {
  const body = await call({ status: 200, json: { ...EVALUATE_OK, contract_version: CONTRACT_VERSION, extra: 1 } },
    { goal: "check", session: SESSION, select: { state: "fail" } });
  assert.doesNotMatch(body.next_step, /custosa@latest setup/);
  assert.match(body.next_step, /Make the same call once more/);
});

test("a reply on another contract, or none, keeps the update words", async () => {
  for (const version of ["1.0", undefined]) {
    const json = { ...EVALUATE_OK, extra: 1, ...(version ? { contract_version: version } : {}) };
    const body = await call({ status: 200, json });
    assert.match(body.next_step, /npx custosa@latest setup/);
    assert.match(body.next_step, /may have run and may have been charged/);
    assert.equal(body.local_notes.length, 1);
  }
});

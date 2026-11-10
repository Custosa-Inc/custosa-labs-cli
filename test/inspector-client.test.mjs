/* The evaluator client against a local stub server on 127.0.0.1: headers and body, the response schema, retries
 * only where the contract says a refusal is never charged, no call without a sign-in, no redirect followed, and the
 * evaluator address rules. No real service is contacted. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, realpathSync, writeFileSync, statSync, chmodSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { evaluate, evaluatorUrl, checkEvaluateAnswer, DEFAULT_EVALUATOR_URL } from "../lib/inspector/client.mjs";
import { readToken, writeToken, removeToken } from "../lib/inspector/auth.mjs";
import { EVALUATE_OK, stub } from "./stub-evaluator.mjs";

const TOKEN = `phisc_${"a".repeat(43)}`;
const temp = (prefix) => realpathSync(mkdtempSync(join(tmpdir(), prefix)));

/* Whether the response schema accepts the stub's evaluate answer at all (the stub must be lawful for the tests). */
test("the stub's evaluate answer is a lawful evaluate_response", () => {
  assert.deepEqual(checkEvaluateAnswer(200, structuredClone(EVALUATE_OK)), { ok: true, body: EVALUATE_OK });
});

test("evaluate: posts the envelope with the contract's headers and returns the evaluator's answer unchanged", async () => {
  const s = await stub(() => ({ status: 200, json: EVALUATE_OK }));
  try {
    const body = { goal: "check", fact_document: { schema_version: 2 } };
    const out = await evaluate(body, { token: TOKEN, baseUrl: s.url, inspectorVersion: "0.1.1" });
    assert.deepEqual(out, { ok: true, body: EVALUATE_OK });
    assert.equal(s.calls.length, 1);
    const [c] = s.calls;
    assert.equal(c.method, "POST");
    assert.equal(c.url, "/v1/evaluate");
    assert.equal(c.headers.authorization, `Bearer ${TOKEN}`);
    assert.equal(c.headers["content-type"], "application/json");
    assert.equal(c.headers["user-agent"], "custosa-inspector/0.1.1");
    assert.deepEqual(c.body, body);
  } finally { await s.close(); }
});

test("evaluate: nothing is sent without a sign-in", async () => {
  const s = await stub(() => ({ status: 200, json: EVALUATE_OK }));
  try {
    const out = await evaluate({ goal: "check" }, { token: null, baseUrl: s.url });
    assert.equal(out.ok, false);
    assert.equal(out.body.error, "sign_in_required");
    assert.equal(out.body.local, true);
    assert.equal(s.calls.length, 0);
  } finally { await s.close(); }
});

test("evaluate: refusals pass through; only never-charged refusals with a short wait are retried", async () => {
  const err = (error, extra = {}) => ({ error, next_step: "Words of the evaluator.", correlation_id: "corr_12345678", ...extra });
  // update_inspector (409) comes back as it is, once.
  let s = await stub(() => ({ status: 409, json: err("update_inspector", { current_ruleset_id: "2026-10-21.89abcdef" }) }));
  try {
    const out = await evaluate({ goal: "check" }, { token: TOKEN, baseUrl: s.url });
    assert.deepEqual(out, { ok: false, body: err("update_inspector", { current_ruleset_id: "2026-10-21.89abcdef" }) });
    assert.equal(s.calls.length, 1);
  } finally { await s.close(); }
  // unavailable twice, then the answer: retried after retry_after_seconds.
  const waits = [];
  s = await stub((_, n) => (n < 3 ? { status: 503, json: err("unavailable", { retry_after_seconds: 2 }) } : { status: 200, json: EVALUATE_OK }));
  try {
    const out = await evaluate({ goal: "check" }, { token: TOKEN, baseUrl: s.url, sleep: async (ms) => { waits.push(ms); } });
    assert.equal(out.ok, true);
    assert.deepEqual(waits, [2000, 2000]);
    assert.equal(s.calls.length, 3);
  } finally { await s.close(); }
  // A long wait is not slept through: the refusal goes back to the assistant.
  s = await stub(() => ({ status: 429, json: err("rate_limited", { retry_after_seconds: 600 }) }));
  try {
    const out = await evaluate({ goal: "check" }, { token: TOKEN, baseUrl: s.url, sleep: async () => assert.fail("slept") });
    assert.equal(out.body.error, "rate_limited");
    assert.equal(s.calls.length, 1);
  } finally { await s.close(); }
  // internal_error is never retried.
  s = await stub(() => ({ status: 500, json: err("internal_error") }));
  try {
    const out = await evaluate({ goal: "check" }, { token: TOKEN, baseUrl: s.url, sleep: async () => assert.fail("slept") });
    assert.equal(out.body.error, "internal_error");
    assert.equal(s.calls.length, 1);
  } finally { await s.close(); }
});

test("evaluate: an answer outside the response schema is never passed on as a result", async () => {
  for (const out of [
    { status: 200, json: { ...EVALUATE_OK, extra: 1 } },
    { status: 200, json: { error: "internal_error", next_step: "x", correlation_id: "corr_12345678" } },
    { status: 401, json: { error: "rate_limited", next_step: "x", correlation_id: "corr_12345678", retry_after_seconds: 1 } },
    { status: 200, raw: "<html>not json</html>" },
    { status: 302, raw: "", headers: { location: "http://127.0.0.1:1/elsewhere" } },
  ]) {
    const s = await stub(() => out);
    try {
      const got = await evaluate({ goal: "check" }, { token: TOKEN, baseUrl: s.url, sleep: async () => {} });
      assert.equal(got.ok, false);
      assert.equal(got.body.error, "evaluator_response_invalid", JSON.stringify(out));
      // an evaluation's unreadable answer may have been charged, so it never invites the same call again.
      assert.match(got.body.next_step, /may have run and may have been charged/, JSON.stringify(out));
      assert.doesNotMatch(got.body.next_step, /then make the same call again\.$/);
      assert.equal(s.calls.length, 1);
    } finally { await s.close(); }
  }
});

test("evaluate: an unreachable evaluator is a local error; an evaluation is not re-sent, a get_result read is once", async () => {
  const s = await stub(() => ({ status: 200, json: EVALUATE_OK }));
  const url = s.url;
  await s.close();
  let calls = 0;
  // undici's network failure: a TypeError whose cause says what happened (a TypeError with no cause is a request that
  // couldn't be built, which never left the machine).
  const failing = async () => { calls++; throw new TypeError("fetch failed", { cause: Object.assign(new Error("other side closed"), { code: "UND_ERR_SOCKET" }) }); };
  // A refused connection: nothing left the machine.
  let out = await evaluate({ goal: "check", fact_document: {} }, { token: TOKEN, baseUrl: url });
  assert.equal(out.body.error, "evaluator_unreachable");
  // A drop that may have come after the request was read: may have run, never re-sent (review item 9).
  out = await evaluate({ goal: "check", fact_document: {} }, { token: TOKEN, baseUrl: url, fetch: failing });
  assert.equal(out.body.error, "evaluator_connection_lost");
  assert.match(out.body.next_step, /may have run/);
  assert.equal(calls, 1);
  calls = 0;
  out = await evaluate({ goal: "check", session: "ps_abcdefghijklmnopqrstuv", select: { state: "fail" } }, { token: TOKEN, baseUrl: url, fetch: failing });
  assert.equal(out.body.error, "evaluator_unreachable");
  assert.equal(calls, 2);
  assert.ok(!JSON.stringify(out).includes(TOKEN));
});

test("evaluatorUrl: https, or http to this computer only; env, then evaluator.json, then the default", () => {
  const dir = temp("a7-url-");
  assert.deepEqual(evaluatorUrl({ env: {}, configDir: dir }), { url: DEFAULT_EVALUATOR_URL, origin: DEFAULT_EVALUATOR_URL, source: "default" });
  writeFileSync(join(dir, "evaluator.json"), JSON.stringify({ url: "https://staging.example.test/base/" }));
  assert.deepEqual(evaluatorUrl({ env: {}, configDir: dir }), { url: "https://staging.example.test/base", origin: "https://staging.example.test", source: "file" });
  assert.deepEqual(evaluatorUrl({ env: { CUSTOSA_EVALUATOR_URL: "http://127.0.0.1:8080" }, configDir: dir }), { url: "http://127.0.0.1:8080", origin: "http://127.0.0.1:8080", source: "env" });
  for (const bad of ["http://evaluator.example.test", "ftp://x", "https://user:pw@x.test", "https://x.test/?q=1", "not a url"]) {
    assert.deepEqual(evaluatorUrl({ env: { CUSTOSA_EVALUATOR_URL: bad }, configDir: dir }), { problem: "evaluator_url_invalid" }, bad);
  }
});

test("token storage: 0600 in the config folder, refused when others can read it, never echoed", () => {
  const dir = join(temp("a7-tok-"), "custosa");
  assert.deepEqual(readToken({ configDir: dir }), { missing: true });
  writeToken(TOKEN, { configDir: dir, host: "https://evaluator.example.test" });
  if (process.platform !== "win32") {
    assert.equal(statSync(join(dir, "token")).mode & 0o777, 0o600);
    assert.equal(statSync(dir).mode & 0o777, 0o700);
  }
  assert.deepEqual(readToken({ configDir: dir }), { token: TOKEN, host: "https://evaluator.example.test" });
  if (process.platform !== "win32") {
    chmodSync(join(dir, "token"), 0o644);
    const r = readToken({ configDir: dir });
    assert.ok(r.refused && !JSON.stringify(r).includes(TOKEN));
    chmodSync(join(dir, "token"), 0o600);
  }
  assert.throws(() => writeToken("short", { configDir: dir, host: "https://evaluator.example.test" }), (e) => !e.message.includes("short"));
  assert.throws(() => writeToken(TOKEN, { configDir: dir }), /bind/); // never stored without the evaluator it belongs to
  assert.equal(removeToken({ configDir: dir }), true);
  assert.deepEqual(readToken({ configDir: dir }), { missing: true });
  mkdirSync(join(dir, "token"));
  assert.ok(readToken({ configDir: dir }).refused);
});

test("evaluator.json gets the token file's safeguards: no symlink, nothing others can write, nobody else's (review p8)", async (t) => {
  if (process.platform === "win32") return t.skip("POSIX permissions");
  const { symlinkSync } = await import("node:fs");
  const dir = temp("a7-evj-");
  writeFileSync(join(dir, "evaluator.json"), JSON.stringify({ url: "https://attacker.example.test" }));
  chmodSync(join(dir, "evaluator.json"), 0o666);
  assert.deepEqual(evaluatorUrl({ env: {}, configDir: dir }), { problem: "evaluator_config_insecure" });
  chmodSync(join(dir, "evaluator.json"), 0o600);
  chmodSync(dir, 0o777);
  assert.deepEqual(evaluatorUrl({ env: {}, configDir: dir }), { problem: "evaluator_config_insecure" });
  chmodSync(dir, 0o700);
  assert.equal(evaluatorUrl({ env: {}, configDir: dir }).source, "file");
  const other = temp("a7-evj2-");
  writeFileSync(join(other, "real.json"), JSON.stringify({ url: "https://attacker2.example.test" }));
  symlinkSync(join(other, "real.json"), join(other, "evaluator.json"));
  assert.deepEqual(evaluatorUrl({ env: {}, configDir: other }), { problem: "evaluator_config_insecure" });
});

test("evaluate: a 200 cut off mid-body is reported as incomplete, never as a result (review item 9)", async () => {
  const { createServer } = await import("node:http");
  let hits = 0;
  const server = createServer((req, res) => {
    req.resume();
    req.on("end", () => { hits++; res.writeHead(200, { "content-type": "application/json" }); res.write('{"goal":"check",'); setTimeout(() => req.socket.destroy(), 30); });
  });
  await new Promise((ok) => server.listen(0, "127.0.0.1", ok));
  try {
    const out = await evaluate({ goal: "check", fact_document: {} }, { token: TOKEN, baseUrl: `http://127.0.0.1:${server.address().port}` });
    assert.equal(out.body.error, "evaluator_response_incomplete");
    assert.match(out.body.next_step, /cut off/);
    assert.equal(hits, 1);
  } finally { await new Promise((ok) => server.close(ok)); }
});

test("An evaluation page that names its evaluator build and the inspector version (RC2) is a lawful answer", async () => {
  const { validateResponse } = await import("../lib/inspector/schema.mjs");
  assert.equal(validateResponse(EVALUATE_OK), null);
  // The evaluator sends both on every evaluation page; before the refresh this inspector refused every answer.
  assert.equal(validateResponse({ ...EVALUATE_OK, evaluator_version: "custosa-hosted-core-00042-abc", inspector_version: "0.45.3" }), null);
  assert.notEqual(validateResponse({ ...EVALUATE_OK, inspector_version: "not a version" }), null);
});

test("A page 1 that names answers the session never issued (not_used) is a lawful answer", async () => {
  const { validateResponse } = await import("../lib/inspector/schema.mjs");
  const stray = { object_id: "phi-columns@public.patients:dob", question_id: "purpose", reason: "not_issued" };
  // The evaluator sets such an answer aside and names it; before the sync this inspector
  // refused the whole answer as evaluator_response_invalid.
  assert.equal(validateResponse({ ...EVALUATE_OK, not_used: [stray] }), null);
  assert.notEqual(validateResponse({ ...EVALUATE_OK, not_used: [{ ...stray, reason: "other" }] }), null);
  assert.notEqual(validateResponse({ ...EVALUATE_OK, not_used: Array(21).fill(stray) }), null);
});

// a get_result read cut off is sent once more (it is never charged), then reported as unreadable, not as incomplete.
test("evaluate: a get_result read cut off twice is evaluator_response_invalid after one retry", async () => {
  const { createServer } = await import("node:http");
  let hits = 0;
  const server = createServer((req, res) => {
    req.resume();
    req.on("end", () => { hits++; res.writeHead(200, { "content-type": "application/json" }); res.write('{"goal":"check",'); setTimeout(() => req.socket.destroy(), 30); });
  });
  await new Promise((ok) => server.listen(0, "127.0.0.1", ok));
  try {
    const out = await evaluate({ goal: "check", session: "ps_abcdefghijklmnopqrstuv", select: { state: "fail" } },
      { token: TOKEN, baseUrl: `http://127.0.0.1:${server.address().port}` });
    assert.equal(out.body.error, "evaluator_response_invalid");
    assert.equal(hits, 2);
  } finally { await new Promise((ok) => server.close(ok)); }
});

// custosa doctor's probe names the inspector like every evaluate call does.
test("health: the probe sends the inspector's user-agent and reads only status ok", async () => {
  const { health } = await import("../lib/inspector/client.mjs");
  const seen = [];
  const fetch = async (url, init) => {
    seen.push([url, init.method, init.redirect, init.headers]);
    return new Response(JSON.stringify({ status: seen.length === 1 ? "ok" : "down" }), { status: 200 });
  };
  assert.deepEqual(await health("https://e.example", { fetch, inspectorVersion: "9.9.9" }), { ok: true });
  assert.deepEqual(await health("https://e.example", { fetch, inspectorVersion: "9.9.9" }), { ok: false, why: "http_200" });
  assert.deepEqual(seen[0], ["https://e.example/v1/health", "GET", "manual",
    { accept: "application/json", "user-agent": "custosa-inspector/9.9.9" }]);
});

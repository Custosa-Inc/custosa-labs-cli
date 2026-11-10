/* The operational fixes: the Idempotency-Key header, custosa logout's server revoke (OP1), custosa doctor (OP2), the
 * Node version floor (OP3), the pinned client command and the Codex timeouts (CC1), and the Supabase personal access
 * token warning (LI7). Every network call goes to a local stub; every config folder and home is temporary. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync, chmodSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createServer } from "node:http";
import { MIN_NODE, nodeSupported, tilde } from "../lib/version.mjs";
import { evaluate, health, notSent, post, revokeToken, REVOKE_PATH, HEALTH_PATH, EVALUATOR_TIMEOUT_MS, EVALUATE_DEADLINE_MS, MIN_SEND_MS } from "../lib/inspector/client.mjs";
import { makeRunCheck, CALL_BUDGET_MS } from "../lib/inspector/tool.mjs";
import { readToken, writeToken } from "../lib/inspector/auth.mjs";
import { platformTokenNotes, SUPABASE_PAT_NOTE } from "../lib/inspector/platform.mjs";
import { runDoctor, npxVersions } from "../lib/doctor.mjs";
import { INSPECT, VERSION } from "../lib/clients.mjs";
import { CODEX_TIMEOUTS, codexAdd, codexEnsureTimeouts, codexSetCommand, codexServer } from "../lib/toml.mjs";
import { EVALUATE_OK, stub } from "./stub-evaluator.mjs";

const TOKEN = `phisc_${"z".repeat(43)}`;
const BIN = fileURLToPath(new URL("../bin/custosa.mjs", import.meta.url));
const temp = (prefix) => realpathSync(mkdtempSync(join(tmpdir(), prefix)));
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const bin = (args, env) => new Promise((ok) => execFile(process.execPath, [BIN, ...args], { env: { ...process.env, ...env }, timeout: 60_000 },
  (error, stdout, stderr) => ok({ code: error ? error.code : 0, stdout, stderr })));

test("Idempotency-Key: a fresh UUID per evaluate call, the same on each retry of that call", async () => {
  let n = 0;
  const s = await stub(() => (++n === 1
    ? { status: 429, json: { error: "rate_limited", next_step: "Wait.", correlation_id: "corr_12345678", retry_after_seconds: 1 } }
    : { status: 200, json: EVALUATE_OK }));
  try {
    const body = { goal: "check", fact_document: {} };
    assert.equal((await evaluate(body, { token: TOKEN, baseUrl: s.url, sleep: async () => {} })).ok, true);
    assert.equal((await evaluate(body, { token: TOKEN, baseUrl: s.url, sleep: async () => {} })).ok, true);
    const keys = s.calls.map((c) => c.headers["idempotency-key"]);
    assert.equal(keys.length, 3);
    assert.ok(keys.every((k) => UUID.test(k)), keys.join(" "));
    assert.equal(keys[0], keys[1], "the retry reuses its call's key");
    assert.notEqual(keys[1], keys[2], "a new call gets a new key");
  } finally { await s.close(); }
});

test("The evaluator timeout is 150 s; a timed-out attempt that is retried reuses its Idempotency-Key", async () => {
  assert.equal(EVALUATOR_TIMEOUT_MS, 150_000, "at least Cloud Run's 150 s request timeout");
  // A server whose first answer comes too late for the (shortened) timeout, then answers at once.
  const calls = [];
  const server = createServer((req, res) => {
    calls.push(req.headers["idempotency-key"]);
    req.resume();
    req.on("end", () => {
      const send = () => { if (!res.destroyed) { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify(EVALUATE_OK)); } };
      if (calls.length === 1) setTimeout(send, 1500); else send();
    });
  });
  await new Promise((ok) => server.listen(0, "127.0.0.1", ok));
  const url = `http://127.0.0.1:${server.address().port}`;
  try {
    // A get_result read evaluates and charges nothing, so a timed-out attempt is retried once, with the same key.
    const read = await evaluate({ goal: "check", session: "ps_abcdefghijklmnopqrstuv", select: { state: "fail" } }, { token: TOKEN, baseUrl: url, timeoutMs: 300 });
    assert.equal(read.ok, true, JSON.stringify(read));
    assert.equal(calls.length, 2);
    assert.ok(UUID.test(calls[0]));
    assert.equal(calls[1], calls[0], "the retry of a timed-out attempt reuses its key");
    // An evaluation that timed out may have been charged: it is never re-sent, and the assistant is told it may have run.
    calls.length = 0;
    const evaluation = await evaluate({ goal: "check", fact_document: {} }, { token: TOKEN, baseUrl: url, timeoutMs: 300 });
    assert.equal(evaluation.body.error, "evaluator_connection_lost");
    assert.equal(calls.length, 1);
  } finally { server.closeAllConnections(); await new Promise((ok) => server.close(ok)); }
});

test("evaluate: an aborted signal stops the call and its retry wait", async () => {
  const s = await stub(() => ({ status: 429, json: { error: "rate_limited", next_step: "Wait.", correlation_id: "corr_12345678", retry_after_seconds: 20 } }));
  try {
    const c = new AbortController();
    const t0 = Date.now();
    setTimeout(() => c.abort(), 200);
    await assert.rejects(evaluate({ goal: "check" }, { token: TOKEN, baseUrl: s.url, signal: c.signal }), { name: "AbortError" });
    assert.ok(Date.now() - t0 < 5000);
    assert.equal(s.calls.length, 1);
  } finally { await s.close(); }
});

test("OP1: revokeToken posts the bearer token to the one revoke path; failures are reported, never thrown", async () => {
  assert.equal(REVOKE_PATH, "/v1/token/revoke");
  const s = await stub((call) => (call.headers.authorization === `Bearer ${TOKEN}` ? { status: 200, json: {} } : { status: 404, json: {} }));
  try {
    assert.deepEqual(await revokeToken({ token: TOKEN, baseUrl: s.url }), { revoked: true });
    assert.equal(s.calls[0].url, REVOKE_PATH);
    assert.equal(s.calls[0].method, "POST");
    assert.deepEqual(await revokeToken({ token: `phisc_${"y".repeat(43)}`, baseUrl: s.url }), { revoked: false, why: "http_404" });
  } finally { await s.close(); }
  assert.deepEqual(await revokeToken({ token: TOKEN, baseUrl: s.url }), { revoked: false, why: "unreachable" });
});

test("OP1: custosa logout revokes on the server, then deletes locally; offline or 404 still deletes and says so", async () => {
  for (const [answer, words] of [[200, /revoked on the server and removed/], [404, /server revoke didn't happen \(the evaluator doesn't offer revoking yet\)/], [null, /server revoke didn't happen \(the evaluator couldn't be reached\)/]]) {
    const s = await stub(() => ({ status: answer ?? 200, json: {} }));
    const configDir = join(temp("custosa-logout-"), "custosa");
    writeToken(TOKEN, { configDir, host: new URL(s.url).origin });
    if (answer === null) await s.close();
    const res = await bin(["logout"], { CUSTOSA_CONFIG_DIR: configDir, CUSTOSA_EVALUATOR_URL: s.url });
    if (answer !== null) await s.close();
    assert.equal(res.code, 0, res.stderr);
    assert.match(res.stdout, words);
    assert.ok(!res.stdout.includes(TOKEN) && !res.stderr.includes(TOKEN));
    assert.deepEqual(readToken({ configDir }), { missing: true });
    if (answer !== null) assert.equal(s.calls[0].url, REVOKE_PATH);
  }
  const none = await bin(["logout"], { CUSTOSA_CONFIG_DIR: join(temp("custosa-logout-"), "custosa") });
  assert.match(none.stdout, /no saved sign-in/);
});

test("custosa logout sends the revoke to the evaluator that issued the token, under its path when it is the one configured", async () => {
  const issuer = await stub(() => ({ status: 200, json: {} }));
  const other = await stub(() => ({ status: 200, json: {} }));
  try {
    for (const [evaluator, path] of [
      [issuer.url, REVOKE_PATH],                                 // the evaluator configured issued it
      [`${issuer.url}/base`, `/base${REVOKE_PATH}`],             // the same origin with a path: revoked under that path
      [other.url, REVOKE_PATH],                                  // another evaluator configured: sent to the issuer's origin
      ["http://evaluator.example.test", REVOKE_PATH],            // an address that can't be used: the issuer's origin
    ]) {
      const configDir = join(temp("custosa-logout-"), "custosa");
      writeToken(TOKEN, { configDir, host: new URL(issuer.url).origin });
      const before = issuer.calls.length;
      const res = await bin(["logout"], { CUSTOSA_CONFIG_DIR: configDir, CUSTOSA_EVALUATOR_URL: evaluator });
      assert.equal(res.code, 0, res.stderr);
      assert.match(res.stdout, /revoked on the server and removed/, evaluator);
      assert.deepEqual(issuer.calls.slice(before).map((c) => c.url), [path], evaluator);
      assert.equal(other.calls.length, 0, evaluator);
    }
  } finally { await issuer.close(); await other.close(); }
});

test("health: one unauthenticated GET of /v1/health, and nothing else, even after a 404", async () => {
  assert.equal(HEALTH_PATH, "/v1/health");
  const s = await stub(() => ({ status: 200, json: { status: "ok" } }));
  try {
    assert.deepEqual(await health(s.url), { ok: true });
    assert.equal(s.calls.length, 1);
    assert.equal(s.calls[0].method, "GET");
    assert.equal(s.calls[0].url, "/v1/health");
    assert.equal(s.calls[0].headers.authorization, undefined);
  } finally { await s.close(); }
  const old = await stub((call) => (call.url === "/health" ? { status: 200, json: { status: "ok" } } : { status: 404, json: {} }));
  try {
    assert.deepEqual(await health(old.url), { ok: false, why: "http_404" });
    assert.deepEqual(old.calls.map((c) => c.url), ["/v1/health"]);
  } finally { await old.close(); }
  const down = await stub(() => ({ status: 503, json: {} }));
  try { assert.deepEqual(await health(down.url), { ok: false, why: "http_503" }); assert.equal(down.calls.length, 1); } finally { await down.close(); }
});

test("Every evaluate attempt carries an Idempotency-Key: a check, a schema_guidance call, a get_result read", async () => {
  const advice = { goal: "explain", status: "done", session: "ps_abcdefghijklmnopqrstuv", content: "## Practice\nText.",
    is_fetch_only: false, charged_units: 10, next_step: "Show it.", notice: "", correlation_id: "corr_12345678" };
  const s = await stub((call) => ({ status: 200, json: call.body.goal === "explain" ? advice : EVALUATE_OK }));
  const configDir = join(temp("custosa-idem-"), "custosa");
  writeToken(TOKEN, { configDir, host: new URL(s.url).origin });
  try {
    const runCheck = wired(s.url, { configDir });
    await runCheck({ goal: "check" }, { roots: ["/p"] });
    await runCheck({ goal: "explain", practice_id: "audit-log" }, { roots: [] });
    await runCheck({ goal: "plan", entities: [{ name: "patients", columns: [{ name: "dob" }] }] }, { roots: [] });
    await runCheck({ goal: "check", session: EVALUATE_OK.session, select: { state: "fail" } }, { roots: [] });
    assert.equal(s.calls.length, 4);
    assert.ok(s.calls.every((c) => c.url === "/v1/evaluate" && UUID.test(c.headers["idempotency-key"])), JSON.stringify(s.calls.map((c) => c.headers["idempotency-key"])));
    assert.equal(new Set(s.calls.map((c) => c.headers["idempotency-key"])).size, 4, "a fresh key per call");
  } finally { await s.close(); }
});

function doctorHome() {
  const home = temp("custosa-doctor-home-");
  const configDir = join(home, ".config", "custosa");
  mkdirSync(configDir, { recursive: true, mode: 0o700 });
  return { home, configDir };
}

test("OP2: custosa doctor passes, warns and fails locally, exits 1 on a fail, and prints no secrets", async () => {
  const s = await stub((call) => (call.url === HEALTH_PATH ? { status: 200, json: { status: "ok" } } : { status: 404, json: {} }));
  try {
    const { home, configDir } = doctorHome();
    const env = { HOME: home, CUSTOSA_CONFIG_DIR: configDir, CUSTOSA_EVALUATOR_URL: s.url, PGSERVICEFILE: join(home, ".pg_service.conf"), PGPASSFILE: join(home, ".pgpass"),
      npm_config_cache: join(home, ".npm"), PATH: "/nonexistent" };
    // not signed in: a fail, exit 1
    let res = await bin(["doctor"], env);
    assert.equal(res.code, 1, res.stdout + res.stderr);
    assert.match(res.stdout, /^PASS  Node\.js/m);
    assert.match(res.stdout, /^FAIL  Sign-in: not signed in/m);
    assert.match(res.stdout, /^PASS  Evaluator: http:\/\/127\.0\.0\.1:\d+ \(from env\) answers its health check/m);
    assert.match(res.stdout, /^WARN  \[phisc\] entry: none/m);
    assert.match(res.stdout, /^WARN  Environment mark: not marked/m);
    assert.match(res.stdout, /^PASS  Platform token: none/m);
    assert.ok(s.calls.every((c) => c.method === "GET" && c.url === HEALTH_PATH && !c.headers.authorization));

    // signed in, a [phisc] entry with a password, a Supabase PAT: no fail, the secrets never printed
    writeToken(TOKEN, { configDir, host: new URL(s.url).origin });
    writeFileSync(join(home, ".pg_service.conf"), "[phisc]\nhost=127.0.0.1\nport=1\ndbname=app\nuser=phisc_ro\n");
    const password = "pw-v\x65ry-secret-123";
    writeFileSync(join(home, ".pgpass"), `127.0.0.1:1:app:phisc_ro:${password}\n`, { mode: 0o600 });
    const pat = `sbp_${"0123456789abcdef".repeat(2)}12345678`;
    writeFileSync(join(configDir, "platform.json"), JSON.stringify({ provider: "supabase", token: pat, project_ref: "abcdefghijklmnopqrst" }), { mode: 0o600 });
    res = await bin(["doctor"], env);
    assert.equal(res.code, 0, res.stdout + res.stderr);
    assert.match(res.stdout, /^PASS  Sign-in: a token is saved for http:\/\/127\.0\.0\.1:\d+, expires about \d{4}-\d{2}-\d{2}/m);
    assert.match(res.stdout, /^PASS  \[phisc\] entry: phisc_ro@127\.0\.0\.1:1\/app, sslmode prefer, password from/m);
    assert.match(res.stdout, /^WARN  Database preflight: couldn't connect/m);
    assert.match(res.stdout, /^WARN  Platform token: platform\.json holds a Supabase personal access token \(sbp_\)/m);
    for (const secret of [TOKEN, password, pat]) assert.ok(!res.stdout.includes(secret) && !res.stderr.includes(secret), "no secret printed");

    // --offline: no request at all
    const before = s.calls.length;
    res = await bin(["doctor", "--offline"], env);
    assert.match(res.stdout, /^WARN  Evaluator: .* not contacted \(--offline\)/m);
    assert.equal(s.calls.length, before);
  } finally { await s.close(); }
});

test("OP2: doctor fails an old Node.js, an expired sign-in and a preflight that finds write access", async () => {
  const { home, configDir } = doctorHome();
  writeToken(TOKEN, { configDir, host: "http://127.0.0.1:9" });
  writeFileSync(join(home, ".pg_service.conf"), "[phisc]\nhost=127.0.0.1\nport=1\ndbname=app\nuser=phisc_ro\npassword=x\n");
  const lines = [];
  const code = await runDoctor({ env: { CUSTOSA_CONFIG_DIR: configDir, CUSTOSA_EVALUATOR_URL: "http://127.0.0.1:9", PGSERVICEFILE: join(home, ".pg_service.conf"), npm_config_cache: join(home, ".npm") },
    home, out: (l) => lines.push(l), offline: true, nodeVersion: "18.20.0", now: () => Date.now() + 100 * 86_400_000,
    which: () => null, run: () => ({ status: 1, stdout: "" }),
    preflight: async () => ({ status: "failed", reason: "preflight_failed", message: "write_privileges: write_schemas" }) });
  const text = lines.join("\n");
  assert.equal(code, 1);
  assert.match(text, /^FAIL  Node\.js: 18\.20\.0; the inspector needs Node\.js 20\.3 or later/m);
  assert.match(text, /^FAIL  Sign-in: .*it has likely expired/m);
  assert.match(text, /^FAIL  Database preflight: phisc_ro has more access than the inspector accepts \(write_privileges: write_schemas\)/m);
  assert.ok(!text.includes(TOKEN));
});

test("OP2: npx cache versions are read from the cache's custosa installs", () => {
  const cache = temp("custosa-npx-");
  for (const [dir, v] of [["a1", "0.1.0"], ["b2", "0.1.1"]]) {
    mkdirSync(join(cache, "_npx", dir, "node_modules", "custosa"), { recursive: true });
    writeFileSync(join(cache, "_npx", dir, "node_modules", "custosa", "package.json"), JSON.stringify({ name: "custosa", version: v }));
  }
  mkdirSync(join(cache, "_npx", "c3"), { recursive: true });
  assert.deepEqual(npxVersions(cache).map((x) => x.version).sort(), ["0.1.0", "0.1.1"]);
});

test("OP3: engines, the runtime check and doctor all say Node.js 20.3", () => {
  const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  assert.equal(pkg.engines.node, ">=20.3");
  const shrink = JSON.parse(readFileSync(new URL("../npm-shrinkwrap.json", import.meta.url), "utf8"));
  assert.equal(shrink.packages[""].engines.node, ">=20.3");
  const src = readFileSync(BIN, "utf8");
  assert.match(src, /custosa needs Node\.js \$\{MIN_NODE\.join\("\."\)\} or later/);
  // bin and doctor read the one copy in lib/version.mjs, which uses only node:fs
  assert.match(src, /^import \{ MIN_NODE, nodeSupported \} from "\.\.\/lib\/version\.mjs";/m);
  assert.deepEqual([...MIN_NODE], [20, 3]);
  assert.deepEqual(["20.2.9", "20.3.0", "21.0.0", "19.9.0"].map(nodeSupported), [false, true, true, false]);
  assert.deepEqual(readFileSync(new URL("../lib/version.mjs", import.meta.url), "utf8").match(/^import .*$/gm),
    ['import { readFileSync } from "node:fs";']);
});

test("CC1: the client command pins this version; Codex tables get startup and tool timeouts", () => {
  assert.deepEqual([...INSPECT], ["npx", "-y", `custosa@${VERSION}`, "inspect", "--stdio"]);
  const added = codexAdd("", "phisc", "npx", INSPECT.slice(1));
  assert.match(added, /startup_timeout_sec = 60\ntool_timeout_sec = 300\n$/);
  assert.equal(codexServer(added, "phisc").command, "npx");
  // codex mcp add writes only command and args: the timeouts are added after, and a person's own value is kept
  const written = `[mcp_servers.phisc]\ncommand = "npx"\nargs = ["-y", "custosa@${VERSION}", "inspect", "--stdio"]\n\n[other]\nx = 1\n`;
  const ensured = codexEnsureTimeouts(written, "phisc");
  assert.match(ensured, /args = \[.*\]\nstartup_timeout_sec = 60\ntool_timeout_sec = 300\n\n\[other\]/);
  assert.equal(codexEnsureTimeouts(ensured, "phisc"), ensured);
  const own = codexEnsureTimeouts(written.replace("\n\n[other]", "\ntool_timeout_sec = 900\n\n[other]"), "phisc");
  assert.match(own, /tool_timeout_sec = 900/);
  assert.ok(!/tool_timeout_sec = 300/.test(own));
  const updated = codexSetCommand(`[mcp_servers.phisc]\ncommand = "old"\ntool_timeout_sec = 120\n`, "phisc", "npx", INSPECT.slice(1));
  assert.match(updated, /startup_timeout_sec = 60\ntool_timeout_sec = 120/);
  assert.equal(CODEX_TIMEOUTS.tool_timeout_sec, 300);
});

test("LI7: a Supabase personal access token in platform.json gets a local warning; the token is never in it", () => {
  const pat = `sbp_${"a".repeat(40)}`;
  assert.deepEqual(platformTokenNotes({ provider: "supabase", token: pat, project_ref: "abcdefghijklmnopqrst" }), [SUPABASE_PAT_NOTE]);
  assert.deepEqual(platformTokenNotes({ provider: "supabase", token: "other-token-form-1234", project_ref: "abcdefghijklmnopqrst" }), []);
  assert.deepEqual(platformTokenNotes({ provider: "rds", access_key_id: "A\x4bIAABCDEFGHIJKLMNOP" }), []);
  assert.ok(!SUPABASE_PAT_NOTE.includes(pat));
});

test("M2: doctor checks the minor version too; 20.2 fails, 20.3 passes", async () => {
  for (const [v, level] of [["20.2.0", "FAIL"], ["20.3.0", "PASS"], ["22.0.0", "PASS"]]) {
    const lines = [];
    await runDoctor({ env: { CUSTOSA_CONFIG_DIR: join(temp("custosa-doc-"), "c"), CUSTOSA_EVALUATOR_URL: "http://127.0.0.1:9", PGSERVICEFILE: "/nonexistent" },
      home: temp("custosa-doc-home-"), out: (l) => lines.push(l), offline: true, nodeVersion: v, which: () => null, run: () => ({ status: 1, stdout: "" }) });
    assert.match(lines.join("\n"), new RegExp(`^${level}  Node\\.js: ${v.replaceAll(".", "\\.")}`, "m"));
  }
});

test("M2: a request that fails before it is sent is never 'connection lost'", async () => {
  assert.equal(notSent(new TypeError("Invalid header")), true, "fetch's own refusal to build a request");
  assert.equal(notSent(new TypeError("fetch failed", { cause: Object.assign(new Error("reset"), { code: "ECONNRESET" }) })), false);
  const throwing = () => { throw new TypeError("AbortSignal.any is not a function"); };
  for (const fetch of [throwing, async () => { throw new TypeError("Request cannot be constructed"); }]) {
    const out = await evaluate({ goal: "check", fact_document: {} }, { token: TOKEN, baseUrl: "http://127.0.0.1:9", fetch });
    assert.equal(out.body.error, "evaluator_unreachable", "nothing was sent, so nothing can have been charged");
  }
  // post marks a failure while building the request as not sent
  await assert.rejects(post("http://127.0.0.1:9", "/x", {}, { timeoutMs: -1 }), (err) => notSent(err));
});

test("M-B: an evaluation starts only with 90 s left; a sent request keeps its full timeout; a retry wait never leaves less", async () => {
  assert.equal(EVALUATE_DEADLINE_MS, 240_000);
  assert.equal(MIN_SEND_MS, 90_000);
  assert.ok(CALL_BUDGET_MS <= 300_000 - 5_000, "under Codex's 300 s tool timeout");
  // a fake clock, and a slow fake fetch that spends 20 s of it per request; AbortSignal.timeout is watched for the
  // timeout each request was given
  let clock = 0;
  const timeouts = [];
  const orig = AbortSignal.timeout;
  AbortSignal.timeout = (ms) => { timeouts.push(ms); return orig.call(AbortSignal, 60_000); };
  const refusal = { error: "unavailable", next_step: "Wait.", correlation_id: "corr_12345678", retry_after_seconds: 5 };
  let calls = 0;
  const fetch = async () => { calls++; await new Promise((ok) => setTimeout(ok, 50)); clock += 20_000;
    return new Response(JSON.stringify(refusal), { status: 503, headers: { "content-type": "application/json" } }); };
  const body = { goal: "check", fact_document: {} };
  try {
    // 91 s left: starts, with the whole 150 s timeout (never cut to what is left)
    let out = await evaluate(body, { token: TOKEN, baseUrl: "http://e.test", fetch, now: () => clock, deadline: clock + 91_000, sleep: async () => {} });
    assert.equal(calls, 1);
    assert.deepEqual(timeouts, [EVALUATOR_TIMEOUT_MS]);
    assert.equal(out.body.error, "unavailable", "after 20 s, 71 s are left: no retry wait that would leave under 90 s");
    // 89 s left: never starts
    calls = 0; clock = 0;
    out = await evaluate(body, { token: TOKEN, baseUrl: "http://e.test", fetch, now: () => clock, deadline: 89_000 });
    assert.equal(out.body.error, "time_budget");
    assert.equal(calls, 0);
    // plenty left: the retry runs (a 5 s wait, then a second attempt with the same full timeout)
    calls = 0; clock = 0; timeouts.length = 0;
    out = await evaluate(body, { token: TOKEN, baseUrl: "http://e.test", fetch, now: () => clock, deadline: 200_000, retries: 1, sleep: async (ms) => { clock += ms; } });
    assert.equal(calls, 2);
    assert.deepEqual(timeouts, [EVALUATOR_TIMEOUT_MS, EVALUATOR_TIMEOUT_MS]);
    // a get_result read (never charged) needs only a second
    calls = 0; clock = 0;
    await evaluate({ goal: "check", session: "ps_abcdefghijklmnopqrstuv", select: { state: "fail" } }, { token: TOKEN, baseUrl: "http://e.test", fetch, now: () => clock, deadline: 5_000, retries: 0 });
    assert.equal(calls, 1);
  } finally { AbortSignal.timeout = orig; }
});

test("L3: a cancel during a retry wait ends it at once and leaves no timer behind", async () => {
  const s = await stub(() => ({ status: 503, json: { error: "unavailable", next_step: "Wait.", correlation_id: "corr_12345678", retry_after_seconds: 20 } }));
  try {
    const timers = () => process.getActiveResourcesInfo().filter((r) => r === "Timeout").length;
    const before = timers();
    const c = new AbortController();
    setTimeout(() => c.abort(), 300);
    const t0 = Date.now();
    await assert.rejects(evaluate({ goal: "check", fact_document: {} }, { token: TOKEN, baseUrl: s.url, signal: c.signal }), { name: "AbortError" });
    assert.ok(Date.now() - t0 < 3000);
    await new Promise((ok) => setImmediate(ok));
    assert.ok(timers() <= before, `timers: ${before} before, ${timers()} after`);
  } finally { await s.close(); }
});

/* A runCheck wired to a real evaluate against a local server, with a fake build: documents for `n` roots. */
function wired(url, { n = 1, configDir, extra = {} } = {}) {
  const docs = Array.from({ length: n }, (_, i) => ({ project: i, label: "", nested: false, other: i > 0, skipped: false, root_id: `${i}`.repeat(64).slice(0, 64), document: { session: null, n: i } }));
  return makeRunCheck({ configDir, localOnly: false, evaluatorUrl: () => ({ url, origin: new URL(url).origin }),
    build: async () => ({ documents: docs, notes: [] }), environmentFor: () => ({ environment: { value: "unknown", source: "setup" }, note: null }), ...extra });
}

test("H1: a cancel after send keeps the request; a repeat always collects anew and reuses the key only for the very same body", async () => {
  const calls = [];
  let aborted = 0;
  const server = createServer((req, res) => {
    let raw = ""; req.on("data", (d) => { raw += d; });
    req.on("end", () => {
      calls.push({ body: JSON.parse(raw), key: req.headers["idempotency-key"] });
      res.on("close", () => { if (!res.writableEnded) aborted++; });
      setTimeout(() => { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify(EVALUATE_OK)); }, 400);
    });
  });
  await new Promise((ok) => server.listen(0, "127.0.0.1", ok));
  const url = `http://127.0.0.1:${server.address().port}`;
  const configDir = join(temp("custosa-h1-"), "custosa");
  writeToken(TOKEN, { configDir, host: new URL(url).origin });
  let facts = "rls_on", builds = 0;
  const runCheck = makeRunCheck({ configDir, localOnly: false, evaluatorUrl: () => ({ url, origin: new URL(url).origin }),
    environmentFor: () => ({ environment: { value: "unknown", source: "setup" }, note: null }),
    build: async () => { builds++; return { documents: [{ project: 0, label: "", nested: false, other: false, skipped: false, root_id: "0".repeat(64), document: { session: null, facts } }], notes: [] }; } });
  const waitCalls = (n) => new Promise((ok) => { const t = setInterval(() => { if (calls.length >= n) { clearInterval(t); ok(); } }, 10); });
  try {
    // 1. cancelled after send: not cut off
    const c = new AbortController();
    const first = runCheck({ goal: "verify" }, { roots: ["/p"], signal: c.signal });
    await waitCalls(1); c.abort();
    await assert.rejects(first, { name: "AbortError" });
    assert.equal(aborted, 0, "the request in flight was not cut off");
    // 2. same call, same project: collected again, the same body re-sent with the kept key (the evaluator answers once)
    await runCheck({ goal: "verify" }, { roots: ["/p"] });
    assert.equal(builds, 2, "a repeat always collects anew");
    assert.equal(calls.length, 2);
    assert.equal(calls[1].key, calls[0].key, "the very same body: its kept Idempotency-Key");
    // 3. cancelled again, then the project changes: a new body, a new key, and only a session note for the kept one
    const c2 = new AbortController();
    const third = runCheck({ goal: "verify" }, { roots: ["/p"], signal: c2.signal });
    await waitCalls(3); c2.abort();
    await assert.rejects(third, { name: "AbortError" });
    await new Promise((ok) => setTimeout(ok, 500)); // it finishes in the background
    facts = "rls_off";
    const changed = await runCheck({ goal: "verify" }, { roots: ["/p"] });
    assert.equal(calls.length, 4);
    assert.equal(calls[3].body.fact_document.facts, "rls_off", "never an answer built from old facts");
    assert.notEqual(calls[3].key, calls[2].key, "a different body never reuses a key (no idempotency_mismatch)");
    // the stub answers every call with the same session, so the evaluator now holds the newer answer for it: the note
    // says so, and never offers get_result for the old one
    assert.ok(changed.local_notes.some((n) => n.includes(`session ${EVALUATE_OK.session}, the same session as this answer`) && !n.includes("get_result")), JSON.stringify(changed.local_notes));
    // the kept entry is gone once noted
    const after = await runCheck({ goal: "verify" }, { roots: ["/p"] });
    assert.ok(!(after.local_notes ?? []).length);
  } finally { server.closeAllConnections(); await new Promise((ok) => server.close(ok)); }
});

test("H1: concurrent cancelled calls keep their own entries; neither overwrites the other", async () => {
  const keys = [];
  const evaluate = async (body, options) => { keys.push([body.fact_document.n, options.idempotencyKey]); await new Promise((ok) => setTimeout(ok, 200)); return { ok: true, body: EVALUATE_OK }; };
  let n = 0;
  const runCheck = makeRunCheck({ localOnly: false, readToken: () => ({ token: TOKEN, host: "https://e.test" }), evaluatorUrl: () => ({ url: "https://e.test", origin: "https://e.test" }),
    environmentFor: () => ({ environment: { value: "unknown", source: "setup" }, note: null }), evaluate,
    build: async (roots) => ({ documents: [{ project: 0, label: "", nested: false, other: false, skipped: false, root_id: "0".repeat(64), document: { session: null, n: roots[0] } }], notes: [] }) });
  const a = new AbortController(), b = new AbortController();
  const pa = runCheck({ goal: "check" }, { roots: ["A"], signal: a.signal });
  const pb = runCheck({ goal: "check" }, { roots: ["B"], signal: b.signal });
  await new Promise((ok) => setTimeout(ok, 50)); a.abort(); b.abort();
  await assert.rejects(pa); await assert.rejects(pb);
  await runCheck({ goal: "check" }, { roots: ["A"] });
  await runCheck({ goal: "check" }, { roots: ["B"] });
  const byRoot = (r) => keys.filter(([x]) => x === r).map(([, k]) => k);
  assert.equal(byRoot("A")[0], byRoot("A")[1], "A's repeat reuses A's key");
  assert.equal(byRoot("B")[0], byRoot("B")[1], "B's repeat reuses B's key");
  assert.notEqual(byRoot("A")[0], byRoot("B")[0]);
  n++;
});

test("M3 + M4: several roots: a cancel stops new roots; a short budget stops them too, and the roots not sent are listed", async () => {
  const calls = [];
  const server = createServer((req, res) => {
    let raw = ""; req.on("data", (d) => { raw += d; });
    req.on("end", () => { calls.push(JSON.parse(raw)); setTimeout(() => { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify(EVALUATE_OK)); }, 300); });
  });
  await new Promise((ok) => server.listen(0, "127.0.0.1", ok));
  const url = `http://127.0.0.1:${server.address().port}`;
  const configDir = join(temp("custosa-m4-"), "custosa");
  writeToken(TOKEN, { configDir, host: new URL(url).origin });
  try {
    // cancel during the first root: the other two never start; the same call again collects anew and sends all three
    const runCheck = wired(url, { n: 3, configDir });
    const c = new AbortController();
    const first = runCheck({ goal: "check", include_other_roots: true }, { roots: ["/p"], signal: c.signal });
    await new Promise((ok) => { const t = setInterval(() => { if (calls.length) { clearInterval(t); ok(); } }, 10); });
    c.abort();
    await assert.rejects(first, { name: "AbortError" });
    await new Promise((ok) => setTimeout(ok, 500));
    assert.equal(calls.length, 1, "no new root started after the cancel");
    const full = await runCheck({ goal: "check", include_other_roots: true }, { roots: ["/p"] });
    assert.equal(full.results.length, 3);
    assert.equal(calls.length, 4);
    calls.length = 0;

    // the call's budget: each evaluation takes 140 s of a fake clock; the third root would start with too little left
    calls.length = 0;
    let clock = 0;
    const timed = wired(url, { n: 3, configDir, extra: { now: () => clock, clientOptions: { now: () => clock } } });
    const orig = globalThis.fetch;
    globalThis.fetch = async (...a) => { const r = await orig(...a); clock += 140_000; return r; };
    let out;
    try { out = await timed({ goal: "check", include_other_roots: true }, { roots: ["/p"] }); } finally { globalThis.fetch = orig; }
    assert.equal(calls.length, 2, JSON.stringify(out).slice(0, 300));
    assert.deepEqual(out.other_roots.not_sent_root_ids, ["2".repeat(64)]);
    // A root the budget didn't reach is not checked, never counted as checked or passed.
    assert.equal(out.other_roots.checked, 1);
    assert.equal(out.results.length, calls.length); // a result only for each root sent
    assert.ok(out.local_notes.some((n) => /1 further roots were collected but not sent, because the call's time budget would have run out/.test(n)));
  } finally { server.closeAllConnections(); await new Promise((ok) => server.close(ok)); }
});

test("A repeat that meets idempotency_running keeps the kept key for the next repeat; only a real answer ends it", async () => {
  const keys = [];
  let firstDone = false;
  const evaluate = async (body, o) => {
    keys.push(o.idempotencyKey);
    if (keys.length === 1) { await new Promise((ok) => setTimeout(ok, 400)); firstDone = true; return { ok: true, body: { ...EVALUATE_OK, session: `ps_${"b".repeat(22)}` } }; }
    if (!firstDone) return { ok: false, body: { error: "rate_limited", next_step: "Wait.", correlation_id: "corr_12345678", retry_after_seconds: 5 } }; // idempotency_running
    return { ok: true, body: { ...EVALUATE_OK, session: `ps_${"b".repeat(22)}` } };
  };
  const runCheck = makeRunCheck({ localOnly: false, readToken: () => ({ token: TOKEN, host: "https://e.test" }), evaluatorUrl: () => ({ url: "https://e.test", origin: "https://e.test" }),
    environmentFor: () => ({ environment: { value: "unknown", source: "setup" }, note: null }), evaluate,
    build: async () => ({ documents: [{ project: 0, label: "", nested: false, other: false, skipped: false, root_id: "0".repeat(64), document: { session: null, same: 1 } }], notes: [] }) });
  const c = new AbortController();
  const first = runCheck({ goal: "check" }, { roots: ["/p"], signal: c.signal });
  setTimeout(() => c.abort(), 50);
  const t0 = Date.now();
  await assert.rejects(first, { name: "AbortError" });
  assert.ok(Date.now() - t0 < 300, "the cancelled call ends at once; its request goes on in the background");
  const second = await runCheck({ goal: "check" }, { roots: ["/p"] }); // the first is still running there
  assert.equal(second.error, "rate_limited");
  await new Promise((ok) => setTimeout(ok, 500));
  await runCheck({ goal: "check" }, { roots: ["/p"] }); // now answered: the same key again, so charged once
  assert.deepEqual(keys.map((k) => k === keys[0]), [true, true, true]);
  await runCheck({ goal: "check" }, { roots: ["/p"] }); // the kept request was answered: a new call gets a new key
  assert.equal(keys[3] === keys[0], false);
});

test("Tilde shows ~ for the home folder and paths inside it only", () => {
  assert.equal(tilde("/home/u/.npm", "/home/u"), "~/.npm");
  assert.equal(tilde("/home/u", "/home/u"), "~");
  assert.equal(tilde("/home/u/x", "/home/u/"), "~/x");
  assert.equal(tilde("/home/u2/x", "/home/u"), "/home/u2/x");
  assert.equal(tilde("/srv/home/u/x", "/home/u"), "/srv/home/u/x");
  assert.equal(tilde("C:\\Users\\u\\x", "C:\\Users\\u"), "~\\x");
  assert.equal(tilde("/home/u/x", ""), "/home/u/x");
});

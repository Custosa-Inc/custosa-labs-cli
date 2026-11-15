/* Device sign-in paths inspector-login.test.mjs doesn't reach: a start call that fails (no evaluator, busy, or an
 * answer outside the schema), a poll that hiccups, a deadline that passes during a poll, and a save that fails after
 * approval. Each stops with its own message, sends nothing further and saves nothing. Local stub only. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, chmodSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { deviceLogin, readToken, writeToken } from "../lib/inspector/auth.mjs";
import { post } from "../lib/inspector/client.mjs";
import { stub } from "./stub-evaluator.mjs";

const TOKEN = `phisc_${"Z".repeat(43)}`;
const CODE = "devcode_ABCDEFGHIJKLMNOP";
const START = { device_code: CODE, user_code: "WDJB-MJHT", verification_uri: "https://auth.custosa.com/device",
  verification_uri_complete: "https://auth.custosa.com/device?code=WDJB-MJHT", expires_in: 600, interval: 5 };
const ERR = { next_step: "x", correlation_id: "corr_12345678" };
const temp = (prefix) => realpathSync(mkdtempSync(join(tmpdir(), prefix)));

/* start: the answer to /v1/device/start; polls: answers to /v1/device/poll in order. wrap(post) may replace the post. */
async function login(start, polls = [], { wrap = (p) => p, configDir = join(temp("t19-login-"), "custosa"), now = null } = {}) {
  const s = await stub((call) => (call.url === "/v1/device/start" ? start : polls.shift() ?? { status: 400, json: { error: "expired_token" } }));
  const lines = [], waits = [];
  const clock = { t: 0 };
  try {
    const code = await deviceLogin({
      baseUrl: s.url, configDir, out: (l) => lines.push(l), post: wrap((b, p, j) => post(b, p, j), clock),
      sleep: async (ms) => { waits.push(ms); clock.t += ms; }, now: now ? now(clock) : () => clock.t,
    });
    return { code, lines, waits, calls: s.calls, configDir };
  } finally { await s.close(); }
}

test("login: no evaluator at the address stops before anything is shown or saved", async () => {
  const gone = await stub(() => ({ status: 200, json: START }));
  await gone.close(); // nothing listens on that port now
  const lines = [];
  const configDir = join(temp("t19-login-"), "custosa");
  const code = await deviceLogin({ baseUrl: gone.url, configDir, out: (l) => lines.push(l), post: (b, p, j) => post(b, p, j), sleep: async () => {} });
  assert.equal(code, 1);
  assert.match(lines.at(-1), /couldn't start: the evaluator couldn't be reached/);
  assert.ok(!lines.join("\n").includes("WDJB-MJHT"));
  assert.deepEqual(readToken({ configDir }), { missing: true });
  // A start answer that isn't JSON reads the same way.
  const r = await login({ status: 200, raw: "<html>gateway</html>" });
  assert.equal(r.code, 1);
  assert.match(r.lines.at(-1), /couldn't be reached/);
  assert.equal(r.calls.length, 1);
});

test("login: a busy evaluator at start says to wait, and nothing is polled", async () => {
  for (const start of [
    { status: 429, json: { error: "rate_limited", ...ERR, retry_after_seconds: 30 } },
    { status: 503, json: { error: "unavailable", ...ERR, retry_after_seconds: 30 } },
  ]) {
    const r = await login(start);
    assert.equal(r.code, 1, JSON.stringify(start));
    assert.match(r.lines.at(-1), /isn't available right now/);
    assert.deepEqual(r.calls.map((c) => c.url), ["/v1/device/start"]);
    assert.deepEqual(readToken({ configDir: r.configDir }), { missing: true });
  }
});

test("login: a start answer outside the schema or its status is unreadable, and nothing is polled", async () => {
  const { device_code: _drop, ...noCode } = START;
  for (const start of [
    { status: 500, json: { error: "internal_error", ...ERR } },
    { status: 429, json: { error: "rate_limited" } }, // no next_step or correlation_id
    { status: 403, json: { error: "account_required", ...ERR } },
    { status: 200, json: { ...START, extra: 1 } },
    { status: 200, json: noCode },
    { status: 200, json: [START] },
    { status: 200, json: { error: "internal_error", ...ERR } }, // lawful as an error, but not a start answer
  ]) {
    const r = await login(start);
    assert.equal(r.code, 1, JSON.stringify(start));
    assert.match(r.lines.at(-1), /in a form this version can't read/);
    assert.deepEqual(r.calls.map((c) => c.url), ["/v1/device/start"]);
    assert.ok(!r.lines.join("\n").includes("WDJB-MJHT"), "no code is shown from an answer that wasn't read");
  }
});

test("login: a poll that fails on the network or answers no JSON is retried, then the approval is saved", async () => {
  let polls = 0;
  const wrap = (real) => async (b, p, j) => {
    if (p === "/v1/device/poll" && ++polls === 1) throw new TypeError("fetch failed");
    return real(b, p, j);
  };
  const r = await login({ status: 200, json: START }, [
    { status: 502, raw: "bad gateway" },
    { status: 200, json: { access_token: TOKEN, token_type: "Bearer" } },
  ], { wrap });
  assert.equal(r.code, 0, r.lines.join("\n"));
  assert.deepEqual(r.waits, [5000, 5000, 5000]);
  assert.equal(readToken({ configDir: r.configDir }).token, TOKEN);
});

test("login: a deadline that passes while a poll is out stops before the next wait", async () => {
  // The poll takes the rest of the code's life: the clock moves past expires_in during the call.
  const wrap = (real, clock) => async (b, p, j) => {
    const res = await real(b, p, j);
    if (p === "/v1/device/poll") clock.t += START.expires_in * 1000;
    return res;
  };
  const r = await login({ status: 200, json: START }, [{ status: 400, json: { error: "authorization_pending" } }], { wrap });
  assert.equal(r.code, 1);
  assert.match(r.lines.at(-1), /expired before it was approved/);
  assert.deepEqual(r.waits, [5000]);
  assert.equal(r.calls.filter((c) => c.url === "/v1/device/poll").length, 1);
});

test("login: an approved token that can't be saved says why, and the token is never printed", { skip: process.platform === "win32" }, async () => {
  const configDir = join(temp("t19-login-"), "custosa");
  mkdirSync(configDir, { mode: 0o700 });
  chmodSync(configDir, 0o777);
  const r = await login({ status: 200, json: START }, [{ status: 200, json: { access_token: TOKEN, token_type: "Bearer" } }], { configDir });
  assert.equal(r.code, 1);
  assert.match(r.lines.at(-1), /^Can't save the sign-in: the config folder is writable by other users/);
  assert.ok(!r.lines.join("\n").includes(TOKEN));
  assert.ok(!r.lines.join("\n").includes("Signed in."));
  chmodSync(configDir, 0o700);
  assert.deepEqual(readToken({ configDir }), { missing: true });
});

test("writeToken: an old token file that can't be deleted stops the save before the host moves", () => {
  const dir = join(temp("t19-login-"), "cfg");
  writeToken("old-token-0123456789abcdef", { configDir: dir, host: "https://a.example.test" });
  rmSync(join(dir, "token"));
  mkdirSync(join(dir, "token")); // a folder: unlink refuses it (EPERM on macOS, EISDIR on Linux)
  writeFileSync(join(dir, "token", "keep"), "x");
  assert.throws(() => writeToken("new-token-0123456789abcdef", { configDir: dir, host: "https://b.example.test" }),
    /^Error: Can't save the sign-in: E[A-Z]+\.$/);
  assert.equal(readFileSync(join(dir, "token.host"), "utf8"), "https://a.example.test\n");
});

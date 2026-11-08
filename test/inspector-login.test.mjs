/* Device sign-in (/v1/device/start and /v1/device/poll) against a local stub:
 * pending, slow_down, approval, decline, expiry; the token stored 0600 and never printed; the device code sent only
 * to /v1/device/poll. No real service is contacted. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, realpathSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { deviceLogin, readToken } from "../lib/inspector/auth.mjs";
import { post } from "../lib/inspector/client.mjs";
import { stub } from "./stub-evaluator.mjs";

const TOKEN = `phisc_${"Z".repeat(43)}`;
const CODE = "devcode_ABCDEFGHIJKLMNOP";
const START = { device_code: CODE, user_code: "WDJB-MJHT", verification_uri: "https://auth.custosa.com/device",
  verification_uri_complete: "https://auth.custosa.com/device?code=WDJB-MJHT", expires_in: 600, interval: 5 };
const temp = (prefix) => realpathSync(mkdtempSync(join(tmpdir(), prefix)));

function evaluator(polls) {
  return stub((call) => {
    if (call.url === "/v1/device/start") return { status: 200, json: START };
    if (call.url === "/v1/device/poll") return polls.shift() ?? { status: 400, json: { error: "expired_token" } };
    return { status: 404, json: { error: "page_missing", next_step: "x", correlation_id: "corr_12345678" } };
  });
}

async function login(polls, extra = {}) {
  const s = await evaluator(polls);
  const configDir = join(temp("a7-login-"), "custosa");
  const lines = [], waits = [];
  let clock = 0;
  try {
    const code = await deviceLogin({
      baseUrl: s.url, configDir, out: (l) => lines.push(l), post: (b, p, j) => post(b, p, j),
      sleep: async (ms) => { waits.push(ms); clock += ms; }, now: () => clock, ...extra,
    });
    return { code, lines, waits, calls: s.calls, configDir, origin: new URL(s.url).origin };
  } finally { await s.close(); }
}

test("login: pending, slow_down, then approval; the token is stored 0600 and never printed", async () => {
  const r = await login([
    { status: 400, json: { error: "authorization_pending" } },
    { status: 400, json: { error: "slow_down" } },
    { status: 400, json: { error: "slow_down", interval: 15 } },
    { status: 200, json: { access_token: TOKEN, token_type: "Bearer" } },
  ]);
  assert.equal(r.code, 0);
  assert.deepEqual(r.waits, [5000, 5000, 10000, 15000]);
  assert.deepEqual(readToken({ configDir: r.configDir }), { token: TOKEN, host: r.origin });
  assert.ok(r.lines[0].includes(r.origin), "the evaluator host is printed before anything else");
  if (process.platform !== "win32") assert.equal(statSync(join(r.configDir, "token")).mode & 0o777, 0o600);
  const text = r.lines.join("\n");
  assert.ok(text.includes("WDJB-MJHT") && text.includes("https://auth.custosa.com/device"));
  assert.ok(!text.includes(TOKEN) && !text.includes(CODE));
  assert.ok(text.includes("PHI Schema Check, a Custosa Labs project"));
  assert.ok(!/—/.test(text));
  // The device code went to /v1/device/poll only; start sent {} and no credential.
  assert.deepEqual(r.calls[0].body, {});
  assert.equal(r.calls[0].headers.authorization, undefined);
  for (const c of r.calls.slice(1)) { assert.equal(c.url, "/v1/device/poll"); assert.deepEqual(c.body, { device_code: CODE }); assert.equal(c.headers.authorization, undefined); }
});

test("login: declined, expired, an unknown code and an unreadable answer save nothing", async () => {
  for (const [poll, words] of [
    [{ status: 400, json: { error: "access_denied" } }, "declined"],
    [{ status: 400, json: { error: "expired_token" } }, "expired"],
    [{ status: 400, json: { error: "invalid_device_code" } }, "recognise"],
    [{ status: 200, json: { access_token: TOKEN, token_type: "Basic" } }, "can't read"],
    [{ status: 200, json: { access_token: "x", token_type: "Bearer" } }, "can't read"],
  ]) {
    const r = await login([poll]);
    assert.equal(r.code, 1, words);
    assert.ok(r.lines.at(-1).includes(words), r.lines.at(-1));
    assert.deepEqual(readToken({ configDir: r.configDir }), { missing: true });
  }
  // Still pending at the deadline: stops, nothing saved.
  const pending = Array.from({ length: 200 }, () => ({ status: 400, json: { error: "authorization_pending" } }));
  const r = await login(pending);
  assert.equal(r.code, 1);
  assert.ok(r.lines.at(-1).includes("expired"));
});

test("custosa login end to end against the stub: prints the code, never the token", async () => {
  const s = await stub((call) => (call.url === "/v1/device/start" ? { status: 200, json: { ...START, interval: 1 } }
    : { status: 200, json: { access_token: TOKEN, token_type: "Bearer" } }));
  const configDir = temp("a7-login-bin-");
  try {
    const bin = fileURLToPath(new URL("../bin/custosa.mjs", import.meta.url));
    const res = await new Promise((ok) => {
      // spawnSync would block the stub's event loop; run it async.
      import("node:child_process").then(({ execFile }) => execFile(process.execPath, [bin, "login"], {
        env: { ...process.env, CUSTOSA_EVALUATOR_URL: s.url, CUSTOSA_CONFIG_DIR: configDir }, timeout: 20_000,
      }, (error, stdout, stderr) => ok({ error, stdout, stderr })));
    });
    assert.equal(res.error, null, res.stderr);
    assert.ok(res.stdout.includes("WDJB-MJHT"));
    assert.ok(!res.stdout.includes(TOKEN) && !res.stderr.includes(TOKEN));
    assert.equal(readFileSync(join(configDir, "token"), "utf8").trim(), TOKEN);
    const out = spawnSync(process.execPath, [bin, "logout"], { env: { ...process.env, CUSTOSA_CONFIG_DIR: configDir }, encoding: "utf8" });
    assert.equal(out.status, 0);
    assert.deepEqual(readToken({ configDir }), { missing: true });
  } finally { await s.close(); }
});

test("login: a non-default address needs the person's yes before anything is sent", async () => {
  const r = await login([{ status: 200, json: { access_token: TOKEN, token_type: "Bearer" } }], { confirm: async () => false });
  assert.equal(r.code, 1);
  assert.equal(r.calls.length, 0);
  assert.deepEqual(readToken({ configDir: r.configDir }), { missing: true });
  const ok = await login([{ status: 200, json: { access_token: TOKEN, token_type: "Bearer" } }], { confirm: async () => true });
  assert.equal(ok.code, 0);
});

test("login: answers outside the schema or their HTTP status stop the sign-in; waits are clamped (review items 6, 7)", async () => {
  const stops = [
    { status: 400, json: { error: "slow_down", interval: 1e12 } },
    { status: 500, json: { error: "slow_down", interval: 3 } },
    { status: 429, json: { error: "rate_limited", next_step: "x", correlation_id: "corr_12345678", retry_after_seconds: 1e12 } },
    { status: 400, json: { error: "made_up" } },
    { status: 200, json: { access_token: TOKEN, token_type: "Bearer", extra: 1 } },
  ];
  for (const poll of stops) {
    const r = await login([poll]);
    assert.equal(r.code, 1, JSON.stringify(poll));
    assert.match(r.lines.at(-1), /can't read/);
    assert.deepEqual(readToken({ configDir: r.configDir }), { missing: true });
  }
  // A long retry_after is clamped to 60 seconds, and the total wait never passes expires_in.
  const busy = Array.from({ length: 50 }, () => ({ status: 503, json: { error: "unavailable", next_step: "x", correlation_id: "corr_12345678", retry_after_seconds: 3600 } }));
  const r = await login(busy);
  assert.equal(r.code, 1);
  assert.ok(r.waits.every((w) => w <= 60_000), JSON.stringify(r.waits));
  assert.ok(r.waits.reduce((a, b) => a + b, 0) <= START.expires_in * 1000);
});

test("login: the verification address must be https on the evaluator's host or custosa.com, with no control characters", async () => {
  for (const uri of ["https://x\u001b[2J\u001b]0;pwned\u0007\nFAKE", "http://auth.custosa.com/device", "https://evil.example.test/device",
    "https://custosa.com.evil.example/device", "https://auth.custosa.com/dev‮ice", "https://u:p@auth.custosa.com/"]) {
    const s = await stub((call) => (call.url === "/v1/device/start" ? { status: 200, json: { ...START, verification_uri: uri } } : { status: 200, json: { access_token: TOKEN, token_type: "Bearer" } }));
    const lines = [];
    try {
      const code = await deviceLogin({ baseUrl: s.url, configDir: join(temp("a7-login-"), "c"), out: (l) => lines.push(l), post: (b, p, j) => post(b, p, j), sleep: async () => {} });
      assert.equal(code, 3, JSON.stringify(uri)); // sign-in isn't available yet
      assert.ok(!lines.join("\n").includes(uri), "the refused address is never printed");
      assert.equal(s.calls.filter((c) => c.url === "/v1/device/poll").length, 0);
    } finally { await s.close(); }
  }
});

test("login: the sign-in page refusal says what to do; the account's sign-in limit gets its own message (merge review 3)", async () => {
  const { ALLOWED_VERIFICATION_HOSTS, verificationAddressOk } = await import("../lib/inspector/auth.mjs");
  assert.deepEqual([...ALLOWED_VERIFICATION_HOSTS], []);
  assert.equal(verificationAddressOk("https://x.authkit.app/device", "https://evaluator.custosa.com"), false); // no wildcard
  const s = await stub((call) => (call.url === "/v1/device/start" ? { status: 200, json: { ...START, verification_uri: "https://x.authkit.app/device" } } : { status: 400, json: { error: "authorization_pending" } }));
  const lines = [];
  try {
    const code = await deviceLogin({ baseUrl: s.url, configDir: join(temp("a7-login-"), "c"), out: (l) => lines.push(l), post: (b, p, j) => post(b, p, j), sleep: async () => {} });
    assert.equal(code, 3);
    assert.match(lines.at(-1), /isn't on this inspector's list of sign-in pages/);
    assert.match(lines.at(-1), /contact hello@custosa\.com/);
  } finally { await s.close(); }
  const r = await login([{ status: 403, json: { error: "account_required", next_step: "x", correlation_id: "corr_12345678" } }]);
  assert.equal(r.code, 1);
  assert.match(r.lines.at(-1), /limit of signed-in computers/);
  assert.ok(!/custosa@latest login/.test(r.lines.at(-1)));
});

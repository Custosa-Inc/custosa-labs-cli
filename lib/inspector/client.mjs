/* The evaluator client: POST /v1/evaluate and the device sign-in endpoints, per evaluator_api.md v2.1
 * (the evaluator's app/core/api.py). Node's built-in fetch only; the one place the inspector talks to the network for
 * the evaluator.
 *
 * evaluatorUrl({env, configDir}) -> {url} | {problem}
 *   CUSTOSA_EVALUATOR_URL, else "url" in <config dir>/evaluator.json, else DEFAULT_EVALUATOR_URL. https only, except
 *   plain http to this machine (localhost, 127.0.0.1, ::1) for a local evaluator or a test stub.
 * evaluate(body, {token, baseUrl, ...}) -> {ok: true, body} | {ok: false, body}
 *   body is the request envelope (section 1.1). Nothing is sent without a token. The answer is checked against
 *   response.schema.json: a 200 must be an evaluate_response, anything else an error_response whose code matches its
 *   HTTP status; any other answer is reported locally as evaluator_response_invalid, never passed on as a result.
 *   Retries: only refusals the contract says are never charged and carry retry_after_seconds (rate_limited,
 *   balance_reserved, unavailable), at most `retries` times and only when the wait is at most maxWaitSeconds. A
 *   network failure is retried only for a fetch-only body (get_result), since an evaluation that reached the
 *   evaluator may have been charged. Redirects are never followed (the bearer token stays with the configured host).
 *   Every evaluate() call carries an Idempotency-Key header: a fresh random UUID per call, the same on each retry of
 *   that call, so the evaluator can tell a retry from a new evaluation.
 *   options.signal (an AbortSignal): cancels the call in flight and any retry wait; the abort error is thrown.
 * post(path, json, opts) -> {status, body}   the raw call, used by the device sign-in.
 * revokeToken({token, baseUrl}) -> {revoked: true} | {revoked: false, why}   POST REVOKE_PATH with the bearer token.
 * health(baseUrl) -> {ok: true} | {ok: false, why}   GET HEALTH_PATH, unauthenticated (custosa doctor).
 *
 * Local answers (the call wasn't made, or its answer couldn't be read) have the error_response shape without a
 * correlation_id and with local: true. Nothing here prints or logs; the token is never in a result or an error. */
import { randomUUID } from "node:crypto";
import { lstatSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { configDirFor } from "./secrets.mjs";
import { validateResponse } from "./schema.mjs";
import { VERSION } from "../version.mjs";

/* The production address is an owner step (evaluator_api.md: "production value is an owner step"). */
export const DEFAULT_EVALUATOR_URL = "https://evaluator.custosa.com";
export const MAX_BODY_BYTES = 5_065_536 + 1_048_576;   // contract 2.3: the committed block's 1 MiB (section 3.4)
export const MAX_RESPONSE_BYTES = 8_000_000;
/* How long one HTTP request to the evaluator may take: at least Cloud Run's 150 s request timeout, so the
 * inspector never gives up on an answer Cloud Run would still deliver. The evaluator's own budget stays 60 s. */
export const EVALUATOR_TIMEOUT_MS = 150_000;
/* One evaluate() call's whole time, retries and their waits included (M4): 55 s of collection plus this fits under
 * Codex's 300 s tool timeout. Past it no new attempt starts and no retry wait begins. */
export const EVALUATE_DEADLINE_MS = 240_000;
/* M-B: the time an evaluation needs left before it starts: the evaluator's 60 s budget plus a 30 s margin. */
export const MIN_SEND_MS = 90_000;
/* Revokes the bearer token it is called with (custosa logout). An older
 * evaluator answers 404. */
export const REVOKE_PATH = "/v1/token/revoke";
/* The evaluator's liveness probe: unauthenticated, answers {"status": "ok"}. */
export const HEALTH_PATH = "/v1/health";
export const IDEMPOTENCY_HEADER = "Idempotency-Key";
export const ERROR_STATUS = Object.freeze({ invalid_fact_document: 400, too_large: 413, update_inspector: 409,
  sign_in_required: 401, token_expired: 401, account_required: 403, insufficient_balance: 402, balance_reserved: 409,
  rate_limited: 429, result_missing: 404, session_unknown: 404, unavailable: 503, internal_error: 500 });
const RETRYABLE = new Set(["rate_limited", "balance_reserved", "unavailable"]);
const SETUP = "npx custosa@latest setup";
const LOGIN = "npx custosa login";

export const LOCAL = Object.freeze({
  sign_in_required: `PHI Schema Check isn't signed in on this computer, so nothing was sent and nothing was charged. Ask the user to run ${LOGIN} in a terminal, then make the same call again.`,
  sign_in_unreadable: `PHI Schema Check's saved sign-in can't be used ({why}), so nothing was sent. Ask the user to run ${LOGIN} in a terminal, then make the same call again.`,
  evaluator_config_insecure: "The inspector's evaluator.json can't be trusted (a symlink, writable by other users, or owned by another user), so nothing was sent. Ask the user to fix its permissions (chmod 600 on it, chmod 700 on its folder) or remove it.",
  sign_in_other_host: `The saved sign-in was made for a different evaluator address than the one now configured, so nothing was sent. Ask the user to run ${LOGIN} again if the new address is intended.`,
  evaluator_url_invalid: "The evaluator address in CUSTOSA_EVALUATOR_URL or evaluator.json isn't one the inspector accepts (https, or http to this computer only), so nothing was sent. Ask the user to fix or remove it.",
  evaluator_unreachable: "The inspector couldn't reach the PHI Schema Check evaluator, so the check didn't run. Ask the user to check the connection, then make the same call again.",
  evaluator_connection_lost: "The connection to the evaluator dropped after the facts were sent, so the check may have run and may have been charged. Don't run it again until the user has checked their usage on their account page; then make the same call again if it didn't run.",
  evaluator_response_incomplete: "The evaluator's answer was cut off before it was complete, so nothing was shown as a result. The check may have run and may have been charged: don't run it again until the user has checked their usage on their account page.",
  evaluator_response_invalid: `The evaluator answered in a form this inspector can't read. Nothing was shown as a result. Ask the user to run ${SETUP} to update the inspector, then make the same call again.`,
  time_budget: "The call ran out of time before the facts could be sent (or sent again), so nothing more was sent. Make the same call again; if it keeps happening, ask the user to open the assistant on a narrower folder.",
  too_large: `This project's facts are larger than one call takes, so nothing was sent and nothing was charged. Ask the user to run ${SETUP} to update the inspector, then make the same call again.`,
});
// an evaluation's answer this inspector can't read may still have been charged (a 200 too large or outside
// the schema), so the words never invite the same call, which would get a new Idempotency-Key and be charged again.
export const RESPONSE_INVALID_AFTER_SEND = `The evaluator answered in a form this inspector can't read, so nothing was shown as a result. The check may have run and may have been charged: don't run it again until the user has checked their usage on their account page. Ask the user to run ${SETUP} to update the inspector.`;
export const localError = (error, extra = {}, words = null) => ({ error, next_step: words ?? LOCAL[error], local: true, ...extra });

const userAgent = (inspectorVersion) => `custosa-inspector/${inspectorVersion}`;

const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);

/* evaluator.json gets the token file's safeguards: a regular file (not a symlink) in a folder only this user can
 * write, itself writable by nobody else, owned by this user. Anything else is refused, not ignored. */
function readEvaluatorFile(dir) {
  const path = join(dir, "evaluator.json");
  let st;
  try { st = lstatSync(path); } catch (err) { return err.code === "ENOENT" ? { missing: true } : { problem: "evaluator_config_insecure" }; }
  if (st.isSymbolicLink() || !st.isFile() || st.size > 4096) return { problem: "evaluator_config_insecure" };
  if (process.platform !== "win32") {
    const mine = (x) => typeof process.getuid !== "function" || x.uid === process.getuid();
    let dst;
    try { dst = statSync(dir); } catch { return { problem: "evaluator_config_insecure" }; }
    if ((st.mode & 0o022) || !mine(st) || (dst.mode & 0o022) || !mine(dst)) return { problem: "evaluator_config_insecure" };
  }
  try {
    const cfg = JSON.parse(readFileSync(path, "utf8"));
    return cfg && typeof cfg.url === "string" ? { url: cfg.url } : { problem: "evaluator_url_invalid" };
  } catch { return { problem: "evaluator_url_invalid" }; }
}

/* Whether a sign-in saved for `host` (the origin custosa login recorded) is for the evaluator `where` (evaluatorUrl's
   answer; one without an origin is read from its url). The token goes only to the evaluator that issued it. */
export const issuedBy = (where, host) => (where.origin ?? new URL(where.url).origin) === host;

/* -> {url, origin, source: "env" | "file" | "default"} | {problem} */
export function evaluatorUrl({ env = process.env, configDir } = {}) {
  let raw = null, source = "default";
  if (env.CUSTOSA_EVALUATOR_URL) { raw = env.CUSTOSA_EVALUATOR_URL; source = "env"; }
  else {
    const file = readEvaluatorFile(configDirFor({ configDir }));
    if (file.problem) return { problem: file.problem };
    if (file.url) { raw = file.url; source = "file"; }
  }
  raw ??= DEFAULT_EVALUATOR_URL;
  let u;
  try { u = new URL(raw); } catch { return { problem: "evaluator_url_invalid" }; }
  const local = LOOPBACK.has(u.hostname);
  if (!(u.protocol === "https:" || (u.protocol === "http:" && local)) || u.username || u.password || u.search || u.hash) {
    return { problem: "evaluator_url_invalid" };
  }
  return { url: `${u.origin}${u.pathname.replace(/\/+$/, "")}`, origin: u.origin, source };
}

async function readCapped(res, max) {
  const reader = res.body?.getReader?.();
  if (!reader) return "";
  const chunks = [];
  let n = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    n += value.length;
    if (n > max) { await reader.cancel().catch(() => {}); throw new Error("response too large"); }
    chunks.push(value);
  }
  return Buffer.concat(chunks.map((c) => Buffer.from(c))).toString("utf8");
}

/* One call: {status, body (parsed JSON or undefined), retryAfter}. Throws only on a network failure or timeout. */
export async function post(baseUrl, path, json, { token = null, fetch = globalThis.fetch, timeoutMs = EVALUATOR_TIMEOUT_MS, inspectorVersion = VERSION,
  idempotencyKey = null, signal = null } = {}) {
  const headers = { "content-type": "application/json", "user-agent": userAgent(inspectorVersion), accept: "application/json" };
  if (token) headers.authorization = `Bearer ${token}`;
  if (idempotencyKey) headers[IDEMPOTENCY_HEADER] = idempotencyKey;
  let init;
  try {
    const timeout = AbortSignal.timeout(timeoutMs);
    init = { method: "POST", headers, body: JSON.stringify(json), redirect: "manual", signal: signal ? AbortSignal.any([timeout, signal]) : timeout };
  } catch (err) { throw markNotSent(err); } // failed while building the request: nothing left this computer
  const res = await fetch(`${baseUrl}${path}`, init);
  let text;
  try { text = await readCapped(res, MAX_RESPONSE_BYTES); } catch (err) {
    // Too large is an answer we won't read; a stream that broke off is an incomplete one.
    return { status: res.status, body: undefined, incomplete: err?.message !== "response too large" };
  }
  let body;
  try { body = JSON.parse(text); } catch { body = undefined; }
  return { status: res.status, body };
}

/* Network failures that happen before any byte of the request leaves: the call wasn't made. Anything else (a reset,
 * a socket closed, a timeout) may have come after the evaluator read the request. */
const NOT_SENT = new Set(["ECONNREFUSED", "ENOTFOUND", "EAI_AGAIN", "ENETUNREACH", "EHOSTUNREACH", "UND_ERR_CONNECT_TIMEOUT",
  "DEPTH_ZERO_SELF_SIGNED_CERT", "SELF_SIGNED_CERT_IN_CHAIN", "UNABLE_TO_VERIFY_LEAF_SIGNATURE", "CERT_HAS_EXPIRED",
  "ERR_TLS_CERT_ALTNAME_INVALID", "UNABLE_TO_GET_ISSUER_CERT_LOCALLY"]);
export function notSent(err) {
  if (err?.custosaNotSent === true) return true;
  // fetch rejects a request it can't build (a bad URL or header) with a TypeError that has no cause, before
  // connecting; a network failure is a TypeError ("fetch failed") whose cause says what happened.
  if (err instanceof TypeError && err.cause === undefined) return true;
  for (let e = err, k = 0; e && k < 5; e = e.cause, k++) if (NOT_SENT.has(e.code)) return true;
  return false;
}
const markNotSent = (err) => { try { Object.defineProperty(err, "custosaNotSent", { value: true }); } catch { /* frozen */ } return err; };

/* An answer from /v1/evaluate as the contract allows it, or null. */
export function checkEvaluateAnswer(status, body) {
  if (body === undefined || body === null || typeof body !== "object" || Array.isArray(body)) return null;
  if (validateResponse(body)) return null;
  // a 200 is an evaluation or advice answer (status), or a get_result answer (matched, T29 o2); the schema checked which
  if (status === 200) return typeof body.goal === "string" && (typeof body.status === "string" || Number.isInteger(body.matched)) ? { ok: true, body } : null;
  if (typeof body.error === "string" && ERROR_STATUS[body.error] === status) return { ok: false, body };
  return null;
}

const isFetchOnly = (body) => body && typeof body === "object" && "select" in body;   // get_result (T29 o2)
/* A wait that a signal ends early: the timer is cleared, so a cancelled wait keeps nothing alive (L3). */
const defaultSleep = (ms, signal = null) => new Promise((ok, fail) => {
  if (signal?.aborted) { fail(signal.reason); return; }
  const onAbort = () => { clearTimeout(timer); fail(signal.reason); };
  const timer = setTimeout(() => { signal?.removeEventListener("abort", onAbort); ok(); }, ms);
  signal?.addEventListener("abort", onAbort, { once: true });
});
/* A wait that ends early, with the abort error, when the signal fires. */
const abortable = (promise, signal) => (!signal ? promise : new Promise((ok, fail) => {
  if (signal.aborted) { fail(signal.reason); return; }
  const onAbort = () => fail(signal.reason);
  signal.addEventListener("abort", onAbort, { once: true });
  promise.then((v) => { signal.removeEventListener("abort", onAbort); ok(v); }, (e) => { signal.removeEventListener("abort", onAbort); fail(e); });
}));

/* Cancellation (options.signal): before an attempt starts, it stops evaluate with the abort error. An attempt that
 * has started is never aborted for an evaluation (check, fix, verify), since its bytes may have reached the evaluator
 * and it may be charged: it runs to its end and its answer is returned, and the caller decides what to keep (tool.mjs
 * keeps it for the next call). A get_result read, which is never charged, is aborted at once. Retry waits end
 * at once on a cancel.
 * Deadline: options.deadline (epoch ms) and EVALUATE_DEADLINE_MS from the start of the call, whichever comes first.
 * An evaluation attempt starts only with MIN_SEND_MS of it left (a get_result read with a second); no retry wait begins
 * that would leave less. A request already sent keeps its whole timeout (EVALUATOR_TIMEOUT_MS): the deadline never
 * cuts off a sent evaluation (M-B), so a request started near the end may finish after it. */
export async function evaluate(body, options = {}) {
  const { token, baseUrl, retries = 2, maxWaitSeconds = 30, sleep = defaultSleep, signal = null, now = Date.now,
    deadlineMs = EVALUATE_DEADLINE_MS, deadline: callDeadline = null, timeoutMs = EVALUATOR_TIMEOUT_MS } = options;
  if (!token) return { ok: false, body: localError("sign_in_required") };
  if (!baseUrl) return { ok: false, body: localError("evaluator_url_invalid") };
  if (Buffer.byteLength(JSON.stringify(body), "utf8") > MAX_BODY_BYTES) return { ok: false, body: localError("too_large") };
  const fetchOnly = isFetchOnly(body);
  let networkTries = fetchOnly ? 1 : 0;
  const end = Math.min(now() + deadlineMs, callDeadline ?? Infinity);
  // One key for this evaluate call, sent again on each of its retries; options.idempotencyKey reuses a key a
  // cancelled call already sent this same body with (tool.mjs), so the evaluator answers it once.
  const idempotencyKey = options.idempotencyKey ?? randomUUID();
  // M-B: an evaluation (or a retry of one) starts only with MIN_SEND_MS left, the evaluator's own 60 s budget and a
  // margin; once sent, a request keeps its full timeout and is never cut short by the deadline.
  const minLeft = fetchOnly ? 1000 : MIN_SEND_MS;
  for (let attempt = 0; ; attempt++) {
    signal?.throwIfAborted();
    if (end - now() < minLeft) return { ok: false, body: localError("time_budget") }; // this attempt never started
    let res;
    try {
      res = await post(baseUrl, "/v1/evaluate", body, { ...options, idempotencyKey, timeoutMs, signal: fetchOnly ? signal : null });
    } catch (err) {
      if (fetchOnly && signal?.aborted) throw signal.reason;
      if (networkTries-- > 0) continue;
      // An evaluation that may have reached the evaluator is never re-sent, and the assistant is told it may have run.
      return { ok: false, body: localError(notSent(err) || fetchOnly ? "evaluator_unreachable" : "evaluator_connection_lost") };
    }
    if (res.incomplete) {
      if (networkTries-- > 0) continue;
      return { ok: false, body: localError(fetchOnly ? "evaluator_response_invalid" : "evaluator_response_incomplete") };
    }
    const answer = checkEvaluateAnswer(res.status, res.body);
    if (!answer) return { ok: false, body: localError("evaluator_response_invalid", {}, fetchOnly ? null : RESPONSE_INVALID_AFTER_SEND) };
    const waitMs = answer.ok ? 0 : answer.body.retry_after_seconds * 1000;
    if (!answer.ok && RETRYABLE.has(answer.body.error) && attempt < retries && answer.body.retry_after_seconds <= maxWaitSeconds
      && now() + waitMs + minLeft <= end) {
      signal?.throwIfAborted(); // a refusal is never charged: a cancel here loses nothing
      await abortable(sleep(waitMs, signal), signal);
      continue;
    }
    return answer;
  }
}

/* custosa logout: asks the evaluator to revoke the token. Never retried; a failure is reported, never thrown, and the
 * token is never in the result. */
export async function revokeToken({ token, baseUrl, fetch = globalThis.fetch, timeoutMs = 10_000 } = {}) {
  if (!token || !baseUrl) return { revoked: false, why: "no_token" };
  let res;
  // Any network failure reads as unreachable: whether or not the request left, the revoke wasn't confirmed.
  try { res = await post(baseUrl, REVOKE_PATH, {}, { token, fetch, timeoutMs }); } catch { return { revoked: false, why: "unreachable" }; }
  if (res.status >= 200 && res.status < 300) return { revoked: true };
  return { revoked: false, why: `http_${res.status}` };
}

/* custosa doctor: one unauthenticated GET of the evaluator's liveness probe. */
export async function health(baseUrl, { fetch = globalThis.fetch, timeoutMs = 5_000, inspectorVersion = VERSION } = {}) {
  try {
    const res = await fetch(`${baseUrl}${HEALTH_PATH}`, { method: "GET", redirect: "manual", signal: AbortSignal.timeout(timeoutMs),
      headers: { accept: "application/json", "user-agent": userAgent(inspectorVersion) } });
    let body;
    try { body = JSON.parse(await readCapped(res, 4096)); } catch { body = undefined; }
    return res.status === 200 && body?.status === "ok" ? { ok: true } : { ok: false, why: `http_${res.status}` };
  } catch (err) {
    return { ok: false, why: err?.name === "TimeoutError" ? "timeout" : notSent(err) ? "unreachable" : "network_error" };
  }
}


/* The device token (evaluator_api.md section 3): stored in <config dir>/token (~/.config/custosa/token unless
 * CUSTOSA_CONFIG_DIR says otherwise), mode 0600, in a directory only this user can write. Never printed, never
 * logged, never put in an error message.
 *
 * readToken({configDir}) -> {token, host} | {missing: true} | {refused: <why, no token text>}
 * writeToken(token, {configDir, host})   removes the old token, then writes through a temporary file renamed into place (0600), with the
 *                                  evaluator origin that issued it in token.host: the token is sent to that origin only
 * removeToken({configDir})         -> true deleted | false none; throws TokenUnremoved when it is there and can't be deleted
 * deviceLogin(...)                  the device sign-in (below) */
import { closeSync, fsyncSync, mkdirSync, openSync, renameSync, unlinkSync, writeSync, constants } from "node:fs";
import { randomBytes } from "node:crypto";
import { join } from "node:path";
import { configDirFor, dirProblem, readPrivateFile } from "./secrets.mjs";

export const TOKEN_FILE = "token";
/* How long the evaluator keeps a device token valid (the evaluator's app/core/device_auth.py DEVICE_TOKEN_LIFETIME). The
 * token carries no expiry of its own, so custosa doctor estimates it from when the token file was written. */
export const DEVICE_TOKEN_DAYS = 90;
// device_token_response.access_token (response.schema.json).
export const TOKEN_PATTERN = /^[A-Za-z0-9._~+/=-]{16,4096}$/;

export const tokenPath = (options = {}) => join(configDirFor(options), TOKEN_FILE);

export const HOST_FILE = "token.host";
const ORIGIN = /^https?:\/\/[A-Za-z0-9.:[\]-]{1,300}$/;

/* The evaluator origin the token was issued by: the token goes to that origin only. */
function readHost(dir) {
  const read = readPrivateFile(join(dir, HOST_FILE), 400);
  const text = read.text?.trim();
  return text !== undefined && ORIGIN.test(text) ? text : null;
}

const TOKEN_REFUSED = Object.freeze({
  not_regular: "the sign-in file is not a regular file",
  open_to_others: "the sign-in file is readable by other users (run chmod 600 on it, or sign in again)",
  other_owner: "the sign-in file belongs to another user",
  too_large: "the sign-in file is not a sign-in token",
  unreadable: "the sign-in file can't be read",
});

export function readToken(options = {}) {
  const dir = configDirFor(options);
  const problem = dirProblem(dir);
  if (problem === "missing") return { missing: true };
  if (problem) return { refused: problem };
  const read = readPrivateFile(join(dir, TOKEN_FILE), 8192);
  if (read.missing) return { missing: true };
  if (read.refused) return { refused: TOKEN_REFUSED[read.refused] };
  const text = read.text.trim();
  if (!TOKEN_PATTERN.test(text)) return { refused: "the sign-in file is not a sign-in token" };
  const host = readHost(dir);
  if (!host) return { refused: "the sign-in has no record of the evaluator it was made for (sign in again)" };
  return { token: text, host };
}

function writePrivate(dir, name, text) {
  const tmp = join(dir, `.${name}.${process.pid}.${randomBytes(6).toString("hex")}`);
  const fd = openSync(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
  try {
    try {
      writeSync(fd, text);
      fsyncSync(fd);
    } finally { closeSync(fd); }
    renameSync(tmp, join(dir, name));
  } catch (err) {
    // a failed write or rename leaves no temporary file, which may hold part of the token
    try { unlinkSync(tmp); } catch { /* gone */ }
    throw new Error(`Can't save the sign-in: ${err.code || "error"}.`);
  }
}

/* host: the evaluator origin that issued the token (https://...), stored beside it in token.host. */
export function writeToken(token, options = {}) {
  if (typeof token !== "string" || !TOKEN_PATTERN.test(token)) throw new Error("The evaluator answered a sign-in token in a form the inspector doesn't accept.");
  if (typeof options.host !== "string" || !ORIGIN.test(options.host)) throw new Error("Can't save the sign-in: no evaluator address to bind it to.");
  const dir = configDirFor(options);
  let problem = dirProblem(dir);
  if (problem === "missing") {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    problem = dirProblem(dir);
  }
  if (problem) throw new Error(`Can't save the sign-in: ${problem}.`);
  // The old token goes first: the two files can't change together, and a save that fails between them must never
  // leave the old token bound to the new host, which would send it to an evaluator that didn't issue it.
  try { unlinkSync(join(dir, TOKEN_FILE)); } catch (err) {
    if (err.code !== "ENOENT") throw new Error(`Can't save the sign-in: ${err.code || "error"}.`);
  }
  writePrivate(dir, HOST_FILE, `${options.host}\n`);
  writePrivate(dir, TOKEN_FILE, `${token}\n`);
}

/* A token file that is there but can't be deleted: its path and the error code, never its text. */
export class TokenUnremoved extends Error {
  constructor(path, code) { super(`${path} couldn't be deleted (${code})`); this.path = path; this.code = code; }
}

/* -> true when the token was deleted, false when there was none. One that can't be deleted throws TokenUnremoved,
 * so logout never says a sign-in was removed while it is still on disk. */
export function removeToken(options = {}) {
  try { unlinkSync(join(configDirFor(options), HOST_FILE)); } catch { /* none, or kept: a token with no host is never sent */ }
  const file = tokenPath(options);
  try { unlinkSync(file); return true; } catch (err) {
    if (err.code === "ENOENT" || err.code === "ENOTDIR") return false;
    throw new TokenUnremoved(file, err.code || "error");
  }
}

/* ---------------------------------------------------------------- device sign-in (custosa login) */

/* deviceLogin({baseUrl, configDir, out, post, sleep, now, confirm}) -> exit code: 0 signed in, 3 the sign-in page's
 * address isn't on the allowlist (sign-in isn't available yet), 1 anything else
 * POST /v1/device/start, show the person the user code and the address, then poll /v1/device/poll no faster than the
 * interval until they approve, decline, or the code expires. Every answer is checked against response.schema.json and
 * its HTTP status (start: device_start_response; poll: device_token_response on 200, device_error_response on 400,
 * error_response with retry_after_seconds on 429 or 503, account_required on 403: the account's sign-in limit);
 * anything else stops the sign-in. slow_down takes the given
 * interval or adds 5 seconds, never past 60; the total wait never passes expires_in. The verification address is shown
 * only when it is https on the evaluator's own host, custosa.com or a subdomain, or an exact host in
 * ALLOWED_VERIFICATION_HOSTS, with no control or direction characters.
 * The device code goes nowhere but /v1/device/poll and is never shown; the token is stored (writeToken, bound to the
 * evaluator's origin) and never shown. out(line) prints for the person (a terminal, never the MCP stdout). */
const START_KEYS = ["device_code", "expires_in", "interval", "user_code", "verification_uri", "verification_uri_complete"];
const DEVICE_ERRORS = ["authorization_pending", "slow_down", "expired_token", "access_denied", "invalid_device_code"];
const MAX_INTERVAL = 60;
const UNSAFE_CHARS = /[\u0000-\u0020\u007f-\u00a0\u2028\u2029\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/;
const sameKeys = (o, keys) => Object.keys(o).sort().join(",") === [...keys].sort().join(",");

/* Exact hosts besides custosa.com (and its subdomains) and the evaluator's own host whose sign-in page login will show.
 * Empty today: Custosa decides the sign-in page's domain, and a release adds it here. No wildcards. */
export const ALLOWED_VERIFICATION_HOSTS = Object.freeze([]);

export function verificationAddressOk(value, evaluatorOrigin) {
  if (typeof value !== "string" || UNSAFE_CHARS.test(value)) return false;
  let u;
  try { u = new URL(value); } catch { return false; }
  if (u.protocol !== "https:" || u.username || u.password) return false;
  const host = u.hostname.toLowerCase();
  return host === new URL(evaluatorOrigin).hostname.toLowerCase() || host === "custosa.com" || host.endsWith(".custosa.com")
    || ALLOWED_VERIFICATION_HOSTS.includes(host);
}

export async function deviceLogin({ baseUrl, configDir, out, post, sleep, now = () => Date.now(), confirm = null }) {
  const { validateResponse } = await import("./schema.mjs");
  const origin = new URL(baseUrl).origin;
  out(`Evaluator: ${origin} (your sign-in token will be sent only there).`);
  // A non-default address from evaluator.json needs the person's yes (the caller passes confirm only then).
  if (confirm && !(await confirm(origin))) { out("Not signed in: the evaluator address wasn't confirmed."); return 1; }
  const unreadable = () => { out("The evaluator answered the sign-in in a form this version can't read. Nothing was saved. Run npx custosa@latest login."); return 1; };
  const call = async (path, json) => {
    try { return await post(baseUrl, path, json); } catch { return null; }
  };
  const lawful = (body) => body && typeof body === "object" && !Array.isArray(body) && !validateResponse(body);

  const start = await call("/v1/device/start", {});
  if (!start || start.body === undefined) {
    out("PHI Schema Check sign-in couldn't start: the evaluator couldn't be reached. Check the connection, then run npx custosa login again.");
    return 1;
  }
  if (start.status !== 200) {
    if (lawful(start.body) && (start.body.error === "rate_limited" || start.body.error === "unavailable")) {
      out("PHI Schema Check sign-in isn't available right now. Wait a minute, then run npx custosa login again.");
      return 1;
    }
    return unreadable();
  }
  const s = start.body;
  if (!lawful(s) || !sameKeys(s, START_KEYS)) return unreadable();
  if (!verificationAddressOk(s.verification_uri, origin) || !verificationAddressOk(s.verification_uri_complete, origin)) {
    out("The sign-in page address the evaluator gave isn't on this inspector's list of sign-in pages, so it isn't shown and nothing was saved. Update the inspector (npx custosa@latest login) or contact hello@custosa.com.");
    return 3; // exit code 3: sign-in isn't available yet (setup says so), apart from other failures
  }
  out("Sign in to PHI Schema Check, a Custosa Labs project.");
  out(`Open ${s.verification_uri} in a browser and enter the code ${s.user_code}`);
  out(`(or open ${s.verification_uri_complete} directly). Waiting for you to approve...`);
  const deadline = now() + s.expires_in * 1000;
  let interval = Math.min(s.interval, MAX_INTERVAL);
  const expired = () => { out("The sign-in code expired before it was approved. Run npx custosa login again."); return 1; };
  for (;;) {
    const left = deadline - now();
    if (left <= 0) return expired();
    await sleep(Math.min(interval * 1000, left));
    if (now() >= deadline) return expired();
    const r = await call("/v1/device/poll", { device_code: s.device_code });
    if (!r || r.body === undefined) continue; // the network or the evaluator hiccuped: keep polling until the deadline
    const b = r.body;
    if (r.status === 200) {
      if (!lawful(b) || !sameKeys(b, ["access_token", "token_type"]) || b.token_type !== "Bearer") return unreadable();
      try { writeToken(b.access_token, { configDir, host: origin }); } catch (err) { out(err.message); return 1; }
      out("Signed in. Your AI assistant's check_schema calls will use this sign-in.");
      return 0;
    }
    if (r.status === 400) {
      if (!lawful(b) || !DEVICE_ERRORS.includes(b.error) || !Object.keys(b).every((k) => k === "error" || k === "interval")) return unreadable();
      if (b.error === "authorization_pending") continue;
      if (b.error === "slow_down") { interval = Math.min(MAX_INTERVAL, Number.isInteger(b.interval) ? Math.max(b.interval, interval) : interval + 5); continue; }
      if (b.error === "expired_token") { out("The sign-in code expired. Run npx custosa login again."); return 1; }
      if (b.error === "access_denied") { out("The sign-in was declined in the browser. Nothing was saved."); return 1; }
      out("The evaluator didn't recognise this sign-in code. Run npx custosa login again.");
      return 1;
    }
    if (r.status === 403 && lawful(b) && b.error === "account_required") {
      out("This account is at its limit of signed-in computers, so this one wasn't signed in. Sign out on another computer (npx custosa logout there) or contact hello@custosa.com, then run npx custosa login again.");
      return 1;
    }
    if ((r.status === 429 || r.status === 503) && lawful(b) && b.error === (r.status === 429 ? "rate_limited" : "unavailable")) {
      interval = Math.min(MAX_INTERVAL, Math.max(interval, b.retry_after_seconds));
      continue;
    }
    return unreadable();
  }
}

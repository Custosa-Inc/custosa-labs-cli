/* The environment mark (evaluator_api.md 1.4): which environment the person says the `phisc` entry in
 * ~/.pg_service.conf points at, as they marked it at setup, in a terminal. Stored in <config dir>/environment.json
 * (~/.config/custosa/environment.json unless CUSTOSA_CONFIG_DIR says otherwise) as exactly
 *   {"value": "development" | "staging" | "production" | "unknown", "source": "setup", "service": <hex> | null}
 * where service is a fingerprint of the [phisc] entry's host, port and dbname when the mark was made (null when there
 * was no entry). The fingerprint stays on this computer; only {value, source} goes in the fact document.
 *
 * Production readiness is judged only with value production from source setup, so the file gets the sign-in file's
 * safeguards: mode 0600, a regular file (opened with O_NOFOLLOW and checked with fstat on the open descriptor) owned
 * by this user, in a folder only this user can write. A file that fails them is refused, never read as a mark.
 *
 * readEnvironment({configDir}) -> {mark: {value, source, service}} | {missing: true} | {refused: <why>}
 * writeEnvironment(value, {configDir, service})   through a temporary file (0600, fsync) renamed into place
 * serviceFingerprint({env, home}) -> <hex> | null   the [phisc] entry's host, port and dbname, as libpq defaults them
 * environmentFor({configDir, env, home}) -> {environment: {value, source: "setup"}, note: <text> | null}
 *   what the inspector sends: the mark when it is valid and the entry still matches its fingerprint; else unknown,
 *   with a note for the assistant saying why (a refused file, or an entry changed since it was marked). */
import { closeSync, constants, fsyncSync, mkdirSync, openSync, renameSync, unlinkSync, writeSync } from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import { homedir } from "node:os";
import { join } from "node:path";
import { configDirFor, dirProblem, readPrivateFile } from "./secrets.mjs";
import { parseServiceEntry, readServiceFile } from "./pgservice.mjs";

export const ENVIRONMENT_FILE = "environment.json";
/* enums.ENVIRONMENTS in the contract; "setup" is the only source this file can hold */
export const ENVIRONMENTS = Object.freeze(["development", "staging", "production", "unknown"]);
export const SOURCE = "setup";
const UNKNOWN = Object.freeze({ value: "unknown", source: SOURCE });
const MAX_BYTES = 4096;
const FINGERPRINT = /^[0-9a-f]{64}$/;
const REMARK = "Ask the user to run npx custosa setup in a terminal to mark it again.";

/* exactly {value, source: "setup", service} with a known value and a fingerprint or null */
export function isMark(v) {
  return Boolean(v) && typeof v === "object" && !Array.isArray(v)
    && Object.keys(v).sort().join(",") === "service,source,value"
    && ENVIRONMENTS.includes(v.value) && v.source === SOURCE && (v.service === null || FINGERPRINT.test(v.service));
}

/* The [phisc] entry's target, defaulted as libpq does (host localhost, port 5432, dbname the user), hashed. null when
   there is no service file or no [phisc] entry; "unreadable" when the file can't be read or the entry can't be parsed. */
export function serviceFingerprint({ env = process.env, home = homedir() } = {}) {
  let text;
  try { text = readServiceFile({ env, home }); } catch { return "unreadable"; }
  if (text === null) return null;
  let entry;
  try { entry = parseServiceEntry(text, "phisc"); } catch { return "unreadable"; }
  if (!entry) return null;
  const target = [entry.host || "localhost", entry.port || "5432", entry.dbname || entry.user || ""];
  return createHash("sha256").update(JSON.stringify(["phisc-service-v1", ...target])).digest("hex");
}

const ENVIRONMENT_REFUSED = Object.freeze({
  not_regular: "the environment file is not a regular file",
  open_to_others: "the environment file is readable or writable by other users (run chmod 600 on it, or run setup again)",
  other_owner: "the environment file belongs to another user",
  too_large: "the environment file is not an environment mark",
  unreadable: "the environment file can't be read",
});

export function readEnvironment(options = {}) {
  const dir = configDirFor(options);
  const problem = dirProblem(dir);
  if (problem === "missing") return { missing: true };
  if (problem) return { refused: problem };
  const read = readPrivateFile(join(dir, ENVIRONMENT_FILE), MAX_BYTES);
  if (read.missing) return { missing: true };
  if (read.refused) return { refused: ENVIRONMENT_REFUSED[read.refused] };
  const text = read.text;
  let value;
  try { value = JSON.parse(text); } catch { return { refused: "the environment file is not an environment mark" }; }
  if (!isMark(value)) return { refused: "the environment file is not an environment mark" };
  return { mark: { value: value.value, source: SOURCE, service: value.service } };
}

export function writeEnvironment(value, options = {}) {
  if (!ENVIRONMENTS.includes(value)) throw new Error(`Unknown environment "${value}". Choose from: ${ENVIRONMENTS.join(", ")}.`);
  const service = options.service ?? null;
  if (service !== null && !FINGERPRINT.test(service)) throw new Error("Can't save the environment mark: the phisc entry can't be read.");
  const dir = configDirFor(options);
  let problem = dirProblem(dir);
  if (problem === "missing") {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    problem = dirProblem(dir);
  }
  if (problem) throw new Error(`Can't save the environment mark: ${problem}.`);
  const tmp = join(dir, `.${ENVIRONMENT_FILE}.${process.pid}.${randomBytes(6).toString("hex")}`);
  const fd = openSync(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
  try {
    writeSync(fd, `${JSON.stringify({ value, source: SOURCE, service })}\n`);
    fsyncSync(fd);
  } finally { closeSync(fd); }
  // rename replaces a symlink of that name itself, never the file it points at
  try { renameSync(tmp, join(dir, ENVIRONMENT_FILE)); } catch (err) { try { unlinkSync(tmp); } catch { /* gone */ } throw new Error(`Can't save the environment mark: ${err.code || "error"}.`); }
  return { value, source: SOURCE, service };
}

export function environmentFor({ configDir, env = process.env, home = homedir() } = {}) {
  const r = readEnvironment({ configDir });
  if (r.missing) return { environment: { ...UNKNOWN }, note: null };
  if (r.refused) return { environment: { ...UNKNOWN }, note: `The environment marked at setup can't be used (${r.refused}), so this check is judged as environment unknown. ${REMARK}` };
  const now = serviceFingerprint({ env, home });
  if (now === "unreadable") {
    return { environment: { ...UNKNOWN }, note: `The phisc database entry couldn't be read, so the environment marked ${r.mark.value} at setup can't be checked against it and this check is judged as environment unknown. ${REMARK}` };
  }
  if (r.mark.service !== now) {
    return { environment: { ...UNKNOWN }, note: `The phisc database entry has changed since it was marked ${r.mark.value} at setup, so this check is judged as environment unknown. ${REMARK}` };
  }
  // production names a database: a mark made with no [phisc] entry has none to name
  if (r.mark.value === "production" && r.mark.service === null) {
    return { environment: { ...UNKNOWN }, note: `The environment was marked production at setup when there was no phisc database entry, so this check is judged as environment unknown. Ask the user to add the entry, then run npx custosa setup in a terminal to mark it again.` };
  }
  return { environment: { value: r.mark.value, source: SOURCE }, note: null };
}

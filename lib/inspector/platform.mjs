/* Platform collectors: the hosting platform's own database settings, read through its API with the read-only
 * token the person chose to save in ~/.config/custosa/platform.json.
 *
 * collectPlatform(config?, options?) -> {provider, status, reason?, settings, errors?, message?}
 *   provider  "supabase" | "rds" | "cloudsql" | "azure" | "firebase" | null (no usable config)
 *   status    "ok" | "failed" | "not_run" (the collection statuses of the fact document)
 *   reason    a code: no_token, config_insecure, config_invalid, partial, not_found, http_<status>, timeout,
 *             network_error, bad_response, too_large (over 4 MB), truncated (a paged read cut at its page limit)
 *   settings  {key: value} with every key of the provider present; a value is true/false, an integer, or one of a
 *             small fixed set of strings, and null when it could not be read (unknown). Never free text.
 *   errors    [{read, reason}] for reads that failed while others succeeded (read is a fixed id, reason a code)
 *
 * toFactPlatform(result) -> {platform, collection} turns it into the fact document's platform block and collection
 * entry (contract v2.1: every key of enums.PLATFORM_SETTINGS, each on/off/not_offered/not_read).
 *
 * Supabase: the Management API (api.supabase.com) with a personal access token and the project ref. High Compliance
 * has no API read (platform-high-compliance practice), so high_compliance is always null here.
 * AWS RDS: DescribeDBInstances, DescribeDBClusters and DescribeDBParameters (rds.<region>.amazonaws.com) and
 * CloudWatch Logs DescribeLogGroups (logs.<region>.amazonaws.com), signed with SigV4 by hand.
 * Cloud SQL: the Admin API's instances.get (sqladmin.googleapis.com) with an OAuth access token, plus, for the log
 * settings, Resource Manager (ancestry and IAM audit configs), Logging (sinks and log buckets), Cloud Storage and
 * BigQuery (sink destinations) and Firestore (whether the project has a database).
 * Firebase: the same Google reads for the project's Firestore databases.
 * Azure: Azure Resource Manager (management.azure.com) for one Azure Database for PostgreSQL flexible server: its
 * diagnostic settings, and each destination's retention (Log Analytics workspace and table, storage account lifecycle
 * management policy).
 *
 * The log settings (log_export, log_retention) follow evaluator_api.md section 1.7 per provider: "on" only for
 * what was read and shown to cover every in-scope log, never because something wasn't seen. A filter this module can't
 * evaluate, a destination it couldn't read, or an event hub or Pub/Sub topic (whose consumer can't be read) never gives
 * on, and never off for retention.
 *
 * What it never does: fetch a URL from the config (hosts are fixed; the region and every name is validated and the
 * URL built from it, and resource names read from a response are validated the same way before they are used),
 * follow a redirect, read an error response's body, put the token in a result, an error or a log line (it logs
 * nothing), write any file, or start a process. Response bodies (the Supabase auth config holds the project's provider
 * secrets) are parsed in memory, the named fields picked, and the rest dropped. */
import { createHash, createHmac } from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { defaultConfigDir } from "./secrets.mjs";

export const PROVIDERS = Object.freeze(["supabase", "rds", "cloudsql", "azure", "firebase"]);
export const CONFIG_FILE = "platform.json";
const CONFIG_MAX_BYTES = 64 * 1024;
const RESPONSE_MAX_BYTES = 4 * 1024 * 1024;
const TIMEOUT_MS = 15_000;
const RDS_PARAMETER_PAGES = 40;

const SUPABASE_HOST = "api.supabase.com";
const CLOUDSQL_HOST = "sqladmin.googleapis.com";
const CRM_HOST = "cloudresourcemanager.googleapis.com";
const LOGGING_HOST = "logging.googleapis.com";
const STORAGE_HOST = "storage.googleapis.com";
const BIGQUERY_HOST = "bigquery.googleapis.com";
const FIRESTORE_HOST = "firestore.googleapis.com";
const AZURE_HOST = "management.azure.com";
const FIXED_HOSTS = new Set([SUPABASE_HOST, CLOUDSQL_HOST, CRM_HOST, LOGGING_HOST, STORAGE_HOST, BIGQUERY_HOST, FIRESTORE_HOST,
  AZURE_HOST]);
// Commercial and GovCloud partitions (amazonaws.com). China and ISO partitions use other domains: not supported.
// One region pattern for the config and both host checks, so a region the config accepts is never refused as a host.
const REGION = "(us|eu|ap|sa|ca|me|af|il|mx)(-gov)?-[a-z]+-[1-9]";
const AWS_REGION = new RegExp(`^${REGION}$`);
const RDS_HOST = new RegExp(`^rds\\.${REGION}\\.amazonaws\\.com$`);
const LOGS_HOST = new RegExp(`^logs\\.${REGION}\\.amazonaws\\.com$`);

// Fact keys per provider (proposed for the fact document's platform.settings; the fact document maps them to the schema).
export const SETTING_KEYS = Object.freeze({
  supabase: Object.freeze([
    "ssl_enforced", "network_restricted", "pitr_enabled", "pitr_retention_days", "backups_enabled",
    "high_compliance", "auth_mfa_enabled", "auth_webauthn_enabled", "leaked_password_protection",
    "email_confirmation_required", "anonymous_sign_ins_enabled", "password_min_length", "otp_expiry_seconds",
    "refresh_token_rotation", "captcha_enabled",
  ]),
  rds: Object.freeze([
    "engine", "postgres_major_version", "storage_encrypted", "backup_retention_days", "pitr_enabled",
    "backups_enabled", "publicly_accessible", "network_restricted", "iam_auth_enabled", "deletion_protection",
    "ssl_enforced", "log_connections", "log_disconnections", "log_export", "log_retention",
  ]),
  cloudsql: Object.freeze([
    "engine", "postgres_major_version", "ssl_enforced", "ssl_mode", "public_ip_enabled", "authorized_network_count",
    "network_restricted", "backups_enabled", "pitr_enabled", "transaction_log_retention_days",
    "backup_retention_count", "storage_encrypted", "storage_key", "deletion_protection", "iam_auth_enabled",
    "pgaudit_enabled", "log_connections", "log_disconnections", "log_export", "log_retention",
  ]),
  azure: Object.freeze(["log_export", "log_retention"]),
  firebase: Object.freeze(["firestore_database_count", "log_export", "log_retention"]),
});

const CONFIG_INSECURE_MESSAGE = "~/.config/custosa/platform.json can be read or changed by other users, so the "
  + "platform token was not used. Run: chmod 600 ~/.config/custosa/platform.json";
const CONFIG_SYMLINK_MESSAGE = "~/.config/custosa/platform.json is a symbolic link, so the platform token was not "
  + "used. Replace it with the file itself (chmod 600).";
const CONFIG_OWNER_MESSAGE = "~/.config/custosa/platform.json belongs to another user, so the platform token was "
  + "not used.";

// ---------------------------------------------------------------------------------------------------------------
// Config

export function configDir(env = process.env) {
  return defaultConfigDir({ env });
}

/* Reads platform.json. Returns {config} or a finished result ({provider, status, reason, settings, message?}). A
 * missing file is not_run (no_token). A symbolic link, a file owned by someone else, or one other users can read or
 * write is refused (failed, config_insecure). */
export function loadPlatformConfig({ dir = configDir() } = {}) {
  const path = join(dir, CONFIG_FILE);
  let st;
  try { st = lstatSync(path); } catch (e) {
    if (e && e.code === "ENOENT") return { result: result(null, "not_run", "no_token") };
    return { result: result(null, "failed", "config_invalid") };
  }
  if (st.isSymbolicLink()) return { result: { ...result(null, "failed", "config_insecure"), message: CONFIG_SYMLINK_MESSAGE } };
  if (!st.isFile() || st.size > CONFIG_MAX_BYTES) return { result: result(null, "failed", "config_invalid") };
  if (process.platform !== "win32") {
    if ((st.mode & 0o077) !== 0) return { result: { ...result(null, "failed", "config_insecure"), message: CONFIG_INSECURE_MESSAGE } };
    if (typeof process.getuid === "function" && st.uid !== process.getuid()) {
      return { result: { ...result(null, "failed", "config_insecure"), message: CONFIG_OWNER_MESSAGE } };
    }
  }
  let config;
  try { config = JSON.parse(readFileSync(path, "utf8")); } catch { return { result: result(null, "failed", "config_invalid") }; }
  return { config };
}

const TOKEN = /^[\x21-\x7e]{8,4096}$/; // printable ASCII, no spaces or control characters
const matches = (re, v) => typeof v === "string" && re.test(v);
const SUPABASE_REF = /^[a-z]{20}$/;
const AWS_KEY_ID = /^(AKIA|ASIA)[A-Z0-9]{16}$/;
const RDS_INSTANCE = /^[A-Za-z][A-Za-z0-9-]{0,62}$/;
const RDS_PARAMETER_GROUP = /^[A-Za-z][A-Za-z0-9.-]{0,254}$/;
const GCP_PROJECT = /^([a-z][a-z0-9.-]{0,62}:)?[a-z][a-z0-9-]{4,28}[a-z0-9]$/;
const CLOUDSQL_INSTANCE = /^[a-z][a-z0-9-]{0,97}$/;
const AZURE_SUBSCRIPTION = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const AZURE_RESOURCE_GROUP = /^[-\w.()]{0,89}[-\w()]$/;
const AZURE_PG_SERVER = /^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/;

/* Checks the config for one provider. Returns {provider, creds} or a finished result. A config without its token is
 * not_run (no_token); anything malformed is failed (config_invalid). */
function validate(config) {
  if (config === null || typeof config !== "object" || Array.isArray(config)) return result(null, "failed", "config_invalid");
  const provider = PROVIDERS.includes(config.provider) ? config.provider : null;
  if (!provider) return result(null, "failed", "config_invalid");
  const bad = () => result(provider, "failed", "config_invalid");
  const noToken = () => result(provider, "not_run", "no_token");
  const blank = (v) => v === undefined || v === null || v === "";
  if (provider === "supabase") {
    if (blank(config.token)) return noToken();
    if (!matches(TOKEN, config.token) || !matches(SUPABASE_REF, config.project_ref)) return bad();
    return { provider, creds: { token: config.token, ref: config.project_ref } };
  }
  if (provider === "rds") {
    if (blank(config.access_key_id) || blank(config.secret_access_key)) return noToken();
    if (!matches(AWS_KEY_ID, config.access_key_id) || !matches(TOKEN, config.secret_access_key)) return bad();
    if (!blank(config.session_token) && !matches(TOKEN, config.session_token)) return bad();
    if (!matches(AWS_REGION, config.region) || !matches(RDS_INSTANCE, config.db_instance_identifier)) return bad();
    return {
      provider,
      creds: {
        accessKeyId: config.access_key_id, secretAccessKey: config.secret_access_key,
        sessionToken: blank(config.session_token) ? null : config.session_token,
        region: config.region, instance: config.db_instance_identifier,
      },
    };
  }
  if (blank(config.access_token)) return noToken();
  if (!matches(TOKEN, config.access_token)) return bad();
  if (provider === "azure") {
    if (!matches(AZURE_SUBSCRIPTION, config.subscription_id) || !matches(AZURE_RESOURCE_GROUP, config.resource_group)
      || !matches(AZURE_PG_SERVER, config.server_name)) return bad();
    return { provider, creds: { token: config.access_token, subscription: config.subscription_id.toLowerCase(),
      group: config.resource_group, server: config.server_name } };
  }
  if (!matches(GCP_PROJECT, config.project)) return bad();
  if (provider === "firebase") return { provider, creds: { token: config.access_token, project: config.project } };
  if (!matches(CLOUDSQL_INSTANCE, config.instance)) return bad();
  return { provider, creds: { token: config.access_token, project: config.project, instance: config.instance } };
}

// ---------------------------------------------------------------------------------------------------------------
// Entry point

/* config: the parsed platform.json (left out: read from CUSTOSA_CONFIG_DIR or ~/.config/custosa). options.fetch
 * replaces the global fetch (tests); options.now gives the signing time for AWS; options.dir the config folder. */
/* Local warnings about the token platform.json holds (LI7), for the person, never sent. Judged from the token's form
 * alone: no call is made to learn what it may do, and the token is never in a note.
 *   Supabase: a personal access token (sbp_) acts as the person on every project and organization they can reach, with
 *   write access through the Management API. Supabase offers no read-only token form today, so this is a warning.
 * Other providers: whether a token can write (an AWS key's IAM policy, a Google OAuth token's roles, an Azure token's
 * RBAC roles) can't be told from the token without privileged calls (IAM policy reads or simulation), so it isn't
 * judged: a documented limitation (README, "Platform tokens"). */
export const SUPABASE_PAT_NOTE = "platform.json holds a Supabase personal access token (sbp_): it can act as you on every "
  + "project and organization you can reach, including writes. The inspector only reads with it, but a narrower "
  + "credential is safer: use an account that is a read-only member of this project's organization, and remove the "
  + "token from platform.json when you no longer need the platform checks.";
export function platformTokenNotes(config) {
  const notes = [];
  if (config && typeof config === "object" && config.provider === "supabase" && typeof config.token === "string"
    && config.token.startsWith("sbp_")) notes.push(SUPABASE_PAT_NOTE);
  return notes;
}

export async function collectPlatform(config, options = {}) {
  if (config === undefined) {
    const loaded = loadPlatformConfig({ dir: options.dir ?? configDir() });
    if (loaded.result) return loaded.result;
    config = loaded.config;
  }
  const notes = platformTokenNotes(config);
  const out = await collectFrom(config, options);
  return notes.length ? { ...out, notes } : out;
}

async function collectFrom(config, options) {
  const checked = validate(config);
  if (checked.status) return checked;
  const http = client(options.fetch ?? globalThis.fetch, options.timeoutMs ?? TIMEOUT_MS, options.deadline ?? null);
  const now = options.now ?? (() => new Date());
  try {
    if (checked.provider === "supabase") return await supabase(checked.creds, http);
    if (checked.provider === "rds") return await rds(checked.creds, http, now);
    if (checked.provider === "azure") return await azure(checked.creds, http);
    if (checked.provider === "firebase") return await firebase(checked.creds, http);
    return await cloudsql(checked.creds, http);
  } catch {
    // An unexpected error: its message is never passed on (it could carry anything).
    return result(checked.provider, "failed", "bad_response");
  }
}

function result(provider, status, reason, settings = {}) {
  const out = { provider, status, settings };
  if (reason) out.reason = reason;
  return out;
}

/* Folds the reads into a result: every key present (null when unknown); ok with reason partial when some reads
 * failed; failed with the first failure's code when none succeeded. */
function finish(provider, values, reads) {
  const failed = reads.filter((r) => !r.ok);
  if (failed.length === reads.length) return result(provider, "failed", failed[0].reason);
  const settings = {};
  for (const key of SETTING_KEYS[provider]) settings[key] = values[key] === undefined ? null : values[key];
  const out = result(provider, "ok", failed.length ? "partial" : null, settings);
  if (failed.length) out.errors = failed.map((r) => ({ read: r.read, reason: r.reason }));
  return out;
}

// ---------------------------------------------------------------------------------------------------------------
// HTTP: fixed hosts, no redirects, error bodies never read

function allowedHost(host) {
  return FIXED_HOSTS.has(host) || RDS_HOST.test(host) || LOGS_HOST.test(host);
}

/* get(read, url, headers, kind, {method, body}): GET by default; POST only for the reads that are POST by API design
 * (Resource Manager getIamPolicy and getAncestry, CloudWatch Logs), with a body this module builds. */
/* The only error-body field ever read: a Google 403's structured reason, and only these two values (the API is
 * disabled). The message text is never read; the body is parsed in memory, the enum picked, the rest dropped. */
const SERVICE_DISABLED_REASONS = new Set(["SERVICE_DISABLED", "accessNotConfigured"]);
function serviceDisabled(text) {
  let data;
  try { data = JSON.parse(text); } catch { return false; }
  const err = obj(obj(data).error);
  const reasons = [...(Array.isArray(err.details) ? err.details : []), ...(Array.isArray(err.errors) ? err.errors : [])]
    .map((d) => obj(d).reason);
  return reasons.some((r) => typeof r === "string" && SERVICE_DISABLED_REASONS.has(r));
}

/* deadline (epoch ms, optional): the check's time budget. A call past it is a timeout without a request; a call before
 * it waits no longer than what is left. */
function client(fetchImpl, timeoutMs, deadline = null) {
  return async function get(read, url, headers, kind = "json", { method = "GET", body, disabledReason = false } = {}) {
    const left = deadline === null ? timeoutMs : Math.min(timeoutMs, deadline - Date.now());
    if (left <= 0) return { read, ok: false, reason: "timeout" };
    const u = new URL(url);
    if (u.protocol !== "https:" || !allowedHost(u.hostname) || u.port !== "" || u.username || u.password
      || !(method === "GET" || method === "POST")) {
      return { read, ok: false, reason: "config_invalid" };
    }
    let res;
    try {
      const init = { method, headers, redirect: "error", signal: AbortSignal.timeout(left) };
      if (method === "POST") init.body = body ?? "";
      res = await fetchImpl(u.href, init);
    } catch (e) {
      const name = e && e.name;
      return { read, ok: false, reason: name === "TimeoutError" || name === "AbortError" ? "timeout" : "network_error" };
    }
    if (!res.ok && disabledReason && res.status === 403) {
      const got = await readCapped(res);
      return { read, ok: false, reason: "http_403", serviceDisabled: got.ok && serviceDisabled(got.text) };
    }
    if (!res.ok) {
      try { await res.body?.cancel(); } catch { /* ignore */ }
      const s = Number.isInteger(res.status) && res.status >= 100 && res.status <= 599 ? res.status : 0;
      return { read, ok: false, reason: s === 404 ? "not_found" : s ? `http_${s}` : "bad_response" };
    }
    const length = Number(res.headers?.get?.("content-length"));
    if (length > RESPONSE_MAX_BYTES) { try { await res.body?.cancel(); } catch { /* ignore */ } return { read, ok: false, reason: "too_large" }; }
    const got = await readCapped(res);
    if (!got.ok) return { read, ok: false, reason: got.reason };
    const text = got.text;
    if (kind === "text") return { read, ok: true, data: text };
    try { return { read, ok: true, data: JSON.parse(text) }; } catch { return { read, ok: false, reason: "bad_response" }; }
  };
}

/* The body as UTF-8 text, counting bytes as they arrive and stopping past RESPONSE_MAX_BYTES (too_large). */
async function readCapped(res) {
  const chunks = [];
  let total = 0;
  try {
    if (res.body) {
      const reader = res.body.getReader();
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > RESPONSE_MAX_BYTES) {
          try { await reader.cancel(); } catch { /* ignore */ }
          return { ok: false, reason: "too_large" };
        }
        chunks.push(value);
      }
    }
  } catch { return { ok: false, reason: "network_error" }; }
  try {
    return { ok: true, text: new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks, total)) };
  } catch { return { ok: false, reason: "bad_response" }; }
}

// ---------------------------------------------------------------------------------------------------------------
// Value guards: only booleans, bounded integers and fixed strings leave this module

const bool = (v) => (typeof v === "boolean" ? v : null);
function int(v, max = 1_000_000) {
  const n = typeof v === "string" && /^\d{1,9}$/.test(v) ? Number(v) : v;
  return Number.isInteger(n) && n >= 0 && n <= max ? n : null;
}
const oneOf = (v, set) => (set.includes(v) ? v : null);
const not = (v) => (v === null ? null : !v);
function major(version) {
  const m = typeof version === "string" ? /^(?:POSTGRES_)?(\d{1,3})(?:[._-]|$)/.exec(version) : null;
  return m ? int(m[1], 999) : null;
}
const obj = (v) => (v !== null && typeof v === "object" && !Array.isArray(v) ? v : {});
// Every value of a list known, else null; then all true.
function allOf(values) {
  if (values.some((v) => v === false)) return false;
  return values.length && values.every((v) => v === true) ? true : null;
}

/* Three-valued logic over true / false / null (unknown). and3 of nothing is null: an empty scope is never "on". */
function and3(values) {
  if (values.some((v) => v === false)) return false;
  return values.length && values.every((v) => v === true) ? true : null;
}
function or3(values) {
  if (values.some((v) => v === true)) return true;
  return values.every((v) => v === false) ? false : null;
}
const not3 = (v) => (v === null ? null : !v);

/* evaluator_api.md section 1.7, log_retention for one in-scope instance. destinations: every destination that
 * receives any of its in-scope logs, or might ({receivesAll, receivesAny, kind, keeps}: kind "store" for a destination
 * whose retention is read, "stream" for an event hub or Pub/Sub topic, whose consumer can't be read, "unknown" for one
 * this module can't follow; keeps true/false/null for any period of a day or more, or no expiry). complete: false when a destination might exist
 * that wasn't seen (a sink list or a diagnostic setting list that couldn't be read).
 *   true:  a destination receiving all of its in-scope logs keeps them a day or more, or never deletes them;
 *   false: complete, at least one destination, none a stream, every one read and determinate, and none of those
 *          receiving all of its logs keeps them that long;
 *   null:  otherwise (never on, never off: an instance whose destinations include a stream is never off). */
function instanceRetention({ destinations, complete }) {
  const mine = destinations.filter((d) => d.receivesAny !== false);
  if (mine.some((d) => d.receivesAll === true && d.kind === "store" && d.keeps === true)) return true;
  if (!complete || mine.length === 0) return null;
  if (mine.some((d) => d.kind !== "store" || d.keeps === null || d.receivesAll === null || d.receivesAny === null)) return null;
  return false;
}

/* A CIDR parsed strictly: {v: 4, bits: BigInt, prefix} or {v: 6, ...}, or null. IPv4: four decimal octets 0-255
 * without leading zeros, prefix 0-32. IPv6: eight groups of 1-4 hex digits, one "::" at most, an optional dotted IPv4
 * tail, prefix 0-128. */
function parseIPv4(text) {
  const parts = text.split(".");
  if (parts.length !== 4) return null;
  let n = 0n;
  for (const p of parts) {
    if (!/^(0|[1-9]\d{0,2})$/.test(p) || Number(p) > 255) return null;
    n = (n << 8n) | BigInt(p);
  }
  return n;
}
function parseIPv6(text) {
  if (!/^[0-9A-Fa-f:.]{2,45}$/.test(text)) return null;
  let tail = [];
  let head = text;
  const lastColon = text.lastIndexOf(":");
  if (text.includes(".")) { // an IPv4 tail fills the last two groups
    const v4 = parseIPv4(text.slice(lastColon + 1));
    if (v4 === null) return null;
    tail = [Number(v4 >> 16n), Number(v4 & 0xffffn)];
    head = text.slice(0, lastColon + 1);
    if (head.endsWith(":") && !head.endsWith("::")) head = head.slice(0, -1);
  }
  const halves = head.split("::");
  if (halves.length > 2) return null;
  const groups = (h) => (h === "" ? [] : h.split(":"));
  const left = groups(halves[0]), right = halves.length === 2 ? groups(halves[1]) : [];
  if ([...left, ...right].some((g) => !/^[0-9A-Fa-f]{1,4}$/.test(g))) return null;
  const known = left.length + right.length + tail.length;
  if (halves.length === 1 ? known !== 8 : known > 7) return null;
  const all = [...left.map((g) => parseInt(g, 16)), ...Array(8 - known).fill(0), ...right.map((g) => parseInt(g, 16)), ...tail];
  return all.reduce((n, g) => (n << 16n) | BigInt(g), 0n);
}
function parseCidr(cidr) {
  if (typeof cidr !== "string") return null;
  const m = /^([^/\s]{2,45})\/(0|[1-9]\d{0,2})$/.exec(cidr.trim());
  if (!m) return null;
  const prefix = Number(m[2]);
  if (m[1].includes(":")) {
    const bits = parseIPv6(m[1]);
    return bits === null || prefix > 128 ? null : { v: 6, bits, prefix };
  }
  const bits = parseIPv4(m[1]);
  return bits === null || prefix > 32 ? null : { v: 4, bits, prefix };
}

const V4_MAPPED = 0xffffn << 32n; // ::ffff:0:0/96
const V4_BROAD_PREFIX = 8, V6_BROAD_PREFIX = 16;
const V4_MAX_TOTAL = 1n << 24n, V6_MAX_TOTAL = 1n << 112n;

/* Whether the listed ranges, taken together, keep the database off the open internet. False if any entry is shorter than /8 (IPv4) or /16 (IPv6), if an IPv4-mapped IPv6
 * entry (::ffff:a.b.c.d/n) has an effective IPv4 prefix shorter than /8 (an IPv6 range holding all of ::ffff:0:0/96
 * counts as IPv4 /0), or if the summed sizes pass 2^24 (IPv4, mapped entries included) or 2^112 (IPv6). Overlaps
 * are counted twice, which only moves toward false. An empty list admits nothing for that family. null when an entry
 * doesn't parse or a list is missing. */
function cidrsRestricted(lists) {
  let v4Total = 0n, v6Total = 0n, restricted = true;
  for (const list of lists) {
    if (!Array.isArray(list)) return null;
    for (const entry of list) {
      const c = parseCidr(entry);
      if (c === null) return null;
      if (c.v === 4) {
        if (c.prefix < V4_BROAD_PREFIX) restricted = false;
        v4Total += 1n << BigInt(32 - c.prefix);
        continue;
      }
      if (c.prefix < V6_BROAD_PREFIX) restricted = false;
      const shift = BigInt(128 - Math.min(c.prefix, 96));
      const mapped = (c.bits >> shift) === (V4_MAPPED >> shift);
      if (mapped) { // the range overlaps ::ffff:0:0/96: count it as IPv4
        const v4Prefix = Math.max(0, c.prefix - 96);
        if (v4Prefix < V4_BROAD_PREFIX) restricted = false;
        v4Total += 1n << BigInt(32 - v4Prefix);
        if (c.prefix >= 96) continue;
      }
      v6Total += 1n << BigInt(128 - c.prefix);
    }
  }
  if (v4Total > V4_MAX_TOTAL || v6Total > V6_MAX_TOTAL) restricted = false;
  return restricted;
}

/* Postgres logging switches as text: on/off and 1/0; PostgreSQL 18's log_connections list counts as on when it holds
 * all or receipt, authentication and authorization. */
function pgSwitch(v, list = false) {
  if (typeof v === "boolean") return v;
  if (typeof v !== "string") return null;
  const s = v.trim().toLowerCase();
  if (["on", "1", "true", "yes"].includes(s)) return true;
  if (["off", "0", "false", "no"].includes(s)) return false;
  if (list) {
    if (s === "") return false;
    const parts = s.split(",").map((p) => p.trim());
    if (parts.includes("all")) return true;
    if (parts.every((p) => /^[a-z_]+$/.test(p))) return ["receipt", "authentication", "authorization"].every((p) => parts.includes(p));
  }
  return null;
}

// ---------------------------------------------------------------------------------------------------------------
// Supabase

async function supabase({ token, ref }, get) {
  const base = `https://${SUPABASE_HOST}/v1/projects/${ref}`;
  const headers = { authorization: `Bearer ${token}`, accept: "application/json" };
  // Only the reads a contract setting rests on (CONTRACT_READS.supabase). The project, postgres config and security
  // advisor reads fed settings the fact document never takes, so they are gone.
  const reads = await Promise.all([
    get("ssl_enforcement", `${base}/ssl-enforcement`, headers),
    get("network_restrictions", `${base}/network-restrictions`, headers),
    get("addons", `${base}/billing/addons`, headers),
    get("backups", `${base}/database/backups`, headers),
    get("auth_config", `${base}/config/auth`, headers),
  ]);
  const [ssl, network, addons, backups, auth] = reads.map((r) => (r.ok ? obj(r.data) : null));
  const v = { high_compliance: null }; // dashboard only: no API read

  if (ssl) v.ssl_enforced = ssl.appliedSuccessfully === true ? bool(obj(ssl.currentConfig).database) : null;
  if (network) {
    // The applied ranges: config once applied, else the previous config while a change is only stored.
    const applied = network.status === "applied" ? network.config : network.status === "stored" ? network.old_config : null;
    v.network_restricted = applied ? cidrsRestricted([obj(applied).dbAllowedCidrs, obj(applied).dbAllowedCidrsV6]) : null;
  }
  let addonPitr = null, backupsPitr = null;
  if (addons) {
    const selected = Array.isArray(addons.selected_addons) ? addons.selected_addons : null;
    if (selected) {
      const addon = selected.find((a) => obj(a).type === "pitr");
      addonPitr = Boolean(addon);
      const m = addon ? /^pitr_(\d{1,3})$/.exec(String(obj(obj(addon).variant).id)) : null;
      v.pitr_retention_days = addon ? (m ? int(m[1], 365) : null) : 0;
    }
  }
  if (backups) {
    backupsPitr = bool(backups.pitr_enabled);
    v.backups_enabled = bool(backups.walg_enabled);
  }
  // Leaning toward fail: off when either read clearly says off (even if the other failed); on only when both were
  // read and both say on; otherwise unknown.
  v.pitr_enabled = addonPitr === false || backupsPitr === false ? false
    : addonPitr === true && backupsPitr === true ? true : null;
  if (auth) {
    // A factor counts when both enrollment and verification are on for it.
    const factor = (enroll, verify) => allOf([bool(auth[enroll]), bool(auth[verify])]);
    const totp = factor("mfa_totp_enroll_enabled", "mfa_totp_verify_enabled");
    const webauthn = factor("mfa_web_authn_enroll_enabled", "mfa_web_authn_verify_enabled");
    v.auth_mfa_enabled = totp === true || webauthn === true ? true : totp === null || webauthn === null ? null : false;
    v.auth_webauthn_enabled = webauthn;
    v.leaked_password_protection = bool(auth.password_hibp_enabled);
    v.email_confirmation_required = not(bool(auth.mailer_autoconfirm));
    v.anonymous_sign_ins_enabled = bool(auth.external_anonymous_users_enabled);
    v.password_min_length = int(auth.password_min_length, 1024);
    v.otp_expiry_seconds = int(auth.mailer_otp_exp, 10_000_000);
    v.refresh_token_rotation = bool(auth.refresh_token_rotation_enabled);
    v.captcha_enabled = bool(auth.security_captcha_enabled);
  }
  return finish("supabase", v, reads);
}

// ---------------------------------------------------------------------------------------------------------------
// AWS SigV4 (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html)

const sha256hex = (s) => createHash("sha256").update(s, "utf8").digest("hex");
const hmac = (key, s) => createHmac("sha256", key).update(s, "utf8").digest();
// RFC 3986 unreserved characters stay; everything else is percent-encoded in upper case.
const uriEncode = (s) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

export function amzDate(date) {
  return date.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
}

/* Signs a request. query: [[name, value], ...]; headers: extra headers (host and x-amz-date are added). Returns the
 * headers to send (without host, which fetch sets from the URL), plus the intermediate strings for tests. */
export function signV4({ method = "GET", host, path = "/", query = [], headers = {}, body = "", region, service,
  accessKeyId, secretAccessKey, sessionToken = null, date }) {
  const stamp = amzDate(date), day = stamp.slice(0, 8);
  const all = {};
  for (const [k, val] of Object.entries(headers)) all[k.toLowerCase()] = String(val);
  all.host = host;
  all["x-amz-date"] = stamp;
  if (sessionToken) all["x-amz-security-token"] = sessionToken;
  const names = Object.keys(all).sort();
  const canonicalHeaders = names.map((n) => `${n}:${all[n].trim().replace(/\s+/g, " ")}\n`).join("");
  const signedHeaders = names.join(";");
  const canonicalQuery = query.map(([k, val]) => [uriEncode(k), uriEncode(val)])
    .sort((a, b) => cmp(a[0], b[0]) || cmp(a[1], b[1])).map(([k, val]) => `${k}=${val}`).join("&");
  const canonicalPath = path.split("/").map((seg) => uriEncode(seg)).join("/") || "/";
  const canonicalRequest = [method, canonicalPath, canonicalQuery, canonicalHeaders, signedHeaders, sha256hex(body)].join("\n");
  const scope = `${day}/${region}/${service}/aws4_request`;
  const stringToSign = ["AWS4-HMAC-SHA256", stamp, scope, sha256hex(canonicalRequest)].join("\n");
  const key = hmac(hmac(hmac(hmac(`AWS4${secretAccessKey}`, day), region), service), "aws4_request");
  const signature = createHmac("sha256", key).update(stringToSign, "utf8").digest("hex");
  const out = { ...all };
  delete out.host;
  out.authorization = `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
  return { headers: out, signature, canonicalRequest, stringToSign, canonicalQuery };
}

// ---------------------------------------------------------------------------------------------------------------
// AWS RDS

/* The text of the first <name>...</name> in xml (simple values only), or null. */
function xmlValue(xml, name) {
  const m = new RegExp(`<${name}>([^<]{0,512})</${name}>`).exec(xml);
  return m ? m[1].trim() : null;
}
const xmlBool = (s) => (s === "true" ? true : s === "false" ? false : null);
function xmlBlocks(xml, name) {
  const out = [];
  const re = new RegExp(`<${name}>([\\s\\S]*?)</${name}>`, "g");
  let m;
  while ((m = re.exec(xml)) && out.length < 10_000) out.push(m[1]);
  return out;
}

const RDS_ENGINES = { postgres: "postgres", "aurora-postgresql": "aurora_postgresql", mysql: "mysql", mariadb: "mariadb",
  "aurora-mysql": "aurora_mysql" };

async function rds(creds, get, now) {
  const host = `rds.${creds.region}.amazonaws.com`;
  const call = (read, params) => {
    const query = [["Action", read], ["Version", "2014-10-31"], ...params];
    const signed = signV4({ host, query, region: creds.region, service: "rds", accessKeyId: creds.accessKeyId,
      secretAccessKey: creds.secretAccessKey, sessionToken: creds.sessionToken, date: now() });
    return get(read, `https://${host}/?${signed.canonicalQuery}`, signed.headers, "text");
  };

  const described = await call("DescribeDBInstances", [["DBInstanceIdentifier", creds.instance]]);
  if (!described.ok) return result("rds", "failed", described.reason);
  const instance = xmlBlocks(described.data, "DBInstance")[0];
  if (instance === undefined) return result("rds", "failed", "not_found");
  // Pending changes repeat some names (BackupRetentionPeriod, EngineVersion): read the current values only.
  const current = instance.replace(/<PendingModifiedValues>[\s\S]*?<\/PendingModifiedValues>/g, "");

  const v = {};
  const engine = xmlValue(current, "Engine");
  v.engine = engine === null ? null : RDS_ENGINES[engine] ?? "other";
  v.postgres_major_version = engine === "postgres" || engine === "aurora-postgresql" ? major(xmlValue(current, "EngineVersion")) : null;
  v.storage_encrypted = xmlBool(xmlValue(current, "StorageEncrypted"));
  v.backup_retention_days = int(xmlValue(current, "BackupRetentionPeriod"), 35);
  v.backups_enabled = v.backup_retention_days === null ? null : v.backup_retention_days > 0;
  v.pitr_enabled = v.backups_enabled; // automated backups give point-in-time restore
  v.publicly_accessible = xmlBool(xmlValue(current, "PubliclyAccessible"));
  // Not public: reachable only inside the VPC. Public: the security groups decide, which this read can't see.
  v.network_restricted = v.publicly_accessible === false ? true : null;
  v.iam_auth_enabled = xmlBool(xmlValue(current, "IAMDatabaseAuthenticationEnabled"));
  v.deletion_protection = xmlBool(xmlValue(current, "DeletionProtection"));

  const reads = [described];
  if (v.engine === "postgres" || v.engine === "aurora_postgresql") await rdsLogs(creds, current, call, now, get, v, reads);
  else { v.log_export = null; v.log_retention = null; } // only a Postgres instance is in scope
  const groupBlock = xmlBlocks(current, "DBParameterGroup")[0];
  const group = groupBlock === undefined ? null : xmlValue(groupBlock, "DBParameterGroupName");
  // The group's values are in effect only when the instance is in-sync with it (not pending-reboot or applying).
  const inSync = groupBlock !== undefined && xmlValue(groupBlock, "ParameterApplyStatus") === "in-sync";
  if (group !== null && RDS_PARAMETER_GROUP.test(group)) {
    const wanted = { "rds.force_ssl": undefined, log_connections: undefined, log_disconnections: undefined };
    let marker = null, pages = 0, failed = null;
    do {
      const params = [["DBParameterGroupName", group], ["MaxRecords", "100"]];
      if (marker) params.push(["Marker", marker]);
      const page = await call("DescribeDBParameters", params);
      if (!page.ok) { failed = page; break; }
      for (const p of xmlBlocks(page.data, "Parameter")) {
        const name = xmlValue(p, "ParameterName");
        if (name !== null && Object.hasOwn(wanted, name)) wanted[name] = xmlValue(p, "ParameterValue");
      }
      const next = xmlValue(page.data.replace(/<Parameters>[\s\S]*<\/Parameters>/, ""), "Marker");
      marker = next && /^[\x21-\x7e]{1,1024}$/.test(next) ? next : null;
      pages += 1;
    } while (marker && pages < RDS_PARAMETER_PAGES);
    if (failed) reads.push(failed);
    else {
      reads.push({ read: "DescribeDBParameters", ok: true });
      if (!marker && inSync) { // a group read to the end and in effect: a parameter not listed stays unknown (null)
        v.ssl_enforced = wanted["rds.force_ssl"] == null ? null : pgSwitch(wanted["rds.force_ssl"]);
        v.log_connections = wanted.log_connections == null ? null : pgSwitch(wanted.log_connections, true);
        v.log_disconnections = wanted.log_disconnections == null ? null : pgSwitch(wanted.log_disconnections);
      } else if (marker) {
        reads[reads.length - 1] = { read: "DescribeDBParameters", ok: false, reason: "truncated" };
      }
    }
  }
  return finish("rds", v, reads);
}

/* The members of a <name><member>...</member></name> list, or [] when the list is absent (AWS leaves an empty list
 * out). */
function xmlMembers(xml, name) {
  const block = xmlBlocks(xml, name)[0];
  return block === undefined ? [] : xmlBlocks(block, "member").map((m) => m.trim());
}

/* A destination counts when it keeps the logs for any retention period, a day or more, or never
 * deletes them. There is no 365-day floor. */
const KEPT_DAYS = 1;

/* log_export and log_retention for one RDS instance, or, for an Aurora instance, its cluster (evaluator_api.md
 * section 1.7, aws): export on when postgresql is in EnabledCloudwatchLogsExports; retention read at the CloudWatch log
 * group the export writes to (/aws/rds/instance/<id>/postgresql or /aws/rds/cluster/<id>/postgresql): on with any
 * retention period set, or when it never expires (no retentionInDays). With export off there is no destination: retention not_read. */
async function rdsLogs(creds, current, call, now, get, v, reads) {
  v.log_export = null;
  v.log_retention = null;
  const cluster = xmlValue(current, "DBClusterIdentifier");
  let exports, group;
  if (cluster !== null) {
    if (!RDS_INSTANCE.test(cluster)) return;
    const described = await call("DescribeDBClusters", [["DBClusterIdentifier", cluster]]);
    reads.push(described.ok ? { read: "DescribeDBClusters", ok: true } : described);
    if (!described.ok) return;
    const block = xmlBlocks(described.data, "DBCluster")[0];
    if (block === undefined) return;
    exports = xmlMembers(block.replace(/<PendingModifiedValues>[\s\S]*?<\/PendingModifiedValues>/g, ""), "EnabledCloudwatchLogsExports");
    group = `/aws/rds/cluster/${cluster}/postgresql`;
  } else {
    exports = xmlMembers(current, "EnabledCloudwatchLogsExports");
    // The identifier as AWS stores it (lower case), from the response, not the configured spelling.
    const id = xmlValue(current, "DBInstanceIdentifier");
    if (id === null || !RDS_INSTANCE.test(id)) return;
    group = `/aws/rds/instance/${id}/postgresql`;
  }
  v.log_export = exports.includes("postgresql");
  if (!v.log_export) return; // no destination: retention stays not_read (section 1.7: off needs at least one)

  const host = `logs.${creds.region}.amazonaws.com`;
  let token = null, pages = 0, found = null;
  do {
    const payload = { logGroupNamePrefix: group, limit: 50 };
    if (token) payload.nextToken = token;
    const body = JSON.stringify(payload);
    const signed = signV4({ method: "POST", host, body, region: creds.region, service: "logs",
      headers: { "content-type": "application/x-amz-json-1.1", "x-amz-target": "Logs_20140328.DescribeLogGroups" },
      accessKeyId: creds.accessKeyId, secretAccessKey: creds.secretAccessKey, sessionToken: creds.sessionToken, date: now() });
    const page = await get("DescribeLogGroups", `https://${host}/`, signed.headers, "json", { method: "POST", body });
    if (!page.ok) { reads.push(page); return; }
    const groups = Array.isArray(obj(page.data).logGroups) ? page.data.logGroups : null;
    if (groups === null) { reads.push({ read: "DescribeLogGroups", ok: false, reason: "bad_response" }); return; }
    found = groups.find((g) => obj(g).logGroupName === group) ?? null;
    const next = obj(page.data).nextToken;
    token = !found && typeof next === "string" && /^[\x21-\x7e]{1,2048}$/.test(next) ? next : null;
    pages += 1;
  } while (token && pages < 10);
  if (token) { reads.push({ read: "DescribeLogGroups", ok: false, reason: "truncated" }); return; }
  reads.push({ read: "DescribeLogGroups", ok: true });
  if (!found) return; // the group the export writes to isn't there: no destination read
  const days = found.retentionInDays;
  if (days === undefined || days === null) v.log_retention = true; // never expires
  else if (Number.isInteger(days) && days > 0) v.log_retention = days >= KEPT_DAYS;
}


// ---------------------------------------------------------------------------------------------------------------
// Google Cloud log settings (Cloud SQL and Firebase; evaluator_api.md section 1.7, gcp and firebase)

/* A Cloud Logging filter, parsed for the subset this module can evaluate: LOG_ID("..."), resource.type and logName
 * compared with = or !=, NOT or a leading -, AND (or juxtaposition), OR and parentheses. AND and OR mixed at one level
 * without parentheses is refused (Logging gives OR the higher precedence; nothing here relies on it). Anything else
 * (a global search term, a label, severity, a regular expression, :) gives null: the filter can't be shown to cover
 * the logs, so a sink resting on it is never on. */
export function parseLogFilter(text) {
  if (typeof text !== "string" || text.length > 20_000) return null;
  const toks = [];
  let i = 0;
  while (i < text.length) {
    const c = text[i];
    if (/\s/.test(c)) { i++; continue; }
    if (c === "(" || c === ")") { toks.push({ t: c }); i++; continue; }
    if (c === '"') {
      const j = text.indexOf('"', i + 1);
      if (j < 0) return null;
      const v = text.slice(i + 1, j);
      if (v.includes("\\")) return null;
      toks.push({ t: "str", v });
      i = j + 1;
      continue;
    }
    if (text.startsWith("!=", i)) { toks.push({ t: "op", v: "!=" }); i += 2; continue; }
    if (c === "=" || c === ":") { toks.push({ t: "op", v: c }); i++; continue; }
    if (c === "-" && i + 1 < text.length && !/\s/.test(text[i + 1])) { toks.push({ t: "NOT" }); i++; continue; }
    const m = /^[A-Za-z0-9_.\/%]+/.exec(text.slice(i));
    if (!m) return null;
    const w = m[0];
    toks.push(w === "AND" || w === "OR" || w === "NOT" ? { t: w } : { t: "word", v: w });
    i += w.length;
  }
  let k = 0;
  const peek = () => toks[k];
  function seq() {
    const items = [unary()];
    const joins = new Set();
    while (peek() && peek().t !== ")") {
      if (peek().t === "OR") { k++; joins.add("OR"); }
      else { if (peek().t === "AND") k++; joins.add("AND"); }
      items.push(unary());
    }
    if (joins.size > 1) throw new Error("mixed");
    return items.length === 1 ? items[0] : { t: joins.has("OR") ? "or" : "and", args: items };
  }
  function unary() {
    const t = toks[k++];
    if (!t) throw new Error("end");
    if (t.t === "NOT") return { t: "not", arg: unary() };
    if (t.t === "(") { const e = seq(); if (!(toks[k] && toks[k].t === ")")) throw new Error("paren"); k++; return e; }
    if (t.t === "word" && t.v === "LOG_ID" && peek() && peek().t === "(") {
      k++;
      const a = toks[k++], b = toks[k++];
      if (!(a && a.t === "str" && b && b.t === ")")) throw new Error("log_id");
      return { t: "logid", v: a.v };
    }
    if (t.t === "word" && (t.v === "resource.type" || t.v === "logName")) {
      const op = toks[k++], val = toks[k++];
      if (!(op && op.t === "op" && val && (val.t === "str" || val.t === "word"))) throw new Error("field");
      return { t: "field", f: t.v, op: op.v, v: val.v };
    }
    throw new Error("term");
  }
  try {
    if (toks.length === 0) return { t: "all" };
    const e = seq();
    return k === toks.length ? e : null;
  } catch { return null; }
}

const decode = (v) => { try { return decodeURIComponent(v); } catch { return v; } };

/* Whether a parsed filter matches one log {logId, resourceType (null when not known here)} of project: true, false or
 * null (can't tell). */
function filterMatches(node, log, project) {
  if (node === null) return null;
  switch (node.t) {
    case "all": return true;
    case "and": return and3(node.args.map((a) => filterMatches(a, log, project)));
    case "or": return or3(node.args.map((a) => filterMatches(a, log, project)));
    case "not": return not3(filterMatches(node.arg, log, project));
    // Logging compares strings without regard to letter case.
    case "logid": return decode(node.v).toLowerCase() === log.logId.toLowerCase();
    case "field": {
      if (node.op === ":") return null;
      let eq;
      if (node.f === "resource.type") eq = log.resourceType === null ? null : node.v.toLowerCase() === log.resourceType.toLowerCase();
      else {
        const m = /^projects\/([^/]+)\/logs\/(.+)$/i.exec(node.v);
        eq = m && m[1].toLowerCase() === project.toLowerCase() ? decode(m[2]).toLowerCase() === log.logId.toLowerCase() : null;
      }
      return node.op === "!=" ? not3(eq) : eq;
    }
    default: return null;
  }
}

const GCP_NUMERIC_ID = /^[0-9]{1,20}$/;
const GCP_PROJECT_REF = /^(?:[a-z][a-z0-9-]{4,28}[a-z0-9]|[0-9]{1,20})$/;
const GCP_LOCATION = /^[a-z0-9-]{1,63}$/;
const GCP_LOG_BUCKET = /^[A-Za-z0-9_-][A-Za-z0-9_.-]{0,99}$/;
const GCS_BUCKET = /^[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]$/;
const BQ_DATASET = /^[A-Za-z0-9_]{1,1024}$/;
const PAGE_TOKEN = /^[A-Za-z0-9_\-=.~+\/]{1,4096}$/;
const DAY_MS = KEPT_DAYS * 86_400_000;
const GCP_PAGES = 10;

/* A sink destination: {kind, key, url?}. kind "bucket" (a log bucket; name kept to tell _Default and _Required),
 * "gcs", "bigquery", "stream" (Pub/Sub: what consumes it can't be read) or "unknown" (another project's log router, a
 * name this module won't put in a URL, anything else). */
function sinkDestination(dest) {
  if (typeof dest !== "string") return { kind: "unknown", key: "?" };
  let m = /^logging\.googleapis\.com\/projects\/([^/]+)\/locations\/([^/]+)\/buckets\/([^/]+)$/.exec(dest);
  if (m) {
    if (!GCP_PROJECT_REF.test(m[1]) || !GCP_LOCATION.test(m[2]) || !GCP_LOG_BUCKET.test(m[3])) return { kind: "unknown", key: dest };
    return { kind: "bucket", key: dest, name: m[3], url: `https://${LOGGING_HOST}/v2/projects/${m[1]}/locations/${m[2]}/buckets/${m[3]}` };
  }
  m = /^storage\.googleapis\.com\/([^/]+)$/.exec(dest);
  if (m) return GCS_BUCKET.test(m[1]) && !m[1].includes("..")
    ? { kind: "gcs", key: dest, url: `https://${STORAGE_HOST}/storage/v1/b/${m[1]}?fields=retentionPolicy,lifecycle` }
    : { kind: "unknown", key: dest };
  m = /^bigquery\.googleapis\.com\/projects\/([^/]+)\/datasets\/([^/]+)$/.exec(dest);
  if (m) return GCP_PROJECT_REF.test(m[1]) && BQ_DATASET.test(m[2])
    ? { kind: "bigquery", key: dest, url: `https://${BIGQUERY_HOST}/bigquery/v2/projects/${m[1]}/datasets/${m[2]}` }
    : { kind: "unknown", key: dest };
  if (/^pubsub\.googleapis\.com\//.test(dest)) return { kind: "stream", key: dest };
  return { kind: "unknown", key: dest };
}

/* A Cloud Storage bucket keeps its objects a day or more: a retention policy of a day or more, else no lifecycle
 * Delete rule that removes a live object within a day. A rule whose conditions this module can't settle gives null. */
export function gcsKeeps(b) {
  const period = obj(b.retentionPolicy).retentionPeriod;
  const seconds = typeof period === "string" && /^\d{1,15}$/.test(period) ? Number(period) : Number.isInteger(period) ? period : null;
  if (seconds !== null && seconds >= KEPT_DAYS * 86_400) return true;
  const lc = b.lifecycle;
  const rules = lc === undefined ? [] : Array.isArray(obj(lc).rule) ? lc.rule : obj(lc).rule === undefined ? [] : null;
  if (rules === null) return null;
  let unknown = false;
  for (const r of rules) {
    const type = obj(obj(r).action).type;
    if (type === "SetStorageClass" || type === "AbortIncompleteMultipartUpload") continue;
    if (type !== "Delete") { unknown = true; continue; }
    const c = obj(obj(r).condition);
    // Conditions that only match noncurrent versions never remove a live log object.
    if (c.isLive === false || "numNewerVersions" in c || "daysSinceNoncurrentTime" in c || "noncurrentTimeBefore" in c) continue;
    const age = Number.isInteger(c.age) && c.age >= 0 ? c.age : null;
    if (age !== null && age >= KEPT_DAYS) continue;
    if (age !== null && Object.keys(c).every((key) => key === "age" || (key === "isLive" && c.isLive === true))) return false;
    unknown = true;
  }
  return unknown ? null : true;
}

const msValue = (v) => (typeof v === "string" && /^\d{1,16}$/.test(v) ? Number(v) : Number.isInteger(v) && v >= 0 ? v : undefined);

/* A BigQuery dataset keeps sink tables a day or more: no default table or partition expiration under a day, and no
 * listed table expiring (from its creation) or dropping partitions sooner. */
export function bigqueryKeeps(dataset, tables) {
  for (const key of ["defaultTableExpirationMs", "defaultPartitionExpirationMs"]) {
    if (dataset[key] === undefined || dataset[key] === null) continue;
    const ms = msValue(dataset[key]);
    if (ms === undefined) return null;
    if (ms < DAY_MS) return false;
  }
  let unknown = false;
  for (const t of tables) {
    const tp = obj(obj(t).timePartitioning);
    if (tp.expirationMs !== undefined && tp.expirationMs !== null) {
      const ms = msValue(tp.expirationMs);
      if (ms === undefined) unknown = true; else if (ms < DAY_MS) return false;
    }
    if (obj(t).expirationTime !== undefined && obj(t).expirationTime !== null) {
      const exp = msValue(t.expirationTime), created = msValue(t.creationTime);
      if (exp === undefined || created === undefined) unknown = true; else if (exp - created < DAY_MS) return false;
    }
  }
  return unknown ? null : true;
}

/* The effective Data Access audit config for one service, the union of the audit configs up the resource ancestry
 * (project, folders, organization): true when DATA_READ and DATA_WRITE are on for the service (or allServices) at
 * some level with no member exempted from them at any level; false when one isn't on; null when a level couldn't be
 * read, or a member is exempted (whether it is the app's identity isn't known). */
function auditOn(policies, service) {
  if (policies.some((p) => p === null)) return null;
  const configs = policies.flatMap((p) => (Array.isArray(obj(p).auditConfigs) ? p.auditConfigs : []))
    .filter((c) => obj(c).service === service || obj(c).service === "allServices");
  const entries = configs.flatMap((c) => (Array.isArray(obj(c).auditLogConfigs) ? c.auditLogConfigs : []))
    .filter((e) => obj(e).logType === "DATA_READ" || obj(e).logType === "DATA_WRITE");
  if (!["DATA_READ", "DATA_WRITE"].every((t) => entries.some((e) => obj(e).logType === t))) return false;
  // An exempted member may or may not be the app's identity: not shown on for the in-scope logs (not off either).
  if (entries.some((e) => Array.isArray(obj(e).exemptedMembers) && e.exemptedMembers.length > 0)) return null;
  return true;
}

/* Lists every page of a Google list read: {ok, items} or the failed read (truncated past GCP_PAGES). */
async function listAll(get, read, url, field, headers, options = {}) {
  const items = [];
  let token = null;
  for (let page = 0; page < GCP_PAGES; page++) {
    const sep = url.includes("?") ? "&" : "?";
    const r = await get(read, token ? `${url}${sep}pageToken=${encodeURIComponent(token)}` : url, headers, "json", options);
    if (!r.ok) return r;
    const data = obj(r.data);
    if (data[field] !== undefined && !Array.isArray(data[field])) return { read, ok: false, reason: "bad_response" };
    items.push(...(data[field] ?? []));
    token = typeof data.nextPageToken === "string" && PAGE_TOKEN.test(data.nextPageToken) ? data.nextPageToken : null;
    if (!token) return { read, ok: true, items };
  }
  return { read, ok: false, reason: "truncated" };
}

const CLOUDSQL_LOGS = Object.freeze([
  { logId: "cloudsql.googleapis.com/postgres.log", resourceType: "cloudsql_database" },
  { logId: "cloudaudit.googleapis.com/data_access", resourceType: "cloudsql_database" },
]);
// Firestore's Data Access audit logs; their resource type isn't settled here, so a resource.type filter gives null.
const FIRESTORE_LOGS = Object.freeze([{ logId: "cloudaudit.googleapis.com/data_access", resourceType: null }]);

/* log_export and log_retention for a Google project. cloudsql: the Cloud SQL instance read is in scope; Firestore
 * is in scope when the project has a Firestore database (always looked up). Returns {values, reads}. */
async function gcpLogs({ token, project }, get, { cloudsql: withCloudsql }) {
  const headers = { authorization: `Bearer ${token}`, accept: "application/json" };
  const post = { ...headers, "content-type": "application/json" };
  const policyBody = JSON.stringify({ options: { requestedPolicyVersion: 3 } });
  const p = encodeURIComponent(project);
  const reads = [];
  const note = (r) => { reads.push(r.ok ? { read: r.read, ok: true } : { read: r.read, ok: false, reason: r.reason }); return r; };

  const [ancestry, projectPolicy, projectSinks, databases] = await Promise.all([
    get("getAncestry", `https://${CRM_HOST}/v1/projects/${p}:getAncestry`, post, "json", { method: "POST", body: "{}" }).then(note),
    get("getIamPolicy", `https://${CRM_HOST}/v1/projects/${p}:getIamPolicy`, post, "json", { method: "POST", body: policyBody }).then(note),
    listAll(get, "logging.sinks", `https://${LOGGING_HOST}/v2/projects/${p}/sinks?pageSize=200`, "sinks", headers).then(note),
    listAll(get, "firestore.databases", `https://${FIRESTORE_HOST}/v1/projects/${p}/databases`, "databases", headers,
      { disabledReason: true }).then(note),
  ]);

  // The ancestors above the project: folders and the organization, by numeric id.
  let ancestors = null;
  if (ancestry.ok) {
    const list = Array.isArray(obj(ancestry.data).ancestor) ? ancestry.data.ancestor : null;
    if (list) {
      ancestors = [];
      for (const a of list.slice(0, 50)) {
        const id = obj(obj(a).resourceId);
        if (id.type === "project") continue;
        if ((id.type === "folder" || id.type === "organization") && GCP_NUMERIC_ID.test(String(id.id))) ancestors.push({ type: id.type, id: String(id.id) });
        else { ancestors = null; break; }
      }
    }
    if (ancestors === null) reads[reads.findIndex((r) => r.read === "getAncestry")] = { read: "getAncestry", ok: false, reason: "bad_response" };
  }
  const plural = (a) => (a.type === "folder" ? "folders" : "organizations");
  const ancestorReads = ancestors === null ? [] : await Promise.all(ancestors.map(async (a) => {
    const [policy, sinks] = await Promise.all([
      get("getIamPolicy", `https://${CRM_HOST}/v3/${plural(a)}/${a.id}:getIamPolicy`, post, "json", { method: "POST", body: policyBody }).then(note),
      listAll(get, "logging.sinks", `https://${LOGGING_HOST}/v2/${plural(a)}/${a.id}/sinks?pageSize=200`, "sinks", headers).then(note),
    ]);
    return { policy, sinks };
  }));

  const policies = ancestors === null ? [null]
    : [projectPolicy.ok ? obj(projectPolicy.data) : null, ...ancestorReads.map((x) => (x.policy.ok ? obj(x.policy.data) : null))];
  // Every sink that routes the project's logs: the project's own, and an ancestor's that includes its children.
  const sinkLists = [projectSinks.ok ? projectSinks.items : null,
    ...ancestorReads.map((x) => (x.sinks.ok ? x.sinks.items.filter((sk) => obj(sk).includeChildren === true) : null))];
  // An ancestor sink with interceptChildren takes the logs it matches away from the project's own sinks.
  const intercepting = ancestorReads.flatMap((x) => (x.sinks.ok ? x.sinks.items : []))
    .filter((sk) => obj(sk).interceptChildren === true && obj(sk).disabled !== true);
  const complete = ancestors !== null && sinkLists.every((l) => l !== null);
  const sinks = sinkLists.filter((l) => l !== null).flat().map((sk) => {
    const x = obj(sk);
    const inclusion = x.filter === undefined || x.filter === "" ? { t: "all" } : parseLogFilter(x.filter);
    const exclusions = (Array.isArray(x.exclusions) ? x.exclusions : []).filter((e) => obj(e).disabled !== true)
      .map((e) => parseLogFilter(obj(e).filter));
    return { disabled: x.disabled === true, inclusion, exclusions, dest: sinkDestination(x.destination) };
  }).filter((sk) => !sk.disabled && !(sk.dest.kind === "bucket" && sk.dest.name === "_Required"));
  const covers = (sk, log) => and3([filterMatches(sk.inclusion, log, project),
    not3(or3(sk.exclusions.map((e) => filterMatches(e, log, project))))]);
  const interceptors = intercepting.map((sk) => ({
    inclusion: obj(sk).filter === undefined || obj(sk).filter === "" ? { t: "all" } : parseLogFilter(obj(sk).filter),
    exclusions: (Array.isArray(obj(sk).exclusions) ? sk.exclusions : []).filter((e) => obj(e).disabled !== true).map((e) => parseLogFilter(obj(e).filter)),
  }));

  // In-scope instances and their logs.
  const instances = [];
  if (withCloudsql) instances.push({ logs: CLOUDSQL_LOGS, service: "cloudsql.googleapis.com" });
  let firestoreCount = null;
  if (databases.ok) {
    firestoreCount = databases.items.length;
    if (firestoreCount > 0) instances.push({ logs: FIRESTORE_LOGS, service: "datastore.googleapis.com" });
  } else if (databases.serviceDisabled === true) {
    firestoreCount = 0; // the Firestore API is off (a 403 whose structured reason says so): no database in scope
  } else {
    // The Firestore list unread (any other 403 or error): the in-scope set isn't known, so neither setting can be on.
    // The Cloud SQL instance is still read, and an observed off still gives off (and3 with this unknown member).
    instances.push({ unknown: true });
  }

  // Read each destination that might receive an in-scope log.
  const wanted = new Map();
  for (const sk of sinks) {
    const relevant = instances.some((inst) => !inst.unknown && inst.logs.some((log) => covers(sk, log) !== false));
    if (relevant && ["bucket", "gcs", "bigquery"].includes(sk.dest.kind)) wanted.set(sk.dest.key, sk.dest);
  }
  const keeps = new Map(), deleted = new Set(), bucketRead = new Map();
  await Promise.all([...wanted.values()].slice(0, 50).map(async (d) => {
    if (d.kind === "bucket") {
      const r = note(await get("logging.buckets", d.url, headers));
      const data = r.ok ? obj(r.data) : {};
      if (r.ok && data.lifecycleState === "DELETE_REQUESTED") { deleted.add(d.key); return; } // receives nothing
      if (r.ok && data.lifecycleState !== undefined && data.lifecycleState !== "ACTIVE") { bucketRead.set(d.key, null); keeps.set(d.key, null); return; }
      bucketRead.set(d.key, r.ok ? true : null);
      const days = data.retentionDays;
      keeps.set(d.key, Number.isInteger(days) && days > 0 ? days >= KEPT_DAYS : null);
    } else if (d.kind === "gcs") {
      const r = note(await get("storage.buckets", d.url, headers));
      keeps.set(d.key, r.ok ? gcsKeeps(obj(r.data)) : null);
    } else {
      const [ds, tables] = await Promise.all([get("bigquery", d.url, headers),
        listAll(get, "bigquery", `${d.url}/tables?maxResults=1000`, "tables", headers)]);
      note(ds); note(tables);
      keeps.set(d.key, ds.ok && tables.ok ? bigqueryKeeps(obj(ds.data), tables.items) : null);
    }
  }));
  if (wanted.size > 50) reads.push({ read: "logging.buckets", ok: false, reason: "truncated" });
  const keepsOf = (d) => (keeps.has(d.key) ? keeps.get(d.key) : null);
  // A destination log_export counts: a log bucket, Cloud Storage or BigQuery; the _Default bucket only with its
  // retention observed (any period).
  // A log bucket counts only when read and active (a bucket pending deletion receives nothing).
  const exportCounts = (d) => (deleted.has(d.key) ? false
    : d.kind === "bucket" ? (d.name === "_Default" ? keepsOf(d) : bucketRead.has(d.key) ? bucketRead.get(d.key) : null)
    : d.kind === "gcs" || d.kind === "bigquery" ? true : d.kind === "stream" ? false : null);

  const exportOf = [], retentionOf = [];
  for (const inst of instances) {
    if (inst.unknown) { exportOf.push(null); retentionOf.push(null); continue; }
    const routed = inst.logs.map((log) => or3([...sinks.map((sk) => and3([covers(sk, log), exportCounts(sk.dest)])),
      ...(complete ? [] : [null])]));
    exportOf.push(and3([auditOn(policies, inst.service), and3(routed)]));
    const byDest = new Map();
    for (const sk of sinks) {
      const entry = byDest.get(sk.dest.key) ?? { dest: sk.dest, perLog: inst.logs.map(() => []) };
      inst.logs.forEach((log, i) => entry.perLog[i].push(covers(sk, log)));
      byDest.set(sk.dest.key, entry);
    }
    const destinations = [...byDest.values()].filter(({ dest }) => !deleted.has(dest.key)).map(({ dest, perLog }) => {
      const each = perLog.map((l) => or3(l));
      return { receivesAll: and3(each), receivesAny: or3(each),
        kind: dest.kind === "stream" ? "stream" : dest.kind === "unknown" ? "unknown" : "store", keeps: keepsOf(dest) };
    });
    retentionOf.push(instanceRetention({ destinations, complete }));
  }
  let logExport = and3(exportOf), logRetention = and3(retentionOf);
  // An intercepting ancestor sink that may match an in-scope log keeps it from the project's sinks: neither setting
  // can be read. Ancestor sink lists not read could hold one, so with an incomplete list neither is on.
  const known = instances.filter((inst) => !inst.unknown).flatMap((inst) => inst.logs);
  const intercepted = interceptors.some((sk) => known.some((log) => covers(sk, log) !== false));
  if (intercepted) { logExport = null; logRetention = null; }
  if (!complete) { if (logExport === true) logExport = null; if (logRetention === true) logRetention = null; }
  return { values: { log_export: logExport, log_retention: logRetention, firestore_database_count: firestoreCount }, reads };
}

// ---------------------------------------------------------------------------------------------------------------
// Cloud SQL

const SSL_MODES = ["ALLOW_UNENCRYPTED_AND_ENCRYPTED", "ENCRYPTED_ONLY", "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"];

async function cloudsql({ token, project, instance }, get) {
  const url = `https://${CLOUDSQL_HOST}/v1/projects/${encodeURIComponent(project)}/instances/${encodeURIComponent(instance)}`;
  const read = await get("instances.get", url, { authorization: `Bearer ${token}`, accept: "application/json" });
  if (!read.ok) return result("cloudsql", "failed", read.reason);
  const data = obj(read.data);
  // Check the shape before reading anything (storage_encrypted included): another body is not an instance.
  if (data.kind !== "sql#instance" || typeof data.databaseVersion !== "string") return result("cloudsql", "failed", "bad_response");
  const settings = obj(data.settings);
  const ip = obj(settings.ipConfiguration);
  const backup = obj(settings.backupConfiguration);
  const v = {};

  const dbv = typeof data.databaseVersion === "string" ? data.databaseVersion : null;
  v.engine = dbv === null ? null : dbv.startsWith("POSTGRES_") ? "postgres" : dbv.startsWith("MYSQL_") ? "mysql"
    : dbv.startsWith("SQLSERVER_") ? "sqlserver" : "other";
  v.postgres_major_version = v.engine === "postgres" ? major(dbv) : null;

  v.ssl_mode = oneOf(ip.sslMode, SSL_MODES);
  if (v.ssl_mode) v.ssl_enforced = v.ssl_mode !== "ALLOW_UNENCRYPTED_AND_ENCRYPTED";
  else if (ip.sslMode === undefined || ip.sslMode === "SSL_MODE_UNSPECIFIED") v.ssl_enforced = bool(ip.requireSsl) ?? (data.settings ? false : null);
  else v.ssl_enforced = null;

  v.public_ip_enabled = bool(ip.ipv4Enabled);
  const networks = ip.authorizedNetworks === undefined ? [] : Array.isArray(ip.authorizedNetworks) ? ip.authorizedNetworks : null;
  v.authorized_network_count = networks === null ? null : int(networks.length, 10_000);
  if (v.public_ip_enabled === false) v.network_restricted = true; // private IP only
  else if (v.public_ip_enabled === true && networks) v.network_restricted = cidrsRestricted([networks.map((n) => obj(n).value)]);

  v.backups_enabled = bool(backup.enabled);
  // pointInTimeRecoveryEnabled is the Postgres field (binaryLogEnabled is MySQL's); left out means off.
  if (v.engine === "postgres") v.pitr_enabled = backup.enabled === false ? false : bool(backup.pointInTimeRecoveryEnabled) ?? (data.settings ? false : null);
  v.transaction_log_retention_days = int(backup.transactionLogRetentionDays, 35);
  v.backup_retention_count = int(obj(backup.backupRetentionSettings).retainedBackups, 1000);

  v.storage_encrypted = true; // Cloud SQL always encrypts at rest
  v.storage_key = data.diskEncryptionConfiguration && obj(data.diskEncryptionConfiguration).kmsKeyName ? "customer_managed" : "platform_default";
  v.deletion_protection = bool(settings.deletionProtectionEnabled);

  const flags = Array.isArray(settings.databaseFlags) ? settings.databaseFlags : data.settings ? [] : null;
  if (flags) {
    const flag = (name) => { const f = flags.find((x) => obj(x).name === name); return f ? obj(f).value : undefined; };
    const pg = v.engine === "postgres";
    // A flag left out has the engine default: off for these on Cloud SQL for PostgreSQL.
    const read = (name, list) => (!pg ? null : flag(name) === undefined ? false : pgSwitch(flag(name), list));
    v.log_connections = read("log_connections", true);
    v.log_disconnections = read("log_disconnections");
    v.iam_auth_enabled = read("cloudsql.iam_authentication");
    v.pgaudit_enabled = read("cloudsql.enable_pgaudit");
  }
  const reads = [read];
  if (v.engine === "postgres") {
    const logs = await gcpLogs({ token, project }, get, { cloudsql: true });
    v.log_export = logs.values.log_export;
    v.log_retention = logs.values.log_retention;
    reads.push(...logs.reads);
  }
  return finish("cloudsql", v, reads);
}

// ---------------------------------------------------------------------------------------------------------------
// Firebase: the project's Firestore databases, read as gcp (evaluator_api.md section 1.7, firebase)

async function firebase({ token, project }, get) {
  const logs = await gcpLogs({ token, project }, get, { cloudsql: false });
  return finish("firebase", logs.values, logs.reads);
}


// ---------------------------------------------------------------------------------------------------------------
// Azure Database for PostgreSQL flexible server (evaluator_api.md section 1.7, azure)

const AZURE_API = Object.freeze({ server: "2022-12-01", diagnostic: "2021-05-01-preview", workspace: "2022-10-01",
  policy: "2023-01-01" });
const AZURE_ID_PREFIX = "^/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[-\\w.()]{1,90}/providers/";
const AZURE_WORKSPACE_ID = new RegExp(`${AZURE_ID_PREFIX}Microsoft\\.OperationalInsights/workspaces/[A-Za-z0-9-]{4,63}$`, "i");
const AZURE_STORAGE_ID = new RegExp(`${AZURE_ID_PREFIX}Microsoft\\.Storage/storageAccounts/[a-z0-9]{3,24}$`, "i");
// Diagnostic settings write PostgreSQLLogs to this container of a storage account.
const AZURE_LOG_CONTAINER = "insights-logs-postgresqllogs";

/* Whether a diagnostic setting sends PostgreSQLLogs: the category enabled, or the allLogs group enabled; the audit
 * group (whose members this module doesn't list) gives null. */
function sendsPostgresLogs(properties) {
  const logs = Array.isArray(properties.logs) ? properties.logs : [];
  const on = logs.filter((l) => obj(l).enabled === true);
  if (on.some((l) => l.category === "PostgreSQLLogs" || l.categoryGroup === "allLogs")) return true;
  if (on.some((l) => typeof l.categoryGroup === "string")) return null;
  return false;
}

/* A storage account's lifecycle management policy keeps the logs' container a day or more: no enabled rule that
 * applies to its append blobs deletes a base blob within a day. A filter this module can't settle (blob index tags, a blob
 * type list it can't read) gives null. */
export function azurePolicyKeeps(policy) {
  const rules = obj(obj(obj(policy).properties).policy).rules;
  if (!Array.isArray(rules)) return null;
  let unknown = false;
  for (const r of rules) {
    const rule = obj(r);
    if (rule.enabled === false) continue;
    const def = obj(rule.definition);
    const filters = obj(def.filters);
    if (filters.blobIndexMatch !== undefined) { unknown = true; continue; }
    if (!Array.isArray(filters.blobTypes)) { unknown = true; continue; }
    if (!filters.blobTypes.includes("appendBlob")) continue;
    const prefixes = filters.prefixMatch === undefined ? [] : Array.isArray(filters.prefixMatch) ? filters.prefixMatch : null;
    if (prefixes === null) { unknown = true; continue; }
    const container = `${AZURE_LOG_CONTAINER}/`;
    if (prefixes.length && !prefixes.some((pre) => typeof pre === "string" && (container.startsWith(pre) || pre.startsWith(container)))) continue;
    const del = obj(obj(def.actions).baseBlob).delete;
    if (del === undefined) continue;
    const days = Object.entries(obj(del)).filter(([k]) => /^daysAfter[A-Za-z]+GreaterThan$/.test(k));
    if (days.length === 0) { unknown = true; continue; }
    for (const [, v] of days) {
      if (!Number.isInteger(v) || v < 0) { unknown = true; continue; }
      if (v < KEPT_DAYS) return false;
    }
  }
  return unknown ? null : true;
}

/* The effective retention, in days, of the Log Analytics table holding PostgreSQLLogs: table-level retention overrides
 * the workspace default (evaluator_api.md 1.7), so the workspace's value counts only where the
 * table says it inherits it (retentionInDays -1, or retentionInDaysAsDefault true), and the total (with archive)
 * inherits the interactive value the same way. A table value that can't be read gives null (not_read), never the
 * workspace default: a 365-day workspace with a 30-day table is 30 days. */
export function azureTableRetention(tp, wp) {
  const days = (x) => Number.isInteger(x) && x >= 0;
  let interactive = null;
  if (tp.retentionInDaysAsDefault === true || tp.retentionInDays === -1) {
    interactive = days(wp.retentionInDays) ? wp.retentionInDays : null;
  } else if (days(tp.retentionInDays)) interactive = tp.retentionInDays;
  if (interactive === null) return null;
  if (days(tp.totalRetentionInDays) && tp.totalRetentionInDaysAsDefault !== true) return Math.max(tp.totalRetentionInDays, interactive);
  if (tp.totalRetentionInDays === -1 || tp.totalRetentionInDays === undefined || tp.totalRetentionInDaysAsDefault === true) return interactive;
  return null;
}

async function azure({ token, subscription, group, server }, get) {
  const headers = { authorization: `Bearer ${token}`, accept: "application/json" };
  const id = `/subscriptions/${subscription}/resourceGroups/${encodeURIComponent(group)}/providers/Microsoft.DBforPostgreSQL/flexibleServers/${server}`;
  const base = `https://${AZURE_HOST}`;
  const srv = await get("server", `${base}${id}?api-version=${AZURE_API.server}`, headers);
  if (!srv.ok) return result("azure", "failed", srv.reason);
  if (typeof obj(srv.data).type !== "string" || srv.data.type.toLowerCase() !== "microsoft.dbforpostgresql/flexibleservers") {
    return result("azure", "failed", "bad_response");
  }
  const reads = [srv];
  const v = { log_export: null, log_retention: null };
  const diag = await get("diagnosticSettings", `${base}${id}/providers/Microsoft.Insights/diagnosticSettings?api-version=${AZURE_API.diagnostic}`, headers);
  reads.push(diag.ok ? { read: "diagnosticSettings", ok: true } : diag);
  const list = diag.ok && Array.isArray(obj(diag.data).value) ? diag.data.value : null;
  if (diag.ok && list === null) reads[reads.length - 1] = { read: "diagnosticSettings", ok: false, reason: "bad_response" };
  if (list === null) return finish("azure", v, reads);

  // Every destination of a setting that sends, or might send, PostgreSQLLogs.
  const destinations = new Map();
  const add = (key, entry, sends) => {
    const prev = destinations.get(key);
    destinations.set(key, prev ? { ...prev, sends: or3([prev.sends, sends]) } : { ...entry, sends });
  };
  for (const setting of list.slice(0, 50)) {
    const props = obj(obj(setting).properties);
    const sends = sendsPostgresLogs(props);
    if (sends === false) continue;
    if (props.workspaceId !== undefined && props.workspaceId !== null) {
      if (typeof props.workspaceId === "string" && AZURE_WORKSPACE_ID.test(props.workspaceId)) {
        add(`w:${props.workspaceId.toLowerCase()}`, { kind: "workspace", id: props.workspaceId, dedicated: props.logAnalyticsDestinationType === "Dedicated" }, sends);
      } else add("unknown", { kind: "unknown" }, sends);
    }
    if (props.storageAccountId !== undefined && props.storageAccountId !== null) {
      if (typeof props.storageAccountId === "string" && AZURE_STORAGE_ID.test(props.storageAccountId)) {
        add(`s:${props.storageAccountId.toLowerCase()}`, { kind: "storage", id: props.storageAccountId }, sends);
      } else add("unknown", { kind: "unknown" }, sends);
    }
    if (props.eventHubAuthorizationRuleId) add(`e:${String(props.eventHubAuthorizationRuleId).toLowerCase()}`, { kind: "eventhub" }, sends);
    if (props.marketplacePartnerId) add(`m:${String(props.marketplacePartnerId).toLowerCase()}`, { kind: "unknown" }, sends);
  }
  const complete = list.length <= 50;
  if (!complete) reads.push({ read: "diagnosticSettings", ok: false, reason: "truncated" });

  // Read each destination: a workspace's retention (the PostgreSQLLogs table's effective retention, azureTableRetention) and
  // whether a transformation could drop logs; a storage account's lifecycle management policy.
  const resolved = await Promise.all([...destinations.values()].map(async (d) => {
    if (d.kind === "workspace") {
      const [ws, table] = await Promise.all([
        get("workspace", `${base}${d.id}?api-version=${AZURE_API.workspace}`, headers),
        d.dedicated ? Promise.resolve(null) : get("workspace.table", `${base}${d.id}/tables/AzureDiagnostics?api-version=${AZURE_API.workspace}`, headers),
      ]);
      reads.push(ws.ok ? { read: "workspace", ok: true } : ws);
      if (table) reads.push(table.ok ? { read: "workspace.table", ok: true } : table);
      const wp = ws.ok ? obj(obj(ws.data).properties) : null;
      // A workspace transformation (a default data collection rule) may drop rows: not shown to cover the logs.
      const filtered = wp === null ? null : wp.defaultDataCollectionRuleResourceId ? null : true;
      const days = wp && table && table.ok ? azureTableRetention(obj(obj(table.data).properties), wp) : null;
      // A daily cap stops ingestion once reached, so the destination may not keep every log: retention not_read.
      const quota = wp ? obj(wp.workspaceCapping).dailyQuotaGb : undefined;
      const capped = typeof quota === "number" && quota >= 0;
      return { ...d, covers: filtered, keeps: days === null || capped ? null : days >= KEPT_DAYS };
    }
    if (d.kind === "storage") {
      const r = await get("storage.managementPolicy", `${base}${d.id}/managementPolicies/default?api-version=${AZURE_API.policy}`, headers);
      // No policy (404): read as no policy read, which never qualifies (section 1.7), and isn't a failed read.
      if (!r.ok && r.reason === "not_found") { reads.push({ read: "storage.managementPolicy", ok: true }); return { ...d, covers: true, keeps: null }; }
      reads.push(r.ok ? { read: "storage.managementPolicy", ok: true } : r);
      return { ...d, covers: true, keeps: r.ok ? azurePolicyKeeps(r.data) : null };
    }
    if (d.kind === "eventhub") return { ...d, covers: true, keeps: null };
    return { ...d, covers: null, keeps: null };
  }));

  // log_export: some setting sends PostgreSQLLogs to a workspace (not shown to drop them), a storage account or an
  // event hub; off only when the list was read whole and no setting sends them.
  const exports = resolved.map((d) => and3([d.sends, d.covers]));
  v.log_export = or3([...exports, ...(complete ? [] : [null])]);
  if (resolved.length === 0 && complete) v.log_export = false;
  v.log_retention = instanceRetention({
    complete,
    destinations: resolved.map((d) => {
      const receives = and3([d.sends, d.covers]);
      return { receivesAll: receives, receivesAny: d.sends === false ? false : receives === false ? false : receives,
        kind: d.kind === "eventhub" ? "stream" : d.kind === "unknown" ? "unknown" : "store", keeps: d.keeps };
    }),
  });
  return finish("azure", v, reads);
}

// ---------------------------------------------------------------------------------------------------------------
// The fact document's platform block and collection entry (contracts/fact_document.schema.json, contract v2.1)

/* enums.PLATFORM_SETTINGS, in order: every key the schema requires. */
export const CONTRACT_KEYS = Object.freeze(["ssl_enforced", "network_restricted", "pitr_enabled", "high_compliance",
  "auth_mfa_enabled", "leaked_password_protection", "password_min_length_15", "password_min_length_8",
  "login_rate_limited", "org_mfa_enforced", "sso_idp_mfa", "storage_encrypted", "functions_verify_jwt",
  "realtime_private_only", "storage_public_access_blocked", "cloudsql_pgaudit_masking", "firestore_backups_scheduled",
  "log_export", "log_retention"]);
const FACT_PROVIDER = Object.freeze({ supabase: "supabase", rds: "aws", cloudsql: "gcp", azure: "azure", firebase: "firebase" });

const AWS_LOG_READS = ["DescribeDBInstances", "DescribeDBClusters", "DescribeLogGroups"];
const GCP_LOG_READS = ["getAncestry", "getIamPolicy", "logging.sinks", "logging.buckets", "storage.buckets", "bigquery",
  "firestore.databases"];
const AZURE_LOG_READS = ["server", "diagnosticSettings", "workspace", "workspace.table", "storage.managementPolicy"];

/* The reads each contract key rests on. null: the provider has no such setting (not_offered). []: no read here (no API
 * reads it, or this collector doesn't read it yet): always not_read, and it doesn't lower the collection status. A key
 * not listed for a provider is []. */
const CONTRACT_READS = Object.freeze({
  supabase: {
    ssl_enforced: ["ssl_enforcement"], network_restricted: ["network_restrictions"], pitr_enabled: ["addons", "backups"],
    high_compliance: [], auth_mfa_enabled: ["auth_config"], leaked_password_protection: ["auth_config"],
    // log_export (a log drain) has no Management API read this collector knows of; its retention is never offered.
    log_export: [], log_retention: null,
  },
  rds: {
    ssl_enforced: ["DescribeDBInstances", "DescribeDBParameters"], network_restricted: ["DescribeDBInstances"],
    pitr_enabled: ["DescribeDBInstances"], high_compliance: null, auth_mfa_enabled: null, leaked_password_protection: null,
    log_export: AWS_LOG_READS.slice(0, 2), log_retention: AWS_LOG_READS,
  },
  cloudsql: {
    ssl_enforced: ["instances.get"], network_restricted: ["instances.get"], pitr_enabled: ["instances.get"],
    high_compliance: null, auth_mfa_enabled: null, leaked_password_protection: null,
    log_export: ["instances.get", ...GCP_LOG_READS], log_retention: ["instances.get", ...GCP_LOG_READS],
  },
  firebase: { high_compliance: null, log_export: GCP_LOG_READS, log_retention: GCP_LOG_READS },
  azure: { high_compliance: null, log_export: AZURE_LOG_READS, log_retention: AZURE_LOG_READS },
});
const readsFor = (provider, key) => (Object.hasOwn(CONTRACT_READS[provider], key) ? CONTRACT_READS[provider][key] : []);

/* This module's reason codes to the contract's collection_reason enum. */
export function factReason(code) {
  if (code === "no_token" || code === "config_invalid") return "not_configured";
  if (code === "config_insecure") return "config_insecure"; // contract v1.1
  if (code === "http_401") return "auth_failed";
  if (code === "http_403") return "not_permitted"; // a valid token without the scope
  if (code === "http_429") return "rate_limited";
  if (code === "network_error" || /^http_5\d\d$/.test(code ?? "")) return "unreachable";
  if (code === "timeout") return "timeout";
  if (code === "too_large") return "size_limit";
  if (code === "truncated") return "item_limit";
  if (code === "not_found") return "platform_mismatch";
  return "internal_error"; // bad_response, another 4xx, anything unexpected
}

const SWITCH = (v) => (v === true ? "on" : v === false ? "off" : "not_read");

/* collectPlatform's result as {platform: {provider, settings}, collection: {collector, status, count, reason}}.
 * Status: ok only when every read a contract key rests on succeeded; truncated when some failed and others didn't
 * (reason: the first failed one's); failed and not_run as collected, with every setting not_read. count: the
 * contract settings read as on or off. Settings outside the contract stay in this module's result. */
export function toFactPlatform(res) {
  const provider = Object.hasOwn(FACT_PROVIDER, res?.provider) ? res.provider : null;
  const notRead = Object.fromEntries(CONTRACT_KEYS.map((k) => [k, "not_read"]));
  const platform = { provider: provider ? FACT_PROVIDER[provider] : "unknown", settings: notRead };
  if (!provider || res.status !== "ok") {
    const status = res?.status === "not_run" ? "not_run" : "failed";
    return { platform, collection: { collector: "platform", status, count: 0, reason: factReason(res?.reason) } };
  }
  const needed = new Set(CONTRACT_KEYS.flatMap((k) => readsFor(provider, k) ?? []));
  const failed = (Array.isArray(res.errors) ? res.errors : []).filter((e) => needed.has(e.read));
  const settings = {};
  for (const k of CONTRACT_KEYS) {
    const reads = readsFor(provider, k);
    settings[k] = reads === null ? "not_offered" : reads.length === 0 ? "not_read" : SWITCH(res.settings?.[k]);
  }
  const count = Object.values(settings).filter((v) => v === "on" || v === "off").length;
  platform.settings = settings;
  const collection = failed.length
    ? { collector: "platform", status: "truncated", count, reason: factReason(failed[0].reason) }
    : { collector: "platform", status: "ok", count, reason: null };
  return { platform, collection };
}

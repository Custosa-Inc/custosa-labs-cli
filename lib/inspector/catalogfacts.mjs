/* Contract v1.1 / v2.1 catalog facts: the new catalog queries' text, and the mapping from collectCatalog's result to the
 * fact document's `catalog` block and `catalog` collection entry (fact_document.schema.json at the evaluator
 * 1c7c1d9e, contract v2.1, copied in test/fixtures/contracts).
 *
 * V2_QUERIES: default_acl, schema_privileges, triggers, constraints, realtime_publication and connected_roles, each a
 * parameterless SELECT that passes checkShippedSql (catalog relations only, ALLOWED_FUNCTIONS only) with the
 * contract's row limit. Their text is the rule set's (rules/queries/<id>.sql, C1, shippedQuerySql),
 * the same files the hosted evaluator lists in its manifest; the row mapping is here. rls_policies.sql returns
 * `roles`, `using_expression` and `check_expression` (pg_get_expr of polqual and polwithcheck) beside the v1 columns.
 *
 * toFactCatalog(result, {key}) -> {catalog: {preflight, queries}, collection: {collector, status, count, reason}}
 *   - Names outside the pg_name pattern are sent as u_ plus 16 hex of HMAC-SHA256 (key: the per-install key).
 *   - rls_policies: the expressions are parsed here (policyexpr.mjs) into the eleven tri-state fields, then dropped;
 *     the column types of table_columns (when collected) decide whether a cast of a row column to an integer type
 *     is lossy.
 *   - connected_roles: application_name is bucketed (rule_bundle.md 5.1), never sent, and sessions summed per bucket.
 *   - A row with a value the contract can't carry (an unknown enum value, a dangling role, a list over its limit) is
 *     left out and its query is truncated with value_out_of_pattern; a row missing a column fails the query
 *     (internal_error). Nothing is filled in with a default: what wasn't read is not_read, failed or not sent.
 *   - The v1 queries are mapped from their row schemas (V1_QUERY_IDS, below). A query id this module has no row
 *     mapping for is left out of `queries`, which the contract reads as failed.
 *   - onRow(query_id, raw, mapped), when given, sees each kept row with its raw values (the column classifier reads
 *     the names before they are hashed); the raw values never leave this process. */
import { hashed, holdsRecordValue } from "./ids.mjs";
import { readFileSync } from "node:fs";
import { CONNECTED_APPLICATION_PREFIXES, PG_NAME } from "./contracts.mjs";
import { policyFields, POLICY_FIELDS, usingBranches } from "./policyexpr.mjs";
import { FACT_SCHEMA, subValidator } from "./schema.mjs";

export const QUERY_ROW_LIMITS = {
  rls_policies: 10000, default_acl: 2000, schema_privileges: 2000, triggers: 10000,
  constraints: 20000, realtime_publication: 10000, connected_roles: 500,
}; // the v1 queries' limits are added from the schema below (frozen there)

/* The shipped query text, as the rule set in this package holds it (rules/queries/<query_id>.sql, copied from the
 * hosted rule set by scripts/sync-rules.mjs and listed with its sha256 in rules/manifest.json). */
const QUERIES_DIR = new URL("../../rules/queries/", import.meta.url);
export function shippedQuerySql(queryId) {
  if (!/^[a-z_]{1,40}$/.test(queryId)) throw new Error("invalid query id");
  return readFileSync(new URL(`${queryId}.sql`, QUERIES_DIR), "utf8");
}

export const V2_QUERIES = Object.freeze(
  ["default_acl", "schema_privileges", "triggers", "constraints", "realtime_publication", "connected_roles"]
    .map((id) => Object.freeze({ query_id: id, row_limit: QUERY_ROW_LIMITS[id], sql: shippedQuerySql(id) })),
);

/* ---------------------------------------------------------------- names */

const PG_NAME_RE = new RegExp(PG_NAME);

/* A name as it is sent: as it is when it fits pg_name, else hashed. A name the evaluator's value screen would refuse
 * (an email, a phone number, a long number, ...) is hashed too, the same way captures.mjs hashes a table name
 * in code, so the two still compare. */
const screenName = (v, key) => (PG_NAME_RE.test(v) && !holdsRecordValue(v) ? v : hashed(key, v));

class Drop extends Error {} // the row holds a value the contract can't carry: leave it out
class Missing extends Error {} // the row lacks a column, or a column has the wrong type: the query fails
const drop = () => { throw new Drop(); };
const missing = () => { throw new Missing(); };

function col(row, k) {
  if (!Object.hasOwn(row, k)) missing();
  return row[k];
}

function nameOf(v, key) {
  if (v === null || v === undefined) drop(); // a dangling oid (a dropped role): not observed
  if (typeof v !== "string") missing();
  if (v === "") drop();
  return screenName(v, key);
}

function bool(v) { if (typeof v !== "boolean") missing(); return v; }

function oneOf(v, allowed) {
  if (v === null) drop();
  if (typeof v !== "string") missing();
  if (!allowed.includes(v)) drop();
  return v;
}

function list(v, max) {
  if (!Array.isArray(v)) missing();
  if (v.length > max) drop();
  return v;
}

/* ---------------------------------------------------------------- rows per query */

export function bucketApplication(name) {
  const n = String(name ?? "").trim().toLowerCase();
  if (n === "") return "none";
  for (const [bucket, prefixes] of CONNECTED_APPLICATION_PREFIXES) if (prefixes.some((p) => n.startsWith(p))) return bucket;
  return "other";
}

const COMMANDS = ["select", "insert", "update", "delete", "all"];
const PRIVILEGES = ["select", "insert", "update", "delete", "truncate", "references", "trigger", "usage", "execute",
  "create", "maintain"];

/* The columns a policy's tenant equalities use (policyexpr), kept on the mapped row as a non-enumerable property for
 * the observed tenancy: never serialised, never sent. */
const withTenantColumns = (fields, row) => Object.defineProperty(row, "tenantColumns", { value: fields.tenantColumns ?? [], enumerable: false });

const ROW = {
  rls_policies(r, key, ctx) {
    const roles = [...new Set(list(col(r, "roles"), 100).map((x) => nameOf(x, key)))];
    if (roles.length === 0) drop();
    const routes = list(col(r, "trusted_routes"), 3);
    if (routes.some((x) => !["s", "u", "m"].includes(x))) drop();
    const command = oneOf(col(r, "command"), COMMANDS);
    const using = col(r, "using_expression"), check = col(r, "check_expression");
    if (!(using === null || typeof using === "string") || !(check === null || typeof check === "string")) missing();
    // The policy's table's column types (table_columns), for the lossy integer cast rule; the text stays here.
    const opts = { casts: ctx.casts, columns: ctx.columns(col(r, "schema_name"), col(r, "table_name")) };
    const fields = policyFields({ command, using, check }, opts);
    return withTenantColumns(fields, {
      schema_name: nameOf(col(r, "schema_name"), key), table_name: nameOf(col(r, "table_name"), key),
      policy_name: nameOf(col(r, "policy_name"), key), command, permissive: bool(col(r, "permissive")),
      always_true: bool(col(r, "always_true")), reads_user_metadata: bool(col(r, "reads_user_metadata")),
      trusted_routes: [...new Set(routes)], owner_match: bool(col(r, "owner_match")), roles,
      ...Object.fromEntries(POLICY_FIELDS.map((f) => [f, fields[f]])),
      // T29-P1-C35: the column the policy compares with the caller (policyexpr ownerColumn), a name only, sent in the
      // same form as table_columns' column_name; null when the policy names none for sure.
      owner_column: typeof fields.ownerColumn === "string" ? nameOf(fields.ownerColumn, key) : null,
      // T29 h4b (T29-P3-C215): one word per top-level OR branch of USING (policyexpr usingBranches), or null. Words
      // only: the expression text stays here. The table name is the raw one, as pg_get_expr prints outer references.
      using_branches: usingBranches(using, col(r, "table_name"), opts),
    });
  },
  default_acl(r, key) {
    const schema = col(r, "schema_name");
    const privileges = [...new Set(list(col(r, "privileges"), 11).map((p) => oneOf(p, PRIVILEGES)))].sort();
    if (privileges.length === 0) drop();
    return {
      schema_name: schema === null ? null : nameOf(schema, key),
      object_type: oneOf(col(r, "object_type"), ["table", "sequence", "function", "type", "schema"]),
      grantor: nameOf(col(r, "grantor"), key), grantee: nameOf(col(r, "grantee"), key), privileges,
      // core reads true as a Data API grantee and false as a known non-API one. A missing, null or
      // non-boolean flag stays unset, never false, so core keeps a grantee it can't place for a person.
      ...(typeof r.api_grantee === "boolean" && Object.hasOwn(r, "api_grantee") ? { api_grantee: r.api_grantee } : {}),
    };
  },
  schema_privileges(r, key) {
    return { schema_name: nameOf(col(r, "schema_name"), key), grantee: nameOf(col(r, "grantee"), key),
      usage: bool(col(r, "usage")), create: bool(col(r, "create")) };
  },
  triggers(r, key) {
    const events = list(col(r, "events"), 4).map((e) => oneOf(e, ["insert", "update", "delete", "truncate"]));
    if (events.length === 0 || new Set(events).size !== events.length) drop();
    return {
      schema_name: nameOf(col(r, "schema_name"), key), table_name: nameOf(col(r, "table_name"), key),
      trigger_name: nameOf(col(r, "trigger_name"), key),
      timing: oneOf(col(r, "timing"), ["before", "after", "instead_of"]), events,
      enabled: oneOf(col(r, "enabled"), ["origin", "always", "replica", "disabled"]),
    };
  },
  constraints(r, key) {
    const type = oneOf(col(r, "type"), ["primary", "unique", "foreign", "check", "exclusion", "unique_index"]);
    const rs = col(r, "referenced_schema"), rn = col(r, "referenced_name");
    let referenced_table = null;
    if (type === "foreign") referenced_table = `${nameOf(rs, key)}.${nameOf(rn, key)}`;
    else if (rs !== null || rn !== null) drop();
    return {
      schema_name: nameOf(col(r, "schema_name"), key), table_name: nameOf(col(r, "table_name"), key),
      constraint_name: nameOf(col(r, "constraint_name"), key), type,
      columns: list(col(r, "columns"), 64).map((c) => nameOf(c, key)),
      expression: bool(col(r, "expression")), partial: bool(col(r, "partial")), referenced_table,
    };
  },
  realtime_publication(r, key) {
    return { publication: nameOf(col(r, "publication"), key), schema_name: nameOf(col(r, "schema_name"), key),
      table_name: nameOf(col(r, "table_name"), key) };
  },
  connected_roles(r, key) {
    const app = col(r, "application_name"), sessions = col(r, "sessions");
    if (!(app === null || typeof app === "string")) missing();
    if (!Number.isInteger(sessions)) missing();
    if (sessions < 1) drop();
    return { role_name: nameOf(col(r, "role_name"), key), application: bucketApplication(app), sessions };
  },
};

/* ---------------------------------------------------------------- the v1 queries
 *
 * The fourteen v1 queries (rls_status, table_grants, table_columns, ...) return exactly their row schema's columns
 * (rule_bundle.md section 5), so their rows are mapped from the schema itself: a name (pg_name, a part of a
 * qualified_name, a bucket id) outside its pattern is hashed, a data type outside the data_type forms is hashed as one
 * name, and every other value (booleans, integers, enums, settings) must already fit its property or the row is left
 * out (value_out_of_pattern). A column missing from the row fails the query. The mapped row is then checked against
 * the whole row schema; a row that still doesn't fit is left out. Nothing is filled in. */
export const V1_QUERY_IDS = Object.freeze(["rls_status", "table_grants", "table_columns", "views", "definer_functions",
  "exposed_schemas", "roles", "storage_buckets", "transport", "logging", "audit", "self_hosted", "advisor"]); // hba_rules left the contract
const DATA_TYPE_RE = new RegExp(FACT_SCHEMA.$defs.data_type.pattern);
const BUCKET_RE = new RegExp(FACT_SCHEMA.$defs.bucket_id.pattern);
const refName = (s) => (s && typeof s.$ref === "string" ? s.$ref.replace("#/$defs/", "") : null);

/* One value by its property schema: {ref} names map, anything else must validate as it is. */
function mapValue(value, prop, key, pointer) {
  if (Array.isArray(prop.anyOf)) {
    if (value === null && prop.anyOf.some((a) => a.type === "null")) return null;
    const ref = prop.anyOf.map(refName).find(Boolean);
    return ref ? mapRef(value, ref, key) : checked(value, pointer, prop);
  }
  const ref = refName(prop);
  if (ref) return mapRef(value, ref, key);
  if (prop.items && refName(prop.items) && (value === null || Array.isArray(value))) {
    if (value === null) return checked(value, pointer);
    if (Number.isInteger(prop.maxItems) && value.length > prop.maxItems) drop();
    const out = value.map((v) => mapRef(v, refName(prop.items), key));
    return prop.uniqueItems ? [...new Set(out)] : out;
  }
  return checked(value, pointer, prop);
}

function mapRef(value, ref, key) {
  if (ref === "pg_name" || ref === "identifier") return nameOf(value, key);
  if (ref === "qualified_name") {
    if (typeof value !== "string") missing();
    const dot = value.indexOf(".");
    if (dot <= 0 || dot === value.length - 1) drop();
    return `${nameOf(value.slice(0, dot), key)}.${nameOf(value.slice(dot + 1), key)}`;
  }
  if (ref === "data_type") return fitsOrHashed(value, (v) => DATA_TYPE_RE.test(v) && v.length <= 120, key);
  if (ref === "bucket_id") return fitsOrHashed(value, (v) => BUCKET_RE.test(v), key);
  return checked(value, `#/$defs/${ref}`);
}

/* A string value sent as it is when it fits, else hashed as one name; an empty one leaves the row out. */
function fitsOrHashed(value, fits, key) {
  if (typeof value !== "string") missing();
  if (value === "") drop();
  return fits(value) ? value : hashed(key, value);
}

/* node-postgres returns a bigint (int8) column as a string: an integer property takes it as a number when it is a
 * whole number Number can hold exactly (storage_buckets.file_size_limit), else the row is left out. */
function bigintToNumber(value, prop) {
  if (typeof value !== "string" || !prop) return value;
  const types = [].concat(prop.type ?? []);
  if (!types.includes("integer") || !/^-?[0-9]{1,20}$/.test(value)) return value;
  const n = Number(value);
  return Number.isSafeInteger(n) ? n : drop();
}

function checked(value, pointer, prop = null) {
  if (value === undefined) missing();
  const v = bigintToNumber(value, prop);
  if (!subValidator(pointer)(v)) drop();
  return v;
}

function v1Row(queryId) {
  const def = FACT_SCHEMA.$defs[`row_${queryId}`];
  const base = `#/$defs/row_${queryId}`;
  return (r, key) => {
    const out = {};
    for (const [k, prop] of Object.entries(def.properties)) out[k] = mapValue(col(r, k), prop, key, `${base}/properties/${k}`);
    if (!subValidator(base)(out)) drop();
    return out;
  };
}
for (const id of V1_QUERY_IDS) ROW[id] = v1Row(id);
for (const id of V1_QUERY_IDS) QUERY_ROW_LIMITS[id] = FACT_SCHEMA.$defs[`query_${id}`].properties.rows.maxItems;
Object.freeze(QUERY_ROW_LIMITS);

/* connected_roles rows summed per (role, bucket): the SQL groups by the raw name, which isn't sent. */
function mergeConnected(rows) {
  const by = new Map();
  for (const r of rows) {
    const k = `${r.role_name}\u0000${r.application}`;
    const prev = by.get(k);
    by.set(k, prev ? { ...prev, sessions: Math.min(100000, prev.sessions + r.sessions) } : { ...r, sessions: Math.min(100000, r.sessions) });
  }
  return [...by.values()].sort((a, b) => (a.role_name < b.role_name ? -1 : a.role_name > b.role_name ? 1
    : a.application < b.application ? -1 : a.application > b.application ? 1 : 0));
}

/* ---------------------------------------------------------------- reasons */

export function catalogReason(code) {
  switch (code) {
    case "timeout": case "lock_timeout": return "timeout";
    case "auth_failed": return "auth_failed";
    case "unreachable": case "tls_failed": return "unreachable";
    case "tls_required": return "tls_required";
    case "permission_denied": case "row_security_filtered": return "not_permitted";
    case "platform_mismatch": return "platform_mismatch";
    case "preflight_failed": case "session_guard": case "wrong_user": return "preflight_failed";
    case "service_missing": case "database_missing": return "not_configured";
    case "config_insecure": return "config_insecure";
    default: return "internal_error"; // invalid_query, denied_reference, query_error, connect_failed, anything else
  }
}

/* ---------------------------------------------------------------- the preflight */

const PREFLIGHT_KEYS = ["role", "session_user", "database", "system_identifier", "settings_mismatched", "superuser",
  "bypassrls", "replication", "createrole", "readable_tables", "public_readable_tables", "writable_tables",
  "extension_relations_readable",
  "catalog_tables", "predefined_roles", "dangerous_functions", "catalog_extensions", "owned_objects", "large_objects",
  "definer_functions_executable", "passed", "failed"];
const PREFLIGHT_ORDER = ["connect", "role", "session_user", "settings", "superuser", "bypassrls", "replication",
  "createrole", "readable_tables", "catalog_tables", "predefined_roles", "dangerous_functions", "catalog_extensions",
  "ownership", "large_objects", "write_privileges"];

function factPreflight(p, key) {
  const none = Object.fromEntries(PREFLIGHT_KEYS.map((k) => [k, null]));
  if (!p || p.role === null || p.role === undefined) return { ...none, passed: false, failed: ["connect"] }; // no connection
  const name = (v) => (typeof v === "string" && v !== "" ? screenName(v, key) : null);
  const count = (v) => (Number.isInteger(v) && v >= 0 ? Math.min(v, 1000000) : null);
  const flag = (v) => (typeof v === "boolean" ? v : null);
  const arr = (v, f) => (Array.isArray(v) ? [...new Set(v.map(f))] : null);
  const qualified = (s) => {
    const dot = String(s).lastIndexOf("."); // schema.relation; each part screened as a name
    return dot <= 0 ? null : `${name(s.slice(0, dot))}.${name(s.slice(dot + 1))}`;
  };
  const out = {
    role: name(p.role), session_user: name(p.session_user), database: name(p.database),
    system_identifier: typeof p.system_identifier === "string" && /^-?[0-9]{1,20}$/.test(p.system_identifier) ? p.system_identifier : null,
    settings_mismatched: arr(p.settings_mismatched, String),
    superuser: flag(p.superuser), bypassrls: flag(p.bypassrls), replication: flag(p.replication), createrole: flag(p.createrole),
    readable_tables: count(p.readable_tables), public_readable_tables: count(p.public_readable_tables),
    writable_tables: count(p.writable_tables),
    // T29-P1-C189 item 3: writes beyond PUBLIC's grants, PUBLIC's default write grants, PUBLIC's CREATE in schema
    // public (catalog.mjs public_writes). Sent only with a connection; core reads them only when write_privileges is the
    // one failed check.
    writable_beyond_public: count(p.public_writes?.beyond_public),
    public_write_defaults: count(p.public_writes?.default_privileges),
    public_schema_create: flag(p.public_writes?.schema_public_create),
    extension_relations_readable: arr(p.extension_relations_readable, qualified)?.filter((x) => x !== null).slice(0, 100) ?? null,
    catalog_tables: arr(p.catalog_tables, String), predefined_roles: arr(p.predefined_roles, String),
    dangerous_functions: arr(p.dangerous_functions, String),
    catalog_extensions: arr(p.catalog_extensions, name)?.filter((x) => x !== null).slice(0, 100) ?? null,
    owned_objects: count(p.owned_objects), large_objects: flag(p.large_objects),
    definer_functions_executable: count(p.definer_functions_executable),
  };
  const failed = PREFLIGHT_ORDER.filter((c) => Array.isArray(p.failed) && p.failed.includes(c));
  const unknown = !Array.isArray(p.failed) || p.failed.some((c) => !PREFLIGHT_ORDER.includes(c));
  const passed = p.passed === true && failed.length === 0 && !unknown;
  // A failure the contract can't name, or a preflight that didn't pass yet names no check: refused as unread.
  if (unknown || (!passed && failed.length === 0)) return { ...none, passed: false, failed: ["connect"] };
  return { ...out, passed, failed };
}

/* ---------------------------------------------------------------- the block */

export function toFactCatalog(result, { key, onRow = null } = {}) {
  if (!key) throw new TypeError("toFactCatalog needs the per-install key");
  const res = result && typeof result === "object" ? result : { status: "failed", reason: "internal_error" };
  const preflight = factPreflight(res.preflight, key);
  // How policy expressions may read casts (policyexpr.mjs): a cast someone defined to a looked-through type turns
  // look-through off, an implicit one (pg_get_expr hides implicit casts) makes every parsed field not_read, and a
  // check that wasn't read counts as the worst case.
  const uc = res.preflight && res.preflight.user_casts;
  const isCount = (v) => Number.isInteger(v) && v >= 0;
  // A user-defined = or <> on those types (pg_get_expr hides which = an IS NOT DISTINCT FROM uses) is unread too.
  const uo = res.preflight && res.preflight.user_operators;
  const casts = !(uc && isCount(uc.any) && isCount(uc.implicit)) || uc.implicit > 0 || !isCount(uo) || uo > 0 ? "unread"
    : uc.any > 0 ? "none" : "lossless";
  // Column types from the table_columns rows collected (the bundle's query: schema_name, table_name, column_name,
  // data_type), by table; a table or column not among them has no known type, so a cast of it to an integer type is
  // read as lossy (not_read).
  const columnsByTable = new Map();
  const tc = (Array.isArray(res.queries) ? res.queries : []).find((q) => q && q.query_id === "table_columns"
    && ["ok", "empty", "truncated"].includes(q.status) && Array.isArray(q.rows));
  for (const r of tc ? tc.rows : []) {
    if (!r || ![r.schema_name, r.table_name, r.column_name, r.data_type].every((v) => typeof v === "string")) continue;
    const k = `${r.schema_name}\u0000${r.table_name}`;
    if (!columnsByTable.has(k)) columnsByTable.set(k, new Map());
    columnsByTable.get(k).set(r.column_name, r.data_type);
  }
  const ctx = { casts, columns: (schema, table) => columnsByTable.get(`${schema}\u0000${table}`) ?? null };
  // Without a passed preflight: the connection's failure when there was none, else preflight_failed.
  const notRunReason = preflight.failed.includes("connect") ? catalogReason(res.reason) : "preflight_failed";
  const queries = [];
  for (const q of Array.isArray(res.queries) ? res.queries : []) {
    const shape = q && Object.hasOwn(ROW, q.query_id) ? ROW[q.query_id] : null;
    if (!shape || queries.some((x) => x.query_id === q.query_id)) continue;
    const raws = [];
    const entry = (status, reason, rows = []) => {
      queries.push({ query_id: q.query_id, status, reason, rows });
      // The kept rows only, once the query's outcome is settled (merged connected_roles rows have no single raw row).
      if (onRow && q.query_id !== "connected_roles") rows.forEach((m, i) => onRow(q.query_id, raws[i], m));
    };
    if (!preflight.passed) { entry("not_run", notRunReason); continue; } // no query runs without a passed preflight
    if (q.status === "not_run") { entry("not_run", catalogReason(q.reason ?? res.reason)); continue; }
    if (q.status === "failed") { entry("failed", catalogReason(q.reason)); continue; }
    if (!["ok", "empty", "truncated"].includes(q.status) || !Array.isArray(q.rows)) { entry("failed", "internal_error"); continue; }
    let rows = [], dropped = false;
    try {
      for (const r of q.rows) {
        if (!r || typeof r !== "object") throw new Missing();
        try { rows.push(shape(r, key, ctx)); raws.push(r); } catch (err) { if (err instanceof Drop) dropped = true; else throw err; }
      }
    } catch (err) {
      if (err instanceof Missing) { entry("failed", "internal_error"); continue; }
      throw err;
    }
    if (q.query_id === "connected_roles") rows = mergeConnected(rows);
    const limit = QUERY_ROW_LIMITS[q.query_id];
    if (rows.length > limit) { rows = rows.slice(0, limit); entry("truncated", "row_limit", rows); continue; }
    // A truncation's own reason: row-level security filtering storage.buckets is not_permitted, else row_limit.
    if (q.status === "truncated") entry("truncated", q.reason === "row_security_filtered" ? "not_permitted" : "row_limit", rows);
    else if (dropped) entry("truncated", "value_out_of_pattern", rows);
    else if (rows.length === 0) entry("empty", null);
    else entry("ok", null, rows);
  }

  let collection;
  if (!preflight.passed || res.status === "not_run") {
    const reason = res.reason === "no_queries" ? "internal_error" : notRunReason;
    collection = { collector: "catalog", status: res.status === "not_run" ? "not_run" : "failed", count: 0, reason };
  } else {
    // Every query reports its own status. The schema holds the two levels consistent (evaluator_api.md section 5): the
    // collector is truncated only when some query is, or the check's time budget left a query not_run (timeout), and
    // then never ok (T19, audit B3): the run was cut by time. A query that failed or didn't run for another reason
    // keeps its own status beside an ok collector, and the evaluator reads each query as the worse of the two, so it
    // is never read as collected.
    const count = queries.filter((q) => q.status === "ok" || q.status === "empty").length;
    const cut = queries.find((q) => q.status === "truncated");
    if (queries.some((q) => q.status === "not_run" && q.reason === "timeout")) {
      collection = { collector: "catalog", status: "truncated", count, reason: "timeout" };
    } else if (cut) {
      collection = { collector: "catalog", status: "truncated", count, reason: cut.reason }; // a truncated query's own reason
    } else if (queries.some((q) => q.status !== "ok" && q.status !== "empty")) {
      collection = { collector: "catalog", status: "ok", count, reason: null };
    } else {
      const empty = queries.length > 0 && queries.every((q) => q.status === "empty");
      collection = { collector: "catalog", status: empty ? "empty" : "ok", count, reason: null };
    }
  }
  return { catalog: { preflight, queries }, collection };
}

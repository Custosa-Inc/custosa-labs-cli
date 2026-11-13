/* Contract v2.1 catalog facts without a database: the policy expression parser and its fuzzing, the connected_roles
 * buckets, the preflight's write_privileges check, the contract patterns, and toFactCatalog against the v2 schema
 * (fixtures/contracts/fact_document.schema.07ff6ab0.json, a byte-for-byte copy of the evaluator's fact schema). */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import Ajv2020Module from "ajv/dist/2020.js";
import { policyFields, parseExpression, tokenize, POLICY_FIELDS, MAX_EXPRESSION_LENGTH, TENANT_KEYS, TRUSTED_OWNER_SOURCES, LOSSLESS_CASTS,
  LOSSY_INTEGER_TARGETS, LOSSY_INTEGER_SOURCES, UNTRUSTED_OWNER_SOURCES, TRUSTED_SESSION_SETTINGS, NON_RESTRICTING_OPERATORS } from "../lib/inspector/policyexpr.mjs";
import { toFactCatalog, bucketApplication, V2_QUERIES, QUERY_ROW_LIMITS, catalogReason } from "../lib/inspector/catalogfacts.mjs";
import { hashed } from "../lib/inspector/ids.mjs";
import { judgePreflight, checkShippedSql, PREFLIGHT_CHECKS } from "../lib/inspector/catalog.mjs";
import * as C from "../lib/inspector/contracts.mjs";

const SCHEMA = JSON.parse(readFileSync(new URL("./fixtures/contracts/fact_document.schema.07ff6ab0.json", import.meta.url), "utf8"));
const Ajv2020 = Ajv2020Module.default ?? Ajv2020Module;
const ajv = new Ajv2020({ strict: false, allErrors: true });
ajv.addSchema(SCHEMA);
const validateCatalog = ajv.compile({
  type: "object", additionalProperties: false, required: ["catalog", "collection"],
  properties: {
    catalog: { $ref: `${SCHEMA.$id}#/properties/catalog` },
    collection: { $ref: `${SCHEMA.$id}#/$defs/collection_entry` },
  },
});
const validateRlsRow = ajv.compile({ $ref: `${SCHEMA.$id}#/$defs/row_rls_policies` });
const KEY = "test-install-key";

function fact(result) {
  const out = toFactCatalog(result, { key: KEY });
  assert.ok(validateCatalog(out), JSON.stringify(validateCatalog.errors, null, 1));
  return out;
}

/* ---------- contract copies ---------- */

test("contracts.mjs patterns and the bucket table match the v2 schema", () => {
  const d = SCHEMA.$defs;
  assert.equal(C.SOURCE_COMMIT.slice(0, 8), "07ff6ab0"); // the evaluator commit the fact schema was last copied from
  assert.equal(C.IDENTIFIER, d.identifier.pattern);
  assert.equal(C.HASHED_IDENTIFIER, d.hashed_identifier.pattern);
  assert.equal(C.PATH, d.path.pattern);
  assert.equal(C.LOCATION, d.location.pattern);
  assert.equal(C.OBJECT_ID, d.object_id.pattern);
  assert.equal(C.PG_NAME, d.pg_name.pattern);
  assert.equal(C.QUALIFIED_NAME, d.qualified_name.pattern);
  assert.equal(C.SESSION, SCHEMA.properties.session.pattern);
  assert.deepEqual(["none", ...C.CONNECTED_APPLICATION_PREFIXES.map(([b]) => b), "other"],
    d.row_connected_roles.properties.application.enum);
  assert.deepEqual(PREFLIGHT_CHECKS, SCHEMA.properties.catalog.properties.preflight.properties.failed.items.enum);
  assert.match("phi-columns@public.patients:dob", new RegExp(C.OBJECT_ID));
  for (const q of V2_QUERIES) {
    assert.equal(checkShippedSql(q.sql).error, undefined, q.query_id);
    assert.equal(q.row_limit, QUERY_ROW_LIMITS[q.query_id]);
    assert.equal(d[`query_${q.query_id}`].properties.rows.maxItems, q.row_limit, q.query_id);
  }
  // server_version had no reader in core or here, so it is neither collected nor sent.
  assert.deepEqual(V2_QUERIES.map((q) => q.query_id),
    ["default_acl", "schema_privileges", "triggers", "constraints", "realtime_publication", "connected_roles"]);
  assert.ok(!("server_version" in QUERY_ROW_LIMITS));
});

/* ---------- preflight: write_privileges ---------- */

const GOOD_ROW = Object.freeze({
  role: "phisc_ro", session_role: "phisc_ro", database: "postgres", system_identifier: "7", settings_mismatched: [],
  superuser: false, bypassrls: false, replication: false, createrole: false, readable_tables: 0, writable_tables: 0,
  extension_relations_readable: [], catalog_tables: [], predefined_roles: [], dangerous_functions: [],
  catalog_extensions: [], owned_objects: 0, definer_functions_executable: 0, readable_large_objects: 0,
  lo_compat_privileges: false, write_relations: 0, write_large_objects: 0, write_schemas: 0, write_database: 0,
  write_default_privileges: 0, write_createdb: 0, write_foreign_servers: 0, write_fdw: 0, user_casts: 0,
  user_casts_implicit: 0, user_operators: 0,
});

test("write_privileges: any writable relation, or a count that wasn't read, refuses the role", () => {
  assert.equal(judgePreflight(GOOD_ROW).passed, true);
  for (const writable_tables of [1, 12, null, undefined, "0", -1]) {
    const p = judgePreflight({ ...GOOD_ROW, writable_tables });
    assert.equal(p.passed, false, String(writable_tables));
    assert.deepEqual(p.failed, ["write_privileges"]);
  }
  const { writable_tables, ...without } = GOOD_ROW;
  assert.deepEqual(judgePreflight(without).failed, ["write_privileges"]);
  assert.equal(PREFLIGHT_CHECKS.at(-1), "write_privileges");
});

/* ---------- policy expressions ---------- */

const T = true, F = false, N = "not_read";
// [command, using, check, expected subset]
const CASES = [
  // every expression the command is judged by must hold the owner; a clause with none (true) lets
  // every row through, so the owner is not required.
  ["FOR ALL, USING true and an owner WITH CHECK: any row can be read", "all", "true", "(auth.uid() = user_id)",
    { owner_comparison: T, owner_with_check: T, owner_required: F }],
  ["the owner in both clauses is required", "update", "(auth.uid() = user_id)", "(auth.uid() = user_id)",
    { owner_required: T }],
  ["owner in USING", "select", "(auth.uid() = user_id)", null,
    { owner_using: T, owner_with_check: F, owner_required: T, owner_source_untrusted: F, owner_comparison: T, tenant_comparison: F, requires_aal2: F }],
  ["owner, column first, scalar subquery wrapper", "select", "(user_id = ( SELECT auth.uid() AS uid))", null,
    { owner_using: T, owner_required: T, owner_source_untrusted: F }],
  ["owner via the JWT's sub, casts on both sides", "delete", "((user_id)::text = (auth.jwt() ->> 'sub'::text))", null,
    { owner_using: T, owner_with_check: F, owner_required: T, owner_source_untrusted: F }],
  ["owner via request.jwt.claims", "select", "(user_id = ((current_setting('request.jwt.claims'::text, true))::json ->> 'sub'::text)::uuid)", null,
    { owner_using: T, owner_source_untrusted: F }],
  ["owner via the legacy claim setting", "select", "(user_id = (current_setting('request.jwt.claim.sub'::text, true))::uuid)", null,
    { owner_using: T, owner_source_untrusted: F }],
  ["CURRENT_USER is an owner of unknown trust (the role name, not the user)", "select", "(owner_name = CURRENT_USER)", null,
    { owner_using: T, owner_required: T, owner_source_untrusted: N }],
  ["SESSION_USER, CURRENT_ROLE and USER likewise", "select", "((a = SESSION_USER) AND (b = CURRENT_ROLE) AND (c = USER))", null,
    { owner_using: T, owner_required: T, owner_source_untrusted: N }],
  ["the JWT's 'SUB' is not 'sub'", "select", "(user_id = ((auth.jwt() ->> 'SUB'::text))::uuid)", null, { owner_using: F }],
  ["the JWT's 'AAL' is not 'aal'", "select", "((auth.jwt() ->> 'AAL'::text) = 'aal2'::text)", null, { requires_aal2: F }],
  ["a tenant-like word before the final key is not the tenant: org_role", "select",
    "(role = ((auth.jwt() -> 'app_metadata'::text) ->> 'org_role'::text))", null, { tenant_using: F, tenant_comparison: F }],
  ["tenant_plan is not the tenant", "select", "(plan = ((auth.jwt() -> 'app_metadata'::text) ->> 'tenant_plan'::text))", null, { tenant_using: F }],
  ["tenant_status is not the tenant", "select", "(status = (auth.jwt() ->> 'tenant_status'::text))", null, { tenant_using: F }],
  ["organizations -> role is not the tenant", "select",
    "(role = (((auth.jwt() -> 'app_metadata'::text) -> 'organizations'::text) ->> 'role'::text))", null, { tenant_using: F }],
  ["every listed tenant key is the tenant", "all",
    "((a = (auth.jwt() ->> 'tenant'::text)) AND (b = (auth.jwt() ->> 'organization_id'::text)) AND (c = (auth.jwt() ->> 'organisation_id'::text)) AND (d = (auth.jwt() ->> 'account_id'::text)) AND (e = (auth.jwt() ->> 'workspace_id'::text)) AND (f = (auth.jwt() ->> 'team_id'::text)) AND (g = (auth.jwt() ->> 'clinic_id'::text)) AND (h = (auth.jwt() ->> 'practice_id'::text)))", null,
    { tenant_using: T, tenant_with_check: T, tenant_required: T, tenant_source_untrusted: F }],
  ["'Tenant_ID' is not tenant_id", "select", "(t = (auth.jwt() ->> 'Tenant_ID'::text))", null, { tenant_using: F }],
  ["char(1) on the sub is a cast outside LOSSLESS_CASTS: not_read", "select", "(c1 = ((auth.uid())::text)::character(1))", null,
    { owner_using: N, owner_comparison: N, owner_required: N, owner_source_untrusted: F }],
  ["varchar(1) on both sides: not_read", "select",
    "((((user_id)::text)::character varying(1))::text = (((auth.uid())::text)::character varying(1))::text)", null, { owner_using: N }],
  ["varchar(3) on the JWT's sub: not_read", "select",
    "((owner)::character varying(3) = ((auth.jwt() ->> 'sub'::text))::character varying(3))", null, { owner_using: N }],
  ["character(2) on the tenant: not_read", "select",
    "((tenant_id)::character(2) = (((auth.jwt() -> 'app_metadata'::text) ->> 'tenant_id'::text))::character(2))", null, { tenant_using: N, tenant_source_untrusted: F }],
  ["name (cut at 63 bytes): not_read", "select", "(owner = ((auth.jwt() ->> 'sub'::text))::name)", null, { owner_using: N }],
  ["COLLATE is not looked through: not_read", "select", "(owner = ((auth.jwt() ->> 'sub'::text) COLLATE \"C\"))", null, { owner_using: N }],
  ["an array cast is not looked through (= ANY): not_read", "select", "(user_id = ANY ((ARRAY[auth.uid()])::uuid[]))", null, { owner_using: N }],
  ["an array cast is not looked through (text[]): not_read", "select", "((ids)::text[] = (ARRAY[(auth.uid())::text])::text[])", null, { owner_using: N }],
  ["a literal key under ::text[] is still read", "select", "(user_id = ((auth.jwt() #>> '{sub}'::text[]))::uuid)", null, { owner_using: T }],
  ["varchar, bpchar and bigint with no modifier are looked through", "select",
    "(((owner)::character varying = ((auth.jwt() ->> 'sub'::text))::character varying) AND ((x)::bpchar = ((auth.jwt() ->> 'tenant_id'::text))::bpchar) AND ((n)::bigint = ((auth.jwt() ->> 'org_id'::text))::bigint))", null,
    { owner_using: T, owner_required: T, tenant_using: T, tenant_required: T }],
  ["IS NOT DISTINCT FROM as pg_get_expr prints it", "select", "(NOT (user_id IS DISTINCT FROM auth.uid()))", null,
    { owner_using: T, owner_required: T }],
  ["IS NOT DISTINCT FROM as written", "select", "(user_id IS NOT DISTINCT FROM auth.uid())", null, { owner_using: T, owner_required: T }],
  ["= ANY of one trusted value", "select", "(user_id = ANY (ARRAY[auth.uid()]))", null, { owner_using: T, owner_required: T }],
  ["= ANY of a set of two values: not_read", "select", "(user_id = ANY (ARRAY[auth.uid(), '00000000-0000-0000-0000-000000000000'::uuid]))", null,
    { owner_using: N, owner_comparison: N, owner_required: N, owner_source_untrusted: F }],
  ["= ANY of a row array: not_read", "select", "(auth.uid() = ANY (member_ids))", null, { owner_using: N }],
  ["<> provably doesn't restrict: false", "select", "(user_id <> auth.uid())", null, { owner_using: F, owner_comparison: F }],
  ["<, >=, IS DISTINCT FROM and <> ALL (NOT IN as printed): false", "select",
    "((a < auth.uid()) AND (b >= auth.uid()) AND ((c IS DISTINCT FROM auth.uid()) OR (e <> ALL (ARRAY[auth.uid()]))))", null,
    { owner_using: F, owner_comparison: F, owner_required: F, owner_source_untrusted: F }],
  ["a non-restricting operator under NOT can restrict: not_read", "select", "(NOT (user_id <> auth.uid()))", null,
    { owner_using: N, owner_required: N }],
  ["NOT IN of a subquery: not_read", "select", "(NOT (d IN ( SELECT m.d FROM m WHERE (m.u = auth.uid()))))", null, { owner_using: N }],
  ["IN a subquery (a membership lookup): not_read", "select",
    "(org_id IN ( SELECT m.org_id FROM members m WHERE (m.user_id = auth.uid())))", null,
    { owner_using: N, owner_required: N, owner_source_untrusted: N, tenant_using: N, tenant_required: N, tenant_source_untrusted: N }],
  ["IN a list: not_read", "select", "(user_id IN (auth.uid(), '00000000-0000-0000-0000-000000000000'::uuid))", null, { owner_using: N }],
  ["LIKE, @> and && relate the row to the session: not_read", "all",
    "((owner ~~ ((auth.jwt() ->> 'sub'::text) || '%'::text)) AND (orgs @> ARRAY[(auth.jwt() ->> 'org_id'::text)]) AND (teams && ARRAY[(auth.jwt() ->> 'team_id'::text)]))", null,
    { owner_using: N, owner_with_check: N, tenant_using: N, tenant_with_check: N, tenant_required: N, tenant_source_untrusted: F }],
  ["EXISTS naming the session: not_read", "select",
    "(EXISTS ( SELECT 1 FROM members m WHERE ((m.org_id = notes.org_id) AND (m.user_id = auth.uid()))))", null, { owner_using: N, tenant_using: N }],
  ["EXISTS over a table whose policies aren't read: not_read", "select", "(EXISTS ( SELECT 1 FROM settings s WHERE s.public))", null, { owner_using: N, tenant_using: N }],
  ["a scalar subquery with no FROM and no session value: false", "select", "(flag = ( SELECT true AS bool))", null, { owner_using: F, tenant_using: F }],
  ["a scalar subquery with FROM is opaque: not_read", "select",
    "(tenant_id = ( SELECT p.tenant_id FROM profiles p WHERE (p.id = auth.uid())))", null, { tenant_using: N, owner_using: N }],
  ["a function around the column: not_read", "select", "(lower((user_id)::text) = (auth.uid())::text)", null, { owner_using: N, owner_required: N }],
  ["a built-in function of a value that isn't a session value: false", "select", "(lower(email) = lower(pg_catalog.btrim(name)))", null, { owner_using: F, tenant_using: F }],
  ["auth.email() is a function whose body isn't read: not_read", "select", "(lower(email) = lower(auth.email()))", null, { owner_using: N, tenant_using: N }],
  ["an opaque function with no argument (is_admin()): not_read, never false", "select", "public.is_admin()", null,
    { owner_using: N, owner_comparison: N, owner_required: N, owner_source_untrusted: N, tenant_using: N, tenant_comparison: N }],
  ["an opaque function of a row column (can_see(org_id)): not_read", "select", "public.can_see(org_id)", null, { owner_using: N, tenant_using: N }],
  ["an opaque function beside a required equality: the equality stands, required", "select", "((user_id = auth.uid()) AND public.is_active())", null,
    { owner_using: T, owner_required: T, owner_source_untrusted: N, tenant_using: N }],
  ["an opaque function under OR: required not_read", "select", "((user_id = auth.uid()) OR public.is_admin())", null,
    { owner_using: T, owner_required: N, tenant_using: N }],
  ["a subquery calling an opaque function: not_read", "select", "(org_id IN ( SELECT public.my_orgs() AS my_orgs))", null, { owner_using: N, tenant_using: N }],
  ["= ANY of a membership subquery: not_read for owner and tenant", "select",
    "(org_id = ANY (ARRAY( SELECT m.org_id FROM members m WHERE (m.user_id = auth.uid()))))", null, { owner_using: N, tenant_using: N }],
  ["a subquery through a view whose body isn't read (no session token visible): not_read", "select",
    "(org_id IN ( SELECT my_memberships.org_id FROM my_memberships))", null,
    { owner_using: N, tenant_using: N, owner_source_untrusted: N, tenant_source_untrusted: N }],
  ["<> ALL of a subquery is a subquery relation: not_read", "select",
    "(oid2 <> ALL ( SELECT o.id FROM orgs o WHERE (o.owner_id <> auth.uid())))", null, { owner_using: N, tenant_using: N }],
  ["<> ALL of ARRAY(subquery): not_read", "select",
    "(oid2 <> ALL (ARRAY( SELECT o.id FROM orgs o WHERE (o.owner_id = auth.uid()))))", null, { owner_using: N, tenant_using: N }],
  ["a quoted-schema function inside a subquery: not_read", "select",
    "(EXISTS ( SELECT 1 WHERE \"Private\".can_see(1)))", null, { owner_using: N, tenant_using: N }],
  ["json_extract_path_text of a request header: not_read, caller-controlled", "select",
    "(org_id = json_extract_path_text((current_setting('request.headers'::text, true))::json, 'org_id'::text))", null,
    { owner_using: N, tenant_using: N, owner_source_untrusted: T, tenant_source_untrusted: T }],
  ["jsonb_extract_path_text of the JWT: not_read, unknown trust", "select",
    "(org_id = jsonb_extract_path_text(auth.jwt(), 'user_metadata'::text, 'org_id'::text))", null,
    { owner_using: N, tenant_using: N, tenant_source_untrusted: N }],
  ["a quoted #>> path into the JWT: not_read", "select", "(org_id = (auth.jwt() #>> '{\"user_metadata\",org_id}'::text[]))", null,
    { owner_using: N, tenant_using: N }],
  ["a computed JWT key: not_read", "select", "(org_id = (auth.jwt() ->> lower('ORG_ID'::text)))", null, { owner_using: N, tenant_using: N }],
  ["a cookie read without a key: not_read, caller-controlled", "select",
    "(sid = (current_setting('request.cookies'::text, true))::text)", null, { tenant_using: N, tenant_source_untrusted: T }],
  ["a JWT claim followed to a literal key naming neither: false", "select", "(role = (auth.jwt() ->> 'role'::text))", null,
    { owner_using: F, tenant_using: F }],
  ["a built-in function relating a row column to a session value: not_read", "select",
    "(strpos((user_id)::text, (auth.uid())::text) > 0)", null, { owner_using: N }],
  ["a user-defined operator in its print form: the expression is not read", "select", "(user_id OPERATOR(public.=) auth.uid())", null,
    { owner_using: N, owner_comparison: N, requires_aal2: N }],
  ["a qualified column is not the row's", "select", "(other.user_id = auth.uid())", null, { owner_using: F }],
  ["an unqualified auth function is not auth.uid()", "select", "(user_id = uid())", null, { owner_using: F }],
  ["under OR: not required", "select", "((auth.uid() = user_id) OR is_public)", null,
    { owner_using: T, owner_required: F, owner_source_untrusted: F }],
  ["under NOT: not required", "select", "(NOT (NOT (user_id = auth.uid())))", null, { owner_using: T, owner_required: F }],
  ["under CASE: not required", "select", "CASE WHEN (user_id = auth.uid()) THEN true ELSE false END", null,
    { owner_using: T, owner_required: F }],
  ["in a function argument: not required", "select", "COALESCE((user_id = auth.uid()), false)", null,
    { owner_using: T, owner_required: F }],
  ["top-level AND keeps both required", "all",
    "((tenant_id = (((auth.jwt() -> 'app_metadata'::text) ->> 'tenant_id'::text))::uuid) AND (owner_id = auth.uid()))", null,
    { owner_using: T, owner_with_check: T, owner_required: T, tenant_using: T, tenant_with_check: T, tenant_required: T,
      tenant_source_untrusted: F }],
  ["tenant via #>> path", "select", "(org_id = ((auth.jwt() #>> '{app_metadata,org_id}'::text[]))::uuid)", null,
    { tenant_using: T, tenant_source_untrusted: F }],
  ["tenant from user_metadata is untrusted", "insert", null,
    "(org_id = ((auth.jwt() -> 'user_metadata'::text) ->> 'org_id'::text))",
    { tenant_using: F, tenant_with_check: T, tenant_required: T, tenant_source_untrusted: T, tenant_comparison: T }],
  ["sub from user_metadata is an untrusted owner", "select", "(user_id = (((auth.jwt() -> 'user_metadata'::text) ->> 'sub'::text))::uuid)", null,
    { owner_using: T, owner_source_untrusted: T }],
  ["a request header is untrusted", "select",
    "(tenant_id = ((current_setting('request.headers'::text, true))::json ->> 'tenant_id'::text))", null,
    { tenant_using: T, tenant_source_untrusted: T }],
  ["a custom setting is of unknown trust: not_read", "select", "(tenant_id = (current_setting('app.tenant_id'::text))::uuid)", null,
    { tenant_using: T, tenant_required: T, tenant_source_untrusted: N }],
  ["a custom setting naming the user is an owner of unknown trust", "select", "(user_id = (current_setting('app.current_user_id'::text))::uuid)", null,
    { owner_using: T, owner_source_untrusted: N }],
  ["one trusted and one unknown comparison: not_read", "select",
    "((user_id = auth.uid()) AND (user_id = (current_setting('app.user_id'::text))::uuid))", null,
    { owner_using: T, owner_required: T, owner_source_untrusted: N }],
  ["a caller-controlled source wins over an unknown one: true", "select",
    "((user_id = (current_setting('app.user_id'::text))::uuid) AND (tenant_id = ((current_setting('request.cookies'::text, true))::json ->> 'org_id'::text)) AND (owner = ((current_setting('request.headers'::text, true))::json ->> 'user_id'::text)))", null,
    { owner_using: T, owner_source_untrusted: T, tenant_using: T, tenant_source_untrusted: T }],
  ["a per-header setting is caller-controlled", "select", "(tenant_id = current_setting('request.header.tenant_id'::text, true))", null,
    { tenant_using: T, tenant_source_untrusted: T }],
  ["request.jwt.claim.<tenant key> is trusted like request.jwt.claims ->> <tenant key>", "select",
    "((org_id = current_setting('request.jwt.claim.org_id'::text, true)) AND (team_id = ((current_setting('request.jwt.claims'::text, true))::json ->> 'team_id'::text)))", null,
    { tenant_using: T, tenant_required: T, tenant_source_untrusted: F }],
  ["another request.jwt.claim.<name> naming the user: unknown trust", "select", "(user_id = (current_setting('request.jwt.claim.user_id'::text, true))::uuid)", null,
    { owner_using: T, owner_source_untrusted: N }],
  ["a JWT claim naming the user other than the top-level sub: unknown trust", "select",
    "(user_id = (((auth.jwt() -> 'app_metadata'::text) ->> 'user_id'::text))::uuid)", null, { owner_using: T, owner_source_untrusted: N }],
  ["the role name compared under a function: not_read relation, unknown trust", "select", "(lower(owner_name) = lower(CURRENT_USER))", null,
    { owner_using: N, owner_source_untrusted: N }],
  ["update with no WITH CHECK: USING checks written rows", "update", "(user_id = auth.uid())", null,
    { owner_using: T, owner_with_check: T, owner_required: T }],
  // this pinned owner_required true, but WITH CHECK true lets any row be written, so it is false.
  ["update whose WITH CHECK drops the comparison", "update", "(user_id = auth.uid())", "true",
    { owner_using: T, owner_with_check: F, owner_comparison: T, owner_required: F }],
  ["update whose WITH CHECK has it under OR: not required", "update", "(user_id = auth.uid())", "((user_id = auth.uid()) OR is_admin)",
    { owner_using: T, owner_with_check: T, owner_required: F }],
  ["insert without WITH CHECK", "insert", null, null, { owner_using: F, owner_with_check: F, owner_comparison: F, requires_aal2: F }],
  ["select with no USING", "select", null, null, { owner_comparison: F, requires_aal2: F }],
  ["aal2 required", "select", "((( SELECT auth.jwt() AS jwt) ->> 'aal'::text) = 'aal2'::text)", null, { requires_aal2: T, owner_comparison: F }],
  ["aal2 under OR", "select", "(((auth.jwt() ->> 'aal'::text) = 'aal2'::text) OR true)", null, { requires_aal2: F }],
  ["aal compared with aal1", "select", "((auth.jwt() ->> 'aal'::text) = 'aal1'::text)", null, { requires_aal2: F }],
  ["aal2 in USING but not in the check of an all policy", "all", "((auth.jwt() ->> 'aal'::text) = 'aal2'::text)", "true", { requires_aal2: F }],
  ["aal2 in both for an all policy", "all", "((auth.jwt() ->> 'aal'::text) = 'aal2'::text)", null, { requires_aal2: T }],
  ["aal2 from user_metadata is not the session's aal", "select",
    "(((auth.jwt() -> 'user_metadata'::text) ->> 'aal'::text) = 'aal2'::text)", null, { requires_aal2: F }],
  ["unparseable USING", "select", "(user_id = auth.uid(", null,
    { owner_using: N, owner_with_check: F, owner_comparison: N, owner_required: N, owner_source_untrusted: N, requires_aal2: N }],
  ["unparseable check, comparison in USING", "update", "(user_id = auth.uid())", "(user_id = $1)",
    { owner_using: T, owner_with_check: N, owner_comparison: T, owner_required: N, owner_source_untrusted: N, requires_aal2: F }],
  ["unparseable check, no comparison in USING", "update", "true", "(user_id = $1)",
    { owner_using: F, owner_with_check: N, owner_comparison: N, requires_aal2: F }],
  ["an E'' string with an escape is not read", "select", "(user_id = (auth.jwt() ->> E'su\\\\b'::text))", null, { owner_using: N }],
  ["BETWEEN is not read", "select", "(n BETWEEN 1 AND 2)", null, { owner_using: N }],
  ["a command outside the five", "truncate", "(user_id = auth.uid())", null, Object.fromEntries(POLICY_FIELDS.map((f) => [f, N]))],
];

function fullRow(command, fields) {
  return { schema_name: "public", table_name: "t", policy_name: "p", command: ["select", "insert", "update", "delete", "all"].includes(command) ? command : "select",
    permissive: true, always_true: false, reads_user_metadata: false, trusted_routes: [], owner_match: false, roles: ["public"], ...fields };
}

for (const [name, command, using, check, expected] of CASES) {
  test(`policyFields: ${name}`, () => {
    const got = policyFields({ command, using, check });
    assert.deepEqual(Object.keys(got), POLICY_FIELDS);
    for (const [k, v] of Object.entries(expected)) assert.equal(got[k], v, `${k} for ${using} / ${check}`);
    if (command !== "truncate") assert.ok(validateRlsRow(fullRow(command, got)), JSON.stringify(validateRlsRow.errors));
  });
}

test("the parser reads pg_get_expr's forms and refuses what it doesn't know", () => {
  assert.ok(parseExpression("((a)::text = ANY ((ARRAY['x'::character varying, 'y'::character varying])::text[]))"));
  assert.ok(parseExpression("(created_at > (now() - '1 day'::interval))"));
  assert.ok(parseExpression("((x)::timestamp with time zone IS NOT NULL)"));
  assert.ok(parseExpression("(EXISTS ( SELECT 1 FROM t WHERE (t.a = 'b)'::text)))"));
  assert.ok(parseExpression("(\"Weird Col\" = auth.uid())"));
  assert.equal(policyFields({ command: "select", using: "(\"Weird Col\" = auth.uid())", check: null }).owner_using, true);
  for (const bad of ["", "   ", "(", ")", "a =", "= b", "a = b = c", "(a = b))", "a = b; drop table t", "$1 = a",
    "a -- comment", "a /* c */ = b", "'unterminated", "\"unterminated", "select", "a.*", "f(a => 1)", "x[1:2]",
    "a AT TIME ZONE 'utc'", "count(DISTINCT a)", "sum(a) OVER ()", "a LIKE 'b'", "(a, b"]) {
    assert.equal(parseExpression(bad), null, bad);
  }
  assert.equal(parseExpression("(".repeat(100000) + "a" + ")".repeat(100000)), null);
  assert.equal(parseExpression("NOT ".repeat(5000) + "a"), null);
  assert.equal(parseExpression("a" + " AND a".repeat(MAX_EXPRESSION_LENGTH)), null);
  assert.throws(() => tokenize("a ; b"));
});

/* ---------- fuzzing: garbage is not_read, never true ---------- */

function rng(seed) { let s = seed >>> 0; return () => ((s = (s * 1664525 + 1013904223) >>> 0) / 2 ** 32); }
const SAMPLES = CASES.map((c) => c[2]).filter((x) => typeof x === "string");
const SOUP = ["(", ")", "=", "auth", ".", "uid", "()", "user_id", "AND", "OR", "NOT", "::", "uuid", "'sub'", "->>", "auth.jwt()",
  "ARRAY[", "]", "ANY", "IS", "DISTINCT", "FROM", "SELECT", ",", "CASE", "WHEN", "THEN", "END", "'aal2'", "$", ";", "\"", "'"];

function assertConsistent(got, input) {
  assert.deepEqual(Object.keys(got), POLICY_FIELDS, input);
  for (const v of Object.values(got)) assert.ok(v === true || v === false || v === "not_read", input);
}

test("fuzz: random characters never give true", () => {
  const r = rng(1);
  const chars = "()[]=<>!:'\"., -_aAuidtjwsb0123456789$;\\#>{}\n\té\u0000";
  for (let k = 0; k < 4000; k++) {
    let s = "";
    const len = Math.floor(r() * 80);
    for (let j = 0; j < len; j++) s += chars[Math.floor(r() * chars.length)];
    for (const command of ["select", "insert", "update", "all"]) {
      const got = policyFields({ command, using: command === "insert" ? null : s, check: command === "select" ? null : s });
      assertConsistent(got, s);
      for (const [f, v] of Object.entries(got)) {
        // a lone word ("t") parses as a boolean column, which pg_get_expr prints the same way as a real
        // one (USING (is_public)), so references_row may be true, but only for text that parses. It says only that
        // the row is read: no owner or tenant comparison comes with it, so it makes no pass by itself.
        if (f === "references_row" && v === true) {
          for (const e of [command === "insert" ? null : s, command === "select" ? null : s]) {
            if (e !== null) assert.notEqual(parseExpression(e), null, `references_row true for unparsed ${JSON.stringify(s)}`);
          }
          continue;
        }
        assert.notEqual(v, true, `${f} true for garbage ${JSON.stringify(s)}`);
      }
    }
  }
});

test("fuzz: token soup never gives true unless it parses to a real comparison", () => {
  const r = rng(2);
  for (let k = 0; k < 4000; k++) {
    const n = 1 + Math.floor(r() * 25);
    const s = Array.from({ length: n }, () => SOUP[Math.floor(r() * SOUP.length)]).join(" ");
    const got = policyFields({ command: "select", using: s, check: null });
    assertConsistent(got, s);
    if (parseExpression(s) === null) {
      for (const [f, v] of Object.entries(got)) if (f !== "owner_with_check" && f !== "tenant_with_check") assert.equal(v, "not_read", `${f} for ${s}`);
    } else if (got.owner_using === true || got.requires_aal2 === true) {
      // A soup that happens to parse: the comparison must really be there.
      assert.match(s, /user_id|auth/);
    }
  }
});

test("fuzz: every prefix and every one-character deletion of a real expression stays tri-state and schema-valid", () => {
  for (const s of SAMPLES) {
    for (let i = 0; i < s.length; i++) {
      for (const variant of [s.slice(0, i), s.slice(0, i) + s.slice(i + 1)]) {
        const got = policyFields({ command: "update", using: variant, check: null });
        assertConsistent(got, variant);
        assert.ok(validateRlsRow(fullRow("update", got)), variant);
        if (parseExpression(variant) === null) assert.equal(got.owner_comparison === true, false, variant);
      }
    }
  }
});

/* ---------- connected_roles buckets ---------- */

test("application names bucket by the published prefixes", () => {
  const seen = {
    "psql": "psql", "pgAdmin 4 - DB:postgres": "pgadmin", "DBeaver 24.1.0 - Main <postgres>": "dbeaver",
    "DataGrip 2024.2.1": "datagrip", "PostgREST 12.2.3": "postgrest", "  PostgREST 11.1.0 (5a04ec7)": "postgrest",
    "Supabase Storage API 1.11.0": "supabase_storage", "realtime_rls": "supabase_realtime",
    "realtime_replication_connection": "supabase_realtime", "realtime_connect": "supabase_realtime",
    "postgres-meta 0.84.2": "supabase_studio", "Supavisor": "supavisor", "PostgreSQL JDBC Driver": "jdbc",
    "Npgsql": "npgsql", "pgbouncer": "pgbouncer", "prisma-migrate": "prisma", "": "none", "   ": "none",
    // Supabase Auth's side connections and a deployment that names it gotrue (contract v2.1 table).
    "auth_migrations": "supabase_auth", "auth_indexworker": "supabase_auth", "GoTrue": "supabase_auth", "gotrue v2.170": "supabase_auth",
    // No longer prefixes of supabase_auth, and names that miss every prefix.
    "supabase auth": "other", "supabase_auth": "other", "Metabase v0.50.0": "other",
  };
  for (const [name, bucket] of Object.entries(seen)) assert.equal(bucketApplication(name), bucket, name);
  // The contract's v2.1 table, prefix for prefix and in order (enums.CONNECTED_APPLICATION_PREFIXES).
  assert.deepEqual(C.CONNECTED_APPLICATION_PREFIXES.map(([b, ps]) => [b, [...ps]]), [
    ["psql", ["psql"]], ["pgadmin", ["pgadmin"]], ["dbeaver", ["dbeaver"]], ["datagrip", ["datagrip"]],
    ["postgrest", ["postgrest"]], ["supabase_auth", ["auth_migrations", "auth_indexworker", "gotrue"]],
    ["supabase_storage", ["storage-api", "supabase storage", "supabase_storage"]],
    ["supabase_realtime", ["realtime", "supabase realtime", "supabase_realtime"]],
    ["supabase_studio", ["supabase studio", "postgres-meta", "supabase/dashboard"]], ["pgbouncer", ["pgbouncer"]],
    ["supavisor", ["supavisor"]], ["prisma", ["prisma"]], ["node_postgres", ["node-postgres", "pg-node"]],
    ["psycopg", ["psycopg"]], ["sqlalchemy", ["sqlalchemy"]], ["django", ["django"]], ["rails", ["rails", "activerecord"]],
    ["jdbc", ["postgresql jdbc driver", "jdbc"]], ["npgsql", ["npgsql"]], ["pgx", ["pgx"]],
  ]);
  assert.equal(bucketApplication(null), "none");
});

/* ---------- toFactCatalog against the v2 schema ---------- */

const GOOD_PREFLIGHT = Object.freeze({ ...judgePreflight(GOOD_ROW) });
const ok = (query_id, rows) => ({ query_id, status: rows.length ? "ok" : "empty", reason: null, rows });
const POLICY_TEXT = "(user_id = ( SELECT auth.uid() AS uid))";
const RLS_ROW = { schema_name: "public", table_name: "notes", policy_name: "own notes", command: "update", permissive: true,
  always_true: false, reads_user_metadata: false, trusted_routes: [], owner_match: true, roles: ["authenticated"],
  using_expression: POLICY_TEXT, check_expression: null };

function goodResult() {
  return { status: "ok", count: 0, reason: null, preflight: GOOD_PREFLIGHT, queries: [
    ok("rls_policies", [RLS_ROW]),
    ok("default_acl", [{ schema_name: null, object_type: "function", grantor: "postgres", grantee: "public", privileges: ["execute"] },
      { schema_name: "public", object_type: "table", grantor: "postgres", grantee: "anon", privileges: ["select", "insert", "select"] }]),
    ok("schema_privileges", [{ schema_name: "public", grantee: "public", usage: true, create: false }]),
    ok("triggers", [{ schema_name: "public", table_name: "notes", trigger_name: "audit", timing: "after", events: ["insert", "update"], enabled: "origin" }]),
    ok("constraints", [
      { schema_name: "public", table_name: "notes", constraint_name: "notes_pkey", type: "primary", columns: ["id"], expression: false, partial: false, referenced_schema: null, referenced_name: null },
      { schema_name: "public", table_name: "notes", constraint_name: "notes_owner_fkey", type: "foreign", columns: ["user_id"], expression: false, partial: false, referenced_schema: "auth", referenced_name: "users" },
    ]),
    ok("realtime_publication", []),
    ok("connected_roles", [
      { role_name: "authenticator", application_name: "PostgREST 12.2.3", sessions: 3 },
      { role_name: "authenticator", application_name: "PostgREST 12.2.2", sessions: 2 },
      { role_name: "postgres", application_name: "", sessions: 1 },
    ]),
  ] };
}

test("toFactCatalog: a full run fits the v2 schema; policy text and application names never leave", () => {
  const out = fact(goodResult());
  assert.deepEqual(out.collection, { collector: "catalog", status: "ok", count: 7, reason: null });
  assert.equal(out.catalog.preflight.passed, true);
  assert.equal(out.catalog.preflight.writable_tables, 0);
  const q = Object.fromEntries(out.catalog.queries.map((x) => [x.query_id, x]));
  const rls = q.rls_policies.rows[0];
  assert.equal(rls.policy_name, hashed(KEY, "own notes")); // a space: hashed, the row kept
  assert.equal(q.rls_policies.status, "ok");
  assert.deepEqual([rls.owner_using, rls.owner_with_check, rls.owner_required, rls.owner_source_untrusted], [true, true, true, false]);
  assert.ok(!("using_expression" in rls) && !("check_expression" in rls));
  assert.deepEqual(q.default_acl.rows[1].privileges, ["insert", "select"]);
  assert.equal(q.constraints.rows[1].referenced_table, "auth.users");
  assert.equal(q.realtime_publication.status, "empty");
  assert.deepEqual(q.connected_roles.rows, [
    { role_name: "authenticator", application: "postgrest", sessions: 5 },
    { role_name: "postgres", application: "none", sessions: 1 },
  ]);
  const text = JSON.stringify(out);
  for (const secret of ["auth.uid", "PostgREST 12", "own notes"]) assert.ok(!text.includes(secret), secret);
});

test("toFactCatalog: default_acl carries api_grantee; a missing, null or non-boolean flag is left unset, never false", () => {
  const ACL = { schema_name: "public", object_type: "table", grantor: "postgres", privileges: ["select"] };
  const r = goodResult();
  r.queries[1] = ok("default_acl", [
    { ...ACL, grantee: "anon", api_grantee: true },
    { ...ACL, grantee: "reporting", api_grantee: false },
    { ...ACL, grantee: "a" }, // an older query without the column
    { ...ACL, grantee: "b", api_grantee: null },
    { ...ACL, grantee: "c", api_grantee: "t" },
  ]);
  const out = fact(r);
  const rows = out.catalog.queries.find((x) => x.query_id === "default_acl").rows;
  assert.deepEqual(rows.map((x) => [x.grantee, x.api_grantee]),
    [["anon", true], ["reporting", false], ["a", undefined], ["b", undefined], ["c", undefined]]);
  for (const row of rows.slice(2)) assert.ok(!Object.hasOwn(row, "api_grantee"), row.grantee);
  assert.equal(out.catalog.queries.find((x) => x.query_id === "default_acl").status, "ok");
});

test("toFactCatalog: rows the contract can't carry are left out (truncated); a missing column fails the query", () => {
  const r = goodResult();
  r.queries[1].rows.push({ schema_name: "public", object_type: "large_object", grantor: "postgres", grantee: "x", privileges: ["select"] });
  r.queries[3].rows.push({ schema_name: "public", table_name: "t", trigger_name: "x", timing: "after", events: [], enabled: "origin" });
  r.queries[0].rows.push({ ...RLS_ROW, roles: [null] }); // a dropped role
  r.queries[4].rows.push({ schema_name: "s", table_name: "t", constraint_name: "c", type: "foreign", columns: [], expression: false, partial: false, referenced_schema: null, referenced_name: null });
  const { using_expression, ...noExpr } = RLS_ROW;
  r.queries[6].rows.push({ role_name: "a", application_name: "x", sessions: 0 });
  let out = fact(r);
  const q = Object.fromEntries(out.catalog.queries.map((x) => [x.query_id, x]));
  for (const id of ["default_acl", "triggers", "rls_policies", "constraints", "connected_roles"]) {
    assert.deepEqual([q[id].status, q[id].reason], ["truncated", "value_out_of_pattern"], id);
  }
  assert.deepEqual([out.collection.status, out.collection.reason], ["truncated", "value_out_of_pattern"]);
  r.queries[0] = ok("rls_policies", [noExpr]);
  out = fact(r);
  assert.equal(out.catalog.queries[0].status, "failed");
});

test("toFactCatalog: no connection, a failed preflight and failed queries", () => {
  const notRun = (reason) => goodResult().queries.map((q) => ({ query_id: q.query_id, status: "not_run", reason: null, rows: [] }));
  const empty = { role: null, session_user: null, database: null, system_identifier: null, settings_mismatched: null,
    superuser: null, bypassrls: null, replication: null, createrole: null, readable_tables: null, writable_tables: null,
    extension_relations_readable: null, catalog_tables: null, predefined_roles: null, dangerous_functions: null,
    catalog_extensions: null, owned_objects: null, large_objects: null, definer_functions_executable: null, passed: false };
  let out = fact({ status: "failed", count: 0, reason: "unreachable", preflight: { ...empty, failed: ["connect"] }, queries: notRun() });
  assert.deepEqual(out.collection, { collector: "catalog", status: "failed", count: 0, reason: "unreachable" });
  assert.ok(out.catalog.queries.every((q) => q.status === "not_run" && q.reason === "unreachable"));
  assert.deepEqual(out.catalog.preflight.failed, ["connect"]);
  // wrong_user is refused before connecting: still no connection.
  out = fact({ status: "failed", count: 0, reason: "wrong_user", preflight: { ...empty, failed: ["role"] }, queries: notRun() });
  assert.deepEqual(out.catalog.preflight.failed, ["connect"]);
  // A preflight that ran and failed.
  const bad = judgePreflight({ ...GOOD_ROW, writable_tables: 2, superuser: true });
  out = fact({ status: "failed", count: 0, reason: "preflight_failed", preflight: bad, queries: notRun() });
  assert.deepEqual(out.catalog.preflight.failed, ["superuser", "write_privileges"]);
  assert.equal(out.catalog.preflight.writable_tables, 2);
  assert.ok(out.catalog.queries.every((q) => q.status === "not_run" && q.reason === "preflight_failed"));
  assert.deepEqual(out.collection, { collector: "catalog", status: "failed", count: 0, reason: "preflight_failed" });
  // A preflight claiming to pass with a check failed is not passed; one with an unknown check fails closed.
  out = fact({ ...goodResult(), preflight: { ...GOOD_PREFLIGHT, failed: ["mystery"] } });
  assert.equal(out.catalog.preflight.passed, false);
  // Failed and truncated queries keep their own status; the collector says collected in part.
  const r = goodResult();
  r.queries[2] = { query_id: "schema_privileges", status: "failed", reason: "timeout", rows: [] };
  r.queries[3] = { ...r.queries[3], status: "truncated" };
  r.queries.push({ query_id: "table_grants", status: "ok", reason: null, rows: [{ anything: 1 }] }); // a v1 query: a row missing its columns fails it
  out = fact(r);
  assert.deepEqual(out.catalog.queries.map((q) => [q.query_id, q.status, q.reason]).slice(2, 4),
    [["schema_privileges", "failed", "timeout"], ["triggers", "truncated", "row_limit"]]);
  assert.deepEqual(out.catalog.queries.find((q) => q.query_id === "table_grants"), { query_id: "table_grants", status: "failed", reason: "internal_error", rows: [] });
  assert.deepEqual([out.collection.status, out.collection.reason], ["truncated", "row_limit"]); // the truncated query's reason
  // Missing status: a query whose status isn't one of the five is failed.
  const m = goodResult(); delete m.queries[3].status;
  assert.deepEqual(fact(m).catalog.queries[3], { query_id: "triggers", status: "failed", reason: "internal_error", rows: [] });
  assert.throws(() => toFactCatalog(goodResult(), {}), /per-install key/);
  assert.equal(catalogReason("session_guard"), "preflight_failed");
  assert.equal(catalogReason("whatever"), "internal_error");
});

/* ---------- review round 1: the reviewer's 60 policies as Postgres 16 prints them ---------- */

// fixtures/policies/pg16-print-forms.json: pg_get_expr of each policy in pg16-print-forms.setup.sql (a database test in
// inspector-catalog.test.mjs checks the local server prints them the same). Each code: owner comparison, using,
// with_check, required, source_untrusted; the same five for tenant; requires_aal2. T true, F false, N not_read.
const PRINT_FORMS = JSON.parse(readFileSync(new URL("./fixtures/policies/pg16-print-forms.json", import.meta.url), "utf8"));
const EXPECTED_FORMS = {
  p01: "FFFFF FFFFF F", p02: "TTFFF FFFFF F", p03: "TTFFF FFFFF F", p04: "NNFNF FFFFF F", p05: "NNFNF FFFFF F",
  p06: "TTFTF FFFFF F", p07: "TTFFF FFFFF F", p08: "TTFFF FFFFF F", p09: "NNFNF NNFNF F", p10: "TTFTF FFFFF F",
  p11: "FFFFF FFFFF F", p12: "TTFTF FFFFF F", p13: "NNFNF FFFFF F", p14: "NNFNF FFFFF F", p15: "NNFNF FFFFF F",
  p16: "TTFTN FFFFF F", p17: "TTFTF FFFFF F", p18: "TTFTF FFFFF F", p19: "TTFFF FFFFF F", p20: "TTFFF FFFFF F",
  p21: "TTFTF FFFFF F", p22: "NNFNN NNFNN F", p23: "NNFNN NNFNN F", p24: "NNFNN NNFNN F", p25: "TTFFF FFFFF F",
  p26: "TTFFF FFFFF F", p27: "TTFTF FFFFF F", p28: "FFFFF TTFTT F", p29: "FFFFF TTFTF F", p30: "FFFFF TTFTN F",
  p31: "FFFFF FFFFF F", p32: "TTFTF FFFFF F", p33: "NNFNN NNFNN N", p34: "NNFNN NNFNN F", p35: "TTFTF FFFFF F",
  p36: "TTFFF FFFFF F", p37: "TTFTF FFFFF T", p38: "TTFTF FFFFF F", p39: "NNFNF FFFFF F", p40: "NNFNF FFFFF F",
  p41: "NNFNF NNFNF F", p42: "NNFNF NNFNF F", p43: "TTFFF FFFFF F", p44: "TTFFF FFFFF F", p45: "NNFNF NNFNF F",
  p46: "TTFFF FFFFF F", p47: "NNFNN NNFNN N", p48: "NNFNF NNFNF F", p49: "TTFTF FFFFF F", p50: "NNFNF FFFFF F",
  p51: "FFFFF NNFNF F", p52: "TTFTF FFFFF F", p53: "NNFNF FFFFF F", p54: "TTFFF FFFFF F" /* WITH CHECK true, owner not required */, p55: "TFTFF FFFFF F",
  p56: "TTTTF FFFFF F", p57: "TTFTF FFFFF F", p58: "TTFTT FFFFF F", p59: "FFFFF TTFTF F", p60: "FFFFF FFFFF F",
};
const CMD = { r: "select", a: "insert", w: "update", d: "delete", "*": "all" };
const code = (v) => (v === true ? "T" : v === false ? "F" : "N");

test("the reviewer's 60 policies as Postgres 16 prints them", () => {
  assert.equal(PRINT_FORMS.length, 60);
  for (const p of PRINT_FORMS) {
    const f = policyFields({ command: CMD[p.cmd], using: p.using, check: p.check });
    const got = [["owner", "comparison", "using", "with_check", "required", "source_untrusted"],
      ["tenant", "comparison", "using", "with_check", "required", "source_untrusted"]]
      .map(([x, ...ks]) => ks.map((k) => code(f[`${x}_${k}`])).join("")).join(" ") + " " + code(f.requires_aal2);
    assert.equal(got, EXPECTED_FORMS[p.name], `${p.name}: ${p.using} / ${p.check}`);
    assert.ok(validateRlsRow(fullRow(CMD[p.cmd], f)), p.name);
  }
});

test("the published lists: tenant keys, trusted owner sources, lossless casts", () => {
  assert.deepEqual(TENANT_KEYS, ["tenant_id", "tenant", "org_id", "organization_id", "organisation_id", "account_id",
    "workspace_id", "team_id", "clinic_id", "practice_id"]);
  assert.deepEqual(TRUSTED_OWNER_SOURCES, ["auth.uid()", "auth.jwt() ->> 'sub'", "current_setting('request.jwt.claim.sub')",
    "current_setting('request.jwt.claims') ->> 'sub'"]);
  assert.ok(!LOSSLESS_CASTS.includes("name") && !LOSSLESS_CASTS.includes("character"));
  // enums.py, contract v2.1, value for value and in order.
  assert.deepEqual(LOSSLESS_CASTS, ["uuid", "text", "varchar", "character varying", "bpchar", "json", "jsonb", "bigint", "integer", "int8", "int4"]);
  assert.deepEqual(LOSSY_INTEGER_TARGETS, ["bigint", "integer", "int8", "int4"]);
  assert.deepEqual(LOSSY_INTEGER_SOURCES, ["numeric", "decimal", "real", "double precision", "float4", "float8", "text", "varchar",
    "character varying", "bpchar"]);
  assert.deepEqual(UNTRUSTED_OWNER_SOURCES, ["CURRENT_USER", "CURRENT_ROLE", "SESSION_USER", "USER"]);
  assert.deepEqual(TRUSTED_SESSION_SETTINGS, ["request.jwt.claims", "request.jwt.claim.sub", ...TENANT_KEYS.map((k) => `request.jwt.claim.${k}`)]);
  assert.deepEqual(NON_RESTRICTING_OPERATORS, ["<>", "IS DISTINCT FROM", "<", ">", "<=", ">="]);
  for (const k of TENANT_KEYS) {
    assert.equal(policyFields({ command: "select", using: `(x = (auth.jwt() ->> '${k}'::text))`, check: null }).tenant_using, true, k);
    assert.equal(policyFields({ command: "select", using: `(x = (current_setting('app.${k}'::text)))`, check: null }).tenant_source_untrusted, "not_read", k);
    assert.equal(policyFields({ command: "select", using: `(x = current_setting('request.jwt.claim.${k}'::text, true))`, check: null }).tenant_source_untrusted, false, k);
    assert.equal(policyFields({ command: "select", using: `(x = ((current_setting('request.headers'::text, true))::json ->> '${k}'::text))`, check: null }).tenant_source_untrusted, true, k);
  }
});

test("casts option: none looks through no cast, unread makes every field not_read; toFactCatalog picks it from the preflight", () => {
  const using = "((user_id)::text = (auth.uid())::text)";
  assert.equal(policyFields({ command: "select", using, check: null }).owner_using, true);
  assert.equal(policyFields({ command: "select", using, check: null }, { casts: "none" }).owner_using, "not_read"); // a cast not looked through
  assert.equal(policyFields({ command: "select", using: "(user_id = auth.uid())", check: null }, { casts: "none" }).owner_using, true);
  assert.equal(policyFields({ command: "select", using: "(tenant_id = (auth.jwt() ->> 'tenant_id'::text))", check: null }, { casts: "none" }).tenant_using, true);
  const unread = policyFields({ command: "select", using: "(user_id = auth.uid())", check: null }, { casts: "unread" });
  const onlyNotRead = (f) => Object.entries(f).every(([k, v]) => v === (k.endsWith("_with_check") ? false : "not_read"));
  assert.ok(onlyNotRead(unread), JSON.stringify(unread)); // a select policy has no write check whatever is read
  assert.ok(onlyNotRead(policyFields({ command: "select", using, check: null }, { casts: "bogus" })));
  const ins = policyFields({ command: "insert", using: null, check: "(user_id = auth.uid())" }, { casts: "unread" });
  assert.deepEqual([ins.owner_using, ins.owner_with_check, ins.owner_comparison], [false, "not_read", "not_read"]);
  assert.ok(validateRlsRow(fullRow("insert", ins)) && validateRlsRow(fullRow("select", unread)));
  // After a call with casts off, the next default call looks through again.
  assert.equal(policyFields({ command: "select", using, check: null }).owner_using, true);
  const rls = (preflightRow) => {
    const r = goodResult();
    r.preflight = judgePreflight({ ...GOOD_ROW, ...preflightRow });
    r.queries = [ok("rls_policies", [{ ...RLS_ROW, using_expression: using }])];
    return fact(r).catalog.queries[0].rows[0];
  };
  assert.equal(rls({}).owner_using, true);
  assert.equal(rls({ user_casts: 2, user_casts_implicit: 0 }).owner_using, "not_read");
  assert.equal(rls({ user_casts: 1, user_casts_implicit: 1 }).owner_using, "not_read");
  assert.equal(rls({ user_casts: null }).owner_using, "not_read"); // not read: the worst case
  assert.equal(rls({ user_operators: 1 }).owner_using, "not_read"); // a user-defined = or <>
  assert.equal(rls({ user_operators: null }).owner_using, "not_read");
});

test("the preflight's local message names the failing write parts; the fact document doesn't", () => {
  const p = judgePreflight({ ...GOOD_ROW, writable_tables: 3, write_schemas: 1, write_createdb: 1, write_relations: 1, superuser: true });
  assert.equal(p.message, "superuser; write_privileges: write_relations, write_schemas, write_createdb");
  assert.equal(judgePreflight(GOOD_ROW).message, null);
  const out = fact({ status: "failed", count: 0, reason: "preflight_failed", preflight: p, queries: [] });
  const text = JSON.stringify(out);
  assert.ok(!/write_(relations|large_objects|schemas|database|default_privileges|createdb|foreign_servers)|user_casts|"message"/.test(text));
});

test("lossy integer casts: not_read only where the row column is the cast side and its type could merge rows", () => {
  const cols = (type) => new Map([["org_id", type]]);
  const f = (using, columns) => policyFields({ command: "select", using, check: null }, { columns });
  const rowSide = "((org_id)::bigint = ((auth.jwt() ->> 'org_id'::text))::bigint)";
  // An allowlist: only an integer column type is lossless; a domain, a qualified or unrecognised type, jsonb, numeric
  // and text are lossy.
  for (const type of ["numeric", "numeric(10,2)", "real", "double precision", "text", "character varying(64)", "character(8)",
    "jsonb", "json", "money", "public.org_id_domain", "org_id_domain", "\"Weird\"", "integer[]", ""]) {
    assert.equal(f(rowSide, cols(type)).tenant_using, "not_read", type);
  }
  for (const type of ["integer", "bigint", "smallint"]) assert.equal(f(rowSide, cols(type)).tenant_using, true, type);
  // The column's type unknown (table_columns not read, or the column not in it): lossy, not_read.
  assert.equal(f(rowSide, null).tenant_using, "not_read");
  assert.equal(f(rowSide, new Map([["other", "integer"]])).tenant_using, "not_read");
  // A session value cast to the column's type merges no rows: read normally, whatever the column.
  assert.equal(f("(org_id = ((auth.jwt() ->> 'org_id'::text))::bigint)", cols("numeric")).tenant_using, true);
  assert.equal(f("(org_id = ((auth.jwt() ->> 'org_id'::text))::bigint)", null).tenant_using, true);
  // Through a text cast first: the integer cast's source is text, lossy whatever the column.
  assert.equal(f("(((org_id)::text)::bigint = ((auth.jwt() ->> 'org_id'::text))::bigint)", cols("integer")).tenant_using, "not_read");
  // Not an integer target: looked through as before.
  assert.equal(f("((org_id)::text = (auth.jwt() ->> 'org_id'::text))", cols("numeric")).tenant_using, true);
});

test("toFactCatalog: table_columns types reach the lossy cast rule", () => {
  const using = "((org_id)::bigint = ((auth.jwt() ->> 'org_id'::text))::bigint)";
  const run = (typeRows) => {
    const r = goodResult();
    r.queries = [ok("rls_policies", [{ ...RLS_ROW, command: "select", using_expression: using }]),
      ...(typeRows ? [ok("table_columns", typeRows)] : [])];
    return fact(r).catalog.queries[0].rows[0].tenant_using;
  };
  const col = (data_type, table_name = "notes") => ({ schema_name: "public", table_name, column_name: "org_id", data_type });
  assert.equal(run([col("integer")]), true);
  assert.equal(run([col("numeric")]), "not_read");
  assert.equal(run([col("integer", "other_table")]), "not_read");
  assert.equal(run(null), "not_read");
});

test("reason codes: what the catalog and platform mappers send is a collector reason the v2.1 schema allows", async () => {
  const { factReason } = await import("../lib/inspector/platform.mjs");
  const reasons = SCHEMA.$defs.collection_reason.enum;
  // parse_failed belongs to supabase.edge_functions only, the secret scan's reasons to the secrets collector only.
  const notOnCatalogOrPlatform = ["parse_failed", "scan_error", "joined_view_budget", "bad_input", "unreadable", "match_cut_at_window"];
  const codes = ["timeout", "lock_timeout", "auth_failed", "unreachable", "tls_failed", "tls_required", "permission_denied",
    "preflight_failed", "session_guard", "wrong_user", "service_missing", "database_missing", "config_insecure", "invalid_query",
    "anything", undefined, null];
  const platformCodes = ["no_token", "config_invalid", "config_insecure", "http_401", "http_403", "http_429", "http_500",
    "http_418", "network_error", "timeout", "too_large", "truncated", "not_found", "bad_response", "partial", undefined];
  for (const r of [...codes.map(catalogReason), ...platformCodes.map(factReason)]) {
    assert.ok(reasons.includes(r), r);
    assert.ok(!notOnCatalogOrPlatform.includes(r), r);
  }
  // The secrets collector's truncated reasons are exactly the contract's (enums.SECRETS_TRUNCATED_REASONS).
  const src = readFileSync(new URL("../lib/inspector/secrets.mjs", import.meta.url), "utf8");
  const used = [...new Set([...src.matchAll(/(?:reasons\.add|report\([^)]*?,)\s*\(?"([a-z_]+)"\)?/g)].map((m) => m[1]))].sort();
  assert.deepEqual(used, ["bad_input", "joined_view_budget", "match_cut_at_window", "scan_error", "unreadable"]);
  for (const r of used) assert.ok(reasons.includes(r), r);
});

test("checkShippedSql: storage.buckets is the one non-catalog relation a shipped query may name", () => {
  const q = (sql) => { const r = checkShippedSql(sql); return r.error ?? [...r.qualifiers].sort(); };
  assert.deepEqual(q("SELECT b.id FROM storage.buckets b ORDER BY 1"), ["b"]);
  assert.deepEqual(q("SELECT o.name FROM storage.objects o"), ["o", "storage"]);
  assert.deepEqual(q('SELECT 1 FROM "storage".buckets'), ["storage"]);
  assert.deepEqual(q("SELECT 1 FROM storage.buckets_copy"), ["storage"]);
  assert.deepEqual(q("SELECT 1 FROM app.patients"), ["app"]);
  assert.equal(q("SELECT storage.buckets()"), "function_not_allowed");
});

// one rule screens every name, in rows and in the preflight: a name that fits pg_name and holds no record value
// is sent as it is, anything else as ids.hashed. Data types and bucket ids are hashed the same way outside their pattern.
test("toFactCatalog: names are screened alike in rows and in the preflight; odd data types and bucket ids are hashed", () => {
  const email = "ops@example.com", spaced = "my role", long = "a".repeat(64), plain = "app_user";
  const pre = { ...GOOD_PREFLIGHT, role: email, session_user: spaced, database: plain, catalog_extensions: [long, plain, ""] };
  const longType = "character varying(" + "9".repeat(5) + ")";
  // Called directly: the schema also pins the passed role, which is not what this test is about.
  const out = toFactCatalog({ ...goodResult(), preflight: pre, queries: [
    ok("schema_privileges", [{ schema_name: plain, grantee: email, usage: true, create: false },
      { schema_name: spaced, grantee: long, usage: false, create: false }]),
    ok("table_columns", [
      { schema_name: "public", table_name: "t", column_name: "a", data_type: "integer[]" },
      { schema_name: "public", table_name: "t", column_name: "b", data_type: longType },
      { schema_name: "public", table_name: "t", column_name: "c", data_type: "x".repeat(121) },
      { schema_name: "public", table_name: "t", column_name: "d", data_type: "" },
    ]),
    ok("storage_buckets", ["avatars", "bad bucket", "-x"].map((bucket) => ({ bucket, public: false, open_read_policies: [],
      owner_scoped_read: true, open_for_all: [], unconfirmed_read_policies: [], owner_by_app_setting: false,
      objects_rls_on: true, file_size_limit: null, allowed_mime_types_set: false }))),
  ] }, { key: KEY });
  const h = (v) => hashed(KEY, v);
  const p = out.catalog.preflight;
  assert.deepEqual([p.role, p.session_user, p.database], [h(email), h(spaced), plain]);
  assert.deepEqual(p.catalog_extensions, [h(long), plain]);
  const rows = Object.fromEntries(out.catalog.queries.map((q) => [q.query_id, [q.status, q.reason, q.rows]]));
  assert.deepEqual(rows.schema_privileges[2].map((r) => [r.schema_name, r.grantee]), [[plain, h(email)], [h(spaced), h(long)]]);
  assert.deepEqual(rows.table_columns.slice(0, 2), ["truncated", "value_out_of_pattern"]); // the empty data type is left out
  assert.deepEqual(rows.table_columns[2].map((r) => r.data_type), ["integer[]", h(longType), h("x".repeat(121))]);
  assert.deepEqual(rows.storage_buckets[2].map((r) => r.bucket), ["avatars", h("bad bucket"), h("-x")]);
});

test("table_grants carries public_privileges, every privilege PUBLIC holds", () => {
  const row = (privs) => ({ schema_name: "public", table_name: "patients", public_select: false, api_table_select: false,
    api_column_select: false, api_reads_every_column: false, api_readable_columns: [], api_unreadable_columns: ["id"],
    authenticated_privileges: [], api_roles_with_privileges: [], public_privileges: privs });
  const sent = (privs) => {
    const r = goodResult();
    r.queries.push(ok("table_grants", [row(privs)]));
    return fact(r).catalog.queries.find((q) => q.query_id === "table_grants");
  };
  // PUBLIC holding only INSERT is sent as such: the evaluator fails least-grants on it, where public_select alone was false.
  const q = sent(["insert"]);
  assert.equal(q.status, "ok");
  assert.deepEqual(q.rows[0].public_privileges, ["insert"]);
  assert.deepEqual(sent([]).rows[0].public_privileges, []);
  // A privilege outside the contract's list never reaches the evaluator.
  assert.notEqual(sent(["usage"]).status, "ok");
});

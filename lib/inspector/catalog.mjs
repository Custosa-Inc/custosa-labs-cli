/* The Postgres catalog collector: runs the shipped catalog queries as `phisc_ro` and returns their rows for the fact
 * document's `catalog` block.
 *
 * collectCatalog(conn, queries, opts) -> {status, count, reason, preflight, queries: [{query_id, status, reason, rows}]}
 *   conn     what readService returns ({host, port, dbname, user, sslmode, sslrootcert} and the hidden password)
 *   queries  [{query_id, sql, row_limit?}], each one parameterless SELECT (the shipped query text; C1 provides them
 *            later); row_limit, when given, replaces the default ROW_LIMIT for that query (the contract's maxItems)
 *   opts.provider  the platform config's provider (platform.mjs), when known: storage_buckets runs only on "supabase";
 *            without it, only where the catalog shows Supabase's own storage.buckets (owned by supabase_storage_admin);
 *            elsewhere not_run with platform_mismatch. Row-level security on storage.buckets with no SELECT policy for
 *            this role fails it with permission_denied (not_permitted), never an empty bucket list
 *   status   ok, empty, truncated, failed or not_run; reason a short code or null; count the row total
 *
 * Order of work:
 *   0. Before any network: no queries gives not_run (no_queries); a duplicate query_id, a user other than phisc_ro or
 *      a non-loopback host without sslmode require/verify-ca/verify-full gives failed. Each query text passes a static
 *      check (checkShippedSql) or that query fails with invalid_query.
 *   1. One connection for the preflight and every query (preflightOnly opens its own). Its startup packet carries no
 *      `options` and no `replication` (pg would otherwise take PGOPTIONS / PGREPLICATION from the environment), and each
 *      transaction on it starts with
 *      BEGIN READ ONLY, SET LOCAL of every PINNED_SETTINGS entry (search_path = pg_catalog, pg_temp, DateStyle,
 *      TimeZone and the rest), statement_timeout and lock_timeout. A role-level or env setting therefore cannot shadow
 *      a catalog table or function or change how a value reads, and the preflight SQL is schema-qualified as well.
 *   2. Preflight (PREFLIGHT_SQL, judged by judgePreflight). Any failure: preflight.passed false with the failed
 *      checks named, every query not_run, status failed.
 *   3. Each query, in its own read-only transaction on the same connection (a transaction pooler may
 *      give each transaction another server connection, so nothing outlives one), repeats the full preflight as its
 *      guard, refuses a query that names a schema other than pg_catalog or information_schema, then runs one unnamed
 *      statement wrapping the shipped text in a LIMIT of rowLimit + 1, and rolls back. The connection closes after the
 *      last query. More than rowLimit rows gives `truncated` with the first rowLimit.
 *
 * Rows keep only catalog values: strings, numbers, booleans, null and arrays of those. Nothing here logs, and the
 * password never appears in a result or an error. No child process; the only network is the database connection. */
import pg from "pg";
import { readFileSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { isIP } from "node:net";
import { homedir } from "node:os";
import { join } from "node:path";
import { TLS_MODES, REQUIRED_USER, isRequiredLogin } from "./pgservice.mjs";

export const ROLE = REQUIRED_USER;
export const ROW_LIMIT = 5000;
export const STATEMENT_TIMEOUT_MS = 10000;
export const LOCK_TIMEOUT_MS = 5000;
export const CONNECT_TIMEOUT_MS = 5000;
export const PINNED_SEARCH_PATH = "pg_catalog, pg_temp";

/* Catalog relations that hold data or secrets (statistics values, large object pages, password hashes, user mapping
 * options, server config files). pg_user_mappings (the view) is not listed: it is readable by PUBLIC by default and
 * shows umoptions only to the mapping's own user or the server owner; the table under it, pg_user_mapping, is. */
export const DATA_CATALOG_TABLES = Object.freeze([
  "pg_authid", "pg_file_settings", "pg_hba_file_rules", "pg_ident_file_mappings", "pg_largeobject", "pg_shadow",
  "pg_statistic", "pg_statistic_ext_data", "pg_user_mapping",
]);
/* Predefined roles that reach past the catalog (server files and programs, other sessions' queries and signals,
 * all data, maintenance). pg_read_all_settings is allowed: it shows settings only, which catalog queries may need. */
export const REFUSED_PREDEFINED_ROLES = Object.freeze([
  "pg_checkpoint", "pg_create_subscription", "pg_database_owner", "pg_execute_server_program", "pg_maintain",
  "pg_monitor", "pg_read_all_data", "pg_read_all_stats", "pg_read_server_files", "pg_signal_backend",
  "pg_stat_scan_tables", "pg_use_reserved_connections", "pg_write_all_data", "pg_write_server_files",
]);
/* Functions that read server files, import or export large objects to files, or reach another database. EXECUTE on
 * any overload (directly, via PUBLIC or a member role) fails the preflight. lo_get, lo_open, loread and lo_from_bytea
 * are not listed: core grants them to PUBLIC and gates them by each large object's ACL, which the large_objects check
 * covers. dblink is executable by PUBLIC once installed, so a database with dblink fails until EXECUTE is revoked. */
export const DANGEROUS_FUNCTIONS = Object.freeze([
  "dblink", "dblink_connect", "dblink_connect_u", "dblink_exec", "dblink_open", "dblink_send_query", "lo_export",
  "lo_import", "pg_file_read", "pg_file_rename", "pg_file_unlink", "pg_file_write", "pg_logdir_ls",
  "pg_ls_archive_statusdir", "pg_ls_dir", "pg_ls_logdir", "pg_ls_tmpdir", "pg_ls_waldir", "pg_read_binary_file",
  "pg_read_file", "pg_stat_file",
]);
/* Extensions that may live in pg_catalog without failing catalog_extensions: pg_cron installs there by
 * its control file on Supabase and RDS, and adds only its own cron schema's tables and job functions. */
export const ALLOWED_CATALOG_EXTENSIONS = Object.freeze(["pg_cron"]);
/* Session settings that change how results read. Every transaction sets them with SET LOCAL, and the preflight
 * fails (check `settings`) if any differs. All are user-settable, so none needs recording instead of pinning. */
export const PINNED_SETTINGS = Object.freeze({
  // quote_all_identifiers first: SET search_path stores its value quoted when it is on.
  quote_all_identifiers: "off", search_path: PINNED_SEARCH_PATH, client_encoding: "UTF8", transform_null_equals: "off",
  DateStyle: "ISO, MDY",
  IntervalStyle: "postgres", TimeZone: "UTC", extra_float_digits: "1", bytea_output: "hex", array_nulls: "on",
  standard_conforming_strings: "on", lc_numeric: "C", lc_monetary: "C", lc_time: "C",
  xmloption: "content", backslash_quote: "safe_encoding",
});

const sqlList = (names) => names.map((n) => `'${n}'`).join(", ");
const NOT_CATALOG = "n.nspname NOT IN ('pg_catalog', 'information_schema')";
const SETTINGS_VALUES = Object.entries(PINNED_SETTINGS).map(([k, v]) => `('${k}', '${v}')`).join(", ");
const anyMemberCan = (fn, obj, priv) => `EXISTS (SELECT 1 FROM member_roles m WHERE pg_catalog.${fn}(m.oid, ${obj}, '${priv}'))`;
/* T29-P1-C189 item 3: the same checks for PUBLIC alone ('public' names the pseudo-role in the privilege functions). */
const publicCan = (fn, obj, priv) => `pg_catalog.${fn}('public', ${obj}, '${priv}')`;
/* Write privileges (contract v1.1, write_privileges): any of these on a relation, or the column-level ones on any of its
 * columns, held by any role the session can become (PUBLIC included, as the privilege functions count it). */
export const WRITE_PRIVILEGES = Object.freeze(["INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"]);
export const COLUMN_WRITE_PRIVILEGES = Object.freeze(["INSERT", "UPDATE", "REFERENCES"]);
/* The one default write grant: core gives PUBLIC UPDATE on the pg_catalog.pg_settings view, which only runs SET for the
 * session (a right every role has anyway). UPDATE there alone is not counted; any other privilege on it still is. */
const without = (list, p) => list.filter((x) => x !== p).join(", ");
/* MAINTAIN (Postgres 17+: VACUUM, ANALYZE, REINDEX, REFRESH MATERIALIZED VIEW, LOCK) counts too; the CASE keeps older
 * servers, which don't know the privilege name, from evaluating it. Sequences also count USAGE (nextval). */
const writableBy = (obj, roles = "member_roles m", who = "m.oid") => `EXISTS (SELECT 1 FROM ${roles} WHERE CASE WHEN ${obj} = 'pg_catalog.pg_settings'::pg_catalog.regclass
                THEN pg_catalog.has_table_privilege(${who}, ${obj}, '${without(WRITE_PRIVILEGES, "UPDATE")}')
                  OR pg_catalog.has_any_column_privilege(${who}, ${obj}, '${without(COLUMN_WRITE_PRIVILEGES, "UPDATE")}')
                ELSE pg_catalog.has_table_privilege(${who}, ${obj}, '${WRITE_PRIVILEGES.join(", ")}')
                  OR pg_catalog.has_any_column_privilege(${who}, ${obj}, '${COLUMN_WRITE_PRIVILEGES.join(", ")}') END
                OR CASE WHEN pg_catalog.current_setting('server_version_num')::int >= 170000
                  THEN pg_catalog.has_table_privilege(${who}, ${obj}, 'MAINTAIN') ELSE false END
                OR CASE WHEN (SELECT k.relkind FROM pg_catalog.pg_class k WHERE k.oid = ${obj}) = 'S'
                  THEN pg_catalog.has_sequence_privilege(${who}, ${obj}, 'USAGE, UPDATE') ELSE false END)`;
/* Default privileges that would give a role the session can become (or PUBLIC) a write privilege on objects created
 * later: any of WRITE_PRIVILEGES, or USAGE on sequences. */
const WRITE_DEFAULTS = `(a.privilege_type IN (${WRITE_PRIVILEGES.map((p) => `'${p}'`).join(", ")})
                 OR (d.defaclobjtype = 'S' AND a.privilege_type = 'USAGE')
                 OR (d.defaclobjtype = 'n' AND a.privilege_type = 'CREATE'))`;
/* The types policyexpr.mjs looks through casts to (LOSSLESS_CASTS), by pg_type name. */
const LOSSLESS_TYPE_NAMES = ["uuid", "text", "varchar", "bpchar", "json", "jsonb", "int8", "int4"];
const readableBy = (obj) => `EXISTS (SELECT 1 FROM member_roles m
                WHERE pg_catalog.has_table_privilege(m.oid, ${obj}, 'SELECT')
                   OR pg_catalog.has_any_column_privilege(m.oid, ${obj}, 'SELECT'))`;

/* One row, all checks. Every name is schema-qualified (and search_path is pinned before it runs). `member_roles` is
 * every role the session user or the current user can become with SET ROLE (pg_has_role MEMBER), themselves
 * included, so a NOINHERIT membership cannot hide a superuser, a BYPASSRLS role, a predefined role or a grant. */
export const PREFLIGHT_SQL = `
WITH member_roles AS (
  SELECT r.oid, r.rolname, r.rolsuper, r.rolbypassrls, r.rolreplication, r.rolcreaterole, r.rolcreatedb
  FROM pg_catalog.pg_roles r
  WHERE pg_catalog.pg_has_role(session_user, r.oid, 'MEMBER') OR pg_catalog.pg_has_role(current_user, r.oid, 'MEMBER')
),
ext_member AS (
  SELECT d.objid, e.extname::text AS extname FROM pg_catalog.pg_depend d
  JOIN pg_catalog.pg_extension e ON e.oid = d.refobjid
  WHERE d.classid = 'pg_catalog.pg_class'::pg_catalog.regclass
    AND d.refclassid = 'pg_catalog.pg_extension'::pg_catalog.regclass AND d.deptype = 'e'
),
writes AS (
  SELECT
    (SELECT pg_catalog.count(*) FROM pg_catalog.pg_class c
      WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S', 't') AND ${writableBy("c.oid")})::int AS relations,
    (SELECT pg_catalog.count(*) FROM pg_catalog.pg_largeobject_metadata l
      WHERE l.lomowner IN (SELECT oid FROM member_roles)
         OR EXISTS (SELECT 1 FROM pg_catalog.aclexplode(l.lomacl) a
                    WHERE a.privilege_type = 'UPDATE' AND (a.grantee = 0 OR a.grantee IN (SELECT oid FROM member_roles))))::int
      AS large_objects,
    (SELECT pg_catalog.count(*) FROM pg_catalog.pg_namespace n
      WHERE n.nspname !~ '^pg_(toast_)?temp_'
        AND ${anyMemberCan("has_schema_privilege", "n.oid", "CREATE")})::int AS schemas,
    (SELECT pg_catalog.count(*) FROM pg_catalog.pg_database d
      WHERE d.datname = pg_catalog.current_database()
        AND ${anyMemberCan("has_database_privilege", "d.oid", "CREATE")})::int AS database,
    (SELECT pg_catalog.count(*) FROM pg_catalog.pg_default_acl d CROSS JOIN LATERAL pg_catalog.aclexplode(d.defaclacl) a
      WHERE (a.grantee = 0 OR a.grantee IN (SELECT oid FROM member_roles)) AND ${WRITE_DEFAULTS})::int AS default_privileges,
    (SELECT pg_catalog.count(*) FROM member_roles WHERE rolcreatedb)::int AS createdb,
    (SELECT pg_catalog.count(*) FROM pg_catalog.pg_foreign_server s
      WHERE ${anyMemberCan("has_server_privilege", "s.oid", "USAGE")})::int AS foreign_servers,
    (SELECT pg_catalog.count(*) FROM pg_catalog.pg_foreign_data_wrapper fw
      WHERE ${anyMemberCan("has_foreign_data_wrapper_privilege", "fw.oid", "USAGE")})::int AS fdw
),
-- T29-P1-C189 item 3: the writes PUBLIC alone holds, part by part as in writes. Every role the session can become is a
-- member of PUBLIC, so each part of writes counts at least these; when the totals match, every write path is a grant to
-- PUBLIC (writable_beyond_public 0). The catalog read still refuses then; the grant itself is the finding.
public_writes AS (
  SELECT
    (SELECT pg_catalog.count(*) FROM pg_catalog.pg_class c
      WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S', 't')
        AND ${writableBy("c.oid", "(SELECT 'public'::pg_catalog.name AS who) m", "m.who")})::int AS relations,
    (SELECT pg_catalog.count(*) FROM pg_catalog.pg_largeobject_metadata l
      WHERE EXISTS (SELECT 1 FROM pg_catalog.aclexplode(l.lomacl) a
                    WHERE a.privilege_type = 'UPDATE' AND a.grantee = 0))::int AS large_objects,
    (SELECT pg_catalog.count(*) FROM pg_catalog.pg_namespace n
      WHERE n.nspname !~ '^pg_(toast_)?temp_' AND ${publicCan("has_schema_privilege", "n.oid", "CREATE")})::int AS schemas,
    (SELECT pg_catalog.count(*) FROM pg_catalog.pg_database d
      WHERE d.datname = pg_catalog.current_database()
        AND ${publicCan("has_database_privilege", "d.oid", "CREATE")})::int AS database,
    (SELECT pg_catalog.count(*) FROM pg_catalog.pg_default_acl d CROSS JOIN LATERAL pg_catalog.aclexplode(d.defaclacl) a
      WHERE a.grantee = 0 AND ${WRITE_DEFAULTS})::int AS default_privileges,
    (SELECT pg_catalog.count(*) FROM pg_catalog.pg_foreign_server s
      WHERE ${publicCan("has_server_privilege", "s.oid", "USAGE")})::int AS foreign_servers,
    (SELECT pg_catalog.count(*) FROM pg_catalog.pg_foreign_data_wrapper fw
      WHERE ${publicCan("has_foreign_data_wrapper_privilege", "fw.oid", "USAGE")})::int AS fdw,
    EXISTS (SELECT 1 FROM pg_catalog.pg_namespace n
      WHERE n.nspname = 'public' AND ${publicCan("has_schema_privilege", "n.oid", "CREATE")}) AS schema_public_create
),
user_operators AS (
  -- = and <> operators someone defined on a type policy comparisons are read on: a looked-through type, a domain over
  -- one, or a polymorphic type that matches them. pg_get_expr prints IS [NOT] DISTINCT FROM without naming the = it
  -- resolves to, so with one, no equality can be read (policyexpr.mjs). An operator counts as built-in only when it
  -- is in pg_catalog from initdb (oid < 16384) and its function (oprcode) is too: a built-in operator whose oprcode
  -- was pointed at another function counts as user-defined.
  SELECT o.oid FROM pg_catalog.pg_operator o
  WHERE o.oprname IN ('=', '<>')
    AND NOT (o.oprnamespace = 'pg_catalog'::pg_catalog.regnamespace AND o.oid < 16384
      AND EXISTS (SELECT 1 FROM pg_catalog.pg_proc f
                  WHERE f.oid = o.oprcode::pg_catalog.oid AND f.pronamespace = 'pg_catalog'::pg_catalog.regnamespace
                    AND f.oid < 16384))
    AND EXISTS (SELECT 1 FROM pg_catalog.pg_type ty WHERE ty.oid IN (o.oprleft, o.oprright)
      AND (ty.typname IN ('anyelement', 'anynonarray', 'anycompatible', 'anycompatiblenonarray')
        OR (CASE WHEN ty.typtype = 'd' THEN ty.typbasetype ELSE ty.oid END) IN
          (SELECT lt.oid FROM pg_catalog.pg_type lt WHERE lt.typnamespace = 'pg_catalog'::pg_catalog.regnamespace
             AND lt.typname IN (${sqlList(LOSSLESS_TYPE_NAMES)}))))
),
user_casts AS (
  -- Casts to a type policy comparisons are read through, defined by someone (a function outside pg_catalog, or any
  -- cast created after initdb): with one, a cast in a policy may change the value it casts (policyexpr.mjs).
  SELECT ca.castcontext FROM pg_catalog.pg_cast ca
  JOIN pg_catalog.pg_type tt ON tt.oid = ca.casttarget
  LEFT JOIN pg_catalog.pg_proc fp ON fp.oid = ca.castfunc
  WHERE tt.typnamespace = 'pg_catalog'::pg_catalog.regnamespace
    AND tt.typname IN (${sqlList(LOSSLESS_TYPE_NAMES)})
    AND (fp.pronamespace <> 'pg_catalog'::pg_catalog.regnamespace OR fp.oid >= 16384 OR ca.oid >= 16384)
),
readable AS (
  -- T27-P1-C60 F5. public_read: PUBLIC can read it. granted: a role the session can become holds SELECT on it or a
  -- column by its own ACL entry. Any read but PUBLIC's alone is refused (readable_tables). One only PUBLIC has is
  -- listed when an extension owns the relation (pg_cron's cron.job, pgsodium's views: extension_relations_readable)
  -- and counted otherwise (public_readable_tables). Neither fails, since the shipped queries read the catalog only.
  SELECT c.oid, n.nspname, c.relname,
    EXISTS (SELECT 1 FROM ext_member x WHERE x.objid = c.oid) AS extension_relation,
    (pg_catalog.has_table_privilege('public', c.oid, 'SELECT')
       OR pg_catalog.has_any_column_privilege('public', c.oid, 'SELECT')) AS public_read,
    (EXISTS (SELECT 1 FROM pg_catalog.aclexplode(c.relacl) a
              WHERE a.privilege_type = 'SELECT' AND a.grantee IN (SELECT m.oid FROM member_roles m))
       OR EXISTS (SELECT 1 FROM pg_catalog.pg_attribute at CROSS JOIN LATERAL pg_catalog.aclexplode(at.attacl) a
                   WHERE at.attrelid = c.oid AND at.attnum > 0 AND NOT at.attisdropped
                     AND a.privilege_type = 'SELECT' AND a.grantee IN (SELECT m.oid FROM member_roles m))) AS granted
  FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
  WHERE ${NOT_CATALOG} AND c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S') AND ${readableBy("c.oid")}
    -- Supabase Storage's bucket list is metadata (ids, public flag, limits) that storage_buckets reads: the one
    -- non-catalog relation a catalog-only role may read (rule_bundle.md section 5, B7 fix round).
    -- Only while no table inherits from it: a child's rows could be any data, read through the parent.
    AND NOT (n.nspname = 'storage' AND c.relname = 'buckets' AND c.relkind = 'r'
             AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_inherits i WHERE i.inhparent = c.oid))
)
SELECT
  current_user::text AS role,
  session_user::text AS session_role,
  pg_catalog.current_database()::text AS database,
  CASE WHEN pg_catalog.has_function_privilege('pg_catalog.pg_control_system()', 'EXECUTE')
       THEN (SELECT s.system_identifier::text FROM pg_catalog.pg_control_system() s) END AS system_identifier,
  COALESCE((SELECT pg_catalog.array_agg(v.name ORDER BY v.name) FROM (VALUES ${SETTINGS_VALUES}) v(name, want)
            WHERE pg_catalog.current_setting(v.name) <> v.want), '{}') AS settings_mismatched,
  COALESCE((SELECT pg_catalog.bool_or(rolsuper) FROM member_roles), false) AS superuser,
  COALESCE((SELECT pg_catalog.bool_or(rolbypassrls) FROM member_roles), false) AS bypassrls,
  COALESCE((SELECT pg_catalog.bool_or(rolreplication) FROM member_roles), false) AS replication,
  COALESCE((SELECT pg_catalog.bool_or(rolcreaterole) FROM member_roles), false) AS createrole,
  (SELECT pg_catalog.count(*) FROM readable WHERE NOT public_read OR granted)::int AS readable_tables,
  (SELECT pg_catalog.count(*) FROM readable WHERE public_read AND NOT granted AND NOT extension_relation)::int
    AS public_readable_tables,
  COALESCE((SELECT pg_catalog.array_agg(nspname::text || '.' || relname::text ORDER BY nspname, relname)
            FROM readable WHERE public_read AND NOT granted AND extension_relation), '{}') AS extension_relations_readable,
  -- Everything the role could change, counted together (the contract has one field): relations in every schema, the
  -- catalog's included, with a write privilege (or USAGE on a sequence, or MAINTAIN), large objects it can update or
  -- owns, schemas other than temporary ones and the database it can CREATE in, and default privileges giving it a
  -- write privilege on future objects. Each part is also returned on its own (write_*, for diagnosis, not sent).
  -- Also CREATEDB on any such role and USAGE on a foreign server (it can create a user mapping and reach out). CREATE on
  -- a tablespace is allowed: it places objects, it doesn't let the role make any.
  (SELECT w.relations + w.large_objects + w.schemas + w.database + w.default_privileges + w.createdb + w.foreign_servers
     + w.fdw FROM writes w)::int AS writable_tables,
  (SELECT w.relations FROM writes w) AS write_relations, (SELECT w.large_objects FROM writes w) AS write_large_objects,
  (SELECT w.schemas FROM writes w) AS write_schemas, (SELECT w.database FROM writes w) AS write_database,
  (SELECT w.default_privileges FROM writes w) AS write_default_privileges, (SELECT w.createdb FROM writes w) AS write_createdb,
  (SELECT w.foreign_servers FROM writes w) AS write_foreign_servers, (SELECT w.fdw FROM writes w) AS write_fdw,
  (SELECT w.relations + w.large_objects + w.schemas + w.database + w.default_privileges + w.createdb + w.foreign_servers
     + w.fdw - p.relations - p.large_objects - p.schemas - p.database - p.default_privileges - p.foreign_servers - p.fdw
     FROM writes w, public_writes p)::int AS writable_beyond_public,
  (SELECT p.default_privileges FROM public_writes p) AS public_write_defaults,
  (SELECT p.schema_public_create FROM public_writes p) AS public_schema_create,
  (SELECT pg_catalog.count(*) FROM user_operators)::int AS user_operators,
  (SELECT pg_catalog.count(*) FROM user_casts)::int AS user_casts,
  (SELECT pg_catalog.count(*) FROM user_casts WHERE castcontext = 'i')::int AS user_casts_implicit,
  COALESCE((SELECT pg_catalog.array_agg(c.relname::text ORDER BY c.relname) FROM pg_catalog.pg_class c
            WHERE c.relnamespace = 'pg_catalog'::pg_catalog.regnamespace
              AND c.relname IN (${sqlList(DATA_CATALOG_TABLES)}) AND ${readableBy("c.oid")}), '{}') AS catalog_tables,
  COALESCE((SELECT pg_catalog.array_agg(m.rolname::text ORDER BY m.rolname) FROM member_roles m
            WHERE m.rolname IN (${sqlList(REFUSED_PREDEFINED_ROLES)})), '{}') AS predefined_roles,
  COALESCE((SELECT pg_catalog.array_agg(DISTINCT p.proname::text ORDER BY p.proname::text) FROM pg_catalog.pg_proc p
            WHERE p.proname IN (${sqlList(DANGEROUS_FUNCTIONS)})
              AND ${anyMemberCan("has_function_privilege", "p.oid", "EXECUTE")}), '{}') AS dangerous_functions,
  COALESCE((SELECT pg_catalog.array_agg(e.extname::text ORDER BY e.extname) FROM pg_catalog.pg_extension e
            WHERE e.extnamespace = 'pg_catalog'::pg_catalog.regnamespace AND e.extname <> 'plpgsql'
              AND e.extname NOT IN (${sqlList(ALLOWED_CATALOG_EXTENSIONS)})), '{}') AS catalog_extensions,
  ( (SELECT pg_catalog.count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
      WHERE ${NOT_CATALOG} AND c.relowner IN (SELECT oid FROM member_roles))
  + (SELECT pg_catalog.count(*) FROM pg_catalog.pg_namespace n
      WHERE ${NOT_CATALOG} AND n.nspowner IN (SELECT oid FROM member_roles))
  + (SELECT pg_catalog.count(*) FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
      WHERE ${NOT_CATALOG} AND p.proowner IN (SELECT oid FROM member_roles))
  + (SELECT pg_catalog.count(*) FROM pg_catalog.pg_type t JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
      WHERE ${NOT_CATALOG} AND t.typowner IN (SELECT oid FROM member_roles))
  + (SELECT pg_catalog.count(*) FROM pg_catalog.pg_database d
      WHERE d.datname = pg_catalog.current_database() AND d.datdba IN (SELECT oid FROM member_roles))
  )::int AS owned_objects,
  (SELECT pg_catalog.count(*) FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
    WHERE ${NOT_CATALOG} AND p.prosecdef
      AND ${anyMemberCan("has_function_privilege", "p.oid", "EXECUTE")})::int AS definer_functions_executable,
  (SELECT pg_catalog.count(*) FROM pg_catalog.pg_largeobject_metadata l
    WHERE l.lomowner IN (SELECT oid FROM member_roles)
       OR EXISTS (SELECT 1 FROM pg_catalog.aclexplode(l.lomacl) a
                  WHERE a.privilege_type = 'SELECT'
                    AND (a.grantee = 0 OR a.grantee IN (SELECT oid FROM member_roles)))
  )::int AS readable_large_objects,
  pg_catalog.current_setting('lo_compat_privileges')::pg_catalog.bool AS lo_compat_privileges
`;

/* Non-catalog schema names, for the per-query reference check. */
const SCHEMAS_SQL = `SELECT n.nspname::text AS nspname FROM pg_catalog.pg_namespace n WHERE ${NOT_CATALOG}`;

export const PREFLIGHT_CHECKS = Object.freeze([
  "connect", "role", "session_user", "settings", "superuser", "bypassrls", "replication", "createrole",
  "readable_tables", "catalog_tables", "predefined_roles", "dangerous_functions", "catalog_extensions", "ownership",
  "large_objects", "write_privileges",
]);

/* The only functions a shipped query may call (an identifier followed by `(`, bare or quoted, schema-qualified or
 * not). C1's queries are checked against this list; anything they need beyond it is added here deliberately.
 * pg_relation_size is allowed: it gives a size, not a value. pg_get_expr and obj_description return text, which the
 * fact document's identifier patterns then have to accept. current_setting takes only a literal from
 * ALLOWED_SETTINGS. aclexplode (contract v1.1: default_acl, schema_privileges) only splits an ACL already readable in
 * the catalog; pg_backend_pid (connected_roles) leaves the inspector's own session out. Added for the v1 queries
 * (C1, moved from the hosted snapshot queries): acldefault (an object's default ACL when its own is NULL); btrim,
 * replace, strpos, substr, string_to_array and the regexp_* functions (text work on catalog strings); and
 * pg_get_functiondef (rls_policies reads sign-up trigger and policy helper bodies in SQL, as pg_get_expr reads policy
 * text: only the booleans worked out from them leave the database). md5 (views): views.sql compares
 * md5(prosrc) of an auth function with the stock bodies, so only a boolean leaves the database. None reads a file, a
 * table or another session. */
export const ALLOWED_FUNCTIONS = Object.freeze([
  "aclexplode", "acldefault", "array_agg", "array_length", "array_to_string", "bool_and", "bool_or", "btrim",
  "cardinality", "coalesce", "count", "current_setting", "format_type", "greatest", "has_any_column_privilege",
  "has_column_privilege", "has_function_privilege", "has_schema_privilege", "has_table_privilege", "least", "lower",
  "max", "md5", "min", "nullif", "obj_description", "pg_backend_pid", "pg_get_expr", "pg_get_functiondef", "pg_get_userbyid",
  "pg_has_role", "pg_relation_size", "quote_ident", "regexp_matches", "regexp_replace", "regexp_split_to_array",
  "replace", "string_agg", "string_to_array", "strpos", "substr", "sum", "to_regclass", "unnest", "upper",
]);
/* Settings current_setting may read in a shipped query (pgaudit.* and pgrst.db_schemas, read with missing_ok true by
 * the audit, exposed_schemas and advisor queries). */
export const ALLOWED_SETTINGS = Object.freeze([
  "lo_compat_privileges", "lock_timeout", "log_connections", "log_disconnections", "log_statement", "password_encryption",
  "pgaudit.log", "pgaudit.log_parameter", "pgaudit.role", "pgrst.db_schemas",
  "row_security", "search_path", "server_version_num", "shared_preload_libraries", "ssl", "statement_timeout",
  "transaction_read_only",
]);
/* SQL keywords that may stand before `(` without being a call (only as bare words). */
export const PAREN_KEYWORDS = Object.freeze([
  "all", "and", "any", "array", "as", "between", "by", "case", "cast", "coalesce", "distinct", "else", "except",
  "exists", "filter", "from", "greatest", "group", "having", "ilike", "in", "intersect", "is", "join", "lateral",
  "least", "like", "limit", "materialized", "not", "nullif", "offset", "on", "or", "over", "partition", "recursive",
  "row", "select", "some", "then", "union", "using", "values", "when", "where", "with",
]);

/* Names a shipped query must never contain at all (as an identifier, quoted or not), whatever their position. */
const DENIED_EXACT = new Set([
  "set_config", "ts_stat", "copy", "loread", "lowrite", "pg_stat_file", "pg_notify", "pg_reload_conf",
  "pg_rotate_logfile", "pg_terminate_backend", "pg_cancel_backend", "pg_logdir_ls", "currtid", "currtid2", "uescape",
]);
const DENIED_PREFIX = ["dblink", "lo_", "pg_read_", "pg_ls_", "pg_stat_statements", "pg_advisory", "pg_file", "pg_try_advisory"];
const DENIED_INFIX = ["_to_xml"]; // query_to_xml, query_to_xmlschema, table_to_xml, cursor_to_xml, schema_to_xml...

/* Static check of a shipped query. Tokenises it (comments, quoted strings and identifiers), and refuses: anything not
 * starting with SELECT or WITH, a semicolon, a backslash, a dollar sign (no dollar quotes or parameters), U& strings
 * or identifiers and UESCAPE, an unterminated string, identifier or comment, a `)` that would close our wrapper
 * (depth below zero) or an unclosed `(`, any denied name, and any call to a function outside ALLOWED_FUNCTIONS
 * (function_not_allowed). An identifier before `(` is not a call when it is a bare PAREN_KEYWORDS word, or follows
 * `::`, AS or `)` (a type modifier or a column alias list). A relation alias with a column list after a plain name
 * must use AS. `storage.buckets` (both parts bare) is not counted as a qualifier: Supabase Storage's bucket list is the
 * one non-catalog relation a shipped query may read (rule_bundle.md section 5); `storage` before anything else is.
 * Returns {text, qualifiers, storageBuckets} (qualifiers: identifiers directly followed by a `.`; storageBuckets: the
 * query names storage.buckets) or {error}. */
export function checkShippedSql(sql) {
  if (typeof sql !== "string" || sql.length === 0 || sql.length > 100000) return { error: "invalid_query" };
  let text = sql.trim();
  if (text.endsWith(";")) text = text.slice(0, -1).trimEnd();
  if (/[\\$;\u0000]/.test(text) || /u&/i.test(text)) return { error: "invalid_query" };
  const tokens = [];
  let depth = 0;
  for (let i = 0; i < text.length;) {
    const ch = text[i];
    if (/\s/.test(ch)) { i++; continue; }
    if (ch === "-" && text[i + 1] === "-") { const nl = text.indexOf("\n", i); i = nl < 0 ? text.length : nl + 1; continue; }
    if (ch === "/" && text[i + 1] === "*") {
      let level = 0;
      while (i < text.length) {
        if (text[i] === "/" && text[i + 1] === "*") { level++; i += 2; }
        else if (text[i] === "*" && text[i + 1] === "/") { level--; i += 2; if (level === 0) break; }
        else i++;
      }
      if (level !== 0) return { error: "invalid_query" };
      continue;
    }
    if (ch === "'" || ch === '"') {
      let j = i + 1, value = "";
      for (;;) {
        if (j >= text.length) return { error: "invalid_query" };
        if (text[j] === ch) { if (text[j + 1] === ch) { value += ch; j += 2; continue; } break; }
        value += text[j++];
      }
      tokens.push(ch === '"' ? { t: "ident", v: value } : { t: "string", v: value });
      i = j + 1; continue;
    }
    const word = /^[A-Za-z_\u0080-￿][A-Za-z0-9_\u0080-￿]*/.exec(text.slice(i));
    if (word) { tokens.push({ t: "ident", v: word[0].toLowerCase(), bare: true }); i += word[0].length; continue; }
    if (ch === "(") depth++;
    if (ch === ")" && --depth < 0) return { error: "invalid_query" };
    tokens.push({ t: "punct", v: ch });
    i++;
  }
  if (depth !== 0) return { error: "invalid_query" };
  if (!(tokens[0] && tokens[0].bare && (tokens[0].v === "select" || tokens[0].v === "with"))) return { error: "invalid_query" };
  const qualifiers = new Set();
  let storageBucketsNamed = false;
  const isPunct = (tok, v) => tok && tok.t === "punct" && tok.v === v;
  for (let k = 0; k < tokens.length; k++) {
    const tok = tokens[k];
    if (tok.t !== "ident") continue;
    const v = tok.v.toLowerCase();
    if (DENIED_EXACT.has(v) || DENIED_PREFIX.some((p) => v.startsWith(p)) || DENIED_INFIX.some((p) => v.includes(p))) {
      return { error: "denied_reference" };
    }
    // storage.buckets, written bare, is the one non-catalog relation a shipped query may name (STORAGE_BUCKETS).
    const storageBuckets = tok.bare && tok.v === "storage" && tokens[k + 2] && tokens[k + 2].t === "ident"
      && tokens[k + 2].bare && tokens[k + 2].v === "buckets" && !isPunct(tokens[k + 3], "(");
    if (isPunct(tokens[k + 1], ".") && !storageBuckets) qualifiers.add(tok.v);
    if (isPunct(tokens[k + 1], ".") && storageBuckets) storageBucketsNamed = true;
    if (!isPunct(tokens[k + 1], "(")) continue;
    if (tok.bare && PAREN_KEYWORDS.includes(tok.v)) continue;
    const prev = tokens[k - 1];
    if (isPunct(prev, ":") && isPunct(tokens[k - 2], ":")) continue; // ::type(n)
    if (prev && prev.t === "ident" && prev.bare && prev.v === "as") continue; // AS alias(cols) or AS type(n)
    if (isPunct(prev, ")")) continue; // (subquery) alias(cols) or func() alias(cols): a call cannot follow `)` directly
    if (!ALLOWED_FUNCTIONS.includes(tok.v)) return { error: "function_not_allowed" };
    if (tok.v === "current_setting") {
      const arg = tokens[k + 2];
      if (!(arg && arg.t === "string" && ALLOWED_SETTINGS.includes(arg.v) && (isPunct(tokens[k + 3], ")") || isPunct(tokens[k + 3], ",")))) {
        return { error: "function_not_allowed" };
      }
    }
  }
  return { text, qualifiers, storageBuckets: storageBucketsNamed };
}

export function isLoopbackHost(host) {
  if (!host || host.startsWith("/")) return true; // socket directory
  const h = host.replace(/^\[|\]$/g, "").toLowerCase();
  if (h === "localhost") return true; // only the literal name: *.localhost is not trusted to resolve locally
  if (isIP(h) === 4) return h.startsWith("127.");
  if (isIP(h) === 6) return h === "::1" || /^::ffff:127\./.test(h);
  return false;
}

/* The `ssl` option for pg from sslmode, under the TLS policy. Returns {ssl} or {error: reason}.
 * As in libpq, `require` with a root certificate available (sslrootcert, or ~/.postgresql/root.crt) verifies the
 * chain like verify-ca. */
export function tlsOptions(conn, { home = homedir() } = {}) {
  let mode = conn.sslmode || "prefer";
  if (!isLoopbackHost(conn.host) && !TLS_MODES.includes(mode)) return { error: "tls_required" };
  if (!TLS_MODES.includes(mode)) return { ssl: false }; // loopback; node's driver has no opportunistic TLS
  const defaultRoot = join(home, ".postgresql", "root.crt");
  const rootcert = conn.sslrootcert && conn.sslrootcert !== "system" ? conn.sslrootcert
    : !conn.sslrootcert && existsSync(defaultRoot) ? defaultRoot : null;
  if (mode === "require") {
    if (!rootcert) return { ssl: { rejectUnauthorized: false } }; // libpq require: encrypted, not verified
    mode = "verify-ca";
  }
  const ssl = { rejectUnauthorized: true };
  if (rootcert) { try { ssl.ca = readFileSync(rootcert, "utf8"); } catch { return { error: "tls_rootcert_unreadable" }; } }
  if (mode === "verify-ca") ssl.checkServerIdentity = () => undefined;
  if (isIP(conn.host) === 0 && !conn.host.startsWith("/")) ssl.servername = conn.host;
  return { ssl };
}

/* Maps a connection or query error to a reason code. Never includes the message (it can name hosts or users). */
export function reasonFor(err) {
  const code = err && err.code;
  if (code === "57014") return "timeout";
  if (code === "55P03") return "lock_timeout";
  if (code === "28P01" || code === "28000") return "auth_failed";
  if (code === "3D000") return "database_missing";
  if (code === "42501") return "permission_denied";
  if (["ECONNREFUSED", "ENOTFOUND", "EHOSTUNREACH", "ENETUNREACH", "ETIMEDOUT", "EAI_AGAIN", "ECONNRESET"].includes(code)) {
    return "unreachable";
  }
  if (typeof code === "string" && /^(ERR_TLS|ERR_SSL|DEPTH_ZERO|SELF_SIGNED|UNABLE_TO|CERT_)/.test(code)) return "tls_failed";
  const msg = String(err && err.message || "");
  if (/timeout expired|Connection terminated due to connection timeout/i.test(msg)) return "unreachable";
  if (/does not support SSL|SSL/i.test(msg)) return "tls_failed";
  if (/password must be a string|SASL/i.test(msg)) return "auth_failed";
  if (typeof code === "string" && /^[0-9A-Z]{5}$/.test(code)) return "query_error";
  return "connect_failed";
}

/* A pg client whose every setting is explicit. pg's ConnectionParameters falls back to PG* environment variables for
 * any falsy config value (so `options: ""` would still take PGOPTIONS); the startup `options` and `replication` are
 * therefore cleared after construction, and getStartupConf() is tested to carry neither. */
export function clientFor(conn, ssl, opts = {}) {
  const password = conn.password;
  const client = new pg.Client({
    host: conn.host, port: conn.port, database: conn.dbname, user: conn.user,
    password: () => password ?? "", // a function: pg never falls back to PGPASSWORD or its own pgpass reading
    ssl,
    sslnegotiation: "postgres",
    client_encoding: "utf8",
    binary: false,
    connectionTimeoutMillis: opts.connectTimeoutMs ?? CONNECT_TIMEOUT_MS,
    application_name: "custosa-inspector",
    keepAlive: false,
  });
  client.connectionParameters.options = undefined;
  client.connectionParameters.replication = undefined;
  client.replication = undefined;
  return client;
}

/* opts.onConnect and opts.beforeClose(client): tests only (count connections, read the session before it closes). */
async function withClient(conn, ssl, opts, fn) {
  const client = clientFor(conn, ssl, opts);
  client.on("error", () => {}); // a dropped connection surfaces through the pending query instead
  try {
    await client.connect();
    if (typeof opts.onConnect === "function") opts.onConnect();
    const out = await fn(client);
    if (typeof opts.beforeClose === "function") await opts.beforeClose(client);
    return out;
  } finally {
    try { await client.end(); } catch { /* already closed */ }
  }
}

async function beginReadOnly(client, opts) {
  await client.query("BEGIN READ ONLY");
  for (const [name, value] of Object.entries(PINNED_SETTINGS)) {
    const v = name === "search_path" ? value : `'${value}'`;
    await client.query(`SET LOCAL ${name} = ${v}`);
  }
  await client.query(`SET LOCAL statement_timeout = ${Math.trunc(opts.statementTimeoutMs)}`);
  await client.query(`SET LOCAL lock_timeout = ${Math.trunc(opts.lockTimeoutMs)}`);
}

async function runPreflight(client) {
  return judgePreflight((await client.query(PREFLIGHT_SQL)).rows[0]);
}

/* The preflight in its own read-only transaction, rolled back: the first step of collectCatalog (on the connection the
 * queries then share) and all of preflightOnly (on its own). Throws on a connection or query error. */
async function preflightOn(client, opts) {
  await beginReadOnly(client, opts);
  const result = await runPreflight(client);
  await client.query("ROLLBACK");
  return result;
}
const preflightTransaction = (conn, ssl, opts) => withClient(conn, ssl, opts, (client) => preflightOn(client, opts));

const names = (v) => (Array.isArray(v) ? v.map(String) : []);

/* The parts writable_tables adds up (each a count in the preflight row, write_<part>). */
export const WRITE_PARTS = Object.freeze(["relations", "large_objects", "schemas", "database", "default_privileges",
  "createdb", "foreign_servers", "fdw"]);

/* The line the person sees locally when the preflight fails: each failed check, and for write_privileges the parts that
 * made it fail (names only). Never sent in the fact document. */
export function preflightMessage(p) {
  if (!p || p.passed) return null;
  return p.failed.map((c) => {
    if (c !== "write_privileges" || !p.write_parts) return c;
    const parts = WRITE_PARTS.filter((k) => p.write_parts[k] !== 0).map((k) => `write_${k}`);
    return parts.length ? `${c}: ${parts.join(", ")}` : c;
  }).join("; ");
}

/* Builds the preflight result from the row. */
export function judgePreflight(row) {
  const num = (v) => (typeof v === "number" && Number.isInteger(v) ? v : NaN); // ::int counts; anything else fails
  const preflight = {
    role: row.role,
    session_user: row.session_role,
    database: row.database ?? null,
    system_identifier: row.system_identifier ?? null,
    settings_mismatched: names(row.settings_mismatched),
    superuser: row.superuser === true,
    bypassrls: row.bypassrls === true,
    replication: row.replication === true,
    createrole: row.createrole === true,
    readable_tables: num(row.readable_tables),
    public_readable_tables: num(row.public_readable_tables), // reported, never failing
    writable_tables: num(row.writable_tables),
    extension_relations_readable: names(row.extension_relations_readable),
    catalog_tables: names(row.catalog_tables),
    predefined_roles: names(row.predefined_roles),
    dangerous_functions: names(row.dangerous_functions),
    catalog_extensions: names(row.catalog_extensions),
    owned_objects: num(row.owned_objects),
    large_objects: num(row.readable_large_objects) !== 0 || row.lo_compat_privileges !== false,
    definer_functions_executable: num(row.definer_functions_executable),
    passed: false,
    failed: [],
    // Local only (toFactCatalog sends none of these): each part of writable_tables, and the casts check policy parsing
    // reads (user_casts: casts to a looked-through type that someone defined; NaN when not read).
    write_parts: Object.fromEntries(WRITE_PARTS.map((k) => [k, num(row[`write_${k}`])])),
    // T29-P1-C189 item 3 (local until the contract slice): writes held other than through PUBLIC, PUBLIC's default
    // write grants, and whether PUBLIC may CREATE in schema public. Missing values are NaN and null, never 0 or false.
    public_writes: { beyond_public: num(row.writable_beyond_public), default_privileges: num(row.public_write_defaults),
      schema_public_create: typeof row.public_schema_create === "boolean" ? row.public_schema_create : null },
    user_casts: { any: num(row.user_casts), implicit: num(row.user_casts_implicit) },
    user_operators: num(row.user_operators),
    message: null,
  };
  const fail = (c) => preflight.failed.push(c);
  if (preflight.role !== ROLE) fail("role");
  if (preflight.session_user !== ROLE || preflight.session_user !== preflight.role) fail("session_user");
  if (!Array.isArray(row.settings_mismatched) || preflight.settings_mismatched.length) fail("settings");
  if (preflight.superuser) fail("superuser");
  if (preflight.bypassrls) fail("bypassrls");
  if (preflight.replication) fail("replication");
  if (preflight.createrole) fail("createrole");
  if (!(preflight.readable_tables === 0)) fail("readable_tables");
  if (preflight.catalog_tables.length) fail("catalog_tables");
  if (preflight.predefined_roles.length) fail("predefined_roles");
  if (preflight.dangerous_functions.length) fail("dangerous_functions");
  if (preflight.catalog_extensions.length) fail("catalog_extensions");
  if (!(preflight.owned_objects === 0)) fail("ownership");
  if (preflight.large_objects) fail("large_objects");
  if (!(preflight.writable_tables === 0)) fail("write_privileges"); // a missing or unreadable count refuses too
  preflight.passed = preflight.failed.length === 0;
  preflight.message = preflightMessage(preflight);
  return preflight;
}

const emptyPreflight = (failed) => ({
  role: null, session_user: null, database: null, system_identifier: null, settings_mismatched: null, superuser: null,
  bypassrls: null, replication: null, createrole: null, readable_tables: null, public_readable_tables: null,
  writable_tables: null,
  extension_relations_readable: null,
  catalog_tables: null, predefined_roles: null, dangerous_functions: null, catalog_extensions: null,
  owned_objects: null, large_objects: null, definer_functions_executable: null, passed: false, failed,
});

function catalogValue(v) {
  if (v === null || typeof v === "string" || typeof v === "boolean") return true;
  if (typeof v === "number") return Number.isFinite(v);
  if (Array.isArray(v)) return v.every((x) => x === null || typeof x === "string" || typeof x === "boolean"
    || (typeof x === "number" && Number.isFinite(x)));
  return false;
}

const isTempSchema = (s) => s === "pg_temp" || s.startsWith("pg_temp_") || s.startsWith("pg_toast_temp_");

/* Supabase Storage's bucket list, as the catalog shows it: whether storage.buckets is there (a plain table), whether
 * Supabase's storage role owns it (the shape Supabase's storage migrations create), whether row-level security is on,
 * and, for the policies that apply to SELECT for this session's role or PUBLIC: whether any permissive one applies
 * (policy), whether a permissive one reads every row (full: its USING is exactly true, as pg_get_expr prints it), and
 * whether a restrictive one applies (restrictive). Only a full permissive policy with no restrictive one proves the
 * role sees every bucket. */
const STORAGE_SHAPE_SQL = `WITH applies AS (
  SELECT p.polpermissive AS permissive, pg_catalog.pg_get_expr(p.polqual, p.polrelid) AS qual
  FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
  JOIN pg_catalog.pg_policy p ON p.polrelid = c.oid
  WHERE n.nspname = 'storage' AND c.relname = 'buckets' AND c.relkind = 'r' AND p.polcmd IN ('r', '*')
    AND (0 = ANY (p.polroles) OR EXISTS (SELECT 1 FROM pg_catalog.unnest(p.polroles) AS r(oid)
                                         WHERE pg_catalog.pg_has_role(current_user, r.oid, 'USAGE'))))
SELECT pg_catalog.pg_get_userbyid(c.relowner) = 'supabase_storage_admin' AS supabase_owned,
  c.relrowsecurity AS rls,
  EXISTS (SELECT 1 FROM applies WHERE permissive) AS policy,
  EXISTS (SELECT 1 FROM applies WHERE permissive AND qual = 'true') AS full_read,
  EXISTS (SELECT 1 FROM applies WHERE NOT permissive) AS restrictive
FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'storage' AND c.relname = 'buckets' AND c.relkind = 'r'`;

/* Whether a query naming storage.buckets may run: only storage_buckets may name it; only on Supabase (opts.provider
 * from the platform config when given, else the catalog's Supabase-owned shape); and not while row-level security
 * hides every row from this role. Returns null to run it with its rows complete, {filtered: true} to run it but report
 * it truncated (row_security_filtered: row-level security is on and completeness isn't provable), else
 * its result. Complete only with row-level security off, or a permissive SELECT or ALL policy for this role or PUBLIC
 * whose USING is exactly true and no restrictive policy for SELECT. (The preflight refuses a role that bypasses it.) */
async function storageGate(client, query_id, opts) {
  const notRun = { query_id, status: "not_run", reason: "platform_mismatch", rows: [] };
  if (query_id !== "storage_buckets") return { query_id, status: "failed", reason: "non_catalog_reference", rows: [] };
  if (opts.provider != null && opts.provider !== "supabase") return notRun;
  const shape = (await client.query(STORAGE_SHAPE_SQL)).rows[0];
  if (!shape) return notRun; // no Supabase Storage here
  if (opts.provider == null && shape.supabase_owned !== true) return notRun;
  if (shape.rls !== true) return null;
  if (shape.policy !== true) return { query_id, status: "failed", reason: "permission_denied", rows: [] };
  if (shape.full_read === true && shape.restrictive !== true) return null;
  return { filtered: true };
}

/* One query in its own read-only transaction on the shared connection (a transaction pooler gives each
 * transaction any server connection, so nothing may outlive one: the settings are SET LOCAL, the statements unnamed,
 * and the session guard runs again inside it). Always ends with ROLLBACK, so the next query starts clean. */
async function runQuery(client, { query_id, row_limit }, checked, opts) {
  const failed = (reason) => ({ query_id, status: "failed", reason, rows: [] });
  if (checked.error) return failed(checked.error);
  if (row_limit !== undefined && !(Number.isSafeInteger(row_limit) && row_limit >= 1)) return failed("invalid_query");
  const rowLimit = row_limit ?? opts.rowLimit;
  try {
    return await (async () => {
      await beginReadOnly(client, opts);
      if (!(await runPreflight(client)).passed) return failed("session_guard");
      const schemas = new Set((await client.query(SCHEMAS_SQL)).rows.map((r) => r.nspname));
      for (const q of checked.qualifiers) {
        if (schemas.has(q) || isTempSchema(q)) return failed("non_catalog_reference");
      }
      let filtered = false;
      if (checked.storageBuckets) {
        const gate = await storageGate(client, query_id, opts);
        if (gate && gate.filtered) filtered = true;
        else if (gate) { await client.query("ROLLBACK"); return gate; }
      }
      const limited = `SELECT * FROM (\n${checked.text}\n) AS custosa_q LIMIT ${rowLimit + 1}`;
      const res = await client.query({ text: limited, values: [] });
      await client.query("ROLLBACK");
      const cols = res.fields.map((f) => f.name);
      if (new Set(cols).size !== cols.length) return failed("duplicate_column");
      const rows = res.rows.slice(0, rowLimit);
      for (const row of rows) if (!Object.values(row).every(catalogValue)) return failed("disallowed_value");
      // Rows row-level security may hide: collected in part, never ok or empty.
      if (filtered) return { query_id, status: "truncated", reason: "row_security_filtered", rows };
      const status = res.rows.length > rowLimit ? "truncated" : rows.length === 0 ? "empty" : "ok";
      return { query_id, status, reason: null, rows };
    })();
  } catch (err) {
    return failed(reasonFor(err));
  } finally {
    try { await client.query("ROLLBACK"); } catch { /* the connection is gone: the next query fails on it too */ }
  }
}

const notRun = (queries) => queries.map((q) => ({ query_id: q && q.query_id, status: "not_run", reason: null, rows: [] }));

export async function collectCatalog(conn, queries, options = {}) {
  const opts = {
    rowLimit: ROW_LIMIT, statementTimeoutMs: STATEMENT_TIMEOUT_MS, lockTimeoutMs: LOCK_TIMEOUT_MS,
    connectTimeoutMs: CONNECT_TIMEOUT_MS, home: homedir(), onPreflightDone: null, ...options,
  };
  if (opts.deadline != null) { // the preflight's connection and statements fit the budget too
    const left = Math.max(100, opts.deadline - Date.now());
    for (const k of ["connectTimeoutMs", "statementTimeoutMs", "lockTimeoutMs"]) opts[k] = Math.min(opts[k], left);
  }
  const list = Array.isArray(queries) ? queries : [];
  const failed = (reason, preflight) => ({ status: "failed", count: 0, reason, preflight, queries: notRun(list) });

  if (list.length === 0) return { status: "not_run", count: 0, reason: "no_queries", preflight: emptyPreflight([]), queries: [] };
  const ids = list.map((q) => q && q.query_id);
  if (ids.some((id) => typeof id !== "string" || id === "")) return failed("invalid_query_id", emptyPreflight([]));
  if (new Set(ids).size !== ids.length) return failed("duplicate_query_id", emptyPreflight([]));
  if (!conn || typeof conn !== "object") return failed("service_missing", emptyPreflight(["connect"]));
  if (!isRequiredLogin(conn.user)) return failed("wrong_user", emptyPreflight(["role"]));
  const tls = tlsOptions(conn, { home: opts.home });
  if (tls.error) return failed(tls.error, emptyPreflight(["connect"]));
  const checked = list.map((q) => checkShippedSql(q.sql));

  // One connection for the preflight and every query, each in its own read-only transaction.
  let preflight = null, results;
  try {
    results = await withClient(conn, tls.ssl, opts, async (client) => {
      preflight = await preflightOn(client, opts);
      if (!preflight.passed) return null;
      if (typeof opts.onPreflightDone === "function") await opts.onPreflightDone(); // tests only: change grants mid-run
      // opts.deadline (epoch ms, optional): the check's time budget. A query not started by then is not_run, timeout;
      // one started before it gets no longer statement timeout than what is left.
      const out = [];
      for (let i = 0; i < list.length; i++) {
        const left = opts.deadline == null ? Infinity : opts.deadline - Date.now();
        if (left <= 0) { out.push({ query_id: list[i].query_id, status: "not_run", reason: "timeout", rows: [] }); continue; }
        const timed = left === Infinity ? opts : { ...opts, statementTimeoutMs: Math.max(100, Math.min(opts.statementTimeoutMs, left)),
          lockTimeoutMs: Math.max(100, Math.min(opts.lockTimeoutMs, left)) };
        out.push(await runQuery(client, list[i], checked[i], timed));
      }
      return out;
    });
  } catch (err) {
    // Before the preflight answered: no connection, or the preflight itself failed. After it: the connection dropped
    // between queries' setup, so each query not yet run is failed with the reason.
    if (!preflight) return failed(reasonFor(err), emptyPreflight(["connect"]));
    results = list.map((q) => ({ query_id: q.query_id, status: "failed", reason: reasonFor(err), rows: [] }));
  }
  // message: the local line for the person's terminal (e.g. "write_privileges: write_schemas"); never in the fact document.
  if (!preflight.passed) return { ...failed("preflight_failed", preflight), message: preflight.message };

  const count = results.reduce((n, q) => n + q.rows.length, 0);
  let status = "ok", reason = null;
  if (results.some((q) => q.status === "failed")) { status = "failed"; reason = "query_failed"; }
  else if (results.some((q) => q.status === "not_run" && q.reason === "timeout")) { status = "truncated"; reason = "timeout"; } // cut by the budget (T19, B3)
  else if (results.some((q) => q.status === "truncated")) status = "truncated";
  else if (results.every((q) => q.status === "empty")) status = "empty";
  return { status, count, reason, preflight, queries: results };
}

/* The preflight alone, for custosa doctor: the same connection rules and read-only transaction as collectCatalog, no
 * catalog query. -> {status: "passed" | "failed" | "error", reason, message, preflight}. Never throws; the password
 * stays inside clientFor. */
export async function preflightOnly(conn, options = {}) {
  const opts = { statementTimeoutMs: STATEMENT_TIMEOUT_MS, lockTimeoutMs: LOCK_TIMEOUT_MS, connectTimeoutMs: CONNECT_TIMEOUT_MS,
    home: homedir(), ...options };
  if (!conn || typeof conn !== "object") return { status: "error", reason: "service_missing", message: null, preflight: null };
  if (!isRequiredLogin(conn.user)) return { status: "error", reason: "wrong_user", message: null, preflight: null };
  const tls = tlsOptions(conn, { home: opts.home });
  if (tls.error) return { status: "error", reason: tls.error, message: null, preflight: null };
  try {
    const preflight = await preflightTransaction(conn, tls.ssl, opts);
    return preflight.passed ? { status: "passed", reason: null, message: null, preflight }
      : { status: "failed", reason: "preflight_failed", message: preflightMessage(preflight), preflight };
  } catch (err) {
    return { status: "error", reason: reasonFor(err), message: null, preflight: null };
  }
}

/* T29 o2, the proof runner (T29-P1-C99). A proof is a fix's test SQL, as core keeps it for a fix call (get_result part
 * proof): it passes only when it runs with no error, and raises (SQLSTATE P0001) when a protection the fix claims is
 * missing. This CLI runs it on verify against the phisc entry, as phisc_ro, and sends only the result.
 *
 * proofBlocks(test_sql) -> [statement] | null
 *   The SQL comes from the evaluator, so only the exact shape core builds is taken (check_fixes._pinned around
 *   _assert and _each blocks): "SET search_path = pg_catalog, pg_temp;\n", then one or more "DO $custosa$\n...\n$custosa$;"
 *   blocks on their own lines, then "\nRESET search_path;". No block body may hold the tag, so each block is exactly one
 *   DO statement with a quoted body and nothing after it: nothing can close the read-only transaction (a COMMIT
 *   between blocks) or name another language. The pin and reset are left out: each transaction pins the same
 *   search_path itself.
 * runProofs(conn, proofs, opts) -> [{object_id, proof_id, result}], one per proof, in order; result pass, fail or unread
 *   proofs   [{object_id, proof_id, test_sql}]; proof_id must be the first 16 hex of the test SQL's sha256
 *   The connection rules are the collector's: phisc_ro only, the TLS policy, the same preflight once and again as the
 *   guard inside each proof's transaction. Each proof runs in its own transaction (BEGIN READ ONLY with the pinned
 *   settings and timeouts), each block as one statement over the extended protocol, and always ends with ROLLBACK.
 *   pass: every block ran. fail: a block raised P0001. unread: anything else (another shape, a wrong id, no
 *   connection, a failed preflight or guard, a write refused by the read-only transaction, a timeout, a missing
 *   table, a deadline past). The time limits are set again before each block, so no block can lift them for the
 *   next (T29-P2-C118). Never throws; nothing is logged, and no row, message or password comes back. */
const PROOF_PIN = "SET search_path = pg_catalog, pg_temp;\n";
const PROOF_RESET = "\nRESET search_path;";
const PROOF_OPEN = "DO $custosa$\n";
const PROOF_CLOSE = "\n$custosa$;";
const PROOF_ID = /^[0-9a-f]{16}$/;
export const PROOF_RESULTS = Object.freeze(["pass", "fail", "unread"]);

export function proofBlocks(sql) {
  if (typeof sql !== "string" || !sql.startsWith(PROOF_PIN) || !sql.endsWith(PROOF_RESET)) return null;
  let rest = sql.slice(PROOF_PIN.length, sql.length - PROOF_RESET.length);
  const blocks = [];
  for (;;) {
    rest = rest.replace(/^\n+/, "");
    if (rest === "") break;
    if (!rest.startsWith(PROOF_OPEN)) return null;
    const end = rest.indexOf(PROOF_CLOSE, PROOF_OPEN.length - 1);
    if (end < 0) return null;
    const body = rest.slice(PROOF_OPEN.length, end);
    if (body.includes("$custosa$")) return null;
    blocks.push(`${PROOF_OPEN}${body}\n$custosa$`);
    rest = rest.slice(end + PROOF_CLOSE.length);
  }
  return blocks.length ? blocks : null;
}

const proofIdOf = (sql) => createHash("sha256").update(sql, "utf8").digest("hex").slice(0, 16);

/* The client stops waiting this long after the server's own statement timeout, and then drops the connection. */
const PROOF_BACKSTOP_MS = 1000;
class ProofTimeout extends Error {}

/* One proof in its own read-only transaction. Before each block the time limits are set again from the time left
 * (a block may change them for the rest of the transaction, C118), with a client-side query_timeout a little above
 * as a backstop; when the backstop fires, ProofTimeout ends the run and the connection is dropped. After the
 * ROLLBACK, session advisory locks a proof took are released, so none is held into the next proof. */
async function runProof(client, blocks, opts) {
  const left = () => (opts.deadline == null ? Infinity : opts.deadline - Date.now());
  let dropped = false;
  try {
    await beginReadOnly(client, opts);
    if (!(await runPreflight(client)).passed) return "unread";
    for (const text of blocks) {
      const t = left();
      if (t <= 0) return "unread";
      const stmt = Math.max(100, Math.trunc(Math.min(opts.statementTimeoutMs, t)));
      const lock = Math.max(100, Math.trunc(Math.min(opts.lockTimeoutMs, t)));
      await client.query(`SET LOCAL statement_timeout = ${stmt}`);
      await client.query(`SET LOCAL lock_timeout = ${lock}`);
      try {
        await client.query({ text, values: [], queryMode: "extended", query_timeout: stmt + PROOF_BACKSTOP_MS });
      } catch (err) {
        if (err && !err.code && /timeout/i.test(String(err.message))) { dropped = true; throw new ProofTimeout(); }
        throw err;
      }
    }
    return "pass";
  } catch (err) {
    if (err instanceof ProofTimeout) throw err;
    return err && err.code === "P0001" ? "fail" : "unread";
  } finally {
    // after the backstop the block may still run on the server: nothing more is queued behind it on this connection
    if (!dropped) {
      try {
        await client.query("ROLLBACK");
        await client.query("SELECT pg_catalog.pg_advisory_unlock_all()");
      } catch { /* the connection is gone: the next proof is unread on it too */ }
    }
  }
}

export async function runProofs(conn, proofs, options = {}) {
  const opts = { statementTimeoutMs: STATEMENT_TIMEOUT_MS, lockTimeoutMs: LOCK_TIMEOUT_MS, connectTimeoutMs: CONNECT_TIMEOUT_MS,
    home: homedir(), ...options };
  const list = Array.isArray(proofs) ? proofs : [];
  const out = list.map((p) => ({ object_id: p?.object_id, proof_id: p?.proof_id, result: "unread" }));
  const blocks = list.map((p) => (typeof p?.test_sql === "string" && PROOF_ID.test(String(p.proof_id))
    && proofIdOf(p.test_sql) === p.proof_id ? proofBlocks(p.test_sql) : null));
  if (!blocks.some(Boolean)) return out;
  if (!conn || typeof conn !== "object" || !isRequiredLogin(conn.user)) return out;
  const tls = tlsOptions(conn, { home: opts.home });
  if (tls.error) return out;
  const left = () => (opts.deadline == null ? Infinity : opts.deadline - Date.now());
  if (left() <= 0) return out;
  if (opts.deadline != null) opts.connectTimeoutMs = Math.max(100, Math.min(opts.connectTimeoutMs, left()));
  try {
    await withClient(conn, tls.ssl, opts, async (client) => {
      if (!(await preflightOn(client, opts)).passed) return;
      for (let i = 0; i < list.length; i++) {
        if (!blocks[i]) continue;
        const t = left();
        if (t <= 0) break;
        const timed = t === Infinity ? opts : { ...opts, statementTimeoutMs: Math.max(100, Math.min(opts.statementTimeoutMs, t)),
          lockTimeoutMs: Math.max(100, Math.min(opts.lockTimeoutMs, t)) };
        try { out[i].result = await runProof(client, blocks[i], timed); } catch (err) {
          if (err instanceof ProofTimeout) break; // the connection is dropped below; what didn't run stays unread
          throw err;
        }
      }
    });
  } catch { /* no connection, or it dropped: what didn't run stays unread */ }
  return out;
}

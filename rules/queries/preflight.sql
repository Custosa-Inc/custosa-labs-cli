
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
      WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S', 't') AND EXISTS (SELECT 1 FROM member_roles m WHERE CASE WHEN c.oid = 'pg_catalog.pg_settings'::pg_catalog.regclass
                THEN pg_catalog.has_table_privilege(m.oid, c.oid, 'INSERT, DELETE, TRUNCATE, REFERENCES, TRIGGER')
                  OR pg_catalog.has_any_column_privilege(m.oid, c.oid, 'INSERT, REFERENCES')
                ELSE pg_catalog.has_table_privilege(m.oid, c.oid, 'INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')
                  OR pg_catalog.has_any_column_privilege(m.oid, c.oid, 'INSERT, UPDATE, REFERENCES') END
                OR CASE WHEN pg_catalog.current_setting('server_version_num')::int >= 170000
                  THEN pg_catalog.has_table_privilege(m.oid, c.oid, 'MAINTAIN') ELSE false END
                OR CASE WHEN (SELECT k.relkind FROM pg_catalog.pg_class k WHERE k.oid = c.oid) = 'S'
                  THEN pg_catalog.has_sequence_privilege(m.oid, c.oid, 'USAGE, UPDATE') ELSE false END))::int AS relations,
    (SELECT pg_catalog.count(*) FROM pg_catalog.pg_largeobject_metadata l
      WHERE l.lomowner IN (SELECT oid FROM member_roles)
         OR EXISTS (SELECT 1 FROM pg_catalog.aclexplode(l.lomacl) a
                    WHERE a.privilege_type = 'UPDATE' AND (a.grantee = 0 OR a.grantee IN (SELECT oid FROM member_roles))))::int
      AS large_objects,
    (SELECT pg_catalog.count(*) FROM pg_catalog.pg_namespace n
      WHERE n.nspname !~ '^pg_(toast_)?temp_'
        AND EXISTS (SELECT 1 FROM member_roles m WHERE pg_catalog.has_schema_privilege(m.oid, n.oid, 'CREATE')))::int AS schemas,
    (SELECT pg_catalog.count(*) FROM pg_catalog.pg_database d
      WHERE d.datname = pg_catalog.current_database()
        AND EXISTS (SELECT 1 FROM member_roles m WHERE pg_catalog.has_database_privilege(m.oid, d.oid, 'CREATE')))::int AS database,
    (SELECT pg_catalog.count(*) FROM pg_catalog.pg_default_acl d CROSS JOIN LATERAL pg_catalog.aclexplode(d.defaclacl) a
      WHERE (a.grantee = 0 OR a.grantee IN (SELECT oid FROM member_roles)) AND (a.privilege_type IN ('INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER')
                 OR (d.defaclobjtype = 'S' AND a.privilege_type = 'USAGE')
                 OR (d.defaclobjtype = 'n' AND a.privilege_type = 'CREATE')))::int AS default_privileges,
    (SELECT pg_catalog.count(*) FROM member_roles WHERE rolcreatedb)::int AS createdb,
    (SELECT pg_catalog.count(*) FROM pg_catalog.pg_foreign_server s
      WHERE EXISTS (SELECT 1 FROM member_roles m WHERE pg_catalog.has_server_privilege(m.oid, s.oid, 'USAGE')))::int AS foreign_servers,
    (SELECT pg_catalog.count(*) FROM pg_catalog.pg_foreign_data_wrapper fw
      WHERE EXISTS (SELECT 1 FROM member_roles m WHERE pg_catalog.has_foreign_data_wrapper_privilege(m.oid, fw.oid, 'USAGE')))::int AS fdw
),
-- T29-P1-C189 item 3: the writes PUBLIC alone holds, part by part as in writes. Every role the session can become is a
-- member of PUBLIC, so each part of writes counts at least these. When the totals match, every write path is a grant to
-- PUBLIC (writable_beyond_public 0). The catalog read still refuses then, and the grant itself is the finding.
public_writes AS (
  SELECT
    (SELECT pg_catalog.count(*) FROM pg_catalog.pg_class c
      WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S', 't')
        AND EXISTS (SELECT 1 FROM (SELECT 'public'::pg_catalog.name AS who) m WHERE CASE WHEN c.oid = 'pg_catalog.pg_settings'::pg_catalog.regclass
                THEN pg_catalog.has_table_privilege(m.who, c.oid, 'INSERT, DELETE, TRUNCATE, REFERENCES, TRIGGER')
                  OR pg_catalog.has_any_column_privilege(m.who, c.oid, 'INSERT, REFERENCES')
                ELSE pg_catalog.has_table_privilege(m.who, c.oid, 'INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')
                  OR pg_catalog.has_any_column_privilege(m.who, c.oid, 'INSERT, UPDATE, REFERENCES') END
                OR CASE WHEN pg_catalog.current_setting('server_version_num')::int >= 170000
                  THEN pg_catalog.has_table_privilege(m.who, c.oid, 'MAINTAIN') ELSE false END
                OR CASE WHEN (SELECT k.relkind FROM pg_catalog.pg_class k WHERE k.oid = c.oid) = 'S'
                  THEN pg_catalog.has_sequence_privilege(m.who, c.oid, 'USAGE, UPDATE') ELSE false END))::int AS relations,
    (SELECT pg_catalog.count(*) FROM pg_catalog.pg_largeobject_metadata l
      WHERE EXISTS (SELECT 1 FROM pg_catalog.aclexplode(l.lomacl) a
                    WHERE a.privilege_type = 'UPDATE' AND a.grantee = 0))::int AS large_objects,
    (SELECT pg_catalog.count(*) FROM pg_catalog.pg_namespace n
      WHERE n.nspname !~ '^pg_(toast_)?temp_' AND pg_catalog.has_schema_privilege('public', n.oid, 'CREATE'))::int AS schemas,
    (SELECT pg_catalog.count(*) FROM pg_catalog.pg_database d
      WHERE d.datname = pg_catalog.current_database()
        AND pg_catalog.has_database_privilege('public', d.oid, 'CREATE'))::int AS database,
    (SELECT pg_catalog.count(*) FROM pg_catalog.pg_default_acl d CROSS JOIN LATERAL pg_catalog.aclexplode(d.defaclacl) a
      WHERE a.grantee = 0 AND (a.privilege_type IN ('INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER')
                 OR (d.defaclobjtype = 'S' AND a.privilege_type = 'USAGE')
                 OR (d.defaclobjtype = 'n' AND a.privilege_type = 'CREATE')))::int AS default_privileges,
    (SELECT pg_catalog.count(*) FROM pg_catalog.pg_foreign_server s
      WHERE pg_catalog.has_server_privilege('public', s.oid, 'USAGE'))::int AS foreign_servers,
    (SELECT pg_catalog.count(*) FROM pg_catalog.pg_foreign_data_wrapper fw
      WHERE pg_catalog.has_foreign_data_wrapper_privilege('public', fw.oid, 'USAGE'))::int AS fdw,
    EXISTS (SELECT 1 FROM pg_catalog.pg_namespace n
      WHERE n.nspname = 'public' AND pg_catalog.has_schema_privilege('public', n.oid, 'CREATE')) AS schema_public_create
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
             AND lt.typname IN ('uuid', 'text', 'varchar', 'bpchar', 'json', 'jsonb', 'int8', 'int4'))))
),
user_casts AS (
  -- Casts to a type policy comparisons are read through, defined by someone (a function outside pg_catalog, or any
  -- cast created after initdb): with one, a cast in a policy may change the value it casts (policyexpr.mjs).
  SELECT ca.castcontext FROM pg_catalog.pg_cast ca
  JOIN pg_catalog.pg_type tt ON tt.oid = ca.casttarget
  LEFT JOIN pg_catalog.pg_proc fp ON fp.oid = ca.castfunc
  WHERE tt.typnamespace = 'pg_catalog'::pg_catalog.regnamespace
    AND tt.typname IN ('uuid', 'text', 'varchar', 'bpchar', 'json', 'jsonb', 'int8', 'int4')
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
  WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S') AND EXISTS (SELECT 1 FROM member_roles m
                WHERE pg_catalog.has_table_privilege(m.oid, c.oid, 'SELECT')
                   OR pg_catalog.has_any_column_privilege(m.oid, c.oid, 'SELECT'))
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
  COALESCE((SELECT pg_catalog.array_agg(v.name ORDER BY v.name) FROM (VALUES ('quote_all_identifiers', 'off'), ('search_path', 'pg_catalog, pg_temp'), ('client_encoding', 'UTF8'), ('transform_null_equals', 'off'), ('DateStyle', 'ISO, MDY'), ('IntervalStyle', 'postgres'), ('TimeZone', 'UTC'), ('extra_float_digits', '1'), ('bytea_output', 'hex'), ('array_nulls', 'on'), ('standard_conforming_strings', 'on'), ('lc_numeric', 'C'), ('lc_monetary', 'C'), ('lc_time', 'C'), ('xmloption', 'content'), ('backslash_quote', 'safe_encoding')) v(name, want)
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
              AND c.relname IN ('pg_authid', 'pg_file_settings', 'pg_hba_file_rules', 'pg_ident_file_mappings', 'pg_largeobject', 'pg_shadow', 'pg_statistic', 'pg_statistic_ext_data', 'pg_user_mapping') AND EXISTS (SELECT 1 FROM member_roles m
                WHERE pg_catalog.has_table_privilege(m.oid, c.oid, 'SELECT')
                   OR pg_catalog.has_any_column_privilege(m.oid, c.oid, 'SELECT'))), '{}') AS catalog_tables,
  COALESCE((SELECT pg_catalog.array_agg(m.rolname::text ORDER BY m.rolname) FROM member_roles m
            WHERE m.rolname IN ('pg_checkpoint', 'pg_create_subscription', 'pg_database_owner', 'pg_execute_server_program', 'pg_maintain', 'pg_monitor', 'pg_read_all_data', 'pg_read_all_stats', 'pg_read_server_files', 'pg_signal_backend', 'pg_stat_scan_tables', 'pg_use_reserved_connections', 'pg_write_all_data', 'pg_write_server_files')), '{}') AS predefined_roles,
  COALESCE((SELECT pg_catalog.array_agg(DISTINCT p.proname::text ORDER BY p.proname::text) FROM pg_catalog.pg_proc p
            WHERE p.proname IN ('dblink', 'dblink_connect', 'dblink_connect_u', 'dblink_exec', 'dblink_open', 'dblink_send_query', 'lo_export', 'lo_import', 'pg_file_read', 'pg_file_rename', 'pg_file_unlink', 'pg_file_write', 'pg_logdir_ls', 'pg_ls_archive_statusdir', 'pg_ls_dir', 'pg_ls_logdir', 'pg_ls_tmpdir', 'pg_ls_waldir', 'pg_read_binary_file', 'pg_read_file', 'pg_stat_file')
              AND EXISTS (SELECT 1 FROM member_roles m WHERE pg_catalog.has_function_privilege(m.oid, p.oid, 'EXECUTE'))), '{}') AS dangerous_functions,
  COALESCE((SELECT pg_catalog.array_agg(e.extname::text ORDER BY e.extname) FROM pg_catalog.pg_extension e
            WHERE e.extnamespace = 'pg_catalog'::pg_catalog.regnamespace AND e.extname <> 'plpgsql'
              AND e.extname NOT IN ('pg_cron')), '{}') AS catalog_extensions,
  ( (SELECT pg_catalog.count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND c.relowner IN (SELECT oid FROM member_roles))
  + (SELECT pg_catalog.count(*) FROM pg_catalog.pg_namespace n
      WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspowner IN (SELECT oid FROM member_roles))
  + (SELECT pg_catalog.count(*) FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND p.proowner IN (SELECT oid FROM member_roles))
  + (SELECT pg_catalog.count(*) FROM pg_catalog.pg_type t JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
      WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND t.typowner IN (SELECT oid FROM member_roles))
  + (SELECT pg_catalog.count(*) FROM pg_catalog.pg_database d
      WHERE d.datname = pg_catalog.current_database() AND d.datdba IN (SELECT oid FROM member_roles))
  )::int AS owned_objects,
  (SELECT pg_catalog.count(*) FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND p.prosecdef
      AND EXISTS (SELECT 1 FROM member_roles m WHERE pg_catalog.has_function_privilege(m.oid, p.oid, 'EXECUTE')))::int AS definer_functions_executable,
  (SELECT pg_catalog.count(*) FROM pg_catalog.pg_largeobject_metadata l
    WHERE l.lomowner IN (SELECT oid FROM member_roles)
       OR EXISTS (SELECT 1 FROM pg_catalog.aclexplode(l.lomacl) a
                  WHERE a.privilege_type = 'SELECT'
                    AND (a.grantee = 0 OR a.grantee IN (SELECT oid FROM member_roles)))
  )::int AS readable_large_objects,
  pg_catalog.current_setting('lo_compat_privileges')::pg_catalog.bool AS lo_compat_privileges

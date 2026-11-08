WITH custosa_api AS (SELECT oid, rolname FROM pg_roles g WHERE (g.rolname IN ('anon', 'authenticated') OR g.rolname NOT IN ('service_role', 'authenticator') AND pg_has_role((SELECT rr.oid FROM pg_roles rr WHERE rr.rolname = 'authenticator'), g.oid, 'MEMBER')))
SELECT n.nspname::text AS schema_name, c.relname::text AS table_name, coalesce(0 = ANY (j.g || k.g), false) AS public_select,
 coalesce(j.g && ARRAY[(SELECT rr.oid FROM pg_roles rr WHERE rr.rolname = 'anon'), (SELECT rr.oid FROM pg_roles rr WHERE rr.rolname = 'authenticated')]::oid[], false) AS api_table_select, coalesce(k.g && ARRAY[(SELECT rr.oid FROM pg_roles rr WHERE rr.rolname = 'anon'), (SELECT rr.oid FROM pg_roles rr WHERE rr.rolname = 'authenticated')]::oid[], false) AS api_column_select,
 e.every AS api_reads_every_column,
 CASE e.every WHEN true THEN '{}' WHEN false THEN coalesce(e.cols, '{}') END AS api_readable_columns,
 CASE e.every WHEN true THEN '{}' WHEN false THEN coalesce(e.ucols, '{}') END AS api_unreadable_columns,
 ARRAY(SELECT p FROM custosa_api, unnest('{select,insert,update,delete,truncate,references,trigger}'::text[]) p WHERE rolname = 'authenticated' AND has_table_privilege(oid, c.oid, p))
  AS authenticated_privileges,
 ARRAY(SELECT rolname::text FROM custosa_api WHERE has_table_privilege(oid, c.oid, 'DELETE,TRUNCATE,TRIGGER')
  OR has_any_column_privilege(oid, c.oid, 'SELECT,INSERT,UPDATE,REFERENCES')) AS api_roles_with_privileges,
 ARRAY(SELECT p FROM unnest('{select,insert,update,delete,truncate,references,trigger,maintain}'::text[]) p WHERE upper(p) = ANY (u.g)) AS public_privileges
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
CROSS JOIN LATERAL (SELECT array_agg(x.grantee) AS g FROM aclexplode(coalesce(c.relacl, acldefault('r', c.relowner))) x WHERE x.privilege_type = 'SELECT') j
CROSS JOIN LATERAL (SELECT array_agg(x.grantee) AS g FROM pg_attribute t CROSS JOIN LATERAL aclexplode(t.attacl) x
 WHERE t.attrelid = c.oid AND t.attnum > 0 AND NOT t.attisdropped AND x.privilege_type = 'SELECT') k
CROSS JOIN LATERAL (SELECT bool_and(r) AS every, array_agg(attname::text ORDER BY attnum) FILTER (WHERE r) AS cols,
  array_agg(attname::text ORDER BY attnum) FILTER (WHERE NOT r) AS ucols FROM (SELECT t.attname, t.attnum,
  (SELECT bool_or(has_column_privilege(oid, c.oid, t.attnum, 'SELECT')) FROM custosa_api) AS r
 FROM pg_attribute t WHERE t.attrelid = c.oid AND t.attnum > 0 AND NOT t.attisdropped) r) e
CROSS JOIN LATERAL (SELECT coalesce(array_agg(x.privilege_type), '{}') AS g FROM (SELECT coalesce(c.relacl, acldefault('r', c.relowner)) AS a
 UNION ALL SELECT t.attacl FROM pg_attribute t WHERE t.attrelid = c.oid AND t.attnum > 0 AND NOT t.attisdropped) l
 CROSS JOIN LATERAL aclexplode(l.a) x WHERE x.grantee = 0) u
WHERE c.relkind IN ('r', 'p') AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast', 'auth', 'storage', 'extensions', 'graphql', 'graphql_public', 'realtime', '_realtime', 'vault', 'pgsodium', 'pgsodium_masks', 'supabase_functions', 'supabase_migrations', 'net', 'cron', 'pgbouncer', '_analytics', 'pgmq') AND n.nspname !~ '^pg_'
ORDER BY 1, 2

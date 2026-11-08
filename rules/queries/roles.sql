SELECT r.rolname::text AS role_name, (r.rolsuper OR EXISTS (SELECT 1 FROM pg_roles g WHERE g.rolsuper AND pg_has_role(r.oid, g.oid, 'MEMBER'))) AS superuser,
       (r.rolbypassrls OR EXISTS (SELECT 1 FROM pg_roles g WHERE g.rolbypassrls AND pg_has_role(r.oid, g.oid, 'MEMBER'))) AS bypass_rls,
       (r.rolcreaterole OR EXISTS (SELECT 1 FROM pg_roles g WHERE g.rolcreaterole AND pg_has_role(r.oid, g.oid, 'MEMBER'))) AS create_role,
       (r.rolcreatedb OR EXISTS (SELECT 1 FROM pg_roles g WHERE g.rolcreatedb AND pg_has_role(r.oid, g.oid, 'MEMBER'))) AS create_db,
       coalesce((SELECT array_agg(n.nspname || '.' || c.relname ORDER BY n.nspname, c.relname)
                   FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                  WHERE c.relkind IN ('r', 'p') AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast', 'auth', 'storage', 'extensions', 'graphql', 'graphql_public', 'realtime', '_realtime', 'vault', 'pgsodium', 'pgsodium_masks', 'supabase_functions', 'supabase_migrations', 'net', 'cron', 'pgbouncer', '_analytics', 'pgmq') AND n.nspname !~ '^pg_'
                    AND (c.relowner = r.oid
                         OR (NOT r.rolsuper AND pg_has_role(r.oid, c.relowner, 'MEMBER')))), '{}') AS owns
  FROM pg_roles r
 WHERE r.rolcanlogin AND r.rolname !~ '^pg_'
 ORDER BY 1

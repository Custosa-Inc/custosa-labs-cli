SELECT n.nspname::text AS schema_name, c.relname::text AS table_name, c.relrowsecurity AS rls_enabled,
       c.relforcerowsecurity AS rls_forced
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE c.relkind IN ('r', 'p') AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast', 'auth', 'storage', 'extensions', 'graphql', 'graphql_public', 'realtime', '_realtime', 'vault', 'pgsodium', 'pgsodium_masks', 'supabase_functions', 'supabase_migrations', 'net', 'cron', 'pgbouncer', '_analytics', 'pgmq') AND n.nspname !~ '^pg_'
 ORDER BY 1, 2

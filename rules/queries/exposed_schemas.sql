-- auth_definers (T19-P1-C148): every SECURITY DEFINER function whose owner can read auth.users (a table or any column
-- privilege, so a superuser's too), but a built-in and a trigger or event trigger function, which no read reaches.
-- Postgres runs functions on a read in more places than views.sql's walk can list, so any of these is a hold.
-- What the platform ships is skipped, narrowly (T19-P1-C154): a member of an extension on views.sql's ext_ok list or of
-- a Supabase platform extension that a platform role owns (ALTER EXTENSION ADD makes any function a member, and the
-- extension's owner runs it, T19-P1-C156, C174), and a definer in definer_functions.sql's platform schemas that a
-- platform role owns.
-- App migrations run as postgres, so an app's own definer holds in any schema.
WITH exposed AS (SELECT DISTINCT btrim(s) AS nspname FROM unnest(string_to_array(coalesce(nullif(current_setting('pgrst.db_schemas', true), ''), (SELECT substr(c.setting, 18) FROM pg_db_role_setting d JOIN pg_roles g ON g.oid = d.setrole CROSS JOIN LATERAL unnest(d.setconfig) AS c(setting) WHERE g.rolname = 'authenticator' AND c.setting ~ '^pgrst[.]db_schemas=' LIMIT 1), 'public'), ',')) AS s), custosa_api AS (SELECT oid FROM pg_roles g WHERE (g.rolname IN ('anon', 'authenticated') OR g.rolname NOT IN ('service_role', 'authenticator') AND pg_has_role((SELECT rr.oid FROM pg_roles rr WHERE rr.rolname = 'authenticator'), g.oid, 'MEMBER')))
SELECT (SELECT coalesce(array_agg(nspname ORDER BY nspname), '{}') FROM exposed)
         AS exposed_schemas,
       EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_graphql') AS graphql_installed,
       EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE ((n.nspname = 'auth' AND c.relname = 'users')
        OR (c.relkind IN ('v', 'm') AND n.nspname IN (SELECT nspname FROM exposed)
            AND EXISTS (SELECT 1 FROM pg_rewrite rw
                         JOIN pg_depend d ON d.classid = 'pg_rewrite'::regclass AND d.objid = rw.oid
                                         AND d.refclassid = 'pg_class'::regclass
                         JOIN pg_class u ON u.oid = d.refobjid JOIN pg_namespace un ON un.oid = u.relnamespace
                        WHERE rw.ev_class = c.oid AND un.nspname = 'auth' AND u.relname = 'users')))
   AND (EXISTS (SELECT 1 FROM aclexplode(coalesce(c.relacl, acldefault('r', c.relowner))) x
          WHERE x.privilege_type = 'SELECT' AND x.grantee = 0)
  OR EXISTS (SELECT 1 FROM pg_attribute t CROSS JOIN LATERAL aclexplode(t.attacl) x
             WHERE t.attrelid = c.oid AND t.attnum > 0 AND NOT t.attisdropped
               AND x.privilege_type = 'SELECT' AND x.grantee = 0)
  OR EXISTS (SELECT 1 FROM custosa_api WHERE has_any_column_privilege(oid, c.oid, 'SELECT')))) AS auth_users_exposed,
       (SELECT coalesce((array_agg(DISTINCT pn.nspname || '.' || p.proname ORDER BY pn.nspname || '.' || p.proname))[1:100], '{}')
          FROM pg_proc p JOIN pg_namespace pn ON pn.oid = p.pronamespace
          JOIN pg_class u ON u.relname = 'users' AND u.relkind IN ('r', 'p')
          JOIN pg_namespace un ON un.oid = u.relnamespace AND un.nspname = 'auth'
         WHERE p.prosecdef AND p.prorettype NOT IN ('trigger'::regtype, 'event_trigger'::regtype)
           AND NOT (pn.nspname IN ('pg_catalog', 'information_schema') AND p.oid < 16384)
           AND NOT EXISTS (SELECT 1 FROM pg_depend d JOIN pg_extension e ON e.oid = d.refobjid
                            WHERE d.classid = 'pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e'
                              AND d.refclassid = 'pg_extension'::regclass
                              AND e.extname IN ('citext', 'pgcrypto', 'uuid-ossp', 'pg_trgm', 'unaccent', 'vector',
                                                'hstore', 'ltree', 'btree_gin', 'btree_gist', 'postgis', 'pg_graphql',
                                                'pg_net', 'pgsodium', 'supabase_vault', 'pg_stat_statements')
                              AND p.proowner IN (SELECT oid FROM pg_roles WHERE rolname IN ('supabase_admin',
                                  'supabase_storage_admin', 'supabase_auth_admin', 'supabase_realtime_admin')))
           AND NOT (pn.nspname IN ('auth', 'storage', 'extensions', 'graphql', 'graphql_public', 'realtime', '_realtime', 'vault', 'pgsodium', 'pgsodium_masks', 'supabase_functions', 'supabase_migrations', 'net', 'cron', 'pgbouncer', '_analytics', 'pgmq')
                    AND p.proowner IN (SELECT oid FROM pg_roles WHERE rolname IN ('supabase_admin', 'supabase_storage_admin',
                                                                                   'supabase_auth_admin', 'supabase_realtime_admin')))
           AND (has_table_privilege(p.proowner, u.oid, 'SELECT')
                OR has_any_column_privilege(p.proowner, u.oid, 'SELECT'))) AS auth_definers

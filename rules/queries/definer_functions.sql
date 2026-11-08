-- The platform's schemas and extension members are left out on Supabase only (S4-16, T23-P1-C59), read as the
-- inspector reads Supabase (catalog.mjs): storage.buckets owned by supabase_storage_admin. Elsewhere `auth` or
-- `cron` is the app's own schema and is kept, as the preflight's definer_functions_executable keeps it.
-- other_execute_roles (T27-P2-C59, T27-P1-C77): the roles other than PUBLIC that hold EXECUTE directly or by
-- membership in a grantee, over every overload, sorted. Left out: the owner, anon, authenticated and phisc_ro (their
-- own fields or this inspector), superusers (they skip every check), and roles that reach EXECUTE only through anon or
-- authenticated (those fields already speak). Past 100 names it is null: not read, so the function holds.
SELECT schema_name, function_name, count(DISTINCT fid)::int AS overloads,
       bool_and(pinned) AS search_path_pinned, bool_or(pub) AS public_execute, bool_or(anon) AS anon_execute,
       bool_or(auth AND NOT trig) AS authenticated_execute, bool_and(trig) AS returns_trigger,
       CASE WHEN count(DISTINCT other) > 100 THEN NULL
            ELSE coalesce(array_agg(DISTINCT other ORDER BY other) FILTER (WHERE other IS NOT NULL), '{}') END
         AS other_execute_roles
  FROM (SELECT p.oid AS fid, o.other, n.nspname::text AS schema_name, p.proname::text AS function_name,
               EXISTS (SELECT 1 FROM unnest(p.proconfig) s WHERE s IN ('search_path=""', 'search_path=pg_temp')
                                                                 OR s LIKE 'search_path=%, pg_temp') AS pinned,
               p.prorettype IN ('trigger'::regtype, 'event_trigger'::regtype) AS trig,
               EXISTS (SELECT 1 FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) x
                        WHERE x.privilege_type = 'EXECUTE' AND x.grantee = 0) AS pub,
               EXISTS (SELECT 1 FROM pg_roles g WHERE g.rolname = 'anon'
                        AND has_function_privilege(g.oid, p.oid, 'EXECUTE')) AS anon,
               EXISTS (SELECT 1 FROM pg_roles g WHERE (g.rolname IN ('anon', 'authenticated') OR g.rolname NOT IN ('service_role', 'authenticator') AND pg_has_role((SELECT rr.oid FROM pg_roles rr WHERE rr.rolname = 'authenticator'), g.oid, 'MEMBER')) AND g.rolname <> 'anon'
                        AND has_function_privilege(g.oid, p.oid, 'EXECUTE')) AS auth
          FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
          LEFT JOIN LATERAL (SELECT r.rolname::text AS other FROM pg_roles r
                              WHERE NOT r.rolsuper AND r.oid <> p.proowner
                                AND r.rolname NOT IN ('anon', 'authenticated', 'phisc_ro')
                                AND EXISTS (SELECT 1 FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) x
                                              JOIN pg_roles gr ON gr.oid = x.grantee
                                             WHERE x.privilege_type = 'EXECUTE'
                                               AND gr.rolname NOT IN ('anon', 'authenticated')
                                               AND (r.oid = x.grantee OR pg_has_role(r.oid, x.grantee, 'MEMBER')))) o ON true
         CROSS JOIN (SELECT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace cn ON cn.oid = c.relnamespace
                                     WHERE cn.nspname = 'storage' AND c.relname = 'buckets'
                                       AND pg_get_userbyid(c.relowner) = 'supabase_storage_admin') AS yes) supa
         WHERE p.prosecdef AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast') AND n.nspname !~ '^pg_'
           AND NOT (supa.yes AND (n.nspname IN ('auth', 'storage', 'extensions', 'graphql', 'graphql_public', 'realtime', '_realtime', 'vault', 'pgsodium', 'pgsodium_masks', 'supabase_functions', 'supabase_migrations', 'net', 'cron', 'pgbouncer', '_analytics', 'pgmq')
                OR EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_proc'::regclass AND d.objid = p.oid
                             AND d.deptype = 'e')))) f
 GROUP BY 1, 2
 ORDER BY 1, 2

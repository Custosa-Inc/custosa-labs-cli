-- A read policy whose condition still holds an auth wrapper ( SELECT auth.uid() ...) after the unwrapping below, in a
-- form the query can't read, is not_read: it counts with the policies whose reach can't be confirmed
-- (unconfirmed_read_policies), never as limited to the owner. Only when the wrapper is what decides it: a policy that
-- is loose outside its wrappers (an OR, NOT, CASE, DISTINCT or a not-equal, with literals blanked and wrappers up to
-- two levels deep cut out) stays open, as the query reads any loose policy.
-- FROM ONLY: a table inheriting from storage.buckets is never read through it (its rows could be any data).
SELECT b.id AS bucket, b.public AS public,
       coalesce(array_agg(f.polname::text ORDER BY f.polname)
                  FILTER (WHERE f.polpermissive AND NOT f.owner AND NOT f.reads), '{}')
         AS open_read_policies,
       coalesce(bool_or(f.owner), false) AS owner_scoped_read,
       coalesce(array_agg(f.polname::text ORDER BY f.polname)
                  FILTER (WHERE f.polpermissive AND NOT f.owner AND NOT f.reads
                            AND f.polcmd = '*'), '{}') AS open_for_all,
       coalesce(array_agg(f.polname::text ORDER BY f.polname)
                  FILTER (WHERE f.polpermissive AND NOT f.owner AND f.reads), '{}')
         AS unconfirmed_read_policies,
       coalesce(bool_or(f.owner AND f.app), false) AS owner_by_app_setting,
       (SELECT c.relrowsecurity FROM pg_class c WHERE c.oid = 'storage.objects'::regclass)
         AS objects_rls_on,
       b.file_size_limit AS file_size_limit,
       coalesce(cardinality(b.allowed_mime_types) > 0, false) AS allowed_mime_types_set
  FROM ONLY storage.buckets b
  LEFT JOIN LATERAL (SELECT p.polname, p.polcmd, p.polpermissive, (e.q !~ '(<>|!=|!~|[[:<:]]NOT[[:>:]](?![[:space:]]+NULL)|[[:<:]]OR[[:>:]]|[[:<:]]CASE[[:>:]]|[[:<:]]DISTINCT[[:>:]])' AND e.q !~* 'user_meta' AND e.u !~ '[[:<:]]SELECT[[:>:]]' AND e.o = '@OWN@') AS owner,
                            EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_policy'::regclass AND d.objid = p.oid
           AND ((d.refclassid = 'pg_class'::regclass AND d.refobjid <> 'storage.objects'::regclass)
                OR d.refclassid = 'pg_operator'::regclass
                OR (d.refclassid = 'pg_proc'::regclass
                    AND NOT EXISTS (SELECT 1 FROM pg_proc h
                                      JOIN pg_namespace hn ON hn.oid = h.pronamespace
                                     WHERE h.oid = d.refobjid AND (hn.nspname = 'pg_catalog'
                                       OR (hn.nspname, h.proname) IN (('auth', 'uid'), ('auth', 'jwt'), ('auth', 'role'), ('auth', 'email'), ('storage', 'foldername'), ('storage', 'filename'), ('storage', 'extension')))))))
                              OR (e.u ~ '[(] SELECT [(]*auth[.](?:uid|jwt)[(]'
    AND NOT (regexp_replace(regexp_replace(e.u, '''(?:[^'']|'''')*''', '''''', 'g'), '[(] SELECT [^()]*(?:[(][^()]*(?:[(][^()]*[)][^()]*)*[)][^()]*)*[)]', '#', 'g') !~ '[[:<:]]SELECT[[:>:]]'
             AND regexp_replace(regexp_replace(e.u, '''(?:[^'']|'''')*''', '''''', 'g'), '[(] SELECT [^()]*(?:[(][^()]*(?:[(][^()]*[)][^()]*)*[)][^()]*)*[)]', '#', 'g') ~ '(<>|!=|!~|[[:<:]]NOT[[:>:]](?![[:space:]]+NULL)|[[:<:]]OR[[:>:]]|[[:<:]]CASE[[:>:]]|[[:<:]]DISTINCT[[:>:]])')) AS reads, e.u ~ 'current_setting[(]''(?![Rr][Ee][Qq][Uu][Ee][Ss][Tt][.])' AS app
                       FROM pg_policy p CROSS JOIN LATERAL (SELECT q, u, regexp_replace(regexp_replace(regexp_replace(regexp_replace(regexp_replace(regexp_replace(regexp_replace(regexp_replace(regexp_replace(regexp_replace(n, '[(]@COL@ = @UID@[)]|[(]@UID@ = @COL@[)]', '@OWN@', 'g'), '@(?:COL|UID)@', 'x', 'g'), '[(][^()@]*[)]', '#', 'g'), '[(](?:[^()@ ]+ AND )*@OWN@(?: AND [^()@ ]+)*[)]', '@OWN@', 'g'), '[(][^()@]*[)]', '#', 'g'), '[(](?:[^()@ ]+ AND )*@OWN@(?: AND [^()@ ]+)*[)]', '@OWN@', 'g'), '[(][^()@]*[)]', '#', 'g'), '[(](?:[^()@ ]+ AND )*@OWN@(?: AND [^()@ ]+)*[)]', '@OWN@', 'g'), '[(][^()@]*[)]', '#', 'g'), '[(](?:[^()@ ]+ AND )*@OWN@(?: AND [^()@ ]+)*[)]', '@OWN@', 'g') AS o
    FROM (SELECT q, u, regexp_replace(regexp_replace(regexp_replace(regexp_replace(regexp_replace(regexp_replace(regexp_replace(u, '[(]current_setting[(]''request[.]jwt[.]claims''::text(?:, (?:true|false))?[)][)]::jsonb? ->> ''sub''::text|current_setting[(]''(?:request[.]jwt[.]claim[.]sub|(?![Rr][Ee][Qq][Uu][Ee][Ss][Tt][.])(?:[^'']|'''')*)''::text(?:, (?:true|false))?[)]|[(]auth[.]jwt[(][)] ->> ''sub''::text[)]|[(]auth[.]uid[(][)][)]|auth[.]uid[(][)]', '@UID@', 'g'), '[(]@UID@[)]|@UID@::(?:text|uuid|jsonb?|character varying)', '@UID@', 'g'), '[(]@UID@[)]|@UID@::(?:text|uuid|jsonb?|character varying)', '@UID@', 'g'), '''(?:[^'']|'''')*''', '''''', 'g'), '[(]storage[.]foldername[(]name[)][)][[][0-9]+[]]|[[:<:]]path_tokens[[][0-9]+[]]|[[:<:]](?:owner_id|owner|name)[[:>:]]', '@COL@', 'g'), '[(]@COL@[)]|@COL@::(?:text|uuid|jsonb?|character varying)', '@COL@', 'g'), '[(]@COL@[)]|@COL@::(?:text|uuid|jsonb?|character varying)', '@COL@', 'g') AS n
    FROM (SELECT q, regexp_replace(regexp_replace(regexp_replace(q,
  '(?<=[(] SELECT [(]*auth[.](?:uid|jwt)[(][)](?: ->> ''sub''::text)?[)]*::(?:text|uuid|jsonb?|character varying))(?: AS [a-z_]+)?[)]|(?<=[(] SELECT [(]*auth[.](?:uid|jwt)[(][)](?: ->> ''sub''::text)?[)]*)(?: AS [a-z_]+[)]|[)](?![)]|::| AS [a-z_]+[)]))', '@W@', 'g'),
  '[(] SELECT (?=[(]*auth[.](?:uid|jwt)[(][)](?: ->> ''sub''::text)?[)]*(?:::(?:text|uuid|jsonb?|character varying))?@W@)', '', 'g'),
  '@W@', '', 'g') AS u
            FROM (SELECT coalesce(pg_get_expr(p.polqual, p.polrelid), '') AS q) e0) e1) e2) e
                      WHERE p.polrelid = 'storage.objects'::regclass AND p.polcmd IN ('r', '*') AND p.polqual IS NOT NULL
  AND EXISTS (SELECT 1 FROM unnest(p.polroles) pr WHERE pr = 0
               OR NOT EXISTS (SELECT 1 FROM pg_roles b WHERE b.oid = pr
                   AND (b.rolname IN ('service_role', 'postgres', 'supabase_admin', 'supabase_auth_admin', 'supabase_storage_admin', 'supabase_functions_admin', 'supabase_realtime_admin', 'supabase_replication_admin', 'supabase_read_only_user', 'dashboard_user', 'authenticator', 'pgbouncer') OR b.rolbypassrls OR b.rolsuper))
               OR EXISTS (SELECT 1 FROM pg_roles g
               WHERE g.rolname IN ('anon', 'authenticated') AND pg_has_role(g.oid, pr, 'USAGE')))
                        AND (e.q !~ '[[:<:]]bucket_id[[:>:]]' OR e.q ~ '(<>|!=|!~|[[:<:]]NOT[[:>:]](?![[:space:]]+NULL)|[[:<:]]OR[[:>:]]|[[:<:]]CASE[[:>:]]|[[:<:]]DISTINCT[[:>:]])'
        OR regexp_replace(e.q, '[[:<:]]bucket_id[[:>:]] = (''(?:[^'']|'''')*''::text|ANY [(]ARRAY[[]''(?:[^'']|'''')*''::text(, ''(?:[^'']|'''')*''::text)*[]][)])|''(?:[^'']|'''')*''::text = [[:<:]]bucket_id[[:>:]]', '', 'g') ~ '[[:<:]]bucket_id[[:>:]]'
        OR strpos(e.q, '''' || replace(b.id, '''', '''''') || '''') > 0)) f ON true
 GROUP BY b.id, b.public, b.file_size_limit, b.allowed_mime_types
 ORDER BY 1

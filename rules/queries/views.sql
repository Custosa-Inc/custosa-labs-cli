-- definer_calls: the functions a view runs that may read what its own reads leave out. It follows only what Postgres
-- records, so each step is exact or fail-closed. The walk starts at the functions, operators, casts and types the
-- view's rule depends on, and at those of every view it reads that sits in a schema left out below (that view is never
-- a row of its own). From each function it reaches, it follows:
-- * a BEGIN ATOMIC body's own dependencies: functions, operators (to oprcode), casts (to castfunc) and types.
-- * a cast Postgres applies, implicit or not, as the function it records for the rule or body.
-- * a type, to the CHECK functions of every domain it holds: itself, its base domains, an array's element, a composite
--   type's or a table's attributes, a range's subtype, a multirange's range, a type a domain's CHECK names (a cast to
--   another domain, or ROW(VALUE) to a composite holding one), at any depth, each type visited once. A
--   domain CHECK's functions are what Postgres records, plus the built-ins in `dyn` and listed functions its conbin
--   names (Postgres records no dependency on a pinned function).
-- * a relation the rule or body reads, to the row types of it and of its pg_inherits descendants at any depth, so a
--   domain reached only through a column or a whole row (jsonb_populate_record(t, ...), hstore's #=) is followed. That
--   fails closed: a domain check that never runs only adds a hold.
-- * an aggregate's support functions.
-- Each view's walk is a plain reachable set, with each function visited once.
-- Listed, and not followed further: a SECURITY DEFINER function (one a superuser made in pg_catalog too). A function
-- whose body Postgres doesn't record (a SQL function with a string body, or any language but sql, c and internal): its
-- calls can't be read, so it may call one. Built-ins and extension functions that run SQL text, reach another server
-- or check a type named by a string (`deny`), named by the rule tree, a body or a domain check. So is a c or internal
-- function whose symbol (prosrc) is one of theirs, or whose library (probin) is dblink's or tablefunc's, under any
-- name. A c function, unless an extension in `ext_ok` owns it. A BEGIN ATOMIC body reading a view in a left-out schema,
-- or a foreign table or a relation with one among its pg_inherits descendants: those rows are out of reads' sight. A
-- foreign table the view reads, directly, through a left-out view, or as a descendant of what it reads, is listed
-- itself.
-- Other internal functions are leaves. Supabase's auth.uid, auth.role, auth.email and auth.jwt are leaves only
-- as shipped (`stock`): invoker, no SET, owned by the auth schema's owner or supabase_auth_admin, and a body whose md5
-- is one Supabase wrote. Any other body there is listed.
-- reads: what the view's rule names, plus what any view in a left-out schema it reads names in turn.
WITH RECURSIVE skip AS (
  SELECT * FROM (VALUES ('pg_catalog'), ('information_schema'), ('pg_toast'), ('auth'), ('storage'), ('extensions'),
                        ('graphql'), ('graphql_public'), ('realtime'), ('_realtime'), ('vault'), ('pgsodium'),
                        ('pgsodium_masks'), ('supabase_functions'), ('supabase_migrations'), ('net'), ('cron'),
                        ('pgbouncer'), ('_analytics'), ('pgmq')) AS t(nsp)
), stock AS (
  SELECT * FROM (VALUES
    -- github.com/supabase/postgres migrations/db/init-scripts/00000000000001-auth-schema.sql at ea0e40f4
    ('uid', '72769e6b3ee8edb21a9942ab6ff3607f'), ('role', 'd4bb3ab4cc808cfb3f95aecdf2abb102'),
    ('email', '4c41429f8d61796c37ae460a28e700af'),
    -- github.com/supabase/auth migrations/20220224000811_update_auth_functions.up.sql at e062eeae
    ('uid', 'cdef18c69c4f4cbbced2eaf81e628b49'), ('role', 'f31486fed08a7402e89d4aa71b0ad273'),
    ('email', 'd83fa9609bbd5e95512922e407b4141d'),
    -- github.com/supabase/auth migrations/20220531120530_add_auth_jwt_function.up.sql at 3b77d62d
    ('jwt', '2db09c3fc855ba90e71d3ae28cfadae3')) AS t(name, body_md5)
), ext_ok AS (
  SELECT * FROM (VALUES ('citext'), ('pgcrypto'), ('uuid-ossp'), ('pg_trgm'), ('unaccent'), ('vector'), ('hstore'),
                        ('ltree'), ('btree_gin'), ('btree_gist'), ('postgis')) AS t(name)
), deny AS (
  SELECT * FROM (VALUES ('dblink'), ('dblink_exec'), ('dblink_send_query'), ('dblink_open'), ('dblink_fetch'),
                        ('dblink_get_result'), ('connectby'), ('ts_stat'), ('pg_input_is_valid'),
                        ('pg_input_error_info')) AS t(name)
), denied AS (
  -- the pinned built-ins `deny` and its patterns name (a c or internal function running one of their symbols is too)
  SELECT p.oid, p.proname, p.prosrc FROM pg_proc p
   WHERE p.pronamespace = 'pg_catalog'::regnamespace AND p.oid < 16384
     AND (p.proname IN (SELECT name FROM deny) OR p.proname ~ '^(query|table|schema|database|cursor)_to_xml'
          OR p.proname = 'ts_rewrite' AND p.pronargs = 2 AND p.proargtypes[1] = 'text'::regtype)
), relkin AS (
  -- each relation, and its pg_inherits descendants at any depth
  SELECT c.oid AS rel, c.oid AS sub FROM pg_class c WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f')
  UNION
  SELECT k.rel, i.inhrelid FROM relkin k JOIN pg_inherits i ON i.inhparent = k.sub
), outside AS (
  SELECT k.rel AS oid FROM relkin k JOIN pg_class s ON s.oid = k.sub WHERE s.relkind = 'f'
  UNION
  SELECT c.oid FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE c.relkind IN ('v', 'm') AND n.nspname NOT IN ('pg_catalog', 'information_schema')
     AND (n.nspname IN (SELECT nsp FROM skip) OR n.nspname ~ '^pg_')
), fn AS (
  SELECT p.oid, pn.nspname || '.' || p.proname AS qualified, p.prosqlbody,
         coalesce(p.prosecdef OR l.lanname NOT IN ('sql', 'c', 'internal')
           OR l.lanname = 'sql' AND p.prosqlbody IS NULL
              AND NOT (pn.nspname = 'auth' AND p.pronargs = 0 AND p.proconfig IS NULL
                       AND (p.proowner = pn.nspowner
                            OR p.proowner IN (SELECT oid FROM pg_roles WHERE rolname = 'supabase_auth_admin'))
                       AND (p.proname, md5(p.prosrc)) IN (SELECT name, body_md5 FROM stock))
           OR l.lanname IN ('c', 'internal')
              AND (p.proname IN (SELECT name FROM deny) OR p.proname LIKE 'crosstab%'
                   OR p.proname ~ '^(query|table|schema|database|cursor)_to_xml'
                   OR p.proname = 'ts_rewrite' AND p.pronargs = 2 AND p.proargtypes[1] = 'text'::regtype
                   OR p.prosrc IN (SELECT prosrc FROM denied) OR p.prosrc IN (SELECT name FROM deny)
                   OR p.prosrc LIKE 'crosstab%' OR regexp_replace(coalesce(p.probin, ''), '^.*/', '')
                      IN ('dblink', 'dblink.so', 'tablefunc', 'tablefunc.so'))
           OR l.lanname = 'c'
              AND NOT EXISTS (SELECT 1 FROM pg_depend d JOIN pg_extension x ON x.oid = d.refobjid
                               WHERE d.classid = 'pg_proc'::regclass AND d.objid = p.oid
                                 AND d.refclassid = 'pg_extension'::regclass AND d.deptype = 'e'
                                 AND x.extname IN (SELECT name FROM ext_ok))
           OR EXISTS (SELECT 1 FROM pg_depend d JOIN outside o ON o.oid = d.refobjid
                       WHERE d.classid = 'pg_proc'::regclass AND d.objid = p.oid AND d.refclassid = 'pg_class'::regclass),
           true) AS listed
    FROM pg_proc p JOIN pg_namespace pn ON pn.oid = p.pronamespace JOIN pg_language l ON l.oid = p.prolang
   WHERE pn.nspname NOT IN ('pg_catalog', 'information_schema') OR p.oid >= 16384
  UNION ALL
  SELECT oid, 'pg_catalog.' || proname, NULL, true FROM denied
), dyn AS (
  -- built-ins: Postgres records no dependency on them, so the rule tree or body is searched for their funcid
  SELECT oid, ':funcid ' || oid || ' ' AS mark FROM fn WHERE oid < 16384
), dep0 AS (
  SELECT d.classid, d.objid, d.refobjid AS fn FROM pg_depend d WHERE d.refclassid = 'pg_proc'::regclass
  UNION
  SELECT d.classid, d.objid, o.oprcode::oid FROM pg_depend d JOIN pg_operator o ON o.oid = d.refobjid
   WHERE d.refclassid = 'pg_operator'::regclass
  UNION
  SELECT d.classid, d.objid, k.castfunc FROM pg_depend d JOIN pg_cast k ON k.oid = d.refobjid
   WHERE d.refclassid = 'pg_cast'::regclass AND k.castfunc <> 0
), chk AS (
  SELECT k.contypid AS typ, e.fn FROM pg_constraint k
    JOIN dep0 e ON e.classid = 'pg_constraint'::regclass AND e.objid = k.oid
   WHERE k.contypid <> 0
  UNION
  SELECT k.contypid, f.oid FROM pg_constraint k JOIN fn f ON f.listed
   WHERE k.contypid <> 0 AND k.conbin IS NOT NULL AND strpos(k.conbin::text, ':funcid ' || f.oid || ' ') > 0
), holds AS (
  SELECT t.oid AS outer_typ, t.typbasetype AS inner_typ FROM pg_type t WHERE t.typtype = 'd'
  UNION ALL
  SELECT t.oid, t.typelem FROM pg_type t WHERE t.typelem <> 0
  UNION ALL
  SELECT t.oid, a.atttypid FROM pg_type t JOIN pg_attribute a ON a.attrelid = t.typrelid
   WHERE t.typrelid <> 0 AND a.attnum > 0 AND NOT a.attisdropped
  UNION ALL
  SELECT g.rngtypid, g.rngsubtype FROM pg_range g
  UNION ALL
  SELECT g.rngmultitypid, g.rngtypid FROM pg_range g
  UNION ALL
  -- a domain whose CHECK names another type (a cast to a domain, or ROW(VALUE) to a composite holding one)
  SELECT k.contypid, d.refobjid FROM pg_constraint k
    JOIN pg_depend d ON d.classid = 'pg_constraint'::regclass AND d.objid = k.oid AND d.refclassid = 'pg_type'::regclass
   WHERE k.contypid <> 0
), within AS (
  SELECT DISTINCT typ, typ AS dom FROM chk
  UNION
  SELECT h.outer_typ, w.dom FROM within w JOIN holds h ON h.inner_typ = w.typ
), typ_fn AS (
  SELECT w.typ, c.fn FROM within w JOIN chk c ON c.typ = w.dom
), rel_fn AS (
  SELECT k.rel, y.fn FROM relkin k JOIN pg_class s ON s.oid = k.sub JOIN typ_fn y ON y.typ = s.reltype
), dep AS (
  SELECT e.classid, e.objid, e.fn FROM dep0 e
  UNION
  SELECT d.classid, d.objid, y.fn FROM pg_depend d JOIN typ_fn y ON y.typ = d.refobjid
   WHERE d.refclassid = 'pg_type'::regclass
  UNION
  SELECT d.classid, d.objid, y.fn FROM pg_depend d JOIN rel_fn y ON y.rel = d.refobjid
   WHERE d.refclassid = 'pg_class'::regclass
), hidden AS (
  SELECT o.oid FROM outside o JOIN pg_class c ON c.oid = o.oid WHERE c.relkind IN ('v', 'm')
), vread AS (
  SELECT rw.ev_class AS v, d.refobjid AS rel FROM pg_rewrite rw
    JOIN pg_depend d ON d.classid = 'pg_rewrite'::regclass AND d.objid = rw.oid AND d.refclassid = 'pg_class'::regclass
  UNION
  SELECT r.v, d.refobjid FROM vread r JOIN hidden h ON h.oid = r.rel JOIN pg_rewrite rw ON rw.ev_class = r.rel
    JOIN pg_depend d ON d.classid = 'pg_rewrite'::regclass AND d.objid = rw.oid AND d.refclassid = 'pg_class'::regclass
), vrule AS (
  SELECT rw.ev_class AS v, rw.oid AS rule FROM pg_rewrite rw
  UNION
  SELECT r.v, rw.oid FROM vread r JOIN hidden h ON h.oid = r.rel JOIN pg_rewrite rw ON rw.ev_class = r.rel
), edge AS (
  SELECT e.objid AS src, e.fn AS dst FROM dep e WHERE e.classid = 'pg_proc'::regclass
  UNION
  SELECT f.oid, x.oid FROM fn f JOIN dyn x ON strpos(f.prosqlbody::text, x.mark) > 0
  UNION
  SELECT a.aggfnoid::oid, s.fn FROM pg_aggregate a
   CROSS JOIN LATERAL unnest(ARRAY[a.aggtransfn::oid, a.aggfinalfn::oid, a.aggcombinefn::oid, a.aggserialfn::oid,
                                   a.aggdeserialfn::oid, a.aggmtransfn::oid, a.aggminvtransfn::oid, a.aggmfinalfn::oid])
                 AS s(fn)
), step AS MATERIALIZED (
  -- what the walk follows, worked out once: an edge out of a function that isn't listed, into one it can read
  SELECT DISTINCT e.src, e.dst FROM edge e JOIN fn g ON g.oid = e.src AND NOT g.listed JOIN fn h ON h.oid = e.dst
), start AS (
  SELECT r.v, e.fn FROM vrule r JOIN dep e ON e.classid = 'pg_rewrite'::regclass AND e.objid = r.rule
  UNION
  SELECT r.v, x.oid FROM vrule r JOIN pg_rewrite rw ON rw.oid = r.rule JOIN dyn x ON strpos(rw.ev_action::text, x.mark) > 0
), reach AS (
  SELECT s.v, s.fn FROM start s JOIN fn g ON g.oid = s.fn
  UNION
  SELECT r.v, s.dst FROM reach r JOIN step s ON s.src = r.fn
), listed AS (
  SELECT r.v, f.qualified AS name FROM reach r JOIN fn f ON f.oid = r.fn AND f.listed
  UNION
  SELECT r.v, rn.nspname || '.' || rc.relname FROM vread r JOIN relkin k ON k.rel = r.rel
    JOIN pg_class rc ON rc.oid = k.sub AND rc.relkind = 'f' JOIN pg_namespace rn ON rn.oid = rc.relnamespace
), calls AS (
  SELECT v, (array_agg(name ORDER BY name))[1:100] AS names FROM listed GROUP BY v
), vreads AS (
  SELECT r.v, array_agg(DISTINCT rn.nspname || '.' || rc.relname) AS names
    FROM vread r JOIN pg_class rc ON rc.oid = r.rel JOIN pg_namespace rn ON rn.oid = rc.relnamespace
   WHERE rc.oid <> r.v AND rc.relkind IN ('r', 'p', 'v', 'm', 'f')
   GROUP BY r.v
)
SELECT n.nspname::text AS schema_name, c.relname::text AS view_name,
       CASE c.relkind WHEN 'm' THEN 'materialized_view' ELSE 'view' END AS kind,
       coalesce((SELECT bool_or(lower(o.opt) IN ('security_invoker=true', 'security_invoker=on', 'security_invoker=1', 'security_invoker=yes'))
                   FROM unnest(c.reloptions) AS o(opt) WHERE o.opt ~ '^security_invoker='), false)
         AS security_invoker,
       coalesce(x.names, '{}') AS reads,
       (EXISTS (SELECT 1 FROM aclexplode(coalesce(c.relacl, acldefault('r', c.relowner))) x WHERE x.privilege_type = 'SELECT' AND x.grantee = 0)
        OR EXISTS (SELECT 1 FROM pg_attribute t CROSS JOIN LATERAL aclexplode(t.attacl) x
                    WHERE t.attrelid = c.oid AND t.attnum > 0 AND NOT t.attisdropped
                      AND x.privilege_type = 'SELECT' AND x.grantee = 0)
        OR EXISTS (SELECT 1 FROM pg_roles g WHERE (g.rolname IN ('anon', 'authenticated') OR g.rolname NOT IN ('service_role', 'authenticator') AND pg_has_role((SELECT rr.oid FROM pg_roles rr WHERE rr.rolname = 'authenticator'), g.oid, 'MEMBER'))
                      AND has_any_column_privilege(g.oid, c.oid, 'SELECT'))) AS api_select,
       (EXISTS (SELECT 1 FROM aclexplode(coalesce(c.relacl, acldefault('r', c.relowner))) x WHERE x.privilege_type = 'SELECT'
                  AND x.grantee <> 0 AND x.grantee <> c.relowner AND x.grantee NOT IN (SELECT oid FROM pg_roles WHERE rolname IN ('anon', 'authenticated')))
        OR EXISTS (SELECT 1 FROM pg_attribute t CROSS JOIN LATERAL aclexplode(t.attacl) x
                    WHERE t.attrelid = c.oid AND t.attnum > 0 AND NOT t.attisdropped AND x.privilege_type = 'SELECT'
                      AND x.grantee <> 0 AND x.grantee <> c.relowner AND x.grantee NOT IN (SELECT oid FROM pg_roles WHERE rolname IN ('anon', 'authenticated')))) AS other_select,
       coalesce(k.names, '{}') AS definer_calls
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  LEFT JOIN vreads x ON x.v = c.oid LEFT JOIN calls k ON k.v = c.oid
 WHERE c.relkind IN ('v', 'm') AND n.nspname NOT IN (SELECT nsp FROM skip) AND n.nspname !~ '^pg_'
 ORDER BY 1, 2

WITH custosa_api AS (SELECT g.oid FROM pg_catalog.pg_roles g WHERE (g.rolname IN ('anon', 'authenticated') OR g.rolname NOT IN ('service_role', 'authenticator') AND pg_catalog.pg_has_role((SELECT rr.oid FROM pg_catalog.pg_roles rr WHERE rr.rolname = 'authenticator'), g.oid, 'MEMBER')))
SELECT n.nspname::text AS schema_name,
  CASE d.defaclobjtype WHEN 'r' THEN 'table' WHEN 'S' THEN 'sequence' WHEN 'f' THEN 'function' WHEN 'T' THEN 'type'
    WHEN 'n' THEN 'schema' END AS object_type,
  g.rolname::text AS grantor,
  CASE WHEN a.grantee = 0 THEN 'public' ELSE e.rolname::text END AS grantee,
  pg_catalog.array_agg(DISTINCT pg_catalog.lower(a.privilege_type)) AS privileges,
  a.grantee = 0 OR a.grantee IN (SELECT oid FROM custosa_api) AS api_grantee
FROM pg_catalog.pg_default_acl d
LEFT JOIN pg_catalog.pg_roles g ON g.oid = d.defaclrole
LEFT JOIN pg_catalog.pg_namespace n ON n.oid = d.defaclnamespace
CROSS JOIN LATERAL pg_catalog.aclexplode(d.defaclacl) AS a
LEFT JOIN pg_catalog.pg_roles e ON e.oid = a.grantee
GROUP BY d.oid, n.nspname, d.defaclobjtype, g.rolname, a.grantee, e.rolname
ORDER BY 1, 2, 3, 4

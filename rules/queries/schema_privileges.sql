SELECT n.nspname::text AS schema_name,
  CASE WHEN a.grantee = 0 THEN 'public' ELSE e.rolname::text END AS grantee,
  pg_catalog.bool_or(a.privilege_type = 'USAGE') AS usage,
  pg_catalog.bool_or(a.privilege_type = 'CREATE') AS "create"
FROM pg_catalog.pg_namespace n
CROSS JOIN LATERAL pg_catalog.aclexplode(n.nspacl) AS a
LEFT JOIN pg_catalog.pg_roles e ON e.oid = a.grantee
WHERE n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast') AND a.grantee <> n.nspowner AND a.privilege_type IN ('USAGE', 'CREATE')
GROUP BY n.oid, n.nspname, a.grantee, e.rolname
ORDER BY 1, 2

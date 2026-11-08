-- Client sessions on this database other than the inspector's own. Without pg_read_all_stats (which the preflight
-- refuses) another role's backend_type reads as NULL, so NULL is kept, and background workers have no user. The
-- inspector buckets application_name into the row's application (rule_bundle.md 5.1) and never sends the name.
SELECT a.usename::text AS role_name, COALESCE(a.application_name, '')::text AS application_name,
  pg_catalog.count(*)::int AS sessions
FROM pg_catalog.pg_stat_activity a
WHERE a.pid <> pg_catalog.pg_backend_pid() AND a.usename IS NOT NULL AND a.datname = current_catalog
  AND (a.backend_type IS NULL OR a.backend_type = 'client backend')
GROUP BY 1, 2
ORDER BY 1, 2

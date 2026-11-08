SELECT EXISTS (SELECT 1 FROM pg_settings WHERE name = 'pgaudit.log') AS pgaudit_installed, g.pgaudit_log,
 g.audit_role, coalesce((SELECT array_agg(n.nspname || '.' || c.relname ORDER BY n.nspname, c.relname)
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace JOIN pg_roles a ON a.rolname = g.audit_role
  WHERE c.relkind IN ('r', 'p') AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast') AND n.nspname !~ '^pg_' AND has_table_privilege(a.oid, c.oid, 'SELECT')), '{}')
  AS audited_tables, g.server_value_hidden, g.log_parameter
 FROM (SELECT DISTINCT coalesce(x.l, h.l, '') AS pgaudit_log, nullif(coalesce(x.o, h.o, ''), '') AS audit_role,
  (x.l IS NULL OR x.o IS NULL) AND h.l IS NULL AS server_value_hidden,
  lower(coalesce(x.p, hp.p, 'off')) IN ('on', 't', 'tr', 'tru', 'true', 'y', 'ye', 'yes', '1') AS log_parameter
  FROM (SELECT datid AS db FROM pg_stat_activity WHERE pid = pg_backend_pid()) t CROSS JOIN pg_roles r
  CROSS JOIN LATERAL (SELECT (array_agg(substr(c.s, 13) ORDER BY d.setrole = 0, d.setdatabase = 0)
   FILTER (WHERE c.s ~* '^(pgaudit[.]log)='))[1] AS l, (array_agg(substr(c.s, 14) ORDER BY d.setrole = 0,
   d.setdatabase = 0) FILTER (WHERE c.s ~* '^(pgaudit[.]role)='))[1] AS o,
   (array_agg(substr(c.s, 23) ORDER BY d.setrole = 0, d.setdatabase = 0)
   FILTER (WHERE c.s ~* '^(pgaudit[.]log_parameter)='))[1] AS p
   FROM pg_db_role_setting d CROSS JOIN LATERAL unnest(d.setconfig) AS c(s) WHERE d.setrole IN (r.oid, 0) AND d.setdatabase IN (0, t.db)) x
  LEFT JOIN LATERAL (SELECT coalesce(current_setting('pgaudit.log', true), '') AS l,
   coalesce(current_setting('pgaudit.role', true), '') AS o WHERE NOT EXISTS (SELECT 1 FROM pg_db_role_setting d CROSS JOIN LATERAL unnest(d.setconfig) AS c(s)
   WHERE d.setrole = (SELECT oid FROM pg_roles WHERE rolname = session_user) AND c.s ~* '^(pgaudit[.](log|role))=' AND d.setdatabase IN (0, t.db))) h ON true
  LEFT JOIN LATERAL (SELECT coalesce(current_setting('pgaudit.log_parameter', true), '') AS p
   WHERE NOT EXISTS (SELECT 1 FROM pg_db_role_setting d CROSS JOIN LATERAL unnest(d.setconfig) AS c(s)
   WHERE d.setrole = (SELECT oid FROM pg_roles WHERE rolname = session_user)
   AND c.s ~* '^(pgaudit[.]log_parameter)=' AND d.setdatabase IN (0, t.db))) hp ON true
  WHERE r.rolcanlogin) g
 ORDER BY 2, 3, 5, 6

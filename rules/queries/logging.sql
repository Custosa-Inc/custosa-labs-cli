SELECT current_setting('log_connections') AS log_connections,
 current_setting('log_disconnections') AS log_disconnections, current_setting('log_statement') AS log_statement,
 coalesce((SELECT setting::int FROM pg_settings WHERE name = 'log_parameter_max_length'), -1) AS log_parameter_max_length,
 (SELECT setting::int FROM pg_settings WHERE name = 'log_min_duration_statement') AS log_min_duration_statement,
 x.role_statement_logging, x.role_duration_logging, x.role_parameter_logging,
 coalesce((SELECT setting::int >= 0 FROM pg_settings WHERE name = 'log_min_duration_sample'), false) AND coalesce((SELECT setting::float8 > 0 FROM pg_settings WHERE name = 'log_statement_sample_rate'), false)
   AS sampled_logging, coalesce((SELECT setting::float8 > 0 FROM pg_settings WHERE name = 'log_transaction_sample_rate'), false) AS transaction_logging,
 x.role_sample_logging, x.role_transaction_logging, a.auto_explain_on, a.auto_explain_unseen,
 coalesce((SELECT array_agg(name ORDER BY name) FROM pg_settings WHERE name IN ('log_statement')
   AND source IN ('database', 'global')), '{}') AS from_database, x.own_role_settings
 FROM (SELECT (count(*) FILTER (WHERE c.s ~* '^(log_statement)=(mod|all)(?!.)'))::int AS role_statement_logging,
   (count(*) FILTER (WHERE c.s ~* '^(log_min_duration_statement)=(?!-1(?!.))'))::int AS role_duration_logging,
   (count(*) FILTER (WHERE c.s ~* '^(log_parameter_max_length)=(?!0(?!.))'))::int AS role_parameter_logging,
   (count(*) FILTER (WHERE c.s ~* '^(log_min_duration_sample)=(?!-1(?!.))'
     OR c.s ~* '^(log_statement_sample_rate)=(?!0+([.]0*)?(?!.))'))::int AS role_sample_logging,
   (count(*) FILTER (WHERE c.s ~* '^(log_transaction_sample_rate)=(?!0+([.]0*)?(?!.))'))::int AS role_transaction_logging,
   coalesce(bool_or(d.setrole = (SELECT oid FROM pg_roles WHERE rolname = session_user) AND c.s ~* '^(log_(statement|min_duration_statement|parameter_max_length|min_duration_sample|statement_sample_rate|transaction_sample_rate)|(session|local)_preload_libraries)='), false) AS own_role_settings
   FROM pg_db_role_setting d CROSS JOIN LATERAL unnest(d.setconfig) AS c(s) WHERE d.setdatabase IN (0, (SELECT datid FROM pg_stat_activity WHERE pid = pg_backend_pid()))
   AND d.setrole IN (SELECT oid FROM pg_roles WHERE rolcanlogin)) x
 CROSS JOIN LATERAL (SELECT coalesce(array_agg(e.n ORDER BY e.n) FILTER (WHERE e.v), '{}') AS auto_explain_on,
   coalesce(array_agg(e.n ORDER BY e.n) FILTER (WHERE e.v IS NULL), '{}') AS auto_explain_unseen
  FROM (SELECT r.rolname::text AS n, CASE WHEN me.s IS NOT NULL OR coalesce(o.p ~* 'auto_explain', false) OR o.l
     THEN coalesce(o.v, CASE WHEN NOT me.own THEN me.s END) !~ '^ *-' ELSE false END AS v
   FROM (SELECT datid AS db FROM pg_stat_activity WHERE pid = pg_backend_pid()) t
   CROSS JOIN LATERAL (SELECT (SELECT setting FROM pg_settings WHERE name = 'auto_explain.log_min_duration') AS s,
     EXISTS (SELECT 1 FROM pg_db_role_setting d CROSS JOIN LATERAL unnest(d.setconfig) AS c(s) WHERE d.setrole = (SELECT oid FROM pg_roles WHERE rolname = session_user) AND d.setdatabase IN (0, t.db) AND c.s ~* '^(auto_explain[.]log_min_duration)=') AS own) me
   CROSS JOIN pg_roles r CROSS JOIN LATERAL (SELECT r.rolname IN ('anon', 'authenticated', 'service_role')
     AND NOT r.rolcanlogin AS api) k
   CROSS JOIN LATERAL (SELECT (array_agg(substr(c.s, 31) ORDER BY d.setrole = 0, d.setrole <> r.oid, d.setdatabase = 0) FILTER (WHERE c.s ~* '^(auto_explain[.]log_min_duration)='))[1] AS v, (array_agg(substr(c.s, 27) ORDER BY d.setrole = 0, d.setrole <> r.oid, d.setdatabase = 0) FILTER (WHERE c.s ~* '^(session_preload_libraries)='))[1] AS p,
     coalesce(bool_or(c.s ~* '^(local_preload_libraries)=.*auto_explain'), false) AS l FROM pg_db_role_setting d CROSS JOIN LATERAL unnest(d.setconfig) AS c(s)
     WHERE d.setdatabase IN (0, t.db) AND (d.setrole IN (r.oid, 0)
       OR (k.api AND d.setrole = (SELECT oid FROM pg_roles WHERE rolname = 'authenticator')))) o
   WHERE r.rolcanlogin OR k.api) e) a

SELECT current_setting('password_encryption') AS password_encryption, (SELECT setting FROM pg_settings WHERE name = 'ssl_min_protocol_version') AS ssl_min_protocol_version,
 x.role_md5_settings,
 coalesce((SELECT array_agg(name ORDER BY name) FROM pg_settings WHERE name IN ('password_encryption')
   AND source IN ('database', 'global')), '{}') AS from_database, x.own_role_settings
 FROM (SELECT (count(*) FILTER (WHERE c.s ~* '^(password_encryption)=(?!scram-sha-256(?!.))'))::int AS role_md5_settings,
   coalesce(bool_or(d.setrole = (SELECT oid FROM pg_roles WHERE rolname = session_user) AND c.s ~* '^(password_encryption)='), false) AS own_role_settings FROM pg_db_role_setting d CROSS JOIN LATERAL unnest(d.setconfig) AS c(s) WHERE d.setdatabase IN (0, (SELECT datid FROM pg_stat_activity WHERE pid = pg_backend_pid()))
   AND d.setrole IN (SELECT oid FROM pg_roles WHERE rolcanlogin)) x

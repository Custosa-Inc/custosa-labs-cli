SELECT current_setting('ssl') AS ssl, (SELECT setting FROM pg_settings WHERE name = 'ssl_min_protocol_version') AS ssl_min_protocol_version,
 (SELECT count(*)::int FROM pg_stat_ssl s JOIN pg_stat_activity a ON a.pid = s.pid
   WHERE a.backend_type = 'client backend' AND a.client_addr IS NOT NULL AND NOT s.ssl) AS sessions_without_tls,
 (SELECT count(*)::int FROM pg_stat_activity a WHERE a.usesysid IS NOT NULL AND a.backend_type IS NULL)
   AS sessions_unseen, (SELECT setting FROM pg_settings WHERE name = 'rds.force_ssl') AS rds_force_ssl

WITH exposed AS (SELECT DISTINCT btrim(s) AS nspname FROM unnest(string_to_array(coalesce(nullif(current_setting('pgrst.db_schemas', true), ''), (SELECT substr(c.setting, 18) FROM pg_db_role_setting d JOIN pg_roles g ON g.oid = d.setrole CROSS JOIN LATERAL unnest(d.setconfig) AS c(setting) WHERE g.rolname = 'authenticator' AND c.setting ~ '^pgrst[.]db_schemas=' LIMIT 1), 'public'), ',')) AS s), custosa_api AS (SELECT oid FROM pg_roles g WHERE (g.rolname IN ('anon', 'authenticated') OR g.rolname NOT IN ('service_role', 'authenticator') AND pg_has_role((SELECT rr.oid FROM pg_roles rr WHERE rr.rolname = 'authenticator'), g.oid, 'MEMBER')))
SELECT 'queue_tables_open' AS lint, count(*)::int AS findings, coalesce((array_agg(n.nspname || '.' || c.relname ORDER BY n.nspname, c.relname))[1:1000], '{}') AS tables
 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = 'pgmq' AND c.relkind IN ('r', 'p') AND c.relname ~ '^q_' AND NOT c.relrowsecurity
   AND EXISTS (SELECT 1 FROM exposed WHERE nspname = 'pgmq_public')
   AND EXISTS (SELECT 1 FROM custosa_api WHERE has_any_column_privilege(oid, c.oid, 'SELECT'))
UNION ALL
SELECT 'sensitive_columns_open', count(*)::int, coalesce((array_agg(n.nspname || '.' || c.relname ORDER BY n.nspname, c.relname))[1:1000], '{}')
 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE c.relkind IN ('r', 'p') AND n.nspname IN (SELECT nspname FROM exposed) AND NOT c.relrowsecurity
   AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
     AND a.attname ~* '(ssn|social_security|passport|drivers?_licen[cs]e|tax_id|credit_card|card_number|bank_account|password|secret|api_key|date_of_birth|^dob(?!.))')
   AND EXISTS (SELECT 1 FROM custosa_api WHERE has_any_column_privilege(oid, c.oid, 'SELECT'))
 ORDER BY 1

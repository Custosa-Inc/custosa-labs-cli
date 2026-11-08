SELECT n.nspname::text AS schema_name, c.relname::text AS table_name, t.tgname::text AS trigger_name,
  CASE WHEN (t.tgtype::int & 64) <> 0 THEN 'instead_of' WHEN (t.tgtype::int & 2) <> 0 THEN 'before' ELSE 'after' END AS timing,
  ARRAY(SELECT v.e FROM (VALUES (4, 'insert', 1), (16, 'update', 2), (8, 'delete', 3), (32, 'truncate', 4)) AS v(b, e, o)
    WHERE (t.tgtype::int & v.b) <> 0 ORDER BY v.o) AS events,
  CASE t.tgenabled WHEN 'O' THEN 'origin' WHEN 'A' THEN 'always' WHEN 'R' THEN 'replica' WHEN 'D' THEN 'disabled' END AS enabled
FROM pg_catalog.pg_trigger t
JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE NOT t.tgisinternal AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
ORDER BY 1, 2, 3

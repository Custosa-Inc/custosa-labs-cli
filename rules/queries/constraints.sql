-- NOT VALID constraints and unique indexes that are ready but not valid (a failed CREATE INDEX CONCURRENTLY) are kept:
-- Postgres enforces them on every new or changed row. A unique index not yet ready (indisready false) enforces nothing
-- and is left out, and so is an invalid index on a partitioned table (relkind I, made ON ONLY): it enforces nothing
-- until every partition has one attached, when Postgres marks it valid. A constraint on such an index is left out the
-- same way. The inspector joins referenced_schema and referenced_name into the row's referenced_table, after hashing
-- each part on its own where needed.
SELECT n.nspname::text AS schema_name, c.relname::text AS table_name, k.conname::text AS constraint_name,
  CASE k.contype WHEN 'p' THEN 'primary' WHEN 'u' THEN 'unique' WHEN 'f' THEN 'foreign' WHEN 'c' THEN 'check'
    WHEN 'x' THEN 'exclusion' END AS type,
  ARRAY(SELECT a.attname::text FROM pg_catalog.unnest(k.conkey) WITH ORDINALITY AS u(attnum, ord)
    JOIN pg_catalog.pg_attribute a ON a.attrelid = k.conrelid AND a.attnum = u.attnum ORDER BY u.ord) AS columns,
  COALESCE(i.indexprs IS NOT NULL, false) AS expression,
  COALESCE(i.indpred IS NOT NULL, false) AS partial,
  rn.nspname::text AS referenced_schema, rc.relname::text AS referenced_name
FROM pg_catalog.pg_constraint k
JOIN pg_catalog.pg_class c ON c.oid = k.conrelid
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
LEFT JOIN pg_catalog.pg_index i ON i.indexrelid = k.conindid AND k.contype IN ('p', 'u', 'x')
LEFT JOIN pg_catalog.pg_class ki ON ki.oid = k.conindid AND k.contype IN ('p', 'u', 'x')
LEFT JOIN pg_catalog.pg_class rc ON rc.oid = k.confrelid AND k.contype = 'f'
LEFT JOIN pg_catalog.pg_namespace rn ON rn.oid = rc.relnamespace
WHERE k.contype IN ('p', 'u', 'f', 'c', 'x') AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
  AND (k.contype NOT IN ('p', 'u', 'x') OR (i.indisready AND (i.indisvalid OR ki.relkind <> 'I')))
UNION ALL
SELECT n.nspname::text, c.relname::text, ic.relname::text, 'unique_index',
  ARRAY(SELECT a.attname::text FROM pg_catalog.unnest(i.indkey::int2[]) WITH ORDINALITY AS u(attnum, ord)
    JOIN pg_catalog.pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = u.attnum
    WHERE u.ord <= i.indnkeyatts ORDER BY u.ord),
  i.indexprs IS NOT NULL, i.indpred IS NOT NULL, NULL, NULL
FROM pg_catalog.pg_index i
JOIN pg_catalog.pg_class ic ON ic.oid = i.indexrelid
JOIN pg_catalog.pg_class c ON c.oid = i.indrelid
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE i.indisunique AND i.indisready AND (i.indisvalid OR ic.relkind <> 'I') AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
  AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint x
                  WHERE x.conindid = i.indexrelid AND x.conrelid = i.indrelid AND x.contype IN ('p', 'u', 'x'))
ORDER BY 1, 2, 3

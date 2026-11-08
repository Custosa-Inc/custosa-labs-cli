SELECT p.pubname::text AS publication, p.schemaname::text AS schema_name, p.tablename::text AS table_name
FROM pg_catalog.pg_publication_tables p
ORDER BY 1, 2, 3

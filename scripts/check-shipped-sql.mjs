#!/usr/bin/env node
/* Shipped query check: every catalog query the inspector runs must pass checkShippedSql, the same check
 * collectCatalog applies before it runs one. A refused query fails with invalid_query on every user's database, so CI
 * fails here first.
 *
 *   node scripts/check-shipped-sql.mjs   exit 1 on any refusal, or on a rules/queries/*.sql file that is neither run
 *                                        nor listed in NOT_RUN below
 *
 * The queries are factdoc.QUERY_IDS, read with shippedQuerySql (rules/queries/<id>.sql), as loadQueries reads them. */
import { readdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { checkShippedSql } from "../lib/inspector/catalog.mjs";
import { shippedQuerySql } from "../lib/inspector/catalogfacts.mjs";
import { QUERY_IDS } from "../lib/inspector/factdoc.mjs";

// In the rule set but never run by the CLI: the preflight runs catalog.mjs's own PREFLIGHT_SQL instead.
const NOT_RUN = new Set(["preflight"]);
const QUERIES_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..", "rules", "queries");

const problems = [];
for (const id of QUERY_IDS) {
  let sql;
  try { sql = shippedQuerySql(id); } catch (err) { problems.push(`${id}: no shipped file (${err.code ?? err.message})`); continue; }
  const r = checkShippedSql(sql);
  if (r.error) problems.push(`${id}: refused (${r.error})`);
}
const run = new Set(QUERY_IDS);
for (const f of readdirSync(QUERIES_DIR).filter((n) => n.endsWith(".sql")).sort()) {
  const id = f.slice(0, -4);
  if (!run.has(id) && !NOT_RUN.has(id)) problems.push(`${id}: rules/queries/${f} is shipped but neither run nor listed in NOT_RUN`);
}

if (problems.length) {
  console.error(`check-shipped-sql: ${problems.length} problem(s)`);
  for (const p of problems) console.error(`  ${p}`);
  process.exit(1);
}
console.log(`check-shipped-sql: ${QUERY_IDS.length} shipped queries pass checkShippedSql`);

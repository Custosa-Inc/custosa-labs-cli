/* A fact document's snapshot ids (screening design §13 items 1 and 19; docs/screen-engine.md §3.1), read as
 * core's app.core.snapshot.ids reads them: a table, schema.table, schema.table.column, table.column, a path, a path
 * with each line or line range the document cites, and a setting name. Each is the name as the document sends it, so a
 * hashed name stays hashed. A backticked name in a note becomes a ref only when it is one of these.
 *
 * Which fields hold a name comes from the fact document schema (this package's copy, the one core hashes into the
 * ruleset), not from a list kept here: every property whose schema points at a name, path or location $def, and every
 * property whose value is a setting. A setting's value is never an id.
 *
 * snapshotIds(document) -> Set<string> */
import { readFileSync } from "node:fs";

const SCHEMA = new URL("./contracts/fact_document.schema.json", import.meta.url);
const NAME_DEFS = new Set(["identifier", "hashed_identifier", "pg_name", "qualified_name", "path", "location"]);
const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const text = (v) => typeof v === "string" && v !== "";

/* The $defs names a property's schema points at, through anyOf, oneOf, allOf and array items. */
function defsOf(node, out = new Set()) {
  if (!isObject(node)) return out;
  if (typeof node.$ref === "string") out.add(node.$ref.slice(node.$ref.lastIndexOf("/") + 1));
  for (const key of ["anyOf", "oneOf", "allOf"]) for (const sub of node[key] ?? []) defsOf(sub, out);
  defsOf(node.items, out);
  return out;
}

let keys = null;
/* {names, settings}: the keys that hold a name and the keys that hold a setting, read once from the schema. */
function schemaKeys() {
  if (keys) return keys;
  const schema = JSON.parse(readFileSync(SCHEMA, "utf8"));
  const names = new Set();
  const settings = new Set(Object.keys(schema.properties.platform.properties.settings.properties));
  const walk = (node) => {
    if (!isObject(node)) return;
    for (const [key, sub] of Object.entries(node.properties ?? {})) {
      const defs = defsOf(sub);
      if ([...defs].some((d) => NAME_DEFS.has(d))) names.add(key);
      if (defs.has("setting")) settings.add(key);
      walk(sub);
    }
    for (const key of ["items", "additionalProperties"]) walk(node[key]);
    for (const key of ["anyOf", "oneOf", "allOf"]) for (const sub of node[key] ?? []) walk(sub);
    for (const sub of Object.values(node.$defs ?? {})) walk(sub);
  };
  walk(schema);
  keys = { names, settings };
  return keys;
}

export function snapshotIds(document) {
  const { names, settings } = schemaKeys();
  const out = new Set();
  const visit = (node) => {
    if (Array.isArray(node)) { for (const v of node) visit(v); return; }
    if (!isObject(node)) return;
    for (const [key, v] of Object.entries(node)) {
      if (settings.has(key) && typeof v === "string") out.add(key); // the setting's name; its value is never an id
      if (names.has(key)) {
        if (text(v)) out.add(v);
        else if (Array.isArray(v)) for (const x of v) if (text(x)) out.add(x);
      }
    }
    const { schema_name: schema, table_name: table } = node;
    if (text(table)) {
      const qualified = text(schema) ? `${schema}.${table}` : table;
      out.add(table).add(qualified);
      if (text(node.column_name)) out.add(`${qualified}.${node.column_name}`).add(`${table}.${node.column_name}`);
    }
    const { table: qual, column } = node;
    const last = (q) => q.slice(q.lastIndexOf(".") + 1);
    if (typeof qual === "string" && qual.includes(".")) out.add(last(qual)); // columns[] and matches[] name a table as schema.table
    if (text(qual) && text(column)) out.add(`${qual}.${column}`).add(`${last(qual)}.${column}`);
    if (text(node.path)) {
      const start = node.line_start;
      const end = Object.hasOwn(node, "line_end") ? node.line_end : start;
      if (Number.isInteger(node.line)) out.add(`${node.path}:${node.line}`);
      else if (Number.isInteger(start) && Number.isInteger(end)) out.add(start === end ? `${node.path}:${start}` : `${node.path}:${start}-${end}`);
    }
    for (const v of Object.values(node)) visit(v);
  };
  visit(document);
  return out;
}

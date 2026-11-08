/* The contract's two JSON Schemas, shipped in the package (./contracts/, copied from the evaluator; see
 * contracts.mjs for the commit), compiled once with ajv's draft 2020-12 build.
 *
 * validateFactDocument(doc) -> null | {at, keyword}   the first refusal, as a JSON pointer (keys and indexes only)
 * validateResponse(body)    -> null | {at, keyword}
 * subValidator(pointer)     -> ajv validate function for a part of the fact schema ("#/$defs/row_roles", ...)
 * FACT_SCHEMA, RESPONSE_SCHEMA: the parsed schemas. */
import { readFileSync } from "node:fs";
import Ajv2020Module from "ajv/dist/2020.js";

const Ajv2020 = Ajv2020Module.default ?? Ajv2020Module;
const load = (name) => JSON.parse(readFileSync(new URL(`./contracts/${name}`, import.meta.url), "utf8"));

export const FACT_SCHEMA = load("fact_document.schema.json");
export const RESPONSE_SCHEMA = load("response.schema.json");

const ajv = new Ajv2020({ strict: false, allErrors: false });
ajv.addSchema(FACT_SCHEMA);
ajv.addSchema(RESPONSE_SCHEMA);
const factValidator = ajv.getSchema(FACT_SCHEMA.$id);
const responseValidator = ajv.getSchema(RESPONSE_SCHEMA.$id);

const first = (validate) => {
  const [e] = validate.errors ?? [];
  return { at: e ? e.instancePath : "", keyword: e ? e.keyword : "unknown" };
};

export function validateFactDocument(doc) {
  return factValidator(doc) ? null : first(factValidator);
}

export function validateResponse(body) {
  return responseValidator(body) ? null : first(responseValidator);
}

const cache = new Map();
export function subValidator(pointer) {
  if (!cache.has(pointer)) {
    const v = ajv.getSchema(`${FACT_SCHEMA.$id}${pointer}`);
    if (!v) throw new Error(`no such part of the fact schema: ${pointer}`);
    cache.set(pointer, v);
  }
  return cache.get(pointer);
}

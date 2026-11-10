/* Patterns and enums copied from the fact document contract, so the tool refuses what the evaluator would refuse.
 * The source is the evaluator's contracts folder, and SOURCE_COMMIT is the evaluator commit the fact schema was last
 * copied from. The package ships both schemas in ./contracts/ (validated with ajv in ./schema.mjs); the test fixtures
 * hold copies (test/fixtures/contracts/*.json, named by the commit each came from) and inspector-factdoc.test.mjs
 * compares them. When the contract changes, refresh ./contracts/, the fixtures and this file together. */

export const SOURCE_COMMIT = "9cc759f7c90cc1d607cb65a472b35923cbcc0bcd";

export const IDENTIFIER = "^[A-Za-z_][A-Za-z0-9_$.\\-]{0,127}$";
export const HASHED_IDENTIFIER = "^u_[0-9a-f]{16}$";
export const PATH = "^(?!/)(?!.*//)(?!.*/$)(?!(?:.*/)?\\.\\.?(?:/|$))[A-Za-z0-9_.@+$\\[\\]()~/-]{1,512}$";
export const PATH_MAX = 512;
export const LOCATION = "^(?!/)(?![^:]*//)(?![^:]*/:)(?!(?:[^:]*/)?\\.\\.?(?:/|:))[A-Za-z0-9_.@+$\\[\\]()~/-]{1,512}:[1-9][0-9]{0,6}(?:-[1-9][0-9]{0,6})?$";
export const LOCATION_MAX = 528;
export const LOCATION_RANGE_MAX = 30; // m - n < 30 and n <= m (the contract says strict intake checks it)
// A location answer's code and its other spans (fact schema answers.items code and at).
export const ANSWER_CODE = "^[a-z][a-z0-9_]{0,63}$";
export const SPANS_MAX = 50;
// The id of one of an item's options (enums.OPTION_PATTERN), sent on a person's decision.
export const OPTION = "^[a-z][a-z0-9_]{0,63}$";
export const SEARCHED_MAX = 20; // a verdict's searched entries (enums.MAX_SEARCHED)
export const SEARCHED_ROOTS_MAX = 20; // repository paths per searched entry (enums.MAX_SEARCHED_ROOTS)
export const OBJECT_ID = "^[a-z0-9][a-z0-9-]{0,63}(?:@[A-Za-z0-9_.@:+$\\[\\]()~/-]{1,512})?$"; // v1.1: the object may hold @ and :
export const OBJECT_ID_MAX = 577;
export const SESSION = "^ps_[A-Za-z0-9_-]{22}$";

export const QUESTION_IDS = Object.freeze(["purpose","staff_access","location","person_confirmation"]);
export const ANSWERS = Object.freeze(["phi","workforce","organization","lookup","technical","secret","not_sure","no_staff_access","admin_app","support_tool","direct_database","reporting","here","not_present","not_found","confirmed","not_confirmed","declined"]);
/* The answers each question takes. */
export const ANSWERS_BY_QUESTION = Object.freeze({
  purpose: Object.freeze(["phi","workforce","organization","lookup","technical","secret","not_sure"]),
  staff_access: Object.freeze(["no_staff_access","admin_app","support_tool","direct_database","reporting","not_sure"]),
  location: Object.freeze(["here","not_present","not_found"]),
  person_confirmation: Object.freeze(["confirmed","not_confirmed","declined"]),
});
/* The one answer that carries a location. */
export const LOCATED_ANSWER = "here";

/* Catalog names (contract v1.1): a name or a part of a schema.name outside PG_NAME is sent hashed (HASHED_IDENTIFIER). */
export const PG_NAME = "^[A-Za-z_][A-Za-z0-9_$\\-]{0,62}$";
export const QUALIFIED_NAME = "^[A-Za-z_][A-Za-z0-9_$\\-]{0,62}\\.[A-Za-z_][A-Za-z0-9_$\\-]{0,62}$";

/* connected_roles application buckets (rule_bundle.md 5.1, enums.CONNECTED_APPLICATION_PREFIXES, contract v2.1), in
 * table order: the application_name, trimmed and case folded, takes the first bucket with a matching prefix; empty is
 * none, else other. supabase/auth (GoTrue) names its side connections auth_migrations and auth_indexworker; its main
 * connection sends no name (none) unless a deployment names it gotrue. */
export const CONNECTED_APPLICATION_PREFIXES = Object.freeze([
  ["psql", ["psql"]],
  ["pgadmin", ["pgadmin"]],
  ["dbeaver", ["dbeaver"]],
  ["datagrip", ["datagrip"]],
  ["postgrest", ["postgrest"]],
  ["supabase_auth", ["auth_migrations", "auth_indexworker", "gotrue"]],
  ["supabase_storage", ["storage-api", "supabase storage", "supabase_storage"]],
  ["supabase_realtime", ["realtime", "supabase realtime", "supabase_realtime"]],
  ["supabase_studio", ["supabase studio", "postgres-meta", "supabase/dashboard"]],
  ["pgbouncer", ["pgbouncer"]],
  ["supavisor", ["supavisor"]],
  ["prisma", ["prisma"]],
  ["node_postgres", ["node-postgres", "pg-node"]],
  ["psycopg", ["psycopg"]],
  ["sqlalchemy", ["sqlalchemy"]],
  ["django", ["django"]],
  ["rails", ["rails", "activerecord"]],
  ["jdbc", ["postgresql jdbc driver", "jdbc"]],
  ["npgsql", ["npgsql"]],
  ["pgx", ["pgx"]],
].map(([bucket, prefixes]) => Object.freeze([bucket, Object.freeze(prefixes)])));

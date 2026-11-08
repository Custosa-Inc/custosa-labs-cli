/* The rule set copy in this package (rule_bundle.md section 1): rules/ holds exactly the files the hosted rule
 * set's manifest lists, and the manifest, copied by scripts/sync-rules.mjs.
 *
 * Who it serves: the inspector runs these rules, queries and secret rules and names the manifest's ruleset_id in every
 * fact document; the evaluator refuses any other id (update_inspector). So the copy must match its manifest byte for
 * byte, ship in the package, and be what the inspector actually runs. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { cpSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import YAML from "yaml";
import { CONTRACTS_DIR, RULES_DIR, rulesetHash, sha256, verify } from "../scripts/sync-rules.mjs";
import { PREFLIGHT_SQL, checkShippedSql } from "../lib/inspector/catalog.mjs";
import { V2_QUERIES, shippedQuerySql } from "../lib/inspector/catalogfacts.mjs";
import { DEFAULT_SECRET_PATTERNS } from "../lib/inspector/secret-patterns.mjs";
import { DEFAULT_RULES_DIR, compareVersions, loadRules } from "../lib/inspector/rules.mjs";
import { ENGINE_VERSION } from "../lib/inspector/parse.mjs";

const CLI = fileURLToPath(new URL("..", import.meta.url));
const MANIFEST = JSON.parse(readFileSync(join(RULES_DIR, "manifest.json"), "utf8"));
const QUERY_IDS = ["rls_status", "rls_policies", "table_grants", "table_columns", "views", "definer_functions",
  "exposed_schemas", "roles", "storage_buckets", "transport", "logging", "audit", "self_hosted", "advisor",
  "default_acl", "schema_privileges", "triggers", "constraints", "realtime_publication",
  "connected_roles"]; // enums.QUERY_IDS (hba_rules was dropped)

function walk(dir) {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    return statSync(p).isDirectory() ? walk(p) : [relative(RULES_DIR, p).split(sep).join("/")];
  });
}

function copyOfRules() {
  const dir = mkdtempSync(join(tmpdir(), "custosa-rules-"));
  cpSync(RULES_DIR, dir, { recursive: true });
  return dir;
}

test("the copy in rules is exactly the files its manifest lists, each matching its sha256", () => {
  assert.deepEqual(verify(RULES_DIR, MANIFEST), []);
  const listed = MANIFEST.files.map((f) => f.path).sort();
  assert.deepEqual(walk(RULES_DIR).filter((p) => p !== "manifest.json").sort(), listed, "a file in rules that the manifest doesn't list");
  assert.equal(MANIFEST.ruleset_id.split(".")[1], rulesetHash([...MANIFEST.files.map((f) => ({ path: f.path, bytes: readFileSync(join(RULES_DIR, f.path)) })),
    ...MANIFEST.contracts.map((c) => ({ path: c.path, bytes: readFileSync(join(CONTRACTS_DIR, c.path)) }))]));
  for (const q of [...QUERY_IDS, "preflight"]) assert.ok(listed.includes(`queries/${q}.sql`), q);
  assert.ok(listed.includes("queries/secrets.yml"));
  assert.ok(!listed.includes("queries/hba_rules.sql"));
  // Only runtime files ship: no fixtures, no README (they stay in the hosted repo, which runs the fixtures). The one
  // data file is the value screen's word list (S3-2, core build_ruleset DATA_FILES).
  for (const p of listed) assert.ok(/^(rules\/[^/]+\/[a-z0-9_]+-[a-z0-9_]+\.yml|queries\/[a-z_]+\.(sql|yml)|value_screen_words\.json)$/.test(p) && !p.includes(".fixtures."), p);
  assert.ok(listed.includes("value_screen_words.json"));
});

test("a copy that differs from its manifest is caught: a changed byte, a missing file, a wrong id", () => {
  const dir = copyOfRules();
  try {
    const one = join(dir, "queries", "rls_status.sql");
    writeFileSync(one, readFileSync(one, "utf8") + "\n");
    assert.match(verify(dir, MANIFEST).join(), /queries\/rls_status\.sql: sha256 differs/);
    unlinkSync(one);
    assert.match(verify(dir, MANIFEST).join(), /queries\/rls_status\.sql: missing/);
    cpSync(join(RULES_DIR, "queries", "rls_status.sql"), one);
    const day = MANIFEST.ruleset_id.split(".")[0];
    assert.match(verify(dir, { ...MANIFEST, ruleset_id: `${day}.00000000` }).join(), /ruleset_id doesn't match/);
    assert.match(verify(dir, { ...MANIFEST, files: [...MANIFEST.files].reverse() }).join(), /not sorted/);
    assert.match(verify(dir, { ...MANIFEST, files: [{ path: "../x", sha256: sha256("") }] }).join(), /bad listed path/);
    assert.deepEqual(verify(dir, MANIFEST), []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

/* The client checks every answer against lib/inspector/contracts/response.schema.json, whose objects and reason enum are
 * closed (client.mjs checkEvaluateAnswer). The evaluator hashes its response schema into the ruleset_id, so a new
 * reason (exposure_suspected, say) moves the id and an older package hears update_inspector instead of refusing every
 * answer. This package's copy must be the schema its manifest names. */
test("the manifest names the contract files, and this package's copies are those files", () => {
  // Contract 2.3: the fact and state schemas are hashed into the id beside the response schema. So are
  // the screen's rule file, its three name lists and their license notices.
  const names = ["NOTICE.txt", "ambiguous_names.txt", "fact_document.schema.json", "personal_names.txt",
    "response.schema.json", "safe_words.txt", "screen_rules.json", "state.schema.json"];
  const copies = names.map((n) => ({ path: `contracts/${n}`, bytes: readFileSync(join(CONTRACTS_DIR, "contracts", n)) }));
  assert.deepEqual(MANIFEST.contracts, copies.map((c) => ({ path: c.path, sha256: sha256(c.bytes) })));
  assert.ok(copies[names.indexOf("response.schema.json")].bytes.toString("utf8").includes('"exposure_suspected"'));
  const entries = MANIFEST.files.map((f) => ({ path: f.path, bytes: readFileSync(join(RULES_DIR, f.path)) }));
  assert.equal(MANIFEST.ruleset_id.split(".")[1], rulesetHash([...entries, ...copies]));
  assert.notEqual(MANIFEST.ruleset_id.split(".")[1], rulesetHash(entries), "the schemas are part of the id");
});

test("a response schema copy that differs from the manifest is caught, and so is a bad contract path", () => {
  const dir = mkdtempSync(join(tmpdir(), "custosa-contracts-"));
  try {
    cpSync(join(CONTRACTS_DIR, "contracts"), join(dir, "contracts"), { recursive: true });
    assert.deepEqual(verify(RULES_DIR, MANIFEST, dir), []);
    const copy = join(dir, "contracts", "response.schema.json");
    writeFileSync(copy, readFileSync(copy, "utf8").replace('"exposure_suspected"', '"exposure_suspected", "zz_new_reason"'));
    assert.match(verify(RULES_DIR, MANIFEST, dir).join(), /contracts\/response\.schema\.json: sha256 differs/);
    unlinkSync(copy);
    assert.match(verify(RULES_DIR, MANIFEST, dir).join(), /contracts\/response\.schema\.json: missing/);
    assert.match(verify(RULES_DIR, { ...MANIFEST, contracts: [{ path: "../x.schema.json", sha256: sha256("") }] }).join(), /bad contract path/);
    // only the screen's own files ride beside the schemas
    assert.match(verify(RULES_DIR, { ...MANIFEST, contracts: [{ path: "contracts/other.json", sha256: sha256("") }] }).join(), /bad contract path/);
    // A manifest that names no contract (a hand-made bundle) has the old shape and the old recipe.
    const { contracts, ...bare } = MANIFEST;
    assert.ok(contracts.length);
    assert.match(verify(RULES_DIR, bare).join(), /ruleset_id doesn't match/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the package ships the rule set: package.json files includes rules and npm pack carries every listed file", () => {
  const pkg = JSON.parse(readFileSync(join(CLI, "package.json"), "utf8"));
  assert.ok(pkg.files.includes("rules"));
  const [packed] = JSON.parse(execFileSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], { cwd: CLI, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }));
  const inPack = new Set(packed.files.map((f) => f.path));
  for (const p of ["rules/manifest.json", ...MANIFEST.files.map((f) => `rules/${f.path}`)]) assert.ok(inPack.has(p), p);
  for (const c of MANIFEST.contracts) assert.ok(inPack.has(`lib/inspector/${c.path}`), c.path);
});

test("the inspector runs the copy: the v1.1 queries load from it and the preflight is the same text", () => {
  for (const q of V2_QUERIES) assert.equal(q.sql, readFileSync(join(RULES_DIR, "queries", `${q.query_id}.sql`), "utf8"), q.query_id);
  // The preflight is built in catalog.mjs from the settings it pins at run time; the shipped file must be that text.
  assert.equal(readFileSync(join(RULES_DIR, "queries", "preflight.sql"), "utf8"), PREFLIGHT_SQL);
  assert.equal(new URL(DEFAULT_RULES_DIR).pathname.replace(/\/$/, ""), RULES_DIR.split(sep).join("/"));
});

test("every shipped catalog query passes the inspector's static check", () => {
  for (const q of QUERY_IDS) {
    const r = checkShippedSql(shippedQuerySql(q));
    assert.equal(r.error, undefined, `${q}: ${r.error}`);
  }
});

test("secrets.yml carries the inspector's plain provider patterns, source for source", () => {
  const doc = YAML.parse(readFileSync(join(RULES_DIR, "queries", "secrets.yml"), "utf8"));
  assert.equal(doc.version, 1);
  // inspectorOnly patterns (gitlab-token) aren't in the hosted secrets.yml yet.
  const plain = DEFAULT_SECRET_PATTERNS.filter((p) => p.regex.flags === "g" && !p.inspectorOnly
    && Object.keys(p).every((k) => ["rule_id", "regex", "placeholders"].includes(k)));
  assert.deepEqual(doc.rules.map((r) => r.id).sort(), plain.map((p) => `secrets.${p.rule_id}`).sort(),
    "every plain inspector pattern is in secrets.yml and nothing else");
  for (const rule of doc.rules) {
    const own = plain.find((p) => `secrets.${p.rule_id}` === rule.id);
    assert.equal(new RegExp(rule.regex, "g").source, own.regex.source, rule.id);
    // secret_group is the number of the pattern's named group `secret`.
    const before = rule.regex.slice(0, rule.regex.indexOf("(?<secret>"));
    const opened = (before.replace(/\\./g, "").replace(/\[[^\]]*\]/g, "").match(/\((?!\?)|\(\?<(?![=!])/g) || []).length;
    assert.equal(rule.secret_group, opened + 1, rule.id);
    for (const word of rule.keywords) assert.ok(typeof word === "string" && word.length > 0);
  }
});

test("the packaged rules load strictly on this engine, one per rule document", () => {
  assert.ok(compareVersions(MANIFEST.min_engine, ENGINE_VERSION) <= 0, `min_engine ${MANIFEST.min_engine} > ${ENGINE_VERSION}`);
  const rules = loadRules(DEFAULT_RULES_DIR, { strict: true });
  const docs = MANIFEST.files.filter((f) => /^rules\/.*\.yml$/.test(f.path) && !f.path.includes(".fixtures."))
    .flatMap((f) => YAML.parseAllDocuments(readFileSync(join(RULES_DIR, f.path), "utf8")).filter((d) => d.contents !== null));
  assert.equal(rules.length, docs.length);
  assert.ok(rules.length > 0);
});

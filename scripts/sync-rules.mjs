#!/usr/bin/env node
/* Copy the rule set into this package (rule_bundle.md section 1).
 *
 *   node scripts/sync-rules.mjs <the evaluator's app/knowledge folder>
 *
 * The source is the evaluator's app/knowledge folder (in Custosa's private evaluator repository), whose
 * manifest.json (written by its scripts/build_ruleset.py) lists every rule, fixture, query and secrets file with its
 * sha256 and the ruleset_id. This copies exactly the listed files, and the manifest, into rules/, replacing what was
 * there, after checking every source file against its hash and the ruleset_id against the listed files. Nothing is
 * fetched at run time and nothing is signed: the package is the unit of trust. test/rules-sync.test.mjs fails when the
 * copy and its manifest differ, so the package can't drift from the rule set it names.
 *
 * The manifest's contracts (the response schema, contracts/response.schema.json, under the evaluator's app/ folder) are
 * part of the ruleset_id too. This copies each one to lib/inspector/contracts/, the copy the client checks every answer
 * against (client.mjs checkEvaluateAnswer). So a schema change on the evaluator moves the id, an older package gets
 * update_inspector instead of answers its closed schema would refuse, and this package's copy can't differ from the
 * schema its rule set names.
 *
 * Release step: run this against the evaluator checkout that is deployed, run npm test, commit rules/, then
 * npm run check-ruleset -- <the same folder> (the release gate, scripts/check-ruleset.mjs).
 *
 * It also writes ruleset-source.json: the core ruleset_id it copied, the full SHA-256 of the
 * listed files and contracts (the ruleset_id's 8-hex part, unshortened), and the SHA-256 of core's manifest.json.
 * check-ruleset fails in CI when rules/ no longer hashes to it, and a release compares the id and the manifest hash
 * with the evaluator's. The file is not in the npm package. */
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

export const RULES_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..", "rules");
export const SOURCE_PIN = resolve(dirname(fileURLToPath(import.meta.url)), "..", "ruleset-source.json");
export const CONTRACTS_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..", "lib", "inspector"); // holds contracts/
const RULESET_ID = /^[0-9]{4}-[0-9]{2}-[0-9]{2}\.[0-9a-f]{8}$/;
// value_screen_words.json: the value screen's common words, listed by core's build_ruleset
// DATA_FILES under app/knowledge, so rules/value_screen_words.json; valueshape.mjs reads it there.
const LISTED_PATH = /^(?:rules\/[a-z0-9][a-z0-9-]{0,63}\/[A-Za-z0-9._-]{1,128}|queries\/[a-z_]{1,40}\.(?:sql|yml)|value_screen_words\.json)$/;
// The schemas, the cited facts' fact_schema.json (T29 line item h, contract 2.6), and the free-text screen's rule file,
// its three name lists and their license notices, which core's build_ruleset lists as contracts so the ruleset id
// covers them.
const CONTRACT_PATH = /^contracts\/(?:[a-z_]{1,40}\.schema\.json|fact_schema\.json|screen_rules\.json|(?:personal|ambiguous)_names\.txt|safe_words\.txt|NOTICE\.txt)$/;
// shared test tables that ride with the contracts but aren't part of the ruleset_id (core's build_ruleset
// leaves them out of CONTRACT_FILES). Copied when the source has them; test/free-text-probes.test.mjs runs the copy.
export const PROBE_TABLES = ["contracts/free_text_probes.json"];

export const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

/* SHA-256 over each listed file's path, NUL, contents, NUL, in path order (rule_bundle.md 2), as 64 hex. */
export function contentSha256(entries) {
  const h = createHash("sha256");
  for (const { path, bytes } of [...entries].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0))) {
    h.update(Buffer.from(path, "utf8")).update(Buffer.from([0])).update(bytes).update(Buffer.from([0]));
  }
  return h.digest("hex");
}
/* The first 8 hex of contentSha256: the ruleset_id's hash part. */
export const rulesetHash = (entries) => contentSha256(entries).slice(0, 8);

/* What ruleset-source.json records for the rule set under root: the manifest's ruleset_id, contentSha256 of its
 * listed files and contracts as they are on disk, and the SHA-256 of manifest.json itself. A listed file that is
 * missing is left out, so the content hash then differs. */
export function sourcePin(root, contractsRoot = CONTRACTS_DIR) {
  const bytes = readFileSync(join(root, "manifest.json"));
  const manifest = JSON.parse(bytes.toString("utf8"));
  const entries = [];
  for (const f of manifest.files ?? []) {
    const file = join(root, ...String(f.path).split("/"));
    if (existsSync(file)) entries.push({ path: f.path, bytes: readFileSync(file) });
  }
  for (const c of manifest.contracts ?? []) {
    const file = join(contractsRoot, ...String(c.path).split("/"));
    if (existsSync(file)) entries.push({ path: c.path, bytes: readFileSync(file) });
  }
  return { ruleset_id: manifest.ruleset_id, content_sha256: contentSha256(entries), manifest_sha256: sha256(bytes) };
}

/* The manifest's problems against the files under root and its contracts under contractsRoot (default this package's
 * lib/inspector; the evaluator's app/ folder for a hosted source). A list; empty when the copy matches it exactly. */
export function verify(root, manifest, contractsRoot = CONTRACTS_DIR) {
  const problems = [];
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) return ["manifest.json is not an object"];
  const keys = Object.keys(manifest).join(",");
  if (keys !== "ruleset_id,min_engine,files" && keys !== "ruleset_id,min_engine,files,contracts") problems.push(`manifest.json keys are ${keys}`);
  if (typeof manifest.ruleset_id !== "string" || !RULESET_ID.test(manifest.ruleset_id)) problems.push("bad ruleset_id");
  if (typeof manifest.min_engine !== "string" || !/^[0-9]+\.[0-9]+\.[0-9]+$/.test(manifest.min_engine)) problems.push("bad min_engine");
  if (!Array.isArray(manifest.files) || manifest.files.length === 0) return [...problems, "no files listed"];
  const entries = [];
  let previous = "";
  for (const f of manifest.files) {
    if (!f || typeof f.path !== "string" || !LISTED_PATH.test(f.path) || f.path.includes("..")) {
      problems.push(`bad listed path ${JSON.stringify(f && f.path)}`);
      continue;
    }
    if (f.path <= previous) problems.push(`${f.path}: files not sorted or repeated`);
    previous = f.path;
    const file = join(root, ...f.path.split("/"));
    if (!existsSync(file) || !statSync(file).isFile()) { problems.push(`${f.path}: missing`); continue; }
    const bytes = readFileSync(file);
    if (sha256(bytes) !== f.sha256) problems.push(`${f.path}: sha256 differs from the manifest`);
    entries.push({ path: f.path, bytes });
  }
  for (const c of manifest.contracts ?? []) {
    if (!c || typeof c.path !== "string" || !CONTRACT_PATH.test(c.path)) {
      problems.push(`bad contract path ${JSON.stringify(c && c.path)}`);
      continue;
    }
    const file = join(contractsRoot, ...c.path.split("/"));
    if (!existsSync(file) || !statSync(file).isFile()) { problems.push(`${c.path}: missing`); continue; }
    const bytes = readFileSync(file);
    if (sha256(bytes) !== c.sha256) problems.push(`${c.path}: sha256 differs from the manifest`);
    entries.push({ path: c.path, bytes });
  }
  if (problems.length === 0 && manifest.ruleset_id.split(".")[1] !== rulesetHash(entries)) {
    problems.push("ruleset_id doesn't match the listed files");
  }
  return problems;
}

function main(argv) {
  if (argv.length !== 1) {
    process.stderr.write("usage: node scripts/sync-rules.mjs <path to the evaluator's app/knowledge>\n");
    return 2;
  }
  const source = resolve(argv[0]);
  const manifest = JSON.parse(readFileSync(join(source, "manifest.json"), "utf8"));
  const problems = verify(source, manifest, join(source, ".."));
  if (problems.length) {
    process.stderr.write(`the source rule set doesn't match its manifest (rebuild it there first):\n  ${problems.join("\n  ")}\n`);
    return 1;
  }
  // The package's own rules/ only (since the repo split the package root is the repository root, not cli/).
  let own = false;
  try { own = JSON.parse(readFileSync(join(RULES_DIR, "..", "package.json"), "utf8")).name === "custosa"; } catch { own = false; }
  if (!RULES_DIR.endsWith(`${sep}rules`) || !own) throw new Error(`refusing to replace ${RULES_DIR}`);
  rmSync(RULES_DIR, { recursive: true, force: true });
  for (const f of manifest.files) {
    const to = join(RULES_DIR, ...f.path.split("/"));
    mkdirSync(dirname(to), { recursive: true });
    writeFileSync(to, readFileSync(join(source, ...f.path.split("/"))));
  }
  for (const c of manifest.contracts ?? []) {
    writeFileSync(join(CONTRACTS_DIR, ...c.path.split("/")), readFileSync(join(source, "..", ...c.path.split("/"))));
  }
  for (const t of PROBE_TABLES) {
    const from = join(source, "..", ...t.split("/"));
    if (existsSync(from)) writeFileSync(join(CONTRACTS_DIR, ...t.split("/")), readFileSync(from));
  }
  writeFileSync(join(RULES_DIR, "manifest.json"), readFileSync(join(source, "manifest.json")));
  const copied = verify(RULES_DIR, JSON.parse(readFileSync(join(RULES_DIR, "manifest.json"), "utf8")));
  if (copied.length) throw new Error(`the copy doesn't match: ${copied.join("; ")}`);
  const pin = sourcePin(source, join(source, ".."));
  writeFileSync(SOURCE_PIN, `${JSON.stringify({ ...pin, source: "the evaluator's app/knowledge" }, null, 2)}\n`);
  process.stdout.write(`rules: ${manifest.files.length} files, ${(manifest.contracts ?? []).length} contracts, ruleset ${manifest.ruleset_id}\n`);
  return 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) process.exitCode = main(process.argv.slice(2));

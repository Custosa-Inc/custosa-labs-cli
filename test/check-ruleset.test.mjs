/* The release gate for the rule set: scripts/check-ruleset.mjs fails when rules names another
 * ruleset_id, or other file hashes, than the hosted evaluator's manifest, and prepublishOnly refuses to publish a copy
 * that doesn't verify against its own manifest. Who it serves: the evaluator refuses any other ruleset_id
 * (update_inspector), so a package that drifted from the hosted rule set can check nothing. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { RULES_DIR } from "../scripts/sync-rules.mjs";
import { checkRuleset, compareManifests } from "../scripts/check-ruleset.mjs";
import { coreSkip, requireCore } from "./core-checkout.mjs";

const CLI = fileURLToPath(new URL("..", import.meta.url));
const SCRIPT = join(CLI, "scripts", "check-ruleset.mjs");
const MANIFEST = JSON.parse(readFileSync(join(RULES_DIR, "manifest.json"), "utf8"));
const HOSTED_RULES = process.env.CUSTOSA_HOSTED_RULES;
const HOSTED = HOSTED_RULES ? dirname(resolve(HOSTED_RULES)) : null; // knowledge/, holding manifest.json and rules/

const run = (args, env = {}) => spawnSync(process.execPath, [SCRIPT, ...args], {
  encoding: "utf8", env: { ...process.env, CUSTOSA_HOSTED_RULES: "", ...env },
});

test("rules matches the hosted rule set the evaluator runs (release gate)", { skip: coreSkip(HOSTED, "set CUSTOSA_HOSTED_RULES to the hosted knowledge/rules folder") }, () => {
  requireCore("CUSTOSA_HOSTED_RULES", HOSTED && existsSync(HOSTED_RULES));
  assert.ok(existsSync(join(HOSTED, "manifest.json")), `no manifest.json next to ${HOSTED_RULES}`);
  assert.deepEqual(checkRuleset({ hostedDir: HOSTED }), []);
  const r = run([HOSTED]);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /the same as the hosted rule set/);
  // --self with CUSTOSA_HOSTED_RULES set compares against the hosted manifest too.
  assert.equal(run(["--self"], { CUSTOSA_HOSTED_RULES: HOSTED_RULES }).status, 0);
});

test("a hosted manifest with another ruleset_id or another file hash fails the gate", () => {
  assert.deepEqual(compareManifests(MANIFEST, structuredClone(MANIFEST)), []);
  const other = structuredClone(MANIFEST);
  other.ruleset_id = `${MANIFEST.ruleset_id.split(".")[0]}.00000000`;
  other.files[0].sha256 = "0".repeat(64);
  other.files.push({ path: "rules/zz-new/sql-generic.yml", sha256: "1".repeat(64) });
  const problems = compareManifests(MANIFEST, other).join("\n");
  assert.match(problems, /ruleset_id: rules has .*, hosted has .*\.00000000/);
  assert.match(problems, new RegExp(`${MANIFEST.files[0].path}: sha256 differs`));
  assert.match(problems, /rules\/zz-new\/sql-generic\.yml: in the hosted rule set, missing from rules/);
  const schema = structuredClone(MANIFEST);
  schema.contracts[0].sha256 = "2".repeat(64);
  assert.match(compareManifests(MANIFEST, schema).join(), /contracts: rules has .*, hosted has .*2{64}/);
  const fewer = { ...MANIFEST, files: MANIFEST.files.slice(1) };
  assert.match(compareManifests(MANIFEST, fewer).join(), /in rules, not in the hosted rule set/);

  const dir = mkdtempSync(join(tmpdir(), "custosa-hosted-"));
  try {
    writeFileSync(join(dir, "manifest.json"), JSON.stringify(other));
    const r = run([dir]);
    assert.equal(r.status, 1);
    assert.match(r.stderr, /doesn't match the hosted rule set/);
    assert.match(r.stderr, /ruleset_id/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
  assert.equal(run([]).status, 2);
});

test("prepublishOnly refuses to publish a rules that doesn't verify against its own manifest", () => {
  const pkg = JSON.parse(readFileSync(join(CLI, "package.json"), "utf8"));
  assert.equal(pkg.scripts.prepublishOnly, "node scripts/check-ruleset.mjs --self");
  assert.equal(pkg.scripts["check-ruleset"], "node scripts/check-ruleset.mjs");
  const ok = run(["--self"]);
  assert.equal(ok.status, 0, ok.stderr);
  const dir = mkdtempSync(join(tmpdir(), "custosa-rules-"));
  try {
    cpSync(RULES_DIR, dir, { recursive: true });
    const one = join(dir, "queries", "rls_status.sql");
    writeFileSync(one, readFileSync(one, "utf8") + "\n");
    assert.match(checkRuleset({ rulesDir: dir }).join(), /queries\/rls_status\.sql: sha256 differs/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
  // The script npm runs before a publish passes on the shipped copy.
  const out = execFileSync("npm", ["run", "prepublishOnly", "--silent"], { cwd: CLI, encoding: "utf8", env: { ...process.env, CUSTOSA_HOSTED_RULES: "" } });
  assert.match(out, /rules verified: ruleset /);
});

/* ruleset-source.json pins the core rule set sync-rules copied (its ruleset_id, its
 * manifest.json SHA-256 and the full content SHA-256), so CLI CI fails when rules drifts from it, even by an edit
 * that rewrites the manifest to match. */
test("rules still hashes to the core rule set it was synced from", () => {
  const pin = JSON.parse(readFileSync(join(CLI, "ruleset-source.json"), "utf8"));
  assert.equal(pin.ruleset_id, MANIFEST.ruleset_id);
  assert.equal(pin.content_sha256.slice(0, 8), MANIFEST.ruleset_id.split(".")[1]);
  assert.deepEqual(checkRuleset(), []);
});

test("an edit that rewrites the manifest to match still fails against the pinned core rule set", async () => {
  const { sha256, sourcePin, rulesetHash } = await import("../scripts/sync-rules.mjs");
  const dir = mkdtempSync(join(tmpdir(), "custosa-pin-"));
  try {
    cpSync(RULES_DIR, dir, { recursive: true });
    const manifest = structuredClone(MANIFEST);
    const entry = manifest.files.find((f) => f.path.startsWith("rules/"));
    const file = join(dir, ...entry.path.split("/"));
    const edited = Buffer.concat([readFileSync(file), Buffer.from("# a local edit\n")]);
    writeFileSync(file, edited);
    entry.sha256 = sha256(edited);
    const entries = [...manifest.files.map((f) => ({ path: f.path, bytes: readFileSync(join(dir, ...f.path.split("/"))) })),
      ...manifest.contracts.map((c) => ({ path: c.path, bytes: readFileSync(join(CLI, "lib", "inspector", ...c.path.split("/"))) }))];
    manifest.ruleset_id = `${manifest.ruleset_id.split(".")[0]}.${rulesetHash(entries)}`;
    writeFileSync(join(dir, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
    const own = checkRuleset({ rulesDir: dir, pinFile: join(dir, "no-pin.json") }).filter((p) => p.startsWith("rules:"));
    assert.deepEqual(own, [], "the edited copy verifies against its own rewritten manifest");
    const problems = checkRuleset({ rulesDir: dir }).join("\n");
    assert.match(problems, /ruleset_id: rules has /);
    assert.match(problems, /content_sha256: /);
    assert.match(problems, /manifest_sha256: /);
    assert.notEqual(sourcePin(dir).content_sha256, sourcePin(RULES_DIR).content_sha256);
    assert.match(checkRuleset({ rulesDir: RULES_DIR, pinFile: join(dir, "no-pin.json") }).join(), /ruleset-source\.json can't be read/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

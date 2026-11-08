#!/usr/bin/env node
/* Release gate for the rule set.
 *
 *   node scripts/check-ruleset.mjs <the evaluator's app/knowledge>   (npm run check-ruleset -- <dir>)
 *   node scripts/check-ruleset.mjs --self                         (prepublishOnly)
 *
 * Who it serves: the evaluator refuses every fact document whose ruleset_id isn't its own (update_inspector), so a
 * package carrying another rule set can't check anything. With a hosted knowledge folder, this fails unless rules
 * verifies against its own manifest and that manifest names the same ruleset_id, min_engine, files and contracts (the
 * response schema copy in lib/inspector/contracts), with the same sha256 for each, as the hosted manifest. With --self it checks rules against its own manifest only (what the
 * package can know at publish time); when CUSTOSA_HOSTED_RULES is set (the hosted knowledge/rules folder), --self
 * also compares against the hosted manifest next to it. Both ways also check ruleset-source.json, which sync-rules
 * writes from core: rules must still have its ruleset_id, its manifest.json SHA-256 and its full content SHA-256
 *. Exit 0 when it matches, 1 when it doesn't, 2 on bad usage. */
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { RULES_DIR, SOURCE_PIN, sourcePin, verify } from "./sync-rules.mjs";

/* The differences between the package's manifest and the hosted one (a list; empty when they match). */
export function compareManifests(local, hosted) {
  const problems = [];
  if (local?.ruleset_id !== hosted?.ruleset_id) problems.push(`ruleset_id: rules has ${local?.ruleset_id}, hosted has ${hosted?.ruleset_id}`);
  if (local?.min_engine !== hosted?.min_engine) problems.push(`min_engine: rules has ${local?.min_engine}, hosted has ${hosted?.min_engine}`);
  const mine = new Map((Array.isArray(local?.files) ? local.files : []).map((f) => [f.path, f.sha256]));
  const theirs = new Map((Array.isArray(hosted?.files) ? hosted.files : []).map((f) => [f.path, f.sha256]));
  for (const [path, sha] of theirs) {
    if (!mine.has(path)) problems.push(`${path}: in the hosted rule set, missing from rules`);
    else if (mine.get(path) !== sha) problems.push(`${path}: sha256 differs from the hosted rule set`);
  }
  for (const path of mine.keys()) if (!theirs.has(path)) problems.push(`${path}: in rules, not in the hosted rule set`);
  const contracts = (m) => JSON.stringify(Array.isArray(m?.contracts) ? m.contracts : []);
  if (contracts(local) !== contracts(hosted)) problems.push(`contracts: rules has ${contracts(local)}, hosted has ${contracts(hosted)}`);
  return problems;
}

const readManifest = (dir) => JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8"));

/* The differences between rules and the core rule set it was synced from (ruleset-source.json). */
export function comparePin(rulesDir, pinFile = SOURCE_PIN, contractsRoot = undefined) {
  let pin;
  try { pin = JSON.parse(readFileSync(pinFile, "utf8")); }
  catch (err) { return [`ruleset-source.json can't be read (run npm run sync-rules -- <the evaluator's app/knowledge>): ${err.message}`]; }
  let now;
  try { now = sourcePin(rulesDir, contractsRoot); } catch (err) { return [`rules can't be hashed: ${err.message}`]; }
  const problems = [];
  for (const key of ["ruleset_id", "manifest_sha256", "content_sha256"]) {
    if (typeof pin?.[key] !== "string" || pin[key] !== now[key]) {
      problems.push(`${key}: rules has ${now[key]}, but it was synced from core's ${pin?.[key]}`);
    }
  }
  return problems;
}

/* Every problem with rules (rulesDir), against its own manifest, the core rule set it was synced from (pinFile)
 * and, when hostedDir is given, the hosted one. */
export function checkRuleset({ rulesDir = RULES_DIR, hostedDir = null, pinFile = SOURCE_PIN } = {}) {
  let local;
  try { local = readManifest(rulesDir); } catch (err) { return [`rules/manifest.json can't be read: ${err.message}`]; }
  const problems = verify(rulesDir, local).map((p) => `rules: ${p}`);
  problems.push(...comparePin(rulesDir, pinFile));
  if (hostedDir) {
    let hosted;
    try { hosted = readManifest(hostedDir); } catch (err) { return [...problems, `the hosted manifest.json can't be read: ${err.message}`]; }
    problems.push(...compareManifests(local, hosted));
  }
  return problems;
}

function main(argv) {
  if (argv.length !== 1) {
    process.stderr.write("usage: node scripts/check-ruleset.mjs <path to the evaluator's app/knowledge> | --self\n");
    return 2;
  }
  let hostedDir = null;
  if (argv[0] !== "--self") hostedDir = resolve(argv[0]);
  else if (process.env.CUSTOSA_HOSTED_RULES) {
    const near = dirname(resolve(process.env.CUSTOSA_HOSTED_RULES));
    if (existsSync(join(near, "manifest.json"))) hostedDir = near;
  }
  const problems = checkRuleset({ hostedDir });
  if (problems.length) {
    process.stderr.write(`rules doesn't match${hostedDir ? " the hosted rule set" : " its manifest"}; nothing should be published `
      + `(run npm run sync-rules -- <the evaluator's app/knowledge>, then npm test):\n  ${problems.slice(0, 50).join("\n  ")}\n`);
    return 1;
  }
  const { ruleset_id: id } = readManifest(RULES_DIR);
  process.stdout.write(`rules verified: ruleset ${id}${hostedDir ? ", the same as the hosted rule set" : ""}\n`);
  return 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) process.exitCode = main(process.argv.slice(2));

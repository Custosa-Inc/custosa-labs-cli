/* Engine change A (factor.mjs, rules-worker.mjs): each rule runs from factored NapiConfigs (repeated sub-rules and
 * regexes as utils), rules with an identical rule object share one findAll per file, and prefilter words are looked
 * up once per file. None of it may change a single field of runRules' output, so every test here runs the same input
 * with factoring on (the default) and off (opts.factor: false, every rule from its rule object as written) and asserts
 * deep equality. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { RULE_FRAMEWORKS, loadRules, loadRulesInThread, runRules } from "../lib/inspector/rules.mjs";
import { engineConfig, engineConfigs, factor } from "../lib/inspector/factor.mjs";
import { coreSkip, requireCore } from "./core-checkout.mjs";

const KEY = Buffer.from("0123456789abcdef0123456789abcdef");
const ALL = RULE_FRAMEWORKS.filter((f) => f !== "generic");
const BUNDLE = fileURLToPath(new URL("../rules/", import.meta.url));
const SUBSET = fileURLToPath(new URL("./fixtures/factor/", import.meta.url));
const temp = (prefix) => realpathSync(mkdtempSync(join(tmpdir(), prefix)));
const EXT = { js: "javascript", ts: "typescript", tsx: "tsx", py: "python", go: "go", java: "java", kt: "kotlin", rb: "ruby", php: "php", yml: "yaml", jsonc: "json" };

/* Fixture files under dir (<practice>/<lang>-<framework>.fixtures.<ext>) as runRules input. */
function fixtureFiles(dir) {
  const files = [];
  for (const practice of readdirSync(dir).sort()) {
    if (!statSync(join(dir, practice)).isDirectory()) continue;
    for (const f of readdirSync(join(dir, practice)).sort()) {
      const m = /^([a-z]+)-[a-z_]+\.fixtures\.([a-z]+)$/.exec(f);
      if (m && EXT[m[2]] === m[1]) files.push({ path: `${practice}/${f}`, lang: m[1], text: readFileSync(join(dir, practice, f), "utf8") });
    }
  }
  return files;
}

/* runRules with factoring on and off; deep equality of the whole result. -> the result. */
async function sameBothWays(rules, files, opts) {
  const on = await runRules(rules, files, { key: KEY, timeoutMs: 600_000, ...opts });
  const off = await runRules(rules, files, { key: KEY, timeoutMs: 600_000, ...opts, factor: false });
  assert.deepEqual(on, off);
  assert.equal(on.status, "ok", JSON.stringify(on.notAnalyzed));
  return on;
}

test("factoring on and off: identical runRules output for the shipped rules on a representative subset of the hosted fixtures", { timeout: 600_000 }, async () => {
  // test/fixtures/factor holds 16 fixture files of the hosted rule bundle, chosen for the rules that factor most (the
  // most utils, hoisted regexes, items with controls, tables, and rule objects shared across frameworks), in every
  // language the shipped rules cover. Every shipped rule for the language runs on each, whatever its framework.
  const rules = loadRules(BUNDLE);
  const files = fixtureFiles(SUBSET);
  assert.equal(files.length, 16);
  assert.ok(new Set(files.map((f) => f.lang)).size >= 10);
  const res = await sameBothWays(rules, files, { frameworks: ALL, workers: 4 });
  assert.ok(res.matches.length > 1000, `${res.matches.length} matches`);
  assert.ok(res.matches.some((m) => m.has_control === true) && res.matches.some((m) => m.has_control === false));
  assert.ok(res.matches.some((m) => m.table !== null) && res.links.length > 0);
  assert.equal(res.analyzed, files.length);
  // The configs worked out once in the loader's thread (rules.loadRulesInThread, the server's and the CLI's load)
  // give the same output as the ones each worker works out for itself, at another worker count.
  const manifest = readFileSync(join(BUNDLE, "manifest.json"), "utf8");
  const threaded = await loadRulesInThread(BUNDLE, manifest).result;
  assert.ok(Array.isArray(threaded));
  assert.deepEqual(await runRules(threaded, files, { key: KEY, frameworks: ALL, workers: 2, timeoutMs: 600_000 }), res);
});

/* A crafted rule set that exercises every part of the change: a YAML anchor used in both rule and control (a sub-rule
 * that binds $DB and the table's $T), one that reads $DB bound before it, a regex in four places, the same rule object
 * in two frameworks' files under different ids and controls, and an evidence rule sharing it too. */
const EXPRESS = `id: factor-check.javascript-express.write
practice_id: factor-check
language: javascript
frameworks: [express]
kind: items
min_engine: 0.45.0
table:
  metavariable: $T
  access: write
rule:
  all:
    - &write
      any:
        - pattern: $DB.from($T).insert($$$ROWS)
        - pattern: $DB.from($T).update($$$ROWS)
    - inside:
        stopBy: end
        any: &handler
          - kind: function_declaration
            regex: (?:[Ss]ave|[Ss]tore|[Ww]rite)\\w*\\s*\\(
          - kind: method_definition
            regex: (?:[Ss]ave|[Ss]tore|[Ww]rite)\\w*\\s*\\(
    - inside:
        kind: statement_block
        stopBy: end
        has:
          stopBy: end
          all:
            - &decl
              pattern: const $DB = createClient($$$ARGS)
control:
  all:
    - *write
    - inside:
        stopBy: end
        any: *handler
    - inside:
        kind: statement_block
        stopBy: end
        has:
          stopBy: end
          all:
            - *decl
            - follows:
                stopBy: neighbor
                kind: expression_statement
                regex: requireUser
---
id: factor-check.javascript-express.write-seen
practice_id: factor-check
language: javascript
frameworks: [express]
kind: evidence
min_engine: 0.45.0
rule:
  all:
    - &write
      any:
        - pattern: $DB.from($T).insert($$$ROWS)
        - pattern: $DB.from($T).update($$$ROWS)
    - inside:
        stopBy: end
        any: &handler
          - kind: function_declaration
            regex: (?:[Ss]ave|[Ss]tore|[Ww]rite)\\w*\\s*\\(
          - kind: method_definition
            regex: (?:[Ss]ave|[Ss]tore|[Ww]rite)\\w*\\s*\\(
    - inside:
        kind: statement_block
        stopBy: end
        has:
          stopBy: end
          all:
            - &decl
              pattern: const $DB = createClient($$$ARGS)
`;
// The same rule object under the koa framework, with another id and another control.
const KOA = EXPRESS.split("---\n")[0].replaceAll("javascript-express", "javascript-koa").replace("frameworks: [express]", "frameworks: [koa]")
  .replace("regex: requireUser", "regex: checkRole");
const SOURCE = `import { createClient } from "./db";
async function saveVisit(req) {
  await requireUser(req);
  const db = createClient(url);
  await db.from("visits").insert({ id: 1 });
}
async function storeNote(req) {
  await checkRole(req, "staff");
  const db = createClient(url);
  await db.from("notes").update({ id: 2 });
}
async function writeAudit(req) {
  await requireUser(req);
  const other = createClient(url);
  await db.from("audit").insert({});
}
function loadThings() {
  const db = createClient(url);
  db.from("things").insert({});
}
class Repo {
  saveRow() {
    checkRole(this.req);
    const db = createClient(url);
    db.from("rows").insert({});
  }
}
`;

test("factoring on and off: identical output on a crafted rule set (shared anchors, repeated regexes, one rule object in two frameworks, controls)", async () => {
  const dir = temp("factor-rules-");
  mkdirSync(join(dir, "factor-check"));
  writeFileSync(join(dir, "factor-check", "javascript-express.yml"), EXPRESS);
  writeFileSync(join(dir, "factor-check", "javascript-koa.yml"), KOA);
  const rules = loadRules(dir, { strict: true });
  assert.equal(rules.length, 3);
  // The factoring does happen: sub-rule utils (u*) and regex utils (r*) in both the rule and the control, and the
  // three rules share one findAll (the koa rule's key is the express rule's id).
  const configs = engineConfigs(rules);
  const items = configs[rules.findIndex((r) => r.id.endsWith("express.write"))];
  for (const c of [items.rule, items.control]) {
    assert.ok(Object.keys(c.utils).some((n) => n.startsWith("u")), JSON.stringify(c));
    assert.ok(Object.keys(c.utils).some((n) => n.startsWith("r")), JSON.stringify(c));
  }
  assert.deepEqual(new Set(configs.map((c) => c.key)).size, 1);
  assert.equal(engineConfig(rules[0]).key, JSON.stringify(rules[0].rule));

  const files = [{ path: "src/save.js", text: SOURCE }];
  for (const workers of [1, 3]) {
    const res = await sameBothWays(rules, files, { frameworks: ["express", "koa"], workers });
    // Not a vacuous equality: $DB is bound inside a util and read inside another (writeAudit's `other` client is no
    // match), $T is captured inside a util (the table), and each framework's control decides its own items.
    assert.deepEqual(res.matches.map((m) => [m.rule_id.split(".").slice(1).join("."), m.line_start, m.has_control, m.table !== null]), [
      ["javascript-express.write", 5, true, true], ["javascript-express.write-seen", 5, null, false], ["javascript-koa.write", 5, false, true],
      ["javascript-express.write", 10, false, true], ["javascript-express.write-seen", 10, null, false], ["javascript-koa.write", 10, true, true],
      ["javascript-express.write", 25, false, true], ["javascript-express.write-seen", 25, null, false], ["javascript-koa.write", 25, true, true],
    ]);
  }
  // A rule that fails to compile is rule_error both ways (the shared findAll doesn't hide it).
  const bad = [{ ...rules[0], id: "factor-check.javascript-express.bad", rule: { all: [rules[0].rule, { kind: "no_such_kind" }] } }];
  const on = await runRules(bad, files, { key: KEY, frameworks: ["express"] });
  const off = await runRules(bad, files, { key: KEY, frameworks: ["express"], factor: false });
  assert.deepEqual(on, off);
  assert.deepEqual(on.notAnalyzed, [{ path: "src/save.js", reason: "rule_error" }]);
});

test("factor: only whole rule objects at rule positions become utils; a relational rule, a pattern object and the top stay", () => {
  const sub = { kind: "call_expression", regex: "^(?:requireUser|checkRole)\\(" };
  const rule = { all: [{ pattern: { context: "class A { $M() {} }", selector: "method_definition" } }, { has: { ...sub, stopBy: "end" } },
    { not: sub }, { any: [sub, { kind: "identifier", regex: "^(?:requireUser|checkRole)\\(" }] }] };
  const { rewritten: [r], utils } = factor([rule]);
  assert.deepEqual(utils, { u0: { kind: "call_expression", matches: "r0" }, r0: { regex: "^(?:requireUser|checkRole)\\(" } });
  assert.deepEqual(r.all[0], rule.all[0], "a pattern object is left alone");
  assert.deepEqual(r.all[1], { has: { kind: "call_expression", matches: "r0", stopBy: "end" } }, "the relational rule keeps its own keys");
  assert.deepEqual(r.all[2], { not: { matches: "u0" } });
  assert.deepEqual(r.all[3], { any: [{ matches: "u0" }, { kind: "identifier", matches: "r0" }] });
  // Short sub-rules stay where they are (MIN_BYTES), and nothing repeats in a rule used once.
  assert.deepEqual(factor([{ all: [{ kind: "a" }, { kind: "a" }] }]).utils, {});
  // Each call gets only the utils it reaches.
  const c = engineConfig({ rule: { all: [{ kind: "x" }, { not: sub }] }, control: { all: [{ kind: "y" }, { has: { all: [sub] } }] } });
  assert.deepEqual(Object.keys(c.rule.utils), ["r0", "u0"], "u0 reaches r0");
  assert.deepEqual(Object.keys(c.control.utils), ["r0", "u0"]);
  const apart = engineConfig({ rule: { all: [{ kind: "x" }, { not: sub }, { has: { all: [sub] } }] }, control: { kind: "y", regex: "^z" } });
  assert.deepEqual(Object.keys(apart.rule.utils), ["r0", "u0"]);
  assert.deepEqual(apart.control, { rule: { kind: "y", regex: "^z" } }, "a control that reaches no util gets none");
  assert.equal(engineConfig({ rule: { kind: "x" } }).control, null);
  assert.deepEqual(engineConfig({ rule: { kind: "x" } }).rule, { rule: { kind: "x" } });
});

/* The hosted rule bundle's fixtures, all of them (the evaluator's app/knowledge/rules): CUSTOSA_HOSTED_RULES.
 * One run per practice folder: all of them in one run passed the run's 20,000 match cap (MAX_MATCHES) once the YAML
 * rules and fixtures came in (20,460), so the last files came back match_limit and the run truncated. */
const HOSTED = process.env.CUSTOSA_HOSTED_RULES ?? "";
test("factoring on and off: identical output for the shipped rules on every hosted fixture", { skip: coreSkip(existsSync(HOSTED), "no hosted rule bundle next to this checkout (set CUSTOSA_HOSTED_RULES)"), timeout: 1_800_000 }, async () => {
  requireCore("CUSTOSA_HOSTED_RULES", existsSync(HOSTED));
  const rules = loadRules(BUNDLE);
  const files = fixtureFiles(HOSTED).filter((f) => rules.some((r) => r.language === f.lang));
  assert.ok(files.length > 100, `${files.length} fixtures`);
  const batches = new Map();
  for (const f of files) {
    const practice = f.path.split("/")[0];
    batches.set(practice, [...(batches.get(practice) ?? []), f]);
  }
  let matches = 0;
  for (const batch of batches.values()) matches += (await sameBothWays(rules, batch, { frameworks: ALL, workers: 4 })).matches.length;
  assert.ok(matches > 5000, `${matches} matches`);
});

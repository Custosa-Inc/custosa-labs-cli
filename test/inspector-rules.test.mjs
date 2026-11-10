/* Smoke test for the structural rule engine: loading and refusing rule files, running rules on files, the fixture
 * runner and `custosa rules test`. The rule set under fixtures/rules has one rule per kind (evidence, violation, items
 * with control). Every match is validated against the `matches` item of the shipped fact schema
 * (lib/inspector/contracts/fact_document.schema.json, contract v2.1, with matches[].table, matches[].handler and links;
 * no vendored test copy). */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import Ajv2020Module from "ajv/dist/2020.js";
import { engineAvailable, isSupported, parseCode, parseSync } from "../lib/inspector/parse.mjs";
import { FUNCTION_KINDS, Handlers, handlerId, tableOf } from "../lib/inspector/captures.mjs";
import { hashed } from "../lib/inspector/ids.mjs";
import { createHash, createHmac } from "node:crypto";
import { threadCpuMs } from "../lib/inspector/rules-worker.mjs";
import { MatchWorker, WarmPool, bundleMatches, fingerprint, liveWorkers, loadRules, loadRulesInThread, malformedMarkers, readMarkers, fixtureSections, runFixtures, runRules, toContractNotAnalyzed } from "../lib/inspector/rules.mjs";
import { coreSkip, requireCore } from "./core-checkout.mjs";

const RULES = fileURLToPath(new URL("./fixtures/rules/", import.meta.url));
const BIN = fileURLToPath(new URL("../bin/custosa.mjs", import.meta.url));
const SCHEMA = JSON.parse(readFileSync(new URL("../lib/inspector/contracts/fact_document.schema.json", import.meta.url), "utf8"));
const Ajv2020 = Ajv2020Module.default ?? Ajv2020Module;
const ajv = new Ajv2020({ strict: false, allErrors: true });
ajv.addSchema(SCHEMA);
const validateMatches = ajv.getSchema(`${SCHEMA.$id}#/properties/matches`);
const validateLinks = ajv.getSchema(`${SCHEMA.$id}#/properties/links`);
const KEY = Buffer.from("0123456789abcdef0123456789abcdef");
const temp = (prefix) => realpathSync(mkdtempSync(join(tmpdir(), prefix)));
/* Handlers that report each match's identity name instead of its HMAC (the naming rules under test). */
class Named extends Handlers {
  idOfFunction(i) { const x = this.identity(i); return x ? x.name : null; }
}
/* The real handler id of the function whose identity is `name` in a file (exactly one such function). */
function idFor(lang, path, text, name) {
  const h = new Named(parseSync(lang, text).root(), lang, path, KEY);
  h.load();
  const owners = new Set();
  h.fns.forEach((_, i) => { const x = h.identity(i); if (x && x.name === name) owners.add(x.owner); });
  assert.equal(owners.size, 1, `one function named ${name}`);
  const f = h.fns[[...owners][0]];
  return handlerId(KEY, path, name, f.line, f.column);
}

const ROUTE = `import { requireUser } from "@/lib/auth";
export async function GET(request) {
  return Response.json(await load(request));
}
export async function POST(request) {
  const user = await requireUser(request);
  await db.from("audit_log").insert({ user });
  return Response.json({});
}
`;
const CLIENT = `function show(record) {\n  console.log(record.patient);\n  localStorage.setItem("p", record.patient);\n}\n`;

/* The slow-walk tests need a per-file limit that the slow file's native walk outlasts by a wide margin, while the work
 * before the walk (the parse and console-phi, a few hundredths of the walk) fits inside it: the worker must be inside
 * the walk when the limit passes. Fixed limits fail one way or the other: the walk takes about 7 s on an old Intel
 * laptop, under 1.5 s on a fast CI runner, and ten times longer on a machine with a load average of 200. So the
 * limit is measured on this machine now: walkMs times one full walk of the slow file in a worker, the same way a run
 * does it (a fresh worker, start-up not counted), and each test takes a fraction of it. The run that follows sees
 * the same machine and the same load. */
async function walkMs(slowRule, text) {
  const { id, practice_id, kind, rule, control } = slowRule;
  const pool = new MatchWorker([{ id, practice_id, kind, rule, control }], KEY);
  await pool.ensure();
  const t = performance.now();
  const r = await pool.run({ path: "src/calibrate.js", lang: "javascript", text, ruleIds: [id], softMs: 3_600_000 }, 3_600_000);
  const ms = performance.now() - t;
  assert.equal(await pool.close(), true);
  assert.ok(r.done && !r.done.late && !r.killed && !r.crashed, "the calibration walk ran to the end");
  return ms;
}

// a file URL names a folder by its decoded path. URL.pathname keeps %20 and other escapes, so a checkout under a
// folder with a space or a non-ASCII name couldn't load rules through a URL (DEFAULT_RULES_DIR is one).
test("loadRules and runFixtures take a file URL whose path has a space or a non-ASCII name", async () => {
  const parent = mkdtempSync(join(tmpdir(), "custosa rules é-"));
  try {
    const dir = join(parent, "rules");
    cpSync(RULES, dir, { recursive: true });
    const url = pathToFileURL(`${dir}/`);
    assert.match(url.pathname, /%20/);
    assert.deepEqual(loadRules(url).map((r) => r.id), loadRules(dir).map((r) => r.id));
    assert.ok(loadRules(url).length > 0);
    assert.deepEqual(await runFixtures(url), await runFixtures(dir));
    // runRules reads a file with no text from a URL root the same way.
    writeFileSync(join(parent, "route.ts"), ROUTE);
    const files = [{ path: "route.ts" }];
    const byUrl = await runRules(loadRules(dir), files, { key: KEY, frameworks: ["nextjs"], root: pathToFileURL(parent) });
    assert.deepEqual(byUrl.notAnalyzed, []);
    assert.deepEqual(byUrl, await runRules(loadRules(dir), files, { key: KEY, frameworks: ["nextjs"], root: parent }));
  } finally {
    rmSync(parent, { recursive: true, force: true });
  }
});

test("loadRules reads one rule per kind from the fixture rule set", () => {
  const rules = loadRules(RULES);
  assert.deepEqual(rules.map((r) => r.id), [
    "access-audit-log.typescript-generic.audit-write",
    "ai-trace-redaction.javascript-generic.console-phi",
    "ai-trace-redaction.javascript-generic.local-storage",
    "audit-actor-recorded.python-generic.audit-call",
    "auth-on-by-default.typescript-nextjs.route-handler",
  ]);
  assert.deepEqual([...new Set(rules.map((r) => r.kind))].sort(), ["evidence", "items", "violation"]);
  assert.ok(rules.find((r) => r.kind === "items").control);
});

test("runFixtures runs a fixture's sections on one warm rule worker per rule file, with the same results", async () => {
  // T19 (T29 conventions audit P1): a cold worker per section paid the worker's start (grammars, rules, prefilters)
  // once per section; core's 793 sections in 377 fixture files took 143 s cold and 95 s warm on P2, same counts.
  const parent = mkdtempSync(join(tmpdir(), "custosa-fixwarm-"));
  try {
    const dir = join(parent, "rules");
    cpSync(RULES, dir, { recursive: true });
    const fixture = join(dir, "ai-trace-redaction", "javascript-generic.fixtures.js");
    const body = readFileSync(fixture, "utf8");
    writeFileSync(fixture, ["a", "b", "c"].map((n) => `// path: src/${n}.js\n${body}`).join(""));
    const files = new Set(loadRules(dir).map((r) => r.file)).size;
    const warm = new WarmPool();
    const got = await runFixtures(dir, { warm });
    assert.deepEqual(got.failed, []);
    assert.ok(warm.started >= 1 && warm.started <= files, `${warm.started} workers for ${files} rule files and 6 sections`);
    const own = await runFixtures(dir);   // no pool given: it makes its own and drops it
    assert.deepEqual(own, got);
    assert.equal(got.passed, (await runFixtures(RULES)).passed + 2 * 4, "the copied sections' 4 markers run twice more");
  } finally {
    rmSync(parent, { recursive: true, force: true });
  }
});

test("runFixtures passes on the fixture rule set, and `custosa rules test` agrees", async () => {
  const { passed, failed } = await runFixtures(RULES);
  assert.deepEqual(failed, []);
  assert.equal(passed, 12);
  const cli = spawnSync(process.execPath, [BIN, "rules", "test", RULES], { encoding: "utf8" });
  assert.equal(cli.status, 0, cli.stderr);
  assert.match(cli.stdout, /12 passed, 0 failed/);
});

test("a wrong fixture expectation fails with its file and line", async () => {
  const dir = temp("custosa-rules-");
  cpSync(RULES, dir, { recursive: true });
  const fx = join(dir, "ai-trace-redaction", "javascript-generic.fixtures.js");
  // Line 4 says ok for console.log("loaded") on line 5; claim a match there instead.
  writeFileSync(fx, readFileSync(fx, "utf8").replace("// ok: ai-trace-redaction.javascript-generic.console-phi", "// ruleid: ai-trace-redaction.javascript-generic.console-phi"));
  // And mark nothing above the real localStorage match on line 7.
  writeFileSync(fx, readFileSync(fx, "utf8").replace("  // ruleid: ai-trace-redaction.javascript-generic.local-storage\n", "\n"));
  const { failed } = await runFixtures(dir);
  assert.deepEqual(failed, [
    { rule_id: "ai-trace-redaction.javascript-generic.console-phi", file: "ai-trace-redaction/javascript-generic.fixtures.js", line: null, expected: "at least one ok marker", got: "none" },
    { rule_id: "ai-trace-redaction.javascript-generic.local-storage", file: "ai-trace-redaction/javascript-generic.fixtures.js", line: null, expected: "at least one ruleid marker", got: "none" },
    { rule_id: "ai-trace-redaction.javascript-generic.console-phi", file: "ai-trace-redaction/javascript-generic.fixtures.js", line: 5, expected: "a match", got: "none" },
    { rule_id: "ai-trace-redaction.javascript-generic.local-storage", file: "ai-trace-redaction/javascript-generic.fixtures.js", line: 7, expected: "no match (no ruleid marker here)", got: "a match" },
  ]);
  const cli = spawnSync(process.execPath, [BIN, "rules", "test", dir], { encoding: "utf8" });
  assert.equal(cli.status, 1);
  assert.match(cli.stderr, /FAIL ai-trace-redaction\/javascript-generic\.fixtures\.js:5 ai-trace-redaction\.javascript-generic\.console-phi: expected a match, got none/);
});

test("runRules reports schema-valid matches with local fingerprints, and every file it can't analyse", async () => {
  const rules = loadRules(RULES);
  const files = [
    { path: "app/api/visits/route.ts", text: ROUTE },
    { path: "src/client.js", text: CLIENT },
    { path: "Services/Visits.cs", text: "class Visits { }" },
    { path: "src/lib.rs", text: "fn main() {}" },
    { path: "scripts/job.go", lang: "go", text: "package main\nfunc main() {}\n" },
    { path: "src/broken.js", text: "console.log(x.patient);\nfunction f( {\n" },
  ];
  const res = await runRules(rules, files, { key: KEY, frameworks: ["nextjs"] });
  assert.ok(validateMatches(res.matches), JSON.stringify(validateMatches.errors));
  assert.equal(validateMatches([{ ...res.matches[0], fingerprint: "abc" }]), false); // the check bites
  const brief = res.matches.map(({ rule_id, kind, path, line_start, line_end, has_control }) => [rule_id.split(".").pop(), kind, path, line_start, line_end, has_control]);
  assert.deepEqual(brief, [
    ["route-handler", "item", "app/api/visits/route.ts", 2, 4, false],
    ["route-handler", "item", "app/api/visits/route.ts", 5, 9, true],
    ["audit-write", "evidence", "app/api/visits/route.ts", 7, 7, null],
    ["console-phi", "violation", "src/broken.js", 1, 1, null],
    ["console-phi", "violation", "src/client.js", 2, 2, null],
    ["local-storage", "violation", "src/client.js", 3, 3, null],
  ]);
  assert.deepEqual(res.notAnalyzed, [
    { path: "Services/Visits.cs", reason: "unsupported_language" }, // C#: no parser in this build
    { path: "src/lib.rs", reason: "unsupported_language" }, // Rust has a language and no grammar
    { path: "scripts/job.go", reason: "unsupported_language" }, // Go parses, but no rule for Go
    { path: "src/broken.js", reason: "parse_error" }, // run (its violation counts) but never counted as analysed
  ]);
  assert.equal(res.analyzed, 2);
  assert.deepEqual(res.languages, ["javascript", "typescript"]);
  assert.equal(res.status, "ok");
  assert.equal(res.reason, null);
  assert.equal(res.count, 4);
  // The fingerprint is the HMAC of rule id, path and the collapsed text; the text itself is in no match.
  const ev = res.matches.find((m) => m.kind === "evidence");
  assert.equal(ev.fingerprint, fingerprint(KEY, ev.rule_id, ev.path, 'db.from("audit_log").insert({ user })'));
  assert.equal(fingerprint(KEY, "r", "p", "a(\n   b)"), fingerprint(KEY, "r", "p", "a( b)"));
  assert.ok(!JSON.stringify(res).includes("audit_log"));
  // Handlers: the nearest enclosing function, the matched node itself counted (the items are the functions).
  const r = (name) => idFor("typescript", "app/api/visits/route.ts", ROUTE, name), c = (name) => idFor("javascript", "src/client.js", CLIENT, name);
  assert.deepEqual(res.matches.map((m) => m.handler), [r("GET"), r("POST"), r("POST"), null /* broken.js: recovered, never linked */, c("show"), c("show")]);
  assert.ok(res.matches.every((m) => m.table === null)); // no fixture rule declares table
  assert.deepEqual(res.links, []);
  // Without nextjs detected, the nextjs items rule doesn't run.
  const plain = await runRules(rules, files.slice(0, 1), { key: KEY, frameworks: [] });
  assert.deepEqual(plain.matches.map((m) => m.kind), ["evidence"]);
  // Same input, same output.
  assert.deepEqual(await runRules(rules, files, { key: KEY, frameworks: ["nextjs"] }), res);
  await assert.rejects(runRules(rules, files, { frameworks: [] }), /per-install key/);
});

test("the launch languages from @ast-grep/lang-* parse here", async () => {
  for (const lang of ["python", "php", "java", "kotlin", "go", "ruby", "yaml", "json"]) assert.ok(isSupported(lang), lang);
  for (const lang of ["csharp", "sql", "toml", "hcl"]) assert.ok(!isSupported(lang), lang);
  assert.equal(parseCode("python", "def f():\n    return 1\n").recovered, false);
});

test("a file past the hard deadline is time_limit, keeps its violations, and the next file still runs", async () => {
  const rules = loadRules(RULES);
  const consolePhi = rules.find((r) => r.id.endsWith("console-phi"));
  // A quadratic rule (refused at load; passed in directly here) on 4,800 statements: one native findAll that runs
  // seconds (walkMs). The file is time_limit at the deadline; its worker is terminated, and runRules returns once that
  // thread has exited. The limit is a quarter of the measured walk: room to parse the file and post console-phi's
  // violation before the walk, and the walk outlasts it four times. The grace for the exit is generous and scales
  // with the walk too, or on a loaded machine the run would return early with the thread alive.
  const slowRule = { ...consolePhi, id: "ai-trace-redaction.javascript-generic.slow", kind: "evidence",
    rule: { kind: "expression_statement", follows: { kind: "expression_statement", regex: "^zzz", stopBy: "end" } } };
  const slowFile = "console.log(x.patient);\n" + "a();\n".repeat(4800) + "// zzz (lets the prefilter run the slow rule)\n";
  const walk = await walkMs(slowRule, slowFile);
  const res = await runRules([consolePhi, slowRule], [{ path: "src/slow.js", text: slowFile }, { path: "src/client.js", text: CLIENT }], { key: KEY, frameworks: [],
    timeoutMs: Math.max(200, Math.ceil(walk / 4)), closeGraceMs: Math.max(120000, Math.ceil(20 * walk)) });
  assert.equal(liveWorkers(), 0);
  assert.deepEqual(res.notAnalyzed, [{ path: "src/slow.js", reason: "time_limit" }]);
  assert.deepEqual(res.matches.map((m) => [m.path, m.line_start, m.kind]), [["src/client.js", 2, "violation"], ["src/slow.js", 1, "violation"]]);
  assert.equal(res.analyzed, 1); // the next file, in a fresh worker
  assert.equal(res.status, "truncated");
  assert.equal(res.reason, "timeout");
  const big = "export const x = { a: [1, 2, 3], b: () => f(1) };\n".repeat(40000);
  const tooBig = await runRules(rules, [{ path: "big.ts", text: big }], { key: KEY, frameworks: [], maxBytes: 1000 });
  assert.deepEqual(tooBig.notAnalyzed, [{ path: "big.ts", reason: "too_large" }]);
  assert.equal(tooBig.status, "empty");
  assert.equal((await runRules(rules, [], { key: KEY, frameworks: [] })).status, "empty");
});

test("1a: a file with rules for its language but none for its frameworks is never analysed with zero rules", async () => {
  const rules = loadRules(RULES);
  const nextOnly = rules.filter((r) => r.kind === "items");
  const route = [{ path: "app/api/visits/route.ts", text: ROUTE }];
  const none = await runRules(nextOnly, route, { key: KEY, frameworks: ["express"] });
  assert.deepEqual(none.notAnalyzed, [{ path: "app/api/visits/route.ts", reason: "no_rule_for_framework" }]);
  assert.equal(none.analyzed, 0);
  assert.equal(none.status, "empty");
  const unknown = await runRules(nextOnly, route, { key: KEY, frameworks: null });
  assert.deepEqual(unknown.notAnalyzed, [{ path: "app/api/visits/route.ts", reason: "frameworks_unknown" }]);
  // Unknown frameworks with a generic rule too: the generic rule runs and counts, the file still isn't analysed.
  const mixed = await runRules(rules, route, { key: KEY, frameworks: null });
  assert.deepEqual(mixed.matches.map((m) => m.kind), ["evidence"]);
  assert.deepEqual(mixed.notAnalyzed, [{ path: "app/api/visits/route.ts", reason: "frameworks_unknown" }]);
  assert.equal(mixed.analyzed, 0);
  assert.deepEqual(toContractNotAnalyzed(mixed.notAnalyzed), [{ path: "app/api/visits/route.ts", reason: "unsupported_language" }]);
  await assert.rejects(runRules(rules, route, { key: KEY }), /opts\.frameworks/);
});

test("1b: a recovered parse (MISSING node, no ERROR) is parse_error and loses its evidence and controls", async () => {
  // A missing `}` lets GET swallow POST: GET would look controlled by POST's requireUser.
  const swallowed = `export async function GET(request) {
  return Response.json(await load(request));

export async function POST(request) {
  await requireUser(request);
  await db.from("audit_log").insert({});
}
`;
  assert.equal(parseCode("javascript", "if (a) { b()\n").recovered, true); // MISSING only
  const rules = loadRules(RULES);
  const res = await runRules(rules, [
    { path: "app/api/visits/route.ts", text: swallowed },
    { path: "src/client.js", text: "function f() {\n  console.log(x.patient);\n" },
  ], { key: KEY, frameworks: ["nextjs"] });
  assert.deepEqual(res.notAnalyzed, [{ path: "app/api/visits/route.ts", reason: "parse_error" }, { path: "src/client.js", reason: "parse_error" }]);
  assert.ok(!res.matches.some((m) => m.kind === "evidence" || m.has_control === true), JSON.stringify(res.matches));
  assert.deepEqual(res.matches.filter((m) => m.kind === "violation").map((m) => [m.path, m.line_start]), [["src/client.js", 2]]);
  assert.equal(res.analyzed, 0);
});

test("1c: a rule that throws keeps the file's violations, drops its evidence, and reports rule_error", async () => {
  const rules = loadRules(RULES);
  const consolePhi = rules.find((r) => r.id.endsWith("console-phi"));
  const evidence = { ...consolePhi, id: "ai-trace-redaction.javascript-generic.ev", kind: "evidence", rule: { pattern: "localStorage.setItem($K, $V)" } };
  const boom = { ...consolePhi, id: "ai-trace-redaction.javascript-generic.boom", rule: { kind: "not_a_kind" } };
  const res = await runRules([evidence, consolePhi, boom], [{ path: "src/client.js", text: CLIENT }], { key: KEY, frameworks: [] });
  assert.deepEqual(res.notAnalyzed, [{ path: "src/client.js", reason: "rule_error" }]);
  assert.deepEqual(res.matches.map((m) => [m.rule_id.split(".").pop(), m.kind]), [["console-phi", "violation"]]);
  assert.equal(res.status, "truncated");
  assert.equal(res.reason, "internal_error");
  // A run that fails outright carries a code, never error text.
  const bad = await runRules([{ ...consolePhi, rule: { kind: "identifier", fn() {} } }], [{ path: "src/client.js", text: CLIENT }], { key: KEY, frameworks: [] });
  assert.deepEqual(bad, { matches: [], links: [], notAnalyzed: [], analyzed: 0, languages: [], status: "failed", reason: "internal_error", count: 0, code: "worker_failed" });
  assert.equal(engineAvailable(), true);
});

test("4a: a marker-like line that isn't a strict marker fails the fixture run", async () => {
  const dir = temp("custosa-rules-");
  cpSync(RULES, dir, { recursive: true });
  const fx = join(dir, "ai-trace-redaction", "javascript-generic.fixtures.js");
  const text = readFileSync(fx, "utf8")
    .replace("// ok: ai-trace-redaction.javascript-generic.local-storage", "// OK: ai-trace-redaction.javascript-generic.local-storage")
    .replace('  console.log("loaded");', '  console.log("loaded"); # ruleid: ai-trace-redaction.javascript-generic.console-phi');
  writeFileSync(fx, text);
  const { failed } = await runFixtures(dir);
  const malformed = failed.filter((f) => f.got === "malformed_marker").map((f) => [f.file, f.line]);
  assert.deepEqual(malformed, [["ai-trace-redaction/javascript-generic.fixtures.js", 5], ["ai-trace-redaction/javascript-generic.fixtures.js", 8]]);
  assert.deepEqual(malformedMarkers("const r = { ok: true };\n// ok: a.b\n", "//"), []); // code, and a strict marker
});

test("Every marker-like line is either read as a marker or reported malformed, never both or neither", () => {
  for (const c of ["//", "#", "--"]) {
    const lines = [`${c} ruleid: a.b`, `  ${c}   ok:   a.b  `, `${c}ok:a.b`, `${c} OK: a.b`, `${c} RuleId: a.b`, `${c} ruleid: a.b c`,
      `${c} ruleid:`, `x ${c} ok: a.b`, `${c} ok : a.b`, `${c} ruleid: a.b\t`];
    for (const line of lines) {
      const text = `${line}\ncode();\n`;
      const read = readMarkers(text, c).length, malformed = malformedMarkers(text, c).length;
      assert.equal(read + malformed, 1, `${JSON.stringify(line)}: read ${read}, malformed ${malformed}`);
    }
  }
  assert.deepEqual(readMarkers("// ruleid: a.b\n\n// ok: c.d\nx();\n// ok: e.f\n", "//"), [
    { type: "ruleid", id: "a.b", line: 1, target: 4 }, { type: "ok", id: "c.d", line: 3, target: 4 },
    { type: "ok", id: "e.f", line: 5, target: null },
  ]);
});

test("5a: at run time a rule for a language with no parser is left out; strict loading refuses it", () => {
  const dir = ruleSet("csharp-generic.yml", [{ ...GOOD, id: "access-audit-log.csharp-generic.x", language: "csharp" }]);
  writeFileSync(join(dir, "access-audit-log", "typescript-generic.yml"), JSON.stringify(GOOD));
  assert.deepEqual(loadRules(dir).map((r) => r.id), [GOOD.id]);
  const strict = (() => { try { loadRules(dir, { strict: true }); } catch (e) { return e.problems; } return []; })();
  assert.ok(strict.some((p) => p.startsWith("access-audit-log/csharp-generic.yml: language: no parser for csharp")), strict.join("\n"));
});

const GOOD = {
  id: "access-audit-log.typescript-generic.x", practice_id: "access-audit-log", language: "typescript",
  frameworks: ["generic"], kind: "evidence", rule: { pattern: "audit($A)" }, min_engine: "0.45.0",
};
function ruleSet(name, docs) {
  const dir = temp("custosa-bad-");
  mkdirSync(join(dir, "access-audit-log"));
  const yaml = (d) => JSON.stringify(d); // JSON is YAML
  writeFileSync(join(dir, "access-audit-log", name), docs.map(yaml).join("\n---\n"));
  return dir;
}
const refusal = (dir) => { try { loadRules(dir, { strict: true }); } catch (e) { assert.equal(e.code, "RULES_INVALID"); return e.problems; } assert.fail("loaded"); };

test("loadRules refuses a bad rule with file: field: problem", () => {
  const f = "access-audit-log/typescript-generic.yml";
  const cases = [
    [{ ...GOOD, mode: "taint" }, `${f}: mode: dataflow/taint rules are not supported at launch`],
    [{ ...GOOD, rule: { pattern: "audit($A)", taint: { sources: [] } } }, `${f}: rule.taint: dataflow/taint rules are not supported at launch`],
    [{ ...GOOD, message: "words" }, `${f}: message: unknown key`],
    [{ ...GOOD, kind: "items" }, `${f}: control: is required for kind items`],
    [{ ...GOOD, control: { has: { pattern: "x" } } }, `${f}: control: only allowed for kind items`],
    [{ ...GOOD, rule: { pattern: "audit($A)", constraints: {} } }, `${f}: rule.constraints: not used at launch`],
    [{ ...GOOD, rule: { regex: "audit" } }, `${f}: rule.regex: only refines a pattern or kind`],
    [{ ...GOOD, rule: { not: { kind: "identifier" } } }, `${f}: rule: needs a pattern or kind`],
    [{ ...GOOD, rule: { kind: "no_such_kind" } }, `${f}: rule: `],
    [{ ...GOOD, rule: { pattern: "audit(" } }, `${f}: rule.pattern: does not parse as typescript`],
    [{ ...GOOD, id: "other-practice.typescript-generic.x" }, `${f}: id: must start with access-audit-log.typescript-generic.`],
    [{ ...GOOD, frameworks: ["generic", "nextjs"] }, `${f}: frameworks: generic stands alone`],
    [{ ...GOOD, min_engine: "9.0.0" }, `${f}: min_engine: needs @ast-grep/napi 9.0.0`],
    [{ ...GOOD, kind: "items", control: { not: { kind: "identifier" } } }, `${f}: control: needs a positive matcher`],
    [{ ...GOOD, rule: { pattern: "$X" } }, `${f}: rule.pattern: a lone metavariable matches every node`],
    [{ ...GOOD, rule: { kind: "call_expression", has: { pattern: "$$$ARGS", stopBy: "end" } } }, `${f}: rule.has.pattern: a lone metavariable`],
    // $$A captures any single node too (unnamed nodes included).
    [{ ...GOOD, rule: { pattern: "$$A" } }, `${f}: rule.pattern: a lone metavariable matches every node`],
    [{ ...GOOD, rule: { pattern: { context: "$X;", selector: "expression_statement" } } }, `${f}: rule.pattern.context: a lone metavariable`],
    [{ ...GOOD, rule: { kind: "call_expression", follows: { kind: "call_expression", stopBy: "end" } } }, `${f}: rule.follows.stopBy: only neighbor on follows`],
    [{ ...GOOD, rule: { kind: "call_expression", precedes: { kind: "identifier", field: "name" } } }, `${f}: rule.precedes.field: not allowed in precedes: field is for has and inside only`],
  ];
  for (const [doc, expected] of cases) {
    const problems = refusal(ruleSet("typescript-generic.yml", [doc]));
    assert.ok(problems.some((p) => p.startsWith(expected)), `${expected}\n got: ${problems.join("\n")}`);
  }
  // Unsupported language: no rule for it ships.
  const cs = refusal(ruleSet("csharp-generic.yml", [{ ...GOOD, id: "access-audit-log.csharp-generic.x", language: "csharp" }]));
  assert.ok(cs.some((p) => p.startsWith("access-audit-log/csharp-generic.yml: language: no parser for csharp")), cs.join("\n"));
  // Duplicate ids, numbered by document; duplicate YAML keys.
  const dup = refusal(ruleSet("typescript-generic.yml", [GOOD, GOOD]));
  assert.ok(dup.some((p) => p.startsWith(`${f}#2: id: ${GOOD.id} is also defined in ${f}#1`)), dup.join("\n"));
  const dir = ruleSet("typescript-generic.yml", [GOOD]);
  writeFileSync(join(dir, "access-audit-log", "typescript-generic.yml"), "id: a\nid: b\n");
  assert.ok(refusal(dir).some((p) => p.startsWith(`${f}: (yaml): `)));
  // A directory where a rule file should be.
  const eis = temp("custosa-bad-");
  mkdirSync(join(eis, "access-audit-log", "typescript-generic.yml"), { recursive: true });
  assert.ok(refusal(eis).some((p) => p.startsWith(`${f}: (file): not a regular file`)));
  // The good rule loads.
  assert.equal(loadRules(ruleSet("typescript-generic.yml", [GOOD])).length, 1);
});

test("over the match cap, violations are kept first and every file that lost a match is not analysed", async () => {
  const rules = loadRules(RULES);
  // 15,000 evidence matches in a file that sorts first, 6,000 violations in one that sorts after it: 21,000 > 20,000.
  const evidence = 'db.from("audit_log").insert(1);\n'.repeat(15000);
  const violations = "console.log(x.patient);\n".repeat(6000);
  const small = "console.log(y.patient);\n";
  const res = await runRules(rules, [
    { path: "a/evidence.ts", text: evidence },
    { path: "b/client.js", text: violations },
    { path: "c/small.js", text: small },
  ], { key: KEY, frameworks: [], timeoutMs: 30000 }); // the cap is under test, not the deadline (CI under load)
  assert.equal(res.matches.length, 20000);
  // Every violation is kept; the evidence is what gets cut.
  assert.equal(res.matches.filter((m) => m.kind === "violation").length, 6001);
  assert.equal(res.matches.filter((m) => m.kind === "evidence").length, 13999);
  // The file that lost matches is not analysed; the files that kept all of theirs still are.
  assert.deepEqual(res.notAnalyzed, [{ path: "a/evidence.ts", reason: "match_limit" }]);
  assert.deepEqual(toContractNotAnalyzed(res.notAnalyzed), [{ path: "a/evidence.ts", reason: "match_limit" }]);
  assert.equal(res.analyzed, 2);
  assert.equal(res.status, "truncated");
  assert.equal(res.reason, "item_limit");
  assert.ok(validateMatches(res.matches), JSON.stringify(validateMatches.errors?.slice(0, 3)));
  // Kept matches are in the usual order.
  const sorted = [...res.matches].sort((x, y) => (x.path < y.path ? -1 : x.path > y.path ? 1 : x.line_start - y.line_start));
  assert.deepEqual(res.matches.map((m) => `${m.path}:${m.line_start}`), sorted.map((m) => `${m.path}:${m.line_start}`));
  // Violations alone over the cap: the file that loses some is not analysed either.
  const flood = await runRules(rules, [{ path: "a/small.js", text: small }, { path: "b/client.js", text: "console.log(x.patient);\n".repeat(20001) }], { key: KEY, frameworks: [], timeoutMs: 30000 });
  assert.equal(flood.matches.length, 20000);
  assert.deepEqual(flood.notAnalyzed, [{ path: "b/client.js", reason: "match_limit" }]);
  assert.equal(flood.analyzed, 1);
  assert.ok(flood.matches.some((m) => m.path === "a/small.js"));
});

test("a timed-out worker is terminated and awaited; no worker or handle outlives the run", async () => {
  const rules = loadRules(RULES);
  const consolePhi = rules.find((r) => r.id.endsWith("console-phi"));
  const slowRule = { ...consolePhi, id: "ai-trace-redaction.javascript-generic.slow", kind: "evidence",
    rule: { kind: "expression_statement", follows: { kind: "expression_statement", regex: "^zzz", stopBy: "end" } } };
  // Smaller than the other slow files: a timed-out file is time_limit whether its worker was terminated mid-walk or
  // skipped the slow rule at the between-rules check, so only the walk outlasting the limit matters here.
  const slowFile = "console.log(x.patient);\n" + "a();\n".repeat(3200) + "// zzz (lets the prefilter run the slow rule)\n";
  const walk = await walkMs(slowRule, slowFile); // its pool is closed before the handles are counted
  const before = process.getActiveResourcesInfo().filter((r) => r !== "CloseReq");
  const files = [{ path: "src/slow.js", text: slowFile }, { path: "src/slow2.js", text: slowFile }, { path: "src/slow3.js", text: slowFile }, { path: "src/client.js", text: CLIENT }];
  // As above: a quarter of the measured walk for the limit, and a grace that scales with it, so the run waits for the
  // terminated threads however slow a loaded machine is.
  const res = await runRules([consolePhi, slowRule], files, { key: KEY, frameworks: [],
    timeoutMs: Math.max(100, Math.ceil(walk / 4)), closeGraceMs: Math.max(120000, Math.ceil(20 * walk)) });
  assert.deepEqual(res.notAnalyzed, files.slice(0, 3).map(({ path }) => ({ path, reason: "time_limit" })));
  assert.equal(res.analyzed, 1);
  assert.equal(liveWorkers(), 0);
  const after = process.getActiveResourcesInfo().filter((r) => r !== "CloseReq");
  assert.deepEqual(after, before, "a handle (worker port or timer) outlived the run");
  // No thread is still burning CPU on the abandoned native walk.
  const cpu0 = process.cpuUsage();
  const wall0 = Date.now();
  await new Promise((resolve) => setTimeout(resolve, 400));
  const used = (process.cpuUsage(cpu0).user + process.cpuUsage(cpu0).system) / 1000;
  assert.ok(used < (Date.now() - wall0) * 0.5, `still using CPU after the run: ${used} ms in ${Date.now() - wall0} ms`);
});

test("the wait for stuck workers is bounded; the run returns what it has, truncated timeout, and the next run starts fresh", async () => {
  const rules = loadRules(RULES);
  const consolePhi = rules.find((r) => r.id.endsWith("console-phi"));
  const slowRule = { ...consolePhi, id: "ai-trace-redaction.javascript-generic.slow", kind: "evidence",
    rule: { kind: "expression_statement", follows: { kind: "expression_statement", regex: "^zzz", stopBy: "end" } } };
  const slowFile = "console.log(x.patient);\n" + "a();\n".repeat(4800) + "// zzz (lets the prefilter run the slow rule)\n"; // seconds of native walk
  const files = [{ path: "src/a.js", text: CLIENT }, { path: "src/slow.js", text: slowFile }, { path: "src/slow2.js", text: slowFile },
    { path: "src/slow3.js", text: slowFile }, { path: "src/z.js", text: CLIENT }];
  // The premise is that each slow file's worker is inside the native walk when its deadline passes, so terminate()
  // can't stop it, and that the first slow file's walk is still running when slow3 waits out the grace: past two
  // limits, a worker start-up and the grace. So the limit is a twelfth of the measured walk (walkMs) and the grace no
  // longer than the limit: about a fifth of the walk is used, and the work before the walk (a few hundredths of it)
  // still fits inside the limit and the between-rules check (80% of it). A fixed limit failed both ways: at 200 ms
  // to 1000 ms a busy machine skipped the slow rule or terminated the worker before the walk began, and a fast CI
  // runner finished the walk inside a 1000 ms limit.
  const walk = await walkMs(slowRule, slowFile);
  const timeoutMs = Math.max(100, Math.ceil(walk / 12)), closeGraceMs = Math.min(300, timeoutMs);
  try {
    const t0 = Date.now();
    const res = await runRules([consolePhi, slowRule], files, { key: KEY, frameworks: [], timeoutMs, closeGraceMs });
    const took = Date.now() - t0;
    // Bounded: the run returns while the stuck threads are still walking (they run for seconds more), after two file
    // limits and one grace, plus worker start-ups; the default grace alone would be 30 s.
    assert.ok(liveWorkers() > 0, "the stuck threads are still finishing their native call");
    assert.ok(took < 2 * timeoutMs + closeGraceMs + Math.max(5000, walk / 2), `the run waited ${took} ms for stuck workers`);
    assert.equal(res.status, "truncated");
    assert.equal(res.reason, "timeout");
    // What was gathered is kept: the first file analysed with its violations; the slow files, and the file that could
    // not start while two stuck workers held the pool, are time_limit.
    assert.equal(res.analyzed, 1);
    assert.ok(res.matches.some((m) => m.path === "src/a.js" && m.kind === "violation"));
    assert.deepEqual(res.notAnalyzed.map((n) => [n.path, n.reason]), [["src/slow.js", "time_limit"], ["src/slow2.js", "time_limit"],
      ["src/slow3.js", "time_limit"], ["src/z.js", "time_limit"]]);
    // The next run builds a fresh pool and never waits on the stuck threads.
    const next = await runRules(rules, [{ path: "src/client.js", text: CLIENT }], { key: KEY, frameworks: [] });
    assert.equal(next.status, "ok");
    assert.equal(next.analyzed, 1);
  } finally {
    // The stuck threads do exit once their native call returns. Waited for even when an assertion above failed, so
    // a failure here never leaves threads behind for the tests after it (they check liveWorkers() is 0). Generous,
    // and scaled like the limit: on a loaded machine the two walks share the cores with the rest of the test run.
    const until = Date.now() + Math.max(120000, Math.ceil(10 * walk));
    while (liveWorkers() > 0 && Date.now() < until) await new Promise((resolve) => setTimeout(resolve, 100));
  }
  assert.equal(liveWorkers(), 0);
});

test("a worker that dies while idle is replaced at once, not waited on until the deadline", async () => {
  const rules = loadRules(RULES).filter((r) => r.language === "javascript");
  const pool = new MatchWorker(rules.map(({ id, practice_id, kind, rule, control }) => ({ id, practice_id, kind, rule, control })), KEY);
  const job = { path: "src/client.js", lang: "javascript", text: CLIENT, ruleIds: rules.map((r) => r.id), softMs: 4000 };
  const first = await pool.run(job, 5000);
  assert.ok(first.done && !first.killed);
  // The idle worker dies (an out-of-memory exit, say) between files.
  const idle = pool.worker;
  await idle.terminate();
  await idle.exited;
  // Waiting on the dead worker would last until the deadline and end killed. The deadline is long so that a fresh
  // worker's start-up on a loaded machine stays far inside half of it.
  const t0 = Date.now();
  const second = await pool.run(job, 20000);
  assert.ok(Date.now() - t0 < 10000, `waited ${Date.now() - t0} ms on a dead worker`);
  assert.equal(second.killed, false);
  assert.ok(second.done, "the next file ran in a fresh worker");
  assert.deepEqual(second.found.map((m) => m.line_start), first.found.map((m) => m.line_start));
  assert.equal(await pool.close(), true);
  // A worker that dies during a file is a crash (rule_error) as soon as its thread exits, not at the deadline.
  const slow = { id: "ai-trace-redaction.javascript-generic.slow", practice_id: "ai-trace-redaction", kind: "evidence",
    rule: { kind: "expression_statement", follows: { kind: "expression_statement", regex: "^zzz", stopBy: "end" } } };
  const slowPool = new MatchWorker([slow], KEY);
  // The thread exits when its native walk (about 0.6 s, longer on a loaded machine) returns; a wait to the deadline
  // would last 30 s and end killed, not crashed.
  const crashJob = slowPool.run({ ...job, text: "a();\n".repeat(1600) + "// zzz\n", ruleIds: [slow.id] }, 30000);
  while (!slowPool.worker) await new Promise((resolve) => setTimeout(resolve, 10));
  const t1 = Date.now();
  slowPool.worker.terminate();
  const crashed = await crashJob;
  assert.ok(Date.now() - t1 < 15000, `took ${Date.now() - t1} ms`);
  assert.equal(crashed.crashed, true);
  assert.equal(await slowPool.close(), true);
  assert.equal(liveWorkers(), 0);
});

test("the between-rules soft limit is the worker's CPU time: a first rule that used it up ends the file late (time_limit), with no kill", async () => {
  const consolePhi = loadRules(RULES).find((r) => r.id.endsWith("console-phi"));
  const slow = { id: "ai-trace-redaction.javascript-generic.slow", practice_id: "ai-trace-redaction", kind: "violation",
    rule: { kind: "expression_statement", follows: { kind: "expression_statement", regex: "^zzz", stopBy: "end" } } };
  // The slow rule walks back over every earlier statement for each one (quadratic): fast next to the hard limit (an
  // hour here), slow next to the parse. Its two matches are the statements after zzz(); console-phi's is the last line.
  const text = "a();\n".repeat(1200) + "zzz();\nb();\nconsole.log(x.patient);\n";
  // softMs is a quarter of the walk's CPU time, measured on this thread now (CPU time, as the worker counts it), so
  // the parse (a few hundredths of the walk) fits well inside it and the walk passes it four times over.
  let c = threadCpuMs();
  const root = parseSync("javascript", text).root();
  const parsed = threadCpuMs() - c;
  c = threadCpuMs();
  assert.equal(root.findAll({ rule: slow.rule }).length, 2);
  const walked = threadCpuMs() - c;
  const softMs = Math.max(1, Math.ceil(walked / 4));
  assert.ok(parsed * 2 < softMs, `the premise: parse ${parsed} ms of CPU, walk ${walked} ms`);
  const slim = ({ id, practice_id, kind, rule, control }) => ({ id, practice_id, kind, rule, control });
  const pool = new MatchWorker([slow, consolePhi].map(slim), KEY);
  const job = { path: "src/slow.js", lang: "javascript", text, ruleIds: [slow.id, consolePhi.id] };
  let closed = null;
  try {
    // With room for both, both rules run. This first run also warms the thread: a fresh worker's first file pays a
    // fixed start-up (about 10 ms of CPU on P2) before its first rule, which doesn't shrink with the walk. On a fast
    // runner softMs fell under it, and the file ended late before the first rule ran (T28-P1-C8, run 42477518240).
    const whole = await pool.run({ ...job, softMs: 3_600_000 }, 3_600_000);
    assert.equal(whole.done.late, false);
    assert.deepEqual(whole.found.map((m) => [m.rule_id, m.line_start]), [[slow.id, 1202], [slow.id, 1203], [consolePhi.id, 1203]]);
    const thread = pool.worker;
    const cut = await pool.run({ ...job, softMs }, 3_600_000);
    assert.equal(cut.killed, false);
    assert.equal(cut.crashed, false);
    assert.equal(cut.done.late, true, "the second rule is not started past softMs");
    assert.deepEqual(cut.found.map((m) => [m.rule_id, m.line_start]), [[slow.id, 1202], [slow.id, 1203]], "the first rule's matches are kept");
    // (runRules lists a late file time_limit and keeps its violations, as after a kill, but the thread lives on.)
    const again = await pool.run({ ...job, softMs: 3_600_000 }, 3_600_000);
    assert.equal(again.done.late, false);
    assert.equal(pool.worker, thread, "no kill: the worker that stopped early is the one that runs the next file");
    assert.deepEqual(again.found, whole.found);
  } finally {
    closed = await pool.close(); // even when an assertion fails: a live thread would keep the test run from ending
  }
  assert.equal(closed, true);
  // threadCpuMs counts this thread's CPU time, not the time it waits. On a Node without process.threadCpuUsage it is
  // wall time by design (rules-worker.mjs), so there the wait counts in full.
  c = threadCpuMs();
  await new Promise((resolve) => setTimeout(resolve, 300));
  const waited = threadCpuMs() - c;
  if (typeof process.threadCpuUsage === "function") assert.ok(waited < 150, `${waited} ms of CPU while waiting`);
  else assert.ok(waited >= 290, `${waited} ms of wall time while waiting (no process.threadCpuUsage)`);
});

// --- Loader: docs in the rules root, table captures, handler attribution, generic stems -------------------

test("L1: the rules root and practice folders may hold NAMING.md and README.md; any other file is still refused", async () => {
  const dir = temp("custosa-rules-");
  cpSync(RULES, dir, { recursive: true });
  writeFileSync(join(dir, "NAMING.md"), "# Naming\n");
  writeFileSync(join(dir, "ai-trace-redaction", "NAMING.md"), "# Naming\n");
  writeFileSync(join(dir, "ai-trace-redaction", "README.md"), "# Readme\n");
  assert.equal(loadRules(dir, { strict: true }).length, 5);
  assert.deepEqual((await runFixtures(dir)).failed, []);
  const cli = spawnSync(process.execPath, [BIN, "rules", "test", dir], { encoding: "utf8" });
  assert.equal(cli.status, 0, cli.stderr);
  assert.match(cli.stdout, /12 passed, 0 failed/);
  // Anything else is RULES_INVALID, at the root or in a practice folder; a folder named NAMING.md is not a doc.
  for (const [where, problem] of [
    ["notes.txt", "notes.txt: (file): not a practice directory"],
    ["ai-trace-redaction/NAMING.txt", "ai-trace-redaction/NAMING.txt: (file name): neither"],
    ["ai-trace-redaction/NOTES.md", "ai-trace-redaction/NOTES.md: (file name): neither"],
  ]) {
    const bad = temp("custosa-rules-");
    cpSync(dir, bad, { recursive: true });
    writeFileSync(join(bad, ...where.split("/")), "x\n");
    const problems = refusal(bad);
    assert.ok(problems.some((p) => p.startsWith(problem)), `${problem}\n got: ${problems.join("\n")}`);
  }
  const folder = temp("custosa-rules-");
  cpSync(dir, folder, { recursive: true });
  mkdirSync(join(folder, "access-audit-log", "README.md"));
  assert.ok(refusal(folder).some((p) => p.startsWith("access-audit-log/README.md: (file): not a regular file")));
});

const TABLE_RULE = { ...GOOD, rule: { pattern: "$DB.from($T).insert($$$ROWS)" }, table: { metavariable: "$T", access: "write" } };

test("L2: table is validated: one capturing metavariable bound on every match path, access read or write", () => {
  const f = "access-audit-log/typescript-generic.yml";
  const ok = [
    TABLE_RULE,
    { ...TABLE_RULE, table: { metavariable: "$T", access: "read" } },
    { ...TABLE_RULE, rule: { any: [{ pattern: "$DB.from($T)" }, { pattern: "prisma.$T.findMany()" }] } },
    { ...TABLE_RULE, rule: { kind: "function_declaration", has: { pattern: "$DB.from($T)", stopBy: "end" } } },
    { ...TABLE_RULE, rule: { all: [{ kind: "call_expression" }, { pattern: "$DB.from($T)" }] } },
    { ...TABLE_RULE, rule: { pattern: { context: "prisma.$T.findMany()", selector: "member_expression" } } },
    { ...TABLE_RULE, kind: "items", rule: { pattern: "$DB.from($T)" }, control: { inside: { kind: "try_statement", stopBy: "end" } } },
  ];
  for (const doc of ok) assert.equal(loadRules(ruleSet("typescript-generic.yml", [doc]), { strict: true })[0].table.metavariable, "$T", JSON.stringify(doc));
  const notBound = `${f}: table.metavariable: $T is not bound on every match of rule`;
  const cases = [
    [{ ...TABLE_RULE, table: { metavariable: "$X", access: "write" } }, `${f}: table.metavariable: $X is not bound`],
    [{ ...TABLE_RULE, rule: { any: [{ pattern: "$DB.from($T)" }, { pattern: "$DB.table($U)" }] } }, notBound],
    [{ ...TABLE_RULE, rule: { all: [{ pattern: "$DB.from($U)" }, { not: { pattern: "$DB.from($T)" } }] } }, notBound],
    [{ ...TABLE_RULE, rule: { pattern: { context: "audit($A, $T)", selector: "identifier" } } }, notBound],
    [{ ...TABLE_RULE, table: { metavariable: "$_", access: "write" } }, `${f}: table.metavariable: must be one capturing metavariable`],
    [{ ...TABLE_RULE, table: { metavariable: "$$$ROWS", access: "write" } }, `${f}: table.metavariable: must be one capturing metavariable`],
    [{ ...TABLE_RULE, table: { metavariable: "T", access: "write" } }, `${f}: table.metavariable: must be one capturing metavariable`],
    [{ ...TABLE_RULE, table: { metavariable: "$T", access: "delete" } }, `${f}: table.access: must be one of read, write`],
    [{ ...TABLE_RULE, table: { metavariable: "$T" } }, `${f}: table.access: must be one of read, write`],
    [{ ...TABLE_RULE, table: { metavariable: "$T", access: "read", schema: "public" } }, `${f}: table.schema: unknown key`],
    [{ ...TABLE_RULE, table: "$T" }, `${f}: table: must be a mapping`],
  ];
  for (const [doc, expected] of cases) {
    const problems = refusal(ruleSet("typescript-generic.yml", [doc]));
    assert.ok(problems.some((p) => p.startsWith(expected)), `${expected}\n got: ${problems.join("\n")}`);
  }
});

test("L3: each match carries its table, normalised and hashed per the contract, and links pair handlers with tables", async () => {
  const dir = ruleSet("typescript-generic.yml", [TABLE_RULE]);
  const rules = loadRules(dir, { strict: true });
  const text = `export async function save(req) {
  await db.from("patients").insert(1);
  await db.from('public.visits').insert(1);
  await db.from("Patient Notes").insert(1);
  await db.from(\`audit.Log ü\`).insert(1);
  await db.from(tableName).insert(1);
  await db.from(\`x_\${y}\`).insert(1);
  await db.from(Patient).insert(1);
  await db.from('"Odd"."T"').insert(1);
  await db.from("a.b.c").insert(1);
  await db.from(TABLE_NAME).insert(1);
  await db.from("").insert(1);
}
db.from("patients").insert(2);
const log = () => db.from("patients").insert(3);
`;
  const res = await runRules(rules, [{ path: "src/save.ts", text }], { key: KEY, frameworks: ["express"] });
  assert.ok(validateMatches(res.matches), JSON.stringify(validateMatches.errors));
  assert.deepEqual(res.matches.map((m) => [m.line_start, m.table]), [
    [2, "patients"], [3, "public.visits"], [4, hashed(KEY, "Patient Notes")], [5, `audit.${hashed(KEY, "Log ü")}`],
    [6, null], [7, null], [8, null /* a PascalCase variable in from(): not a known ORM model position */], [9, "Odd.T"], [10, hashed(KEY, "a.b.c")], [11, null], [12, null],
    [14, "patients"], [15, "patients"],
  ]);
  assert.match(hashed(KEY, "Patient Notes"), /^u_[0-9a-f]{16}$/);
  const save = idFor("typescript", "src/save.ts", text, "save"), log = idFor("typescript", "src/save.ts", text, "log");
  assert.deepEqual(res.matches.map((m) => m.handler), [...Array(11).fill(save), null, log]);
  assert.ok(validateLinks(res.links), JSON.stringify(validateLinks.errors));
  const expected = [
    { handler: save, table: "patients", access: "write" }, { handler: save, table: "public.visits", access: "write" },
    { handler: save, table: hashed(KEY, "Patient Notes"), access: "write" }, { handler: save, table: `audit.${hashed(KEY, "Log ü")}`, access: "write" },
    { handler: save, table: "Odd.T", access: "write" },
    { handler: save, table: hashed(KEY, "a.b.c"), access: "write" }, { handler: log, table: "patients", access: "write" },
  ];
  const order = (a, b) => (a.handler < b.handler ? -1 : a.handler > b.handler ? 1 : a.table < b.table ? -1 : a.table > b.table ? 1 : 0);
  assert.deepEqual(res.links, expected.sort(order));
  // Every link's pair is on some match (evaluator_api.md 1.2's consistency check).
  for (const l of res.links) assert.ok(res.matches.some((m) => m.handler === l.handler && m.table === l.table));
  // The raw names never leave in the clear when they are hashed.
  assert.ok(!JSON.stringify(res).includes("Patient Notes") && !JSON.stringify(res).includes("Log ü"));
  // Unbound on a match (a rule handed in without the loader's check): table is null, never a guess.
  const unbound = await runRules([{ ...rules[0], table: { metavariable: "$NOPE", access: "read" } }], [{ path: "src/save.ts", text }], { key: KEY, frameworks: [] });
  assert.ok(unbound.matches.length === 13 && unbound.matches.every((m) => m.table === null));
  assert.deepEqual(unbound.links, []);
  // A recovered file keeps its violations without a handler, so it adds no link.
  const viol = { ...rules[0], kind: "violation" };
  const broken = await runRules([viol], [{ path: "src/b.ts", text: 'function f() {\n  db.from("patients").insert(1);\n' }], { key: KEY, frameworks: [] });
  assert.deepEqual(broken.notAnalyzed, [{ path: "src/b.ts", reason: "parse_error" }]);
  assert.deepEqual(broken.matches.map((m) => [m.table, m.handler]), [["patients", null]]);
  assert.deepEqual(broken.links, []);
});

test("L3b: table captures across languages: string literals, symbols and model names; variables and interpolation give null", () => {
  const cases = [
    ["python", "def f():\n  sb.table('patients')\n  sb.table(f\"p_{x}\")\n  sb.table(name)\n  session.query(Patient)\n  sb.table(\"\"\"s.t\"\"\")\n", "$C.$M($T)", ["patients", null, null, "Patient", "s.t"]],
    ["go", "package m\nfunc F() { db.Table(\"patients\"); db.Table(`raw`); db.Table(name) }\n", { context: "func t() { $D.Table($T) }", selector: "call_expression" }, ["patients", "raw", null]],
    ["java", "class A { void m() { jdbc.table(\"patients\"); jdbc.table(name); } }", "jdbc.table($T)", ["patients", null]],
    ["kotlin", "fun f() { db.from(\"patients\"); db.from(\"p$x\"); db.from(name) }", "db.from($T)", ["patients", null, null]],
    ["ruby", "def f\n  db.from(:patients)\n  db.from(\"p#{x}\")\n  db.from('visits')\nend\n", "db.from($T)", ["patients", null, "visits"]],
  ];
  for (const [lang, src, pattern, expected] of cases) {
    const root = parseSync(lang, src).root();
    const got = root.findAll({ rule: { pattern } }).map(tableOfFor(lang));
    assert.deepEqual(got, expected, lang);
  }
  // PHP wraps each argument: the wrapper is looked through.
  const php = parseSync("php", "<?php\nfunction f() { DB::table('patients'); DB::table(\"p$x\"); DB::table($t); }\n").root();
  assert.deepEqual(php.findAll({ rule: { pattern: { context: "<?php DB::table($T);", selector: "scoped_call_expression" } } }).map(tableOfFor("php")), ["patients", null, null]);
});
const tableOfFor = (lang) => (n) => tableOf(n.getMatch("T"), KEY, lang);

test("L4: handler is the function the match belongs to, the matched node counted, in every grammar", () => {
  // Each `target()` call is attributed to the name after it in `expected` (null: no function, or an unnamed one).
  const cases = {
    typescript: [`export async function GET(req) { target(); }
export const POST = async (req) => { target(); };
const f = function named() { target(); };
obj.prop = function () { target(); };
const o = { k: () => target(), m() { target(); } };
class A { handle = () => { target(); }; async run() { target(); } static s() { target(); } }
target();
function outer() { items.map((x) => target()); }
function* gen() { target(); }`, ["GET", "POST", "named", "prop", "k", "m", "handle", "run", "s", null, "outer", "gen"]],
    tsx: [`export default function Page() { target(); return <div/>; }\nconst C = () => { target(); return null; };`, ["Page", "C"]],
    javascript: [`export default function () { target(); }\nmodule.exports.h = async function () { target(); };\nclass B { x = () => { target(); } }`, ["default", "h", "x"]],
    python: ["async def f():\n  target()\n@app.route('/')\ndef g():\n  target()\nh = lambda: target()\nclass C:\n  def m(self):\n    target()\ntarget()\n", ["f", "g", "h", "m", null]],
    go: ["package m\nfunc F() { target() }\nfunc (s *S) M() { target() }\nvar h = func() { target() }\nfunc G() { k := func() { target() }; _ = k }\n", ["F", "M", "h", "k"]],
    java: ["class A { void m() { target(); Runnable r = () -> { target(); }; } A() { target(); } }", ["m", "r", "A"]],
    kotlin: ["fun f() { target() }\nclass C { fun m() { target() } }\nval g = fun() { target() }\nval l = { target() }\n", ["f", "m", "g", "l"]],
    php: ["<?php\nfunction f() { target(); }\nclass C { public function m() { target(); } public static function s() { target(); } }\n$h = function() { target(); };\n$a = fn() => target();\n", ["f", "m", "s", "$h", "$a"]],
    ruby: ["def f\n  target()\nend\ndef self.g\n  target()\nend\nclass C\n  def m\n    target()\n  end\nend\nk = ->() { target() }\n", ["f", "g", "m", "k"]],
  };
  for (const [lang, [src, expected]] of Object.entries(cases)) {
    const root = parseSync(lang, src).root();
    const targets = [];
    const walk = (n) => {
      if (/^target\(\)$/.test(n.text()) && !n.children().some((c) => c.text() === n.text())) targets.push(n);
      else for (const c of n.children()) walk(c);
    };
    walk(root);
    const handlers = new Named(root, lang, "src/f", KEY);
    assert.deepEqual(targets.map((t) => handlers.of(t)), expected, lang);
  }
  // The matched node itself counts: a function, a decorated def, an exported declaration (top-level items rules).
  const ts = parseSync("typescript", "export async function GET() {}\nexport const PUT = async () => {};\n").root();
  const hts = new Named(ts, "typescript", "r.ts", KEY);
  assert.deepEqual(ts.findAll({ rule: { kind: "export_statement" } }).map((n) => hts.of(n)), ["GET", "PUT"]);
  assert.equal(hts.of(ts.find({ rule: { kind: "function_declaration" } })), "GET");
  const py = parseSync("python", "@app.get('/')\nasync def read():\n  pass\n").root();
  assert.equal(new Named(py, "python", "a.py", KEY).of(py.find({ rule: { kind: "decorated_definition" } })), "read");
  // The same name and position in another file is another handler.
  assert.notEqual(handlerId(KEY, "a.py", "read", 2, 0), handlerId(KEY, "b.py", "read", 2, 0));
  assert.match(handlerId(KEY, "a.py", "read", 2, 0), /^[0-9a-f]{64}$/);
  // A grammar with no function kinds (YAML) gives null.
  const yml = parseSync("yaml", "a: 1\n").root();
  assert.equal(new Handlers(yml, "yaml", "a.yml", KEY).of(yml), null);
});

test("L5: a <lang>-generic rule file applies to every framework of its language and never trips no_rule_for_framework", async () => {
  const dir = ruleSet("typescript-generic.yml", [GOOD]);
  writeFileSync(join(dir, "access-audit-log", "typescript-nextjs.yml"), JSON.stringify({ ...GOOD, id: "access-audit-log.typescript-nextjs.y", frameworks: ["nextjs"], rule: { pattern: "nextOnly($A)" } }));
  const rules = loadRules(dir, { strict: true });
  const genericOnly = rules.filter((r) => r.frameworks[0] === "generic");
  const file = [{ path: "src/a.ts", text: "audit(1);\nnextOnly(2);\n" }];
  for (const frameworks of [[], ["express"], ["nextjs", "prisma"], ["django"]]) {
    for (const set of [genericOnly, rules]) {
      const res = await runRules(set, file, { key: KEY, frameworks });
      assert.deepEqual(res.notAnalyzed, [], `${JSON.stringify(frameworks)} ${set.length}`);
      assert.equal(res.analyzed, 1);
      assert.ok(res.matches.some((m) => m.rule_id === GOOD.id));
      assert.equal(res.matches.some((m) => m.rule_id.endsWith(".y")), set === rules && frameworks.includes("nextjs"));
    }
  }
  // Frameworks unknown: a generic-only language is analysed; one with framework rules is frameworks_unknown.
  assert.equal((await runRules(genericOnly, file, { key: KEY, frameworks: null })).analyzed, 1);
  assert.deepEqual((await runRules(rules, file, { key: KEY, frameworks: null })).notAnalyzed, [{ path: "src/a.ts", reason: "frameworks_unknown" }]);
  // A typescript-generic file is for TypeScript only: JavaScript and TSX files have no rule from it.
  const other = await runRules(genericOnly, [{ path: "src/a.js", text: "audit(1);\n" }, { path: "src/a.tsx", text: "audit(1);\n" }], { key: KEY, frameworks: ["express"] });
  assert.deepEqual(other.notAnalyzed, [{ path: "src/a.js", reason: "unsupported_language" }, { path: "src/a.tsx", reason: "unsupported_language" }]);
});

// --- Loader, round 1 ---------------------------------------------------------------------------------------

const tsRule = (name, kind, rule, extra = {}) => ({ id: `access-audit-log.typescript-generic.${name}`, practice_id: "access-audit-log",
  language: "typescript", frameworks: ["generic"], kind, rule, min_engine: "0.45.0", ...extra });
const READ = tsRule("read", "evidence", { pattern: "$DB.from($T).select($$$A)" }, { table: { metavariable: "$T", access: "read" } });
const CONTROL = { has: { pattern: "requireUser($$$A)", stopBy: "end" } };

test("an item and the matches in its body carry one handler id, and the links attach to it", async () => {
  const items = [
    tsRule("next", "items", { kind: "lexical_declaration", regex: "^const (GET|POST|PUT)\\b" }, { control: CONTROL }),
    tsRule("nest", "items", { kind: "decorator", regex: "^@(Get|Post)\\b" }, { control: CONTROL }),
    tsRule("route", "items", { kind: "call_expression", regex: "^(app|router|fastify)\\.(get|post|route\\([^)]*\\)\\.get)\\(" }, { control: CONTROL }),
  ];
  const text = `export const GET = async (req) => {
  return await supabase.from("patients").select("*");
};
export const POST = withAuth(withLog(async (req) => {
  return await supabase.from("visits").select("*");
}));
export class PatientsController {
  @Get(":id")
  @UseGuards(AuthGuard)
  async findOne(id) {
    return await this.supabase.from("patients").select("*");
  }
}
app.get("/patients", async (req, res) => {
  res.json(await db.from("patients").select("*"));
});
fastify.get("/notes", async (request, reply) => {
  const rows = await db.from("notes").select("*");
  return rows.map((r) => db.from("audit").select(r.id));
});
router.post(PATH, async (req, res) => {
  await db.from("orders").select("*");
});
app.route("/visits").get((req, res) => {
  db.from("visits").select("*");
});
`;
  const path = "src/api.ts";
  const res = await runRules([...items, READ], [{ path, text }], { key: KEY, frameworks: [] });
  assert.deepEqual(res.notAnalyzed, []);
  assert.ok(validateMatches(res.matches), JSON.stringify(validateMatches.errors));
  const h = (name) => idFor("typescript", path, text, name);
  const byLine = (line) => res.matches.filter((m) => m.line_start === line).map((m) => [m.kind, m.handler]);
  // Each item is uncontrolled, and its handler is the one its body's evidence carries.
  for (const [itemLine, bodyLine, name] of [[1, 2, "GET"], [4, 5, "POST"], [8, 11, "findOne"], [14, 15, "app GET /patients"],
    [17, 18, "fastify GET /notes"], [17, 19, "fastify GET /notes"], [24, 25, "app GET /visits"]]) {
    assert.deepEqual(byLine(itemLine).filter(([k]) => k === "item"), [["item", h(name)]], `item at ${itemLine}`);
    assert.ok(byLine(bodyLine).some(([k, id]) => k === "evidence" && id === h(name)), `evidence at ${bodyLine}: ${JSON.stringify(byLine(bodyLine))}`);
  }
  // A route whose path isn't a literal has no name: the item and its body agree on null, and no link is made.
  assert.deepEqual(byLine(21), [["item", null]]);
  assert.deepEqual(byLine(22), [["evidence", null]]);
  assert.deepEqual(res.links.map((l) => [l.handler, l.table]).sort(), [
    [h("GET"), "patients"], [h("POST"), "visits"], [h("findOne"), "patients"], [h("app GET /patients"), "patients"],
    [h("fastify GET /notes"), "notes"], [h("fastify GET /notes"), "audit"], [h("app GET /visits"), "visits"],
  ].sort());
  assert.ok(res.matches.filter((m) => m.kind === "item").every((m) => m.has_control === false));
  // Python: a decorated def and its decorator both stand for the function.
  const py = "@app.get('/p')\nasync def read_patients():\n  return sb.table('patients').select('*')\n";
  const root = parseSync("python", py).root();
  const hp = new Named(root, "python", "a.py", KEY);
  const want = "read_patients";
  for (const kind of ["decorated_definition", "decorator", "function_definition", "call"]) assert.equal(hp.of(root.find({ rule: { kind } })), want, kind);
  // Go gin, Laravel and Ktor registrations name their callbacks the same way.
  for (const [lang, src, name] of [
    ["go", 'package m\nfunc routes(r *gin.Engine) { r.GET("/a", func(c *gin.Context) { target() }) }\n', "r GET /a"],
    ["php", "<?php\nRoute::get('/a', function () { target(); });\n", "Route GET /a"],
    ["kotlin", 'fun Application.m() { routing { get("/a") { target() } } }\n', "GET /a"],
  ]) {
    const r = parseSync(lang, src).root();
    let t = null;
    const walk = (n) => { if (!t && /^target\(\)$/.test(n.text()) && !n.children().some((c) => c.text() === n.text())) t = n; else for (const c of n.children()) walk(c); };
    walk(r);
    assert.equal(new Named(r, lang, "f", KEY).of(t), name, lang);
  }
});

test("identifiers are table names only in known positions; every other variable gives null", () => {
  const cases = [
    ["javascript", "const auditTable = 'patients'; db[auditTable].insert(1);", "$DB[$T].insert($$$R)", [null]],
    ["javascript", "knex.insert({ table: auditTable });", "knex.insert({ table: $T })", [null]],
    ["python", "sb.query(table=audit_table)\n", "sb.query(table=$T)", [null]],
    ["typescript", "db.from(TABLE); db.from(PatientTable); db.from(Tables.PATIENTS);", "db.from($T)", [null, null, null]],
    ["typescript", "prisma.patient.findMany(); prisma.$T2.x();", "prisma.$T.findMany()", ["patient"]],
    ["python", "Patient.objects.filter(1)\npatient.objects.filter(1)\n", "$T.objects.filter($$$A)", ["Patient", null]],
    ["python", "session.query(Patient)\nselect(Patient)\nrun(Patient)\nsession.query(x, Patient)\n", "$F($T)", ["Patient", "Patient", null]],
    ["python", "session.query(Patient)\nselect(Patient)\n", "select($T)", ["Patient"]],
    ["typescript", "dataSource.getRepository(Patient); repo<Patient>(); const r: Repository<Visit> = x;", "dataSource.getRepository($T)", ["Patient"]],
    ["typescript", "const r: Repository<Visit> = x; const q: Repository<visit> = y;", { context: "let r: Repository<$T>", selector: "generic_type" }, ["Visit", "visit"]],
    ["ruby", "Patient.where(x: 1)\npatient.where(x: 1)\n", "$T.where($$$A)", ["Patient", null]],
  ];
  for (const [lang, src, pattern, expected] of cases) {
    const root = parseSync(lang, src).root();
    assert.deepEqual(root.findAll({ rule: { pattern } }).map(tableOfFor(lang)), expected, `${lang} ${src}`);
  }
});

test("a metavariable inside a string literal captures it; loader binding is token-aware", async () => {
  const dir = ruleSet("typescript-generic.yml", [{ ...GOOD, rule: { pattern: 'db.from("$T").select($$$A)' }, table: { metavariable: "$T", access: "read" } }]);
  const rules = loadRules(dir, { strict: true });
  const res = await runRules(rules, [{ path: "a.ts", text: 'function f() { db.from("patients").select(); db.from(`p${x}`).select(); }\n' }], { key: KEY, frameworks: [] });
  assert.deepEqual(res.matches.map((m) => m.table), ["patients"]); // an interpolated string doesn't match a plain string pattern
  const f = "access-audit-log/typescript-generic.yml";
  for (const pattern of ["db.from(foo$T).select($$$A)", "db.from($Tx).select($$$A)", "db.from(x /* $T */).select($$$A)"]) {
    const problems = refusal(ruleSet("typescript-generic.yml", [{ ...GOOD, rule: { pattern }, table: { metavariable: "$T", access: "read" } }]));
    assert.ok(problems.some((p) => p.startsWith(`${f}: table.metavariable: $T is not bound`)), `${pattern}\n${problems.join("\n")}`);
  }
});

test("string literals are unescaped per language before normalising; quoted identifiers per Postgres", () => {
  const cases = [
    ["javascript", "db.from('pat\\x69ents'); db.from(\"pat\\u0069ents\"); db.from(`Pat\\u{69}ents`);", "db.from($T)", ["patients", "patients", "Patients"]],
    ["python", "sb.table('pat\\x69ents')\nsb.table(r'pat\\x69ents')\nsb.table('pat' \"ients\")\n", "sb.table($T)", ["patients", hashed(KEY, "pat\\x69ents"), "patients"]],
    ["ruby", "db.from('pat\\x69ents')\ndb.from(\"pat\\x69ents\")\n", "db.from($T)", [hashed(KEY, "pat\\x69ents"), "patients"]],
    ["go", "package m\nfunc F() { db.Table(\"pat\\x69ents\"); db.Table(`pat\\x69ents`) }\n", { context: "func t() { $D.Table($T) }", selector: "call_expression" }, ["patients", hashed(KEY, "pat\\x69ents")]],
    ["java", "class A { void m() { j.table(\"pat\\u0069ents\"); } }", "j.table($T)", ["patients"]],
    ["javascript", "db.from('\"a\"\"b\".\"T\"'); db.from('\"Odd\"');", "db.from($T)", [`${hashed(KEY, 'a"b')}.T`, "Odd"]],
  ];
  for (const [lang, src, pattern, expected] of cases) {
    const root = parseSync(lang, src).root();
    assert.deepEqual(root.findAll({ rule: { pattern } }).map(tableOfFor(lang)), expected, `${lang} ${src}`);
  }
  const php = parseSync("php", "<?php\nDB::table('pat\\x69ents'); DB::table(\"pat\\x69ents\");\n").root();
  assert.deepEqual(php.findAll({ rule: { pattern: { context: "<?php DB::table($T);", selector: "scoped_call_expression" } } }).map(tableOfFor("php")), [hashed(KEY, "pat\\x69ents"), "patients"]);
});

test("the handler id is the HMAC of JSON [path, name, line, column], so no two inputs can collide", () => {
  assert.equal(handlerId(KEY, "app/r.ts", "GET", 3, 13), createHmac("sha256", KEY).update('["app/r.ts","GET",3,13]', "utf8").digest("hex"));
  assert.notEqual(handlerId(KEY, "a", "b\nc", 1, 0), handlerId(KEY, "a\nb", "c", 1, 0));
});

test("C# has its function kinds listed; with no parser here its handler is null, never an error", () => {
  assert.deepEqual([...FUNCTION_KINDS.csharp].sort(), ["anonymous_method_expression", "constructor_declaration", "lambda_expression", "local_function_statement", "method_declaration"]);
  const yml = parseSync("yaml", "a: 1\n").root();
  assert.equal(new Handlers(yml, "csharp", "a.cs", KEY).of(yml), null);
});

// --- Loader, round 2: no merges, no inheritance into registrations -----------------------------------------

/* Every handler of a file, by marker call: [marker, id] for each `tN()` call. */
function markers(lang, src, handlers = Handlers) {
  const root = parseSync(lang, src).root();
  const h = new handlers(root, lang, "f", KEY);
  const out = [];
  const walk = (n) => {
    const m = /^(t\d+)\(\)$/.exec(n.text());
    if (m && !n.children().some((c) => c.text() === n.text())) out.push([m[1], h.of(n)]);
    else for (const c of n.children()) walk(c);
  };
  walk(root);
  return Object.fromEntries(out);
}

test("A3R2-1: two functions never share an id: same-named methods, routes and handlers stay apart", () => {
  const cases = [
    ["typescript", "export class A { @Get() sync() { t1() } }\nexport class B { @Put() sync() { t2() } }"],
    ["javascript", "const a = { handler: function () { t1() } };\nconst b = { handler: function () { t2() } };"],
    ["javascript", "adminRouter.get('/records', (q, s) => { t1() });\nv1.get('/records', (q, s) => { t2() });"],
    ["javascript", "app.get('/records', (q, s) => { t1() });\napp.get('/records', (q, s) => { t2() });"],
    ["go", "package m\nfunc (s *S) get() { t1() }\nfunc (s *T) get() { t2() }\n"],
    ["python", "class A:\n  def get(self):\n    t1()\nclass B:\n  def get(self):\n    t2()\n"],
    ["ruby", "class A\n  def show\n    t1()\n  end\nend\nclass B\n  def show\n    t2()\n  end\nend\n"],
  ];
  for (const [lang, src] of cases) {
    const m = markers(lang, src);
    assert.ok(m.t1 && m.t2 && m.t1 !== m.t2, `${lang}: ${src}\n${JSON.stringify(m)}`);
  }
  // Names stay readable for the HMAC input only: the receiver is part of a route's name.
  assert.deepEqual(markers("javascript", "adminRouter.get('/records', (q, s) => { t1() });\nv1.get('/records', (q, s) => { t2() });", Named),
    { t1: "adminRouter GET /records", t2: "v1 GET /records" });
  // The match and the item carry one id end to end, and the id is the HMAC of path, name and the function's start.
  const text = "export class A { @Get() sync() { t1() } }\n";
  const root = parseSync("typescript", text).root();
  const fn = root.find({ rule: { kind: "method_definition" } }).range().start;
  assert.equal(markers("typescript", text).t1, handlerId(KEY, "f", "sync", fn.line + 1, fn.column));
});

test("A3R2-2: callbacks of unrecognised registrations get null; only allowlisted callbacks inherit; by-reference items resolve", async () => {
  const N = (lang, src) => markers(lang, src, Named);
  // Registration-shaped calls the route table doesn't recognise: null, never the enclosing setup function.
  assert.deepEqual(N("javascript", "function routes(app) {\n  app.use('/import', async (req, res) => { t1() });\n  t2();\n}"), { t1: null, t2: "routes" });
  assert.deepEqual(N("go", 'package m\nfunc Register(r *gin.Engine) {\n  r.Handle("PUT", "/p", func(c *gin.Context) { t1() })\n  http.HandleFunc("/a", func(w W, r *R) { t2() })\n}\n'), { t1: null, t2: null });
  assert.deepEqual(N("typescript", "function m(app) { app.on('GET', '/p', (c) => { t1() }); }"), { t1: null });
  assert.deepEqual(N("python", "def setup(app):\n  app.add_url_rule('/p', view_func=lambda: t1())\n  app.add_url_rule('/q', 'q', lambda: t2())\n"), { t1: null, t2: null });
  // Allowlisted non-route callbacks inherit; anything else gives null.
  assert.deepEqual(N("javascript", "function GET() {\n  rows.map((r) => t1());\n  p.then(() => t2());\n  setTimeout(() => t3(), 1);\n  db.transaction(async () => { t4() });\n  db.get('SELECT 1', (err, row) => { t5() });\n}"),
    { t1: "GET", t2: "GET", t3: "GET", t4: null, t5: null });
  // By reference: the referenced function's own id when it is declared once in this file; otherwise null.
  const src = "function routes(r) {\n  r.get('/p', mw, listPatients);\n  r.get('/q', missing);\n}\nfunction listPatients(q, s) { t1() }\n";
  const root = parseSync("javascript", src).root();
  const h = new Named(root, "javascript", "f", KEY);
  const calls = root.findAll({ rule: { kind: "call_expression", regex: "^r\\.get" } });
  assert.deepEqual(calls.map((c) => h.of(c)), ["listPatients", null]);
  assert.equal(N("javascript", src).t1, "listPatients");
  const dup = "app.get('/p', show);\nfunction show() { t1() }\nfunction other() { function show() {} }\n";
  const dr = parseSync("javascript", dup).root();
  assert.equal(new Named(dr, "javascript", "f", KEY).of(dr.find({ rule: { kind: "call_expression", regex: "^app" } })), null); // two `show`s: uncertain
  // End to end: a controlled gin item and an unaudited Handle closure's write never share an id or a link.
  const goRule = (name, kind, rule, extra = {}) => ({ id: `access-audit-log.go-gin.${name}`, practice_id: "access-audit-log",
    language: "go", frameworks: ["gin"], kind, rule, min_engine: "0.45.0", ...extra });
  const rules = [
    goRule("read-handler", "items", { kind: "call_expression", regex: "^r\\.(GET|Handle)\\(" }, { control: { has: { pattern: "audit.Middleware()", stopBy: "end" } } }),
    goRule("write", "evidence", { pattern: { context: "func t() { $DB.Table($T).Save($$$A) }", selector: "call_expression" } }, { table: { metavariable: "$T", access: "write" } }),
  ];
  const go = 'package api\nfunc Register(r *gin.Engine, db *gorm.DB) {\n\tr.GET("/patients", audit.Middleware(), listPatients)\n\tr.Handle("PUT", "/patients/:id", func(c *gin.Context) {\n\t\tdb.Table("patients").Save(&p)\n\t})\n}\n';
  const res = await runRules(rules, [{ path: "routes.go", text: go }], { key: KEY, frameworks: ["gin"] });
  assert.deepEqual(res.matches.map((m) => [m.kind, m.line_start, m.has_control, m.handler, m.table]), [
    ["item", 3, true, null, null], ["item", 4, false, null, null], ["evidence", 5, null, null, "patients"],
  ]);
  assert.deepEqual(res.links, []);
});

test("A3R2-3: the route heuristic: paths start with /, the handler is the last non-error function, fastify route options", () => {
  const N = (lang, src) => markers(lang, src, Named);
  assert.deepEqual(N("php", "<?php\nRoute::get('users', function () { t1(); });\n$db->get('x', function () { t2(); });\n"), { t1: "Route GET users", t2: null });
  assert.deepEqual(N("javascript", "app.get('/a', async (req, res) => { t1() }, (err, req, res, next) => { t2() });\napp.get('/b', async (req, res) => { t3() }, withOpts(() => t4()));"),
    { t1: "app GET /a", t2: null, t3: "app GET /b", t4: null });
  assert.deepEqual(N("javascript", "app.route('/c').get((q, s) => { t1() }).post((q, s) => { t2() });"), { t1: "app GET /c", t2: "app POST /c" });
  const fastify = "fastify.route({ method: 'GET', url: '/p', handler: async (req) => { t1() } });\nfastify.route({ method: 'GET', url: '/r', async handler(req) { t2() } });\n";
  const root = parseSync("javascript", fastify).root();
  const h = new Handlers(root, "javascript", "f", KEY);
  const m = markers("javascript", fastify);
  assert.deepEqual(root.findAll({ rule: { kind: "call_expression", regex: "^fastify" } }).map((c) => h.of(c)), [m.t1, m.t2]);
  assert.ok(m.t1 && m.t2 && m.t1 !== m.t2);
});

test("A3R2-4: TS wrappers around exported consts, and deep nesting is computed, never capped to null", () => {
  const N = (lang, src) => markers(lang, src, Named);
  assert.deepEqual(N("typescript", "export const GET = (async (req) => { t1() }) satisfies H;\nexport const PUT = <H>(async () => { t2() });\nexport const DELETE = (async () => { t3() }) as H;"),
    { t1: "GET", t2: "PUT", t3: "DELETE" });
  const deep = "function GET() {" + "rows.map(() => {".repeat(80) + "t1()" + "})".repeat(80) + "; }";
  assert.deepEqual(N("javascript", deep), { t1: "GET" });
});

test("A3R2-5: tables: local PascalCase variables, Java text blocks, Python \\N and bytes, Ruby single-quote symbols", () => {
  const T = (lang, src, pattern) => parseSync(lang, src).root().findAll({ rule: { pattern } }).map(tableOfFor(lang));
  assert.deepEqual(T("javascript", "const Tmp = getRows(); Tmp.insert(x); Patient.insert(y);", "$T.insert($$$A)"), [null, "Patient"]);
  assert.deepEqual(T("python", "Archive = make()\nArchive.objects.create()\nPatient.objects.create()\n", "$T.objects.create($$$A)"), [null, "Patient"]);
  assert.deepEqual(T("java", 'class A { void f(){ db.table("""\n      patients\n      """); db.table("""\n   public.visits"""); } }', "db.table($T)"),
    [hashed(KEY, "patients\n"), "public.visits"]);
  assert.deepEqual(T("python", 'db.table("pat\\N{LATIN SMALL LETTER I}ents")\ndb.table("pat\\N{GREEK SMALL LETTER ALPHA}")\ndb.table(b"patients")\n', "db.table($T)"), ["patients", null, null]);
  assert.deepEqual(T("ruby", "x(:'pat\\x69')\nx(%s(pat\\x69))\nx(:\"pat\\x69ents\")\n", "x($T)"), [hashed(KEY, "pat\\x69"), hashed(KEY, "pat\\x69"), "patients"]);
  // A quoted part is sent like an unquoted one: without its quotes, as written when it fits pg_name, else hashed. A
  // part mixing quoted and unquoted text hashes the whole text as one name.
  assert.deepEqual(T("javascript", `db.from('"Public".patients'); db.from('Public.patients'); db.from('"Pat ients"'); db.from('"a"b.c');`, "db.from($T)"),
    ["Public.patients", "Public.patients", hashed(KEY, "Pat ients"), hashed(KEY, '"a"b.c')]);
});

test("handler identity: an Express path array is a route; handle/handler are registrations only with a path (p1-cov)", () => {
  const targetsOf = (lang, src, re = /^target\(\)$/) => {
    const root = parseSync(lang, src).root();
    const out = [];
    const walk = (n) => {
      if (re.test(n.text()) && !n.children().some((c) => c.text() === n.text())) out.push(n);
      else for (const c of n.children()) walk(c);
    };
    walk(root);
    const h = new Named(root, lang, "src/f.ts", KEY);
    return out.map((t) => h.of(t));
  };
  // 1. router.get(["/a", "/b"], fn): named by its first path, like a single path.
  assert.deepEqual(targetsOf("typescript", 'router.get(["/a", "/b"], (req, res) => { target(); });\n'), ["router GET /a"]);
  assert.deepEqual(targetsOf("javascript", "app.post(['/x/:id', '/y'], function (req, res) { target(); });\n"), ["app POST /x/:id"]);
  // An array with no path, or anything but literals, is no path.
  assert.deepEqual(targetsOf("typescript", "router.get([prefix, '/b'], (req, res) => { target(); });\n"), [null]);
  // 2. Next's `return handler(req, ctx)` inside the exported route is a call, not a registration: the route keeps its identity.
  assert.deepEqual(targetsOf("typescript", "export async function GET(req, ctx) {\n  return handler(req, ctx);\n}\n", /^handler\(req, ctx\)$/), ["GET"]);
  assert.deepEqual(targetsOf("typescript", "export async function POST(request) {\n  return handle(request, {});\n}\n", /^handle\(request, \{\}\)$/), ["POST"]);
  assert.deepEqual(targetsOf("typescript", "export async function POST(request) {\n  target();\n  return handle(request, {});\n}\n"), ["POST"]);
  // handle with a path is still a registration (its own route name stays unnamed: a registration, not a verb).
  assert.deepEqual(targetsOf("javascript", "mux.handle('/x', function (w, r) { target(); });\n"), [null]);
});

test("handle with a method then a path (gin) stays a registration (p1-cov)", () => {
  // The closure is a registered handler (never the enclosing function's), as A3R2-2 checks end to end.
  const go = 'package api\nfunc Register(r *gin.Engine) {\n\tr.Handle("PUT", "/p", func(c *gin.Context) {\n\t\ttarget()\n\t})\n}\n';
  const root = parseSync("go", go).root();
  const h = new Named(root, "go", "routes.go", KEY);
  assert.deepEqual(root.findAll({ rule: { pattern: "target()" } }).map((t) => h.of(t)), [null]);
});

// --- The prefilter, the worker pool and the overall time budget --------------------------------------------

test("the prefilter only skips rules that can't match: words of patterns, literal runs of regexes", async () => {
  const { requirement, satisfied, FileText } = await import("../lib/inspector/prefilter.mjs");
  const can = (rule, lang, text) => satisfied(requirement(rule, lang), new FileText(text));
  // Pattern words: a file without `console` can't hold console.log($X); a metavariable gives no word.
  assert.equal(can({ pattern: "console.log($X)" }, "javascript", "print(x)"), false);
  assert.equal(can({ pattern: "console.log($X)" }, "javascript", "console . log ( a )"), true);
  assert.equal(can({ pattern: { context: "<?php $A == $B;", selector: "binary_expression" } }, "php", "<?php $x == $y;"), true);
  // Regex literal runs, case-insensitive under (?i) (with the long s and the Kelvin sign folded), any as or, not free.
  assert.equal(can({ kind: "identifier", regex: "^(audit|accessLog)$" }, "javascript", "const a = 1"), false);
  assert.equal(can({ kind: "identifier", regex: "^(audit|accessLog)$" }, "javascript", "accessLog()"), true);
  assert.equal(can({ kind: "identifier", regex: "(?i)^PASSWORD$" }, "javascript", "let password"), true);
  assert.equal(can({ kind: "identifier", regex: "(?i)ask" }, "javascript", "aſK"), true);
  assert.equal(can({ kind: "identifier", regex: "ab?c" }, "javascript", "ac"), true); // an optional b ends the run
  assert.equal(can({ kind: "call_expression", not: { has: { regex: "zzz" } } }, "javascript", "f()"), true);
  assert.equal(can({ any: [{ pattern: "foo()" }, { kind: "identifier" }] }, "javascript", "bar"), true);
  // Every rule of the test bundle matches its own fixture whenever findAll finds something (soundness on real rules).
  for (const r of loadRules(RULES)) {
    const ext = { javascript: "js", typescript: "ts", tsx: "tsx" }[r.language];
    if (!ext) continue;
    for (const text of [ROUTE, CLIENT]) {
      const found = parseSync(r.language, text).root().findAll({ rule: r.rule }).length;
      if (found) assert.ok(can(r.rule, r.language, text), `${r.id} skipped on a file it matches`);
    }
  }
});

test("a pool of workers gives the same result as one; past the deadline files are time_limit, truncated timeout", async () => {
  const rules = loadRules(RULES);
  const files = [];
  for (let i = 0; i < 12; i++) files.push({ path: `src/c${i}.js`, text: CLIENT }, { path: `app/api/v${i}/route.ts`, text: ROUTE });
  const one = await runRules(rules, files, { key: KEY, frameworks: ["nextjs"] });
  const four = await runRules(rules, files, { key: KEY, frameworks: ["nextjs"], workers: 4 });
  assert.deepEqual(four, one);
  assert.equal(liveWorkers(), 0);
  const late = await runRules(rules, files, { key: KEY, frameworks: ["nextjs"], workers: 2, deadline: Date.now() - 1 });
  assert.equal(late.status, "truncated");
  assert.equal(late.reason, "timeout");
  assert.equal(late.analyzed, 0);
  assert.deepEqual(late.notAnalyzed, files.map(({ path }) => ({ path, reason: "time_limit" })));
});

test("a secret-shaped, high-entropy or email-shaped captured table name is hashed, never sent as written", async () => {
  const rules = loadRules(ruleSet("typescript-generic.yml", [TABLE_RULE]), { strict: true });
  const values = {
    stripe: "sk\x5flive_CANARYstablek3j9x0a1abcdefgh",
    aws: "AKIAIOSFODNN7EXAMPLE",
    jwt: "e\x79JhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJl",
    entropy: "a8f3K29dLq0xZ7mP4vN1",
    email: "jane.doe@example.com",
    qualified: "public.sk\x5flive_51HabcdefghijklmnopqrstuvWX",
    uuid: "a23e4567-e89b-12d3-a456-426614174000",
    letters: "qXvTbWzKpLmRnHjGfDsCxVbQ",
  };
  const text = `export async function save(req) {\n${Object.values(values).map((v) => `  await db.from("${v}").insert(1);`).join("\n")}\n  await db.from("patients").insert(1);\n}\n`;
  const res = await runRules(rules, [{ path: "src/save.ts", text }], { key: KEY, frameworks: [] });
  assert.ok(validateMatches(res.matches), JSON.stringify(validateMatches.errors));
  const tables = res.matches.map((m) => m.table);
  assert.deepEqual(tables.slice(0, 5), [values.stripe, values.aws, values.jwt, values.entropy, values.email].map((v) => hashed(KEY, v)));
  assert.equal(tables[5], hashed(KEY, values.qualified)); // a text holding a secret is hashed whole
  assert.deepEqual(tables.slice(6, 8), [hashed(KEY, values.uuid), hashed(KEY, values.letters)]);
  assert.equal(tables[8], "patients"); // an ordinary name is still sent as written
  const sent = JSON.stringify(res);
  for (const v of Object.values(values)) assert.ok(!sent.includes(v.split(".").pop()), v);
  assert.ok(!sent.includes("jane.doe") && !sent.includes("example.com"));
  // Long names made of words, in any case style, are names, not tokens.
  const { tableName } = await import("../lib/inspector/captures.mjs");
  for (const n of ["FacilitySubscriptionPayment", "patientmedicationadministrations", "PatientMedicationAdministrationRecord", "clinical_notes_procedure_results"]) {
    assert.equal(tableName(KEY, n), n);
  }
});

test("Rust's \\< and \\> are zero-width; a pattern word glued to an escape still runs", async () => {
  const { requirement, satisfied, FileText } = await import("../lib/inspector/prefilter.mjs");
  const cases = [
    [{ kind: "identifier", regex: "\\<password\\>" }, "const password = 1;"],
    [{ pattern: '"\\nusers"' }, 'const q = "\\nusers";'],
    [{ kind: "identifier", regex: "pass\\kword" }, "const password = 1;"], // an unknown escape requires nothing
  ];
  for (const [rule, text] of cases.slice(0, 2)) {
    const found = parseSync("javascript", text).root().findAll({ rule }).length;
    assert.ok(found > 0, `ast-grep matches ${JSON.stringify(rule)}`);
    assert.ok(satisfied(requirement(rule, "javascript"), new FileText(text)), `the prefilter runs ${JSON.stringify(rule)}`);
  }
  assert.equal(requirement(cases[2][0], "javascript"), true);
});

/* The evaluator's rule bundle fixtures (its app/knowledge/rules), found through CUSTOSA_HOSTED_RULES or
 * next to this checkout; skipped when absent. */
const HOSTED = process.env.CUSTOSA_HOSTED_RULES ?? "";
test("CUSTOSA_NO_PREFILTER=1: the shipped rules give identical matches on every hosted fixture, prefilter on or off", { skip: coreSkip(existsSync(HOSTED), "no hosted rule bundle next to this checkout (set CUSTOSA_HOSTED_RULES)"), timeout: 600_000 }, async () => {
  requireCore("CUSTOSA_HOSTED_RULES", existsSync(HOSTED));
  const { readdirSync, statSync } = await import("node:fs");
  const rules = loadRules();
  const files = [];
  for (const dir of readdirSync(HOSTED)) {
    if (!statSync(join(HOSTED, dir)).isDirectory()) continue;
    for (const f of readdirSync(join(HOSTED, dir))) {
      const m = /^([a-z]+)-[a-z_]+\.fixtures\.[a-z]+$/.exec(f);
      if (m && rules.some((r) => r.language === m[1])) files.push({ path: `${dir}/${f}`, lang: m[1], text: readFileSync(join(HOSTED, dir, f), "utf8") });
    }
  }
  assert.ok(files.length > 100, `${files.length} fixtures`);
  const all = ["express", "nextjs", "nestjs", "fastify", "hono", "koa", "remix", "sveltekit", "nuxt", "django", "flask", "fastapi", "rails",
    "laravel", "spring", "gin", "echo", "aspnetcore", "prisma", "drizzle", "typeorm", "sequelize", "sqlalchemy", "alembic", "knex",
    "supabase", "firebase", "expo", "react_native", "terraform", "github_actions"];
  const opts = { key: KEY, frameworks: all, workers: 4, timeoutMs: 60_000 };
  const on = await runRules(rules, files, opts);
  const saved = process.env.CUSTOSA_NO_PREFILTER;
  process.env.CUSTOSA_NO_PREFILTER = "1";
  let off;
  try { off = await runRules(rules, files, opts); } finally {
    if (saved === undefined) delete process.env.CUSTOSA_NO_PREFILTER; else process.env.CUSTOSA_NO_PREFILTER = saved;
  }
  assert.ok(on.matches.length > 500, `${on.matches.length} matches`);
  assert.deepEqual(on.matches, off.matches);
  assert.deepEqual(on.notAnalyzed, off.notAnalyzed);
  assert.equal(on.analyzed, off.analyzed);
});

test("loadRulesInThread parses the same rules as loadRules, frozen; an invalid set gives null", async () => {
  const here = loadRules(RULES);
  const dir = temp("rules-thread-");
  cpSync(RULES, join(dir, "rules"), { recursive: true });
  const manifest = JSON.stringify({ ruleset_id: "2026-01-01.deadbeef" });
  writeFileSync(join(dir, "manifest.json"), manifest);
  const there = await loadRulesInThread(dir, manifest).result;
  assert.deepEqual(there, here);
  assert.ok(there.every((r) => Object.isFrozen(r)));
  mkdirSync(join(dir, "rules", "not_a_practice!"));
  assert.equal(await loadRulesInThread(dir, manifest).result, null);
  assert.equal(await loadRulesInThread(dir, "{}").result, "stale", "the manifest it was keyed on is no longer there");
});

test("loadRulesInThread and bundleMatches take a file URL as loadRules does, under a folder with a space and non-ASCII", async () => {
  const here = loadRules(RULES);
  const dir = join(temp("rules-thread-url-"), "custosa rules é");
  cpSync(RULES, join(dir, "rules"), { recursive: true });
  const manifest = JSON.stringify({ ruleset_id: "2026-01-01.deadbeef" });
  writeFileSync(join(dir, "manifest.json"), manifest);
  const url = pathToFileURL(`${dir}/`);
  assert.equal(bundleMatches(url, manifest), bundleMatches(dir, manifest));
  assert.equal(bundleMatches(url, manifest), true);
  assert.deepEqual(await loadRulesInThread(url, manifest).result, here);
  assert.equal(await loadRulesInThread(url, "{}").result, "stale");
});

test("WarmPool: a second run reuses the started workers and gives the same result; a cancelled run leaves it usable", async () => {
  const rules = loadRules(RULES);
  const root = temp("warm-");
  const files = [];
  for (let i = 0; i < 12; i++) {
    writeFileSync(join(root, `f${i}.ts`), `export async function f${i}(p) { console.log(p.ssn); await db.from("patients").insert(p); }\n`);
    files.push({ path: `f${i}.ts` });
  }
  const opts = { key: KEY, frameworks: [], root, workers: 2 };
  const cold = await runRules(rules, files, opts);
  assert.equal(liveWorkers(), 0);
  const warm = new WarmPool();
  try {
    const first = await runRules(rules, files, { ...opts, warm });
    assert.deepEqual(first, cold);
    assert.equal(warm.started, 2);
    assert.equal(warm.warmThreads, 2, "the idle workers keep their threads");
    const second = await runRules(rules, files, { ...opts, warm });
    assert.deepEqual(second, cold);
    assert.equal(warm.started, 2, "no new worker for the second run");
    // A cancel kills the running workers; the pool stays usable and the next run is complete.
    const c = new AbortController();
    const cut = await runRules(rules, files, { ...opts, warm, signal: c.signal, onFile: (done) => { if (done === 2) c.abort(); } });
    assert.ok(cut.notAnalyzed.some((e) => e.reason === "time_limit"));
    const after = await runRules(rules, files, { ...opts, warm });
    assert.deepEqual(after, cold);
    assert.ok(warm.idle.length <= 4 && warm.idle.every((w) => !w.poisoned));
    // Other rules (a synced bundle) drop the idle workers and start fresh ones.
    const other = rules.map((r) => ({ ...r }));
    await runRules(other, files, { ...opts, warm });
    assert.equal(warm.rules, other);
  } finally { await warm.drop(); }
  assert.equal(liveWorkers(), 0, "drop() stops every idle worker");
});

test("a run with no time left to start a worker lists its files time_limit (setupTimedOut), never failed", async () => {
  const rules = loadRules(RULES);
  const root = temp("setup-");
  writeFileSync(join(root, "a.ts"), "export const a = 1;\n");
  writeFileSync(join(root, "b.ts"), "export const b = 1;\n");
  // The hard deadline minus the 4 s reserve is already past: no worker may start.
  const res = await runRules(rules, [{ path: "a.ts" }, { path: "b.ts" }], { key: KEY, frameworks: [], root, workers: 2, hardDeadline: Date.now() + 3_000 });
  assert.deepEqual([res.status, res.reason, res.setupTimedOut], ["truncated", "timeout", true]);
  assert.deepEqual(res.notAnalyzed.map((e) => e.reason), ["time_limit", "time_limit"]);
  assert.equal(liveWorkers(), 0);
});

test("WarmPool: two calls with different install keys at once never hand a worker to the other key", async () => {
  const rules = loadRules(); // the shipped rules: these files match them
  const root = temp("warm-keys-");
  const files = [];
  for (let i = 0; i < 6; i++) {
    writeFileSync(join(root, `f${i}.ts`), `export async function f${i}(p) { console.log(p.ssn); await db.from("patients").insert(p); }\n`);
    files.push({ path: `f${i}.ts` });
  }
  const K1 = Buffer.alloc(32, 1), K2 = Buffer.alloc(32, 2);
  const opts = { frameworks: ["supabase", "nextjs"], root, workers: 1 };
  const ref1 = await runRules(rules, files, { ...opts, key: K1 });
  const ref2 = await runRules(rules, files, { ...opts, key: K2 });
  assert.notDeepEqual(ref1.matches, ref2.matches, "fingerprints depend on the key");
  const warm = new WarmPool();
  try {
    // A (K1) checks out first, B (K2) switches the pool to K2 while A runs, then A checks its workers back in.
    const a = runRules(rules, files, { ...opts, key: K1, warm });
    await new Promise((ok) => setTimeout(ok, 5));
    const b = runRules(rules, files, { ...opts, key: K2, warm });
    assert.deepEqual(await a, ref1);
    assert.deepEqual(await b, ref2);
    assert.ok(warm.idle.every((w) => w.keyId === Buffer.from(K2).toString("hex")), "only K2 workers are kept");
    assert.deepEqual(await runRules(rules, files, { ...opts, key: K2, workers: 2, warm }), ref2);
  } finally { await warm.drop(); }
  assert.equal(liveWorkers(), 0);
});

test("bundleMatches: the rule files must be the manifest's (sha256 list) and the manifest unchanged", () => {
  const dir = temp("bundle-match-");
  mkdirSync(join(dir, "rules", "p"), { recursive: true });
  writeFileSync(join(dir, "rules", "p", "typescript-generic.yml"), "x: 1\n");
  const manifest = (h) => JSON.stringify({ ruleset_id: "2026-01-01.deadbeef", files: [{ path: "rules/p/typescript-generic.yml", sha256: h }] });
  const h = createHash("sha256").update("x: 1\n").digest("hex");
  writeFileSync(join(dir, "manifest.json"), manifest(h));
  assert.equal(bundleMatches(dir, manifest(h)), true);
  assert.equal(bundleMatches(dir, manifest("0".repeat(64))), false, "the manifest changed since the load was keyed");
  writeFileSync(join(dir, "rules", "p", "typescript-generic.yml"), "x: 2\n");
  assert.equal(bundleMatches(dir, manifest(h)), false, "a rule file changed");
  writeFileSync(join(dir, "rules", "p", "typescript-generic.yml"), "x: 1\n");
  writeFileSync(join(dir, "rules", "p", "python-generic.yml"), "y: 1\n");
  assert.equal(bundleMatches(dir, manifest(h)), false, "a rule file the manifest doesn't list");
});

test("bundleMatches checks only what the loader reads: fixtures, README.md and NAMING.md may sit beside the rules unlisted", () => {
  const dir = temp("bundle-extras-");
  mkdirSync(join(dir, "rules", "p"), { recursive: true });
  writeFileSync(join(dir, "rules", "p", "typescript-generic.yml"), "x: 1\n");
  const h = createHash("sha256").update("x: 1\n").digest("hex");
  const manifest = JSON.stringify({ ruleset_id: "2026-01-01.deadbeef", files: [{ path: "rules/p/typescript-generic.yml", sha256: h }] });
  writeFileSync(join(dir, "manifest.json"), manifest);
  writeFileSync(join(dir, "rules", "p", "typescript-generic.fixtures.ts"), "// ruleid: x\n");
  writeFileSync(join(dir, "rules", "README.md"), "# rules\n");
  writeFileSync(join(dir, "rules", "NAMING.md"), "# naming\n");
  writeFileSync(join(dir, "rules", "p", "README.md"), "# p\n");
  assert.equal(bundleMatches(dir, manifest), true);
  writeFileSync(join(dir, "rules", "p", "typescript-generic.yml"), "x: 2\n");
  assert.equal(bundleMatches(dir, manifest), false, "a rule file the loader reads still has to match");
  writeFileSync(join(dir, "rules", "p", "typescript-generic.yml"), "x: 1\n");
  writeFileSync(join(dir, "rules", "p", "python-generic.yml"), "y: 1\n");
  assert.equal(bundleMatches(dir, manifest), false, "a rule file the loader reads but the manifest doesn't list");
});

test("coded errors keep their class, message and code, and the stack starts where they are thrown", async () => {
  const thrownHere = (e) => {
    const top = e.stack.split("\n").find((l) => l.startsWith("    at "));
    assert.match(top, /rules\.mjs:\d+:\d+\)?$/, e.stack);
    assert.doesNotMatch(top, /at coded /, "the top frame is the throw site, not a helper");
  };
  // RULES_INVALID: a plain Error with the problems listed.
  const dir = ruleSet("typescript-generic.yml", [{ ...GOOD, message: "words" }]);
  try { loadRules(dir, { strict: true }); assert.fail("loaded"); } catch (e) {
    assert.equal(Object.getPrototypeOf(e), Error.prototype);
    assert.equal(e.code, "RULES_INVALID");
    assert.equal(e.message, "The rule set has 1 problem:\naccess-audit-log/typescript-generic.yml: message: unknown key (no other key is allowed: words live in the registry)");
    thrownHere(e);
  }
  // BAD_INPUT: a TypeError, passed through by runRules.
  const rules = loadRules(RULES);
  await assert.rejects(runRules(rules, [{ path: "/etc/passwd", text: "" }], { key: KEY, frameworks: null, workers: 1 }), (e) => {
    assert.equal(Object.getPrototypeOf(e), TypeError.prototype);
    assert.equal(e.code, "BAD_INPUT");
    assert.equal(e.message, 'runRules: "/etc/passwd" is not a root-relative path as sent (fact schema path)');
    thrownHere(e);
    return true;
  });
  // SETUP_DEADLINE and POOL_STUCK from ensure(), with terminated workers that never exit (no thread is started).
  const pending = () => new Promise(() => {});
  const stuck = (graceMs) => { const w = new MatchWorker([], KEY, graceMs); for (let i = 0; i < 3; i++) w.stopping.add(pending()); return w; };
  const cases = [
    [Object.assign(stuck(60000), { until: Date.now() + 20 }), "SETUP_DEADLINE", "out of time waiting for terminated workers"],
    [stuck(20), "POOL_STUCK", "terminated workers did not exit"],
    [Object.assign(new MatchWorker([], KEY), { until: Date.now() - 1 }), "SETUP_DEADLINE", "out of time before a worker could start"],
  ];
  for (const [w, code, message] of cases) {
    await assert.rejects(w.ensure(), (e) => {
      assert.equal(Object.getPrototypeOf(e), Error.prototype);
      assert.deepEqual([e.code, e.message], [code, message]);
      thrownHere(e);
      return true;
    });
    assert.equal(w.worker, null, "no thread started");
  }
});

test("a rule set with no fixture file at all says so once, and still fails; one missing fixture still fails per rule", async () => {
  // The shipped bundle carries no fixtures: one clear error, not a "a fixture file: none" failure for every rule.
  await assert.rejects(runFixtures(), (e) => {
    assert.equal(e.code, "NO_FIXTURES");
    assert.match(e.message, /^no fixtures in this bundle: \d+ rule files and no \.fixtures\.\* file beside them in /);
    return true;
  });
  const bare = temp("custosa-nofix-");
  cpSync(RULES, bare, { recursive: true, filter: (src) => !/\.fixtures\.[a-z]+$/.test(src) });
  const cli = spawnSync(process.execPath, [BIN, "rules", "test", bare], { encoding: "utf8" });
  assert.equal(cli.status, 1);
  assert.match(cli.stderr, /^no fixtures in this bundle: /);
  assert.doesNotMatch(cli.stderr, /^FAIL /m);
  // One fixture missing in a set that has others: each of its rules still fails on its own line.
  const one = temp("custosa-onefix-");
  cpSync(RULES, one, { recursive: true, filter: (src) => !src.endsWith("javascript-generic.fixtures.js") });
  const { failed } = await runFixtures(one);
  assert.ok(failed.length > 0);
  for (const f of failed) assert.deepEqual([f.file, f.line, f.expected, f.got], ["ai-trace-redaction/javascript-generic.fixtures.js", null, "a fixture file", "none"]);
});

// --- path_regex (rule_bundle.md 3.4) --------------------------------------------------------------------------------

const HOOK = { ...GOOD, id: "access-audit-log.typescript-generic.hook", path_regex: "(^|/)webhooks?/" };

test("path_regex loads when anchored to a segment start; anything else is refused with the reason", () => {
  assert.equal(loadRules(ruleSet("typescript-generic.yml", [HOOK]), { strict: true })[0].path_regex, "(^|/)webhooks?/");
  assert.equal(loadRules(ruleSet("typescript-generic.yml", [{ ...HOOK, path_regex: "^app/api/webhooks?/" }]), { strict: true }).length, 1);
  const f = "access-audit-log/typescript-generic.yml";
  const cases = [
    ["webhooks/", "must start with ^ or (^|/)"], // a substring of any name, not a folder
    [".*webhooks/", "must start with ^ or (^|/)"],
    ["(^|/)(?<!x)webhooks/", "no lookaround"],
    ["(^|/)(a)\\1/", "no lookaround, backreference"],
    ["(^|/)(?i)webhooks/", "no lookaround, backreference, named group or inline flag"],
    ["(^|/)webhooks[/", "does not compile"],
    // escapes JS reads as a letter and Python as an anchor or a class, or the other way round.
    ["(^|/)webhooks/[^/]+\\.ts\\Z", "an escape JS and Python read differently"],
    ["(^|/)a\\A", "an escape JS and Python read differently"],
    ["(^|/)\\p{L}+/", "an escape JS and Python read differently"],
    ["", "must be a string of 1 to 200"],
    [["(^|/)webhooks/"], "must be a string of 1 to 200"],
    ["^" + "a".repeat(200), "must be a string of 1 to 200"],
  ];
  for (const [re, expected] of cases) {
    const problems = refusal(ruleSet("typescript-generic.yml", [{ ...HOOK, path_regex: re }]));
    assert.ok(problems.some((p) => p.startsWith(`${f}: path_regex: ${expected}`)), `${JSON.stringify(re)}\n got: ${problems.join("\n")}`);
  }
});

test("A loader that doesn't know a rule key refuses the whole rule set, never runs the rule without it", () => {
  // What a package from before path_regex does with a bundle that has it: the key is unknown there, so the set is
  // RULES_INVALID and the rules collector fails (internal_error). It never drops the key and runs the rule on every
  // file. path_scope stands in for a key this loader doesn't know.
  const dir = ruleSet("typescript-generic.yml", [GOOD, { ...GOOD, id: "access-audit-log.typescript-generic.hook", path_scope: "(^|/)webhooks?/" }]);
  for (const strict of [true, false]) {
    assert.throws(() => loadRules(dir, { strict }), (e) => e.code === "RULES_INVALID"
      && e.problems.some((p) => p.startsWith("access-audit-log/typescript-generic.yml#2: path_scope: unknown key")));
  }
});

test("A rule with path_regex runs only on files under its folders; a file it leaves with no rule is not analysed", async () => {
  const rules = loadRules(ruleSet("typescript-generic.yml", [GOOD, HOOK]), { strict: true });
  const files = ["src/webhooks/stripe.ts", "webhook/a.ts", "src/mywebhooks/a.ts", "src/webhooks.ts", "src/a.ts"]
    .map((path) => ({ path, text: "audit(1);\n" }));
  const res = await runRules(rules, files, { key: KEY, frameworks: [] });
  assert.equal(res.analyzed, files.length);
  const hooked = res.matches.filter((m) => m.rule_id === HOOK.id).map((m) => m.path).sort();
  assert.deepEqual(hooked, ["src/webhooks/stripe.ts", "webhook/a.ts"]);
  assert.equal(res.matches.filter((m) => m.rule_id === GOOD.id).length, files.length);
  // With only the path rule, a file outside its folders has no applicable rule: no_rule_for_framework, never analysed.
  const only = await runRules(rules.filter((r) => r.id === HOOK.id), files.slice(3), { key: KEY, frameworks: [] });
  assert.equal(only.analyzed, 0);
  assert.deepEqual(only.notAnalyzed.map((n) => n.reason), ["no_rule_for_framework", "no_rule_for_framework"]);
});

test("A fixture's path lines run the lines after them as a file at that path, with line numbers kept", async () => {
  const dir = ruleSet("typescript-generic.yml", [GOOD, HOOK]);
  const fx = join(dir, "access-audit-log", "typescript-generic.fixtures.ts");
  const text = [
    `// ruleid: ${GOOD.id}`, `// ok: ${HOOK.id}`, "audit(1);", // the fixture's own path: no webhooks folder
    "// path: src/webhooks/stripe.ts",
    `// ruleid: ${GOOD.id}`, `// ruleid: ${HOOK.id}`, "audit(2);",
    "// path: src/a.ts",
    `// ok: ${HOOK.id}`, `// ruleid: ${GOOD.id}`, "audit(3);", `// ok: ${GOOD.id}`, "other(4);", "",
  ].join("\n");
  writeFileSync(fx, text);
  assert.deepEqual(await runFixtures(dir), { passed: 7, failed: [] });
  assert.deepEqual(readMarkers(text, "//").map((m) => m.target), [3, 3, 7, 7, 11, 11, 13]);
  // Without the path line, the hook rule's match is missing on line 7.
  writeFileSync(fx, text.replace("// path: src/webhooks/stripe.ts", "// a comment"));
  assert.deepEqual((await runFixtures(dir)).failed.map((f) => [f.rule_id, f.line, f.got]), [[HOOK.id, 7, "none"]]);
  // A path line that isn't a root-relative path fails the fixture, and its section isn't run.
  writeFileSync(fx, text.replace("// path: src/a.ts", "// path: /abs/a.ts"));
  assert.deepEqual((await runFixtures(dir)).failed.map((f) => [f.line, f.got]), [[8, "malformed_path"], [11, "none"]]);
});

// a renamed (hashed) file the fact document builder couldn't read keeps the reason it was refused for.
// Without it the engine read <root>/<sent path>, which doesn't exist, and said unreadable for a too_large file.
test("runRules keeps the read refusal of a renamed file instead of reading the sent path", async () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "custosa-t27-refused-")));
  const files = [{ path: "aaaaaaaaaaaa/bbbbbbbbbbbb.js", local: "src/My Page.js", lang: "javascript", refused: "too_large" },
    { path: "cccccccccccc.js", local: "odd name.js", lang: "javascript", refused: "unreadable" }];
  const res = await runRules(loadRules(RULES), files, { key: KEY, frameworks: [], root });
  assert.deepEqual(res.notAnalyzed.map((n) => [n.path, n.reason]),
    [["aaaaaaaaaaaa/bbbbbbbbbbbb.js", "too_large"], ["cccccccccccc.js", "unreadable"]]);
});

// a lone CR is a line break in the worker (normalizeBreaks), so the fixture markers count it as one too.
test("fixture markers and sections count a lone CR as a line break, as the engine does", () => {
  assert.deepEqual(readMarkers("a\r// ruleid: x.y\nfoo();\n", "//").map((m) => [m.line, m.target]), [[2, 3]]);
  assert.deepEqual(fixtureSections("a\r// path: src/b.ts\nfoo();\n", "//").map((x) => [x.path, x.lines]),
    [[null, [1, 1]], ["src/b.ts", [2, 4]]]);
});

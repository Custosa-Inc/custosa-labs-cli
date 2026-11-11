/* T29-P1-C192 item 2 (P2 C198 item 2): a file that is not the app's own code (a dependency or build folder, a minified
 * or bundled name, minified text) past its time limit stays time_limit, listed as not read with its violations kept,
 * but no longer cuts the whole rules collector. On the 20 sweep repos one such file (chart.umd.min.js, bootstrap's dist
 * bundles, filament's published js) truncated the collector on 6, and core then held every code practice as
 * collection_truncated. App code past its limit still truncates. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { MatchWorker, loadRules, minified, notAppCodePath, runRules, toContractNotAnalyzed } from "../lib/inspector/rules.mjs";

const RULES = fileURLToPath(new URL("./fixtures/rules/", import.meta.url));
const KEY = Buffer.from("0123456789abcdef0123456789abcdef");
const CLIENT = `function show(record) {\n  console.log(record.patient);\n  localStorage.setItem("p", record.patient);\n}\n`;

/* The slow rule and file of inspector-rules.test.mjs's deadline test: a quadratic walk that runs seconds. The limit is
 * a quarter of the walk measured here, so the file is past it on any machine, while the parse fits inside it. */
const rules = loadRules(RULES);
const consolePhi = rules.find((r) => r.id.endsWith("console-phi"));
const slowRule = { ...consolePhi, id: "ai-trace-redaction.javascript-generic.slow", kind: "evidence",
  rule: { kind: "expression_statement", follows: { kind: "expression_statement", regex: "^zzz", stopBy: "end" } } };
const SLOW = "console.log(x.patient);\n" + "a();\n".repeat(4800) + "// zzz (lets the prefilter run the slow rule)\n";
// The same statements minified: one line, as a published bundle ships.
const SLOW_MIN = "console.log(x.patient);" + "a();".repeat(4800) + "\n// zzz\n";

async function walkMs(text) {
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

async function runWithSlow(path, text) {
  const walk = await walkMs(text);
  return runRules([consolePhi, slowRule], [{ path, text }, { path: "src/client.js", text: CLIENT }], { key: KEY, frameworks: [],
    timeoutMs: Math.max(200, Math.ceil(walk / 4)), closeGraceMs: Math.max(120000, Math.ceil(20 * walk)) });
}

for (const [label, path, text] of [
  ["a minified name", "app/static/js/chart.umd.min.js", SLOW],
  ["a tracked build folder", "wwwroot/lib/bootstrap/dist/js/bootstrap.js", SLOW],
  ["minified text under any name", "public/js/filament/support/support.js", SLOW_MIN],
  ["a Playwright spec (C196: test files too)", "tests/ui/tests/beta-e2e.spec.js", SLOW],
  ["a file under tests/", "tests/api/cron-automations.test.js", SLOW],
]) {
  test(`C192 item 2: ${label} past its limit is time_limit and keeps its violations, and the collector stays ok`, async () => {
    const res = await runWithSlow(path, text);
    assert.deepEqual(res.notAnalyzed, [{ path, reason: "time_limit" }]);
    // still listed as not read in the fact document's own words, so no coverage pass can rest on it
    assert.deepEqual(toContractNotAnalyzed(res.notAnalyzed), [{ path, reason: "time_limit" }]);
    assert.deepEqual(res.analyzedPaths, ["src/client.js"]);
    assert.ok(res.matches.some((m) => m.path === path && m.kind === "violation"), "its violation is kept");
    assert.deepEqual([res.status, res.reason], ["ok", null]);
  });
}

test("C192 item 2: the app's own file past its limit still truncates the collector", async () => {
  const res = await runWithSlow("src/slow.js", SLOW);
  assert.deepEqual(res.notAnalyzed, [{ path: "src/slow.js", reason: "time_limit" }]);
  assert.deepEqual([res.status, res.reason], ["truncated", "timeout"]);
});

test("C192 item 2: a run whose budget ends on files that aren't app code stays ok; one that ends on app code doesn't", async () => {
  const files = [
    { path: "src/app.js", text: CLIENT },
    { path: "public/vendor.min.js", text: CLIENT },
    { path: "frontend/node_modules/lib/index.js", text: CLIENT },
  ];
  // The run's budget (opts.deadline, compared with Date.now()) passes once the first file is read: a deadline whose
  // value moves to the past after onFile's first call. Files that aren't app code by path run last, so the app's own
  // file is that first one.
  let read = 0;
  const afterFirst = { valueOf: () => (read ? 0 : Number.MAX_SAFE_INTEGER) };
  const cut = await runRules(rules, files, { key: KEY, frameworks: [], workers: 1, deadline: afterFirst, onFile: () => { read++; } });
  assert.deepEqual(cut.analyzedPaths, ["src/app.js"]);
  assert.deepEqual(cut.notAnalyzed, [{ path: "public/vendor.min.js", reason: "time_limit" },
    { path: "frontend/node_modules/lib/index.js", reason: "time_limit" }]);
  assert.deepEqual([cut.status, cut.reason], ["ok", null]);
  // a budget gone before the app's own file was read still truncates
  const late = await runRules(rules, files, { key: KEY, frameworks: [], workers: 1, deadline: Date.now() - 1 });
  assert.deepEqual(late.notAnalyzed.map((n) => n.reason), ["time_limit", "time_limit", "time_limit"]);
  assert.deepEqual([late.status, late.reason], ["truncated", "timeout"]);
});

test("C192 item 2: what counts as not app code", () => {
  for (const p of ["a/chart.umd.min.js", "b/x.bundle.js", "b/x-bundle.mjs", "c/jquery.min.cjs", "vendor/a/b.ts", "web/dist/x.js",
    "frontend/node_modules/y/index.js"]) assert.ok(notAppCodePath(p), p);
  // C196: core's test forms (hosted-core app/core/file_roles.py _TEST_DIRS and _TEST_FILE), in any letter case
  for (const p of ["tests/api/a.ts", "src/__tests__/x.js", "web/e2e/login.ts", "playwright/fixtures.ts", "src/a.test.tsx",
    "src/b.spec.mjs", "app/test_views.py", "pkg/x_test.go", "app/UserTest.php", "src/Tests/A.cs", "conftest.py"]) assert.ok(notAppCodePath(p), p);
  for (const p of ["src/app/api/route.ts", "src/minify.js", "src/bundle.ts", "lib/admin.js", "dist.js", "public/js/app.js",
    "src/contest.ts", "src/testing-utils.ts", "smarthub/qa/run.mjs", "src/attestation.ts"]) {
    assert.ok(!notAppCodePath(p), p);
  }
  assert.ok(minified("a();".repeat(1000)));
  assert.ok(!minified("a();\n".repeat(1000)));
  // an app file with one long line (an inline image) among ordinary code
  assert.ok(!minified("const x = 1;\n".repeat(200) + `const img = "data:image/png;base64,${"A".repeat(40000)}";\n`));
  assert.ok(!minified("x".repeat(1500)), "too short to say");
});

test("C192 item 2: a stopped thread of a file that isn't app code, still exiting at the end, doesn't truncate the run", async () => {
  // dholbach's chart.umd.min.js on the sweep: past its limit, its thread stayed in the native walk past the end-of-run
  // wait (factdoc's endGraceMs), and the run came back truncated, timeout, though every file was decided.
  const walk = await walkMs(SLOW);
  const opts = { key: KEY, frameworks: [], timeoutMs: Math.max(200, Math.ceil(walk / 4)), endGraceMs: 1 };
  const vendor = await runRules([consolePhi, slowRule], [{ path: "public/js/chart.umd.min.js", text: SLOW }, { path: "src/client.js", text: CLIENT }], opts);
  assert.deepEqual([vendor.status, vendor.reason], ["ok", null]);
  assert.deepEqual(vendor.notAnalyzed, [{ path: "public/js/chart.umd.min.js", reason: "time_limit" }]);
  const app = await runRules([consolePhi, slowRule], [{ path: "src/slow.js", text: SLOW }, { path: "src/client.js", text: CLIENT }], opts);
  assert.deepEqual([app.status, app.reason], ["truncated", "timeout"]);
});

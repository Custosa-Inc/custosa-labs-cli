/* custosa inspect --document <dir> (the corpus scorer's builder): the validated fact document for a checkout,
 * built locally with no sign-in and no network, and the LOCAL handler map, printed as one JSON object on stdout. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { validateFactDocument } from "../lib/inspector/schema.mjs";

const BIN = fileURLToPath(new URL("../bin/custosa.mjs", import.meta.url));
const temp = (prefix) => realpathSync(mkdtempSync(join(tmpdir(), prefix)));
const run = (args, env) => new Promise((ok) => execFile(process.execPath, [BIN, ...args], { env: { ...process.env, ...env }, maxBuffer: 50e6 },
  (error, stdout, stderr) => ok({ code: error ? error.code : 0, stdout, stderr })));

function bundle() {
  const dir = temp("a7-bundle-");
  writeFileSync(join(dir, "manifest.json"), JSON.stringify({ ruleset_id: "2026-10-20.0123abcd", min_engine: "0.39.0", files: [] }));
  cpSync(fileURLToPath(new URL("./fixtures/rules/", import.meta.url)), join(dir, "rules"), { recursive: true });
  return dir;
}

test("inspect --document prints {document, handlers}: a valid local document and the local handler names", async () => {
  const root = temp("a7-doc-");
  mkdirSync(join(root, "app/api/visits"), { recursive: true });
  writeFileSync(join(root, "app/api/visits/route.ts"), 'import { requireUser } from "@/lib/auth";\nexport async function POST(request) {\n  const user = await requireUser(request);\n  await db.from("audit_log").insert({ user });\n  return Response.json({});\n}\n');
  writeFileSync(join(root, "package.json"), JSON.stringify({ dependencies: { next: "14.2.0" } }));
  const out = await run(["inspect", "--document", root], { CUSTOSA_BUNDLE_DIR: bundle(), CUSTOSA_CONFIG_DIR: temp("a7-doc-cfg-"), CUSTOSA_EVALUATOR_URL: "http://127.0.0.1:9" });
  assert.equal(out.code, 0, out.stderr);
  const { document, handlers } = JSON.parse(out.stdout);
  assert.equal(validateFactDocument(document), null);
  for (const name of ["catalog", "platform"]) assert.equal(document.collection.find((c) => c.collector === name).status, "not_run");
  const ids = new Set(document.matches.map((m) => m.handler).filter(Boolean));
  assert.ok(ids.size > 0, "the fixture yields handler ids");
  assert.deepEqual(Object.keys(handlers).sort(), [...ids].sort());
  for (const h of Object.values(handlers)) {
    assert.equal(h.path, "app/api/visits/route.ts");
    assert.equal(typeof h.name, "string");
    assert.ok(Number.isInteger(h.line) && Number.isInteger(h.column));
  }
  // The readable names are in the local map only, never in the document.
  for (const m of document.matches) assert.deepEqual(Object.keys(m).sort(), ["fingerprint", "handler", "has_control", "kind", "line_end", "line_start", "path", "practice_id", "rule_id", "shared_fingerprint", "table"]);
  assert.ok(!JSON.stringify(document).includes(root));
});

test("inspect --document exits non-zero without a document it can vouch for", async () => {
  const root = temp("a7-doc-");
  writeFileSync(join(root, "a.ts"), "x\n");
  const out = await run(["inspect", "--document", root], { CUSTOSA_BUNDLE_DIR: temp("a7-nobundle-"), CUSTOSA_CONFIG_DIR: temp("a7-doc-cfg-") });
  assert.notEqual(out.code, 0);
  assert.equal(out.stdout, "");
});

test("inspect --document refuses a file, and creates no install key without a rule bundle (merge review 4)", async () => {
  const root = temp("a7-doc-");
  writeFileSync(join(root, "a.ts"), "x\n");
  const out = await run(["inspect", "--document", join(root, "a.ts")], { CUSTOSA_BUNDLE_DIR: bundle(), CUSTOSA_CONFIG_DIR: temp("a7-doc-cfg-") });
  assert.equal(out.code, 1);
  assert.equal(out.stdout, "");
  const cfg = temp("a7-doc-cfg-");
  const none = await run(["inspect", "--document", root], { CUSTOSA_BUNDLE_DIR: temp("a7-nobundle-"), CUSTOSA_CONFIG_DIR: cfg });
  assert.equal(none.code, 1);
  const { readdirSync } = await import("node:fs");
  assert.deepEqual(readdirSync(cfg), [], "no install.key before the ruleset check passes");
});

/* the corpus fixed budget. With CUSTOSA_CORPUS_FIXED_BUDGET=1 (set by validation/corpus/score.py only) the
 * build gets the same large budget on every machine, and a document that still hit a time limit is refused, so one
 * input gives one output or an error, never a machine-dependent cut. */
/* The local budget fits the 290 s call. The whole local build plus the
   longest wait for one evaluator answer stays inside the call, and collection gets the rest, not Codex's old 60 s. */
test("The local budgets fit the 290 s call with the evaluator's answer after them", async () => {
  const { COLLECT_BUDGET_MS, TOTAL_BUDGET_MS } = await import("../lib/inspector/factdoc.mjs");
  const { CALL_BUDGET_MS } = await import("../lib/inspector/tool.mjs");
  const { EVALUATOR_TIMEOUT_MS } = await import("../lib/inspector/client.mjs");
  assert.equal(CALL_BUDGET_MS, 290_000);
  assert.ok(TOTAL_BUDGET_MS + EVALUATOR_TIMEOUT_MS <= CALL_BUDGET_MS, "the build and one answer fit the call");
  assert.ok(COLLECT_BUDGET_MS >= 120_000, "collection gets the room the call leaves");
  assert.ok(TOTAL_BUDGET_MS - COLLECT_BUDGET_MS >= 10_000, "the steps after collection keep their margin");
});

test("corpusBudget gives the fixed options only for CUSTOSA_CORPUS_FIXED_BUDGET=1", async () => {
  const { corpusBudget, CORPUS_BUDGET, COLLECT_BUDGET_MS } = await import("../lib/inspector/factdoc.mjs");
  assert.deepEqual(corpusBudget({}), null);
  assert.deepEqual(corpusBudget({ CUSTOSA_CORPUS_FIXED_BUDGET: "" }), null);
  assert.deepEqual(corpusBudget({ CUSTOSA_CORPUS_FIXED_BUDGET: "1" }), CORPUS_BUDGET);
  assert.throws(() => corpusBudget({ CUSTOSA_CORPUS_FIXED_BUDGET: "yes" }), /CUSTOSA_CORPUS_FIXED_BUDGET/);
  assert.ok(Object.isFrozen(CORPUS_BUDGET));
  assert.ok(CORPUS_BUDGET.timeBudgetMs >= 10 * COLLECT_BUDGET_MS && CORPUS_BUDGET.fileTimeoutMs >= 60_000 && CORPUS_BUDGET.readsBudgetMs >= 60_000);
  // Inside the scorer's 1800 s builder timeout, with room for the hard end.
  assert.ok(CORPUS_BUDGET.timeBudgetMs + 60_000 < 1_800_000);
});

test("timedOut finds a time_limit file or a collector cut on timeout", async () => {
  const { timedOut } = await import("../lib/inspector/factdoc.mjs");
  const doc = (na, reasons) => ({ files: { not_analyzed: na }, collection: reasons.map((reason, i) => ({ collector: `c${i}`, status: reason ? "truncated" : "ok", count: 0, reason })) });
  assert.equal(timedOut(doc([], [null, null])), false);
  assert.equal(timedOut(doc([{ path: "a.ts", kind: "file", reason: "parse_error", tracked: null }], [null])), false);
  assert.equal(timedOut(doc([{ path: "a.ts", kind: "file", reason: "time_limit", tracked: null }], [null])), true);
  assert.equal(timedOut(doc([], [null, "timeout"])), true);
});

test("The fixed options reach the build: the per-file rule limit and the budgets", async () => {
  const { buildLocalDocuments, CORPUS_BUDGET } = await import("../lib/inspector/factdoc.mjs");
  const { loadRules, runRules } = await import("../lib/inspector/rules.mjs");
  const root = temp("t18-budget-");
  writeFileSync(join(root, "a.ts"), "export const x = 1;\n");
  let seen = null, reads = null;
  const started = Date.now();
  const { documents } = await buildLocalDocuments([root], {
    configDir: temp("t18-budget-cfg-"), ...CORPUS_BUDGET,
    ruleset: { id: "2026-10-20.0123abcd", rules: loadRules(fileURLToPath(new URL("./fixtures/rules/", import.meta.url))), queries: [] },
    runRules: (r, input, opts) => { seen = opts; return runRules(r, input, opts); },
    collectCatalog: async (queries, opts) => { reads = opts?.deadline ?? null; return { status: "not_run", count: 0, reason: "service_missing", preflight: null, queries: [] }; },
  });
  assert.equal(documents[0].problem, null, JSON.stringify(documents[0].problem));
  assert.equal(seen.timeoutMs, CORPUS_BUDGET.fileTimeoutMs);
  assert.ok(seen.deadline - started >= CORPUS_BUDGET.timeBudgetMs - 10_000, "the rules get the fixed budget");
  assert.ok(reads - started >= CORPUS_BUDGET.readsBudgetMs - 1_000, "the catalog reads get the fixed budget");
  // Without the options, the defaults stand: the engine's own per-file limit.
  await buildLocalDocuments([root], { configDir: temp("t18-budget-cfg-"),
    ruleset: { id: "2026-10-20.0123abcd", rules: loadRules(fileURLToPath(new URL("./fixtures/rules/", import.meta.url))), queries: [] },
    runRules: (r, input, opts) => { seen = opts; return runRules(r, input, opts); } });
  assert.equal(seen.timeoutMs, undefined);
});

test("inspect --document with the fixed budget still prints a valid document", async () => {
  const root = temp("t18-doc-");
  writeFileSync(join(root, "package.json"), JSON.stringify({ dependencies: { next: "14.2.0" } }));
  writeFileSync(join(root, "a.ts"), "export const x = 1;\n");
  const env = { CUSTOSA_BUNDLE_DIR: bundle(), CUSTOSA_CONFIG_DIR: temp("t18-doc-cfg-"), CUSTOSA_EVALUATOR_URL: "http://127.0.0.1:9" };
  let out = await run(["inspect", "--document", root], { ...env, CUSTOSA_CORPUS_FIXED_BUDGET: "1" });
  assert.equal(out.code, 0, out.stderr);
  assert.equal(validateFactDocument(JSON.parse(out.stdout).document), null);
  out = await run(["inspect", "--document", root], { ...env, CUSTOSA_CORPUS_FIXED_BUDGET: "2" });
  assert.equal(out.code, 1);
  assert.match(out.stderr, /CUSTOSA_CORPUS_FIXED_BUDGET/);
});

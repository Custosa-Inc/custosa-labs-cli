/* Two valid constructs the pinned grammars can't parse.
 * - tsx and javascript: a bare `&` in JSX text (`<p>Plan & Services</p>`; tree-sitter-javascript#366).
 * - php: a trailing comma in a group use (`use A\{B, C,};`, PHP 7.2+).
 * parseCode repairs the site the recovered tree points at (one character becomes a space) and parses again. The repaired
 * tree is used only when it is clean: a recovered parse is still a failure, so anything else keeps the first tree, stays
 * recovered and is parse_error, never partly read. Every snippet here is synthetic. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { REPAIR_ROUNDS, mainRepair, parseCode, repairSites, parseSync, recovered } from "../lib/inspector/parse.mjs";
import { Handlers } from "../lib/inspector/captures.mjs";
import { kindAt } from "../lib/inspector/locationkind.mjs";
import { EventEmitter } from "node:events";
import { MatchWorker, WarmPool, loadRules, runRules } from "../lib/inspector/rules.mjs";
import { matchRoot, runJob } from "../lib/inspector/rules-worker.mjs";

const RULES = fileURLToPath(new URL("./fixtures/rules/", import.meta.url));
const KEY = Buffer.from("0123456789abcdef0123456789abcdef");

/* The indexes where two texts of one length differ. */
function diffAt(a, b) {
  assert.equal(a.length, b.length, "a repair keeps the length");
  const out = [];
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) out.push(i);
  return out;
}
/* Each index of `ch` in text, from the given occurrences (0-based) of it. */
const nth = (text, ch, ...which) => {
  const all = [];
  for (let i = text.indexOf(ch); i !== -1; i = text.indexOf(ch, i + 1)) all.push(i);
  return which.map((k) => all[k]);
};

/* Clean after the repair: the repaired sites are exactly `sites`, each now a space, and the tree is the repaired text. */
function assertRepaired(lang, text, sites) {
  assert.equal(recovered(parseSync(lang, text).root()), true, "the pinned grammar recovers on this text");
  const got = parseCode(lang, text);
  assert.equal(got.recovered, false, `${lang}: ${JSON.stringify(text)} parses cleanly after the repair`);
  assert.equal(got.repairs, sites.length);
  assert.deepEqual(diffAt(text, got.text), sites);
  for (const i of sites) assert.equal(got.text[i], " ");
  assert.equal(got.root.text(), got.text);
  assert.equal(recovered(got.root), false);
  return got;
}
/* Still a failure: the first tree, the text as given, recovered. */
function assertStillRecovered(lang, text) {
  const got = parseCode(lang, text);
  assert.equal(got.recovered, true, `${lang}: ${JSON.stringify(text)} stays recovered`);
  assert.equal(got.repairs, 0);
  assert.equal(got.text, text);
  assert.equal(got.root.text(), text);
  assert.equal(recovered(got.root), true);
}

test("A clean file is parsed once and left as it is", () => {
  for (const [lang, text] of [["tsx", "const a = <p>a &amp; b &#38; c</p>;\n"], ["php", "<?php\nuse A\\{B, C};\n$x = [1, 2,];\nf(1, 2,);\n"],
    ["javascript", "const s = 'a & b'; // c & d\n"], ["typescript", "const n = a & b;\n"]]) {
    const got = parseCode(lang, text);
    assert.deepEqual([got.recovered, got.repairs, got.text], [false, 0, text], lang);
  }
});

test("A bare & in JSX text (tsx and javascript) is repaired to a space and parses cleanly", () => {
  for (const lang of ["tsx", "javascript"]) {
    const one = "const a = <p>Plan & Services</p>;\n";
    assertRepaired(lang, one, nth(one, "&", 0));
    const word = "const a = <p>R&D</p>;\n"; // & right before a letter, no `;`: no character reference
    assertRepaired(lang, word, nth(word, "&", 0));
    const alone = "const a = <p>&</p>;\n";
    assertRepaired(lang, alone, nth(alone, "&", 0));
    const notRef = "const a = <p>a &amp b</p>;\n"; // `&amp` with no `;` is text to TypeScript too
    assertRepaired(lang, notRef, nth(notRef, "&", 0));
    const lines = "const a = (\n  <div>\n    Plan &\n    More\n  </div>\n);\n";
    assertRepaired(lang, lines, nth(lines, "&", 0));
    // Between other children: an element, an expression, a self-closing element; in a fragment.
    const mixed = "const a = <><b>x</b> & {y} & <i /></>;\n";
    assertRepaired(lang, mixed, nth(mixed, "&", 0, 1));
    // Two in one text: the first recovery climbs to the statement, so a second round finds the rest.
    const two = "const a = <p>A & B & C</p>;\n";
    assertRepaired(lang, two, nth(two, "&", 0, 1));
    // Separate texts each holding several, between elements and expressions.
    const runs = "const a = <div>\n  A & B & C\n  <b>x</b>\n  D & E\n  {f}\n  G && H\n</div>;\n";
    assertRepaired(lang, runs, nth(runs, "&", 0, 1, 2, 3, 4));
    // `&&` and `&=` in text: the scanner stops at the first `&`, and the parser reads an operator token.
    const ops = "const a = <p>A && B</p>, b = <p>C &= D</p>, c = <p>&&</p>;\n";
    assertRepaired(lang, ops, nth(ops, "&", 0, 1, 2, 3, 4));
    // A real reference next to a bare & keeps its `&`.
    const ref = "const a = <p>a &amp; b & c</p>;\n";
    assertRepaired(lang, ref, nth(ref, "&", 1));
  }
});

test("A & in a string, comment, template, attribute or expression is never touched", () => {
  const text = [
    "// a & b in a comment",
    "const s = 'c & d', t = `e & ${f & g}`;",
    "const n = h & i, m = j && k;",
    "export function View() {",
    "  return <p title=\"l & m\" data-x={n & 1}>Plan & Services</p>;",
    "}",
    "",
  ].join("\n");
  assertRepaired("tsx", text, nth(text, "&", 9)); // only the one in the element's text
});

test("Offsets are JavaScript string indexes, past astral and wide characters", () => {
  const tsx = "const a = <p>😀 漢字 Plan & Services 😀</p>;\n";
  assertRepaired("tsx", tsx, nth(tsx, "&", 0));
  const php = "<?php\n// 😀 漢字\n$s = '😀';\nuse A\\{B, C,};\n";
  assertRepaired("php", php, [php.lastIndexOf(",")]);
});

test("A trailing comma in a PHP group use is repaired to a space and parses cleanly", () => {
  const group = "<?php\nnamespace App;\n\nuse Vendor\\Pkg\\{\n    ConnectionFactory,\n    ConnectionOptions,\n    Container,\n};\nuse Vendor\\Other;\n";
  assertRepaired("php", group, [group.indexOf("Container,") + "Container".length]);
  const oneLine = "<?php\nuse A\\{B, C,};\n";
  assertRepaired("php", oneLine, [oneLine.lastIndexOf(",")]);
  const fn = "<?php\nuse function A\\{b, c,};\nuse const A\\{D, E,};\n";
  assertRepaired("php", fn, [fn.indexOf("c,") + 1, fn.indexOf("E,") + 1]);
  // A comment between the comma and the brace: the comma is repaired, the comment is kept.
  const comment = "<?php\nuse A\\{B, C, /* last */ };\n";
  assertRepaired("php", comment, [comment.indexOf("C,") + 1]);
  // One clause: the parser recovers with an ERROR holding the comma instead of a MISSING clause.
  const single = "<?php\nuse A\\{B,};\nuse C\\{D, /* last */ };\n";
  assertRepaired("php", single, [single.indexOf("B,") + 1, single.indexOf("D,") + 1]);
  // Three group uses in one file, as in one of the corpus files.
  const three = "<?php\nuse A\\{B, C,};\nuse D\\{E,};\nuse F\\{G, H,};\nclass K { public function m() { return [1, 2,]; } }\n";
  assertRepaired("php", three, [three.indexOf("C,") + 1, three.indexOf("E,") + 1, three.indexOf("H,") + 1]);
});

test("A recovered parse is still a failure: anything else keeps the first tree and stays recovered", () => {
  // Other recoveries, with no repairable site.
  assertStillRecovered("php", "<?php\nuse A\\{B,, C};\n"); // two commas: not a trailing comma
  assertStillRecovered("php", "<?php\nuse A\\{,};\n"); // an empty group
  assertStillRecovered("php", "<?php\nfunction f() { return 1;\n"); // a missing }
  assertStillRecovered("tsx", "const a = <p>{a &}</p>;\n"); // a & in an expression, not JSX text
  assertStillRecovered("typescript", "type T = { abstract?: boolean };\n"); // tree-sitter-typescript#377, no repair
  assertStillRecovered("javascript", "if (a) { b()\n"); // MISSING only
  // A repairable site next to a real error: the repair alone doesn't make the file clean, so nothing of it is used.
  assertStillRecovered("tsx", "export function A() {\n  return <p>Plan & Services</p>;\n\nexport function B() {}\n");
  assertStillRecovered("php", "<?php\nuse A\\{B, C,};\nfunction f() { return 1;\n");
  assertStillRecovered("php", "<?php\nuse A\\{B, C,};\nuse D\\{E,, F};\n");
});

test("An & that is an operator in broken code is never an anchor, even next to a real JSX site", () => {
  for (const lang of ["tsx", "javascript"]) {
    assertStillRecovered(lang, "const m = flags & ;\n");
    assertStillRecovered(lang, "function f() {\n  return a & & b;\n}\n");
    assertStillRecovered(lang, "const a = <p>x</p> & ;\n"); // after the element closed: code, not text
    // A good JSX site, then an operator & in a broken statement: the JSX site alone can't make it clean, and the
    // operator & is never blanked to make it so.
    assertStillRecovered(lang, "const a = <p>x &\n</p>\nconst b = y & ;\n");
  }
});

test("A character reference inside a repaired run keeps its &", () => {
  for (const lang of ["tsx", "javascript"]) {
    const text = "const a = <p>a & b &amp; c &#38; d</p>;\n";
    const got = assertRepaired(lang, text, [15]);
    assert.ok(got.text.includes("&amp; c &#38; d"));
  }
});

test("The repair rounds are bounded; past them the file stays recovered", () => {
  assert.ok(Number.isInteger(REPAIR_ROUNDS) && REPAIR_ROUNDS >= 2 && REPAIR_ROUNDS <= 16, String(REPAIR_ROUNDS));
  // Many bare & in one text still finish in the bound.
  const many = `const a = <p>${Array.from({ length: 60 }, (_, i) => `w${i} &`).join(" ")} end</p>;\n`;
  const got = parseCode("tsx", many);
  assert.equal(got.recovered, false);
  assert.equal(got.repairs, 60);
  assert.equal(got.text, many.replaceAll("&", " "));
});

test("parseCode gives the repaired tree, or recovered when the file still recovers", () => {
  const ok = parseCode("tsx", "export const V = () => <p>Plan & Services</p>;\n");
  assert.equal(ok.recovered, false);
  assert.ok(ok.root.text().includes("Plan   Services"));
  assert.equal(parseCode("php", "<?php\nuse A\\{B, C,};\n").recovered, false);
  assert.equal(parseCode("php", "<?php\nuse A\\{B,, C};\n").recovered, true);
  assert.equal(parseCode("tsx", "export function A() {\n  return <p>a & b</p>;\n").recovered, true);
});

test("runRules analyses the repaired files and keeps their evidence and handlers; an unrepairable one is parse_error", async () => {
  const base = loadRules(RULES).find((r) => r.id.endsWith("console-phi"));
  const rule = (lang, kind) => ({ ...base, id: `access-audit-log.${lang}-generic.audit-call`, practice_id: "access-audit-log", language: lang,
    frameworks: ["generic"], kind: "evidence", rule: { kind, regex: "^audit\\(" } });
  const rules = [rule("tsx", "call_expression"), rule("php", "function_call_expression")];
  const TSX = "export function Plan() {\n  audit(\"viewed\");\n  return <p>Plan & Services</p>;\n}\n";
  const PHP = "<?php\nuse Vendor\\Pkg\\{\n    Factory,\n    Container,\n};\n\nfunction record() {\n    audit('viewed');\n}\n";
  const res = await runRules(rules, [
    { path: "src/Plan.tsx", text: TSX },
    { path: "lib/sql.inc.php", text: PHP },
    { path: "src/Broken.tsx", text: "export function Broken() {\n  audit(\"x\");\n  return <p>a & b</p>;\n" },
    { path: "lib/broken.php", text: "<?php\nuse A\\{B,, C};\nfunction f() { audit('x'); }\n" },
  ], { key: KEY, frameworks: [] });
  assert.deepEqual(res.notAnalyzed, [{ path: "src/Broken.tsx", reason: "parse_error" }, { path: "lib/broken.php", reason: "parse_error" }]);
  assert.deepEqual(res.analyzedPaths, ["lib/sql.inc.php", "src/Plan.tsx"]);
  assert.equal(res.analyzed, 2);
  // Evidence from the two repaired files, on the source's own lines, each linked to its function; none from the others.
  assert.deepEqual(res.matches.map((m) => [m.path, m.kind, m.line_start]), [["lib/sql.inc.php", "evidence", 8], ["src/Plan.tsx", "evidence", 2]]);
  const id = (lang, path, text, name) => {
    const h = new Handlers(parseCode(lang, text).root, lang, path, KEY);
    h.load();
    const i = h.fns.findIndex((_, k) => h.identity(k)?.name === name);
    return h.idOfFunction(i);
  };
  assert.deepEqual(res.matches.map((m) => m.handler), [id("php", "lib/sql.inc.php", PHP, "record"), id("tsx", "src/Plan.tsx", TSX, "Plan")]);
  assert.ok(res.matches.every((m) => m.handler));
});

test("Location kinds read the repaired tree too", () => {
  const text = "export function Plan() {\n  return <p>Plan & Services</p>;\n}\n";
  assert.equal(kindAt("function", { path: "src/Plan.tsx", lang: "tsx", text, start: 1, end: 3, key: KEY }), true);
});

/* runJob (the worker's job) on a repairable file: the first pass is the recovered tree, the second the repaired one. */
const auditRule = (lang, kind, ruleKind = "violation") => ({ id: `access-audit-log.${lang}-generic.audit-call`, practice_id: "access-audit-log",
  language: lang, frameworks: ["generic"], kind: ruleKind, rule: { kind, regex: "^audit\\(" } });
const REPAIRABLE = "export function Plan() {\n  audit(\"viewed\");\n  return <p>Plan & Services</p>;\n}\n";
function job(text, ctx = {}) {
  const sent = [];
  const done = runJob({ path: "src/Plan.tsx", lang: "tsx", text, softMs: 60_000 },
    { rules: [auditRule("tsx", "call_expression")], key: KEY, send: (m) => sent.push(m), ...ctx });
  return { sent, done };
}
const firstPass = (sent) => sent.filter((m) => m.type === "found").flatMap((m) => m.matches);

test("runJob: a repaired file's second pass replaces the first pass's matches in one message, and the file is clean", () => {
  const { sent, done } = job(REPAIRABLE);
  assert.deepEqual(sent.map((m) => m.type), ["found", "replace"]);
  assert.deepEqual(firstPass(sent).map((m) => m.line_start), [2]); // the recovered tree's violation, posted as found
  assert.deepEqual(sent[1].matches.map((m) => [m.kind, m.line_start]), [["violation", 2]]);
  assert.deepEqual(done, { type: "done", parseError: false, recovered: false, late: false, ruleError: false });
});

for (const [what, outcome, reason, done] of [
  ["runs late", { late: true, ruleError: false }, "parse_error", { recovered: true, ruleError: false }],
  ["hits a rule error", { late: false, ruleError: true }, "rule_error", { recovered: false, ruleError: true }]]) {
  test(`runJob: a second pass that ${what} is dropped whole: no replace, the first pass's violations stay, ${reason}`, () => {
    let calls = 0;
    const match = (...args) => {
      calls++;
      const result = matchRoot(...args); // the second pass finds its matches (buffered), then reports the outcome
      return calls === 1 ? result : outcome;
    };
    const { sent, done: result } = job(REPAIRABLE, { match });
    assert.equal(calls, 2, "the second pass ran");
    assert.deepEqual(sent.map((m) => m.type), ["found"]); // nothing of the second pass reached the parent
    assert.deepEqual(firstPass(sent).map((m) => [m.kind, m.line_start]), [["violation", 2]]);
    // Late: as if no repair had been tried (recovered, so parse_error). A rule error: rule_error (the collector reports
    // a failed rule). Either way the file is not analysed and blocks.
    assert.deepEqual(result, { type: "done", parseError: false, late: false, ...done });
  });
}

test("runJob: with less budget left than the first pass took, the repair is skipped and the file stays parse_error", () => {
  let t = 0;
  const clock = () => { const now = t; t = 600; return now; }; // the first pass takes 600 of a 1000 budget
  let calls = 0;
  const match = (...args) => { calls++; return matchRoot(...args); };
  const sent = [];
  const done = runJob({ path: "src/Plan.tsx", lang: "tsx", text: REPAIRABLE, softMs: 1000 },
    { rules: [auditRule("tsx", "call_expression")], key: KEY, send: (m) => sent.push(m), clock, match });
  assert.equal(calls, 1, "no second pass");
  assert.deepEqual(sent.map((m) => m.type), ["found"]);
  assert.deepEqual(done, { type: "done", parseError: false, recovered: true, late: false, ruleError: false });
});

test("A repaired file's match lines are the original file's lines (same-length repairs, no offset shift)", async () => {
  // Repair sites before, on and after the matched lines, several on one line, and a wide character before them.
  const TSX = [
    "// 😀 漢字",
    "export function Plan() {",
    "  const a = <p>A & B && C</p>;",
    "  audit(\"one\");",
    "  const b = <p>R&D & co</p>; audit(\"two\");",
    "  return <div>",
    "    x & y",
    "    {audit(\"three\")}",
    "  </div>;",
    "}",
    "",
  ].join("\n");
  const PHP = "<?php\n// 😀\nuse A\\{B, C,};\nuse D\\{E,};\n\nfunction f() {\n    audit('one');\n}\nuse F\\{G, H,};\naudit('two');\n";
  const lineOf = (text, needle) => text.slice(0, text.indexOf(needle)).split("\n").length;
  for (const [path, lang, text, kind, needles] of [["src/Plan.tsx", "tsx", TSX, "call_expression", ['audit("one")', 'audit("two")', 'audit("three")']],
    ["lib/a.php", "php", PHP, "function_call_expression", ["audit('one')", "audit('two')"]]]) {
    const parsed = parseCode(lang, text);
    assert.equal(parsed.recovered, false);
    assert.equal(parsed.text.length, text.length);
    assert.equal(parsed.text.split("\n").length, text.split("\n").length);
    const res = await runRules([auditRule(lang, kind)], [{ path, text }], { key: KEY, frameworks: [] });
    assert.deepEqual(res.notAnalyzed, [], path);
    const want = needles.map((n) => lineOf(text, n));
    assert.deepEqual(res.matches.map((m) => [m.line_start, m.line_end]), want.map((l) => [l, l]), path);
    // Each reported line holds the call in the user's own text.
    res.matches.forEach((m, i) => assert.ok(text.split("\n")[m.line_start - 1].includes(needles[i]), path));
  }
});

/* Deeply nested JSX with a bare & at every level: the repair costs many times the parse (review N1). */
const NESTED = (n) => `const a = ${Array.from({ length: n }, (_, i) => `<b>x${i} & y & `).join("")}${"</b>".repeat(n)};\n`;

test("Past its deadline the repair stops and keeps the recovered tree (deeply nested & JSX)", () => {
  const text = NESTED(400);
  assert.equal(parseCode("tsx", text).recovered, false, "unbounded, it repairs");
  // A deadline already passed: no round runs.
  const none = parseCode("tsx", text, { clock: () => 10, deadline: 10 });
  assert.deepEqual([none.recovered, none.repairs, none.text], [true, 0, text]);
  // A deadline reached during the site search, which checks it every 256 ERROR nodes: the search stops there. This
  // needs at least 512 ERROR nodes (checks at 256 and 512); if the grammar's recovery changes, say so.
  const deep = NESTED(600);
  const tree = parseSync("tsx", deep).root();
  const errors = tree.findAll({ rule: { kind: "ERROR" } }).length;
  assert.ok(errors >= 512, `NESTED(600) gives ${errors} ERROR nodes, fewer than the 512 this case needs`);
  let checks = 0;
  assert.equal(repairSites("tsx", tree, deep, () => ++checks >= 2), null, "the search stopped at its second check");
  assert.equal(checks, 2);
  checks = 0;
  const all = repairSites("tsx", tree, deep, () => { checks++; return false; });
  assert.ok(all.length > 0);
  assert.equal(checks, Math.floor(errors / 256), "one check per 256 ERROR nodes");
  // And through parseCode: a deadline met inside the first round's search keeps the recovered tree.
  let ticks = 0;
  const mid = parseCode("tsx", deep, { clock: () => ticks++, deadline: 2 }); // 0: the round's start, 1: 256, 2: 512
  assert.deepEqual([mid.recovered, mid.repairs, mid.text], [true, 0, deep]);
  assert.equal(ticks, 3);
  // The main-thread callers pass a deadline too: a location check on such a file still answers.
  assert.equal(typeof kindAt("function", { path: "src/N.tsx", lang: "tsx", text, start: 1, end: 1, key: KEY }), "boolean");
});

test("runJob: the repair is bounded by the job's softMs; past it the file stays parse_error with no second pass", () => {
  // The first pass takes no time (so the budget skip lets the repair start); after it the clock reads 0 once more
  // (runJob's firstPass), then past started + softMs, which the repair meets at its first check.
  let calls = 0, after = 0;
  const clock = () => (calls === 0 ? 0 : after++ === 0 ? 0 : 5000);
  const match = (...args) => { const r = matchRoot(...args); calls++; return r; };
  const sent = [];
  const done = runJob({ path: "src/N.tsx", lang: "tsx", text: NESTED(50), softMs: 1000 },
    { rules: [auditRule("tsx", "call_expression")], key: KEY, send: (m) => sent.push(m), clock, match });
  assert.equal(calls, 1, "no second pass");
  assert.ok(!sent.some((m) => m.type === "replace"));
  assert.deepEqual(done, { type: "done", parseError: false, recovered: true, late: false, ruleError: false });
});

/* A stand-in worker thread for MatchWorker: it replays the given messages for a job, then never answers (a thread
 * inside a long native call), and on terminate() it posts a replace and a done, as a thread finishing its call might. */
class HangingThread extends EventEmitter {
  constructor(messages) {
    super();
    this.messages = messages; this.terminated = false;
    this.exited = new Promise((resolve) => { this.exit = resolve; });
  }
  postMessage() { setImmediate(() => { for (const m of this.messages) this.emit("message", m); }); }
  terminate() {
    this.terminated = true;
    // At once (the strictest timing): a listener still attached would clear the matches before run() returns them.
    this.emit("message", { type: "replace", matches: [] }); this.emit("message", { type: "done" });
    setImmediate(() => this.exit());
    return Promise.resolve(0);
  }
  ref() {} unref() {}
}

test("end to end: a hard-deadline kill during the second pass keeps the first pass's matches, and the file is time_limit", async () => {
  const rules = [auditRule("tsx", "call_expression")];
  // The real first pass of the worker's job on a repairable file: its found messages, then the second pass would run.
  const first = [];
  runJob({ path: "src/Plan.tsx", lang: "tsx", text: REPAIRABLE, softMs: 60_000 },
    { rules, key: KEY, send: (m) => first.push(m), match: (...args) => (first.length ? { late: false, ruleError: false } : matchRoot(...args)) });
  const found = first.filter((m) => m.type === "found");
  assert.equal(found.flatMap((m) => m.matches).length, 1);
  // runRules with a warm pool whose one worker is that thread, hanging in the second pass until the hard deadline.
  const warm = new WarmPool();
  const thread = new HangingThread(found);
  const worker = new MatchWorker(rules, KEY);
  worker.worker = thread;
  warm.rules = rules; warm.keyId = worker.keyId; warm.factor = true; warm.idle.push(worker);
  const res = await runRules(rules, [{ path: "src/Plan.tsx", text: REPAIRABLE }], { key: KEY, frameworks: [], warm, timeoutMs: 300, workers: 1 });
  assert.equal(thread.terminated, true, "the worker was killed at the deadline");
  assert.deepEqual(res.notAnalyzed, [{ path: "src/Plan.tsx", reason: "time_limit" }]);
  // The first pass's violation is kept (without its handler); the replace the thread posted after the kill is ignored.
  assert.deepEqual(res.matches.map((m) => [m.kind, m.line_start, m.handler]), [["violation", 2, null]]);
  assert.equal(res.status, "truncated");
  warm.drop();
});

/* The main-thread repair budget (parse.mjs mainRepair) set to nothing, for one test. */
async function withNoMainBudget(fn) {
  const saved = mainRepair.ms;
  mainRepair.ms = 0;
  try { return await fn(); } finally { mainRepair.ms = saved; }
}
const PLAN = "export function Plan() {\n  audit(\"viewed\");\n  return <p>Plan & Services</p>;\n}\n";

test("parseCode: the repair stops at the file's deadline and the file reads as recovered", () => {
  const late = parseCode("tsx", PLAN, { clock: () => 100, deadline: 50 });
  assert.equal(late.recovered, true, "past the deadline the repair didn't run");
  assert.equal(parseCode("tsx", PLAN, { clock: () => 0, deadline: 50 }).recovered, false);
});

test("location kinds: a tree still recovered confirms nothing, so a repair that ran out of time answers not confirmed", async () => {
  const at = (text) => kindAt("function", { path: "src/Plan.tsx", lang: "tsx", text, start: 1, end: 1, key: KEY });
  assert.equal(recovered(parseSync("tsx", PLAN).root()), true);
  assert.equal(at(PLAN), true, "repaired in time: the function is confirmed");
  // No main-thread budget: the repair stops, the tree is the recovered one (which on its own still shows the function
  // on line 1), and the answer is not confirmed rather than read from it.
  await withNoMainBudget(() => assert.equal(at(PLAN), false));
  // A file that stays recovered whatever the budget: not confirmed either.
  assert.equal(at("export function Plan() {\n  return 1;\n"), false);
});

test("handler map: a tree still recovered on the main thread names no handler (left out, never read from it)", async () => {
  const { buildLocalDocuments } = await import("../lib/inspector/factdoc.mjs");
  const { mkdtempSync, writeFileSync, realpathSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const temp = (prefix) => realpathSync(mkdtempSync(join(tmpdir(), prefix)));
  const root = temp("b44-handlers-");
  writeFileSync(join(root, "Plan.tsx"), PLAN);
  const rule = { ...auditRule("tsx", "call_expression", "evidence"), min_engine: "0.45.0" };
  const build = () => buildLocalDocuments([root], { configDir: temp("b44-handlers-cfg-"), handlerMap: true,
    ruleset: { id: "2026-10-20.0123abcd", rules: [rule], queries: [] } });
  const named = (out) => {
    const [doc] = out.documents;
    assert.equal(doc.problem, null, JSON.stringify(doc.problem));
    const ids = doc.document.matches.map((m) => m.handler);
    assert.equal(ids.length, 1);
    assert.ok(ids[0], "the worker repaired the file and linked the match");
    return doc.handlers?.[ids[0]] ?? null;
  };
  assert.equal(named(await build())?.name, "Plan", "repaired in time on the main thread too: the id is named");
  assert.equal(await withNoMainBudget(async () => named(await build())), null, "out of time: left out of the map");
});

test("a repaired pass's shared fingerprints walk the repaired text, the one its tree was parsed from", async () => {
  const { sharedFingerprint } = await import("../lib/inspector/walk.mjs");
  const { repairRecovered } = await import("../lib/inspector/parse.mjs");
  const CONTENT = "ab".repeat(32);
  // A rule whose node holds the repaired &: sliced from the original text, the walk's self-check would see the shift.
  const rule = { id: "access-audit-log.tsx-generic.plan", practice_id: "access-audit-log", language: "tsx",
    frameworks: ["generic"], kind: "violation", rule: { kind: "function_declaration", regex: "^export function Plan|^function Plan" } };
  const sent = [];
  runJob({ path: "src/Plan.tsx", lang: "tsx", text: REPAIRABLE, softMs: 60_000 },
    { rules: [rule], key: KEY, send: (m) => sent.push(m), contentKey: CONTENT });
  const replace = sent.find((m) => m.type === "replace");
  assert.ok(replace && replace.matches.length === 1, JSON.stringify(sent.map((m) => m.type)));
  const repaired = repairRecovered("tsx", REPAIRABLE, parseSync("tsx", REPAIRABLE).root());
  assert.equal(repaired.recovered, false);
  assert.notEqual(repaired.text, REPAIRABLE);
  const node = repaired.root.find({ rule: rule.rule });
  const want = sharedFingerprint(CONTENT, rule.id, "src/Plan.tsx", node, "tsx", repaired.text);
  assert.match(want, /^[0-9a-f]{64}$/);
  assert.equal(replace.matches[0].shared_fingerprint, want);
  assert.equal(sharedFingerprint(CONTENT, rule.id, "src/Plan.tsx", node, "tsx", REPAIRABLE), null, "the original text fails the self-check");
  // With no content key, every match of both passes carries null (the field is required since the schema pair).
  const plain = [];
  runJob({ path: "src/Plan.tsx", lang: "tsx", text: REPAIRABLE, softMs: 60_000 }, { rules: [rule], key: KEY, send: (m) => plain.push(m) });
  assert.ok(plain.flatMap((m) => m.matches ?? []).every((m) => m.shared_fingerprint === null));
});

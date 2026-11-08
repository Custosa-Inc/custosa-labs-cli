// Contract 2.3 §3.5 and §6.1 test 7c: the walk behind matches[].shared_fingerprint.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { parseSync } from "../lib/inspector/parse.mjs";
import { DERIVED_STRING_LIKE, joinWalk, LISTED_STRING_LIKE, STRING_CONTENT_KINDS, sharedFingerprint, walk } from "../lib/inspector/walk.mjs";
import { FACT_SCHEMA } from "../lib/inspector/schema.mjs";

const KEY = "ab".repeat(32);
const require = createRequire(import.meta.url);

// The fingerprint of the first node of `kind` (the whole file when no kind), as a rule's match would hold it.
function fp(lang, text, kind, key = KEY) {
  const root = parseSync(lang, text).root();
  const node = kind ? root.find({ rule: { kind } }) : root;
  assert.ok(node, `no ${kind} in ${JSON.stringify(text)}`);
  return sharedFingerprint(key, "rule.x", "src/a." + lang, node, lang, text);
}
const same = (lang, a, b, kind) => assert.equal(fp(lang, a, kind), fp(lang, b, kind));
const differ = (lang, a, b, kind) => {
  const [x, y] = [fp(lang, a, kind), fp(lang, b, kind)];
  assert.ok(x && y, "both walk");
  assert.notEqual(x, y);
};

test("7c: an edit inside a matched tool node changes it, though the rule's facts stay the same", () => {
  const before = "const t = tool({\n  inputSchema: z.object({}),\n  execute: async () => db.visit.findMany({ where: { patientId: session.user.patientId } }),\n});\n";
  const after = "const t = tool({\n  inputSchema: z.object({ patientId: z.string() }),\n  execute: async ({ patientId }) => db.visit.findMany({ where: { patientId } }),\n});\n";
  differ("typescript", before, after, "call_expression");
});

test("7c: the ai-trace-redaction variant, only the exporter URL changes", () => {
  differ("typescript", 'init({ exporter: { url: "https://a.example" }, redact: true });\n',
    'init({ exporter: { url: "https://b.example" }, redact: true });\n', "call_expression");
});

test("7c: reindenting, a comment, whitespace between tokens and moving lines leave it", () => {
  const base = "f({\n  a: 1,\n  b: g(x, y),\n});\n";
  same("typescript", base, "f({\n      a: 1,\n      b: g(x, y),\n    });\n", "call_expression");
  same("typescript", base, "f({\n  a: 1, // why\n  /* c */ b: g(x, y),\n});\n", "call_expression");
  same("typescript", base, "f({ a : 1 ,\n b:g( x,y ), });\n", "call_expression");
  same("typescript", base, "\n\n\nlet z = 0;\n" + base, "call_expression");
});

test("7c W3: reindenting a multi-line template literal changes it", () => {
  differ("typescript", "q(`SELECT a\n  FROM t`);\n", "q(`SELECT a\n      FROM t`);\n", "call_expression");
});

test("7c R2b: SQL inside a template string joined onto one line changes it", () => {
  differ("typescript", "run(`SELECT * FROM visits -- every column\n  WHERE patient_id = ${session.patientId}`);\n",
    "run(`SELECT * FROM visits -- every column  WHERE patient_id = ${session.patientId}`);\n", "call_expression");
  differ("python", 'def f():\n    run("""SELECT * FROM visits # every column\n  WHERE patient_id = %s""")\n',
    'def f():\n    run("""SELECT * FROM visits # every column  WHERE patient_id = %s""")\n', "function_definition");
});

test("7c R2c: automatic semicolon insertion splits a return differently", () => {
  differ("typescript", "function f() {\n  return\n    db.visit.findMany();\n}\n",
    "function f() {\n  return db.visit.findMany();\n}\n", "function_declaration");
});

test("7c: a comment between two tokens, in TS", () => {
  same("typescript", "const y = typeof/**/x;\n", "const y = typeof x;\n");
  differ("typescript", "const y = typeof/**/x;\n", "const y = typeofx;\n");
});

test("7c R2a: a dedented Python statement changes it; a uniformly reindented function doesn't", () => {
  const inside = "def get_visits(patient_id):\n    if can_read(current_user, patient_id):\n        data = db.visits(patient_id)\n    return data\n";
  const out = "def get_visits(patient_id):\n    if can_read(current_user, patient_id):\n        pass\n    data = db.visits(patient_id)\n    return data\n";
  const plain = "def get_visits(patient_id):\n    if can_read(current_user, patient_id):\n        data = db.visits(patient_id)\n        return data\n";
  differ("python", inside, plain, "function_definition");
  differ("python", inside, out, "function_definition");
  same("python", inside, "class A:\n    " + inside.trimEnd().split("\n").join("\n    ") + "\n", "function_definition");
});

test("7c: a statement moved between two blocks, in Python and TS", () => {
  differ("python", "def f():\n    if a:\n        x()\n    else:\n        y()\n", "def f():\n    if a:\n        pass\n    else:\n        y()\n        x()\n", "function_definition");
  differ("typescript", "function f() { if (a) { x(); } else { y(); } }\n", "function f() { if (a) { } else { y(); x(); } }\n", "function_declaration");
});

test("text the grammar keeps in gaps changes it", () => {
  differ("python", "def f():\n    q = 'SELECT a FROM t\\n'\n", "def f():\n    q = 'DELETE FROM t\\n'\n", "function_definition");
  differ("python", "def f():\n    return f'{x:>10}'\n", "def f():\n    return f'{x:<10}'\n", "function_definition");
  differ("yaml", "acl: 'private'\n", "acl: 'public-read'\n");
  differ("yaml", 'acl: "private"\n', 'acl: "public-read"\n');
  differ("yaml", "run: |\n  curl https://internal\n", "run: |\n  curl https://evil.example\n");
  differ("yaml", "run: >\n  echo a\n", "run: >\n  echo b\n");
  differ("kotlin", "val c = 'a'\n", "val c = 'b'\n");
});

test("a PHP docblock is code; a plain comment is not", () => {
  const m = (doc, note = "") => `<?php\nclass C {\n  ${doc}\n  public function show($id) { ${note}return Patient::find($id); }\n}\n`;
  differ("php", m('/** @IsGranted("ROLE_ADMIN") */'), m('/** @IsGranted("PUBLIC_ACCESS") */'), "class_declaration");
  same("php", m('/** @IsGranted("ROLE_ADMIN") */'), m('/** @IsGranted("ROLE_ADMIN") */', "// look\n    "), "class_declaration");
  same("php", m('/** @IsGranted("ROLE_ADMIN") */'), m('/** @IsGranted("ROLE_ADMIN") */', "/* look */ "), "class_declaration");
  const col = (t) => `<?php\nclass P {\n  /** @ORM\\Column(type="${t}") */\n  private $ssn;\n}\n`;
  differ("php", col("encrypted_string"), col("string"), "class_declaration");
});

test("7c: a comment join in PHP is kept, so a/**/+ b differs from a + b", () => {
  differ("php", "<?php\n$c = $a/**/+ $b;\n", "<?php\n$c = $a + $b;\n");
});

test("a blank line inside a PHP heredoc changes it", () => {
  differ("php", "<?php\n$q = <<<S\nSELECT a\n\nFROM t\nS;\n", "<?php\n$q = <<<S\nSELECT a\nFROM t\nS;\n");
});

test("LF and CRLF give the same fingerprint, multi-line strings included", () => {
  const ts = "const q = `SELECT a\nFROM t`;\nf(q);\n";
  same("typescript", ts, ts.replace(/\n/g, "\r\n"));
  const py = 'def f():\n    q = """SELECT a\nFROM t"""\n    return q\n';
  same("python", py, py.replace(/\n/g, "\r\n"), "function_definition");
});

test("1a: the fingerprint is keyed; no key gives null; it names the rule and the path", () => {
  const text = "f(a, b);\n";
  assert.match(fp("typescript", text), /^[0-9a-f]{64}$/);
  assert.notEqual(fp("typescript", text), fp("typescript", text, undefined, "cd".repeat(32)));
  assert.equal(fp("typescript", text, undefined, null), null);
  const node = parseSync("typescript", text).root();
  assert.notEqual(sharedFingerprint(KEY, "rule.x", "a.ts", node, "typescript", text),
    sharedFingerprint(KEY, "rule.y", "a.ts", node, "typescript", text));
  assert.notEqual(sharedFingerprint(KEY, "rule.x", "a.ts", node, "typescript", text),
    sharedFingerprint(KEY, "rule.x", "b.ts", node, "typescript", text));
});

test("the self-check fails safe: offsets into other text, or a language with no table, give null", () => {
  const text = "  f(a, b);\n";
  const node = parseSync("typescript", text).root();
  assert.ok(walk(node, "typescript", text));
  assert.equal(walk(node, "typescript", "XX" + text), null);           // shifted, as root.text() would be
  assert.equal(walk(node, "cobol", text), null);
  assert.equal(sharedFingerprint(KEY, "r", "a.ts", node, "typescript", text.trimStart()), null);
});

test("the string-like kinds match a fresh derivation from each grammar's node-types.json", () => {
  const content = new Set(STRING_CONTENT_KINDS);
  for (const lang of ["go", "java", "json", "kotlin", "php", "python", "ruby", "yaml"]) {
    const dir = dirname(require.resolve(`@ast-grep/lang-${lang}/package.json`));
    const types = JSON.parse(readFileSync(join(dir, "src", "node-types.json"), "utf8"));
    const derived = types.filter((t) => [t.children, ...Object.values(t.fields ?? {})].filter(Boolean)
      .some((l) => l.types.some((c) => content.has(c.type)))).map((t) => t.type).sort();
    assert.deepEqual([...DERIVED_STRING_LIKE[lang]].sort(), derived, lang);
  }
});

test("TS, TSX and JS: the derived string-like kinds are the ones napi's built-in grammars parse around string content", () => {
  // napi ships no node-types.json for its built-in grammars, so this checks the lists against the parser itself:
  // every kind seen holding string content is derived or listed, and every derived kind is seen.
  const content = new Set(STRING_CONTENT_KINDS);
  const samples = {
    typescript: ["const a = 'x  y' + \"p\\nq\" + `m ${b}  n`;", "type T = `a ${B}  c`;", "import x from 'm';"],
    tsx: ["const a = 'x  y' + `m ${b}  n`;", "type T = `a ${B}  c`;", "const e = <div title=\"t  u\">v</div>;"],
    javascript: ["const a = 'x  y' + \"p\\nq\" + `m ${b}  n`;", "import x from 'm';"],
  };
  for (const [lang, texts] of Object.entries(samples)) {
    const seen = new Set();
    const visit = (n) => {
      if (n.children().some((c) => content.has(c.kind()))) seen.add(n.kind());
      n.children().forEach(visit);
    };
    texts.forEach((t) => visit(parseSync(lang, t).root()));
    const known = new Set([...DERIVED_STRING_LIKE[lang], ...LISTED_STRING_LIKE]);
    assert.deepEqual([...seen].filter((k) => !known.has(k)), [], lang);
    assert.deepEqual(DERIVED_STRING_LIKE[lang].filter((k) => !seen.has(k)), [], lang);
  }
});

test("non-ASCII text and a leading BOM still walk: the slice unit is range().index's", () => {
  for (const text of ['const s = "é😀中文"; f(s);\n', "﻿  f(a);\n", '// é😀\nconst t = `中文 ${x}`;\n']) {
    const node = parseSync("typescript", text).root();
    assert.ok(walk(node, "typescript", text), JSON.stringify(text));
  }
});

test("matchRoot gives each match its shared fingerprint when a content key is passed, and null otherwise", async () => {
  const { matchRoot } = await import("../lib/inspector/rules-worker.mjs");
  const rule = { id: "x.typescript-generic.y", practice_id: "x", kind: "evidence", rule: { pattern: "console.log($A)" } };
  const run = (text, opts) => {
    const found = [];
    matchRoot(parseSync("typescript", text).root(), "src/a.ts", "typescript", [rule], Buffer.alloc(32, 7),
      { started: Date.now(), softMs: 10000, post: (m) => found.push(...m), ...opts });
    return found;
  };
  const text = "\n  console.log(a);\nconsole.log(b);\n";
  const off = run(text, {});
  assert.equal(off.length, 2);
  assert.ok(off.every((m) => m.shared_fingerprint === null));    // required on every match: null with no content key
  const on = run(text, { contentKey: KEY, source: text });
  const node = (t) => parseSync("typescript", t).root().find({ rule: rule.rule });
  assert.equal(on[0].shared_fingerprint, sharedFingerprint(KEY, rule.id, "src/a.ts", node(text), "typescript", text));
  assert.notEqual(on[0].shared_fingerprint, on[1].shared_fingerprint);
  // Moved to other lines, the same node keeps its value; the per-install fingerprint is unchanged by the key.
  assert.equal(run("\n\n\n" + text, { contentKey: KEY, source: "\n\n\n" + text })[0].shared_fingerprint,
    on[0].shared_fingerprint);
  assert.equal(on[0].fingerprint, off[0].fingerprint);
  // A content key without the parsed text can't slice gaps: null, never a value from root.text().
  assert.ok(run(text, { contentKey: KEY }).every((m) => m.shared_fingerprint === null));
});

test("runRules threads the content key to its workers; a warm pool never reuses a worker across content keys", async () => {
  const { mkdtempSync, writeFileSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { WarmPool, liveWorkers, loadRules, runRules } = await import("../lib/inspector/rules.mjs");
  const rules = loadRules();
  const root = mkdtempSync(join(tmpdir(), "walk-key-"));
  const files = [];
  for (let i = 0; i < 3; i++) {
    writeFileSync(join(root, `f${i}.ts`), `export async function f${i}(p) { console.log(p.ssn); await db.from("patients").insert(p); }\n`);
    files.push({ path: `f${i}.ts` });
  }
  const opts = { key: Buffer.alloc(32, 1), frameworks: ["supabase", "nextjs"], root, workers: 1 };
  const plain = await runRules(rules, files, opts);
  assert.ok(plain.matches.length && plain.matches.every((m) => m.shared_fingerprint === null));
  const keyed = await runRules(rules, files, { ...opts, contentKey: KEY });
  assert.ok(keyed.matches.every((m) => /^[0-9a-f]{64}$/.test(m.shared_fingerprint)));
  const bare = (ms) => ms.map(({ shared_fingerprint, ...m }) => m);
  assert.deepEqual(bare(keyed.matches), bare(plain.matches));
  await assert.rejects(runRules(rules, files, { ...opts, contentKey: "nothex" }), TypeError);
  const warm = new WarmPool();
  try {
    assert.deepEqual(await runRules(rules, files, { ...opts, contentKey: KEY, warm }), keyed);
    const other = await runRules(rules, files, { ...opts, contentKey: "cd".repeat(32), warm });
    assert.equal(warm.started, 2, "another content key starts a fresh worker");
    assert.notDeepEqual(other.matches.map((m) => m.shared_fingerprint), keyed.matches.map((m) => m.shared_fingerprint));
    assert.deepEqual(await runRules(rules, files, { ...opts, warm }), plain);
    assert.equal(warm.started, 3);
  } finally { await warm.drop(); }
  assert.equal(liveWorkers(), 0);
});

test("each root's matches carry the content key of its own state file; no file or an unreadable one gives null [1a]", async () => {
  const { mkdtempSync, mkdirSync, writeFileSync, realpathSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { buildFactDocuments, checkDocument, loadRuleset } = await import("../lib/inspector/factdoc.mjs");
  const { loadRules } = await import("../lib/inspector/rules.mjs");
  const { readState, writeState } = await import("../lib/inspector/state.mjs");
  const RULESET_ID = "2026-10-20.0123abcd";
  const ruleset = { id: RULESET_ID, rules: loadRules(), queries: loadRuleset({ bundleDir: "/nonexistent", rulesetId: RULESET_ID }).queries };
  const quiet = async () => ({ status: "not_run", count: 0, reason: "service_missing", preflight: null, queries: [] });
  const quietPlatform = async () => ({ provider: null, status: "not_run", reason: "no_token", settings: {} });
  const repo = () => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), "walk-doc-")));
    writeFileSync(join(root, "package.json"), JSON.stringify({ dependencies: { next: "14.2.0", "@supabase/supabase-js": "2.0.0" } }));
    mkdirSync(join(root, "app/api/visits"), { recursive: true });
    writeFileSync(join(root, "app/api/visits/route.ts"),
      'export async function POST(p) {\n  console.log(p.ssn);\n  await db.from("patients").insert(p);\n  return Response.json({});\n}\n');
    return root;
  };
  const doc = async (root, configDir = mkdtempSync(join(tmpdir(), "walk-cfg-"))) => {
    const out = await buildFactDocuments([root], { configDir, ruleset, collectCatalog: quiet, collectPlatform: quietPlatform });
    const d = out.documents[0].document;
    assert.equal(checkDocument(d), null);
    assert.ok(d.matches.length > 0);
    return d;
  };
  const shared = (d) => d.matches.map((m) => m.shared_fingerprint);

  const none = repo();
  assert.ok(shared(await doc(none)).every((v) => v === null), "no state file: null");

  const keyed = repo();
  assert.equal(writeState(keyed, { status: "missing" }, {}, { env: {} }).written, true);
  assert.match(readState(keyed).state.content_key, /^[0-9a-f]{64}$/);
  const a = await doc(keyed), b = await doc(keyed);
  assert.ok(shared(a).every((v) => /^[0-9a-f]{64}$/.test(v)));
  assert.deepEqual(shared(b), shared(a), "two installs of one project give the same values");
  assert.notDeepEqual(b.matches.map((m) => m.fingerprint), a.matches.map((m) => m.fingerprint));

  const broken = repo();
  mkdirSync(join(broken, ".custosa"));
  writeFileSync(join(broken, ".custosa", "state.json"), "{");
  assert.ok(shared(await doc(broken)).every((v) => v === null), "an unreadable file: null");
});

test("the shipped fact schema requires shared_fingerprint on every match, null or 64 hex", () => {
  const items = FACT_SCHEMA.properties.matches.items;
  assert.ok(items.required.includes("shared_fingerprint"));
  assert.deepEqual(items.properties.shared_fingerprint, { anyOf: [{ $ref: "#/$defs/hash" }, { type: "null" }] });
});

test("the shared fingerprint takes the local path, so a path each install hashes still gives one value per project", async () => {
  const { mkdtempSync, mkdirSync, writeFileSync, realpathSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { buildFactDocuments, loadRuleset } = await import("../lib/inspector/factdoc.mjs");
  const { loadRules } = await import("../lib/inspector/rules.mjs");
  const { writeState } = await import("../lib/inspector/state.mjs");
  const RULESET_ID = "2026-10-20.0123abcd";
  const ruleset = { id: RULESET_ID, rules: loadRules(), queries: loadRuleset({ bundleDir: "/nonexistent", rulesetId: RULESET_ID }).queries };
  const quiet = async () => ({ status: "not_run", count: 0, reason: "service_missing", preflight: null, queries: [] });
  const quietPlatform = async () => ({ provider: null, status: "not_run", reason: "no_token", settings: {} });
  const root = realpathSync(mkdtempSync(join(tmpdir(), "walk-local-")));
  writeFileSync(join(root, "package.json"), JSON.stringify({ dependencies: { next: "14.2.0", "@supabase/supabase-js": "2.0.0" } }));
  mkdirSync(join(root, "app/api/123-45-6789"), { recursive: true });
  writeFileSync(join(root, "app/api/123-45-6789/route.ts"),
    'export async function POST(p) {\n  console.log(p.ssn);\n  await db.from("patients").insert(p);\n  return Response.json({});\n}\n');
  assert.equal(writeState(root, { status: "missing" }, {}, { env: {} }).written, true);
  const install = async () => (await buildFactDocuments([root], { configDir: mkdtempSync(join(tmpdir(), "walk-cfg-")),
    ruleset, collectCatalog: quiet, collectPlatform: quietPlatform })).documents[0].document;
  const [a, b] = [await install(), await install()];
  const hashedPaths = (d) => d.matches.map((m) => m.path).filter((p) => !p.includes("123-45-6789"));
  assert.ok(a.matches.length > 0 && hashedPaths(a).length === a.matches.length, "the sent path is hashed");
  assert.notDeepEqual(hashedPaths(a), hashedPaths(b), "per install");
  assert.ok(a.matches.every((m) => /^[0-9a-f]{64}$/.test(m.shared_fingerprint)));
  assert.deepEqual(b.matches.map((m) => m.shared_fingerprint), a.matches.map((m) => m.shared_fingerprint));
});

test("the walk's items are escaped before they are joined, so two different walks never join to the same string", () => {
  const cases = [["La\x1fLb"], ["La", "Lb"], ["La\\", "Lb"], ["La\\\x1fLb"], ["La\\x1fLb"], ["La\\\\x1fLb"]];
  const joined = cases.map((items) => joinWalk(items));
  assert.equal(new Set(joined).size, cases.length);
  assert.equal(joinWalk(["<string", "La b", ">"]), "<string\x1fLa b\x1f>", "text with neither character is unchanged");
  // In real code: a string holding U+001F then text shaped like a walk item is not the same as two leaves.
  const one = fp("javascript", 'f("a\x1fLb");\n'), two = fp("javascript", 'f("a" + "b");\n');
  assert.ok(one && two);
  assert.notEqual(one, two);
});

test("runRules refuses a local path that is not a non-empty string", async () => {
  const { loadRules, runRules } = await import("../lib/inspector/rules.mjs");
  const opts = { key: Buffer.alloc(32, 1), frameworks: [], workers: 1, contentKey: KEY };
  for (const local of ["", null, 7]) {
    await assert.rejects(runRules(loadRules(), [{ path: "a.ts", local, text: "f();\n" }], opts), TypeError);
  }
});

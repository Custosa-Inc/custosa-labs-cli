/* locationkind.kindAt: a location answer gets the question's E3 kind only when that construct is
 * there; every look-alike gives false (the answer is sent with "other"). The reviewer's cases, plus the true ones. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { kindAt } from "../lib/inspector/locationkind.mjs";

const key = Buffer.alloc(32, 1);
const at = (kind, path, lang, text, start, end = start) => kindAt(kind, { path, lang, text, start, end, key });
const js = `function a() {\n  return 1;\n}\n// call b() here and function c() { }\nfunction b() {\n  return 2;\n}\n/* function d() {} */\nconst s = "foo(1)";\n`;

test("look-alikes are never the expected kind", () => {
  const no = [
    ["span over the end of a and the start of b", "function", "x.js", "javascript", js, 3, 5],
    ["inside a's body, not its header", "function", "x.js", "javascript", js, 2, 2],
    ["a comment naming a function", "function", "x.js", "javascript", js, 4, 4],
    ["a comment naming a call", "call", "x.js", "javascript", js, 4, 4],
    ["a block comment", "function", "x.js", "javascript", js, 8, 8],
    ["a string holding call text", "call", "x.js", "javascript", js, 9, 9],
    [".sql line comment only", "sql_statement", "db/q.sql", null, "-- just a comment\n", 1, 1],
    [".sql block comment only", "sql_statement", "db/q.sql", null, "/* just a comment */\n", 1, 1],
    [".sql multi-line block comment", "sql_statement", "db/q.sql", null, "/*\n select 1;\n*/\n", 1, 3],
    [".sql a lone semicolon", "sql_statement", "db/q.sql", null, ";\n", 1, 1],
    ["migrations/README.md", "migration", "db/migrations/README.md", null, "# notes\n", 1, 1],
    ["migrations/helpers.js", "migration", "src/migrations/helpers.js", "javascript", "export const x = 1;\n", 1, 1],
    ["api/versions/v1.js", "migration", "src/api/versions/v1.js", "javascript", "export const x = 1;\n", 1, 1],
    ["docs/versions/changelog.md", "migration", "docs/versions/changelog.md", null, "x\n", 1, 1],
    ["a key in a .js file", "config_key", "src/config.js", "javascript", "port: 3000\n", 1, 1],
    ["a key in a .md file", "config_key", "README.md", null, "port: 3000\n", 1, 1],
    ["a YAML comment", "config_key", "app.yml", null, "# port: 3000\n", 1, 1],
    ["a YAML list item", "config_key", "app.yml", null, "- a\n", 1, 1],
    ["a YAML block scalar body", "config_key", "app.yml", null, "script: |\n  foo: bar\n", 2, 2],
    ["a TOML multi-line string body", "config_key", "a.toml", null, 'x = """\nfoo = bar\n"""\n', 2, 2],
    ["a TS type annotation", "decorator", "a.ts", "typescript", "let x: string = 'a';\n", 1, 1],
    ["a TS parameter type", "decorator", "a.ts", "typescript", "function f(a: number) { return a; }\n", 1, 1],
    ["a Python return annotation", "decorator", "a.py", "python", "def f(a: int) -> int:\n    return a\n", 1, 1],
    ["a TS interface method signature", "method", "a.ts", "typescript", "interface I {\n  m(): void;\n}\n", 2, 2],
    ["a TS abstract method", "method", "a.ts", "typescript", "abstract class A {\n  abstract m(): void;\n}\n", 2, 2],
    ["a Java method reference", "method", "A.java", "java", "class A {\n  void f() {\n    list.forEach(System.out::println);\n  }\n}\n", 3, 3],
    ["cache.get('/k', fn)", "route_handler", "a.js", "javascript", "cache.get('/k', function () { return 1; });\n", 1, 1],
    ["bus.on('/k', fn)", "route_handler", "a.js", "javascript", "bus.on('/k', function () { return 1; });\n", 1, 1],
    ["a function named DELETE in a util", "route_handler", "src/util.js", "javascript", "function DELETE() { return 1; }\n", 1, 1],
    ["obj['GET x'] = fn", "route_handler", "src/util.js", "javascript", "obj['GET x'] = function () { return 1; };\n", 1, 1],
    ["def GET in a plain class", "route_handler", "a.py", "python", "class A:\n    def GET(self):\n        return 1\n", 2, 2],
    ["middleware is never confirmed", "middleware", "a.js", "javascript", "app.use(function (req,res,next){next();});\n", 1, 1],
    ["an unknown kind", "secret", "a.js", "javascript", "x\n", 1, 1],
    ["class in a string", "class", "a.js", "javascript", "const s = 'class A {}';\n", 1, 1],
    ["ruby .class", "class", "a.rb", "ruby", "x = y.class\n", 1, 1],
    ["python class pattern", "class", "a.py", "python", "match v:\n    case Point(x=0):\n        pass\n", 2, 2],
    ["a JSX element", "call", "a.tsx", "tsx", "const e = <Foo bar={1} />;\n", 1, 1],
    ["new X()", "call", "a.js", "javascript", "const e = new Foo();\n", 1, 1],
    ["a Go func literal as method", "method", "a.go", "go", "package m\nvar f = func() {}\n", 2, 2],
    ["a decorator in a comment", "decorator", "a.py", "python", "# @login_required\nx = 1\n", 1, 1],
    // Round 6: only a function's or call's own first line; parse-tree config keys; strict migration folders.
    ["an expression-bodied arrow's body line", "function", "a.js", "javascript", "const f = (a) =>\n  db.query(a);\n", 2, 2],
    ["a Python def's first body line", "function", "a.py", "python", "def f(a):\n    return db.query(a)\n", 2, 2],
    ["a Python method body line", "method", "a.py", "python", "class A:\n    def m(self):\n        return 1\n", 3, 3],
    ["a range from line 1 that only reaches a call", "call", "a.js", "javascript", "const a = 1;\nconst b = 2;\nfoo();\n", 1, 3],
    ["a chained call's second line", "call", "a.js", "javascript", "a\n  .b()\n  .c();\n", 2, 2],
    ["a migration-named file outside migrations", "migration", "src/0001_initial.py", "python", "x=1\n", 1, 1],
    ["a site changelog", "migration", "content/changelog/changelog.yml", null, "- version: 1\n", 1, 1],
    ["a query helper under migrate/", "migration", "src/migrate/report_queries.sql", null, "select 1;\n", 1, 1],
    ["a test fixture migration", "migration", "test/fixtures/migrations/0001_broken.sql", null, "x;\n", 1, 1],
    ["a TOML table header", "config_key", "a.toml", null, "[database]\nhost = \"x\"\n", 1, 1],
    ["a TOML multi-line array element", "config_key", "a.toml", null, "args = [\n  \"--port=3000\",\n  \"a=1\",\n]\n", 3, 3],
    ["a JSON array string", "config_key", ".eslintrc.json", null, "{\n  \"extends\": [\n    \"plugin:react/recommended\"\n  ]\n}\n", 3, 3],
    ["a YAML plain scalar continuation", "config_key", "a.yml", null, "description: this goes\n  on: and on\n", 2, 2],
    ["a YAML flow sequence line", "config_key", "a.yml", null, "args: [\n  a=1,\n]\n", 2, 2],
    ["a TOML multi-line string line", "config_key", "a.toml", null, "s = \"\"\"a\nfoo = bar\"\"\"\nx = 1\n", 2, 2],
    ["an INI comment", "config_key", "a.ini", null, "; port = 1\n", 1, 1],
    ["a YAML literal under a list item", "config_key", "a.yml", null, "steps:\n  - run: |\n      FOO: bar\n", 3, 3],
    ["JSON test data", "config_key", "fixtures/patients.json", null, "{\"name\": \"x\"}\n", 1, 1],
  ];
  for (const [label, kind, path, lang, text, s, e] of no) assert.equal(at(kind, path, lang, text, s, e), false, label);
});

test("the real constructs are confirmed", () => {
  const yes = [
    ["a function's header line", "function", "src/db.ts", "typescript", "export async function save(p) {\n  await db.from('x').insert(p);\n}\n", 1, 3],
    ["app.get('/x', fn)", "route_handler", "a.js", "javascript", "app.get('/x', function (req, res) { res.send(1); });\n", 1, 1],
    ["router.post('/x', fn)", "route_handler", "a.ts", "typescript", "router.post('/x', async (req, res) => { res.send(1); });\n", 1, 1],
    ["a Next.js route export", "route_handler", "app/api/x/route.ts", "typescript", "export async function POST(req) {\n  return Response.json({});\n}\n", 1, 3],
    ["a .sql migration", "migration", "supabase/migrations/20240101_init.sql", null, "create table x (id int);\n", 1, 1],
    ["a Django migration", "migration", "app/migrations/0001_initial.py", "python", "x = 1\n", 1, 1],
    ["a Rails migration", "migration", "db/migrate/20240101120000_create.rb", "ruby", "x\n", 1, 1],
    ["a knex migration", "migration", "migrations/20240101120000_init.js", "javascript", "x\n", 1, 1],
    ["an Alembic revision", "migration", "migrations/versions/3f2a1b9c4d5e_add.py", "python", "x = 1\n", 1, 1],
    ["a Java method", "method", "A.java", "java", "class A {\n  void f() {\n  }\n}\n", 2, 2],
    ["a JS method", "method", "a.js", "javascript", "class A {\n  m() {\n    return 1;\n  }\n}\n", 2, 4],
    ["a TS decorator", "decorator", "a.ts", "typescript", "class A {\n  @Get('/x')\n  m() {}\n}\n", 2, 2],
    ["a Python decorator", "decorator", "a.py", "python", "@app.get('/x')\ndef f():\n    pass\n", 1, 1],
    ["SQL after a block comment", "sql_statement", "q.sql", null, "/* c */\nselect 1;\n", 1, 2],
    ["a key after a block scalar", "config_key", "app.yml", null, "script: |\n  foo: bar\nport: 3\n", 3, 3],
    ["a class", "class", "a.js", "javascript", "class A {}\n", 1, 1],
    ["a call", "call", "a.js", "javascript", "foo(1);\n", 1, 1],
    ["a nested function header on an outer line", "function", "a.js", "javascript", "if (x) { setTimeout(function tick() {\n  go();\n}, 1); }\n", 1, 1],
    ["a TOML key", "config_key", "a.toml", null, "[database]\nhost = \"x\"\n", 2, 2],
    ["a JSON key", "config_key", "tsconfig.json", null, "{\n  \"compilerOptions\": {}\n}\n", 2, 2],
    ["a Prisma migration", "migration", "prisma/migrations/20240101120000_init/migration.sql", null, "create table x();\n", 1, 1],
    ["a Liquibase changelog", "migration", "db/migrations/changelog.xml", null, "<databaseChangeLog>\n</databaseChangeLog>\n", 1, 1],
  ];
  for (const [label, kind, path, lang, text, s, e] of yes) assert.equal(at(kind, path, lang, text, s, e), true, label);
});

test("config_key is linear and capped: a 20k-key locale JSON and a 10k-key one answer in well under a second", async () => {
  const { CONFIG_MAX_BYTES } = await import("../lib/inspector/locationkind.mjs");
  for (const n of [10000, 20000]) {
    const big = `{\n${Array.from({ length: n }, (_, i) => `  "k${i}": "v${i}"`).join(",\n")}\n}\n`;
    // CPU time, not wall time: the scan is synchronous, and a loaded machine stretches wall time, not the work.
    const cpu = process.cpuUsage();
    const got = at("config_key", "locales/en.json", null, big, n, n);
    const { user, system } = process.cpuUsage(cpu);
    const ms = (user + system) / 1000;
    assert.ok(ms < 1000, `${n} keys used ${Math.round(ms)} ms of CPU`);
    assert.equal(got, big.length <= CONFIG_MAX_BYTES, `${n} keys`); // over the cap: other
  }
});

test("escaped triple quotes, test-named migrations, a Java method's annotation line", () => {
  assert.equal(at("config_key", "a.toml", null, 's = """a \\""" b\nfoo = bar\n"""\nx = 1\n', 2, 2), false);
  assert.equal(at("config_key", "a.toml", null, 's = """a \\""" b\nfoo = bar\n"""\nx = 1\n', 4, 4), true);
  assert.equal(at("migration", "migrations/0001_init.test.ts", "typescript", "x\n", 1, 1), false);
  assert.equal(at("migration", "migrations/0001_init.spec.js", "javascript", "x\n", 1, 1), false);
  const java = "class A {\n  @Override\n  public String toString() {\n    return \"a\";\n  }\n}\n";
  assert.equal(at("method", "A.java", "java", java, 2, 2), false);
  assert.equal(at("method", "A.java", "java", java, 3, 5), true);
});

test("JSON and JSONC keys: one linear string-aware pass; comments, trailing commas and a BOM tolerated (final round)", () => {
  const key = (path, text, line) => at("config_key", path, null, text, line, line);
  // tsconfig-like .json with a comment and a trailing comma; the same as .jsonc.
  const ts = '{\n  // options\n  "compilerOptions": { "strict": true, },\n}\n';
  assert.equal(key("tsconfig.json", ts, 3), true);
  assert.equal(key("a.jsonc", ts, 3), true);
  assert.equal(key("a.jsonc", '{\n  "$schema": "https://json.schemastore.org/x.json",\n  "name": "a"\n}\n', 3), true);
  assert.equal(key("a.jsonc", '{\n  "url": "http://x/*not-a-comment*/y" // trailing\n}\n', 2), true);
  assert.equal(key(".devcontainer/devcontainer.json", '{\n  // c\n  "image": "x"\n}\n', 3), true);
  assert.equal(key("a.json", '﻿{\n  "k": 1\n}\n', 2), true);
  // Not keys: array strings, values, a doubled comma, an unclosed comment or string or bracket.
  assert.equal(key("a.json", '{\n  "list": [\n    "a: b"\n  ]\n}\n', 3), false);
  assert.equal(key("a.json", '{\n  "k": 1,,\n}\n', 2), false);
  assert.equal(key("a.jsonc", '{\n  "k": 1 /* open\n}\n', 2), false);
  assert.equal(key("a.json", '{\n  "k": "open\n}\n', 2), false);
  assert.equal(key("a.json", '{\n  "k": [1\n}\n', 2), false);
});

test("a 250 KB .jsonc with an unclosed comment answers in under 200 ms (final round)", () => {
  const text = `{\n  "a": 1, /* ${"/* ".repeat(85000)}\n}\n`;
  // CPU time, not wall time (as above).
  const cpu = process.cpuUsage();
  assert.equal(at("config_key", "big.jsonc", null, text, 2, 2), false);
  const { user, system } = process.cpuUsage(cpu);
  const ms = (user + system) / 1000;
  assert.ok(ms < 200, `used ${Math.round(ms)} ms of CPU`);
});

test("JSON keys: an escaped newline ends a string's line, and a value followed by a colon is never a key (final check)", () => {
  // An escaped LF inside a string: the old scanner skipped the newline and reported later keys a line early.
  const escaped = '{\n"a": "x\\\n",\n\n"c": 2,\n"d": 3\n}';
  for (const line of [2, 3, 4, 5, 6]) assert.equal(at("config_key", "x.json", null, escaped, line, line), false);
  assert.equal(at("config_key", "x.json", null, '{\n"a\\\nb": 1,\n"c": 2\n}', 2, 2), false);
  // A string in value position followed by a colon is invalid JSON, not a key.
  assert.equal(at("config_key", "x.json", null, '{\n"a":\n"b":\n1\n}', 3, 3), false);
  assert.equal(at("config_key", "x.json", null, '[{"a": "b": 1}]', 1, 1), false);
  // A plain object still reports its keys.
  assert.equal(at("config_key", "x.json", null, '{\n"a": 1,\n"b": 2\n}', 3, 3), true);
});

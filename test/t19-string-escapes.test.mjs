/* captures.mjs: a table name written with an escape is read as the language reads it, or not at all. Octal escapes,
 * a code point past U+10FFFF or a lone surrogate, an unknown escape (dropped in JavaScript and Ruby, kept elsewhere),
 * \N{...} outside Python, a JavaScript line continuation, a Python u or f prefix, and Ruby %q ran in no test
 * (unescapeC lines 189 to 206, escapeMode 233, literalText 251). Each expected name is what the language's own
 * runtime makes of the literal. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { tableName, tableOf } from "../lib/inspector/captures.mjs";
import { parseSync } from "../lib/inspector/parse.mjs";

const KEY = Buffer.alloc(32, 3);
const name = (text) => tableName(KEY, text);
const tables = (lang, src, pattern) =>
  parseSync(lang, src).root().findAll({ rule: { pattern } }).map((n) => tableOf(n.getMatch("T"), KEY, lang));

test("octal escapes are read as the code point they name", () => {
  assert.deepEqual(tables("javascript", String.raw`db.from("\160atients"); db.from("pat\0");`, "db.from($T)"),
    [name("patients"), name("pat\0")]);
  assert.deepEqual(tables("python", String.raw`db.table('\160atients')`, "db.table($T)"), [name("patients")]);
  assert.deepEqual(tables("go", String.raw`package m
func F() { db.Table("\160atients") }`, { context: "func t() { $D.Table($T) }", selector: "call_expression" }), [name("patients")]);
  assert.deepEqual(tables("java", String.raw`class A { void m() { j.table("\160atients"); } }`, "j.table($T)"), [name("patients")]);
  assert.deepEqual(tables("php", String.raw`<?php DB::table("\160atients");`,
    { context: "<?php DB::table($T);", selector: "scoped_call_expression" }), [name("patients")]);
});

test("an escape past U+10FFFF or a lone surrogate names no table, never a wrong one", () => {
  assert.deepEqual(tables("javascript", String.raw`db.from("\u{110000}"); db.from("\ud800"); db.from("\u{70}atients");`,
    "db.from($T)"), [null, null, name("patients")]);
  assert.deepEqual(tables("python", String.raw`db.table('\U00110000')
db.table('\ud800')
db.table('\U00000070atients')
`, "db.table($T)"), [null, null, name("patients")]);
  assert.deepEqual(tables("go", String.raw`package m
func F() { db.Table("\U00110000"); db.Table("\U00000070atients") }`,
  { context: "func t() { $D.Table($T) }", selector: "call_expression" }), [null, name("patients")]);
  assert.deepEqual(tables("java", String.raw`class A { void m() { j.table("\uD800"); } }`, "j.table($T)"), [null]);
});

test("an unknown escape is dropped where the language drops it and kept where it is kept", () => {
  // JavaScript and Ruby read \q as q; Python, Go, PHP and Kotlin keep the backslash (or refuse the literal).
  assert.deepEqual(tables("javascript", String.raw`db.from("pat\qients"); db.from("pat\N{x}ients");`, "db.from($T)"),
    [name("patqients"), name("patN{x}ients")]);
  assert.deepEqual(tables("ruby", String.raw`x("pat\qients")`, "x($T)"), [name("patqients")]);
  assert.deepEqual(tables("python", String.raw`db.table('pat\qients')`, "db.table($T)"), [name(String.raw`pat\qients`)]);
  assert.deepEqual(tables("go", String.raw`package m
func F() { db.Table("pat\qients") }`, { context: "func t() { $D.Table($T) }", selector: "call_expression" }),
  [name(String.raw`pat\qients`)]);
  assert.deepEqual(tables("php", String.raw`<?php DB::table("pat\qients");`,
    { context: "<?php DB::table($T);", selector: "scoped_call_expression" }), [name(String.raw`pat\qients`)]);
  assert.deepEqual(tables("kotlin", String.raw`fun f() { db.from("pat\qients"); db.from("\$x") }`, "db.from($T)"),
    [name(String.raw`pat\qients`), name("$x")]);
  // A Python \N{...} name outside the short table here names no table.
  assert.deepEqual(tables("python", String.raw`db.table('pat\N{BOGUS NAME}')`, "db.table($T)"), [null]);
});

test("a line continuation, a Python u or f prefix, Ruby %q and PHP \\u{...} read as their runtimes read them", () => {
  assert.deepEqual(tables("javascript", "db.from(\"pat\\\nients\");", "db.from($T)"), [name("patients")]);
  assert.deepEqual(tables("python", "db.table(u'patients')\ndb.table(f'patients')\ndb.table(U\"pat\\x69ents\")\n", "db.table($T)"),
    [name("patients"), name("patients"), name("patients")]);
  assert.deepEqual(tables("ruby", String.raw`x(%q(pat\x69))`, "x($T)"), [name(String.raw`pat\x69`)]);
  assert.deepEqual(tables("php", String.raw`<?php DB::table("\u{70}atients");`,
    { context: "<?php DB::table($T);", selector: "scoped_call_expression" }), [name("patients")]);
});

test("Java's \\uu escape is a parse error in the grammar, so its name is unknown, never a wrong one", () => {
  // unescapeC accepts \uu0069 as Java does, but the Java grammar gives an ERROR node there, so the literal is not text.
  assert.deepEqual(tables("java", String.raw`class A { void m() { j.table("pat\uu0069ents"); j.table("patients"); } }`,
    "j.table($T)"), [null, name("patients")]);
});

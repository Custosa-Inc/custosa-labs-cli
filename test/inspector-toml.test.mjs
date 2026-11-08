/* the TOML reader (tomlparse.mjs) pinned on what it reads and what it refuses: numbers in every base, strings
 * in every form, inline and array tables, and the errors with their offsets. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseToml, TomlError } from "../lib/inspector/tomlparse.mjs";

test("numbers: decimal, hex, octal and binary integers with underscores; floats; inf and nan; out of range refused", () => {
  assert.deepEqual(parseToml("a = 1_000\nb = -7\nc = 0xdead_BEEF\nd = 0o7_5\ne = 0b1_01\nf = +0\n"),
    { a: 1000, b: -7, c: 0xdeadbeef, d: 0o75, e: 0b101, f: 0 });
  assert.deepEqual(parseToml("a = 1.5\nb = -2e3\nc = 6.0_1E-2\n"), { a: 1.5, b: -2000, c: 0.0601 });
  const special = parseToml("a = inf\nb = -inf\nc = +nan\n");
  assert.deepEqual([special.a, special.b, Number.isNaN(special.c)], [Infinity, -Infinity, true]);
  for (const bad of ["a = 9007199254740992", "a = 0x20000000000000", "a = 0b" + "1".repeat(54)]) {
    assert.throws(() => parseToml(bad), { name: "TomlError", message: "integer out of range (offset " + bad.length + ")" }, bad);
  }
  for (const bad of ["a = 0x", "a = 1__0", "a = 0o8", "a = 1.", "a = .5", "a = 0b2"]) {
    assert.throws(() => parseToml(bad), { name: "TomlError" }, bad);
  }
});

test("dates and times are kept as their text", () => {
  assert.deepEqual(parseToml("a = 1979-05-27\nb = 07:32:00.5\nc = 1979-05-27T07:32:00Z\nd = 1979-05-27 07:32:00+01:00\n"),
    { a: "1979-05-27", b: "07:32:00.5", c: "1979-05-27T07:32:00Z", d: "1979-05-27 07:32:00+01:00" });
});

test("strings: basic with escapes, literal, and both multi-line forms with up to two extra closing quotes", () => {
  assert.deepEqual(parseToml(String.raw`a = "x\ty\u00e9\U0001F600\"" ` + "\nb = 'c:\\no\\escape'\n"),
    { a: "x\ty\u00e9\u{1F600}\"", b: "c:\\no\\escape" });
  const t = 'a = """\nline1\r\nline2 \\\n   \n  joined"""\n' + 'b = """x""""\n' + 'c = """y"""""\n'
    + "d = '''\nraw \\n'''\n" + "e = '''z''''\n" + "f = '''w'''''\n";
  assert.deepEqual(parseToml(t), { a: "line1\r\nline2 joined", b: 'x"', c: 'y""', d: "raw \\n", e: "z'", f: "w''" });
  // Six closing quotes: the string ends after five and one is left over.
  assert.throws(() => parseToml('a = """y""""""\n'), { name: "TomlError", message: "expected the end of the line (offset 13)" });
  assert.throws(() => parseToml("a = '''y''''''\n"), { name: "TomlError", message: "expected the end of the line (offset 13)" });
  for (const bad of ['a = """x', "a = '''x", 'a = "\\x"', 'a = "\\uD800"', 'a = """x\\\r y"""', 'a = """\u0001"""', "a = '''\u0001'''"]) {
    assert.throws(() => parseToml(bad), { name: "TomlError" }, JSON.stringify(bad));
  }
});

test("tables: dotted and quoted keys, inline tables, arrays of tables, and redefinitions refused", () => {
  const t = [
    'title = "x"', "site.name = 'n'", 'site."my key" = 1',
    "[server]", "inline = { a = 1, b.c = [1, 2], d = {} }", "list = [ 1,", "  2, # c", "]",
    "[[fn]]", "name = 'a'", "[[fn]]", "name = 'b'", "[fn.opts]", "x = true",
  ].join("\n") + "\n";
  assert.deepEqual(parseToml(t), {
    title: "x", site: { name: "n", "my key": 1 },
    server: { inline: { a: 1, b: { c: [1, 2] }, d: {} }, list: [1, 2] },
    fn: [{ name: "a" }, { name: "b", opts: { x: true } }],
  });
  const refused = [
    ["x = { a = 1 }\nx.b = 2", "key already defined (offset 21)"],
    ["x = { a = 1 b = 2 }", "expected , or } in an inline table (offset 12)"],
    ["x = { a 1 }", "expected = (offset 8)"],
    ["a 1", "expected = (offset 2)"],
    ["[[a]]\n[a]", "table already defined (offset 9)"],
    ["a = []\n[[a]]", "key already defined (offset 12)"],
    ["x = {a = 1, }", "trailing comma in an inline table (offset 12)"],
  ];
  for (const [bad, message] of refused) assert.throws(() => parseToml(bad), { name: "TomlError", message }, JSON.stringify(bad));
  assert.ok(new TomlError("m", 3) instanceof Error);
});

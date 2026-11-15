/* locationkind.mjs jsonKeyLines: a closed block comment in a .json or .jsonc file. Only an unclosed one ran in a test
 * (lines 172 to 175: the skip and the line count across the comment). tsc --init writes tsconfig.json with a block
 * comment on almost every line, so a key after one must keep its own line, and a key inside one is no key. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { kindAt } from "../lib/inspector/locationkind.mjs";

const key = Buffer.alloc(32, 1);
/* The lines 1..n of `text` that are config keys in a file at `path`. */
const keyLines = (path, text) => {
  const n = text.split("\n").length;
  return Array.from({ length: n }, (_, i) => i + 1).filter((line) => kindAt("config_key", { path, lang: null, text, start: line, end: line, key }));
};

test("a tsc --init tsconfig: each real key on its own line; comments and commented-out keys are none", () => {
  const ts = [
    "{",
    '  "compilerOptions": {',
    "    /* Visit https://aka.ms/tsconfig to read more about this file */",
    '    "target": "es2016",                                  /* Set the JavaScript language version. */',
    '    // "lib": [],                                        /* Specify a set of bundled library files. */',
    '    "module": "commonjs",                                /* Specify what module code is generated. */',
    '    /* "rootDir": "./", */',
    '    "strict": true                                       /* Enable all strict type-checking options. */',
    "  }",
    "}",
    "",
  ].join("\n");
  for (const path of ["tsconfig.json", "tsconfig.base.jsonc"]) assert.deepEqual(keyLines(path, ts), [2, 4, 6, 8], path);
});

test("a block comment over several lines is counted, so later keys keep their lines and keys inside it are none", () => {
  const text = '{\n  "a": 1,\n  /*\n  "fake": 2,\n\n  "also": 3\n  */\n  "b": 4,\n  /* one */ /* two\n  */ "c": 5\n}\n';
  assert.deepEqual(keyLines("x.jsonc", text), [2, 8, 10]);
  // A newline right before the closing */ counts too.
  assert.deepEqual(keyLines("x.jsonc", '{\n/*\n*/\n"k": 1\n}\n'), [4]);
  // CRLF line ends count the same.
  assert.deepEqual(keyLines("x.jsonc", text.replace(/\n/g, "\r\n")), [2, 8, 10]);
});

test("a block comment between a key and its colon, or right after the brace, still leaves the key", () => {
  assert.deepEqual(keyLines("x.json", '{/**/"k": 1}'), [1]);
  assert.deepEqual(keyLines("x.json", '{\n  "k" /* note */ : 1\n}\n'), [2]);
  // The key is on the line its string starts on, even when the colon is two lines down.
  assert.deepEqual(keyLines("x.json", '{\n  "k" /*\n\n  */ : 1,\n  "m": 2\n}\n'), [2, 5]);
  // Block comments don't nest: the first */ ends one.
  assert.deepEqual(keyLines("x.jsonc", '{\n  /* a /* b */ "k": 1\n}\n'), [2]);
});

test("/*/ opens a comment and doesn't close it; a */ with no opener is not a comment", () => {
  assert.deepEqual(keyLines("x.jsonc", '{\n  /*/ "k": 1 */\n  "m": 2\n}\n'), [3]);
  assert.deepEqual(keyLines("x.jsonc", '{\n  /*/ "k": 1\n}\n'), []); // never closed: no keys at all
  assert.deepEqual(keyLines("x.jsonc", '{\n  "k": 1 */\n}\n'), []);
});

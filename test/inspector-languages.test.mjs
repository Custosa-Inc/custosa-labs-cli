/* The inspector's extension -> language table , read the same way by the walker
 * (files.mjs languageOf, a walked file's `lang`) and the parser (parse.mjs languageOf), and the fact document a small
 * tree with every once-disputed extension gives. Once the two views differed on pyi, rake, cs, jsonc, toml, tf and
 * hcl; the fact document took the walker's language, else the parser's, so it is pinned here unchanged by the merge.
 * .sql has no parser (unsupported_language).
 * Everything runs on temporary folders; the catalog and platform collectors are replaced. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { languageOf as walkLanguageOf, walk } from "../lib/inspector/files.mjs";
import { LANGUAGES, languageOf as parseLanguageOf } from "../lib/inspector/parse.mjs";
import { buildFactDocuments, loadRuleset } from "../lib/inspector/factdoc.mjs";
import { loadRules } from "../lib/inspector/rules.mjs";

// extension: language
const VIEW = {
  ts: "typescript", mts: "typescript", cts: "typescript", tsx: "tsx",
  js: "javascript", jsx: "javascript", mjs: "javascript", cjs: "javascript",
  py: "python", pyi: "python", php: "php", java: "java", kt: "kotlin",
  kts: "kotlin", go: "go", rb: "ruby", rake: "ruby", cs: "csharp", sql: "sql",
  yml: "yaml", yaml: "yaml", json: "json", jsonc: "json", toml: "toml",
  tf: "hcl", hcl: "hcl", md: null, txt: null, lock: null, gradle: null,
  // languages with no grammar (unsupported_language, never unknown_type). .h is c always.
  swift: "swift", dart: "dart", m: "objc", mm: "objc", rs: "rust", scala: "scala", sc: "scala", ex: "elixir",
  exs: "elixir", vue: "vue", svelte: "svelte", astro: "astro", c: "c", h: "c", cpp: "cpp", cc: "cpp", cxx: "cpp",
  hpp: "cpp", hh: "cpp", hxx: "cpp", lua: "lua", groovy: "groovy", clj: "clojure", cljs: "clojure", cljc: "clojure",
  erl: "erlang", hrl: "erlang", hs: "haskell", lhs: "haskell", fs: "fsharp", fsi: "fsharp", fsx: "fsharp", vb: "vbnet",
};

const temp = (prefix) => realpathSync(mkdtempSync(join(tmpdir(), prefix)));
function repo(files) {
  const root = temp("t23-lang-");
  for (const [p, t] of Object.entries(files)) {
    mkdirSync(join(root, p, ".."), { recursive: true });
    writeFileSync(join(root, p), t);
  }
  return root;
}

test("languageOf: the walker and the parser give every extension the same language", () => {
  for (const [ext, lang] of Object.entries(VIEW)) {
    for (const p of [`a.${ext}`, `src/x.y/A.${ext.toUpperCase()}`]) {
      assert.equal(walkLanguageOf(p), lang, `walker ${p}`);
      assert.equal(parseLanguageOf(p), lang, `parser ${p}`);
    }
  }
  for (const p of ["Makefile", ".py", "src/.ts", "a.", "dir.py/README"]) {
    assert.equal(walkLanguageOf(p), null, p);
    assert.equal(parseLanguageOf(p), null, p);
  }
  assert.deepEqual(LANGUAGES, ["javascript", "typescript", "tsx", "python", "go", "java", "kotlin", "ruby", "php", "csharp",
    "sql", "yaml", "json", "toml", "hcl", "swift", "dart", "objc", "rust", "scala", "elixir", "vue", "svelte", "astro", "c",
    "cpp", "lua", "groovy", "clojure", "erlang", "haskell", "fsharp", "vbnet"]);
});

const TREE = {
  "a.py": "def f():\n    return 1\n", "a.pyi": "def f() -> int: ...\n", "a.rb": "def f; end\n", "tasks/x.rake": "task :x do\nend\n",
  "a.cs": "class A {}\n", "Upper.CS": "class B {}\n", "main.tf": "resource \"x\" \"y\" {}\n", "x.hcl": "a = 1\n",
  "pyproject.toml": "[x]\na = 1\n", "tsconfig.jsonc": "{ // c\n}\n", "db/x.sql": "select 1;\n", "a.rs": "fn main() {}\n",
  "README.md": "# x\n", "a.ts": "export const x = 1;\n",
};

test("walk: a walked file's lang is the table's language", async () => {
  const res = await walk(repo(TREE));
  const got = Object.fromEntries(res.files.map((f) => [f.path, f.lang]));
  assert.deepEqual(got, {
    "README.md": null, "Upper.CS": "csharp", "a.cs": "csharp", "a.py": "python", "a.pyi": "python", "a.rb": "ruby", "a.rs": "rust",
    "a.ts": "typescript", "db/x.sql": "sql", "main.tf": "hcl", "pyproject.toml": "toml", "tasks/x.rake": "ruby",
    "tsconfig.jsonc": "json", "x.hcl": "hcl",
  });
});

test("fact document: every extension has a language, as before the merge; .sql and .rs are unsupported_language", async () => {
  const RULESET_ID = "2026-10-20.0123abcd";
  const out = await buildFactDocuments([repo(TREE)], {
    configDir: temp("t23-cfg-"),
    ruleset: { id: RULESET_ID, rules: loadRules(fileURLToPath(new URL("./fixtures/rules/", import.meta.url))),
      queries: loadRuleset({ bundleDir: "/nonexistent", rulesetId: RULESET_ID }).queries },
    collectCatalog: async () => ({ status: "not_run", count: 0, reason: "service_missing", preflight: null, queries: [] }),
    collectPlatform: async () => ({ provider: null, status: "not_run", reason: "no_token", settings: {} }),
  });
  const [{ document: doc, problem }] = out.documents;
  assert.equal(problem, null);
  assert.equal(doc.files.analyzed, 3); // a.py, a.pyi (python) and a.ts: the fixture rules' languages
  assert.deepEqual(doc.files.languages, ["python", "typescript"]);
  // A file with a language and no rules for it is unsupported_language; one with none is unknown_type.
  const unsupported = (path) => ({ path, kind: "file", reason: "unsupported_language", tracked: null });
  const unknown = (path) => ({ path, kind: "file", reason: "unknown_type", tracked: null });
  assert.deepEqual(doc.files.not_analyzed, [unknown("README.md"), unsupported("Upper.CS"), unsupported("a.cs"), unsupported("a.rb"),
    unsupported("a.rs"), unsupported("db/x.sql"), unsupported("main.tf"), unsupported("pyproject.toml"), unsupported("tasks/x.rake"),
    unsupported("tsconfig.jsonc"), unsupported("x.hcl")]);
  assert.deepEqual(doc.collection.find((c) => c.collector === "files"), { collector: "files", status: "ok", count: 14, reason: null });
  assert.deepEqual(doc.collection.find((c) => c.collector === "rules"), { collector: "rules", status: "ok", count: 2, reason: null });
});

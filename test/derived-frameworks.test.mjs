/* Frameworks derived from imports and paths, and the count of non-literal
 * require()/import() calls per language, which the core needs before a derived framework counts for coverage. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { dynamicImportsIn, scanImports } from "../lib/inspector/imports.mjs";

function tree(files) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "b31b-")));
  const list = [];
  for (const [path, text] of Object.entries(files)) {
    mkdirSync(join(root, dirname(path)), { recursive: true });
    writeFileSync(join(root, path), text);
    const ext = path.split(".").pop();
    list.push({ disk: path, path, lang: { ts: "typescript", tsx: "tsx", js: "javascript", mjs: "javascript", py: "python", go: "go" }[ext] ?? null });
  }
  return { root, list };
}
const scan = async (files, opts) => { const t = tree(files); return scanImports(t.root, t.list, opts); };

test("frameworks come from imports, normalised to their package, and from supabase paths", async () => {
  const out = await scan({
    "app/api/x/route.ts": 'import { NextResponse } from "next/server";\nimport { createClient } from "@supabase/supabase-js";\n',
    "fn/main.ts": 'import { Hono } from "npm:hono@4";\n',
    "srv/app.py": "from flask import Flask\nimport firebase_admin\n",
    "lib/util.ts": 'import x from "./x";\n// import express from "express"\n',
  });
  assert.deepEqual([...out.frameworks].sort(), ["firebase", "flask", "hono", "nextjs", "supabase"]);
  assert.deepEqual(out.dynamic, { python: 0, typescript: 0 });
  const paths = await scan({ "supabase/functions/hello/index.ts": "Deno.serve(() => new Response());\n", "pkg/supabase/migrations/1_init.sql": "" });
  assert.deepEqual([...paths.frameworks], ["supabase"]);
});

test("a non-literal require or import() is counted per language; literals are not", () => {
  const js = [
    'require("a");', "require('b');", "require(`c`);", 'import("d");', 'await import("e", { with: {} });',
    "const t = import('x').T;", 'obj.require(name);', "myimport(name);",
  ].join("\n");
  assert.equal(dynamicImportsIn(js, "javascript"), 0);
  assert.equal(dynamicImportsIn("const r = require(name);\nawait import(`./routes/${n}`);\nrequire(\n  path.join(a)\n);\n", "javascript"), 3);
  assert.equal(dynamicImportsIn("// require(name)\n/* import(x) */\n", "typescript"), 0, "comments don't count");
  assert.equal(dynamicImportsIn('import_module("a.b")\nimportlib.import_module(name)\n__import__(mod)\n__import__("os")\n', "python"), 2);
  assert.equal(dynamicImportsIn("# importlib.import_module(name)\n", "python"), 0);
});

test("the count names only languages whose every file was read; the scan reads past the last fingerprint", async () => {
  const big = "x".repeat(1_000_001);
  const out = await scan({
    "a.ts": 'import OpenAI from "openai";\n', "b.ts": "require(name);\n", "c.js": big, "d.js": 'require("express");\n', "e.go": "package main\n",
  });
  assert.deepEqual(out.dynamic, { typescript: 1 }, "javascript had an unread file: no count, so no coverage from it");
  assert.ok(out.frameworks.has("express"));
  const late = await scan({ "a.ts": 'import "next";\n' }, { until: Date.now() - 1 });
  assert.deepEqual(late.dynamic, {}, "a scan cut by its deadline counts nothing");
});

test("the fact document carries both, and the rules get the union of manifest and derived frameworks", async () => {
  const { buildFactDocuments, checkDocument } = await import("../lib/inspector/factdoc.mjs");
  const t = tree({ "app/api/x/route.ts": 'import { NextResponse } from "next/server";\nexport async function GET() { return NextResponse.json({}); }\n',
    "package.json": JSON.stringify({ dependencies: { express: "4.0.0" } }) });
  let got = null;
  const runRules = async (_rules, _files, opts) => { got = opts.frameworks;
    return { matches: [], links: [], notAnalyzed: [], analyzed: 1, analyzedPaths: ["app/api/x/route.ts"], languages: ["typescript"], status: "ok", count: 0 }; };
  const out = await buildFactDocuments([t.root], { configDir: mkdtempSync(join(tmpdir(), "b31b-cfg-")), runRules,
    ruleset: { id: "2026-10-20.0123abcd", rules: [], queries: [] },
    collectCatalog: async () => ({ status: "not_run", count: 0, reason: "service_missing", preflight: null, queries: [] }),
    collectPlatform: async () => ({ provider: null, status: "not_run", reason: "no_token", settings: {} }) });
  const doc = out.documents[0].document;
  assert.deepEqual(doc.files.frameworks, ["express"]);
  assert.deepEqual(doc.files.derived_frameworks, ["nextjs"]);
  assert.deepEqual(doc.files.imports_dynamic, { typescript: 0 });
  assert.deepEqual([...got].sort(), ["express", "nextjs"]);
  assert.equal(checkDocument(doc), null);
});

test("design v3 2.3.6 point 8, planted: a second router behind a non-literal require is counted, so the core holds", async () => {
  // A no-manifest Next.js app whose route handlers are controlled, and a javascript server that loads another router
  // by a computed path. The fact document must carry the derived nextjs and javascript's count of 1: with that, the
  // core counts nextjs for typescript only, javascript stays uncovered, and nothing passes on it (core
  // test_b31b_derived.py, the planted negative).
  const { buildFactDocuments, checkDocument } = await import("../lib/inspector/factdoc.mjs");
  const t = tree({
    "app/api/notes/route.ts": 'import { NextResponse } from "next/server";\nexport async function GET() { return NextResponse.json({}); }\n',
    "server.js": 'const routes = process.env.ROUTES || "./legacy";\nconst router = require(routes);\nmodule.exports = router;\n',
    "legacy/index.js": "module.exports = (req, res) => res.end(String(req.query.id));\n",
  });
  const runRules = async () => ({ matches: [], links: [], notAnalyzed: [], analyzed: 3,
    analyzedPaths: ["app/api/notes/route.ts", "legacy/index.js", "server.js"], languages: ["javascript", "typescript"], status: "ok", count: 0 });
  const out = await buildFactDocuments([t.root], { configDir: mkdtempSync(join(tmpdir(), "b31b-cfg-")), runRules,
    ruleset: { id: "2026-10-20.0123abcd", rules: [], queries: [] },
    collectCatalog: async () => ({ status: "not_run", count: 0, reason: "service_missing", preflight: null, queries: [] }),
    collectPlatform: async () => ({ provider: null, status: "not_run", reason: "no_token", settings: {} }) });
  const doc = out.documents[0].document;
  assert.deepEqual(doc.files.frameworks, []);
  assert.deepEqual(doc.files.derived_frameworks, ["nextjs"]);
  assert.deepEqual(doc.files.imports_dynamic, { javascript: 1, typescript: 0 });
  assert.equal(checkDocument(doc), null);
});

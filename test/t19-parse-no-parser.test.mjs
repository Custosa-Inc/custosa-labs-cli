/* parse.mjs when a parser is missing: no @ast-grep/napi binding at all, a language package that isn't installed, one
 * with no parser for this platform, and one whose parser was built at install time (parser.so at its root). parse.mjs
 * resolves its packages next to itself (createRequire), so each case copies it into a temp folder with its own
 * node_modules and reads it in a child process: the real binding registers languages once per process. Not here: a
 * parser.so that won't load. @ast-grep/napi panics on it and the process aborts, so the catch around
 * registerDynamicLanguage never runs (T19-P2-C251). Temp folders only. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const PARSE = fileURLToPath(new URL("../lib/inspector/parse.mjs", import.meta.url));
const NAPI = dirname(require.resolve("@ast-grep/napi/package.json"));
const PYTHON = dirname(require.resolve("@ast-grep/lang-python/package.json"));
const PLATFORM = { darwin: "macOS", linux: "Linux", win32: "Windows" }[process.platform];
const ARCH = { x64: "X64", arm64: "ARM64" }[process.arch];
const musl = process.platform === "linux" && !process.report.getReport().header.glibcVersionRuntime;
const PREBUILD = PLATFORM && ARCH && !musl ? join(PYTHON, "prebuilds", `prebuild-${PLATFORM}-${ARCH}`, "parser.so") : null;

/* A temp folder holding lib/parse.mjs (a copy) and node_modules/@ast-grep/<name> for each entry of `packages`: true
 * links the real @ast-grep/napi, an object makes a package folder with those files. */
function copyOfParse(packages = {}) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "t19-parse-")));
  mkdirSync(join(root, "lib"));
  copyFileSync(PARSE, join(root, "lib", "parse.mjs"));
  for (const [name, files] of Object.entries(packages)) {
    const dir = join(root, "node_modules", "@ast-grep", name);
    mkdirSync(dirname(dir), { recursive: true });
    if (files === true) { symlinkSync(NAPI, dir, "junction"); continue; }
    mkdirSync(dir);
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: `@ast-grep/${name}`, version: "0.0.1" }));
    for (const [file, from] of Object.entries(files)) {
      mkdirSync(dirname(join(dir, file)), { recursive: true });
      if (Buffer.isBuffer(from)) writeFileSync(join(dir, file), from); else copyFileSync(from, join(dir, file));
    }
  }
  return root;
}

/* What the copy reports, read in a child process. */
function report(root) {
  const script = `
    const p = await import(${JSON.stringify(new URL("lib/parse.mjs", `file://${root.replaceAll("\\", "/")}/`).href)});
    const thrown = () => { try { p.engine(); return null; } catch (e) { return { code: e.code, message: e.message }; } };
    const reasons = Object.fromEntries(p.LANGUAGES.map((l) => [l, p.unsupportedReason(l)]));
    let parsed = null;
    if (p.isSupported("python")) parsed = p.parseCode("python", "x = 1\\n").root.kind();
    console.log(JSON.stringify({ available: p.engineAvailable(), version: p.ENGINE_VERSION, first: thrown(),
      second: thrown(), reasons, parsed }));`;
  return JSON.parse(execFileSync(process.execPath, ["--input-type=module", "-e", script], { cwd: root, encoding: "utf8" }));
}
const notInstalled = (lang) => `@ast-grep/lang-${lang} is not installed`;

test("no @ast-grep/napi: engine() throws ENGINE_UNAVAILABLE every time, and no language has a parser", () => {
  const r = report(copyOfParse());
  assert.equal(r.available, false);
  assert.equal(r.version, "0.0.0");
  const unavailable = { code: "ENGINE_UNAVAILABLE", message: "@ast-grep/napi has no binding for this platform" };
  assert.deepEqual(r.first, unavailable);
  assert.deepEqual(r.second, unavailable);
  for (const [lang, reason] of Object.entries(r.reasons)) assert.equal(reason, unavailable.message, lang);
});

test("napi but no language package: the built-in languages parse, each other one says it isn't installed", () => {
  const r = report(copyOfParse({ napi: true }));
  assert.equal(r.available, true);
  assert.equal(r.first, null);
  for (const lang of ["javascript", "typescript", "tsx"]) assert.equal(r.reasons[lang], null, lang);
  for (const lang of ["python", "php", "java", "kotlin", "go", "ruby", "yaml", "json"]) assert.equal(r.reasons[lang], notInstalled(lang));
  assert.equal(r.reasons.rust, "no parser in this build");
  assert.equal(r.parsed, null);
});

test("a language package with no parser for this platform says so, with the platform", () => {
  const r = report(copyOfParse({ napi: true, "lang-python": { "prebuilds/prebuild-Nowhere-X64/parser.so": Buffer.from("x") } }));
  assert.equal(r.reasons.python, `@ast-grep/lang-python has no parser for ${process.platform}-${process.arch}${musl ? " (musl)" : ""}`);
  assert.equal(r.reasons.php, notInstalled("php"));
});

test("a parser built at install time (parser.so at the package root) is used when there is no prebuild", { skip: !PREBUILD }, () => {
  const r = report(copyOfParse({ napi: true, "lang-python": { "parser.so": PREBUILD } }));
  assert.equal(r.reasons.python, null);
  assert.equal(r.parsed, "module");
  assert.equal(r.reasons.php, notInstalled("php"));
});

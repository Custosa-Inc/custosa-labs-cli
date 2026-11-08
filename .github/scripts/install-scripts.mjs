#!/usr/bin/env node
/* Allowlisted install scripts. CI installs with `npm ci --ignore-scripts` (or `npm install
 * --ignore-scripts` for the packed tarball), then runs this:
 *
 *   node .github/scripts/install-scripts.mjs <project dir>
 *
 * It finds every installed package that declares a preinstall, install or postinstall script (or has a binding.gyp,
 * which npm would build), fails if any is not on ALLOW, then runs only the allowlisted ones with `npm rebuild`, and
 * finally checks the native pieces load: @ast-grep/napi and each @ast-grep/lang-* parser.
 *
 * Why these: @ast-grep/napi ships its native binary as per-platform optionalDependencies (@ast-grep/napi-<os>-<arch>),
 * which npm installs without running any script. The @ast-grep/lang-* packages carry a postinstall
 * (@ast-grep/setup-lang) that only checks for a prebuilt parser.so (present for macOS x64/arm64, Linux x64/arm64 glibc
 * and Windows x64) and otherwise tries a tree-sitter build from source. Adding a package here is a reviewed change. */
import { spawnSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { join, resolve } from "node:path";

const ALLOW = new Set([
  "@ast-grep/lang-go",
  "@ast-grep/lang-java",
  "@ast-grep/lang-json",
  "@ast-grep/lang-kotlin",
  "@ast-grep/lang-php",
  "@ast-grep/lang-python",
  "@ast-grep/lang-ruby",
  "@ast-grep/lang-yaml",
]);
const HOOKS = ["preinstall", "install", "postinstall"];

const project = process.argv[2] && resolve(process.argv[2]);
if (!project || process.argv.length !== 3) { console.error("usage: node install-scripts.mjs <project dir>"); process.exit(2); }

/* Every package folder under node_modules, nested ones included. */
function* packages(nm) {
  if (!existsSync(nm)) return;
  for (const e of readdirSync(nm, { withFileTypes: true })) {
    if (!e.isDirectory() || e.name.startsWith(".")) continue;
    const dir = join(nm, e.name);
    if (e.name.startsWith("@")) {
      for (const s of readdirSync(dir, { withFileTypes: true })) if (s.isDirectory()) yield* one(join(dir, s.name));
    } else yield* one(dir);
  }
}
function* one(dir) {
  yield dir;
  yield* packages(join(dir, "node_modules"));
}

const withScripts = new Map(); // name -> [dir]
for (const dir of packages(join(project, "node_modules"))) {
  let pkg;
  try { pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf8")); } catch { continue; }
  const hooks = HOOKS.filter((h) => pkg.scripts?.[h]);
  if (!hooks.length && existsSync(join(dir, "binding.gyp"))) hooks.push("binding.gyp");
  if (!hooks.length) continue;
  if (!withScripts.has(pkg.name)) withScripts.set(pkg.name, []);
  withScripts.get(pkg.name).push(`${dir} (${hooks.join(", ")})`);
}

const unknown = [...withScripts.keys()].filter((n) => !ALLOW.has(n));
if (unknown.length) {
  console.error("Packages with install scripts that are not on the allowlist (.github/scripts/install-scripts.mjs):");
  for (const n of unknown) for (const d of withScripts.get(n)) console.error(`  ${n}: ${d}`);
  process.exit(1);
}
const run = [...withScripts.keys()].sort();
console.log(`install scripts found: ${run.length ? run.join(", ") : "none"}`);
for (const n of ALLOW) if (!withScripts.has(n)) console.log(`note: allowlisted ${n} is not installed or has no install script`);

if (run.length) {
  const r = spawnSync("npm", ["rebuild", ...run, "--ignore-scripts=false", "--foreground-scripts"], {
    cwd: project, stdio: "inherit", shell: process.platform === "win32",
  });
  if (r.status !== 0) { console.error(`npm rebuild of the allowlisted packages failed (exit ${r.status})`); process.exit(1); }
}

/* The native pieces must load from the project's own node_modules. */
const custosaDir = existsSync(join(project, "node_modules", "custosa", "package.json")) ? join(project, "node_modules", "custosa") : project;
const reqFrom = createRequire(join(custosaDir, "package.json"));
try {
  const napi = reqFrom("@ast-grep/napi");
  if (typeof napi.parse !== "function" && typeof napi.registerDynamicLanguage !== "function") throw new Error("unexpected exports");
  console.log("ok   @ast-grep/napi native binary loads");
} catch (err) { console.error(`FAIL @ast-grep/napi does not load: ${err.message}`); process.exit(1); }
let bad = 0;
for (const name of ALLOW) {
  try {
    const lang = reqFrom(name);
    const p = lang.libraryPath;
    if (!existsSync(p)) throw new Error(`no parser at ${p}`);
    console.log(`ok   ${name}: ${p.slice(p.indexOf("prebuilds") >= 0 ? p.indexOf("prebuilds") : 0)}`);
  } catch (err) { bad += 1; console.error(`FAIL ${name}: ${err.message}`); }
}
process.exit(bad ? 1 : 0);

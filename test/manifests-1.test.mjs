/* files.manifests lists package manifests and lockfiles by
 * ecosystem, from walk paths only. No file is opened: the keys are exactly ecosystem, count and paths, and the paths
 * are sent paths. Absent when a skipped folder could hide a manifest or the walk stopped early. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { ECOSYSTEMS, MANIFEST_PATHS_MAX, ecosystemOf, manifestsOf } from "../lib/inspector/manifests.mjs";
import { FACT_SCHEMA } from "../lib/inspector/schema.mjs";

const same = (p) => p;
const walk = (paths, notAnalyzed = []) => ({ files: paths.map((path) => ({ path })), notAnalyzed });

test("the ecosystems are the fact schema's enum, in its order, and the bounds match", () => {
  const field = FACT_SCHEMA.properties.files.properties.manifests;
  assert.deepEqual(ECOSYSTEMS, field.items.properties.ecosystem.enum);
  assert.equal(field.maxItems, ECOSYSTEMS.length);
  assert.equal(field.items.properties.paths.maxItems, MANIFEST_PATHS_MAX);
  assert.deepEqual(Object.keys(field.items.properties).sort(), ["count", "ecosystem", "paths"]);
});

test("names map to their ecosystem, patterns on the basename or the path", () => {
  const cases = {
    "yarn.lock": "npm", "web/bun.lockb": "npm", "requirements-dev.txt": "pip", "api/requirements.in": "pip",
    "x.gemspec": "bundler", "go.work.sum": "gomod", "gradle/libs.versions.toml": "gradle", "a/gradle/libs.versions.toml": "gradle",
    "Cargo.lock": "cargo", "src/App/App.csproj": "nuget", "Package.resolved": "swiftpm", "pubspec.lock": "pub",
    "pkg.cabal": "cabal", "deps.edn": "clojure", "infra/.terraform.lock.hcl": "terraform", "chart/Chart.lock": "helm",
    "deno.jsonc": "deno", "environment.yml": "conda", "Gopkg.lock": "dep", "x-1.0-1.rockspec": "luarocks",
  };
  for (const [p, eco] of Object.entries(cases)) assert.equal(ecosystemOf(p), eco, p);
  for (const p of ["libs.versions.toml", "my-requirements.txt", "package.json.bak", "Dockerfile", ".github/workflows/ci.yml",
    "docs/requirements.md", "cargo.toml"]) assert.equal(ecosystemOf(p), null, p);
});

test("every match is listed by ecosystem, sorted, with skipped files and sent paths", () => {
  const got = manifestsOf(walk(["src/a.ts", "package.json", "docs/package.json", "Cargo.toml", "apps/web/yarn.lock"],
    [{ kind: "file", path: "big/pnpm-lock.yaml", reason: "too_large", tracked: null }]), (p) => `s/${p}`, null);
  assert.deepEqual(got, [
    { ecosystem: "npm", count: 4, paths: ["s/apps/web/yarn.lock", "s/big/pnpm-lock.yaml", "s/docs/package.json", "s/package.json"] },
    { ecosystem: "cargo", count: 1, paths: ["s/Cargo.toml"] },
  ]);
  for (const e of got) assert.deepEqual(Object.keys(e), ["ecosystem", "count", "paths"]);
  assert.deepEqual(manifestsOf(walk(["src/a.ts"]), same, null), []);
});

test("paths stop at the cap and count holds them all", () => {
  const paths = Array.from({ length: 25 }, (_, i) => `p${String(i).padStart(2, "0")}/go.mod`);
  const [e] = manifestsOf(walk(paths), same, null);
  assert.equal(e.count, 25);
  assert.deepEqual(e.paths, paths.slice(0, MANIFEST_PATHS_MAX));
});

test("absent when the walk could hide a manifest", () => {
  const dir = (path, reason, tracked) => ({ kind: "directory", path, reason, tracked });
  for (const gap of ["file_limit", "item_limit", "not_permitted"]) assert.equal(manifestsOf(walk(["package.json"]), same, gap), null, gap);
  assert.equal(manifestsOf(walk(["package.json"], [dir("secret", "unreadable", "yes")]), same, null), null);
  assert.equal(manifestsOf(walk(["package.json"], [dir("node_modules", "excluded_directory", "not_checked")]), same, null), null);
  // an untracked dependency folder or the VCS folder hides nothing of the app's
  assert.equal(manifestsOf(walk(["package.json"], [dir("node_modules", "excluded_directory", "no"), dir(".git", "excluded_directory", "yes")]), same, null).length, 1);
});

function tree(files) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "b56f-repo-")));
  for (const [p, t] of Object.entries(files)) {
    mkdirSync(dirname(join(root, p)), { recursive: true });
    writeFileSync(join(root, p), t);
  }
  return root;
}

test("the fact document carries files.manifests and passes its schema", async () => {
  const { buildFactDocuments, checkDocument } = await import("../lib/inspector/factdoc.mjs");
  const root = tree({ "package.json": "{}\n", "yarn.lock": "\n", "docs/package.json": "{}\n", "Cargo.toml": "[package]\n",
    "src/index.js": "export const a = 1;\n" });
  const runRules = async () => ({ matches: [], links: [], notAnalyzed: [], analyzed: 1, analyzedPaths: ["src/index.js"],
    languages: ["javascript"], status: "ok", count: 0 });
  const out = await buildFactDocuments([root], { configDir: mkdtempSync(join(tmpdir(), "b56f-cfg-")), runRules,
    ruleset: { id: "2026-10-20.0123abcd", rules: [], queries: [] },
    collectCatalog: async () => ({ status: "not_run", count: 0, reason: "service_missing", preflight: null, queries: [] }),
    collectPlatform: async () => ({ provider: null, status: "not_run", reason: "no_token", settings: {} }) });
  const doc = out.documents[0].document;
  assert.deepEqual(doc.files.manifests, [
    { ecosystem: "npm", count: 3, paths: ["docs/package.json", "package.json", "yarn.lock"] },
    { ecosystem: "cargo", count: 1, paths: ["Cargo.toml"] },
  ]);
  assert.equal(checkDocument(doc), null);
});

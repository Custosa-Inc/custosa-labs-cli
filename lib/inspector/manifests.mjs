/* Package manifests and lockfiles by ecosystem (fact schema files.manifests, rule_bundle.md section 9).
 *
 * manifestsOf(walkResult, sent, gap) -> [{ecosystem, count, paths}] | null
 *   Reads walk paths only: the files the walk listed, and the file entries it skipped. No file is opened, and no
 *   contents or sizes are sent. Every match is listed, docs, examples, tests and vendored folders included: which count
 *   is the evaluator's call. `sent(path)` gives a path as the document sends it (sentPath); `gap` is factdoc's walkGap. One entry per ecosystem
 *   with at least one match, in the order of ECOSYSTEMS; paths are the first MANIFEST_PATHS_MAX by sent path, and
 *   count holds them all. null when a skipped directory could hide a manifest (the test fingerprints use) or the walk
 *   stopped early (file_limit, item_limit, a symlink it didn't follow): then the field is sent absent, never empty. */
import { hidesManifest } from "./frameworks.mjs";

export const MANIFEST_PATHS_MAX = 20;
// Exact basenames, or a pattern tested on the whole path (a basename pattern starts at a "/" or the path's start). The ecosystems are the fact
// schema's enum, in its order (test/manifests-1.test.mjs checks both against contracts/fact_document.schema.json).
const NAMES = [
  ["npm", ["package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", ".yarnrc.yml", "pnpm-lock.yaml",
    "pnpm-workspace.yaml", "bun.lock", "bun.lockb"]],
  ["composer", ["composer.json", "composer.lock"]],
  ["pip", [/(?:^|\/)requirements[^/]*\.(?:txt|in)$/, /(?:^|\/)requirements\/[^/]*\.(?:txt|in)$/, "Pipfile", "Pipfile.lock", "pyproject.toml", "poetry.lock", "uv.lock",
    "pdm.lock", "setup.py", "setup.cfg",
    // requirements.d/ (direct children), dev- and test-requirements.txt, and PEP 751 locks
    /(?:^|\/)requirements\.d\/[^/]*\.(?:txt|in)$/, "dev-requirements.txt", "test-requirements.txt", "pylock.toml",
    /(?:^|\/)pylock\.[^/]*\.toml$/]],
  ["bundler", ["Gemfile", "Gemfile.lock", "gems.rb", "gems.locked", /\.gemspec$/]],
  ["gomod", ["go.mod", "go.sum", "go.work", "go.work.sum"]],
  ["maven", ["pom.xml"]],
  ["gradle", ["build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts", "gradle.lockfile",
    /(?:^|\/)gradle\/libs\.versions\.toml$/]],
  ["cargo", ["Cargo.toml", "Cargo.lock"]],
  ["nuget", [/\.(?:cs|fs|vb)proj$/, "packages.config", "packages.lock.json", "Directory.Packages.props",
    "paket.dependencies", "paket.lock"]],
  ["swiftpm", ["Package.swift", "Package.resolved"]],
  ["cocoapods", ["Podfile", "Podfile.lock"]],
  ["carthage", ["Cartfile", "Cartfile.resolved"]],
  ["pub", ["pubspec.yaml", "pubspec.lock"]],
  ["hex", ["mix.exs", "mix.lock"]],
  ["rebar", ["rebar.config", "rebar.lock"]],
  ["cabal", [/\.cabal$/, "cabal.project", "cabal.project.freeze"]],
  ["stack", ["stack.yaml", "stack.yaml.lock"]],
  ["leiningen", ["project.clj"]],
  ["clojure", ["deps.edn"]],
  ["sbt", ["build.sbt"]],
  ["conan", ["conanfile.txt", "conanfile.py", "conan.lock"]],
  ["vcpkg", ["vcpkg.json"]],
  ["luarocks", [/\.rockspec$/]],
  ["terraform", [".terraform.lock.hcl"]],
  ["helm", ["Chart.yaml", "Chart.lock"]],
  ["deno", ["deno.json", "deno.jsonc", "deno.lock"]],
  ["conda", ["environment.yml", "environment.yaml"]],
  ["renv", ["renv.lock"]],
  ["julia", ["Project.toml", "Manifest.toml", /(?:^|\/)Manifest-v[^/]*\.toml$/, "JuliaProject.toml", "JuliaManifest.toml",
    /(?:^|\/)JuliaManifest-v[^/]*\.toml$/]],
  ["dep", ["Gopkg.toml", "Gopkg.lock"]],
  // a bare WORKSPACE too, since a legacy Bazel repo may have only that
  ["cpan", ["cpanfile", "cpanfile.snapshot", "Makefile.PL", "Build.PL", "META.json", "dist.ini"]],
  ["pixi", ["pixi.toml", "pixi.lock"]],
  ["nix", ["flake.nix", "flake.lock", "default.nix", "shell.nix"]],
  ["bazel", ["MODULE.bazel", "MODULE.bazel.lock", "WORKSPACE", "WORKSPACE.bazel", "WORKSPACE.bzlmod"]],
  ["shards", ["shard.yml", "shard.lock"]],
  // ecosystems that passed beside a fully read npm app; each holds unread
  ["bower", ["bower.json"]],
  ["elm", ["elm.json"]],
  ["zig", ["build.zig.zon"]],
  ["opam", ["dune-project", /\.opam$/]],
  ["gleam", ["gleam.toml"]],
  ["nimble", [/\.nimble$/]],
  ["dub", ["dub.json", "dub.sdl", "dub.selections.json"]],
  ["cran", ["DESCRIPTION", "packrat.lock"]],
];
export const ECOSYSTEMS = Object.freeze(NAMES.map(([eco]) => eco));
// The name rules as data, for the core's cross-check against rule_bundle.md section 9 (test_b56f_manifests.py).
export const MANIFEST_NAMES = Object.freeze(NAMES.map(([eco, rules]) => [eco, rules.map((r) => (typeof r === "string" ? { name: r } : { re: r.source }))]));

/** The ecosystem a path's manifest or lockfile belongs to, or null. A gradle catalog is matched on its path. */
export function ecosystemOf(path) {
  const name = path.slice(path.lastIndexOf("/") + 1);
  for (const [eco, rules] of NAMES) {
    for (const r of rules) if (typeof r === "string" ? r === name : r.test(path)) return eco;
  }
  return null;
}

// The walk gaps that could hide a manifest (factdoc's walkGap): beyond these, each skipped directory is checked.
const HIDING_GAPS = new Set(["file_limit", "item_limit", "not_permitted"]);

export function manifestsOf(walk, sent, gap) {
  const skipped = walk?.notAnalyzed ?? [];
  if (!walk || HIDING_GAPS.has(gap) || skipped.some(hidesManifest)) return null;
  const found = new Map();
  for (const p of [...(walk.files ?? []).map((f) => f.path), ...skipped.filter((e) => e.kind === "file").map((e) => e.path)]) {
    const eco = ecosystemOf(p);
    if (!eco) continue;
    if (!found.has(eco)) found.set(eco, new Set());
    found.get(eco).add(sent(p));
  }
  return ECOSYSTEMS.filter((eco) => found.has(eco)).map((eco) => {
    const paths = [...found.get(eco)].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    return { ecosystem: eco, count: paths.length, paths: paths.slice(0, MANIFEST_PATHS_MAX) };
  });
}

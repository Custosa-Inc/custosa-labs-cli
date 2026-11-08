/* five more ecosystems, requirements/ files and Julia's
 * versioned manifest. Each name goes to its own ecosystem; near names go nowhere. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { ECOSYSTEMS, ecosystemOf } from "../lib/inspector/manifests.mjs";

const SCHEMA = JSON.parse(readFileSync(new URL("../lib/inspector/contracts/fact_document.schema.json", import.meta.url), "utf8"));

test("the next five ecosystems follow the first thirty", () => {
  assert.deepEqual(ECOSYSTEMS.slice(30, 35), ["cpan", "pixi", "nix", "bazel", "shards"]);  // eight more follow
  assert.deepEqual([...ECOSYSTEMS], SCHEMA.properties.files.properties.manifests.items.properties.ecosystem.enum);
  assert.equal(SCHEMA.properties.files.properties.manifests.maxItems, ECOSYSTEMS.length);
});

test("each new name goes to its ecosystem", () => {
  const cases = {
    "cpanfile": "cpan", "svc/cpanfile.snapshot": "cpan", "Makefile.PL": "cpan", "lib/Build.PL": "cpan",
    "pixi.toml": "pixi", "env/pixi.lock": "pixi",
    "flake.nix": "nix", "flake.lock": "nix",
    "MODULE.bazel": "bazel", "MODULE.bazel.lock": "bazel", "WORKSPACE": "bazel", "WORKSPACE.bazel": "bazel",
    "tools/WORKSPACE.bzlmod": "bazel",
    "shard.yml": "shards", "shard.lock": "shards",
    "requirements/base.txt": "pip", "api/requirements/dev.in": "pip", "requirements-dev.txt": "pip",
    "Manifest-v1.11.toml": "julia", "pkg/Manifest-v1.10.toml": "julia", "Manifest.toml": "julia",
  };
  assert.deepEqual(Object.fromEntries(Object.keys(cases).map((p) => [p, ecosystemOf(p)])), cases);
});

test("near names go nowhere", () => {
  for (const p of ["Makefile", "cpanfile.txt", "pixi.json", "flake.nix.bak", "WORKSPACE.md", "workspace", "shard.yaml",
    "requirements/sub/dev.txt", "requirements/notes.md", "Manifest-1.11.toml", "MyManifest-v1.toml", "BUILD.bazel"]) {
    assert.equal(ecosystemOf(p), null, p);
  }
});

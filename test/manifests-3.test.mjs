/* Eight more ecosystems, and the names the edited ecosystems missed: Julia's
 * JuliaProject.toml and JuliaManifest*.toml, nix's default.nix and shell.nix, cpan's META.json and dist.ini, and pip's
 * dev- and test-requirements.txt, requirements.d/ and pylock.toml. Each name goes to its own ecosystem; near names go
 * nowhere. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { ECOSYSTEMS, ecosystemOf } from "../lib/inspector/manifests.mjs";

const SCHEMA = JSON.parse(readFileSync(new URL("../lib/inspector/contracts/fact_document.schema.json", import.meta.url), "utf8"));

test("the eight new ecosystems close the schema's enum, in order", () => {
  assert.deepEqual(ECOSYSTEMS.slice(-8), ["bower", "elm", "zig", "opam", "gleam", "nimble", "dub", "cran"]);
  assert.deepEqual([...ECOSYSTEMS], SCHEMA.properties.files.properties.manifests.items.properties.ecosystem.enum);
  assert.equal(SCHEMA.properties.files.properties.manifests.maxItems, ECOSYSTEMS.length);
});

test("each new name goes to its ecosystem", () => {
  const cases = {
    "bower.json": "bower", "elm.json": "elm", "build.zig.zon": "zig", "dune-project": "opam", "lib/core.opam": "opam",
    "gleam.toml": "gleam", "app.nimble": "nimble", "dub.json": "dub", "dub.sdl": "dub", "dub.selections.json": "dub",
    "DESCRIPTION": "cran", "packrat/packrat.lock": "cran",
    "JuliaProject.toml": "julia", "JuliaManifest.toml": "julia", "JuliaManifest-v1.11.toml": "julia",
    "default.nix": "nix", "shell.nix": "nix", "META.json": "cpan", "dist.ini": "cpan",
    "dev-requirements.txt": "pip", "test-requirements.txt": "pip", "requirements.d/base.txt": "pip",
    "api/requirements.d/dev.in": "pip", "pylock.toml": "pip", "pylock.dev.toml": "pip",
  };
  assert.deepEqual(Object.fromEntries(Object.keys(cases).map((p) => [p, ecosystemOf(p)])), cases);
});

test("near names go nowhere", () => {
  for (const p of ["bower.yml", "elm.js", "build.zig", "dune", "opam", "gleam.json", "nimble", "dub.yaml",
    "DESCRIPTION.md", "packrat.json", "MyJuliaProject.toml", "release.nix", "META.yml", "dist.toml",
    "prod-requirements.txt", "requirements.d/sub/x.txt", "pylock.json"]) {
    assert.equal(ecosystemOf(p), null, p);
  }
});

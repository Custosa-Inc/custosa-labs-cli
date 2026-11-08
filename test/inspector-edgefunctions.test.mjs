/* The edge_functions collector's look for a supabase/config.toml git ignores (edgefunctions.mjs ignoredConfigs). The
 * end-to-end case (one ignored config) is in inspector-factdoc.test.mjs, review 10. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { collectEdgeFunctions, MAX_IGNORED_PROBES } from "../lib/inspector/edgefunctions.mjs";

const KEY = Buffer.alloc(32, 7);

/* A walk that listed one file in each of n folders (d0/a.ts ... d<n-1>/a.ts). The files needn't exist: the look only
 * runs lstat on <folder>/supabase/config.toml. */
const walkOver = (n) => ({ files: Array.from({ length: n }, (_, i) => ({ path: `d${i}/a.ts` })), notAnalyzed: [] });

test("a git-ignored config.toml in the last folder the look reaches is found", async () => {
  const root = mkdtempSync(join(tmpdir(), "custosa-edge-"));
  const last = `d${MAX_IGNORED_PROBES - 2}`; // the root is probed first, then d0, d1, ...
  mkdirSync(join(root, last, "supabase"), { recursive: true });
  writeFileSync(join(root, last, "supabase", "config.toml"), "[functions.f]\n");
  const out = await collectEdgeFunctions(root, walkOver(MAX_IGNORED_PROBES - 1), { key: KEY, filesStatus: "ok" });
  assert.deepEqual(out.edge, { status: "failed", reason: "ignore_unverified", items: [] });
  assert.deepEqual(out.notAnalyzed.map((e) => [e.path, e.reason]), [[`${last}/supabase/config.toml`, "ignored_unverified"]]);
  assert.equal(out.ignored, true);
});

test("past the look's limit, edge_functions is unverified, never not_configured", async () => {
  // More folders than the look probes: one it never reached could hold a config git ignores.
  const root = mkdtempSync(join(tmpdir(), "custosa-edge-"));
  const out = await collectEdgeFunctions(root, walkOver(MAX_IGNORED_PROBES), { key: KEY, filesStatus: "ok" });
  assert.deepEqual(out.edge, { status: "failed", reason: "ignore_unverified", items: [] });
  assert.deepEqual(out.notAnalyzed, []);
  // The files collector keeps its status: the walk itself saw every file it listed.
  assert.notEqual(out.ignored, true);
});

test("within the look's limit, no config anywhere is not_configured", async () => {
  const root = mkdtempSync(join(tmpdir(), "custosa-edge-"));
  const out = await collectEdgeFunctions(root, walkOver(MAX_IGNORED_PROBES - 1), { key: KEY, filesStatus: "ok" });
  assert.deepEqual(out.edge, { status: "not_run", reason: "not_configured", items: [] });
});

/* Function folders with no supabase/config.toml at all. Supabase deploys each
 * <supabase dir>/functions/<name>/ folder (not _shared or another _ folder), so a project with such folders and no
 * config is listed, never not_configured: "no config" read as "no functions" was the false absence. */
const bare = (...paths) => ({ files: paths.map((path) => ({ path })), notAnalyzed: [] });

test("function folders with no config.toml are listed, verify_jwt not_read; _shared is left out", async () => {
  const root = mkdtempSync(join(tmpdir(), "custosa-edge-"));
  const out = await collectEdgeFunctions(root, bare("supabase/functions/hello/index.ts", "supabase/functions/hello/util.ts",
    "supabase/functions/_shared/cors.ts", "apps/web/supabase/functions/bye/main.ts", "src/app.ts"), { key: KEY, filesStatus: "ok" });
  assert.equal(out.edge.status, "ok");
  assert.equal(out.edge.reason, null);
  // bye has no index file: its entrypoint is null, which the core reads as entrypoints_not_observed
  assert.deepEqual(out.edge.items.map((i) => [i.name, i.entrypoint, i.verify_jwt]).sort(), [
    ["bye", null, "not_read"],
    ["hello", "supabase/functions/hello/index.ts", "not_read"],
  ]);
  assert.deepEqual(out.notAnalyzed, []);
  assert.equal(out.configPaths.size, 0);
});

test("only _shared, or a file loose in functions/, is still not_configured", async () => {
  const root = mkdtempSync(join(tmpdir(), "custosa-edge-"));
  const out = await collectEdgeFunctions(root, bare("supabase/functions/_shared/cors.ts", "supabase/functions/deno.json",
    "supabase/functions/.vscode/settings.json"), { key: KEY, filesStatus: "ok" });
  assert.deepEqual(out.edge, { status: "not_run", reason: "not_configured", items: [] });
});

test("a function folder in a supabase directory with no config is listed beside another directory's config", async () => {
  const root = mkdtempSync(join(tmpdir(), "custosa-edge-"));
  mkdirSync(join(root, "supabase"), { recursive: true });
  writeFileSync(join(root, "supabase", "config.toml"), "[functions.f]\nverify_jwt = true\n");
  const out = await collectEdgeFunctions(root, bare("supabase/config.toml", "apps/web/supabase/functions/g/index.ts"),
    { key: KEY, filesStatus: "ok" });
  assert.equal(out.edge.status, "ok");
  assert.deepEqual(out.edge.items.map((i) => [i.name, i.entrypoint, i.verify_jwt]).sort(), [
    ["f", "supabase/functions/f/index.ts", true],
    ["g", "apps/web/supabase/functions/g/index.ts", "not_read"],
  ]);
});

test("function folders with no config, on a walk with a gap, are a truncated list, never complete", async () => {
  const root = mkdtempSync(join(tmpdir(), "custosa-edge-"));
  const out = await collectEdgeFunctions(root, bare("supabase/functions/hello/index.ts"), { key: KEY, filesStatus: "ok", gap: "file_limit" });
  assert.equal(out.edge.status, "truncated");
  assert.equal(out.edge.reason, "item_limit");
});

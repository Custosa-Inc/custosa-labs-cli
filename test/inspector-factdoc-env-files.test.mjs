/* env-named files in the secret scan. A tracked one is read locally and
 * scanned; untracked and ignored ones are never opened and don't truncate; a not_checked one is never opened and keeps
 * the scan from reading as clean (truncated, unreadable; its path is the redacted env_files entry). A tracked one that
 * can't be read truncates the collector too. Real git fixtures (isomorphic-git), as the walk's tests use. */
import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { syncBuiltinESMExports } from "node:module";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import git from "isomorphic-git";
import { buildFactDocuments, loadRuleset } from "../lib/inspector/factdoc.mjs";
import { loadRules } from "../lib/inspector/rules.mjs";
import * as walkread from "../lib/inspector/walkread.mjs";

const { mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync, chmodSync } = fs;
const RULES = loadRules(fileURLToPath(new URL("./fixtures/rules/", import.meta.url)));
const RULESET_ID = "2026-10-20.0123abcd";
const temp = (prefix) => realpathSync(mkdtempSync(join(tmpdir(), prefix)));
const put = (root, path, text) => { mkdirSync(join(root, path, ".."), { recursive: true }); writeFileSync(join(root, path), text); };
const quietCatalog = async () => ({ status: "not_run", count: 0, reason: "service_missing", preflight: null, queries: [] });
const quietPlatform = async () => ({ provider: null, status: "not_run", reason: "no_token", settings: {} });
const URL_PW = "postgresql://app:Zq7wVm2Kp9@db.example.org:5432/app\n";

async function build(root) {
  const configDir = temp("b58-cfg-");
  const out = await buildFactDocuments([root], {
    configDir, ruleset: { id: RULESET_ID, rules: RULES, queries: loadRuleset({ bundleDir: "/nonexistent", rulesetId: RULESET_ID }).queries },
    collectCatalog: quietCatalog, collectPlatform: quietPlatform,
  });
  const [d] = out.documents;
  assert.equal(d.problem, null, JSON.stringify(d.problem));
  return d.document;
}
const col = (doc) => doc.collection.find((c) => c.collector === "secrets");
const found = (doc) => doc.secrets.map((s) => `${s.rule_id}@${s.path}:${s.line}`);

/* A repository with `tracked` committed to the index, `untracked` on disk only, and `ignored` listed in .gitignore. */
async function repo({ tracked = {}, untracked = {}, ignored = {} }) {
  const root = temp("b58-repo-");
  await git.init({ fs, dir: root, defaultBranch: "main" });
  const ignore = Object.keys(ignored).map((p) => `/${p}`).join("\n");
  const all = { "src/a.ts": "export const a = 1;\n", ...tracked, ...(ignore ? { ".gitignore": `${ignore}\n` } : {}) };
  for (const [p, t] of Object.entries(all)) put(root, p, t);
  await git.add({ fs, dir: root, filepath: Object.keys(all), force: true });
  for (const [p, t] of Object.entries({ ...untracked, ...ignored })) put(root, p, t);
  return root;
}

test("a tracked env file is scanned; untracked and ignored ones are never opened and don't truncate", async () => {
  const root = await repo({ tracked: { "config/production.env": URL_PW, ".env.example": "SMTP_PASSWORD=Hq4rTz8Lw2\n" },
    untracked: { ".env.local": URL_PW }, ignored: { ".env": URL_PW } });
  const doc = await build(root);
  assert.deepEqual(doc.files.env_files, [
    { path: ".env", git: "ignored" }, { path: ".env.example", git: "tracked" }, { path: ".env.local", git: "untracked" },
    { path: "config/production.env", git: "tracked" },
  ]);
  assert.deepEqual(found(doc), ["secrets.config-password@.env.example:1", "secrets.postgres-url-password@config/production.env:1"]);
  assert.deepEqual(col(doc), { collector: "secrets", status: "ok", count: 2, reason: null });
});

test("only tracked env files are opened", async (t) => {
  const root = await repo({ tracked: { "prod.env": URL_PW }, untracked: { ".env.local": URL_PW }, ignored: { ".env": URL_PW } });
  const opened = [];
  const real = fs.promises.open;
  t.mock.method(fs.promises, "open", async (p, ...rest) => { opened.push(String(p)); return real(p, ...rest); });
  syncBuiltinESMExports();
  try { await build(root); } finally { t.mock.restoreAll(); syncBuiltinESMExports(); }
  assert.ok(opened.some((p) => p.endsWith("/prod.env")), "the tracked one is read");
  const envOpened = opened.filter((p) => /(?:^|\/)(?:\.env[^/]*|[^/]*\.env)$/.test(p)).map((p) => p.slice(root.length + 1));
  assert.ok(!envOpened.includes(".env") && !envOpened.includes(".env.local"), envOpened.join(","));
});

test("a not_checked env file is never opened, and the scan can't read as clean", async () => {
  // No .git: the tracked set is unknown, so every env file is not_checked.
  const root = temp("b58-nogit-");
  put(root, "src/a.ts", "export const a = 1;\n");
  put(root, "config/production.env", URL_PW);
  const doc = await build(root);
  assert.deepEqual(doc.files.env_files, [{ path: "config/production.env", git: "not_checked" }]);
  assert.deepEqual(doc.secrets, []);
  assert.deepEqual(col(doc), { collector: "secrets", status: "truncated", count: 0, reason: "unreadable" });
  // A finding elsewhere doesn't make it complete either.
  put(root, "config/env.local.example", "SUPABASE_SERVICE_ROLE_KEY=Aa1B\x622Cc3Dd4Ee5Ff6Gg7Hh8\n");
  const doc2 = await build(root);
  assert.deepEqual(found(doc2), ["secrets.supabase-service-role-config@config/env.local.example:1"]);
  assert.deepEqual(col(doc2), { collector: "secrets", status: "truncated", count: 1, reason: "unreadable" });
  // Without env files, nothing changes: empty.
  const bare = temp("b58-nogit-");
  put(bare, "src/a.ts", "export const a = 1;\n");
  assert.deepEqual(col(await build(bare)), { collector: "secrets", status: "empty", count: 0, reason: null });
});

test("a tracked env file that can't be read truncates the collector, never empty", async (t) => {
  if (process.platform === "win32" || process.getuid?.() === 0) return t.skip("permissions don't bind here");
  const root = await repo({ tracked: { "prod.env": URL_PW } });
  chmodSync(join(root, "prod.env"), 0o000);
  try {
    const doc = await build(root);
    assert.deepEqual(doc.secrets, []);
    assert.deepEqual(col(doc), { collector: "secrets", status: "truncated", count: 0, reason: "unreadable" });
    assert.ok(doc.files.not_analyzed.some((e) => e.path === "prod.env"));
  } finally { chmodSync(join(root, "prod.env"), 0o644); }
});

test("a tracked env file over the size limit truncates with size_limit", async () => {
  const root = await repo({ tracked: { "big.env": `A=${"x".repeat(2_100_000)}\n` } });
  const doc = await build(root);
  assert.deepEqual(col(doc), { collector: "secrets", status: "truncated", count: 0, reason: "size_limit" });
});

test("readWalked still refuses env names unless asked for one", async () => {
  const root = temp("b58-read-");
  put(root, "prod.env", "A=1\n");
  assert.deepEqual(await walkread.readWalked(root, "prod.env", 1000), { refused: "unreadable" });
  const read = await walkread.readWalked(root, "prod.env", 1000, { envName: true });
  assert.equal(read.buf.toString(), "A=1\n");
  assert.equal(readFileSync(join(root, "prod.env"), "utf8"), "A=1\n");
});

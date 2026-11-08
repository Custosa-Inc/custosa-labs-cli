#!/usr/bin/env node
/* Smoke test for an installed custosa package (audit SC5): run from CI against the packed tarball installed into an
 * empty folder, never against the source tree.
 *
 *   node .github/scripts/smoke.mjs <install dir>      (the folder `npm install <tarball>` ran in)
 *
 * Checks, in order:
 *   1. `custosa --version` prints the installed package.json version;
 *   2. `custosa inspect --stdio` answers initialize and tools/list over stdio, listing check_schema;
 *   3. a check_schema call on a tiny fixture project, in local-only mode, builds its fact document;
 *   4. `custosa inspect --document <fixture>` builds the same project's document from the command line.
 * With CUSTOSA_SMOKE_STRICT=1 (set in CI) the rules collector must also finish and analyse the fixture's code.
 *
 * Nothing reaches the network evaluator: every child gets CUSTOSA_INSPECT_LOCAL_ONLY=1, an empty config folder (no
 * sign-in token), and CUSTOSA_EVALUATOR_URL pointing at a closed loopback port, so even a regression that ignored
 * local-only mode would fail locally instead of sending anything. */
import { spawn, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const installDir = process.argv[2] && resolve(process.argv[2]);
if (!installDir || process.argv.length !== 3) {
  console.error("usage: node smoke.mjs <install dir>");
  process.exit(2);
}
const pkgDir = join(installDir, "node_modules", "custosa");
const pkg = JSON.parse(readFileSync(join(pkgDir, "package.json"), "utf8"));
const bin = join(pkgDir, pkg.bin.custosa);

const work = realpathSync(mkdtempSync(join(tmpdir(), "custosa-smoke-")));
const configDir = join(work, "config");
mkdirSync(configDir);
const env = {
  ...process.env,
  CUSTOSA_INSPECT_LOCAL_ONLY: "1",
  CUSTOSA_CONFIG_DIR: configDir,
  CUSTOSA_EVALUATOR_URL: "http://127.0.0.1:9",
};

const STRICT = process.env.CUSTOSA_SMOKE_STRICT === "1";
let failures = 0;
const ok = (msg) => console.log(`ok   ${msg}`);
const fail = (msg) => { failures += 1; console.error(`FAIL ${msg}`); };

/* The fixture: a small Express app with a Postgres migration, as its own git repository. */
function makeFixture() {
  const dir = join(work, "fixture-app");
  mkdirSync(join(dir, "src"), { recursive: true });
  mkdirSync(join(dir, "migrations"), { recursive: true });
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "fixture-app", version: "1.0.0", private: true,
    dependencies: { express: "5.2.1", pg: "8.23.1" } }, null, 2));
  writeFileSync(join(dir, "migrations", "001_patients.sql"), [
    "create table patients (",
    "  id uuid primary key,",
    "  full_name text not null,",
    "  date_of_birth date,",
    "  ssn text",
    ");",
    "",
  ].join("\n"));
  writeFileSync(join(dir, "src", "server.js"), [
    "const express = require('express');",
    "const { Pool } = require('pg');",
    "const app = express();",
    "const pool = new Pool();",
    "app.get('/patients/:id', async (req, res) => {",
    "  const { rows } = await pool.query('select * from patients where id = $1', [req.params.id]);",
    "  console.log('patient', rows[0]);",
    "  res.json(rows[0]);",
    "});",
    "app.listen(3000);",
    "",
  ].join("\n"));
  const git = (...args) => spawnSync("git", args, { cwd: dir, encoding: "utf8" });
  const init = git("init", "-q");
  if (init.status !== 0) throw new Error(`git init failed: ${init.stderr}`);
  git("add", "-A");
  git("-c", "user.name=smoke", "-c", "user.email=smoke@example.invalid", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "fixture");
  return dir;
}

function versionCheck() {
  const r = spawnSync(process.execPath, [bin, "--version"], { env, encoding: "utf8", timeout: 60_000 });
  const out = (r.stdout ?? "").trim();
  if (r.status === 0 && out === pkg.version) ok(`custosa --version prints ${out}`);
  else fail(`custosa --version: exit ${r.status}, printed ${JSON.stringify(out)}, expected ${pkg.version}; stderr: ${r.stderr}`);
}

/* A newline-delimited JSON-RPC session with `custosa inspect --stdio`, started in the fixture (its git root). */
function stdioSession(cwd) {
  const child = spawn(process.execPath, [bin, "inspect", "--stdio"], { cwd, env, stdio: ["pipe", "pipe", "pipe"] });
  let buf = "", stderr = "";
  const pending = new Map();
  child.stderr.on("data", (d) => { stderr += d; });
  child.stdout.on("data", (d) => {
    buf += d;
    let i;
    while ((i = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, i).trim();
      buf = buf.slice(i + 1);
      if (!line) continue;
      let msg;
      try { msg = JSON.parse(line); } catch { fail(`non-JSON line on the server's stdout: ${line.slice(0, 200)}`); continue; }
      if (msg.id !== undefined && pending.has(msg.id) && (msg.result !== undefined || msg.error !== undefined)) {
        pending.get(msg.id)(msg);
        pending.delete(msg.id);
      } else if (msg.method && msg.id !== undefined) {
        // A request from the server (roots/list, for one): this client declared no capabilities, so refuse it.
        child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: msg.id, error: { code: -32601, message: "not supported" } })}\n`);
      }
    }
  });
  let next = 1;
  const request = (method, params, timeoutMs = 120_000) => new Promise((res, rej) => {
    const id = next++;
    const timer = setTimeout(() => { pending.delete(id); rej(new Error(`${method}: no answer in ${timeoutMs} ms; stderr: ${stderr.slice(-2000)}`)); }, timeoutMs);
    pending.set(id, (msg) => { clearTimeout(timer); res(msg); });
    child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
  });
  const notify = (method, params) => child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method, params })}\n`);
  const close = () => new Promise((res) => {
    child.once("exit", (code, signal) => res({ code, signal }));
    child.stdin.end();
    setTimeout(() => child.kill(), 10_000).unref();
  });
  return { request, notify, close, stderr: () => stderr };
}

async function stdioCheck(fixture) {
  const s = stdioSession(fixture);
  try {
    const init = await s.request("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "custosa-smoke", version: "1" } });
    if (init.error) { fail(`initialize: ${JSON.stringify(init.error)}`); return; }
    ok(`initialize: server ${init.result?.serverInfo?.name} ${init.result?.serverInfo?.version}`);
    if (init.result?.serverInfo?.version !== pkg.version) fail(`serverInfo.version ${init.result?.serverInfo?.version} is not ${pkg.version}`);
    s.notify("notifications/initialized", {});

    const list = await s.request("tools/list", {});
    const names = (list.result?.tools ?? []).map((t) => t.name);
    if (list.error || !names.includes("check_schema")) fail(`tools/list: ${JSON.stringify(list.error ?? names)}`);
    else ok(`tools/list: ${names.join(", ")}`);

    const call = await s.request("tools/call", { name: "check_schema", arguments: { goal: "check" } }, 300_000);
    const text = (call.result?.content ?? []).filter((c) => c.type === "text").map((c) => c.text).join("\n");
    // structuredContent is the result; the text is a short summary followed by the same JSON (TU2)
    let body = call.result?.structuredContent ?? null;
    if (!body) {
      const at = text.indexOf("{");
      try { body = JSON.parse(at >= 0 ? text.slice(at) : text); } catch { /* not JSON: reported below */ }
    }
    const doc = body?.documents?.[0]?.document;
    if (call.error || call.result?.isError || body?.local_only !== true || !doc) {
      fail(`check_schema (local only): ${JSON.stringify(call.error ?? call.result).slice(0, 2000)}`);
    } else {
      documentOk("check_schema (local only)", doc);
    }
  } catch (err) {
    fail(err.message);
  } finally {
    const { code, signal } = await s.close();
    if (code !== 0 && signal !== "SIGTERM") fail(`inspect --stdio exited with ${code ?? signal}; stderr: ${s.stderr().slice(-2000)}`);
  }
}

function documentCheck(fixture) {
  const r = spawnSync(process.execPath, [bin, "inspect", "--document", fixture], { env, encoding: "utf8", timeout: 300_000, maxBuffer: 64 * 1024 * 1024 });
  let out = null;
  try { out = JSON.parse(r.stdout); } catch { /* reported below */ }
  if (r.status === 0 && out?.document) documentOk("inspect --document", out.document);
  else fail(`inspect --document: exit ${r.status}; stderr: ${(r.stderr ?? "").slice(-2000)}`);
}

/* A fact document for the fixture: the files collector walked it and, in strict mode (CI), the rules collector ran to
 * completion and analysed src/server.js. Strict mode is off by default because a heavily loaded machine can hit the
 * rules time limit even on this tiny project. */
function documentOk(what, doc) {
  const status = (name) => doc.collection?.find((c) => c.collector === name)?.status ?? "missing";
  const problems = [];
  if (doc.inspector_version !== pkg.version) problems.push(`inspector_version ${doc.inspector_version}`);
  if (status("files") !== "ok") problems.push(`files collector ${status("files")}`);
  if (status("rules") === "failed" || status("rules") === "missing") problems.push(`rules collector ${status("rules")}`);
  if (STRICT) {
    if (status("rules") !== "ok") problems.push(`rules collector ${status("rules")} (strict)`);
    if (!(doc.files?.analyzed >= 1)) problems.push(`files.analyzed ${doc.files?.analyzed} (strict)`);
  }
  if (problems.length) fail(`${what}: ${problems.join("; ")}`);
  else ok(`${what}: built the fixture's fact document locally (files ${status("files")}, rules ${status("rules")}, analyzed ${doc.files?.analyzed})`);
}

try {
  const fixture = makeFixture();
  versionCheck();
  await stdioCheck(fixture);
  documentCheck(fixture);
} catch (err) {
  fail(err.stack || err.message);
} finally {
  try { rmSync(work, { recursive: true, force: true }); } catch { /* best effort */ }
}
if (failures) { console.error(`${failures} smoke check(s) failed`); process.exit(1); }
console.log("smoke: all checks passed");

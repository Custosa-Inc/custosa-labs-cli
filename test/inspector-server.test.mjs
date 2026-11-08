/* Smoke test for the local inspector's MCP server: `custosa inspect --stdio` speaks MCP on stdio, lists its
 * three tools, answers a call (with no sign-in: the local sign-in message), takes its project roots from the host on
 * each check_schema call (entry by entry, never falling back to the working directory when the host named roots),
 * refuses check_schema without a root, and keeps stdout for the protocol. These drive the 2025 handshake;
 * test/mcp-conformance.test.mjs drives both protocol revisions. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { fileURLToPath, pathToFileURL } from "node:url";
import AjvModule from "ajv";
import {
  NO_ROOT_MESSAGE, ROOTS_UNREADABLE_MESSAGE, UNUSABLE_ROOTS_MESSAGE, findGitRoot, rootsFromHost, startServer,
} from "../lib/inspector/server.mjs";
import { GUIDANCE_INPUT_SCHEMA, INPUT_SCHEMA, PAGE_INPUT_SCHEMA, locationProblem } from "../lib/inspector/tool.mjs";
import { localError } from "../lib/inspector/client.mjs";

const BIN = fileURLToPath(new URL("../bin/custosa.mjs", import.meta.url));
const SERVER = new URL("../lib/inspector/server.mjs", import.meta.url).href;
const temp = (prefix) => realpathSync(mkdtempSync(join(tmpdir(), prefix)));
const repo = () => { const dir = temp("custosa-repo-"); mkdirSync(join(dir, ".git")); return dir; };
const fileRoot = (path) => ({ uri: pathToFileURL(path).href, name: "project" });
/* Spawned inspectors use an empty temporary config folder: never the real ~/.config/custosa, so no sign-in, and the
 * real handler answers every evaluation with the local sign-in message before collecting anything. */
const CHILD_ENV = () => ({ ...process.env, CUSTOSA_CONFIG_DIR: temp("custosa-config-") });
const NOT_SIGNED_IN = localError("sign_in_required");
/* PC4: a refusal is an isError result whose text leads with the next step and carries the error as JSON. */
const isNotSignedIn = (result) => {
  assert.equal(result.isError, true, JSON.stringify(result));
  assert.equal(result.structuredContent, undefined);
  assert.ok(result.content[0].text.startsWith(NOT_SIGNED_IN.next_step), result.content[0].text);
  assert.deepEqual(JSON.parse(result.content[0].text.split("\n\n").at(-1)), NOT_SIGNED_IN);
  return true;
};

/* A minimal MCP client over a pair of streams. Every line the server writes must be a JSON-RPC message. `roots` (a
 * mutable box) is what the client answers to roots/list. */
function client(input, output, box = { roots: null }) {
  let buffer = "", nextId = 1;
  const pending = new Map(), seen = [];
  output.on("data", (d) => {
    buffer += d;
    let nl;
    while ((nl = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, nl); buffer = buffer.slice(nl + 1);
      const msg = JSON.parse(line); // throws (failing the test) on anything that isn't a protocol message
      assert.equal(msg.jsonrpc, "2.0");
      seen.push(msg);
      if (msg.method === "roots/list") send({ jsonrpc: "2.0", id: msg.id, result: { roots: box.roots ?? [] } });
      else if (msg.id !== undefined && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id); }
    }
  });
  const send = (msg) => input.write(JSON.stringify(msg) + "\n");
  const request = (method, params) => new Promise((ok) => { const id = nextId++; pending.set(id, ok); send({ jsonrpc: "2.0", id, method, params }); });
  const initialize = () => request("initialize", {
    protocolVersion: "2025-06-18", clientInfo: { name: "test", version: "0" },
    capabilities: box.roots ? { roots: { listChanged: true } } : {},
  });
  async function handshake() {
    const init = await initialize();
    send({ jsonrpc: "2.0", method: "notifications/initialized" });
    return init;
  }
  const call = (args = { goal: "check" }) => request("tools/call", { name: "check_schema", arguments: args }).then((m) => m.result);
  const callTool = (name, args) => request("tools/call", { name, arguments: args }).then((m) => m.result);
  return { send, request, initialize, handshake, call, callTool, seen, box };
}

/* The bin, spawned. */
function spawned(cwd, box) {
  const child = spawn(process.execPath, [BIN, "inspect", "--stdio"], { cwd, stdio: ["pipe", "pipe", "pipe"], env: CHILD_ENV() });
  let err = "";
  child.stderr.on("data", (d) => { err += d; });
  const exited = new Promise((ok) => child.on("exit", (code) => ok(code)));
  return { ...client(child.stdin, child.stdout, box), child, exited, stderr: () => err };
}

/* startServer in this process over PassThrough streams, with a runCheck that records the roots it was given. */
function inProcess({ root = null, roots = null, projectRoot = null, home } = {}) {
  const stdin = new PassThrough(), stdout = new PassThrough();
  const checks = [];
  const refused = [];
  const runCheck = async (args, ctx) => { checks.push(ctx.roots); refused.push(ctx.refused); return { ok: true }; };
  const done = startServer({ stdin, stdout, root, runCheck, projectRoot, ...(home ? { home } : {}) });
  const c = client(stdin, stdout, { roots });
  return { ...c, checks, refused, done, end: () => { stdin.end(); return done; } };
}

test("inspect --stdio: handshake, exactly check_schema, the sign-in message, then a clean exit", async () => {
  const s = spawned(repo());
  const init = await s.handshake();
  assert.equal(init.result.serverInfo.name, "custosa-inspector");
  assert.ok(init.result.capabilities.tools);

  const list = await s.request("tools/list", {});
  assert.deepEqual(list.result.tools.map((t) => t.name), ["check_schema", "schema_guidance", "get_result_page"]);
  assert.equal(list.result.tools[0].annotations.openWorldHint, true); // the facts go to the evaluator
  assert.deepEqual(list.result.tools[0].annotations, { title: "PHI Schema Check", readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true });
  assert.equal(list.result.tools[0].title, "PHI Schema Check");
  assert.equal(list.result.tools[0].outputSchema.type, "object");
  const props = Object.keys(list.result.tools[0].inputSchema.properties);
  for (const key of ["goal", "session", "answers", "decisions"]) assert.ok(props.includes(key), key); // decisions: the person's
  assert.deepEqual(Object.keys(list.result.tools[2].inputSchema.properties), ["goal", "session", "page", "resend"]); // TU1: pages are get_result_page's
  for (const key of ["tables", "fields", "json_schema", "verified", "verified_file", "changed_files", "app"]) assert.ok(!props.includes(key), key);

  const ok = await s.call({ goal: "check", session: "ps_abcdefghijklmnopqrstuv", answers: [
    { object_id: "audit-log@src/db/schema.ts", question_id: "location", answer: "here", location: "src/db/schema.ts:12-14" },
    { object_id: "rls-forced", question_id: "purpose", answer: "phi" },
  ] });
  isNotSignedIn(ok);

  const evidence = await s.call({ goal: "check", tables: [] });
  assert.equal(evidence.isError, true);
  assert.match(evidence.content[0].text, /tables/);

  s.child.stdin.end();
  assert.equal(await s.exited, 0);
  assert.ok(!s.seen.some((m) => m.method === "roots/list"), "no roots asked of a host that offers none");
});

test("inspect --stdio: with no root, check_schema is refused with the message; the other tools and the server go on", async (t) => {
  const cwd = temp("custosa-inspect-noroot-");
  if (findGitRoot(cwd)) return t.skip("the temp folder is inside a git repository");

  const s = spawned(cwd);
  await s.handshake();
  const refused = await s.call();
  assert.equal(refused.isError, true);
  assert.equal(refused.content[0].text, NO_ROOT_MESSAGE);
  isNotSignedIn(await s.callTool("get_result_page", { session: "ps_abcdefghijklmnopqrstuv", page: 2 }));
  s.child.stdin.end();
  assert.equal(await s.exited, 0);
  assert.ok(s.stderr().includes(NO_ROOT_MESSAGE), s.stderr());
});

test("inspect --stdio: the host's roots are used even outside a git folder", async (t) => {
  const cwd = temp("custosa-inspect-noroot-");
  if (findGitRoot(cwd)) return t.skip("the temp folder is inside a git repository");
  const s = spawned(cwd, { roots: [fileRoot(temp("custosa-project-"))] });
  await s.handshake();
  isNotSignedIn(await s.call());
  assert.ok(s.seen.some((m) => m.method === "roots/list"));
  s.child.stdin.end();
  assert.equal(await s.exited, 0);
});

test("a mixed roots list uses its file root (realpathed), not the working directory's repository", async () => {
  const project = temp("custosa-project-");
  const link = join(temp("custosa-links-"), "proj");
  symlinkSync(project, link);
  const s = inProcess({ root: repo(), roots: [fileRoot(link), { uri: "https://example.com/x", name: "web" }, { name: "no uri" }] });
  await s.handshake();
  const result = await s.call();
  assert.equal(result.isError, undefined, result.content?.[0]?.text);
  assert.deepEqual(s.checks, [[project]]);
  await s.end();
});

test("a host whose roots are all unusable is refused (no fallback to the working directory) and the server keeps running", async () => {
  const project = temp("custosa-project-");
  const s = inProcess({ root: repo(), roots: [{ uri: "https://example.com/x" }, fileRoot(join(project, "missing"))] });
  await s.handshake();
  const refused = await s.call();
  assert.equal(refused.isError, true);
  assert.equal(refused.content[0].text, UNUSABLE_ROOTS_MESSAGE);
  assert.equal(s.checks.length, 0);

  // Roots are read on each call: the host fixes them, calls work; it changes them to nothing usable, calls fail and
  // the server stays up. No roots/list_changed is needed (2026-07-28 has none).
  s.box.roots = [fileRoot(project)];
  assert.equal((await s.call()).isError, undefined);
  assert.deepEqual(s.checks, [[project]]);
  s.box.roots = [{ uri: "https://example.com/y" }];
  assert.equal((await s.call()).isError, true);
  const list = await s.request("tools/list", {});
  assert.deepEqual(list.result.tools.map((t) => t.name), ["check_schema", "schema_guidance", "get_result_page"]);
  await s.end(); // resolves: a refused root list is not a crash
});

test("a host that offers roots but lists none is refused too", async () => {
  const s = inProcess({ root: repo(), roots: [] });
  s.box.roots = []; // offered (the capability is sent) but empty
  const init = await s.request("initialize", { protocolVersion: "2025-06-18", clientInfo: { name: "t", version: "0" }, capabilities: { roots: {} } });
  assert.ok(init.result);
  s.send({ jsonrpc: "2.0", method: "notifications/initialized" });
  const refused = await s.call();
  assert.equal(refused.isError, true);
  assert.equal(refused.content[0].text, UNUSABLE_ROOTS_MESSAGE);
  await s.end();
});

test("a host that offers roots but doesn't answer roots/list is refused with the message", async () => {
  const stdin = new PassThrough(), stdout = new PassThrough();
  const done = startServer({ stdin, stdout, root: repo(), runCheck: async () => ({ ok: true }), rootsTimeoutMs: 200 });
  const c = client(stdin, stdout, { roots: [] });
  stdout.removeAllListeners("data"); // a host that reads answers but never answers roots/list
  let buffer = "";
  const answers = new Map();
  stdout.on("data", (d) => { buffer += d; let nl; while ((nl = buffer.indexOf("\n")) >= 0) { const m = JSON.parse(buffer.slice(0, nl)); buffer = buffer.slice(nl + 1); if (m.id !== undefined && !m.method) answers.set(m.id, m); } });
  c.send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", clientInfo: { name: "t", version: "0" }, capabilities: { roots: {} } } });
  c.send({ jsonrpc: "2.0", method: "notifications/initialized" });
  c.send({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "check_schema", arguments: {} } });
  for (let i = 0; i < 250 && !answers.has(2); i++) await new Promise((ok) => setTimeout(ok, 20));
  assert.equal(answers.get(2)?.result?.isError, true, JSON.stringify(answers.get(2)));
  assert.equal(answers.get(2).result.content[0].text, ROOTS_UNREADABLE_MESSAGE);
  stdin.end();
  await done;
});

test("an embedder passing process.stdout: stray writes go to stderr, stdout stays protocol only", async () => {
  const dir = temp("custosa-embed-");
  mkdirSync(join(dir, ".git"));
  const script = join(dir, "embed.mjs");
  writeFileSync(script, `import { startServer } from ${JSON.stringify(SERVER)};
setTimeout(() => { process.stdout.write("stray write\\n"); console.log("stray log"); }, 50);
await startServer({ stdin: process.stdin, stdout: process.stdout, root: process.cwd() });
process.stdout.write("after close");
`);
  const child = spawn(process.execPath, [script], { cwd: dir, stdio: ["pipe", "pipe", "pipe"], env: CHILD_ENV() });
  let err = "", out = "";
  child.stderr.on("data", (d) => { err += d; });
  child.stdout.on("data", (d) => { out += d; });
  const c = client(child.stdin, child.stdout);
  await c.handshake();
  await new Promise((ok) => setTimeout(ok, 150));
  isNotSignedIn(await c.call());
  child.stdin.end();
  assert.equal(await new Promise((ok) => child.on("exit", ok)), 0);
  assert.match(err, /stray write/);
  assert.match(err, /stray log/);
  assert.ok(!out.includes("stray"), out);
  assert.ok(out.endsWith("after close"), "process.stdout is given back after the server closes");
});

test("inspect without --stdio prints usage and exits 2", async () => {
  const child = spawn(process.execPath, [BIN, "inspect"], { stdio: ["ignore", "pipe", "pipe"] });
  let out = "", err = "";
  child.stdout.on("data", (d) => { out += d; });
  child.stderr.on("data", (d) => { err += d; });
  assert.equal(await new Promise((ok) => child.on("exit", ok)), 2);
  assert.equal(out, "");
  assert.match(err, /custosa inspect --stdio/);
});

test("findGitRoot walks up to a .git entry; rootsFromHost judges each entry and realpaths it", () => {
  const dir = repo();
  mkdirSync(join(dir, "a", "b"), { recursive: true });
  assert.equal(findGitRoot(join(dir, "a", "b")), dir);
  const link = join(temp("custosa-links-"), "r");
  symlinkSync(dir, link);
  assert.deepEqual(rootsFromHost([
    fileRoot(link), fileRoot(dir), { uri: "https://example.com/x" }, fileRoot(join(dir, "missing")),
    { uri: "not a uri" }, { uri: 7 }, null, fileRoot(join(dir, "a")),
  ]), [dir, join(dir, "a")]);
});

test("the input schema takes the fact document contract's answers, sessions and locations", () => {
  const validate = new AjvModule.default({ strict: true }).compile(INPUT_SCHEMA);
  const ok = (args) => validate(args) && locationProblem(args) === null;
  const answer = (o) => ({ answers: [{ object_id: "audit-log", question_id: "location", answer: "here", location: "src/a.ts:3", ...o }] });

  for (const args of [
    answer({}), answer({ location: "src/a.ts:3-32" }), answer({ location: "lib/[id]/page.tsx:9999999" }),
    answer({ object_id: "rls-forced@app/models/patient.rb" }), answer({ answer: "not_found", location: null }),
    answer({ question_id: "purpose", answer: "phi", location: undefined }),
    answer({ question_id: "staff_access", answer: "admin_app", location: null }),
    answer({ question_id: "person_confirmation", answer: "declined", location: null }),
    { session: "ps_abcdefghij_-KLMNOPQRST" },
  ]) assert.ok(ok(args), JSON.stringify(args));
  // TU1: guidance and page arguments are the other tools'
  const guidance = new AjvModule.default({ strict: true }).compile(GUIDANCE_INPUT_SCHEMA);
  const page = new AjvModule.default({ strict: true }).compile(PAGE_INPUT_SCHEMA);
  assert.ok(guidance({ goal: "explain", practice_id: "access-audit-log" }));
  assert.ok(page({ session: "ps_abcdefghij_-KLMNOPQRST", page: 2, resend: ["all"] }));
  assert.ok(!page({ page: 2 }), "a page needs its session");
  assert.ok(!page({ session: "ps_abcdefghij_-KLMNOPQRST", page: 0 }));

  for (const args of [
    answer({ location: "./src/a.ts:3" }), answer({ location: "/etc/passwd:1" }), answer({ location: "src//a.ts:3" }),
    answer({ location: "src/:3" }), answer({ location: "src/../a.ts:3" }), answer({ location: "src/./a.ts:3" }),
    answer({ location: "my file.ts:3" }), answer({ location: "src/a.ts:0" }), answer({ location: "src/a.ts:12345678" }),
    answer({ location: "src/a‮.ts:3" }), answer({ location: "src/a\tb.ts:3" }), answer({ location: "src/a.ts" }),
    answer({ location: "src/a.ts:3-33" }), answer({ location: "src/a.ts:9-3" }),
    answer({ location: null }), answer({ location: undefined }), answer({ answer: "not_found" }),
    answer({ question_id: "purpose", answer: "here" }), answer({ question_id: "purpose", answer: "phi", location: "a.ts:1" }),
    answer({ question_id: "where" }), answer({ answer: "yes" }), answer({ object_id: "Audit-Log" }),
    answer({ object_id: "audit-log@" }), answer({ object_id: "audit log" }), answer({ location_kind: "function" }),
    { session: "ps_short" }, { session: "xx_abcdefghijklmnopqrstuv" }, { goal: "assess" }, { tables: [] }, { page: 2 }, { goal: "plan" },
  ]) assert.ok(!ok(args), JSON.stringify(args));
});

test("roots that are the disk or the home folder are refused; with another usable root they are passed on as refused", async () => {
  const project = repo();
  const s = inProcess({ root: repo(), roots: [fileRoot("/"), fileRoot(project), fileRoot(homedir())] });
  await s.handshake();
  const result = await s.call();
  assert.equal(result.isError, undefined, result.content?.[0]?.text);
  assert.deepEqual(s.checks, [[project]]);
  assert.deepEqual(s.refused, [[{ root: "/", code: "filesystem_root" }, { root: realpathSync(homedir()), code: "home_folder" }]]);
  await s.end();
  const only = inProcess({ root: repo(), roots: [fileRoot("/")] });
  await only.handshake();
  const refusedCall = await only.call();
  assert.equal(refusedCall.isError, true);
  assert.match(refusedCall.content[0].text, /filesystem root/);
  await only.end();
});

test("the tool accepts exactly what the evaluator's next steps say (final review I1), and refuses an assistant's decided_by", async () => {
  const s = inProcess({ root: repo() });
  await s.handshake();
  // finding_ids name the evaluator's object ids: a table, a file path, a handler id, project.
  const fix = await s.call({ goal: "fix", session: "ps_abcdefghijklmnopqrstuv", finding_ids: [
    "rls-enabled@public.care_messages", "edge-function-auth@supabase/functions/x/index.ts",
    "authz-every-handler@src/routes/patients.ts:GET:/patients/:id", "audit-log@project", "rls-forced"] });
  assert.equal(fix.isError, undefined, fix.content?.[0]?.text);
  assert.equal((await s.callTool("get_result_page", { goal: "check", session: "ps_abcdefghijklmnopqrstuv", page: 1000 })).isError, undefined);
  assert.equal((await s.callTool("get_result_page", { goal: "check", session: "ps_abcdefghijklmnopqrstuv", page: 1001 })).isError, true);
  assert.equal((await s.call({ goal: "check", session: "ps_abcdefghijklmnopqrstuv",
    decisions: [{ object_id: "phi-columns@public.patients:dob", decision: "accepted" }] })).isError, undefined);
  const decided = await s.call({ goal: "check", session: "ps_abcdefghijklmnopqrstuv",
    decisions: [{ object_id: "phi-columns@public.patients:dob", decision: "accepted", decided_by: "person" }] });
  assert.equal(decided.isError, true);
  assert.match(decided.content[0].text, /check_schema: decisions\[0\]\.decided_by: don.t send decided_by/);
  assert.equal(s.checks.length, 3); // the refused calls never reach the handler
  await s.end();
});

// the explicit project root and the working directory's root are judged like a host's (projectroot.mjs).
test("a project root override or a fallback root that is the home folder is refused; a project folder is used", async () => {
  const home = realpathSync(repo()), project = repo();
  const { ROOT_PROBLEMS } = await import("../lib/inspector/projectroot.mjs");
  for (const opts of [{ projectRoot: home, root: project }, { root: home }]) {
    const s = inProcess({ ...opts, home });
    await s.handshake();
    const result = await s.call();
    assert.deepEqual([result.isError, result.content[0].text], [true, ROOT_PROBLEMS.home_folder], JSON.stringify(opts));
    assert.deepEqual(s.checks, []);
    await s.end();
  }
  for (const opts of [{ projectRoot: project, root: home }, { root: project }]) {
    const s = inProcess({ ...opts, home });
    await s.handshake();
    const result = await s.call();
    assert.equal(result.isError, undefined, result.content?.[0]?.text);
    assert.deepEqual([s.checks, s.refused], [[[realpathSync(project)]], [[]]], JSON.stringify(opts));
    await s.end();
  }
});

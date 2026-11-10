/* the inspector against MCP clients on both protocol revisions it serves, 2025-11-25 (the initialize handshake)
 * and 2026-07-28 (no handshake: server/discover, a _meta envelope on every request, resultType on every result).
 * Each test spawns the real bin (custosa inspect --stdio) and drives it with the official SDK client
 * (@modelcontextprotocol/client) or with raw JSON-RPC lines. The config folder is an empty temporary one, so no
 * sign-in exists and every call stops at the local sign-in message before anything is collected or sent: no network.
 * All arguments are synthetic metadata. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { UNUSABLE_ROOTS_MESSAGE, toolsListResult } from "../lib/inspector/server.mjs";
import { localError } from "../lib/inspector/client.mjs";
import { toolsListDigest } from "../scripts/tools-list-hash.mjs";

const BIN = fileURLToPath(new URL("../bin/custosa.mjs", import.meta.url));
const LEGACY = "2025-11-25", MODERN = "2026-07-28";
const temp = (prefix) => realpathSync(mkdtempSync(join(tmpdir(), prefix)));
const repo = () => { const dir = temp("custosa-conf-"); mkdirSync(join(dir, ".git")); return dir; };
const env = () => ({ ...process.env, CUSTOSA_CONFIG_DIR: temp("custosa-conf-cfg-"), ANTHROPIC_API_KEY: "" });
const NOT_SIGNED_IN = localError("sign_in_required");
const SESSION = "ps_abcdefghijklmnopqrstuv";

/* One synthetic call per tool: names and goals only, never values. */
const CALLS = [
  ["check_schema", { goal: "check" }],
  ["schema_guidance", { goal: "plan", entities: [{ name: "patients", columns: [{ name: "dob" }] }] }],
  ["get_result", { session: SESSION, select: { state: "fail" } }],
];

/* The SDK client on one revision, connected to a spawned inspector. `roots`: the roots the client offers (null: it
 * offers none). */
async function sdkClient(version, { roots = null, cwd = repo() } = {}) {
  const client = new Client({ name: "conformance-test", version: "0.0.0" }, {
    capabilities: roots ? { roots: {} } : {},
    ...(version === MODERN ? { versionNegotiation: { mode: { pin: MODERN } } } : {}),
  });
  if (roots) client.setRequestHandler("roots/list", async () => ({ roots }));
  const transport = new StdioClientTransport({ command: process.execPath, args: [BIN, "inspect", "--stdio"], cwd, env: env(), stderr: "pipe" });
  await client.connect(transport);
  return client;
}

/* Raw JSON-RPC lines to a spawned inspector: every line it writes must be a JSON-RPC message. */
function rawServer({ cwd = repo() } = {}) {
  const child = spawn(process.execPath, [BIN, "inspect", "--stdio"], { cwd, stdio: ["pipe", "pipe", "pipe"], env: env() });
  let buffer = "";
  const seen = [], waiters = new Map();
  child.stdout.on("data", (d) => {
    buffer += d;
    let nl;
    while ((nl = buffer.indexOf("\n")) >= 0) {
      const msg = JSON.parse(buffer.slice(0, nl)); buffer = buffer.slice(nl + 1);
      assert.equal(msg.jsonrpc, "2.0");
      seen.push(msg);
      if (waiters.has(msg.id)) { waiters.get(msg.id)(msg); waiters.delete(msg.id); }
    }
  });
  const raw = (line) => child.stdin.write(`${line}\n`);
  const request = (id, method, params) => { const p = new Promise((ok) => waiters.set(id, ok)); raw(JSON.stringify({ jsonrpc: "2.0", id, method, params })); return p; };
  const exited = new Promise((ok) => child.on("exit", ok));
  // end: the client closes stdin and the server exits on its own (it can take seconds: the rule bundle preload runs
  // to completion); kill: for tests that don't check the exit.
  return { raw, request, seen, end: () => { child.stdin.end(); return exited; }, kill: () => { child.kill(); return exited; } };
}
const envelope = (extra = {}) => ({ _meta: {
  "io.modelcontextprotocol/protocolVersion": MODERN,
  "io.modelcontextprotocol/clientInfo": { name: "raw-test", version: "0" },
  "io.modelcontextprotocol/clientCapabilities": {},
  ...extra,
} });

const isNotSignedIn = (result) => {
  assert.equal(result.isError, true, JSON.stringify(result));
  assert.ok(result.content[0].text.startsWith(NOT_SIGNED_IN.next_step), result.content[0].text);
};

for (const version of [LEGACY, MODERN]) {
  test(`${version}: connect, tools/list matches the published list, one call per tool, error shapes`, async () => {
    const client = await sdkClient(version);
    try {
      assert.equal(client.getNegotiatedProtocolVersion(), version);
      assert.equal(client.getServerVersion().name, "custosa-inspector");
      assert.ok(client.getServerCapabilities().tools);
      if (version === MODERN) {
        const discovered = await client.discover();
        assert.ok(discovered.supportedVersions.includes(MODERN), JSON.stringify(discovered));
        assert.ok(discovered.capabilities.tools);
      }
      const listed = await client.listTools();
      assert.deepEqual(listed.tools, toolsListResult().tools, "the wire list is the published list");
      for (const tool of listed.tools) {
        assert.ok(tool.title && tool.annotations?.title === tool.title, tool.name);
        for (const hint of ["readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"]) assert.equal(typeof tool.annotations[hint], "boolean", `${tool.name} ${hint}`);
      }
      for (const [name, args] of CALLS) isNotSignedIn(await client.callTool({ name, arguments: args }));
      // A tool refusal is a result (isError); an unknown tool is a JSON-RPC error.
      const refused = await client.callTool({ name: "check_schema", arguments: { goal: "doubts" } });
      assert.equal(refused.isError, true);
      assert.match(refused.content[0].text, /goal/);
      await assert.rejects(client.callTool({ name: "no_such_tool", arguments: {} }), (e) => e.code === -32602 && /no_such_tool/.test(e.message));
    } finally { await client.close(); }
  });

  test(`${version}: check_schema takes the project from the client's roots (none usable: refused, no fallback)`, async () => {
    const project = temp("custosa-conf-project-");
    const used = await sdkClient(version, { roots: [{ uri: pathToFileURL(project).href, name: "project" }] });
    try { isNotSignedIn(await used.callTool({ name: "check_schema", arguments: {} })); } finally { await used.close(); }
    const unusable = await sdkClient(version, { roots: [{ uri: pathToFileURL(join(project, "missing")).href, name: "gone" }] });
    try {
      const res = await unusable.callTool({ name: "check_schema", arguments: {} });
      assert.equal(res.isError, true);
      assert.equal(res.content[0].text, UNUSABLE_ROOTS_MESSAGE);
      // guidance needs no project
      isNotSignedIn(await unusable.callTool({ name: CALLS[1][0], arguments: CALLS[1][1] }));
    } finally { await unusable.close(); }
  });
}

test(`${MODERN} on the wire: discover without a handshake, resultType and cache fields on every result, typed errors`, async () => {
  const s = rawServer();
  const discover = await s.request(1, "server/discover", envelope());
  assert.ok(discover.result.supportedVersions.includes(MODERN), JSON.stringify(discover));
  assert.equal(discover.result.resultType, "complete");
  const list = await s.request(2, "tools/list", envelope());
  assert.equal(list.result.resultType, "complete");
  assert.equal(typeof list.result.ttlMs, "number");
  assert.ok(["public", "private"].includes(list.result.cacheScope));
  assert.deepEqual(list.result.tools, toolsListResult().tools);
  assert.equal(list.result._meta?.["io.modelcontextprotocol/serverInfo"]?.name, "custosa-inspector");
  const call = await s.request(3, "tools/call", { name: "get_result", arguments: { session: SESSION, select: { state: "fail" } }, ...envelope() });
  assert.equal(call.result.resultType, "complete");
  isNotSignedIn(call.result);
  // Unknown method, unknown tool, non-object arguments, then lines that aren't JSON or JSON-RPC.
  assert.equal((await s.request(5, "no/such_method", envelope())).error?.code, -32601);
  assert.equal((await s.request(6, "tools/call", { name: "no_such_tool", arguments: {}, ...envelope() })).error?.code, -32602);
  assert.equal((await s.request(7, "tools/call", { name: "check_schema", arguments: [1], ...envelope() })).error?.code, -32602);
  const parse = new Promise((ok) => { const t = setInterval(() => { const m = s.seen.find((x) => x.error?.code === -32700); if (m) { clearInterval(t); ok(m); } }, 10); });
  s.raw("{not json");
  assert.equal((await parse).id, null);
  const invalid = new Promise((ok) => { const t = setInterval(() => { const m = s.seen.find((x) => x.id === 8); if (m) { clearInterval(t); ok(m); } }, 10); });
  s.raw(JSON.stringify({ id: 8, method: 5 }));
  assert.equal((await invalid).error.code, -32600);
  await s.kill();

  // A revision the server doesn't serve, as a connection's first request: UnsupportedProtocolVersion (-32022) naming
  // the supported ones.
  const other = rawServer();
  const future = await other.request(1, "tools/list", envelope({ "io.modelcontextprotocol/protocolVersion": "2099-01-01" }));
  assert.equal(future.error?.code, -32022, JSON.stringify(future));
  assert.ok(JSON.stringify(future.error.data).includes(MODERN), JSON.stringify(future));
  await other.kill();
});

test(`${LEGACY} on the wire: initialize answers ${LEGACY}, results carry no resultType, the same error codes`, async () => {
  const s = rawServer();
  const init = await s.request(1, "initialize", { protocolVersion: LEGACY, clientInfo: { name: "raw-test", version: "0" }, capabilities: {} });
  assert.equal(init.result.protocolVersion, LEGACY);
  assert.equal(init.result.serverInfo.name, "custosa-inspector");
  s.raw(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }));
  const list = await s.request(2, "tools/list", {});
  assert.deepEqual(list.result.tools, toolsListResult().tools);
  assert.equal(list.result.resultType, undefined);
  assert.equal((await s.request(3, "no/such_method", {})).error?.code, -32601);
  assert.equal((await s.request(4, "tools/call", { name: "no_such_tool", arguments: {} })).error?.code, -32602);
  assert.equal((await s.request(5, "tools/call", { name: "check_schema", arguments: "x" })).error?.code, -32602);
  assert.equal(await s.end(), 0);
});

test("tools/list is pinned: the shipped digest file matches the list the server serves", () => {
  const shipped = readFileSync(new URL("../lib/inspector/tools-list.sha256", import.meta.url), "utf8");
  assert.equal(shipped, `${toolsListDigest()}  tools/list\n`,
    "tools/list changed: run npm run tools-list-hash and commit lib/inspector/tools-list.sha256 with the change");
  assert.match(shipped, /^[0-9a-f]{64} {2}tools\/list\n$/);
});

test("tools/list is deterministic: the same bytes from a fresh process, with no paths, times or versions in it", async () => {
  const again = await new Promise((ok, fail) => {
    const child = spawn(process.execPath, ["--input-type=module", "-e",
      `import { toolsListDigest } from ${JSON.stringify(new URL("../scripts/tools-list-hash.mjs", import.meta.url).href)}; process.stdout.write(toolsListDigest());`],
    { cwd: temp("custosa-conf-elsewhere-"), env: { ...env(), HOME: temp("custosa-conf-home-"), TZ: "Pacific/Chatham", LANG: "tr_TR.UTF-8" } });
    let out = "";
    child.stdout.on("data", (d) => { out += d; });
    child.on("exit", (code) => (code === 0 ? ok(out) : fail(new Error(`exit ${code}`))));
  });
  assert.equal(again, toolsListDigest());
  const text = JSON.stringify(toolsListResult());
  const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  for (const leak of [process.cwd(), tmpdir(), fileURLToPath(new URL("..", import.meta.url)), pkg.version]) assert.ok(!text.includes(leak), leak);
  assert.doesNotMatch(text, /\b20\d\d-\d\d-\d\dT\d\d:/);
});

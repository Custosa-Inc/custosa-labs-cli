/* server.mjs: a fix question that gets no usable answer, and a 2026-07-28 retry that leaves the roots out. An
 * elicitation/create that fails is no approval (confirmFix lines 487 to 490): no evaluator call. A retry whose
 * inputResponses has no readable roots is refused (rootsFor line 455), and a fix retry that answers only one of the
 * two questions asks both again. The spawned conformance tests reach the 2026-07-28 roots ask, but not these. The
 * runCheck stub stands for the evaluator call: each call is one fetch. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { PassThrough } from "node:stream";
import { mkdirSync, mkdtempSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { ROOTS_UNREADABLE_MESSAGE, startServer } from "../lib/inspector/server.mjs";

const repo = () => { const dir = realpathSync(mkdtempSync(join(tmpdir(), "t19-confirm-roots-"))); mkdirSync(join(dir, ".git")); return dir; };
const MODERN = "2026-07-28";

/* An in-process server and a bare client. `reply(id)` is the client's line for an elicitation/create (null: none).
 * `root`: the working-directory fallback, or none. */
function harness({ caps, reply = (id) => ({ jsonrpc: "2.0", id, result: { action: "decline" } }), root = repo(), modern = false }) {
  const stdin = new PassThrough(), stdout = new PassThrough();
  const fetches = [];
  const runCheck = async (args, ctx) => { fetches.push({ args, roots: ctx.roots }); return { goal: args.goal ?? "check", status: "done", next_step: "show the person the fixes", charged_units: 1 }; };
  const done = startServer({ stdin, stdout, root, runCheck });
  let buffer = "", nextId = 1;
  const pending = new Map(), asked = [], answered = [];
  const send = (msg) => stdin.write(JSON.stringify(msg) + "\n");
  stdout.on("data", (d) => {
    buffer += d;
    let nl;
    while ((nl = buffer.indexOf("\n")) >= 0) {
      const msg = JSON.parse(buffer.slice(0, nl)); buffer = buffer.slice(nl + 1);
      if (msg.method === "elicitation/create") {
        asked.push(msg);
        const line = reply(msg.id);
        if (line) send(line);
      } else if (msg.id !== undefined) {
        answered.push(msg.id);
        if (pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id); }
      }
    }
  });
  const request = (method, params, id = nextId++) => new Promise((ok) => { pending.set(id, ok); send({ jsonrpc: "2.0", id, method, params }); });
  const envelope = (extra = {}) => ({ _meta: { "io.modelcontextprotocol/protocolVersion": MODERN,
    "io.modelcontextprotocol/clientInfo": { name: "t19-test", version: "0" }, "io.modelcontextprotocol/clientCapabilities": caps }, ...extra });
  const open = async () => {
    if (modern) return;
    await request("initialize", { protocolVersion: "2025-11-25", clientInfo: { name: "t19-test", version: "0" }, capabilities: caps });
    send({ jsonrpc: "2.0", method: "notifications/initialized" });
  };
  const call = async (args, extra = {}, id) => (await request("tools/call", { name: "check_schema", arguments: args, ...(modern ? envelope(extra) : {}) }, id)).result;
  return { open, call, send, fetches, asked, answered, end: () => { stdin.end(); return done; } };
}

const isDecline = (r) => {
  assert.equal(r.isError, undefined);
  assert.equal(r.structuredContent.goal, "fix");
  assert.equal(r.structuredContent.charged_units, 0);
  assert.match(r.structuredContent.next_step, /ask again only if they ask for fixes/);
};

test("a fix question the host answers with an error, or with an answer outside the schema, is no approval", async () => {
  const replies = {
    "JSON-RPC error": (id) => ({ jsonrpc: "2.0", id, error: { code: -32603, message: "the editor closed the box" } }),
    "unknown action": (id) => ({ jsonrpc: "2.0", id, result: { action: "maybe" } }),
    "no action": (id) => ({ jsonrpc: "2.0", id, result: { content: { apply: true } } }),
  };
  for (const [name, reply] of Object.entries(replies)) {
    const h = harness({ caps: { elicitation: {} }, reply });
    await h.open();
    const r = await h.call({ goal: "fix" });
    assert.equal(h.asked.length, 1, name);
    assert.equal(h.fetches.length, 0, name);
    isDecline(r);
    // The server is still up and asks again on the next fix.
    await h.call({ goal: "fix" });
    assert.equal(h.asked.length, 2, name);
    assert.equal(h.fetches.length, 0, name);
    await h.end();
  }
});

test("a fix cancelled while its question is open makes no call and gets no answer", async () => {
  const h = harness({ caps: { elicitation: {} }, reply: () => null });
  await h.open();
  const id = 77;
  h.call({ goal: "fix" }, {}, id); // never settles
  while (h.asked.length === 0) await new Promise((r) => setTimeout(r, 5));
  h.send({ jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: id, reason: "the person stopped it" } });
  // The next call is answered, so the cancelled one had its turn; it never is.
  const next = await h.call({ goal: "check" });
  assert.equal(next.structuredContent.goal, "check");
  await new Promise((r) => setTimeout(r, 50));
  assert.ok(!h.answered.includes(id), "a cancelled call is not answered");
  assert.deepEqual(h.fetches.map((f) => f.args.goal), ["check"]);
  await h.end();
});

// With or without a working-directory repository: a host that offers roots never falls back to it.
test("2026-07-28: a retry whose inputResponses has no readable roots is refused, with no call", async () => {
  const project = repo();
  for (const root of [null, repo()]) for (const responses of [{}, { roots: "junk" }, { roots: { roots: "junk" } }, { other: { roots: [] } }]) {
    const h = harness({ caps: { roots: {} }, root, modern: true });
    const first = await h.call({ goal: "check" });
    assert.ok(first.inputRequests?.roots, JSON.stringify(first));
    const r = await h.call({ goal: "check" }, { inputResponses: responses });
    const what = `${root ? "with" : "without"} a fallback: ${JSON.stringify(responses)}`;
    assert.equal(r.isError, true, what);
    assert.equal(r.content[0].text, ROOTS_UNREADABLE_MESSAGE, what);
    assert.equal(h.fetches.length, 0, what);
    // The same retry with the roots answered goes on with that project.
    const ok = await h.call({ goal: "check" }, { inputResponses: { roots: { roots: [{ uri: pathToFileURL(project).href }] } } });
    assert.equal(ok.isError, undefined);
    assert.deepEqual(h.fetches.map((f) => f.roots), [[project]]);
    await h.end();
  }
});

test("2026-07-28: a fix retry that answers only one of the two questions asks both again", async () => {
  const project = repo();
  const roots = { roots: { roots: [{ uri: pathToFileURL(project).href }] } };
  const yes = { confirm_fix: { action: "accept", content: { apply: true } } };
  const h = harness({ caps: { roots: {}, elicitation: {} }, root: null, modern: true });
  const first = await h.call({ goal: "fix" });
  assert.deepEqual(Object.keys(first.inputRequests).sort(), ["confirm_fix", "roots"]);
  const rootsOnly = await h.call({ goal: "fix" }, { inputResponses: roots });
  assert.deepEqual(Object.keys(rootsOnly.inputRequests).sort(), ["confirm_fix", "roots"]);
  // Yes without the roots: the project is unknown, so nothing runs.
  const yesOnly = await h.call({ goal: "fix" }, { inputResponses: yes });
  assert.equal(yesOnly.isError, true);
  assert.equal(yesOnly.content[0].text, ROOTS_UNREADABLE_MESSAGE);
  assert.equal(h.fetches.length, 0);
  const both = await h.call({ goal: "fix" }, { inputResponses: { ...roots, ...yes } });
  assert.equal(both.structuredContent.confirmed_by, "person");
  assert.deepEqual(h.fetches.map((f) => f.roots), [[project]]);
  await h.end();
});

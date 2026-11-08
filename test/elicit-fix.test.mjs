/* Before any fixes are given, the person confirms in their own editor. check_schema
 * goal fix asks with elicitation/create when the host declared the capability; on a decline it makes no evaluator call
 * and charges nothing. Hosts without the capability go on as before (confirmed_by: instructions). Only fix asks. The
 * runCheck stub stands for the evaluator call: each call is one fetch. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { PassThrough } from "node:stream";
import { mkdirSync, mkdtempSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startServer } from "../lib/inspector/server.mjs";

const repo = () => { const dir = realpathSync(mkdtempSync(join(tmpdir(), "custosa-elicit-"))); mkdirSync(join(dir, ".git")); return dir; };
const MODERN = "2026-07-28";

function harness({ elicitation, answer = null, modern = false }) {
  const stdin = new PassThrough(), stdout = new PassThrough();
  const fetches = [];
  const runCheck = async (args) => { fetches.push(args); return { goal: args.goal ?? "check", status: "done", next_step: "show the person the fixes", charged_units: 1 }; };
  const done = startServer({ stdin, stdout, root: repo(), runCheck });
  let buffer = "", nextId = 1;
  const pending = new Map(), asked = [];
  const send = (msg) => stdin.write(JSON.stringify(msg) + "\n");
  stdout.on("data", (d) => {
    buffer += d;
    let nl;
    while ((nl = buffer.indexOf("\n")) >= 0) {
      const msg = JSON.parse(buffer.slice(0, nl)); buffer = buffer.slice(nl + 1);
      if (msg.method === "elicitation/create") {
        asked.push(msg.params);
        send({ jsonrpc: "2.0", id: msg.id, result: answer ?? { action: "decline" } });
      } else if (msg.id !== undefined && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id); }
    }
  });
  const request = (method, params) => new Promise((ok) => { const id = nextId++; pending.set(id, ok); send({ jsonrpc: "2.0", id, method, params }); });
  const caps = elicitation ? { elicitation: {} } : {};
  const envelope = (extra = {}) => ({ _meta: { "io.modelcontextprotocol/protocolVersion": MODERN,
    "io.modelcontextprotocol/clientInfo": { name: "elicit-test", version: "0" }, "io.modelcontextprotocol/clientCapabilities": caps }, ...extra });
  const open = async () => {
    if (modern) return;
    await request("initialize", { protocolVersion: "2025-11-25", clientInfo: { name: "elicit-test", version: "0" }, capabilities: caps });
    send({ jsonrpc: "2.0", method: "notifications/initialized" });
  };
  const call = async (args, extra = {}) => (await request("tools/call", { name: "check_schema", arguments: args, ...(modern ? envelope(extra) : {}) })).result;
  return { open, call, fetches, asked, end: () => { stdin.end(); return done; } };
}

test("A declined fix makes no evaluator call and says so", async () => {
  const h = harness({ elicitation: true, answer: { action: "decline" } });
  await h.open();
  const r = await h.call({ goal: "fix" });
  assert.equal(h.fetches.length, 0);
  assert.equal(h.asked.length, 1);
  assert.equal(r.isError, undefined);
  assert.equal(r.structuredContent.goal, "fix");
  assert.equal(r.structuredContent.charged_units, 0);
  assert.match(r.structuredContent.next_step, /ask again only if they ask for fixes/);
  await h.end();
});

// Cursor closes the question after about 60 s and can hide it in a
// collapsed tool row, so a decline may be a question the person never saw. Every decline, the 2025 call and the
// 2026-07-28 retry alike, says so in the text and in next_step, and still makes no evaluator call.
test("A declined fix says to call again if the person missed the question", async () => {
  for (const [modern, extra] of [[false, {}], [true, { inputResponses: { confirm_fix: { action: "cancel" } } }]]) {
    const h = harness({ elicitation: true, answer: { action: "cancel" }, modern });
    await h.open();
    const r = await h.call({ goal: "fix" }, extra);
    assert.equal(h.fetches.length, 0);
    assert.match(r.content[0].text, /If you missed the question, call again/);
    assert.match(r.structuredContent.local_notes.join(" "), /If you missed the question, call again/);
    assert.match(r.structuredContent.next_step, /missed the question/);
    assert.match(r.structuredContent.next_step, /ask again only if they ask for fixes/);
    await h.end();
  }
});

test("A fix accepted with yes makes exactly one evaluator call, confirmed by the person", async () => {
  const h = harness({ elicitation: true, answer: { action: "accept", content: { apply: true } } });
  await h.open();
  const r = await h.call({ goal: "fix" });
  assert.equal(h.fetches.length, 1);
  assert.equal(r.structuredContent.confirmed_by, "person");
  await h.end();
});

test("Accepting with no, or cancelling, is a decline", async () => {
  for (const answer of [{ action: "accept", content: { apply: false } }, { action: "cancel" }]) {
    const h = harness({ elicitation: true, answer });
    await h.open();
    const r = await h.call({ goal: "fix" });
    assert.equal(h.fetches.length, 0, JSON.stringify(answer));
    assert.equal(r.structuredContent.charged_units, 0);
    await h.end();
  }
});

test("A host without elicitation goes on, confirmed by instructions", async () => {
  const h = harness({ elicitation: false });
  await h.open();
  const r = await h.call({ goal: "fix" });
  assert.equal(h.fetches.length, 1);
  assert.equal(h.asked.length, 0);
  assert.equal(r.structuredContent.confirmed_by, "instructions");
  await h.end();
});

test("Only fix asks; check and verify never do", async () => {
  const h = harness({ elicitation: true, answer: { action: "decline" } });
  await h.open();
  await h.call({ goal: "check" });
  await h.call({ goal: "verify" });
  assert.equal(h.asked.length, 0);
  assert.equal(h.fetches.length, 2);
  await h.end();
});

// The box shows no count of findings; it points to the report and asks once.
const NO_LINK = "Your PHI Schema Check report is ready in this chat. Do you want to start making the changes it recommends to your code and local development database?";
test("The question points to the report, with no number of findings and no table, column or file", async () => {
  const h = harness({ elicitation: true, answer: { action: "decline" } });
  await h.open();
  await h.call({ goal: "fix", finding_ids: ["rls-forced@public.patients", "phi-in-logs@src/api/visits.ts"] });
  const [asked] = h.asked;
  assert.equal(asked.message, NO_LINK);
  assert.doesNotMatch(asked.message, /[0-9]|patients|visits/);
  assert.deepEqual(Object.keys(asked.requestedSchema.properties), ["apply"]);
  assert.equal(asked.requestedSchema.properties.apply.type, "boolean");
  await h.end();
});

test("The confirmation rides input_required, and a declined retry makes no call", async () => {
  const h = harness({ elicitation: true, modern: true });
  const first = await h.call({ goal: "fix" });
  assert.equal(h.fetches.length, 0);
  assert.ok(first.inputRequests?.confirm_fix, JSON.stringify(first));
  assert.equal(first.inputRequests.confirm_fix.params.message, NO_LINK);
  const declined = await h.call({ goal: "fix" }, { inputResponses: { confirm_fix: { action: "decline" } } });
  assert.equal(h.fetches.length, 0);
  assert.equal(declined.structuredContent.charged_units, 0);
  const accepted = await h.call({ goal: "fix" }, { inputResponses: { confirm_fix: { action: "accept", content: { apply: true } } } });
  assert.equal(h.fetches.length, 1);
  assert.equal(accepted.structuredContent.confirmed_by, "person");
  await h.end();
});

// a done check's page 1 carries report_url, the account page where the run is
// listed. The fix question in that session points there; another session, or a link that isn't https, keeps "in this chat".
const SESSION = "ps_AbCdEfGhIjKlMnOpQrStUv";
const LINK = "https://custosa.com/billing#results";
test("The fix question names the check's report link in that session, and only there", async () => {
  const stdin = new PassThrough(), stdout = new PassThrough();
  const asked = [];
  const runCheck = async (args) => (args.goal === "check"
    ? { goal: "check", status: "done", session: SESSION, report_url: LINK, next_step: "show the person", charged_units: 1 }
    : { goal: args.goal, status: "done", next_step: "x", charged_units: 1 });
  const done = startServer({ stdin, stdout, root: repo(), runCheck });
  const h = wire(stdin, stdout, asked);
  await h.open();
  await h.call({ goal: "fix", session: SESSION });
  assert.equal(asked.at(-1).message, NO_LINK);
  await h.call({ goal: "check" });
  await h.call({ goal: "fix", session: SESSION });
  assert.equal(asked.at(-1).message, `Your PHI Schema Check report is ready: ${LINK}. Do you want to start making the changes it recommends to your code and local development database?`);
  assert.doesNotMatch(asked.at(-1).message.replace(LINK, ""), /[0-9]/);
  await h.call({ goal: "fix", session: "ps_ZyXwVuTsRqPoNmLkJiHgFe" });
  assert.equal(asked.at(-1).message, NO_LINK);
  stdin.end(); await done;
});

test("A report_url that isn't an https link is never shown", async () => {
  for (const bad of ["http://custosa.com/billing#results", "javascript:alert(1)", `https://custosa.com/${"a".repeat(300)}`, "https://custosa.com/a b"]) {
    const stdin = new PassThrough(), stdout = new PassThrough();
    const asked = [];
    const runCheck = async (args) => ({ goal: args.goal, status: "done", session: SESSION, report_url: bad, next_step: "x", charged_units: 1 });
    const done = startServer({ stdin, stdout, root: repo(), runCheck });
    const h = wire(stdin, stdout, asked);
    await h.open();
    await h.call({ goal: "check" });
    await h.call({ goal: "fix", session: SESSION });
    assert.equal(asked.at(-1).message, NO_LINK, bad);
    stdin.end(); await done;
  }
});

/* A bare client on the server's stdio that declines every question and keeps it in `asked`. */
function wire(stdin, stdout, asked) {
  let buffer = "", nextId = 1;
  const pending = new Map();
  const send = (msg) => stdin.write(JSON.stringify(msg) + "\n");
  stdout.on("data", (d) => {
    buffer += d;
    let nl;
    while ((nl = buffer.indexOf("\n")) >= 0) {
      const msg = JSON.parse(buffer.slice(0, nl)); buffer = buffer.slice(nl + 1);
      if (msg.method === "elicitation/create") { asked.push(msg.params); send({ jsonrpc: "2.0", id: msg.id, result: { action: "decline" } }); }
      else if (msg.id !== undefined && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id); }
    }
  });
  const request = (method, params) => new Promise((ok) => { const id = nextId++; pending.set(id, ok); send({ jsonrpc: "2.0", id, method, params }); });
  return {
    open: async () => {
      await request("initialize", { protocolVersion: "2025-11-25", clientInfo: { name: "elicit-test", version: "0" }, capabilities: { elicitation: {} } });
      send({ jsonrpc: "2.0", method: "notifications/initialized" });
    },
    call: async (args) => (await request("tools/call", { name: "check_schema", arguments: args })).result,
  };
}

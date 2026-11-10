/* The production-audit fixes to the inspector's MCP surface: JSON-RPC errors for unreadable lines and non-object
 * arguments (PC4), refusals as isError results (PC4), structuredContent against the outputSchema (PC5), the text block
 * (TU2), cancellation (PC8), progress (PC9) and the project root override (PC3). In process, over PassThrough
 * streams; no real service. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { fileURLToPath, pathToFileURL } from "node:url";
import AjvModule from "ajv";
import { InspectorStdioTransport, startServer, textFor } from "../lib/inspector/server.mjs";
import { GUIDANCE_OUTPUT_SCHEMA, OUTPUT_SCHEMA, RESULT_OUTPUT_SCHEMA, TOOL, TOOLS, makeRunCheck } from "../lib/inspector/tool.mjs";
import { LOCAL, localError } from "../lib/inspector/client.mjs";
import { writeToken } from "../lib/inspector/auth.mjs";
import { liveWorkers, loadRules, runRules } from "../lib/inspector/rules.mjs";
import { buildFactDocuments } from "../lib/inspector/factdoc.mjs";
import { EVALUATE_OK, stub } from "./stub-evaluator.mjs";

const Ajv = AjvModule.default ?? AjvModule;
const validateOutput = new Ajv({ strict: false }).compile(OUTPUT_SCHEMA);
const validateGuidance = new Ajv({ strict: false }).compile(GUIDANCE_OUTPUT_SCHEMA);
const validateResult = new Ajv({ strict: false }).compile(RESULT_OUTPUT_SCHEMA);
const temp = (prefix) => realpathSync(mkdtempSync(join(tmpdir(), prefix)));
const repo = (files = {}) => {
  const dir = temp("custosa-proto-");
  mkdirSync(join(dir, ".git"));
  for (const [p, t] of Object.entries(files)) { mkdirSync(join(dir, p, ".."), { recursive: true }); writeFileSync(join(dir, p), t); }
  return dir;
};

/* A minimal client that records every message, answers roots/list from `roots`, and can send raw lines. */
function serve({ runCheck, root = null, roots = null, projectRoot = null, clientName = "test" } = {}) {
  const stdin = new PassThrough(), stdout = new PassThrough();
  const done = startServer({ stdin, stdout, root, runCheck, projectRoot });
  let buffer = "", nextId = 1;
  const pending = new Map(), seen = [];
  stdout.on("data", (d) => {
    buffer += d;
    let nl;
    while ((nl = buffer.indexOf("\n")) >= 0) {
      const msg = JSON.parse(buffer.slice(0, nl)); buffer = buffer.slice(nl + 1);
      seen.push(msg);
      if (msg.method === "roots/list") raw(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { roots: roots ?? [] } }));
      else if (msg.id !== undefined && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id); }
    }
  });
  const raw = (line) => stdin.write(`${line}\n`);
  const waitFor = (id) => new Promise((ok) => pending.set(id, ok));
  const request = (method, params, id = nextId++) => { const p = waitFor(id); raw(JSON.stringify({ jsonrpc: "2.0", id, method, params })); return p; };
  const handshake = async () => {
    await request("initialize", { protocolVersion: "2025-06-18", clientInfo: { name: clientName, version: "0" }, capabilities: roots ? { roots: {} } : {} });
    raw(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }));
  };
  return { raw, request, waitFor, handshake, seen, end: () => { stdin.end(); return done; }, nextId: () => nextId++ };
}

const ok = async () => EVALUATE_OK;

test("PC4: a line that isn't JSON gets -32700, JSON that isn't JSON-RPC gets -32600, and the server keeps serving", async () => {
  const s = serve({ runCheck: ok, root: repo() });
  await s.handshake();
  const parse = new Promise((done) => { const t = setInterval(() => { const m = s.seen.find((x) => x.error?.code === -32700); if (m) { clearInterval(t); done(m); } }, 10); });
  s.raw("{not json");
  const m = await parse;
  assert.equal(m.id, null);
  const invalid = s.waitFor(77);
  s.raw(JSON.stringify({ id: 77, method: 5 })); // a request that isn't valid JSON-RPC
  assert.equal((await invalid).error.code, -32600);
  // L1: no answer to anything that isn't a request: a broken notification, a response or batch from the client,
  // a bare value, a blank line or a lone carriage return.
  for (const line of [JSON.stringify({ jsonrpc: "2.0", method: 5 }), JSON.stringify({ id: 78, hello: "world" }), JSON.stringify({ jsonrpc: "2.0", id: 79, result: null, extra: 1 }),
    "[]", JSON.stringify([{ jsonrpc: "2.0", id: 80, method: "ping" }]), "null", "1", "", "\r", "   "]) s.raw(line);
  const list = await s.request("tools/list", {});
  assert.equal(list.result.tools[0].name, "check_schema");
  assert.equal(s.seen.filter((x) => x.error && x.id === null).length, 1, JSON.stringify(s.seen.filter((x) => x.error)));
  assert.ok(!s.seen.some((x) => [78, 79, 80].includes(x.id)));
  await s.end();
});

test("PC4: non-object arguments get JSON-RPC -32602", async () => {
  const s = serve({ runCheck: ok, root: repo() });
  await s.handshake();
  for (const args of ["check", [1, 2], 42, null]) {
    const res = await s.request("tools/call", { name: "check_schema", arguments: args });
    assert.equal(res.error?.code, -32602, `${JSON.stringify(args)}: ${JSON.stringify(res)}`);
  }
  const absent = await s.request("tools/call", { name: "check_schema" }); // no arguments at all: the default goal
  assert.equal(absent.result.isError, undefined);
  await s.end();
});

test("PC4: not signed in, unreachable, low balance and evaluator 4xx/5xx are isError results with the next step", async () => {
  const answers = [
    localError("sign_in_required"),
    localError("evaluator_unreachable"),
    { error: "insufficient_balance", next_step: "Add credit, then call check_schema again.", correlation_id: "corr_12345678", balance: 0, currency: "usd", top_up_url: "https://custosa.com/billing" },
    { error: "unavailable", next_step: "Wait, then call check_schema again.", correlation_id: "corr_12345678", retry_after_seconds: 5 },
    { error: "internal_error", next_step: "Call check_schema again.", correlation_id: "corr_12345678" },
  ];
  let i = 0;
  const s = serve({ runCheck: async () => answers[i++], root: repo() });
  await s.handshake();
  for (const a of answers) {
    const res = (await s.request("tools/call", { name: "check_schema", arguments: { goal: "check" } })).result;
    assert.equal(res.isError, true, a.error);
    assert.equal(res.structuredContent, undefined);
    assert.ok(res.content[0].text.startsWith(a.next_step), res.content[0].text);
    if (a.top_up_url) assert.match(res.content[0].text, /Top up: https:\/\/custosa\.com\/billing/);
  }
  assert.match(LOCAL.evaluator_unreachable, /check the connection/);
  await s.end();
});

test("PC5 + TU2: structuredContent matches the outputSchema; the text is a summary plus the response for text-only clients", async () => {
  const s = serve({ runCheck: ok, root: repo() });
  await s.handshake();
  const res = (await s.request("tools/call", { name: "check_schema", arguments: {} })).result;
  assert.deepEqual(res.structuredContent, EVALUATE_OK);
  assert.ok(validateOutput(res.structuredContent), JSON.stringify(validateOutput.errors));
  const text = res.content[0].text;
  assert.ok(text.startsWith(EVALUATE_OK.headline));
  assert.match(text, /status in_progress/);
  assert.match(text, /session ps_abcdefghijklmnopqrstuv/);
  assert.match(text, /Next step: Answer the questions\./);
  assert.deepEqual(JSON.parse(text.split("\n").at(-1)), EVALUATE_OK);
  const short = textFor(EVALUATE_OK, { full: false });
  assert.ok(!short.includes(EVALUATE_OK.correlation_id) && short.endsWith("The full response is in structuredContent."));
  assert.deepEqual(TOOL.outputSchema, OUTPUT_SCHEMA);
  await s.end();
});

test("PC5: real outputs validate against the outputSchema (single root, other roots, advice, local-only)", async () => {
  const RULES = loadRules(fileURLToPath(new URL("./fixtures/rules/", import.meta.url)));
  const quiet = {
    ruleset: { id: "2026-10-20.0123abcd", rules: RULES, queries: [] },
    collectCatalog: async () => ({ status: "not_run", count: 0, reason: "service_missing", preflight: null, queries: [] }),
    collectPlatform: async () => ({ provider: null, status: "not_run", reason: "no_token", settings: {} }),
  };
  const advice = { goal: "explain", status: "done", session: "ps_abcdefghijklmnopqrstuv", content: "## Practice\nText.",
    is_fetch_only: false, charged_units: 10, next_step: "Show it.", notice: "", correlation_id: "corr_12345678" };
  // a get_result read answers get_result_response (T29 o2): here a selector that matches nothing
  const read = (body) => ({ goal: body.goal, session: body.session, select: body.select, part: "detail", matched: 0, results: [],
    values: [], is_fetch_only: true, charged_units: 0, correlation_id: "corr_12345678" });
  const evaluator = await stub((call) => ({ status: 200, json: call.body.select ? read(call.body)
    : call.body.goal === "explain" ? advice : EVALUATE_OK }));
  const configDir = join(temp("custosa-proto-cfg-"), "custosa");
  writeToken(`phisc_${"t".repeat(43)}`, { configDir, host: new URL(evaluator.url).origin });
  try {
    const runCheck = makeRunCheck({ configDir, localOnly: false, buildOptions: quiet,
      evaluatorUrl: () => ({ url: evaluator.url, origin: new URL(evaluator.url).origin }), clientOptions: { sleep: async () => {} } });
    const root = repo({ "src/db.ts": "export const x = 1;\n" }), other = repo();
    const outputs = [
      await runCheck({ goal: "check" }, { roots: [root, other] }), // another root found, not checked
      await runCheck({ goal: "check", include_other_roots: true }, { roots: [root, other] }),
      await runCheck({ goal: "check" }, { roots: [repo()] }),
      await makeRunCheck({ localOnly: true, configDir, buildOptions: quiet })({ goal: "check" }, { roots: [root] }),
    ];
    assert.ok(outputs[0].other_roots && outputs[1].results.length === 2, JSON.stringify(outputs[0]).slice(0, 300));
    for (const out of outputs) assert.ok(validateOutput(out), `${JSON.stringify(validateOutput.errors)} ${JSON.stringify(out).slice(0, 300)}`);
    // schema_guidance and get_result, each against its own outputSchema
    const advised = await runCheck({ goal: "explain", practice_id: "audit-log" }, { roots: [] });
    assert.ok(validateGuidance(advised), JSON.stringify(validateGuidance.errors));
    assert.ok(!validateOutput(advised), "an advice answer is not a check_schema result");
    const local = await makeRunCheck({ localOnly: true, configDir, buildOptions: quiet })({ goal: "plan", entities: [{ name: "patients", columns: [{ name: "dob" }] }] }, { roots: [] });
    assert.ok(validateGuidance(local), JSON.stringify(validateGuidance.errors));
    for (const args of [{ goal: "check", session: EVALUATE_OK.session, select: { state: "fail" } }, { goal: "explain", session: EVALUATE_OK.session, select: { advice: "practice" } }]) {
      const fetched = await runCheck(args, { roots: [] });
      assert.ok(validateResult(fetched), JSON.stringify(validateResult.errors));
      assert.ok(!validateResult(EVALUATE_OK), "a check answer is not a get_result result");
    }
    // L-b: a get_result read in local-only mode validates too
    const localRead = await makeRunCheck({ localOnly: true, configDir, buildOptions: quiet })({ goal: "check", session: EVALUATE_OK.session, select: { state: "fail" } }, { roots: [] });
    assert.equal(localRead.local_only, true);
    assert.ok(validateResult(localRead), JSON.stringify(validateResult.errors));
    assert.ok(!validateOutput({ error: "sign_in_required", next_step: "x", local: true }), "an error is never a structured result");
  } finally { await evaluator.close(); }
});

test("PC8: notifications/cancelled aborts the call's signal; no answer is sent for it", async () => {
  let aborted = null;
  const started = Date.now();
  const runCheck = (args, ctx) => new Promise((_, fail) => {
    const stop = () => { aborted = Date.now() - started; fail(ctx.signal.reason); };
    // under load the cancel can be read before runCheck starts, as the real runCheck's throwIfAborted allows for
    if (ctx.signal.aborted) return stop();
    ctx.signal.addEventListener("abort", stop);
  });
  const s = serve({ runCheck, root: repo() });
  await s.handshake();
  const id = s.nextId();
  s.raw(JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params: { name: "check_schema", arguments: {} } }));
  await new Promise((ok) => setTimeout(ok, 100));
  s.raw(JSON.stringify({ jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: id, reason: "user" } }));
  // polled rather than slept: on a loaded machine the notification can take a moment to be read
  const sentAt = Date.now() - started;
  for (let i = 0; i < 100 && aborted === null; i++) await new Promise((ok) => setTimeout(ok, 20));
  assert.ok(aborted !== null && aborted - sentAt < 2000, `aborted ${aborted} ms after start, the cancel sent at ${sentAt} ms`);
  assert.ok(!s.seen.some((m) => m.id === id), "no answer to a cancelled request");
  assert.equal((await s.request("tools/list", {})).result.tools.length, 3, "still serving");
  await s.end();
});

test("PC8: a cancelled scan stops its rule workers promptly and the build throws instead of returning", async () => {
  const RULES = loadRules(fileURLToPath(new URL("./fixtures/rules/", import.meta.url)));
  const root = repo(Object.fromEntries(Array.from({ length: 60 }, (_, i) => [`src/f${i}.ts`, `export async function f${i}(p) { await db.from("patients").insert(p); }\n`])));
  const files = Array.from({ length: 60 }, (_, i) => ({ path: `src/f${i}.ts` }));
  const controller = new AbortController();
  let seen = 0;
  const t0 = Date.now();
  const res = await runRules(RULES, files, { key: "k".repeat(32), frameworks: [], root, workers: 2, signal: controller.signal,
    onFile: (done) => { seen = done; if (done === 3) controller.abort(); } });
  assert.ok(Date.now() - t0 < 15_000);
  assert.equal(liveWorkers(), 0, "every worker exited");
  assert.ok(res.notAnalyzed.filter((e) => e.reason === "time_limit").length > 40, `files left after the abort: ${seen}`);

  const c2 = new AbortController();
  const events = [];
  const quiet = {
    ruleset: { id: "2026-10-20.0123abcd", rules: RULES, queries: [] }, configDir: join(temp("custosa-proto-cfg-"), "custosa"),
    collectCatalog: async () => ({ status: "not_run", count: 0, reason: "service_missing", preflight: null, queries: [] }),
    collectPlatform: async () => ({ provider: null, status: "not_run", reason: "no_token", settings: {} }),
  };
  await assert.rejects(buildFactDocuments([root], { ...quiet, signal: c2.signal,
    onProgress: (e) => { events.push(e); if (e.phase === "rules" && e.done >= 2) c2.abort(); } }), { name: "AbortError" });
  assert.equal(liveWorkers(), 0);
  assert.deepEqual([...new Set(events.map((e) => e.phase))].slice(0, 4), ["platform", "catalog", "walk", "rules"]);

  // The tool's handler passes the call's signal on: a cancelled call never builds, sends or answers.
  const c3 = new AbortController();
  c3.abort();
  await assert.rejects(makeRunCheck({ localOnly: true, configDir: quiet.configDir, buildOptions: quiet })({ goal: "check" }, { roots: [root], signal: c3.signal }),
    { name: "AbortError" });
});

test("PC9: progress notifications go out only with a progressToken, throttled, rising, ending at 100", async () => {
  const runCheck = async (args, ctx) => {
    ctx.progress?.({ phase: "platform" });
    ctx.progress?.({ phase: "catalog" });
    ctx.progress?.({ phase: "walk", root: 0, roots: 1 });
    for (let i = 0; i <= 200; i++) ctx.progress?.({ phase: "rules", done: i, total: 200 });
    ctx.progress?.({ phase: "send" });
    return EVALUATE_OK;
  };
  const s = serve({ runCheck, root: repo() });
  await s.handshake();
  await s.request("tools/call", { name: "check_schema", arguments: {} });
  assert.ok(!s.seen.some((m) => m.method === "notifications/progress"), "none without a progressToken");
  await s.request("tools/call", { name: "check_schema", arguments: {}, _meta: { progressToken: "tok-1" } });
  await new Promise((ok) => setTimeout(ok, 50));
  const progress = s.seen.filter((m) => m.method === "notifications/progress").map((m) => m.params);
  assert.ok(progress.length >= 5 && progress.length < 20, `${progress.length} notifications`);
  assert.ok(progress.every((p) => p.progressToken === "tok-1" && p.total === 100 && typeof p.message === "string"));
  for (let i = 1; i < progress.length; i++) assert.ok(progress[i].progress > progress[i - 1].progress);
  assert.equal(progress.at(-1).progress, 100);
  assert.ok(progress.some((p) => /^Scanning files: \d+ of 200$/.test(p.message)));
  await s.end();
});

test("PC3: an explicit project root wins over the host's roots; a missing one is refused, never replaced", async () => {
  const chosen = repo(), offered = repo();
  const got = [];
  const s = serve({ runCheck: async (a, ctx) => { got.push(ctx.roots); return EVALUATE_OK; }, projectRoot: chosen, roots: [{ uri: pathToFileURL(offered).href }] });
  await s.handshake();
  assert.equal((await s.request("tools/call", { name: "check_schema", arguments: {} })).result.isError, undefined);
  assert.deepEqual(got, [[chosen]]);
  assert.ok(!s.seen.some((m) => m.method === "roots/list"), "the host's roots aren't asked for");
  await s.end();

  const missing = serve({ runCheck: ok, projectRoot: join(chosen, "nope") });
  await missing.handshake();
  const res = (await missing.request("tools/call", { name: "check_schema", arguments: {} })).result;
  assert.equal(res.isError, true);
  assert.match(res.content[0].text, /CUSTOSA_PROJECT_ROOT/);
  await missing.end();
});

test("L5: the SDK pin is @modelcontextprotocol/server 2.3.1; the transport reads lines itself, through no SDK private field", async () => {
  const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  assert.equal(pkg.dependencies["@modelcontextprotocol/server"], "2.3.1");
  assert.equal(pkg.dependencies["@modelcontextprotocol/sdk"], undefined, "the v1 SDK is gone");
  assert.equal(Object.getPrototypeOf(InspectorStdioTransport.prototype), Object.prototype, "subclasses no SDK transport");
  const stdin = new PassThrough(), stdout = new PassThrough();
  const t = new InspectorStdioTransport(stdin, stdout);
  const got = [];
  t.onmessage = (m) => got.push(m);
  await t.start();
  stdin.write('{"jsonrpc":"2.0","method":"a"}\r\n{"jsonrpc":"2.0",');
  stdin.write('"method":"b"}\n\n');
  await new Promise((ok) => setImmediate(ok));
  assert.deepEqual(got.map((m) => m.method), ["a", "b"]);
  let closed = 0;
  t.onclose = () => { closed++; };
  stdin.end();
  await t.closed;
  assert.equal(closed, 1);
  await t.send({ jsonrpc: "2.0", id: 1, result: {} }); // after close: dropped, no throw
});

test("TU1: three tools, each with a title, a short name, its own schemas and annotations; get_result alone is idempotent", () => {
  assert.deepEqual(TOOLS.map((t) => t.name), ["check_schema", "schema_guidance", "get_result"]);
  for (const t of TOOLS) {
    assert.ok(t.name.length <= 64 && /^[a-z_]+$/.test(t.name));
    assert.ok(t.title && t.annotations.title === t.title);
    assert.equal(t.inputSchema.type, "object");
    assert.equal(t.outputSchema.type, "object");
    assert.equal(t.annotations.openWorldHint, true);
    assert.equal(t.annotations.destructiveHint, false);
    assert.ok(!/\bfree\b|—|\bexpert\b|never stop/i.test(t.description), t.name);
  }
  const [check, guidance, result] = TOOLS;
  for (const t of [check, guidance]) { assert.equal(t.annotations.readOnlyHint, false); assert.equal(t.annotations.idempotentHint, false); }
  // get_result reads what is stored: the same answer each time, never charged (T29 o2), and writes nothing on this
  // computer, so it is read-only (T29-P1-C119)
  assert.equal(result.annotations.readOnlyHint, true);
  assert.equal(result.annotations.idempotentHint, true);
  assert.match(result.description, /Not charged/);
  assert.match(guidance.description, /advice rate/);
  assert.doesNotMatch(guidance.description, /app_description/);
  assert.deepEqual(check.inputSchema.properties.goal.enum, ["check", "fix", "verify"]);
  assert.deepEqual(guidance.inputSchema.properties.goal.enum, ["plan", "pattern", "explain"]);
});

test("TU1: each tool refuses what belongs to another, with isError and the right tool named; nothing reaches the handler", async () => {
  const calls = [];
  const s = serve({ runCheck: async (args) => { calls.push(args); return EVALUATE_OK; }, root: repo() });
  await s.handshake();
  const call = (name, args) => s.request("tools/call", { name, arguments: args }).then((m) => m.result);
  const cases = [
    ["check_schema", { goal: "plan", entities: [] }, "schema_guidance"],
    ["check_schema", { goal: "explain", practice_id: "audit-log" }, "schema_guidance"],
    ["check_schema", { goal: "check", session: EVALUATE_OK.session, select: { state: "fail" } }, "get_result"],
    ["check_schema", { goal: "check", session: EVALUATE_OK.session, part: "fix" }, "get_result"],
    ["schema_guidance", { goal: "check" }, "check_schema"],
    ["schema_guidance", { goal: "explain", practice_id: "audit-log", select: { advice: "practice" } }, "get_result"],
    ["schema_guidance", { goal: "plan", answers: [] }, "check_schema"],
    ["get_result", { session: EVALUATE_OK.session, select: { state: "fail" }, answers: [] }, "check_schema"],
    ["get_result", { session: EVALUATE_OK.session, select: { state: "fail" }, practice_id: "audit-log" }, "schema_guidance"],
    // concerns and concern_decisions go with check_schema.
    ["schema_guidance", { goal: "plan", entities: [], concerns: [] }, "check_schema"],
    ["get_result", { session: EVALUATE_OK.session, select: { state: "fail" }, concern_decisions: [] }, "check_schema"],
  ];
  for (const [tool, args, right] of cases) {
    const res = await call(tool, args);
    assert.equal(res.isError, true, `${tool} ${JSON.stringify(args)}`);
    assert.match(res.content[0].text, new RegExp(`belongs to ${right}, not ${tool}\\. Call ${right} with it instead\\.`), res.content[0].text);
  }
  const none = await call("get_result", { session: EVALUATE_OK.session });
  assert.equal(none.isError, true);
  assert.match(none.content[0].text, /needs select/);
  assert.equal(calls.length, 0);
  // and the right tool takes them
  assert.equal((await call("schema_guidance", { goal: "explain", practice_id: "audit-log" })).isError, undefined);
  assert.equal((await call("get_result", { session: EVALUATE_OK.session, select: { state: "fail" } })).isError, undefined);
  assert.equal((await call("check_schema", { goal: "check", session: EVALUATE_OK.session, answers: [] })).isError, undefined);
  assert.equal(calls.length, 3);
  // goal doubts is no goal of either tool: the schema refuses it, with no pointer to another tool
  for (const tool of ["check_schema", "schema_guidance"]) {
    const res = await call(tool, { goal: "doubts" });
    assert.equal(res.isError, true, tool);
    assert.doesNotMatch(res.content[0].text, /belongs to/, tool);
    assert.match(res.content[0].text, /goal/, tool);
  }
  assert.equal(calls.length, 3);
  await s.end();
});

test("The text summary names the check's report link, only when it is an https link; the output schema lists it", () => {
  const link = "https://custosa.com/billing#results";
  const withLink = { ...EVALUATE_OK, report_url: link };
  assert.ok(validateOutput(withLink), JSON.stringify(validateOutput.errors));
  assert.equal(OUTPUT_SCHEMA.anyOf[0].properties.report_url.type, "string");
  assert.match(textFor(withLink, { full: false }), /\nReport on the website: https:\/\/custosa\.com\/billing#results\n/);
  assert.match(textFor({ results: [{ root: 0, nested: "", response: withLink }] }, { full: false }), /Report on the website: https:\/\/custosa\.com\/billing#results/);
  for (const bad of [undefined, "http://custosa.com/billing", "https://custosa.com/a b", `https://custosa.com/${"a".repeat(300)}`]) {
    assert.ok(!/Report on the website/.test(textFor({ ...EVALUATE_OK, report_url: bad }, { full: false })), String(bad));
  }
});

test("the text summary names the practices the response's guidance covers; the output schema lists guidance", () => {
  const entry = (practice_id) => ({ practice_id, why: "Why it matters.", look_for: [{ stack: "any", items: ["Where to look."] }],
    examples: { safe: "A safe shape.", unsafe: "An unsafe shape." }, saw: ["What this run read."], answer_with: ["no_storage_bucket"] });
  const withGuidance = { ...EVALUATE_OK, guidance: [entry("access-audit-log"), entry("rls-enabled")] };
  assert.ok(validateOutput(withGuidance), JSON.stringify(validateOutput.errors));
  assert.equal(OUTPUT_SCHEMA.anyOf[0].properties.guidance.type, "array");
  const short = textFor(withGuidance, { full: false });
  assert.match(short, /\nGuidance for 2 practices \(access-audit-log, rls-enabled\): read each practice's why, look_for, examples, saw and answer_with in guidance before you answer\.\n/);
  assert.ok(!/Guidance for/.test(textFor(EVALUATE_OK, { full: false })), "no line when the response has no guidance");
});

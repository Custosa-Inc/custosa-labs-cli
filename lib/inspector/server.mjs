/* The local inspector: a stdio MCP server offering check_schema, schema_guidance and get_result_page (./tool.mjs).
 *
 * Protocol revisions: serveStdio (@modelcontextprotocol/server) picks the era from the client's first message. A
 * client that opens with initialize gets the 2025-11-25 protocol (earlier 2025 revisions too); a client that sends
 * server/discover or a request carrying the per-request _meta envelope gets 2026-07-28 (no handshake, no session,
 * resultType on every result). One factory (makeServer) serves both, so the tools and their answers are the same.
 *
 * Stdout carries protocol messages only; every log line goes to stderr. The server starts no child process and makes
 * no network call of its own: the tools' handler (./tool.mjs) sends the fact documents it builds to the hosted
 * evaluator (./client.mjs), and only once the person has signed in (custosa login).
 *
 * Project roots, read per check_schema call: when the client offers MCP roots, the server uses the usable ones it
 * names (file: URIs of existing folders, realpathed) and never falls back to the working directory, even when none of
 * them is usable: a client that offers roots decides the project. On 2025-11-25 the server asks with roots/list; on
 * 2026-07-28, where a server sends no requests, check_schema answers input_required with a roots/list input request
 * and the client retries with the roots. A client that offers no roots gets the git root of the working directory
 * (found by looking for a .git entry, never by running git). A root that is a filesystem root, the home folder, a
 * folder above it or a folder of repositories is refused with a message saying so (projectroot.mjs). With no root
 * possible, check_schema returns that message; schema_guidance and get_result_page need no root.
 *
 * Project root override: CUSTOSA_PROJECT_ROOT (or custosa inspect --stdio --root <dir>) names the project folder and
 * takes precedence over the client's roots and the working directory. It is judged like any other root
 * (projectroot.mjs) and, when refused, calls return that message: the server never falls back from an explicit setting.
 *
 * Results: a successful call carries the response as structuredContent (matching the tool's outputSchema) and a text
 * block (textFor, below). A refusal or failure (not signed in, evaluator unreachable, zero balance, any evaluator 4xx or
 * 5xx, a local problem) is isError: true, with the next step for the person in the text and no structuredContent.
 * Cancellation (notifications/cancelled) aborts the request's signal, which stops the scan, its rule workers and any
 * evaluator call in flight. Progress notifications go out when the request carries a progressToken (throttled).
 *
 * Fixes: check_schema goal fix asks the person with elicitation/create, when the host declared
 * it, before any evaluator call; only a yes goes on (confirmFix, below). */
import { lstatSync, readFileSync, realpathSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import AjvModule from "ajv";
import {
  CLIENT_CAPABILITIES_META_KEY, CLIENT_INFO_META_KEY, ProtocolError, ProtocolErrorCode, Server, deserializeMessage, inputRequired, inputResponse,
  serializeMessage,
} from "@modelcontextprotocol/server";
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import { INSTRUCTIONS, NAME, TOOLS, concernsProblem, decisionsProblem, locationProblem, runCheck as defaultRunCheck, verdictsProblem, wrongToolProblem } from "./tool.mjs";
import { preloadRuleset } from "./factdoc.mjs";
import { WarmPool } from "./rules.mjs";
import { projectRootProblem } from "./projectroot.mjs";

const VERSION = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8")).version;
const ROOTS_TIMEOUT_MS = 10_000; // a 2025-11-25 client's answer to roots/list

export const NO_ROOT_MESSAGE = "custosa inspect: no project root. Start it from inside a git repository (a folder with "
  + "a .git entry at or above the working directory), or from an assistant that shares its workspace roots.";
export const UNUSABLE_ROOTS_MESSAGE = "custosa inspect: the assistant shares workspace roots, but none of them is a "
  + "folder on this computer (only file: folders that exist are used), and the inspector won't guess the project from "
  + "its working directory. Open the project folder in the assistant and call check_schema again.";
export const ROOTS_UNREADABLE_MESSAGE = "custosa inspect: the assistant offers workspace roots but did not list them. "
  + "Restart the assistant from the project folder and call check_schema again.";

const overrideMissingMessage = (dir) => `custosa inspect: the project root set in CUSTOSA_PROJECT_ROOT (or --root), ${dir}, `
  + "is not an existing folder given as an absolute path. Fix the setting in the assistant's configuration for this server, then restart it.";

const log = (line) => process.stderr.write(`custosa inspect: ${line.replace(/^custosa inspect: /, "")}\n`);

/* The nearest folder at or above `start` holding a .git entry (a folder, or a file as in worktrees and submodules),
 * or null. Only checks that the entry exists: nothing inside it is read and git is never run. */
export function findGitRoot(start) {
  let dir = resolve(start);
  for (;;) {
    try { lstatSync(join(dir, ".git")); return dir; } catch { /* not here */ }
    const parent = dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

/* The usable entries of a host's roots list, judged one by one: file: URIs naming an existing directory, realpathed
 * (so later containment checks compare real paths), in the order given, without repeats. Anything else is skipped. */
export function rootsFromHost(roots) {
  const out = [];
  for (const root of Array.isArray(roots) ? roots : []) {
    try {
      if (typeof root?.uri !== "string") continue;
      const url = new URL(root.uri);
      if (url.protocol !== "file:") continue;
      const path = fileURLToPath(url);
      if (!isAbsolute(path)) continue;
      const real = realpathSync(path);
      if (statSync(real).isDirectory() && !out.includes(real)) out.push(real);
    } catch { /* not a usable root */ }
  }
  return out;
}

/* The SDK checks a result against its schema before handing it over, and its roots schema refuses the whole list for
 * one odd entry. This Standard Schema passes the raw result through; rootsFromHost then judges each entry. */
const RAW_RESULT = Object.freeze({ "~standard": Object.freeze({ version: 1, vendor: "custosa", validate: (value) => ({ value }) }) });

const Ajv = AjvModule.default ?? AjvModule;
const ajv = new Ajv({ allErrors: false, strict: true });
const VALIDATORS = new Map(TOOLS.map((t) => [t.name, ajv.compile(t.inputSchema)]));

function argumentProblem(tool, args) {
  const elsewhere = wrongToolProblem(tool, args);
  if (elsewhere) return elsewhere;
  const decided = decisionsProblem(args);
  if (decided) return decided;
  const validateArgs = VALIDATORS.get(tool);
  if (!validateArgs(args)) {
    const [e] = validateArgs.errors;
    const where = e.instancePath ? e.instancePath.slice(1).replaceAll("/", ".") : "arguments";
    const extra = e.params?.additionalProperty ? ` ("${e.params.additionalProperty}")` : "";
    const message = e.keyword === "pattern" ? "is not in the form the tool's input schema gives" : e.message;
    return `${where}: ${message}${extra}.`;
  }
  return locationProblem(args) ?? verdictsProblem(args) ?? concernsProblem(args);
}

const toolError = (text) => ({ isError: true, content: [{ type: "text", text }] });

/* Point process.stdout.write at stderr while the transport owns the real stdout, so a stray write anywhere in the
 * process can't corrupt the protocol stream. Returns the stream the transport should use and a restore function. */
function guardStdout(stdout) {
  if (stdout !== process.stdout) return { stream: stdout, restore() {} };
  const write = process.stdout.write;
  const real = write.bind(process.stdout);
  const stream = {
    write: (chunk, ...rest) => real(chunk, ...rest),
    once: (event, fn) => { process.stdout.once(event, fn); return stream; },
    on: (event, fn) => { process.stdout.on(event, fn); return stream; },
  };
  process.stdout.write = (chunk, ...rest) => process.stderr.write(chunk, ...rest);
  return { stream, restore() { if (process.stdout.write !== write) process.stdout.write = write; } };
}

/* The stdio transport serveStdio is given. The SDK's own drops a line it can't read (onerror only), so the client
 * waits for an answer that never comes. This one answers it: -32700 (parse error) for a line that isn't JSON, -32600
 * (invalid request) for JSON that isn't a JSON-RPC request, with the request's id when one can be read, else null.
 * Lines end at \n (a trailing \r is dropped); blank lines are skipped. It uses only the SDK's public message
 * helpers. */
export class InspectorStdioTransport {
  constructor(stdin, stdout) {
    this._stdin = stdin;
    this._stdout = stdout;
    this._buffer = null;
    this._closed = false;
    this.closed = new Promise((ok) => { this._onClosed = ok; });
    this._ondata = (chunk) => { this._buffer = this._buffer ? Buffer.concat([this._buffer, chunk]) : chunk; this._drain(); };
    this._onend = () => { this.close().catch(() => {}); };
    this._onerror = (error) => this.onerror?.(error);
  }

  async start() {
    this._stdin.on("data", this._ondata);
    this._stdin.once("end", this._onend);
    this._stdin.once("close", this._onend);
    this._stdin.on("error", this._onerror);
  }

  send(message) {
    if (this._closed) return Promise.resolve();
    return new Promise((ok) => { this._stdout.write(serializeMessage(message), () => ok()); });
  }

  async close() {
    if (this._closed) return;
    this._closed = true;
    this._stdin.off("data", this._ondata);
    this._stdin.off("end", this._onend);
    this._stdin.off("close", this._onend);
    this._stdin.off("error", this._onerror);
    this._buffer = null;
    this.onclose?.();
    this._onClosed();
  }

  _drain() {
    for (;;) {
      if (!this._buffer || this._closed) return;
      const index = this._buffer.indexOf("\n");
      if (index === -1) return;
      const line = this._buffer.toString("utf8", 0, index).replace(/\r$/, "");
      this._buffer = this._buffer.subarray(index + 1);
      let message;
      try { message = deserializeMessage(line); } catch { this._refuse(line); continue; }
      try { this.onmessage?.(message); } catch (error) { this.onerror?.(error); }
    }
  }

  /* A line that failed the JSON-RPC schema. A line that isn't JSON gets -32700 (id null). Of the JSON lines, only a
   * request (an object with a method and an id) gets -32600; anything else (a response or batch from the client, a
   * notification, a bare value) is ignored and logged, since JSON-RPC answers only requests (L1). */
  _refuse(line) {
    if (line.trim() === "") return;
    let parsed;
    try { parsed = JSON.parse(line); } catch {
      this.onerror?.(new Error("a line from the client is not JSON (answered -32700)"));
      this.send({ jsonrpc: "2.0", id: null, error: { code: ProtocolErrorCode.ParseError, message: "Parse error: the line is not JSON." } });
      return;
    }
    const isRequest = parsed !== null && typeof parsed === "object" && !Array.isArray(parsed) && "method" in parsed && "id" in parsed;
    if (!isRequest) { this.onerror?.(new Error("a JSON line from the client is not a JSON-RPC message (ignored)")); return; }
    this.onerror?.(new Error("a request from the client is not a valid JSON-RPC request (answered -32600)"));
    const id = typeof parsed.id === "string" || Number.isInteger(parsed.id) ? parsed.id : null;
    this.send({ jsonrpc: "2.0", id, error: { code: ProtocolErrorCode.InvalidRequest, message: "Invalid request: the line is not a JSON-RPC 2.0 request." } });
  }
}

/* The tools/list result, the same on every revision, run and machine: the tools in a fixed order with nothing taken
 * from the environment. scripts/tools-list-hash.mjs hashes it into tools-list.sha256 (shipped beside this file). On
 * 2026-07-28 the SDK adds resultType and the cache fields (ttlMs 0, cacheScope private). */
export const toolsListResult = () => ({ tools: [...TOOLS] });

/* Clients known to show the model a tool result's structuredContent. For them the text block is a short summary; for
 * every other client it is the summary followed by the whole response as JSON, since a client that reads only text
 * would otherwise lose the findings, questions and fixes the next call depends on. Matched against clientInfo.name.
 * Empty until each supported client's behaviour is confirmed. */
export const STRUCTURED_CLIENTS = Object.freeze([]);

const count = (v) => (Array.isArray(v) ? v.length : 0);
/* a done check's page 1 carries report_url, the account page where the run is listed.
 * Only a plain https link fits the response schema (maxLength 300); anything else is never shown or put in a question. */
const REPORT_LINKS_KEPT = 50;
const REPORT_LINK = /^https:\/\/[!-~]{1,292}$/;
export const reportLinkOf = (r) => (typeof r?.report_url === "string" && REPORT_LINK.test(r.report_url) ? r.report_url : null);

/* One response's short summary: headline, readiness score, counts, status, session, the report link and the next step. */
function summaryOf(r) {
  if (!r || typeof r !== "object") return "";
  if (r.local_only) return "Local-only mode: the fact documents were built and checked locally; nothing was sent.";
  const lines = [];
  if (r.headline) lines.push(r.headline);
  const pct = r.readiness && typeof r.readiness.percent === "number" ? `readiness score ${r.readiness.percent}%` : null;
  const counts = [`${count(r.findings)} findings`, `${count(r.questions)} questions`, `${count(r.fixes)} fixes`,
    // the concerns on this page, and how many still wait on a step (unconfirmed or confirmed open)
    ...(count(r.concerns) ? [`${count(r.concerns)} concerns (${r.concerns.filter((c) => c?.status === "unconfirmed" || c?.status === "confirmed_open").length} unresolved)`] : [])];
  const page = r.page && r.page.of > 1 ? `page ${r.page.n} of ${r.page.of}` : null;
  lines.push([`goal ${r.goal}`, `status ${r.status}`, pct, ...(r.goal === "plan" || r.goal === "pattern" || r.goal === "explain" ? [] : counts), page,
    r.session ? `session ${r.session}` : null].filter(Boolean).join(", "));
  // the practices the response's guidance covers, by id; the entries themselves are in the full response.
  const guided = Array.isArray(r.guidance) ? r.guidance.map((g) => g?.practice_id).filter((id) => typeof id === "string") : [];
  if (guided.length) {
    lines.push(`Guidance for ${guided.length} practice${guided.length === 1 ? "" : "s"} (${guided.join(", ")}): read each `
      + "practice's why, look_for, examples, saw and answer_with in guidance before you answer.");
  }
  const link = reportLinkOf(r);
  if (link) lines.push(`Report on the website: ${link}`);
  if (r.next_step) lines.push(`Next step: ${r.next_step}`);
  return lines.join("\n");
}

export function textFor(response, { full = true } = {}) {
  let summary;
  if (Array.isArray(response?.results)) {
    summary = [`${response.results.length} roots checked.`, ...response.results.map((x) => `Root ${x.root}${x.nested ? ` (${x.nested})` : ""}: ${x.response?.error ? `error ${x.response.error}: ${x.response.next_step ?? ""}` : summaryOf(x.response)}`),
      ...(response.other_roots?.note ? [response.other_roots.note] : [])].join("\n");
  } else summary = summaryOf(response);
  if (Array.isArray(response?.local_notes) && response.local_notes.length) summary += `\nLocal notes: ${response.local_notes.join(" ")}`;
  return full ? `${summary}\n\nFull response (the same as structuredContent):\n${JSON.stringify(response)}`
    : `${summary}\nThe full response is in structuredContent.`;
}

/* An error answer (local or the evaluator's) as an isError result: the next step first, then the error as JSON. */
function errorResult(response) {
  const extra = response.top_up_url ? ` Top up: ${response.top_up_url}` : "";
  return toolError(`${response.next_step ?? "The call failed."}${extra}\n\n${JSON.stringify(response)}`);
}

/* Progress for one call, as a percentage with a message, sent at most every PROGRESS_MS (phase changes always go). */
const PROGRESS_MS = 500;
const PHASES = { start: [0, "Starting"], platform: [2, "Reading platform settings"], catalog: [5, "Reading the database catalog"],
  walk: [10, "Listing project files"], rules: [15, "Scanning files"], secrets: [80, "Scanning for secrets"],
  build: [85, "Building the fact document"], send: [90, "Sending facts to the evaluator"], done: [100, "Done"] };
function progressSender(ctx) {
  const token = ctx?.mcpReq?._meta?.progressToken;
  if (token === undefined || typeof ctx.mcpReq.notify !== "function") return null;
  let last = -1, lastAt = 0, lastPhase = null;
  return (event) => {
    const [base, label] = PHASES[event.phase] ?? [null, null];
    if (base === null) return;
    let progress = base, message = label;
    if (event.phase === "rules" && event.total > 0) {
      progress = 15 + Math.floor((65 * Math.min(event.done, event.total)) / event.total);
      message = `Scanning files: ${event.done} of ${event.total}`;
    }
    if (event.root !== undefined && event.roots > 1) message += ` (root ${event.root + 1} of ${event.roots})`;
    const now = Date.now();
    if (progress <= last) return;
    if (event.phase === lastPhase && now - lastAt < PROGRESS_MS && progress !== 100) return;
    last = progress; lastAt = now; lastPhase = event.phase;
    ctx.mcpReq.notify({ method: "notifications/progress", params: { progressToken: token, progress, total: 100, message } }).catch(() => {});
  };
}

/* Run the inspector over stdin and stdout until the client closes the connection.
 * `root`: the fallback project root (the git root of the working directory, or null).
 * `runCheck`, `rootsTimeoutMs`: the handler and the roots/list timeout, replaceable for tests.
 * Resolves when the connection closes. */
/* The one yes-or-no field the fix confirmation asks for, and the answer when the person says no. Cursor
 * closes the question after about 60 s and can hide it in a collapsed tool row, so a no may be a question the person
 * never saw; the answer says to call again then. */
const FIX_CONFIRM_KEY = "confirm_fix";
const FIX_CONFIRM_SCHEMA = Object.freeze({ type: "object", properties: { apply: { type: "boolean", title: "Apply the fixes" } }, required: ["apply"] });
function fixDeclined(args) {
  return {
    goal: "fix", status: "done", ...(typeof args.session === "string" ? { session: args.session } : {}),
    headline: "The person did not approve fixes.", findings: [], charged_units: 0,
    next_step: "Show the person the findings; ask again only if they ask for fixes or say they missed the question.",
    confirmed_by: "person", local_notes: [
      "Nothing was sent to the evaluator and nothing was charged.",
      "If you missed the question, call again: ask for the fixes, and the question comes back.",
    ],
  };
}

export async function startServer({
  stdin = process.stdin, stdout = process.stdout, root = null,
  runCheck = defaultRunCheck, rootsTimeoutMs = ROOTS_TIMEOUT_MS, home = homedir(),
  projectRoot = null,
} = {}) {
  let fallback = null;
  if (root) { try { fallback = realpathSync(root); } catch { fallback = null; } }
  // The explicit project root (CUSTOSA_PROJECT_ROOT or --root): realpathed; one that doesn't exist is refused at call time.
  let override = null;
  if (projectRoot) {
    try { override = isAbsolute(projectRoot) && statSync(projectRoot).isDirectory() ? realpathSync(projectRoot) : { missing: projectRoot }; }
    catch { override = { missing: projectRoot }; }
  }

  // Setup is paid once per process, not once per call: the rule bundle is parsed in a thread from launch (its cache is
  // the process's, keyed by the manifest, so a synced bundle is parsed again on the next call), and the rule workers
  // a call starts stay warm for the next one (WarmPool: at most MAX_WORKERS idle, stopped after WARM_IDLE_MS).
  // Only for the real handler: a test's stub never runs rules.
  const warm = runCheck === defaultRunCheck ? new WarmPool() : null;
  // each session's report link, from its done check's page 1, for the fix question in that session. The newest
  // REPORT_LINKS_KEPT only: a session past them asks with "in this chat".
  const reportLinks = new Map();
  if (warm) preloadRuleset();

  // One root the person or the working directory chose: used, unless it is the disk, the home folder or a folder of
  // projects .
  async function singleRoot(dir) {
    const why = await projectRootProblem(dir, { home });
    return why ? { kind: "refused", message: why.message } : { kind: "ready", roots: [dir] };
  }

  // The client's roots list, judged entry by entry. Roots refused beside allowed ones are named in every response's
  // local notes, never dropped silently.
  async function judgeRoots(list) {
    if (!Array.isArray(list)) return { kind: "refused", message: ROOTS_UNREADABLE_MESSAGE };
    const judged = await Promise.all(rootsFromHost(list).map(async (r) => [r, await projectRootProblem(r, { home })]));
    const allowed = judged.filter(([, p]) => !p).map(([r]) => r);
    const refused = judged.filter(([, p]) => p);
    if (allowed.length) return { kind: "ready", roots: allowed, refused: refused.map(([r, p]) => ({ root: r, code: p.code })) };
    return { kind: "refused", message: refused.length ? refused[0][1].message : UNUSABLE_ROOTS_MESSAGE };
  }

  // The client's capabilities and name for one request: from its _meta envelope on 2026-07-28, from initialize before.
  const clientOf = (server, ctx) => (ctx.mcpReq.envelope
    ? { capabilities: ctx.mcpReq.envelope[CLIENT_CAPABILITIES_META_KEY], info: ctx.mcpReq.envelope[CLIENT_INFO_META_KEY] }
    : { capabilities: server.getClientCapabilities(), info: server.getClientVersion() });

  // The roots for one check_schema call: ready, refused, or (2026-07-28) an input_required result asking for them.
  async function rootsFor(server, ctx) {
    if (override) return typeof override === "object" ? { kind: "refused", message: overrideMissingMessage(override.missing) } : singleRoot(override);
    if (!clientOf(server, ctx).capabilities?.roots) return fallback ? singleRoot(fallback) : { kind: "refused", message: NO_ROOT_MESSAGE };
    if (ctx.mcpReq.envelope) { // 2026-07-28: no server requests; ask in the result, read the retry's inputResponses
      const answer = inputResponse(ctx.mcpReq.inputResponses, "roots");
      if (answer.kind === "roots") return judgeRoots(answer.roots);
      if (ctx.mcpReq.inputResponses !== undefined) return { kind: "refused", message: ROOTS_UNREADABLE_MESSAGE };
      return { kind: "ask", result: inputRequired({ inputRequests: { roots: inputRequired.listRoots() } }) };
    }
    try {
      const result = await server.request({ method: "roots/list" }, RAW_RESULT, { timeout: rootsTimeoutMs, signal: ctx.mcpReq.signal });
      return judgeRoots(result?.roots);
    } catch (error) {
      if (ctx.mcpReq.signal?.aborted) throw error;
      log(`roots/list failed: ${error.message}`);
      return { kind: "refused", message: ROOTS_UNREADABLE_MESSAGE };
    }
  }

  /* Before any fixes are given, the person confirms in their own editor. check_schema goal fix
   * asks with elicitation/create when the host declared the capability, before any evaluator call; yes goes on
   * (confirmed_by: person), anything else ends the call with nothing sent or charged. A host without it goes on under
   * the instructions (confirmed_by: instructions). The question names no count and no table, column or file. */
  async function confirmFix(server, ctx, args, reportLink = null) {
    if (!clientOf(server, ctx).capabilities?.elicitation) return { kind: "instructions" };
    // No count of findings; the report, then one question. The account page link from the
    // session's check when there is one; else the report is here, in the chat.
    const where = reportLink ? `: ${reportLink}` : " in this chat";
    const ask = { message: `Your PHI Schema Check report is ready${where}. Do you want to start making the changes it recommends to your code and local development database?`, requestedSchema: FIX_CONFIRM_SCHEMA };
    const yes = (action, content) => (action === "accept" && content?.apply === true ? { kind: "person" } : { kind: "declined" });
    if (ctx.mcpReq.envelope) { // 2026-07-28: ask in the result, read the retry's answer
      const answer = inputResponse(ctx.mcpReq.inputResponses, FIX_CONFIRM_KEY);
      return answer.kind === "elicit" ? yes(answer.action, answer.content) : { kind: "ask", request: inputRequired.elicit(ask) };
    }
    try {
      const result = await server.elicitInput(ask, { signal: ctx.mcpReq.signal });
      return yes(result?.action, result?.content);
    } catch (error) {
      if (ctx.mcpReq.signal?.aborted) throw error;
      log(`elicitation/create failed: ${error.message}`);
      return { kind: "declined" }; // no answer is no approval
    }
  }

  async function callTool(server, request, ctx) {
    const tool = request.params.name;
    if (!VALIDATORS.has(tool)) throw new ProtocolError(ProtocolErrorCode.InvalidParams, `Unknown tool "${tool}".`);
    const args = request.params.arguments ?? {}; // the SDK answers -32602 to arguments that aren't an object
    const problem = argumentProblem(tool, args);
    if (problem) return toolError(`${tool}: ${problem}${/ instead\.$|again\.$/.test(problem) ? "" : ` Fix the arguments and call ${tool} again.`}`);
    // Only check_schema reads the project; guidance and pages need no roots. Only its fix goal asks the person first.
    let now = { roots: [], refused: [] };
    let confirmed = null;
    if (tool === NAME) {
      // 2026-07-28 reads or asks in the result; 2025 asks the host only once the project is known (below).
      if (args.goal === "fix" && ctx.mcpReq.envelope) confirmed = await confirmFix(server, ctx, args, reportLinks.get(args.session) ?? null);
      now = await rootsFor(server, ctx);
      // 2026-07-28: a retry carries only the round's answers, so the roots and the confirmation are asked together.
      if (confirmed?.kind === "ask") {
        const askRoots = now.kind === "ask" || (ctx.mcpReq.inputResponses === undefined ? false : !override && clientOf(server, ctx).capabilities?.roots);
        return inputRequired({ inputRequests: { ...(askRoots ? { roots: inputRequired.listRoots() } : {}), [FIX_CONFIRM_KEY]: confirmed.request } });
      }
      if (now.kind === "ask") return now.result;
      if (now.kind === "refused") { log(now.message); return toolError(now.message); }
      if (args.goal === "fix" && !ctx.mcpReq.envelope) confirmed = await confirmFix(server, ctx, args, reportLinks.get(args.session) ?? null);
      if (confirmed?.kind === "declined") {
        const declined = fixDeclined(args);
        return { content: [{ type: "text", text: `${declined.headline} ${declined.local_notes.join(" ")}\n\nNext: ${declined.next_step}` }], structuredContent: declined };
      }
    }
    const signal = ctx.mcpReq.signal;
    const progress = progressSender(ctx);
    const client = clientOf(server, ctx).info?.name;
    try {
      const response = await runCheck(args, { roots: [...now.roots], refused: [...(now.refused ?? [])], log, signal,
        progress: progress ?? undefined, client, ...(warm ? { warm } : {}) });
      if (response && typeof response.error === "string") return errorResult(response);
      if (confirmed && response && typeof response === "object") response.confirmed_by = confirmed.kind; // local, never sent
      for (const r of Array.isArray(response?.results) ? response.results.map((x) => x?.response) : [response]) {
        const link = reportLinkOf(r);
        if (!link || typeof r.session !== "string") continue;
        reportLinks.delete(r.session);
        reportLinks.set(r.session, link);
        if (reportLinks.size > REPORT_LINKS_KEPT) reportLinks.delete(reportLinks.keys().next().value);
      }
      progress?.({ phase: "done" });
      const full = !STRUCTURED_CLIENTS.includes(client);
      return { content: [{ type: "text", text: textFor(response, { full }) }], structuredContent: response };
    } catch (error) {
      if (signal?.aborted) throw new ProtocolError(ProtocolErrorCode.InternalError, `${tool} was cancelled.`); // never sent: the SDK drops answers to cancelled requests
      log(`${tool} failed: ${error.stack || error.message}`);
      return toolError(`${tool}: the local inspector failed. Run the call again; if it fails again, tell the person.`);
    }
  }

  // One server per era serveStdio settles on (a server/discover probe followed by initialize builds two): cheap, and
  // everything that lasts the process (roots settings, the warm pool) lives out here.
  const makeServer = () => {
    const server = new Server({ name: "custosa-inspector", title: "PHI Schema Check", version: VERSION },
      { capabilities: { tools: {} }, instructions: INSTRUCTIONS });
    server.setRequestHandler("tools/list", async () => toolsListResult());
    server.setRequestHandler("tools/call", (request, ctx) => callTool(server, request, ctx));
    return server;
  };

  const guard = guardStdout(stdout);
  const transport = new InspectorStdioTransport(stdin, guard.stream);
  const handle = serveStdio(makeServer, { transport, onerror: (error) => log(error.message) });
  try {
    await transport.closed;
  } finally {
    warm?.drop();
    await handle.close().catch(() => {});
    guard.restore();
  }
}

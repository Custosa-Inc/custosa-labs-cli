/* Contract 2.3, CLI half part 3: the committed block on the wire. Each root sends its own file's block
 * (section 3.1, Roots), with no probe of the evaluator's version first, and an unreadable file sends nothing and says
 * why (section 1.3). */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { makeRunCheck } from "../lib/inspector/tool.mjs";
import { MAX_BODY_BYTES } from "../lib/inspector/client.mjs";

const MADE = { account_tag: "0123456789abcdef", made_on: "2026-10-30", ruleset_id: "2026-10-31.90bf3c76",
  registry_id: "2026-10-30.1234abcd", fact_token: "a".repeat(32), seal: "b".repeat(32) };
const AUDIT = { decided_by: "person", relayed_by: "assistant", client: null, decided_at: "2026-10-30T12:00:00Z" };
const stateWith = (subject) => ({ state_version: 1, content_key: "c".repeat(64), suppressions: [], grants_baseline: [],
  decisions: [{ subject, practice_id: subject.split("@")[0], option: "not_used", expires_on: null, max_age_on: null,
    reasons: [], f4_class: "coverage_gap", why_asked: "assistant_could_not_decide", made: MADE, audit: AUDIT }] });

function rootWith(state) {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "custosa-send-")));
  if (state !== undefined) {
    mkdirSync(join(dir, ".custosa"));
    writeFileSync(join(dir, ".custosa", "state.json"), typeof state === "string" ? state : JSON.stringify(state));
  }
  return dir;
}

function harness({ roots, refuseCommitted = false }) {
  const bodies = [];
  const fetched = [];
  const evaluate = async (body) => {
    bodies.push(structuredClone(body));
    if (refuseCommitted && body.committed) return { ok: false, body: { error: "invalid_fact_document", at: "/committed" } };
    return { ok: true, body: { goal: body.goal, status: "done", session: null } };
  };
  const runCheck = makeRunCheck({ localOnly: false, readToken: () => ({ token: "t", host: "https://e.test" }),
    evaluatorUrl: () => ({ url: "https://e.test", origin: "https://e.test" }),
    clientOptions: { fetch: async (url) => { fetched.push(url); throw new Error("no fetch outside evaluate"); } },
    environmentFor: () => ({ environment: { value: "unknown", source: "setup" }, note: null }), evaluate,
    build: async () => ({ notes: [], documents: roots.map((abs, i) => ({ project: i, label: "", nested: false,
      other: i > 0, skipped: false, root_id: String(i).repeat(64), abs, document: { session: null, n: i } })) }) });
  return { runCheck, bodies, fetched };
}

test("no file: no block, no note", async () => {
  const h = harness({ roots: [rootWith()] });
  const out = await h.runCheck({ goal: "check" }, { roots: ["A"] });
  assert.equal(h.bodies[0].committed, undefined);
  assert.equal(out.local_notes, undefined);
});

test("the body cap holds the committed block", () => {
  assert.equal(MAX_BODY_BYTES, 5_065_536 + 1_048_576);
});

test("the evaluator gets each root's own block, with no version probe first", async () => {
  const a = rootWith(stateWith("rls-enabled@public.a")), b = rootWith(stateWith("rls-enabled@public.b"));
  const h = harness({ roots: [a, b] });
  await h.runCheck({ goal: "check", include_other_roots: true }, { roots: [a, b] });
  assert.deepEqual(h.bodies.map((x) => x.committed.decisions.map((d) => d.object_id)),
    [["rls-enabled@public.a"], ["rls-enabled@public.b"]]);
  assert.ok(!JSON.stringify(h.bodies).includes("c".repeat(64)), "the content key is never sent");
  assert.deepEqual(h.fetched, [], "no health probe");
});

test("a refusal at /committed is returned as it is: never retried without the block", async () => {
  const h = harness({ roots: [rootWith(stateWith("rls-enabled@public.a"))], refuseCommitted: true });
  const out = await h.runCheck({ goal: "check" }, { roots: ["A"] });
  assert.equal(h.bodies.length, 1);
  assert.ok(h.bodies[0].committed);
  assert.notEqual(out.status, "done");
  assert.ok(!JSON.stringify(out).includes("state_not_sent_core_older"));
});

test("an unreadable file sends nothing and names its reason, never its content", async () => {
  const h = harness({ roots: [rootWith("{\"state_version\": 2, \"secret\": \"hunter2\"}")] });
  const out = await h.runCheck({ goal: "check" }, { roots: ["A"] });
  assert.equal(h.bodies[0].committed, undefined);
  const note = out.local_notes.find((n) => n.startsWith("state_unreadable"));
  assert.ok(note && note.includes("(version)") && !note.includes("hunter2"));
});

// --- Writing report.state.to_commit (6.2 tests 1a, 4, 5, 6) ----------------------------------------------------------
import { existsSync, readFileSync } from "node:fs";
import { entriesFrom, readState } from "../lib/inspector/state.mjs";

const issued = (object_id, more = {}) => ({ kind: "decision", object_id, option: "not_used", expires_on: null,
  max_age_on: "2027-01-28", practice_id: object_id.split("@")[0], reasons: ["person_must_decide"],
  f4_class: "coverage_gap", why_asked: "assistant_could_not_decide", ...MADE, ...more });

/* `pages`: the answer of each evaluation call in turn (T29 o2: there are no pages; a check whose body carries the
 * state's lists, as an older core sent them, is used as sent, so no get_result read is made). */
function writer({ root, pages, env = {} }) {
  let calls = 0;
  const evaluate = async () => ({ ok: true, body: pages[Math.min(calls++, pages.length - 1)] });
  return makeRunCheck({ localOnly: false, readToken: () => ({ token: "t", host: "https://e.test" }),
    evaluatorUrl: () => ({ url: "https://e.test", origin: "https://e.test" }), stateEnv: env,
    environmentFor: () => ({ environment: { value: "unknown", source: "setup" }, note: null }), evaluate,
    build: async () => ({ notes: [], documents: [{ project: 0, label: "", nested: false, other: false, skipped: false,
      root_id: "0".repeat(64), abs: root, document: { session: null } }] }) });
}
const page = (to_commit, extra = {}) => ({ goal: "check", status: "done", session: "s_0123456789abcdef0123",
  report: { state: { state_version: 1, sent: { decisions: 0, suppressions: 0, grants: 0 }, by_outcome: {},
    unmatched: [], to_commit, not_committed: [] } }, ...extra });

test("to_commit from two checks in a session is written to the session's root; the key is made once", async () => {
  const root = rootWith();
  const run = writer({ root, pages: [page([issued("rls-enabled@public.a")]), page([issued("rls-enabled@public.b")])] });
  const first = await run({ goal: "check" }, { roots: ["A"] });
  assert.ok(first.local_notes.some((n) => n.includes("before others record decisions")));
  const key = readState(root).state.content_key;
  const later = await run({ goal: "check", session: "s_0123456789abcdef0123" }, { roots: ["A"] });
  assert.ok(later.local_notes.some((n) => n.includes("commit it")));
  const got = readState(root).state;
  assert.equal(got.content_key, key);
  assert.deepEqual(got.decisions.map((d) => d.subject), ["rls-enabled@public.a", "rls-enabled@public.b"]);
  assert.equal(got.decisions[0].audit.decided_by, "person");
  assert.equal(got.decisions[0].made.seal, MADE.seal);
});

test("in CI nothing is written, and the note names the variable", async () => {
  const root = rootWith();
  const out = await writer({ root, env: { GITHUB_ACTIONS: "true" }, pages: [page([issued("rls-enabled@public.a")])] })(
    { goal: "check" }, { roots: ["A"] });
  assert.ok(out.local_notes.some((n) => n.startsWith("no_person_in_ci") && n.includes("GITHUB_ACTIONS")));
  assert.ok(!existsSync(join(root, ".custosa")));
});

test("no_content_key in not_committed writes the file with a new key", async () => {
  const root = rootWith();
  const p = page([]);
  p.report.state.not_committed = [{ index: 0, reason: "no_content_key" }];
  await writer({ root, pages: [p] })({ goal: "check" }, { roots: ["A"] });
  assert.match(readState(root).state.content_key, /^[0-9a-f]{64}$/);
});

test("subjects that are never committed are left out and counted", () => {
  const screen = (name) => name.includes("jane.doe");
  const { adds, refused } = entriesFrom([
    issued(`authz-every-handler@${"d".repeat(64)}`), issued("rls-enabled@public.u_0123456789abcdef"),
    issued("edge-function-auth@supabase/functions/a.ts:12-14"), issued("no-committed-secrets@config/dev.ts"),
    issued("rls-enabled@public.jane.doe"), issued("rls-enabled@public.ok")], { screen });
  assert.equal(refused, 5);
  assert.deepEqual(adds.decisions.map((d) => d.subject), ["rls-enabled@public.ok"]);
  const file = readFileSync(new URL("../lib/inspector/state.mjs", import.meta.url), "utf8");
  assert.ok(file.includes("state_subject_not_committable"));
});

test("a hand-edited entry comes back as seal_mismatch, and the note names its subject", async () => {
  const root = rootWith(stateWith("rls-enabled@public.a"));
  const p = page([]);
  p.report.state.unmatched = [{ kind: "decision", index: 0, outcome: "seal_mismatch" }];
  const out = await writer({ root, pages: [p] })({ goal: "check" }, { roots: ["A"] });
  assert.ok(out.local_notes.some((n) => n.startsWith("seal_mismatch") && n.includes("rls-enabled@public.a")));
  assert.equal(readState(root).state.decisions[0].made.seal, MADE.seal, "never repaired");
});

test("a phi-schema-check.json beside the project is no state: no note names it", async () => {
  const root = rootWith();
  writeFileSync(join(root, "phi-schema-check.json"), "{}");
  const out = await writer({ root, pages: [page([])] })({ goal: "check" }, { roots: ["A"] });
  assert.ok(!JSON.stringify(out).includes("phi-schema-check.json"));
});

test("entries the check couldn't read are counted in a note (T29 o2: state_entries_not_read)", async () => {
  const root = rootWith();
  const p = page([issued("rls-enabled@public.a")]);
  p.report.state.to_commit_total = 4;
  const out = await writer({ root, pages: [p] })({ goal: "check" }, { roots: ["A"] });
  assert.ok(out.local_notes.some((n) => n.startsWith("state_entries_not_read: 3 more")));
});

test("the audit names the MCP client the person used, when its name fits the schema; else null", async () => {
  for (const [client, want] of [["claude-code", "claude-code"], ["Cursor (1.2)", "Cursor (1.2)"],
    ["bad\nname", null], ["x".repeat(65), null], [undefined, null]]) {
    const root = rootWith();
    const run = writer({ root, pages: [page([issued("rls-enabled@public.a")]), page([issued("rls-enabled@public.b")])] });
    await run({ goal: "check" }, { roots: ["A"], client });
    await run({ goal: "check", session: "s_0123456789abcdef0123" }, { roots: ["A"], client });
    const got = readState(root).state;
    assert.deepEqual(got.decisions.map((d) => d.audit.client), [want, want], JSON.stringify(client));
  }
});

// --- state_ignored_by_git (section 1.1): the file is still read and sent; the person is told --------------------------
function inGit(root, ignore) {
  mkdirSync(join(root, ".git"), { recursive: true });
  if (ignore !== null) writeFileSync(join(root, ".gitignore"), ignore);
  return root;
}

test("a state.json that git ignores is still read and sent, with state_ignored_by_git", async () => {
  for (const ignore of [".custosa/\n", "state.json\n", "*.json\n"]) {
    const h = harness({ roots: [inGit(rootWith(stateWith("rls-enabled@public.a")), ignore)] });
    const out = await h.runCheck({ goal: "check" }, { roots: ["A"] });
    assert.deepEqual(h.bodies[0].committed.decisions.map((d) => d.object_id), ["rls-enabled@public.a"], ignore);
    assert.ok(out.local_notes?.some((n) => n.startsWith("state_ignored_by_git")), ignore);
  }
});

test("no state_ignored_by_git when git doesn't ignore the file, re-includes it, or there is no git repository", async () => {
  const roots = [inGit(rootWith(stateWith("rls-enabled@public.a")), null),
    inGit(rootWith(stateWith("rls-enabled@public.a")), "*.json\n!.custosa/state.json\n"),
    (() => { const r = rootWith(stateWith("rls-enabled@public.a")); writeFileSync(join(r, ".gitignore"), ".custosa/\n"); return r; })()];
  for (const root of roots) {
    const h = harness({ roots: [root] });
    const out = await h.runCheck({ goal: "check" }, { roots: ["A"] });
    assert.ok(h.bodies[0].committed);
    assert.ok(!(out.local_notes ?? []).some((n) => n.startsWith("state_ignored_by_git")), root);
  }
});

test("a first write into an ignored .custosa says state_ignored_by_git, so the person knows a commit won't share it", async () => {
  const root = inGit(rootWith(), ".custosa/\n");
  const out = await writer({ root, pages: [page([issued("rls-enabled@public.a")])] })({ goal: "check" }, { roots: ["A"] });
  assert.equal(readState(root).status, "ok");
  assert.ok(out.local_notes.some((n) => n.startsWith("state_ignored_by_git")));
  const plain = inGit(rootWith(), null);
  const out2 = await writer({ root: plain, pages: [page([issued("rls-enabled@public.a")])] })({ goal: "check" }, { roots: ["A"] });
  assert.ok(!out2.local_notes.some((n) => n.startsWith("state_ignored_by_git")));
});

test("contract 2.3: the top-level state is read, so an in-progress check with no report still records its entries", async () => {
  const root = rootWith();
  const p = { goal: "check", status: "in_progress", session: "s_0123456789abcdef0123",
    state: { state_version: 1, sent: { decisions: 0, suppressions: 0, grants: 0 }, by_outcome: {}, unmatched: [],
      to_commit: [issued("rls-enabled@public.a")], to_commit_total: 2, not_committed: [] } };
  const out = await writer({ root, pages: [p] })({ goal: "check" }, { roots: ["A"] });
  assert.deepEqual(readState(root).state.decisions.map((d) => d.subject), ["rls-enabled@public.a"]);
  assert.ok(out.local_notes.some((n) => n.startsWith("state_entries_not_read: 1 ")));
});

test("the block comes from the same state.json read as the content key: a file changed after the build isn't read again", async () => {
  const { readState } = await import("../lib/inspector/state.mjs");
  const root = rootWith(stateWith("rls-enabled@public.a"));
  const read = readState(root);
  writeFileSync(join(root, ".custosa", "state.json"), JSON.stringify(stateWith("rls-enabled@public.b")));
  const h = harness({ roots: [root] });
  const build = async () => ({ notes: [], documents: [{ project: 0, label: "", nested: false, other: false, skipped: false,
    root_id: "0".repeat(64), abs: root, stateRead: read, document: { session: null } }] });
  const runCheck = makeRunCheck({ localOnly: false, readToken: () => ({ token: "t", host: "https://e.test" }),
    evaluatorUrl: () => ({ url: "https://e.test", origin: "https://e.test" }),
    environmentFor: () => ({ environment: { value: "unknown", source: "setup" }, note: null }),
    evaluate: async (body) => { h.bodies.push(structuredClone(body)); return { ok: true, body: { goal: body.goal, status: "done", session: null } }; },
    build });
  await runCheck({ goal: "check" }, { roots: [root] });
  assert.deepEqual(h.bodies[0].committed.decisions.map((d) => d.object_id), ["rls-enabled@public.a"]);
});

test("each built root carries its one state.json read, and its matches' content key is that read's", async () => {
  const { buildFactDocuments } = await import("../lib/inspector/factdoc.mjs");
  const { readState } = await import("../lib/inspector/state.mjs");
  const root = rootWith(stateWith("rls-enabled@public.a"));
  let seen = null;
  const runRules = async (_rules, _files, opts) => { seen = opts.contentKey;
    return { matches: [], links: [], notAnalyzed: [], analyzed: 0, analyzedPaths: [], languages: [], status: "ok", count: 0 }; };
  writeFileSync(join(root, "a.ts"), "f();\n");
  const out = await buildFactDocuments([root], { configDir: mkdtempSync(join(tmpdir(), "send-cfg-")), runRules,
    ruleset: { id: "2026-10-20.0123abcd", rules: [], queries: [] },
    collectCatalog: async () => ({ status: "not_run", count: 0, reason: "service_missing", preflight: null, queries: [] }),
    collectPlatform: async () => ({ provider: null, status: "not_run", reason: "no_token", settings: {} }) });
  assert.deepEqual(out.documents[0].stateRead, readState(root));
  assert.equal(seen, "c".repeat(64));
});

/* T29 o2 step 2 (T29-P1-C116 (a)): the state's lists are in the call's store. After an evaluation the CLI reads
 * state.to_commit (and not_committed) through get_result, following a sub_index entry by entry, and writes every entry;
 * nothing waits on a later page. */
test("T29 o2: to_commit is read through get_result, every entry past a sub_index, and written in the same call", async () => {
  const root = rootWith();
  const asked = [];
  const fixed = { state_version: 1, sent: { decisions: 0, suppressions: 0, grants: 0 }, by_outcome: {}, to_commit_total: 2 };
  const entries = [issued("rls-enabled@public.a"), issued("rls-enabled@public.b")];
  const evaluate = async (body) => {
    if (!body.select) return { ok: true, body: { goal: "check", status: "done", session: "s_0123456789abcdef0123", state: fixed,
      report: { state: fixed } } };
    asked.push(body.select.list);
    const [name, at] = body.select.list.split("#");
    const base = { goal: "check", session: "s_0123456789abcdef0123", select: body.select, part: "detail", is_fetch_only: true,
      charged_units: 0 };
    if (name !== "state.to_commit") return { ok: true, body: { ...base, matched: 0, results: [] } };
    if (at === undefined) return { ok: true, body: { ...base, matched: 2, sub_index: entries.map((e, i) => ({ select: { list: `state.to_commit#${i}` } })) } };
    return { ok: true, body: { ...base, matched: 1, results: [entries[Number(at)]] } };
  };
  const run = makeRunCheck({ localOnly: false, readToken: () => ({ token: "t", host: "https://e.test" }),
    evaluatorUrl: () => ({ url: "https://e.test", origin: "https://e.test" }), stateEnv: {},
    environmentFor: () => ({ environment: { value: "unknown", source: "setup" }, note: null }), evaluate,
    build: async () => ({ notes: [], documents: [{ project: 0, label: "", nested: false, other: false, skipped: false,
      root_id: "0".repeat(64), abs: root, document: { session: null } }] }) });
  const out = await run({ goal: "check" }, { roots: ["A"] });
  assert.deepEqual(readState(root).state.decisions.map((d) => d.subject), ["rls-enabled@public.a", "rls-enabled@public.b"]);
  assert.ok(asked.includes("state.to_commit") && asked.includes("state.to_commit#1"), asked.join(","));
  assert.ok(!(out.local_notes ?? []).some((n) => n.startsWith("state_entries_not_read")));
});

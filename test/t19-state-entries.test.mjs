/* T19 (P2): the committed state file, the parts no test reached. Suppressions and grants the core issued are written
 * and read back (only decisions were); a grant on a table that may not be committed is left out and counted; a
 * state.json that is a folder, a .custosa that is a file, and a read-only project. A write that fails gives the
 * state_not_written note, and the check's answer still comes back: before, the throw turned it into "the local
 * inspector failed", and every retry failed the same way. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync,
  writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { entriesFrom, readState, recordIssued, writeState } from "../lib/inspector/state.mjs";
import { makeRunCheck } from "../lib/inspector/tool.mjs";

const root = () => realpathSync(mkdtempSync(join(tmpdir(), "custosa-t19-state-")));
const MADE = { account_tag: "0123456789abcdef", made_on: "2026-10-30", ruleset_id: "2026-10-31.90bf3c76",
  registry_id: "2026-10-30.1234abcd", fact_token: "a".repeat(32), seal: "b".repeat(32) };
const AT = new Date("2026-11-11T10:00:00.500Z");
const decision = (object_id) => ({ kind: "decision", object_id, practice_id: object_id.split("@")[0],
  option: "not_used", expires_on: null, max_age_on: "2027-01-28", reasons: ["person_must_decide"],
  f4_class: "coverage_gap", why_asked: "assistant_could_not_decide", ...MADE });
const suppression = (object_id) => ({ kind: "suppression", object_id, practice_id: object_id.split("@")[0],
  reason: "accepted_risk", expires_on: "2027-01-28", ...MADE });
const grant = (table, grantee, privileges) => ({ kind: "grant", table, grantee,
  ...(privileges === undefined ? {} : { privileges }), expires_on: "2027-01-28", ...MADE });
const NOT_WRITTEN = /^state_not_written: \.custosa\/state\.json could not be written \((E[A-Z]+)\), so these decisions apply in this session only\./;

test("a suppression and grants the core issued are written, and the file reads back ok", () => {
  const dir = root();
  const notes = recordIssued(dir, { to_commit: [suppression("rls-enabled@public.visits"),
    grant("public.visits", "anon", ["update", "select"]), grant("public.care_messages", "PUBLIC")] },
  { env: {}, client: "Claude Code", at: AT });
  assert.equal(notes.length, 1);
  assert.ok(notes[0].includes("before others record decisions"));
  const read = readState(dir);
  assert.equal(read.status, "ok");
  const audit = { decided_by: "person", relayed_by: "assistant", client: "Claude Code", decided_at: "2026-11-11T10:00:00Z" };
  const { kind, object_id, account_tag, made_on, ruleset_id, registry_id, fact_token, seal, ...rest } = suppression("x@y");
  const made = { account_tag, made_on, ruleset_id, registry_id, fact_token, seal };
  assert.deepEqual(read.state.suppressions, [{ ...rest, subject: "rls-enabled@public.visits", practice_id: "rls-enabled",
    made, audit }]);
  // sorted by table then grantee; privileges sorted; none given is null (every privilege)
  assert.deepEqual(read.state.grants_baseline, [
    { table: "public.care_messages", grantee: "PUBLIC", privileges: null, expires_on: "2027-01-28", made, audit },
    { table: "public.visits", grantee: "anon", privileges: ["select", "update"], expires_on: "2027-01-28", made, audit }]);
  assert.deepEqual(read.state.decisions, []);
});

test("a grant on a per-install, hashed or value-shaped table is left out and counted", () => {
  const screen = (name) => name.includes("jane.doe");
  const { adds, refused } = entriesFrom([grant("public.u_0123456789abcdef", "anon"), grant("d".repeat(64), "anon"),
    grant("public.jane.doe", "anon"), grant("public.visits", "anon")], { screen });
  assert.equal(refused, 3);
  assert.deepEqual(adds.grants_baseline.map((g) => g.table), ["public.visits"]);
  const dir = root();
  const notes = recordIssued(dir, { to_commit: [grant("public.u_0123456789abcdef", "anon")] }, { env: {}, screen });
  assert.match(notes[0], /^state_subject_not_committable: 1 decisions/);
  assert.ok(notes[1].includes("before others record decisions"));   // the key is still made
  assert.deepEqual(readState(dir).state.grants_baseline, []);
});

test("a state.json that is a folder is unreadable, and is never written over", () => {
  const dir = root();
  mkdirSync(join(dir, ".custosa", "state.json"), { recursive: true });
  assert.deepEqual(readState(dir), { status: "unreadable", reason: "parse" });
  const notes = recordIssued(dir, { to_commit: [decision("rls-enabled@public.a")] }, { env: {} });
  assert.ok(notes[0].startsWith("state_unreadable: "));
  assert.deepEqual(readdirSync(join(dir, ".custosa")), ["state.json"]);
  assert.deepEqual(readdirSync(join(dir, ".custosa", "state.json")), []);
});

test("a .custosa that is a file reads as no state; a write says state_not_written and leaves the file alone", () => {
  const dir = root();
  writeFileSync(join(dir, ".custosa"), "kept\n");
  assert.deepEqual(readState(dir), { status: "missing" });
  const notes = recordIssued(dir, { to_commit: [decision("rls-enabled@public.a")] }, { env: {} });
  assert.equal(notes.length, 1);
  assert.match(notes[0], NOT_WRITTEN);
  assert.equal(readFileSync(join(dir, ".custosa"), "utf8"), "kept\n");
});

test("a read-only project folder: state_not_written, nothing made", { skip: process.getuid?.() === 0 && "root ignores folder modes" }, () => {
  const dir = root();
  chmodSync(dir, 0o555);
  try {
    const notes = recordIssued(dir, { to_commit: [decision("rls-enabled@public.a")] }, { env: {} });
    assert.equal(notes[0].match(NOT_WRITTEN)?.[1], "EACCES");
  } finally {
    chmodSync(dir, 0o755);
  }
  assert.deepEqual(readdirSync(dir), []);
});

test("writeState: a rename that fails takes its temp file away and throws", () => {
  const dir = root();
  mkdirSync(join(dir, ".custosa", "state.json", "inside"), { recursive: true });   // a folder that isn't empty
  assert.throws(() => writeState(dir, { status: "missing" }, { decisions: [] }, { env: {} }), (e) => /^E[A-Z]+$/.test(e.code));
  assert.deepEqual(readdirSync(join(dir, ".custosa")).sort(), ["state.json"]);
});

test("a check whose state can't be written still returns its answer, with the note", async () => {
  const dir = root();
  writeFileSync(join(dir, ".custosa"), "kept\n");
  const answer = { goal: "check", status: "done", session: "s_0123456789abcdef0123", report: { state: { state_version: 1,
    sent: { decisions: 0, suppressions: 0, grants: 0 }, by_outcome: {}, unmatched: [],
    to_commit: [decision("rls-enabled@public.a")], not_committed: [] } } };
  const run = makeRunCheck({ localOnly: false, readToken: () => ({ token: "t", host: "https://e.test" }),
    evaluatorUrl: () => ({ url: "https://e.test", origin: "https://e.test" }), stateEnv: {},
    environmentFor: () => ({ environment: { value: "unknown", source: "setup" }, note: null }),
    evaluate: async () => ({ ok: true, body: structuredClone(answer) }),
    build: async () => ({ notes: [], documents: [{ project: 0, label: "", nested: false, other: false, skipped: false,
      root_id: "0".repeat(64), abs: dir, document: { session: null } }] }) });
  const out = await run({ goal: "check" }, { roots: ["A"] });
  assert.equal(out.status, "done");
  assert.equal(out.session, answer.session);
  assert.ok(out.local_notes.some((n) => NOT_WRITTEN.test(n)), JSON.stringify(out.local_notes));
  assert.equal(existsSync(join(dir, ".custosa")) && readFileSync(join(dir, ".custosa"), "utf8"), "kept\n");
});

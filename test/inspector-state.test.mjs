/* Contract 2.3, CLI half part 1: the committed state file
 * .custosa/state.json. A strict read that ignores the whole file on any fault, with a closed reason (section 1.3); the
 * block sent to the core, with only the fields it reads (section 3.1); CI detection (section 1.1); the atomic write
 * with no symlinks, no backups and no git (section 1.1); the content key (section 2.4). */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, symlinkSync,
  writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { blockOf, ciMode, emptyState, mergeEntries, newContentKey, readState, STATE_CAPS, STATE_DIR, STATE_FILE,
  STATE_MAX_BYTES, writeState } from "../lib/inspector/state.mjs";

const root = () => realpathSync(mkdtempSync(join(tmpdir(), "custosa-state-")));
const MADE = { account_tag: "0123456789abcdef", made_on: "2026-10-30", ruleset_id: "2026-10-31.90bf3c76",
  registry_id: "2026-10-30.1234abcd", fact_token: "a".repeat(32), seal: "b".repeat(32) };
const AUDIT = { decided_by: "person", relayed_by: "assistant", client: "Claude Code", decided_at: "2026-10-30T12:00:00Z" };
const decision = (subject, more = {}) => ({ subject, practice_id: subject.split("@")[0], option: "not_used",
  expires_on: null, max_age_on: null, reasons: ["person_must_decide"], f4_class: "coverage_gap",
  why_asked: "assistant_could_not_decide", made: MADE, audit: AUDIT, ...more });
const suppression = (subject) => ({ subject, practice_id: subject.split("@")[0], reason: "accepted_risk",
  expires_on: "2027-01-28", made: MADE, audit: AUDIT });
const grant = (table, grantee, privileges = null) => ({ table, grantee, privileges, expires_on: "2027-01-28",
  made: MADE, audit: AUDIT });
const KEY = "c".repeat(64);
const valid = () => ({ state_version: 1, content_key: KEY,
  decisions: [decision("rls-enabled@public.appointments"), decision("rls-enabled@public.visits")],
  suppressions: [suppression("rls-enabled@public.care_messages")],
  grants_baseline: [grant("public.care_messages", "PUBLIC", ["select", "update"]), grant("public.care_messages", "anon")] });

function put(dir, value) {
  mkdirSync(join(dir, ".custosa"), { recursive: true });
  writeFileSync(join(dir, ".custosa", "state.json"), typeof value === "string" ? value : JSON.stringify(value, null, 2));
  return dir;
}

// --- Read (6.2 tests 1 and 2) ---------------------------------------------------------------------------------------
test("no file: nothing is sent and no note is shown", () => {
  assert.deepEqual(readState(root()), { status: "missing" });
});

test("a valid file is read, and the block holds only what the core reads", () => {
  const got = readState(put(root(), valid()));
  assert.equal(got.status, "ok");
  assert.equal(got.state.content_key, KEY);
  const block = blockOf(got.state);
  assert.deepEqual(Object.keys(block), ["state_version", "decisions", "suppressions", "grants"]);
  assert.deepEqual(block.decisions[0], { object_id: "rls-enabled@public.appointments", option: "not_used",
    expires_on: null, max_age_on: null, account_tag: MADE.account_tag, made_on: MADE.made_on,
    fact_token: MADE.fact_token, seal: MADE.seal });
  assert.deepEqual(block.suppressions[0], { object_id: "rls-enabled@public.care_messages", reason: "accepted_risk",
    expires_on: "2027-01-28", account_tag: MADE.account_tag, made_on: MADE.made_on, fact_token: MADE.fact_token,
    seal: MADE.seal });
  assert.deepEqual(block.grants[0].privileges, ["select", "update"]);
  const text = JSON.stringify(block);
  for (const leak of [KEY, "decided_by", "relayed_by", "Claude Code", "decided_at", "ruleset_id", "f4_class",
    "why_asked", "person_must_decide"]) assert.ok(!text.includes(leak), leak);
});

const unreadable = [
  ["state_version 2", { ...valid(), state_version: 2 }, "version"],
  ["state_version 0", { ...valid(), state_version: 0 }, "version"],
  ["state_version \"1\"", { ...valid(), state_version: "1" }, "version"],
  ["no state_version", (({ state_version, ...rest }) => rest)(valid()), "version"],
  ["bad JSON", "{\"state_version\": 1,", "parse"],
  ["a BOM", "﻿" + JSON.stringify(valid()), "parse"],
  ["a duplicate key", JSON.stringify(valid()).replace("{\"state_version\":1,", "{\"state_version\":1,\"state_version\":1,"), "parse"],
  ["a duplicate key deep down", JSON.stringify(valid()).replace("\"option\":\"not_used\"", "\"option\":\"not_used\",\"option\":\"used\""), "parse"],
  ["not UTF-8", Buffer.from([0x7b, 0xff, 0x7d]), "parse"],
  ["an unknown field", { ...valid(), notes: "hi" }, "schema"],
  ["an unknown field in an entry", { ...valid(), decisions: [decision("rls-enabled@public.a", { note: "x" })] }, "schema"],
  ["two entries with one key", { ...valid(), decisions: [decision("rls-enabled@public.a"), decision("rls-enabled@public.a")] }, "schema"],
  ["entries out of order", { ...valid(), decisions: [decision("rls-enabled@public.b"), decision("rls-enabled@public.a")] }, "schema"],
  ["practice_id not the subject's", { ...valid(), decisions: [decision("rls-enabled@public.a", { practice_id: "rls-forced" })] }, "schema"],
  ["privileges out of order", { ...valid(), grants_baseline: [grant("public.t", "PUBLIC", ["update", "select"])] }, "schema"],
  ["a handler id", { ...valid(), decisions: [decision(`authz-every-handler@${"d".repeat(64)}`)] }, "schema"],
  ["a line ending", { ...valid(), decisions: [decision("edge-function-auth@supabase/functions/a.ts:12")] }, "schema"],
  ["1,001 decisions", { ...valid(), decisions: Array.from({ length: 1001 }, (_, i) => decision(`rls-enabled@public.t${String(i).padStart(4, "0")}`)) }, "size"],
  ["10,000 decisions", { ...valid(), decisions: Array.from({ length: 10000 }, (_, i) => decision(`rls-enabled@public.t${String(i).padStart(5, "0")}`)) }, "size"],
];
for (const [name, value, reason] of unreadable) {
  test(`unreadable, ${name}: ignored whole, reason ${reason}, nothing sent, never rewritten`, () => {
    const dir = root();
    mkdirSync(join(dir, ".custosa"));
    const path = join(dir, ".custosa", "state.json");
    const bytes = Buffer.isBuffer(value) ? value : typeof value === "string" ? value : JSON.stringify(value, null, 2);
    writeFileSync(path, bytes);
    const got = readState(dir);
    assert.deepEqual(got, { status: "unreadable", reason });
    assert.equal(writeState(dir, got, { decisions: [] }).written, false);
    assert.deepEqual(readFileSync(path), Buffer.from(bytes));
  });
}

test("a file over 2 MiB is unreadable for its size", () => {
  const dir = put(root(), " ".repeat(STATE_MAX_BYTES + 1));
  assert.deepEqual(readState(dir), { status: "unreadable", reason: "size" });
});

test("a symlinked state.json or .custosa is unreadable, and nothing is written outside the repository", () => {
  const outside = root();
  writeFileSync(join(outside, "state.json"), JSON.stringify(valid()));
  const a = root();
  mkdirSync(join(a, ".custosa"));
  symlinkSync(join(outside, "state.json"), join(a, ".custosa", "state.json"));
  const b = root();
  symlinkSync(outside, join(b, ".custosa"));
  for (const dir of [a, b]) {
    const got = readState(dir);
    assert.deepEqual(got, { status: "unreadable", reason: "symlink" });
    assert.equal(writeState(dir, got, { decisions: [] }).written, false);
  }
  assert.deepEqual(readdirSync(outside), ["state.json"]);
  assert.deepEqual(JSON.parse(readFileSync(join(outside, "state.json"), "utf8")), valid());
});

// --- CI (6.2 test 5) -------------------------------------------------------------------------------------------------
const CI_VARS = ["CI", "GITHUB_ACTIONS", "GITLAB_CI", "BUILDKITE", "CIRCLECI", "JENKINS_URL", "TF_BUILD",
  "CODEBUILD_BUILD_ID", "TEAMCITY_VERSION"];
test("CI mode is any of the nine variables set to anything but false or 0", () => {
  for (const name of CI_VARS) {
    assert.equal(ciMode({ [name]: "true" }), name);
    assert.equal(ciMode({ [name]: "yes" }), name);
    assert.equal(ciMode({ [name]: "false" }), null);
    assert.equal(ciMode({ [name]: "0" }), null);
  }
  assert.equal(ciMode({}), null);
  assert.equal(ciMode({ CI: "" }), null);
  assert.equal(ciMode({}, { ci: true }), "--ci");
});

test("in CI nothing is written", () => {
  const dir = root();
  const got = writeState(dir, readState(dir), { decisions: [decision("rls-enabled@public.a")] }, { env: { CI: "1" } });
  assert.deepEqual(got, { written: false, note: "no_person_in_ci", variable: "CI" });
  assert.ok(!existsSync(join(dir, ".custosa")));
});

// --- Write (6.2 test 4) ----------------------------------------------------------------------------------------------
test("the first write makes a content key, the .gitignore and a sorted file; no backup, no temp file left", () => {
  const dir = root();
  const got = writeState(dir, readState(dir), { decisions: [decision("rls-enabled@public.b"), decision("rls-enabled@public.a")],
    grants_baseline: [grant("public.t", "anon"), grant("public.t", "PUBLIC", ["update", "select"])] }, { env: {} });
  assert.equal(got.written, true);
  assert.equal(got.note, "state_key_created");
  const back = readState(dir);
  assert.equal(back.status, "ok");
  assert.match(back.state.content_key, /^[0-9a-f]{64}$/);
  assert.deepEqual(back.state.decisions.map((d) => d.subject), ["rls-enabled@public.a", "rls-enabled@public.b"]);
  assert.deepEqual(back.state.grants_baseline.map((g) => g.grantee), ["PUBLIC", "anon"]);
  assert.deepEqual(back.state.grants_baseline[0].privileges, ["select", "update"]);
  assert.deepEqual(readdirSync(join(dir, ".custosa")).sort(), [".gitignore", "state.json"]);
  assert.equal(readFileSync(join(dir, ".custosa", ".gitignore"), "utf8"), "local/\n*.custosa-tmp\n");
  const text = readFileSync(join(dir, ".custosa", "state.json"), "utf8");
  assert.ok(text.endsWith("}\n") && !text.includes("\r") && text.includes("\n  \"content_key\""));
  // a later write keeps the key, replaces by key, and leaves the .gitignore as the person has it
  writeFileSync(join(dir, ".custosa", ".gitignore"), "mine\n");
  const again = writeState(dir, back, { decisions: [decision("rls-enabled@public.a", { option: "used_open" })] }, { env: {} });
  assert.equal(again.written, true);
  assert.equal(again.note, undefined);
  const after = readState(dir).state;
  assert.equal(after.content_key, back.state.content_key);
  assert.deepEqual(after.decisions.map((d) => [d.subject, d.option]), [["rls-enabled@public.a", "used_open"],
    ["rls-enabled@public.b", "not_used"]]);
  assert.equal(readFileSync(join(dir, ".custosa", ".gitignore"), "utf8"), "mine\n");
});

test("a write over a cap is refused whole: state_full", () => {
  const dir = put(root(), { ...valid(), decisions: [], suppressions: Array.from({ length: STATE_CAPS.suppressions },
    (_, i) => suppression(`rls-enabled@public.t${String(i).padStart(3, "0")}`)) });
  const before = readFileSync(join(dir, ".custosa", "state.json"));
  const got = writeState(dir, readState(dir), { suppressions: [suppression("rls-enabled@public.zzz")] }, { env: {} });
  assert.deepEqual(got, { written: false, note: "state_full" });
  assert.deepEqual(readFileSync(join(dir, ".custosa", "state.json")), before);
});

test("mergeEntries replaces by key and sorts by key in code-point order", () => {
  const merged = mergeEntries(emptyState(KEY), { decisions: [decision("rls-enabled@public.b"), decision("rls-enabled@public.B")] });
  assert.deepEqual(merged.decisions.map((d) => d.subject), ["rls-enabled@public.B", "rls-enabled@public.b"]);
});

test("the content key is 32 random bytes as 64 hex", () => {
  const a = newContentKey();
  assert.match(a, /^[0-9a-f]{64}$/);
  assert.notEqual(a, newContentKey());
});

test("the state module runs no git write command", () => {
  const src = readFileSync(new URL("../lib/inspector/state.mjs", import.meta.url), "utf8");
  assert.ok(!/child_process|execFile|spawn/.test(src));
  assert.ok(!/files\.mjs|writeSafely|custosa-backup/.test(src));
});

test("the state schema copy is the core's", () => {
  const ours = readFileSync(new URL("../lib/inspector/contracts/state.schema.json", import.meta.url), "utf8");
  assert.equal(JSON.parse(ours).$id, "https://custosa.com/schemas/state/1");
  assert.ok(lstatSync(new URL("../lib/inspector/contracts/state.schema.json", import.meta.url)).isFile());
});

test("the state path ignoredByGit asks about is ASCII, so its NFC and on-disk forms can't differ", () => {
  // gitread.ignoreState reads the NFC form of the path it is given; git matches the on-disk bytes when
  // core.precomposeunicode is off. That is the same for an ASCII path, so the state_ignored_by_git note
  // can't call a file ignored that git shows. A non-ASCII state path would need the walker's two-form rule here too.
  assert.match(`${STATE_DIR}/${STATE_FILE}`, /^[\x21-\x7e]+$/);
});

/* the local span pre-check. A location span that touches no confirming match of its
 * practice in the document gets a local warning; nothing about it is sent, and the answer is sent as it was. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildFactDocuments, SPAN_PRECHECK_NOTE, spanWarnings } from "../lib/inspector/factdoc.mjs";

const m = (o) => ({ rule_id: "r", practice_id: "ai-tools", kind: "item", path: "src/a.ts", line_start: 10, line_end: 20,
  has_control: true, ...o });
const here = (o) => ({ object_id: "ai-tools@t1", question_id: "location", answer: "here", location: "src/a.ts:12",
  location_kind: "function", ...o });
const warned = (answers, matches) => spanWarnings(answers, matches, new Map());

test("a span on a controlled item or evidence of its practice is fine; overlap is enough", () => {
  assert.deepEqual(warned([here()], [m()]), []);
  assert.deepEqual(warned([here({ location: "src/a.ts:5-10" })], [m()]), []);
  assert.deepEqual(warned([here({ location: "src/a.ts:20-30" })], [m()]), []);
  assert.deepEqual(warned([here()], [m({ kind: "evidence", has_control: null })]), []);
});

test("a span that misses, or lands on the wrong kind, practice or file, is warned about", () => {
  for (const match of [m({ line_start: 13, line_end: 20 }), m({ has_control: false }), m({ kind: "violation", has_control: null }),
    m({ practice_id: "other" }), m({ path: "src/b.ts" })]) {
    const out = warned([here()], [match]);
    assert.equal(out.length, 1, JSON.stringify(match));
    assert.ok(out[0].includes("ai-tools@t1") && out[0].includes("src/a.ts:12"));
  }
  assert.equal(warned([here()], []).length, 1);
});

test("with a code, only controlled items count; every span in at is checked and named once", () => {
  assert.equal(warned([here({ code: "tools_scoped_at" })], [m({ kind: "evidence", has_control: null })]).length, 1);
  assert.deepEqual(warned([here({ code: "tools_scoped_at" })], [m()]), []);
  const out = warned([here({ at: ["src/a.ts:15", "src/a.ts:40-41", "src/a.ts:50"] })], [m()]);
  assert.equal(out.length, 1);
  assert.ok(out[0].includes("src/a.ts:40-41, src/a.ts:50") && !out[0].includes("src/a.ts:15"));
});

test("answers with no location are skipped, and the note names the span as the assistant gave it", () => {
  assert.deepEqual(warned([here({ answer: "not_present", location: null }), here({ location: null, location_kind: "not_found" })], []), []);
  const out = spanWarnings([here({ location: "src/u_0123456789abcdef.ts:12" })], [], new Map([["src/u_0123456789abcdef.ts:12", "src/123-45-6789.ts:12"]]));
  assert.deepEqual(out, [SPAN_PRECHECK_NOTE.replace("{object_id}", "ai-tools@t1").replace("{spans}", "src/123-45-6789.ts:12")]);
});

test("buildFactDocuments returns the warning as a local note and sends the answer unchanged", async () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "span-pre-")));
  mkdirSync(join(root, "src"));
  writeFileSync(join(root, "src/a.ts"), Array.from({ length: 30 }, (_, i) => `f${i}();`).join("\n") + "\n");
  const runRules = async () => ({ matches: [m({ line_start: 10, line_end: 12 })], links: [], notAnalyzed: [], analyzed: 1,
    analyzedPaths: ["src/a.ts"], languages: ["typescript"], status: "ok", count: 1 });
  const build = (location) => buildFactDocuments([root], { configDir: mkdtempSync(join(tmpdir(), "span-cfg-")), runRules,
    ruleset: { id: "2026-10-20.0123abcd", rules: [], queries: [] }, session: "ps_abcdefghijklmnopqrstuv",
    answers: [{ object_id: "ai-tools@t1", question_id: "location", answer: "here", location }],
    collectCatalog: async () => ({ status: "not_run", count: 0, reason: "service_missing", preflight: null, queries: [] }),
    collectPlatform: async () => ({ provider: null, status: "not_run", reason: "no_token", settings: {} }) });
  const ok = await build("src/a.ts:11");
  assert.ok(!ok.notes.some((n) => n.includes("ai-tools@t1")));
  const off = await build("src/a.ts:25");
  assert.equal(off.notes.filter((n) => n.includes("ai-tools@t1")).length, 1);
  assert.equal(off.documents[0].document.answers[0].location, "src/a.ts:25");
  assert.ok(!JSON.stringify(off.documents[0].document).includes("evaluator won't"), "the note is never sent");
});

/* T29-P1-C7 rank 6 (accept-evidence), the spelled_digits part: on the shipped screen rules, a number word in plain
 * technical prose near a hotword ("patient", "record") is not a record value. In the fullhp run and in
 * lab/T29/bottlenecks.md section 2.3 these plain sentences were refused, while their digit forms passed. Refuse only for
 * privacy: a long run of number words (a spelled id or phone number) and names still refuse. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { loadRules, screenRaw } from "../lib/screen.mjs";
import { NOTE_RULES_FILE } from "../lib/inspector/tool.mjs";
import { refsRefused } from "../lib/inspector/notes.mjs";

const RULES = loadRules(fileURLToPath(NOTE_RULES_FILE));
const IDS = ["patients", "appointments", "src/lib/prisma.ts"];
const rulesHit = (note) => screenRaw(note, IDS, RULES).hits.map((h) => h.rule);

for (const note of [
  "Each patient record is read by four handlers with no session check.",
  "The patient table keeps three years of history and no retention job.",
  "Audit rows for patient reads are missing in five of the seven handlers.",
  "Only one patient route checks the session.",
]) {
  test(`plain prose with a count near a hotword is not refused: ${note}`, () => {
    assert.deepEqual(rulesHit(note).filter((r) => r === "spelled_digits"), []);
  });
}

for (const note of [
  "The patient record number is four four seven one eight eight two.",
  "Patient phone is five five five one two one two.",
]) {
  test(`a spelled-out value near a hotword still refuses: ${note}`, () => {
    assert.ok(rulesHit(note).includes("spelled_digits"), rulesHit(note).join(","));
  });
}

test("a person's name still refuses", () => {
  assert.ok(rulesHit("Dr Smith can read every patient.").length > 0);
});

/* line_uncited: a line the check itself cited is citable. A match cites path:start-end; the AI citing a line or a
 * narrower range inside it cites what the check cited. A line outside every cited range, or an uncited path, is still
 * refused (line_uncited, not_read). */
const DOC = { matches: [{ rule_id: "authz-every-handler.typescript-nextjs.route", practice_id: "authz-every-handler",
  kind: "item", path: "app/api/notes/route.ts", line_start: 12, line_end: 30 }] };
const refsOf = (...refs) => refsRefused({ verdicts: [{ practice_id: "authz-every-handler", refs }] }, [DOC]);

test("a line or range inside a range the check cited is citable", () => {
  assert.deepEqual(refsOf("app/api/notes/route.ts:12-30"), []);
  assert.deepEqual(refsOf("app/api/notes/route.ts:12"), []);
  assert.deepEqual(refsOf("app/api/notes/route.ts:15"), []);
  assert.deepEqual(refsOf("app/api/notes/route.ts:14-20"), []);
});

test("a line outside every cited range, or an uncited file, is still refused", () => {
  assert.deepEqual(refsOf("app/api/notes/route.ts:31").map((r) => r.why), ["line_uncited"]);
  assert.deepEqual(refsOf("app/api/notes/route.ts:10-14").map((r) => r.why), ["line_uncited"]);
  assert.deepEqual(refsOf("app/other.ts:3").map((r) => r.why), ["not_read"]);
});

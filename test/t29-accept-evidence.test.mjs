/* T29-P1-C7 rank 6 (accept-evidence), the spelled_digits part: on the shipped screen rules, a number word in plain
 * technical prose near a hotword ("patient", "record") is not a record value. In the fullhp run and in
 * lab/T29/bottlenecks.md section 2.3 these plain sentences were refused, while their digit forms passed. Refuse only for
 * privacy: a long run of number words (a spelled id or phone number) and names still refuse. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { loadRules, screenRaw } from "../lib/screen.mjs";
import { NOTE_RULES_FILE } from "../lib/inspector/tool.mjs";

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

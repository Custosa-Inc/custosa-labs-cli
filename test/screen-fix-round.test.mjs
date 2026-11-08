/* The screen fix round from the held-out results, on the shipped rule file:
 * the CLI twin of core's tests/core/test_t27_c145_fix_round.py, case for case.
 *
 * Names lean to refusing: a capitalised strong NAME refuses alone (item 1), an ambiguous word with a name signal refuses
 * (item 2), and the ambiguous list is pruned by rule (item 3). Ordinary developer text stops refusing: line breaks
 * (item 4), common punctuation (item 5), plain URLs (item 6), issue references (item 7), quoted words (item 8) and
 * language names (item 9). The cases are the ruling's own examples; none comes from a held-out set. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { defaultNoteRules, NOTE_RULES_FILE } from "../lib/inspector/tool.mjs";
import { screenRaw } from "../lib/screen.mjs";

const rules = defaultNoteRules();
const rulesHit = (text) => new Set(screenRaw(text, [], rules).hits.map((h) => h.rule));
const tag = (word) => (rules.safeWords.has(word) ? "SAFE" : rules.personalNames.has(word) ? "NAME"
  : rules.ambiguousNames.has(word) ? "AMBIG" : "OOV");

test("names lean to refusing: a lone capitalised NAME, and an ambiguous word with a name signal", () => {
  for (const [text, rule] of [
    ["Kwon is the patient who reported the allergy", "name_alone"],
    ["Ananya asked us to hide it", "name_alone"],
    ["Wen's A1c came back 11.2%", "ambig_name"],
    ["Grant's chart was updated", "ambig_name"],
    ["Grant reported the rash", "ambig_name"],
    ["Grant is the patient", "ambig_name"],
    ["the pt Grant needs a refill", "ambig_name"],
    ["Dr Grant reviewed it", "title_name"],
  ]) assert.ok(rulesHit(text).has(rule), `${text}: ${[...rulesHit(text)]}`);
});

test("no signal, no refusal", () => {
  for (const text of ["will run the migration", "GRANT SELECT ON notes TO clinician", "grant usage to authenticated",
    "May release notes", "KWON is not a name in caps", "Apgar score column has no encryption",
    "Glasgow Coma Scale values are stored as integers", "Mr. and Mrs. are titles"]) {
    assert.equal(screenRaw(text, [], rules).decision, "pass", `${text}: ${[...rulesHit(text)]}`);
  }
});

test("common surnames stay names, so Smith pairs and titles as before", () => {
  for (const word of ["smith", "brown", "king", "white"]) assert.ok(["NAME", "AMBIG"].includes(tag(word)), word);
  assert.ok(rulesHit("Jane Smith was admitted").has("name_pair"));
  assert.ok(rulesHit("Dr Smith reviewed it").has("title_name"));
});

test("code keywords and language names are safe words", () => {
  for (const word of ["select", "null", "english", "french", "greek", "kenya"]) assert.equal(tag(word), "SAFE", word);
  assert.notEqual(tag("jordan"), "SAFE"); // 100,000 births or more: still a name
});

test("ordinary developer text passes", () => {
  for (const text of [
    "fix the parser\nso it reads tabs\r\nand blank lines",
    "feat: camera polish \u2014 live doc detection",
    "rows \u2192 columns \u2022 3 \u00d7 4 at 20\u00b0 \u2018quoted\u2019 \u201cwords\u201d",
    "see https://hl7.org/fhir/StructureDefinition/Observation for the shape",
    "closes task #12746", "bug 34705 again", "PR #12 and issue 123", "closes #9",
    "the role is 'authenticated' and the message is \"no rows\"",
    "English and French labels are both shown",
  ]) assert.equal(screenRaw(text, [], rules).decision, "pass", `${JSON.stringify(text)}: ${[...rulesHit(text)]}`);
});

test("values still refuse", () => {
  for (const [text, rule] of [
    ["a\u0000b", "control_char"], ["a\u001bb", "control_char"], ["a\u202eb", "control_char"], ["a\u0085b", "control_char"],
    ["https://user:pw@db.internal/x", "url"], ["https://x.io/a?id=7", "url"],
    ["https://x.io/patients/0012-3456", "digit_run"],
    ["see PR 1234-56-78", "digit_run"], ["patient #12345678", "hotword_digits"],
    ["'John Doe'", "placeholder_value"], ["'000-00-0000'", "quoted_literal"], ["set it to 'Kwon'", "quoted_literal"],
    ["a line\nKwon was seen", "name_alone"],
  ]) assert.ok(rulesHit(text).has(rule), `${JSON.stringify(text)}: ${[...rulesHit(text)]}`);
});

test("a line break is a space for every rule", () => {
  assert.ok(rulesHit("Jane\nSmith").has("name_pair"));
});

test("the new lists, limit, rules and folds are in the shipped rule file", () => {
  const doc = JSON.parse(readFileSync(NOTE_RULES_FILE, "utf8"));
  for (const key of ["issue_words", "person_verbs", "person_cues"]) assert.ok(doc.lists[key].length > 0, key);
  assert.equal(doc.limits.cue_window, 3);
  const ids = new Set(doc.rules.map((r) => r.id));
  assert.ok(ids.has("name_alone") && ids.has("ambig_name"));
  assert.equal(doc.char_map["\n"], " ");
  assert.equal(doc.char_map["\u2014"], "-");
  assert.ok(!("code_keywords" in doc.lists) && !("char_folds" in doc.lists));
});

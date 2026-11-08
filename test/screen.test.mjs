// lib/screen.mjs, the free-text screen written from core's docs/screen-engine.md. Both engines
// must give the same output, byte for byte (spec §1). The parity fixture holds core's app/screen.py output for every
// shared vector, both adversarial sets and seeded fuzz, on a made-up rule file (see its "about").
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadRules, refStep, RuleFileError, rulesFromDoc, screen, screenRaw } from "../lib/screen.mjs";

const FIXTURE = JSON.parse(readFileSync(new URL("./fixtures/screen-parity.5e907cf8.json", import.meta.url), "utf8"));
const rules = rulesFromDoc(FIXTURE.doc, FIXTURE.sets);
const IDS = FIXTURE.snapshots.s0;

test("every parity case gives core's output exactly", () => {
  assert.ok(FIXTURE.cases.length > 2000);
  const differ = FIXTURE.cases.filter((c) =>
    JSON.stringify(screenRaw(c.raw, FIXTURE.snapshots[c.ids], rules, c.previous ?? null)) !== JSON.stringify(c.expect));
  assert.deepEqual(differ.map((c) => c.id), []);
});

test("offsets count code points: a character above U+FFFF is one", () => {
  const out = screenRaw("\u{1F600} MRN 0012-3456", IDS, rules);
  assert.deepEqual(out.hits.map((h) => [h.rule, h.start, h.end]),
    [["non_ascii_token", 0, 1], ["hotword_digits", 2, 15], ["digit_run", 6, 15]]);
  const { hits } = refStep("\u{1F600} `nope`", IDS, rules);
  assert.deepEqual(hits, [{ rule: "unknown_backtick_ref", start: 2, end: 8 }]);
});

test("a lone surrogate is a control character, and the whole note refuses on it alone", () => {
  assert.deepEqual(screenRaw("Maria \uD800 Gonzalez", IDS, rules), { decision: "refuse", hits: [{ rule: "control_char", start: 0, end: 16 }] });
});

test("a fullwidth placeholder made by NFKC is a spoof", () => {
  assert.deepEqual(screen("see \uFF1Cref:0\uFF1E", IDS, rules, []).hits, [{ rule: "placeholder_spoof", start: 0, end: 11 }]);
});

test("Unicode spaces and letters are never \\s or \\w: the regexes read ASCII only (spec §13 item 7)", () => {
  // U+1680 is a space to Python's Unicode \s, and ж a letter to its \w; to the screen both are just non-ASCII.
  assert.ok(screenRaw("password=hunter22a\u1680x", IDS, rules).hits.some((h) => h.rule === "credential_assignment" && h.end === 20));
  assert.ok(screenRaw("\u0436a1:b2::c3", IDS, rules).hits.some((h) => h.rule === "ipv6"));
});

test("a hit names only a rule the file lists", () => {
  const doc = { ...FIXTURE.doc, rules: FIXTURE.doc.rules.filter((r) => r.id !== "digit_run") };
  assert.throws(() => screenRaw("MRN 0012-3456", IDS, rulesFromDoc(doc, FIXTURE.sets)), RuleFileError);
});

test("loadRules reads the name sets from the newline files beside the rule file", () => {
  const dir = mkdtempSync(join(tmpdir(), "screen-rules-"));
  writeFileSync(join(dir, "screen_rules.json"), JSON.stringify(FIXTURE.doc));
  for (const name of ["safe_words", "personal_names", "ambiguous_names"]) writeFileSync(join(dir, `${name}.txt`), `${FIXTURE.sets[name].join("\n")}\n`);
  const loaded = loadRules(join(dir, "screen_rules.json"));
  assert.equal(loaded.version, FIXTURE.doc.version);
  assert.ok(loaded.personalNames.has("maria") && loaded.ambiguousNames.has("grant") && loaded.safeWords.has("table"));
  assert.ok(screenRaw("Maria Gonzalez is in the seed", IDS, loaded).hits.some((h) => h.rule === "name_pair"));
});

test("a long run of one shape is scanned once: no 16,000-character note takes over a second", () => {
  // the evaluator's screen starts _TYPE_SIZE and the dotted-id scan only at a run's start; without that left bound
  // a run of letters with no ( or . is scanned again from each start, about 2 to 4 s here at 16,000 characters.
  const slow = [];
  for (const unit of ["a", "Ab", "deadbeef", "a_", "a1", "a.b", "a/b", "A(", "a "]) {
    const text = unit.repeat(Math.ceil(16000 / unit.length)).slice(0, 16000);
    const t = performance.now();
    screenRaw(text, IDS, rules);
    const ms = performance.now() - t;
    if (ms > 1000) slow.push(`${JSON.stringify(unit)} ${Math.round(ms)} ms`);
  }
  assert.deepEqual(slow, []);
});

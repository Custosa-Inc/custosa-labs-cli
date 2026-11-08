/* The shared free-text probe table: lib/inspector/contracts/free_text_probes.json, a copy of
 * the evaluator's app/contracts/free_text_probes.json that scripts/sync-rules.mjs takes with the contracts. Core
 * runs it through app.validation (tests/core/test_free_text_probes.py); this runs it through the CLI's screens, so the
 * two sides answer the same text the same way, or the table names the gap. It is not part of the ruleset_id. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { holdsFreeTextValue, holdsProseValue } from "../lib/inspector/ids.mjs";
import { roleRefShape } from "../lib/inspector/valueshape.mjs";
import { PROBE_TABLES } from "../scripts/sync-rules.mjs";
import { coreSkip, requireCore } from "./core-checkout.mjs";

const COPY = new URL("../lib/inspector/contracts/free_text_probes.json", import.meta.url);
const TABLE = JSON.parse(readFileSync(COPY, "utf8"));
// Core's file, found through CUSTOSA_CORE_CONTRACTS (its app/contracts folder) or next to this checkout.
const CORE_DIR = process.env.CUSTOSA_CORE_CONTRACTS ?? "";
const CORE = `${CORE_DIR.replace(/\/?$/, "/")}free_text_probes.json`;

// Each field as core reads it (the table's about): decider_ref by free_text_spans or role_ref_shape, reason and concern
// by free_text_spans, root by prose_value_spans.
const SCREENS = {
  decider_ref: (t) => holdsFreeTextValue(t) || roleRefShape(t),
  reason: holdsFreeTextValue,
  concern: holdsFreeTextValue,
  root: holdsProseValue,
};
const answer = (refused) => (refused ? "refuse" : "send");

test("the probe table copy rides with the contracts and has the shape core's test reads", () => {
  assert.deepEqual(PROBE_TABLES, ["contracts/free_text_probes.json"]);
  assert.deepEqual(Object.keys(TABLE), ["about", "refuse", "send", "roots_refuse", "sequences", "known_gaps"]);
  for (const k of ["refuse", "send", "roots_refuse"]) assert.ok(TABLE[k].length && TABLE[k].every((t) => typeof t === "string"), k);
  for (const seq of TABLE.sequences) {
    assert.ok(seq.length > 1);
    for (const s of seq) assert.ok(s.field in SCREENS && ["refuse", "send"].includes(s.expect), JSON.stringify(s));
  }
  for (const g of TABLE.known_gaps) assert.ok(["refuse", "send"].includes(g.want) && ["both", "cli", "core"].includes(g.gap_in), JSON.stringify(g));
});

test("the copy is byte-equal to core's table", { skip: coreSkip(existsSync(CORE), "no core checkout next to this one (set CUSTOSA_CORE_CONTRACTS)") }, () => {
  requireCore("CUSTOSA_CORE_CONTRACTS", existsSync(CORE));
  assert.ok(readFileSync(COPY).equals(readFileSync(CORE)), `${fileURLToPath(COPY)} differs from ${CORE}: run scripts/sync-rules.mjs`);
});

test("every refuse entry is refused in free text", () => {
  const sent = TABLE.refuse.filter((t) => !holdsFreeTextValue(t));
  assert.deepEqual(sent, []);
});

test("every send entry is sent in free text", () => {
  const refused = TABLE.send.filter((t) => holdsFreeTextValue(t));
  assert.deepEqual(refused, []);
});

test("every roots_refuse entry is refused as a searched root", () => {
  const sent = TABLE.roots_refuse.filter((t) => !holdsProseValue(t));
  assert.deepEqual(sent, []);
});

test("each sequence gives its answers in order, in one process", () => {
  for (const seq of TABLE.sequences) {
    assert.deepEqual(seq.map((s) => answer(SCREENS[s.field](s.text))), seq.map((s) => s.expect), JSON.stringify(seq));
  }
});

test("each known gap still gets the CLI's current answer, so a fix has to move the entry", () => {
  for (const g of TABLE.known_gaps) {
    const now = answer(holdsFreeTextValue(g.text));
    const cliWrong = g.gap_in === "both" || g.gap_in === "cli";
    assert.equal(now === g.want, !cliWrong, `${JSON.stringify(g.text)} (gap_in ${g.gap_in}) gives ${now}`);
  }
});

test("parity pins beyond the table: accented and decomposed names beside a condition, as core's _ANY_PERSON_NAME", () => {
  for (const t of ["Siobhán Kelly has asthma", "José García has diabetes", "Zoë Kim, HIV positive", "Dr. José Garcia saw them"]) {
    assert.equal(holdsFreeTextValue(t), true, t);
  }
  // A name with no condition beside it, and an accented name beside a date (date_with_name stays ASCII on both sides,
  // a known gap), are sent.
  for (const t of ["José García reviewed the policy", "José García 1984-03-12"]) assert.equal(holdsFreeTextValue(t), false, t);
  assert.equal(holdsFreeTextValue("Jose Garcia 1984-03-12"), true);
});

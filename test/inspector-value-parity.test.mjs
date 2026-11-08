/* The inspector and the evaluator agree on every case of the shared
 * fixture: what is sent as written, what the inspector hashes, and what the evaluator's screen refuses. A name and a
 * date joined by _ or - is a record value when neither word is common and the pair stands alone in its path segment; a
 * migration name is not.
 * The fixture is a pinned copy of the evaluator's tests/data/valueshape_parity.json at 22db4740
 * (fixtures/contracts/valueshape_parity.22db4740.json). The common words are rules/value_screen_words.json, which core's
 * manifest lists, so scripts/sync-rules.mjs copies it with the rule set and rules-sync.test.mjs checks its
 * hash. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { recordValueSpans, screenValue } from "../lib/inspector/valueshape.mjs";
import { sentPath } from "../lib/inspector/ids.mjs";
import { computeTableName } from "../lib/inspector/captures.mjs";

const FIXTURE = JSON.parse(readFileSync(new URL("./fixtures/contracts/valueshape_parity.22db4740.json", import.meta.url), "utf8"));
const WORDS = JSON.parse(readFileSync(new URL("../rules/value_screen_words.json", import.meta.url), "utf8"));
const MANIFEST = JSON.parse(readFileSync(new URL("../rules/manifest.json", import.meta.url), "utf8"));
const KEY = Buffer.alloc(32, 11);
// Table names the evaluator passes but the CLI hashes anyway: not a plain Postgres identifier (captures.mjs PG_NAME,
// a leading digit), so they are hashed whatever the screen says. Stricter than core, so safe.
const CLI_HASHES_NAME = new Set(["2024-01-05_users_table", "20240105_add_users"]);
const HASH = /u_[0-9a-f]{16}/;

test("the shared fixture is well formed: synthetic cases of the two kinds", () => {
  const inputs = FIXTURE.cases.map((c) => c.input);
  assert.ok(inputs.length >= 45);
  assert.equal(new Set(inputs).size, inputs.length, "no duplicate cases");
  for (const c of FIXTURE.cases) {
    assert.ok(["path_segment", "name"].includes(c.kind), c.input);
    assert.ok(typeof c.expect === "string" && c.why, c.input);
  }
});

test("the common-word lists are data: lowercase words, the two lists apart", () => {
  assert.ok(MANIFEST.files.some((f) => f.path === "value_screen_words.json"), "the manifest lists the word file");
  for (const w of [...WORDS.common, ...WORDS.file_words]) assert.match(w, /^[a-z_]+$/);
  assert.deepEqual(WORDS.common.filter((w) => WORDS.file_words.includes(w)), []);
  for (const w of ["add", "create", "drop", "alter", "update", "users", "patients", "table", "migration", "init", "backup"]) {
    assert.ok(WORDS.common.includes(w) || WORDS.file_words.includes(w), w);
  }
});

for (const c of FIXTURE.cases) {
  test(`${c.kind} ${JSON.stringify(c.input)} -> ${c.expect}`, () => {
    const sent = c.kind === "path_segment" ? sentPath(KEY, c.input) : computeTableName(KEY, c.input);
    const labels = recordValueSpans(c.input).map((s) => s.label);
    if (c.expect === "kept" && CLI_HASHES_NAME.has(c.input)) {
      assert.equal(c.kind, "name");
      assert.match(sent, HASH, "hashed as a name that is not a plain identifier");
      assert.deepEqual(labels, [], "the evaluator passes it");
      return;
    }
    if (c.expect === "kept") {
      assert.equal(sent, c.input, "sent as written");
      assert.deepEqual(labels, [], "the evaluator passes it");
      return;
    }
    assert.notEqual(sent, c.input, "hashed");
    assert.match(sent, HASH);
    assert.equal(screenValue(sent), false, "what is sent passes the screen");
    if (c.expect !== "hashed") assert.ok(labels.includes(c.expect), `the evaluator refuses it as ${c.expect}: ${labels}`);
  });
}

test("a joined hit spans the date and the pair, as core's does", () => {
  const s = "patients/john_smith_1985-03-02.json";
  const spans = new Set(recordValueSpans(s).filter((x) => x.label === "date_with_name").map((x) => `${x.start}:${x.end}`));
  assert.ok(spans.has(`${s.indexOf("john")}:${s.indexOf("smith") + "smith".length}`));
  assert.ok(spans.has(`${s.indexOf("1985")}:${s.indexOf(".json")}`));
});

test("a joined pair is a hit only alone in its path segment, and only with neither word common", () => {
  const hit = (s) => recordValueSpans(s).some((x) => x.label === "date_with_name");
  assert.ok(hit("x/john_smith_1985-03-02_extra/y"));
  assert.ok(hit("scans/1980-02-03_jane_doe.pdf"));
  assert.ok(!hit("foo-john_smith_1985-03-02"), "a word before the pair: not alone in its segment");
  assert.ok(!hit("visits/smith_create_1985-03-02.json"), "one word common");
  assert.ok(!hit("patients/patient_jane_1980-02-03.json"), "one word common");
  assert.ok(!hit("2024-01-05_add_users_table.sql"));
});

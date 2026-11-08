/* The note screen's rule file and its three name lists are checked against the sha256 the
 * shipped manifest (rules/manifest.json, contracts) gives each, before first use. A damaged list (empty, cut short, or
 * one byte changed) stops the tool as a missing file does, instead of loading a weaker screen that lets names pass.
 * Temp copies of the shipped files only. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { cpSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { loadPinnedNoteRules, NOTE_RULES_FILE, SHIPPED_MANIFEST } from "../lib/inspector/tool.mjs";
import { screenRaw } from "../lib/screen.mjs";

const CONTRACTS_ROOT = fileURLToPath(new URL("../lib/inspector/", import.meta.url));

// A copy of the shipped manifest and contracts in a temp folder: {manifest, root}, root holding contracts/.
function shippedCopy() {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "t27-note-pins-")));
  cpSync(join(CONTRACTS_ROOT, "contracts"), join(dir, "contracts"), { recursive: true });
  cpSync(fileURLToPath(SHIPPED_MANIFEST), join(dir, "manifest.json"));
  return { dir, manifest: join(dir, "manifest.json"), root: dir };
}
const manifestOf = (copy) => JSON.parse(readFileSync(copy.manifest, "utf8"));

test("the shipped rule file and lists match the manifest, load, and refuse a full name", () => {
  assert.equal(fileURLToPath(NOTE_RULES_FILE), join(CONTRACTS_ROOT, "contracts", "screen_rules.json"));
  const rules = loadPinnedNoteRules();
  assert.equal(screenRaw("Windy Okafor was admitted", [], rules).decision, "refuse");
  assert.equal(screenRaw("rename foo to baz in settle.py", [], rules).decision, "pass");
  const copy = shippedCopy();
  try {
    assert.equal(screenRaw("Windy Okafor was admitted", [], loadPinnedNoteRules(copy)).decision, "refuse");
  } finally { rmSync(copy.dir, { recursive: true, force: true }); }
});

for (const [what, why, damage] of [
  ["an empty personal_names.txt", /contracts\/personal_names\.txt has changed/, (c) => writeFileSync(join(c.root, "contracts/personal_names.txt"), "")],
  ["a cut-short personal_names.txt", /contracts\/personal_names\.txt has changed/, (c) => {
    const p = join(c.root, "contracts/personal_names.txt");
    writeFileSync(p, readFileSync(p, "utf8").split("\n").slice(0, 100).join("\n") + "\n");
  }],
  ["a one-byte change to screen_rules.json", /contracts\/screen_rules\.json has changed/, (c) => {
    const p = join(c.root, "contracts/screen_rules.json");
    const b = readFileSync(p);
    const i = b.indexOf(0x20); // a space: the JSON still parses, the bytes differ
    b[i] = 0x0a;
    JSON.parse(b.toString("utf8"));
    writeFileSync(p, b);
  }],
  ["an empty safe_words.txt", /contracts\/safe_words\.txt has changed/, (c) => writeFileSync(join(c.root, "contracts/safe_words.txt"), "")],
  ["a changed ambiguous_names.txt", /contracts\/ambiguous_names\.txt has changed/, (c) => writeFileSync(join(c.root, "contracts/ambiguous_names.txt"), "june\n")],
  ["a changed schema beside them", /contracts\/state\.schema\.json has changed/, (c) => writeFileSync(join(c.root, "contracts/state.schema.json"), "{}\n")],
  ["a missing personal_names.txt", /contracts\/personal_names\.txt is missing/, (c) => rmSync(join(c.root, "contracts/personal_names.txt"))],
  ["a manifest with no entry for personal_names.txt", /contracts\/personal_names\.txt is not listed/, (c) => {
    const m = manifestOf(c);
    m.contracts = m.contracts.filter((e) => e.path !== "contracts/personal_names.txt");
    writeFileSync(c.manifest, JSON.stringify(m));
  }],
  ["a manifest with no contracts", /the manifest lists no contracts/, (c) => {
    const m = manifestOf(c);
    delete m.contracts;
    writeFileSync(c.manifest, JSON.stringify(m));
  }],
  ["a contracts entry that leaves the contracts folder", /a contracts entry is malformed/, (c) => {
    const m = manifestOf(c);
    m.contracts.push({ path: "contracts/../manifest.json", sha256: "0".repeat(64) });
    writeFileSync(c.manifest, JSON.stringify(m));
  }],
  ["no manifest", /no readable manifest/, (c) => rmSync(c.manifest)],
  ["a manifest that is not JSON", /no readable manifest/, (c) => writeFileSync(c.manifest, "{\"contracts\": [")],
]) {
  test(`${what} stops the note rules from loading`, () => {
    const copy = shippedCopy();
    try {
      damage(copy);
      assert.throws(() => loadPinnedNoteRules(copy), (e) => /^The note screen's rule files don't match the package's manifest \(/.test(e.message) && why.test(e.message));
    } finally { rmSync(copy.dir, { recursive: true, force: true }); }
  });
}

test("a damaged list's error names the file and the manifest, never a word from it", () => {
  const copy = shippedCopy();
  try {
    writeFileSync(join(copy.root, "contracts/personal_names.txt"), "okafor\n");
    assert.throws(() => loadPinnedNoteRules(copy), (e) => /personal_names\.txt/.test(e.message) && /manifest/.test(e.message) && !/okafor/i.test(e.message));
  } finally { rmSync(copy.dir, { recursive: true, force: true }); }
});

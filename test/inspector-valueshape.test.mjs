/* the evaluator refuses, uncharged, a fact document with any string its value screen reads as a record value
 * or a secret. The inspector's port of that screen (valueshape.mjs) must agree with the evaluator's own verdicts
 * (fixtures/value-screen-parity.json, computed with the evaluator's code), and a document built from a repository with
 * such file names must pass it: risky path segments hashed, folders and extensions readable, the same text every run. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { documentValueProblem, recordValueSpans, screenValue } from "../lib/inspector/valueshape.mjs";
import { buildLocalDocuments, checkDocument, CORPUS_BUDGET, screenDocument } from "../lib/inspector/factdoc.mjs";
import { hashed, sentPath, sentIdentifier } from "../lib/inspector/ids.mjs";
import { loadRules } from "../lib/inspector/rules.mjs";

const PARITY = JSON.parse(readFileSync(new URL("./fixtures/value-screen-parity.json", import.meta.url), "utf8"));
const temp = (prefix) => realpathSync(mkdtempSync(join(tmpdir(), prefix)));
const KEY = Buffer.alloc(32, 7);
const TIGHTENED = new Set(["x.io2024-01-02Johnsk-John/"]);

test("the port gives the evaluator's own verdict on every string of the parity fixture", () => {
  assert.ok(PARITY.cases.length > 500);
  const wrong = PARITY.cases.filter(([s, refused]) => !TIGHTENED.has(s) && (recordValueSpans(s).length > 0) !== refused);
  assert.deepEqual(wrong, []);
  // a name and a date joined by _ or - is refused now, by the evaluator's validation.py
  // as here; the fixture's verdicts predate it. Drop this once the fixture is recomputed.
  for (const s of TIGHTENED) {
    assert.equal(PARITY.cases.find(([c]) => c === s)?.[1], false, s);
    assert.deepEqual([...new Set(recordValueSpans(s).map((x) => x.label))], ["date_with_name"], s);
  }
});

test("screenValue reads a string the evaluator's way: hash shapes masked, object_id after its '@', some fields exempt", () => {
  assert.equal(screenValue("u_0123456789abcdef"), false);
  assert.equal(screenValue("a".repeat(0) + "0123456789abcdef".repeat(4)), false, "a 64-hex hash is masked");
  assert.equal(screenValue("audit-log@john.doe@example.com", "object_id"), true);
  assert.equal(screenValue("audit-log@public.patients", "object_id"), false);
  assert.equal(screenValue("12345678901234567890", "system_identifier"), false);
  assert.equal(screenValue("12345678901234567890", "name"), true);
});

test("risky path segments are hashed, keeping folders and a plain extension; the same path gives the same text", () => {
  const cases = {
    "patients/john.doe@example.com.json": /^patients\/u_[0-9a-f]{16}\.json$/,
    "exports/5552345678.csv": /^exports\/u_[0-9a-f]{16}\.csv$/,
    "123-45-6789.txt": /^u_[0-9a-f]{16}\.txt$/,
    "records/2024/078-05-1120/notes.md": /^records\/2024\/u_[0-9a-f]{16}\/notes\.md$/,
    "src/app/page.tsx": /^src\/app\/page\.tsx$/,
    "migrations/20240101120000_init.sql": /^migrations\/20240101120000_init\.sql$/,
  };
  for (const [path, want] of Object.entries(cases)) {
    const sent = sentPath(KEY, path);
    assert.match(sent, want, path);
    assert.equal(screenValue(sent), false, sent);
    assert.equal(sentPath(KEY, path), sent, "stable");
  }
  assert.match(sentIdentifier(KEY, "send_5552345678"), /^u_[0-9a-f]{16}$/);
  assert.equal(sentIdentifier(KEY, "send-email"), "send-email");
});

test("a document built from a repository with record values in its file names passes the evaluator's screen", async () => {
  const root = temp("custosa-p1212-");
  mkdirSync(join(root, ".git"));
  const files = {
    "patients/john.doe@example.com.json": "{}\n",
    "exports/5552345678.csv": "a,b\n",
    "123-45-6789.txt": "x\n",
    "records/Jane Doe 1980-02-03.pdf": "x\n",
    "notes/sk\x5flive_ABCDEFGHIJKLMNOP1234.md": "x\n",
    "src/handlers/5552345678.ts": 'export async function save(p) { await db.from("patients").insert(p); }\n',
    "src/db.ts": 'export async function load(id) { return db.from("patients").select("*").eq("id", id); }\n',
  };
  for (const [p, t] of Object.entries(files)) { mkdirSync(join(root, p, ".."), { recursive: true }); writeFileSync(join(root, p), t); }
  const options = {
    ruleset: { id: "2026-10-20.0123abcd", rules: loadRules(fileURLToPath(new URL("./fixtures/rules/", import.meta.url))), queries: [] },
    configDir: join(temp("custosa-p1212-cfg-"), "custosa"), handlerMap: true,
    // The corpus budget (120 s a file): the two runs are compared whole, so neither may hit a time limit when the
    // machine is busy (under the full suite one run listed a handler file time_limit).
    ...CORPUS_BUDGET,
  };
  const first = await buildLocalDocuments([root], options);
  const again = await buildLocalDocuments([root], options);
  for (const run of [first, again]) {
    assert.deepEqual(run.documents[0].document.files.not_analyzed.filter((e) => e.reason === "time_limit"), [], "no file timed out");
  }
  const [own] = first.documents;
  assert.equal(own.problem, null, JSON.stringify(own.problem));
  assert.equal(documentValueProblem(own.document), null);
  const text = JSON.stringify(own.document);
  for (const raw of ["john.doe@example.com", "5552345678", "123-45-6789", "1980-02-03", "sk\x5flive_ABCDEFGHIJKLMNOP1234"]) assert.ok(!text.includes(raw), raw);
  assert.deepEqual(again.documents[0].document.files, own.document.files, "the same paths every run");
  assert.deepEqual(again.documents[0].document.matches, own.document.matches, "handler identity and paths stable");
  // the handler map (local only) still resolves every handler the document names
  for (const m of own.document.matches.filter((x) => x.handler)) assert.ok(own.handlers[m.handler], m.handler);
  const paths = text.match(/"(?:path|file)":"[^"]*"/g) ?? [];
  assert.ok(paths.some((p) => /patients\/u_[0-9a-f]{16}\.json"/.test(p)), paths.join(" "));
  assert.ok(paths.some((p) => /exports\/u_[0-9a-f]{16}\.csv"/.test(p)), paths.join(" "));
});

test("the last pass hashes a string that still trips the screen, and checkDocument refuses one it can't fix", async () => {
  const doc = { files: { data_files: [{ path: "a/john.doe@example.com" }] }, answers: [{ object_id: "audit-log@jane@example.org" }], name: "5552345678" };
  screenDocument(doc, KEY);
  assert.equal(documentValueProblem(doc), null, JSON.stringify(doc));
  assert.match(doc.answers[0].object_id, /^audit-log@u_[0-9a-f]{16}$/);
  assert.match(doc.files.data_files[0].path, /^a\/u_[0-9a-f]{16}\.com$/);
  // a document that slipped one through is refused locally (value_shape), never sent
  const root = temp("custosa-p1212b-");
  mkdirSync(join(root, ".git"));
  writeFileSync(join(root, "a.ts"), "export {};\n");
  const built = await buildLocalDocuments([root], { ruleset: { id: "2026-10-20.0123abcd", rules: [], queries: [] }, configDir: join(temp("c-"), "custosa") });
  const bad = structuredClone(built.documents[0].document);
  bad.files.not_analyzed.push({ path: "x/jane@example.org", kind: "file", reason: "unreadable", tracked: null });
  assert.deepEqual(checkDocument(bad), { at: `/files/not_analyzed/${bad.files.not_analyzed.length - 1}/path`, keyword: "value_shape" });
});

test("L-a: a captured schema.table name is screened part by part, so it matches the catalog's names", async () => {
  const { computeTableName } = await import("../lib/inspector/captures.mjs");
  assert.equal(computeTableName(KEY, "public.events_123456789012"), `public.${hashed(KEY, "events_123456789012")}`);
  assert.equal(computeTableName(KEY, "public.patients"), "public.patients");
  assert.match(computeTableName(KEY, "555.234.5678"), /^u_[0-9a-f]{16}$/, "a shape across the parts hashes the whole name");
  assert.equal(screenValue(computeTableName(KEY, "public.events_123456789012")), false);
});

test("path fields are also read without their last extension, as the evaluator's _path_refused reads them", () => {
  // api.py check_values reads path, location and object_id with _path_refused, which also screens the text with its
  // last extension (and a :line suffix) cut off: 4155550123.csv passes as written (a dot follows the digits), its
  // stem doesn't. A miss here would send a document the evaluator refuses.
  for (const [field, value] of [["path", "data/4155550123.csv"], ["location", "a/4155550123.csv:12"],
    ["location", "exports/123456789.json:3-4"], ["object_id", "audit-log@exports/4155550123.json"]]) {
    assert.equal(screenValue(value, field), true, `${field} ${value}`);
    const doc = { files: { not_analyzed: [{ [field]: value }] } };
    assert.equal(documentValueProblem(doc)?.at, `/files/not_analyzed/0/${field}`);
    screenDocument(doc, KEY);
    assert.equal(documentValueProblem(doc), null, JSON.stringify(doc));
  }
  // Other fields read the text as written, as check_values does: no stem read there.
  assert.equal(screenValue("4155550123.csv", "name"), false);
  assert.equal(documentValueProblem({ name: "4155550123.csv" }), null);
  // A plain path is untouched.
  assert.equal(screenValue("src/handlers/save.ts:12", "location"), false);
});

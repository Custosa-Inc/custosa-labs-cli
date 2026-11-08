/* T28 t28-fullhp-refusals (T28-P1-C3), the CLI half: the refusal shapes from the fullhp benchmark's arm B, names only.
 *
 * Arm B sent its verdicts and concerns five times before one went through:
 *   calls 27 and 28: note_refused (unknown_backtick_ref). The agent had done what our own text said, "put table,
 *     column, setting and file names in backticks", and backticked names the check never sent.
 *   call 30: the tool's input schema refused a bare file path as a ref, though a path the check read is a snapshot id.
 *   calls 29 and 31: the evaluator refused file:line refs at lines the check never cites (ref_unknown), with no word on
 *     which part was wrong. The agent then dropped every ref, and ten answers with them.
 * The fix: the text says only names this check sent go in backticks and in refs; a bare path is a ref shape; and the
 * tool checks file refs against the fact document's snapshot ids before anything is sent, naming each refused ref's
 * field and whether to drop its line or the ref. Stub evaluator and temp folders only; made-up names. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import AjvModule from "ajv";
import { DESCRIPTION, INPUT_SCHEMA, NOTE_REFUSED, REFS_REFUSED, makeRunCheck } from "../lib/inspector/tool.mjs";
import { refsRefused } from "../lib/inspector/notes.mjs";
import { snapshotIds } from "../lib/inspector/snapshot.mjs";
import { writeToken } from "../lib/inspector/auth.mjs";
import { loadRules } from "../lib/inspector/rules.mjs";
import { rulesFromDoc } from "../lib/screen.mjs";
import { EVALUATE_OK, stub } from "./stub-evaluator.mjs";

const Ajv = AjvModule.default ?? AjvModule;
const validateArgs = new Ajv({ strict: true }).compile(INPUT_SCHEMA);
const FIXTURE = JSON.parse(readFileSync(new URL("./fixtures/screen-parity.5e907cf8.json", import.meta.url), "utf8"));
const NOTE_RULES = rulesFromDoc(FIXTURE.doc, FIXTURE.sets);
const RULESET = { id: "2026-10-20.0123abcd", rules: loadRules(fileURLToPath(new URL("./fixtures/rules/", import.meta.url))), queries: [] };
const TOKEN = `phisc_${"t".repeat(43)}`;
const SESSION = EVALUATE_OK.session;
const temp = (prefix) => realpathSync(mkdtempSync(join(tmpdir(), prefix)));
const quiet = {
  ruleset: RULESET,
  collectCatalog: async () => ({ status: "not_run", count: 0, reason: "service_missing", preflight: null, queries: [] }),
  collectPlatform: async () => ({ provider: null, status: "not_run", reason: "no_token", settings: {} }),
};
const verdict = (refs) => ({ practice_id: "session-timeouts", state: "fail", reason_code: "control_missing", refs });
const concern = (refs) => ({ category: "access", area: "auth", file_kind: "route_handler", proposed_severity: "medium", refs,
  note: "The handler has no session check." });

function repo() {
  const root = temp("t28-");
  mkdirSync(join(root, "src/lib"), { recursive: true });
  writeFileSync(join(root, "src/lib/db.ts"), 'export async function save(p) { await db.from("patients").insert(p); }\n');
  return root;
}
async function setup() {
  const configDir = join(temp("t28-cfg-"), "custosa");
  const s = await stub(() => ({ status: 200, json: EVALUATE_OK }));
  writeToken(TOKEN, { configDir, host: new URL(s.url).origin });
  const runCheck = makeRunCheck({ configDir, localOnly: false, buildOptions: quiet, noteRules: NOTE_RULES, learningFor: () => true,
    evaluatorUrl: () => ({ url: s.url, origin: new URL(s.url).origin }), clientOptions: { sleep: async () => {} } });
  return { s, runCheck };
}

/* ---- the input schema: a bare path is a ref (call 30) */

for (const ref of ["src/lib/session.ts", "src/app/api/items/[id]/route.ts", "src/app/(group)/page.tsx"]) {
  test(`a bare path is a ref shape in the tool's input schema: ${ref}`, () => {
    assert.ok(validateArgs({ goal: "check", session: SESSION, verdicts: [verdict([ref])] }), JSON.stringify(validateArgs.errors));
    assert.ok(validateArgs({ goal: "check", session: SESSION, concerns: [concern([ref])] }), JSON.stringify(validateArgs.errors));
  });
}

test("a path shape still refuses what a path never is", () => {
  for (const ref of ["/etc/passwd", "src//x.ts", "src/x/", "../x.ts", "src/./x.ts", "a b.ts"]) {
    assert.equal(validateArgs({ goal: "check", session: SESSION, verdicts: [verdict([ref])] }), false, ref);
  }
});

/* ---- the text (calls 27 and 28) */

test("the note rule and the note refusal say only names this check sent go in backticks", () => {
  for (const text of [NOTE_REFUSED, INPUT_SCHEMA.properties.verdicts.description, INPUT_SCHEMA.properties.concerns.description]) {
    assert.ok(!/put table, column, setting and file names in backticks/i.test(text), text);
    assert.match(text, /only names this check sent/i);
    assert.match(text, /plain words/i);
  }
  assert.match(NOTE_REFUSED, /unknown_backtick_ref is a backticked name this check never sent/);
});

test("the refs text says which refs count, that a line counts only where the check cites it, and that refs are optional", () => {
  for (const text of [INPUT_SCHEMA.properties.verdicts.description, INPUT_SCHEMA.properties.concerns.description]) {
    assert.match(text, /a line only where the check cites it/i);
    assert.match(text, /never a file or line you found yourself/i);
  }
  assert.ok(DESCRIPTION.length > 0);
});

/* ---- the local ref check (calls 29 and 31) */

test("refsRefused names each file ref the document never names, and says whether only its line is the problem", () => {
  const doc = { files: { imports: [{ fingerprint: "ai_sdk", package: "openai", path: "src/lib/model.ts", line: 3 }] } };
  assert.ok(snapshotIds(doc).has("src/lib/model.ts:3"));
  const args = { verdicts: [verdict(["src/lib/model.ts", "src/lib/model.ts:3", "public.sessions", "session-timeouts"]),
    verdict(["src/lib/model.ts:33"])], concerns: [concern(["src/lib/other.ts:4", "session-timeouts@public.sessions", "other.ts"])] };
  assert.deepEqual(refsRefused(args, [doc]), [
    { field: "verdicts[1].refs[0]", why: "line_uncited" },
    { field: "concerns[0].refs[0]", why: "not_read" },
  ]);
});

test("a file ref the check never read, or at a line it never cites, is refused locally: nothing is sent", async () => {
  const root = repo();
  const { s, runCheck } = await setup();
  try {
    await runCheck({ goal: "check" }, { roots: [root] });
    const ids = snapshotIds(s.calls[0].body.fact_document);
    assert.ok(ids.has("src/lib/db.ts") && !ids.has("src/lib/db.ts:33"));
    const out = await runCheck({ goal: "check", session: SESSION, verdicts: [verdict(["src/lib/db.ts:33"])],
      concerns: [concern(["src/lib/nope.ts:4"])] }, { roots: [root] });
    assert.equal(s.calls.length, 1);
    assert.equal(out.error, "refs_refused");
    assert.ok(out.next_step.startsWith(REFS_REFUSED.split("{")[0]));
    assert.match(out.next_step, /verdicts\[0\]\.refs\[0\] \(line_uncited\)/);
    assert.match(out.next_step, /concerns\[0\]\.refs\[0\] \(not_read\)/);
    assert.ok(!out.next_step.includes("db.ts:33") && !out.next_step.includes("nope.ts"));
    assert.match(out.next_step, /without the line/);
    assert.match(out.next_step, /refs are optional/i);
  } finally { await s.close(); }
});

test("a bare path the check read goes out as written", async () => {
  const root = repo();
  const { s, runCheck } = await setup();
  try {
    await runCheck({ goal: "check", session: SESSION, verdicts: [verdict(["src/lib/db.ts"])] }, { roots: [root] });
    assert.equal(s.calls.length, 1);
    assert.deepEqual(s.calls[0].body.verdicts[0].refs, ["src/lib/db.ts"]);
  } finally { await s.close(); }
});

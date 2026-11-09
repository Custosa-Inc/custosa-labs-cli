/* T29-P1-C60 (C48 condition 1): the break-glass cited code rests on the inspector's span check. A location answer's
 * spans (its location and every `at` span) are sent only when each lies in a file the walk listed and inside that
 * file's lines, with n <= m; else the answer goes with location null and no spans, so core keeps its fail. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { buildFactDocuments } from "../lib/inspector/factdoc.mjs";

const CODE = "emergency_path_cited";

function repo(files) {
  const root = mkdtempSync(join(tmpdir(), "custosa-cited-"));
  for (const [p, text] of Object.entries(files)) {
    mkdirSync(dirname(join(root, p)), { recursive: true });
    writeFileSync(join(root, p), text);
  }
  return root;
}

const ROOT_FILES = { "supabase/migrations/0001_break_glass.sql": "create role break_glass;\ngrant select on patients to break_glass;\ncomment on role break_glass is 'emergency';\n" };
const SQL = "supabase/migrations/0001_break_glass.sql";

async function answersFor(answers) {
  const root = repo(ROOT_FILES);
  const runRules = async () => ({ matches: [], links: [], notAnalyzed: [], analyzed: 1, analyzedPaths: [SQL],
    languages: ["sql"], status: "ok", count: 0 });
  const out = await buildFactDocuments([root], { configDir: mkdtempSync(join(tmpdir(), "t29-cited-cfg-")), runRules,
    answers, ruleset: { id: "2026-10-20.0123abcd", rules: [], queries: [] },
    collectCatalog: async () => ({ status: "not_run", count: 0, reason: "service_missing", preflight: null, queries: [] }),
    collectPlatform: async () => ({ provider: null, status: "not_run", reason: "no_token", settings: {} }) });
  return out.documents[0].document.answers;
}

const ask = (location, at) => ({ object_id: "break-glass-access", question_id: "location", answer: "here", location, code: CODE, ...(at ? { at } : {}) });

test("a cited answer whose spans all lie in walked files and inside their lines is sent with its code and spans", async () => {
  const [a] = await answersFor([ask(`${SQL}:1-2`, [`${SQL}:3`])]);
  assert.equal(a.location, `${SQL}:1-2`);
  assert.equal(a.code, CODE);
  assert.deepEqual(a.at, [`${SQL}:3`]);
});

for (const [name, location, at] of [
  ["a location outside the walked files", "ops/runbook.sql:1", undefined],
  ["an at span outside the walked files", `${SQL}:1`, ["ops/runbook.sql:1"]],
  ["a location past the file's last line", `${SQL}:40`, undefined],
  ["an at span past the file's last line", `${SQL}:1`, [`${SQL}:2-40`]],
  ["a reversed location", `${SQL}:3-2`, undefined],
  ["a reversed at span", `${SQL}:1`, [`${SQL}:3-2`]],
]) {
  test(`${name} sends no location and no spans`, async () => {
    const [a] = await answersFor([ask(location, at)]);
    assert.equal(a.location, null, name);
    assert.equal(a.at, undefined, name);
  });
}

// T29-P1-C7 (harmony brief ranks 2 and 8, the owner's yes of 2026-11-08). Under the HIPAA configuration every word of
// the server instructions and the tool descriptions loads on every turn, and tool choice rides on the description.
// So they are short, say first what the check gives that grep and psql don't, and carry no person-gated imperative:
// consent to change code belongs to the person and the harness, not to text from a tool. In the fullhp rerun "make no
// fixes yet" and "never apply part of it" were ignored every time, and goal fix was never reached.
import { test } from "node:test";
import assert from "node:assert/strict";
import { INSTRUCTIONS, DESCRIPTION, GUIDANCE_DESCRIPTION, PAGE_DESCRIPTION, INPUT_SCHEMA } from "../lib/inspector/tool.mjs";

// Well under the 4,096 characters the brief names, with room for page 1's lines (T29 item 2) beside them.
const BUDGET = 3600;
const GATED = /make no fixes|ask the person|ask before|do you want me to|only after the person|after the person (says|asks)|the person says yes|never apply part|each whole|not your own summary|fixes only after/i;
const flat = (text) => text.replace(/\s+/g, " ");
const firstSentence = (text) => flat(text).split(/(?<=\.) /)[0];

test("the server instructions and the three descriptions fit the budget together", () => {
  const total = INSTRUCTIONS.length + DESCRIPTION.length + GUIDANCE_DESCRIPTION.length + PAGE_DESCRIPTION.length;
  assert.ok(total <= BUDGET, `${total} characters, over ${BUDGET}`);
});

test("no person-gated imperative in the instructions or a description", () => {
  for (const text of [INSTRUCTIONS, DESCRIPTION, GUIDANCE_DESCRIPTION, PAGE_DESCRIPTION]) {
    assert.doesNotMatch(flat(text), GATED);
  }
});

test("the check's description and the instructions open with what grep and psql don't give", () => {
  for (const text of [DESCRIPTION, INSTRUCTIONS.split("\n").slice(1).join("\n")]) {
    const first = firstSentence(text);
    assert.match(first, /grep/, first);
    assert.match(first, /psql/, first);
  }
});

test("a fix is information the assistant may apply in whole or in part", () => {
  assert.match(flat(INSTRUCTIONS), /in whole or in part/);
  // the safety line stays: fixes go to a development database
  assert.match(flat(INSTRUCTIONS), /development database/);
});

test("goal fix takes a finding of the assistant's own, by practice and file location", () => {
  const ids = INPUT_SCHEMA.properties.finding_ids;
  assert.match(ids.description, /practice_id@path:line/);
  assert.match("authz-every-handler@app/api/notes/[id]/route.ts:12", new RegExp(ids.items.pattern));
});

// T29-P3-C17 low 2: an own finding names a file this check walked, or it is refused here, uncharged, and nothing is sent.
// A check finding's own id (its path as the check sent it) still passes; a range runs forward.
test("goal fix: an own finding on a file the check did not walk is refused before anything is sent", async () => {
  const { mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { fileURLToPath } = await import("node:url");
  const { makeRunCheck, TOOL_ERRORS } = await import("../lib/inspector/tool.mjs");
  const { writeToken } = await import("../lib/inspector/auth.mjs");
  const { loadRules } = await import("../lib/inspector/rules.mjs");
  const { hashed } = await import("../lib/inspector/ids.mjs");
  const { buildFactDocuments } = await import("../lib/inspector/factdoc.mjs");
  const { EVALUATE_OK, stub } = await import("./stub-evaluator.mjs");
  const temp = (prefix) => realpathSync(mkdtempSync(join(tmpdir(), prefix)));
  const root = temp("t29-own-");
  for (const [p, t] of Object.entries({ "src/db.ts": "export const a = 1;\nexport const b = 2;\n", "odd dir/a.ts": "x\ny\n", ".env": "A=1\n" })) {
    mkdirSync(join(root, p, ".."), { recursive: true }); writeFileSync(join(root, p), t);
  }
  const configDir = join(temp("t29-own-cfg-"), "custosa");
  const s = await stub(() => ({ status: 200, json: { ...EVALUATE_OK, goal: "fix" } }));
  writeToken(`phisc_${"t".repeat(43)}`, { configDir, host: new URL(s.url).origin });
  const ruleset = { id: "2026-10-20.0123abcd", rules: loadRules(fileURLToPath(new URL("./fixtures/rules/", import.meta.url))), queries: [] };
  const runCheck = makeRunCheck({
    configDir, localOnly: false,
    buildOptions: { ruleset,
      collectCatalog: async () => ({ status: "not_run", count: 0, reason: "service_missing", preflight: null, queries: [] }),
      collectPlatform: async () => ({ provider: null, status: "not_run", reason: "no_token", settings: {} }) },
    evaluatorUrl: () => ({ url: s.url, origin: new URL(s.url).origin }), clientOptions: { sleep: async () => {} },
    build: (roots, opts) => buildFactDocuments(roots, opts),
  });
  try {
    for (const ids of [["authz-every-handler@src/missing.ts:3"], ["rls-forced@public.patients", "authz-every-handler@src/db.ts:2-1"],
      ["authz-every-handler@~/src/db.ts:1"], ["authz-every-handler@odd dir/a.ts:1"]]) {
      const out = await runCheck({ goal: "fix", finding_ids: ids }, { roots: [root] });
      assert.equal(out.error, "finding_ids_refused", ids.join());
      assert.equal(out.local, true);
      assert.match(out.next_step, /finding_ids\[[01]\] \((not_walked|name_hashed|range_backwards)\)/);
      for (const id of ids) assert.ok(!out.next_step.includes(id.split("@")[1]), "the refusal never repeats the path");
    }
    assert.equal(s.calls.length, 0, "a refused fix sends nothing and is charged nothing");
    const key = readFileSync(join(configDir, "install.key"));
    const ok = ["rls-forced@public.patients", "authz-every-handler@src/db.ts:1-2", `authz-every-handler@${hashed(key, "odd dir")}/a.ts:2`,
      "no-committed-secrets@.env:1"];
    await runCheck({ goal: "fix", finding_ids: ok }, { roots: [root] });
    assert.equal(s.calls.length, 1);
    assert.deepEqual(s.calls[0].body.finding_ids, ok);
  } finally { await s.close(); }
});

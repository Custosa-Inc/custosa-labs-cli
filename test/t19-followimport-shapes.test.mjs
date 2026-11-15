/* T19 (P2): follow_import shapes test/t28-authz-helper.test.mjs doesn't reach (lib/inspector/followimport.mjs).
 *
 * That file covers a named function export, a const arrow with an aliased import, a package import, a missing file or
 * export, and named and star barrels. These cases cover the rest of exportedFunction, importsOf and functionExport:
 *   - the three default export forms (export default function, export default <name>, export default <arrow>), and a
 *     local export clause with an alias (function f() {}; export { f as requireX }): followed to the function;
 *   - `import type { f }` binds nothing at run time, and a name the file declares itself is no import: neither is
 *     followed, so the evidence is dropped and the item keeps has_control false, as for a package import;
 *   - a barrel cycle (a.ts re-exports b.ts, b.ts re-exports a.ts) and a chain one barrel past REEXPORT_DEPTH (4) end
 *     unresolved, so the evidence is held, and the cycle ends;
 *   - a helper file over maxBytes is not read, so the evidence is held, never a fail or a pass.
 * Made-up names only. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadRules, runRules } from "../lib/inspector/rules.mjs";
import { engineAvailable } from "../lib/inspector/parse.mjs";

const KEY = Buffer.from("0123456789abcdef0123456789abcdef");
const temp = (prefix) => realpathSync(mkdtempSync(join(tmpdir(), prefix)));
const ITEMS = "authz-every-handler.typescript-nextjs.route";
const UNOBSERVED = "authz-every-handler.typescript-nextjs.auth-unobserved-import";

const RULES = `id: ${ITEMS}
practice_id: authz-every-handler
language: typescript
frameworks:
- nextjs
kind: items
rule:
  kind: function_declaration
  all:
  - has:
      field: name
      kind: identifier
      regex: '^(GET|POST)$'
  - inside:
      kind: export_statement
control:
  has:
    stopBy: end
    pattern: auth()
min_engine: 0.39.0
---
id: ${UNOBSERVED}
practice_id: authz-every-handler
language: typescript
frameworks:
- nextjs
kind: evidence
follow_import: true
rule:
  kind: call_expression
  all:
  - has:
      field: function
      kind: identifier
  - inside:
      stopBy: end
      kind: function_declaration
      inside:
        kind: export_statement
min_engine: 0.39.0
`;

const route = (imp, call) => `${imp}
export async function GET(req) {
  const { error } = await ${call};
  if (error) return error;
  return Response.json({});
}
`;
const GUARD_BODY = `{
  const session = await auth();
  return session ? { session } : { error: new Response(null, { status: 401 }) };
}`;
const AUTH = 'import { auth } from "@/lib/auth";\n';
// five barrels in a row (d1 to d5) before the function in d6: one past REEXPORT_DEPTH, so it is out of reach; near has four
const chain = {};
for (let i = 1; i <= 5; i += 1) chain[`src/lib/deep/d${i}.ts`] = `export * from "./d${i + 1}";\n`;
chain["src/lib/deep/d6.ts"] = `${AUTH}export async function requireDeep(roles) ${GUARD_BODY}\n`;
const near = { "src/lib/near/n1.ts": 'export * from "./n2";\n', "src/lib/near/n2.ts": 'export * from "./n3";\n',
  "src/lib/near/n3.ts": 'export * from "./n4";\n', "src/lib/near/n4.ts": 'export * from "./n5";\n',
  "src/lib/near/n5.ts": `${AUTH}export async function requireNear(roles) ${GUARD_BODY}\n` };

const FILES = {
  "src/lib/auth.ts": "export async function auth() { return null; }\n",
  "src/lib/default-fn.ts": `${AUTH}export default async function requireAuth(roles) ${GUARD_BODY}\n`,
  "src/lib/default-name.ts": `${AUTH}async function requireAuth(roles) ${GUARD_BODY}\nexport default requireAuth;\n`,
  "src/lib/default-arrow.ts": `${AUTH}export default async (roles) => ${GUARD_BODY};\n`,
  "src/lib/clause.ts": `${AUTH}async function check(roles) ${GUARD_BODY}\nexport { check as requireAuth };\n`,
  "src/lib/types.ts": `${AUTH}export async function requireAuth(roles) ${GUARD_BODY}\n`,
  "src/lib/loop-a.ts": 'export * from "./loop-b";\n',
  "src/lib/loop-b.ts": 'export * from "./loop-a";\n',
  ...chain,
  ...near,
  "src/app/api/default-fn/route.ts": route('import gate from "@/lib/default-fn";', 'gate(["Admin"])'),
  "src/app/api/default-name/route.ts": route('import gate from "@/lib/default-name";', 'gate(["Admin"])'),
  "src/app/api/default-arrow/route.ts": route('import gate from "@/lib/default-arrow";', 'gate(["Admin"])'),
  "src/app/api/clause/route.ts": route('import { requireAuth } from "@/lib/clause";', 'requireAuth(["Admin"])'),
  "src/app/api/type-only/route.ts": route('import type { requireAuth } from "@/lib/types";', 'requireAuth(["Admin"])'),
  "src/app/api/type-spec/route.ts": route('import { type requireAuth } from "@/lib/types";', 'requireAuth(["Admin"])'),
  "src/app/api/declared/route.ts": `async function requireAuth(roles) { return { error: null }; }\n${route("", 'requireAuth(["Admin"])')}`,
  "src/app/api/loop/route.ts": route('import { requireAuth } from "@/lib/loop-a";', 'requireAuth(["Admin"])'),
  "src/app/api/deep/route.ts": route('import { requireDeep } from "@/lib/deep/d1";', 'requireDeep(["Admin"])'),
  "src/app/api/near/route.ts": route('import { requireNear } from "@/lib/near/n1";', 'requireNear(["Admin"])'),
};

async function run(files = FILES, opts = {}) {
  const dir = temp("t19fi-rules-");
  mkdirSync(join(dir, "authz-every-handler"));
  writeFileSync(join(dir, "authz-every-handler", "typescript-nextjs.yml"), RULES);
  const root = temp("t19fi-app-");
  const list = [];
  for (const [path, text] of Object.entries(files)) {
    mkdirSync(join(root, path, ".."), { recursive: true });
    writeFileSync(join(root, path), text);
    list.push({ path, text });
  }
  return runRules(loadRules(dir), list, { key: KEY, frameworks: ["nextjs"], root, ...opts });
}
const of = (res, path) => res.matches.filter((m) => m.path === path);
const item = (res, path) => { const items = of(res, path).filter((m) => m.rule_id === ITEMS); assert.equal(items.length, 1, path); return items[0]; };
const held = (res, path) => of(res, path).filter((m) => m.rule_id === UNOBSERVED);
const api = (name) => `src/app/api/${name}/route.ts`;

test("each default export form and a local export clause with an alias are followed to the helper's function", { skip: !engineAvailable() }, async () => {
  const res = await run();
  for (const name of ["default-fn", "default-name", "default-arrow", "clause"]) {
    assert.equal(item(res, api(name)).has_control, true, name);
    assert.deepEqual(held(res, api(name)), [], name);
  }
});

test("a type-only import and a name the file declares are not followed: the evidence is dropped, the item still lacks its control", { skip: !engineAvailable() }, async () => {
  const res = await run();
  for (const name of ["type-only", "type-spec", "declared"]) {
    assert.equal(item(res, api(name)).has_control, false, name);
    assert.deepEqual(held(res, api(name)), [], name);
  }
});

test("a barrel cycle ends unresolved and the evidence is held", { skip: !engineAvailable() }, async () => {
  const res = await run();
  assert.equal(item(res, api("loop")).has_control, false);
  assert.equal(held(res, api("loop")).length, 1);
});

test("re-exports are followed through four barrels, not five", { skip: !engineAvailable() }, async () => {
  const res = await run();
  assert.equal(item(res, api("near")).has_control, true);
  assert.deepEqual(held(res, api("near")), []);
  assert.equal(item(res, api("deep")).has_control, false);
  assert.equal(held(res, api("deep")).length, 1);
});

test("a helper file over maxBytes is not read: the evidence is held, never a fail or a pass", { skip: !engineAvailable() }, async () => {
  const big = `${FILES["src/lib/default-fn.ts"]}// ${"x".repeat(4000)}\n`;
  const files = { "src/lib/auth.ts": FILES["src/lib/auth.ts"], "src/lib/default-fn.ts": big,
    "src/app/api/default-fn/route.ts": FILES["src/app/api/default-fn/route.ts"] };
  const small = await run({ ...files, "src/lib/default-fn.ts": FILES["src/lib/default-fn.ts"] }, { maxBytes: 2000 });
  assert.equal(item(small, api("default-fn")).has_control, true);
  const res = await run(files, { maxBytes: 2000 });
  assert.equal(item(res, api("default-fn")).has_control, false);
  assert.equal(held(res, api("default-fn")).length, 1);
});

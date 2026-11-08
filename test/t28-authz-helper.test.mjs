/* T28 t28-authz-helper (T28-P1-C5, design in T28-P3-C14), the engine half: an evidence rule marked follow_import is
 * followed one import hop. On fullhp, authz-every-handler failed 25 Next.js route handlers, and 24 of them call the
 * app's own auth helper first (`const { error } = await requireAuth([...])`, imported from "@/lib/<guard>"), which
 * calls auth() itself. The rule can't see into another file, so it said fail; the agent called the fails false and
 * dropped the practice.
 *
 * For each match of a follow_import evidence rule (a call whose callee is a bare name), the engine looks the name up
 * among the file's imports. A name a local specifier binds (relative, @/ or ~/) is followed: the named export's function
 * body is run against the control of each item on the same handler.
 *   1. resolved, the body holds the control: the item gets has_control true (still needs_review in core: the record
 *      check is dataflow), and the evidence match is dropped;
 *   2. resolved, the body holds no control: the evidence is dropped and the item keeps has_control false (a fail);
 *   3. a local specifier that doesn't resolve (no such file walked, no such export): the evidence is kept, so core
 *      holds the item for a person (auth-unobserved), never a fail and never a pass.
 * A name no local import binds (a package import, a name declared in the file, a global) is not followed: its evidence
 * is dropped, as if the rule had not matched. Made-up names only. */
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
const FILES = {
  "src/lib/guard.ts": `import { auth } from "@/lib/auth";
export async function requireAuth(roles) {
  const session = await auth();
  if (!session) return { error: new Response(null, { status: 401 }) };
  return { session };
}
export const requireStaff = async (roles) => {
  const session = await auth();
  return session ? { session } : { error: new Response(null, { status: 401 }) };
};
`,
  "src/lib/noguard.ts": `export async function requireAuth(roles) {
  return { error: null };
}
`,
  "src/lib/auth.ts": `export async function auth() { return null; }\n`,
  "src/app/api/checked/route.ts": route('import { requireAuth } from "@/lib/guard";', 'requireAuth(["Admin"])'),
  "src/app/api/arrow/route.ts": route('import { requireStaff as gate } from "../../../lib/guard";', 'gate(["Admin"])'),
  "src/app/api/unchecked/route.ts": route('import { requireAuth } from "@/lib/noguard";', 'requireAuth(["Admin"])'),
  "src/app/api/missing/route.ts": route('import { requireAuth } from "@/lib/nowhere";', 'requireAuth(["Admin"])'),
  "src/app/api/noexport/route.ts": route('import { requireOther } from "@/lib/guard";', 'requireOther(["Admin"])'),
  "src/app/api/package/route.ts": route('import { requireAuth } from "some-auth-package";', 'requireAuth(["Admin"])'),
  // P2's shape (T28-P2-C13): a helper re-exported through a barrel is followed through it to its function.
  "src/lib/index.ts": 'export { requireAuth as requireUser } from "./guard";\nexport { requireAuth } from "./gone";\n',
  "src/lib/all.ts": 'export * from "./guard";\n',
  "src/app/api/barrel/route.ts": route('import { requireUser } from "@/lib";', 'requireUser(["Admin"])'),
  "src/app/api/star/route.ts": route('import { requireStaff } from "@/lib/all";', 'requireStaff(["Admin"])'),
  "src/app/api/barrel-gone/route.ts": route('import { requireAuth } from "@/lib";', 'requireAuth(["Admin"])'),
  "src/app/api/direct/route.ts": `import { auth } from "@/lib/nowhere";
import { requireAuth } from "@/lib/nowhere";
export async function GET(req) {
  const session = await auth();
  await requireAuth();
  return Response.json({});
}
`,
};

async function run() {
  const dir = temp("t28-rules-");
  mkdirSync(join(dir, "authz-every-handler"));
  writeFileSync(join(dir, "authz-every-handler", "typescript-nextjs.yml"), RULES);
  const root = temp("t28-app-");
  const files = [];
  for (const [path, text] of Object.entries(FILES)) {
    mkdirSync(join(root, path, ".."), { recursive: true });
    writeFileSync(join(root, path), text);
    files.push({ path, text });
  }
  return runRules(loadRules(dir), files, { key: KEY, frameworks: ["nextjs"], root });
}
const of = (res, path) => res.matches.filter((m) => m.path === path);
const item = (res, path) => { const items = of(res, path).filter((m) => m.rule_id === ITEMS); assert.equal(items.length, 1, path); return items[0]; };
const held = (res, path) => of(res, path).filter((m) => m.rule_id === UNOBSERVED);

test("a follow_import evidence rule loads; the key is refused on any other kind", { skip: !engineAvailable() }, () => {
  const dir = temp("t28-bad-");
  mkdirSync(join(dir, "authz-every-handler"));
  writeFileSync(join(dir, "authz-every-handler", "typescript-nextjs.yml"),
    RULES.replace("kind: items\n", "kind: items\nfollow_import: true\n"));
  assert.throws(() => loadRules(dir), /follow_import/);
  const ok = temp("t28-ok-");
  mkdirSync(join(ok, "authz-every-handler"));
  writeFileSync(join(ok, "authz-every-handler", "typescript-nextjs.yml"), RULES);
  assert.equal(loadRules(ok).find((r) => r.id === UNOBSERVED).follow_import, true);
});

test("shape 1: a handler calling an imported helper that loads the session has its control, and nothing is held", { skip: !engineAvailable() }, async () => {
  const res = await run();
  for (const path of ["src/app/api/checked/route.ts", "src/app/api/arrow/route.ts"]) {
    assert.equal(item(res, path).has_control, true, path);
    assert.deepEqual(held(res, path), [], path);
  }
});

test("shape 2: a handler calling an imported helper that loads no session still lacks its control", { skip: !engineAvailable() }, async () => {
  const res = await run();
  assert.equal(item(res, "src/app/api/unchecked/route.ts").has_control, false);
  assert.deepEqual(held(res, "src/app/api/unchecked/route.ts"), []);
});

test("shape 3: a local import that doesn't resolve keeps the evidence on the handler, so core holds it for a person", { skip: !engineAvailable() }, async () => {
  const res = await run();
  for (const path of ["src/app/api/missing/route.ts", "src/app/api/noexport/route.ts"]) {
    const it = item(res, path);
    assert.equal(it.has_control, false, path);
    const ev = held(res, path);
    assert.equal(ev.length, 1, path);
    assert.equal(ev[0].handler, it.handler, path);
    assert.equal(ev[0].line_start, 3, path);
  }
});

test("a package import is not followed: its evidence is dropped and the item is left as the rule found it", { skip: !engineAvailable() }, async () => {
  const res = await run();
  assert.equal(item(res, "src/app/api/package/route.ts").has_control, false);
  assert.deepEqual(held(res, "src/app/api/package/route.ts"), []);
  // the helpers' own files hold no handler, so nothing of theirs is held either
  assert.deepEqual(res.matches.filter((m) => m.path.startsWith("src/lib/")), []);
});

test("a handler that already has its control keeps no follow_import evidence, even for a call that doesn't resolve", { skip: !engineAvailable() }, async () => {
  const res = await run();
  assert.equal(item(res, "src/app/api/direct/route.ts").has_control, true);
  assert.deepEqual(held(res, "src/app/api/direct/route.ts"), []);
});

test("a helper re-exported through a barrel (named or star) is followed to its function; a re-export of a missing file is held", { skip: !engineAvailable() }, async () => {
  const res = await run();
  for (const path of ["src/app/api/barrel/route.ts", "src/app/api/star/route.ts"]) {
    assert.equal(item(res, path).has_control, true, path);
    assert.deepEqual(held(res, path), [], path);
  }
  assert.equal(item(res, "src/app/api/barrel-gone/route.ts").has_control, false);
  assert.equal(held(res, "src/app/api/barrel-gone/route.ts").length, 1);
});

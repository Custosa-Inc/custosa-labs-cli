/* T29-P1-C53 (t29-p3-batch2-lows), P2's C44 low 3: the CLI's line_uncited check reads a ref as a span only when it is a
 * contract location, as core's api._inside_cited applies _LOCATION first. Before this, a ref inside a range the
 * document cites on a path the contract refuses (a space, "..", an absolute path) passed here and core refused it. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { refsRefused } from "../lib/inspector/notes.mjs";

const doc = (path) => ({ matches: [{ rule_id: "authz-every-handler.typescript-nextjs.route",
  practice_id: "authz-every-handler", kind: "item", path, line_start: 12, line_end: 30 }] });
const refsOf = (path, ref) => refsRefused({ verdicts: [{ practice_id: "authz-every-handler", refs: [ref] }] }, [doc(path)]);

for (const path of ["app/api/my notes/route.ts", "app/api/../route.ts", "/srv/app/route.ts", "app//api/route.ts"]) {
  test(`a line inside a cited range on a path the contract refuses is not cited: ${path}`, () => {
    assert.deepEqual(refsOf(path, `${path}:15`).map((r) => r.why), ["not_read"]);
  });
}

test("a contract location inside a cited range is still citable, and one outside it is line_uncited", () => {
  assert.deepEqual(refsOf("app/api/notes/route.ts", "app/api/notes/route.ts:15"), []);
  assert.deepEqual(refsOf("app/api/notes/route.ts", "app/api/notes/route.ts:31").map((r) => r.why), ["line_uncited"]);
});

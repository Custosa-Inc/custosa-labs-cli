/* Handlers' range searches (captures.mjs): innermost and decoratorAt, checked against a plain scan over every node of
 * a file with nested functions and decorators, and over random ranges. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { Handlers } from "../lib/inspector/captures.mjs";
import { parseSync } from "../lib/inspector/parse.mjs";

const KEY = Buffer.alloc(32, 3);
const SOURCE = `
import { Controller, Get, Post } from "@nestjs/common";
function outer(a) {
  const inner = (b) => { function deeper() { return () => b; } return deeper; };
  return function named() { return inner(a); };
}
@Controller("x")
export class Things {
  @Get(":id") show(id) { return [1, 2].map((n) => n + id); }
  @Post() create(body) { const f = function () { return body; }; return f(); }
  plain() { return async () => { await null; }; }
}
const a = () => () => () => 1;
export default function () { return outer(1); }
`;

const nodes = (root) => {
  const out = [], stack = [root];
  while (stack.length) { const n = stack.pop(); out.push(n); stack.push(...n.children()); }
  return out;
};

test("innermost and decoratorAt agree with a plain scan, on every node and on random ranges", () => {
  const root = parseSync("typescript", SOURCE).root();
  const h = new Handlers(root, "typescript", "a.ts", KEY);
  h.load();
  assert.ok(h.fns.length >= 12 && h.decorators.length === 3, `${h.fns.length} functions, ${h.decorators.length} decorators`);
  const innermost = (s, e) => { let best = -1; h.fns.forEach((f, i) => { if (f.start <= s && f.end >= e) best = i; }); return best; };
  const decoratorAt = (s, e) => h.decorators.find((d) => d.start <= s && d.end >= e)?.node ?? null;
  const ranges = nodes(root).map((n) => { const { start, end } = n.range(); return [start.index, end.index]; });
  let seed = 7;
  const rand = (n) => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed % n; };
  for (let k = 0; k < 2000; k++) { const s = rand(SOURCE.length + 1); ranges.push([s, s + rand(SOURCE.length + 1 - s)]); }
  let inFunction = 0, inDecorator = 0;
  for (const [s, e] of ranges) {
    const i = h.innermost(s, e);
    assert.equal(i, innermost(s, e), `innermost ${s}:${e}`);
    const d = h.decoratorAt(s, e);
    assert.equal(d?.id() ?? null, decoratorAt(s, e)?.id() ?? null, `decoratorAt ${s}:${e}`);
    if (i !== -1) inFunction++;
    if (d) inDecorator++;
  }
  assert.ok(inFunction > 100 && inDecorator > 10, `${inFunction} in a function, ${inDecorator} in a decorator`);
});

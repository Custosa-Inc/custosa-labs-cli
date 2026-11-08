/* CUSTOSA_REQUIRE_CONTRACTS=1: Custosa's release gate sets it, so the four tests that read core's checkout fail
 * instead of skipping when CUSTOSA_CORE_CONTRACTS or CUSTOSA_HOSTED_RULES is missing. A skip that guards a contract
 * counts as not run. CI and local runs leave the flag off and keep skipping. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const CLI = fileURLToPath(new URL("..", import.meta.url));
const CORE_TESTS = [
  ["test/free-text-probes.test.mjs", "the copy is byte-equal to core's table"],
  ["test/check-ruleset.test.mjs", "rules matches the hosted rule set the evaluator runs (release gate)"],
  ["test/inspector-rules.test.mjs", "CUSTOSA_NO_PREFILTER=1: the shipped rules give identical matches on every hosted fixture, prefilter on or off"],
  ["test/inspector-factor.test.mjs", "factoring on and off: identical output for the shipped rules on every hosted fixture"],
];
const escape = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

// Each of the four tests on its own, with both variables empty and the flag as given. NODE_TEST_CONTEXT is dropped, or
// the child reports to this runner instead of printing TAP.
const { NODE_TEST_CONTEXT, ...ENV } = process.env;
const run = ([file, name], flag) => spawnSync(process.execPath, [
  "--test", "--test-reporter=tap", `--test-name-pattern=^${escape(name)}$`, file,
], {
  cwd: CLI, encoding: "utf8", timeout: 120_000,
  env: { ...ENV, CUSTOSA_CORE_CONTRACTS: "", CUSTOSA_HOSTED_RULES: "", CUSTOSA_REQUIRE_CONTRACTS: flag },
});

for (const t of CORE_TESTS) {
  test(`flag set, variables missing: "${t[1]}" fails`, () => {
    const r = run(t, "1");
    assert.notEqual(r.status, 0, r.stdout);
    assert.match(r.stdout, /# fail 1\n/, r.stdout);
    assert.match(r.stdout, /CUSTOSA_REQUIRE_CONTRACTS=1/, r.stdout);
  });

  test(`flag off, variables missing: "${t[1]}" skips`, () => {
    const r = run(t, "");
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /# skipped 1\n/, r.stdout);
  });
}

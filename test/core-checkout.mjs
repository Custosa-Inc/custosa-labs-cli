/* The tests that read core's checkout (CUSTOSA_CORE_CONTRACTS, CUSTOSA_HOSTED_RULES) skip when it is missing. Custosa's release
 * gate sets CUSTOSA_REQUIRE_CONTRACTS=1: then they run, and requireCore fails them unless the variable is
 * set and names a folder that exists. A fallback checkout next to this one does not count, since it may be another
 * commit than the gate's candidate. */
import assert from "node:assert/strict";

export const REQUIRE_CONTRACTS = process.env.CUSTOSA_REQUIRE_CONTRACTS === "1";

// The skip option for such a test: its reason when the checkout is missing, never with the flag set.
export const coreSkip = (found, reason) => !REQUIRE_CONTRACTS && !found && reason;

// The first line of such a test.
export function requireCore(name, found) {
  if (!REQUIRE_CONTRACTS) return;
  const value = process.env[name];
  assert.ok(value && found, `CUSTOSA_REQUIRE_CONTRACTS=1, but ${name} is ${value ? `${value}, which does not exist` : "not set"}`);
}

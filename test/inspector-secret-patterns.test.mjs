/* scanSecrets refuses a malformed pattern list before it reads anything, with a SecretPatternError that names the
 * pattern and what is wrong. Each refusal, and the flags a regex is compiled with. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { scanSecrets, SecretPatternError } from "../lib/inspector/secrets.mjs";

const key = Buffer.alloc(32, 7);
const refused = (patterns) => {
  try { scanSecrets([], { key, patterns }); } catch (err) {
    assert.ok(err instanceof SecretPatternError, String(err));
    return err.message;
  }
  return null;
};

test("a malformed secret pattern is refused with its own message", () => {
  const ok = { rule_id: "r1", regex: /abc/ };
  assert.equal(refused("nope"), "patterns must be an array of {rule_id, regex}.");
  assert.equal(refused([null]), "Secret pattern 0 has no rule_id.");
  assert.equal(refused([ok, { regex: /x/ }]), "Secret pattern 1 has no rule_id.");
  assert.equal(refused([{ rule_id: "", regex: /x/ }]), "Secret pattern 0 has no rule_id.");
  assert.equal(refused([{ rule_id: "r", regex: "" }]), "Secret pattern r has an invalid regex.");
  assert.equal(refused([{ rule_id: "r", regex: "(" }]), "Secret pattern r has an invalid regex.");
  assert.equal(refused([{ rule_id: "r", regex: 5 }]), "Secret pattern r has an invalid regex.");
  assert.equal(refused([{ ...ok, validate: "x" }]), "Secret pattern r1 has a validate that is not a function.");
  assert.equal(refused([{ ...ok, normalize: 1 }]), "Secret pattern r1 has a normalize that is not a function.");
  assert.equal(refused([{ ...ok, fileContext: "x" }]), "Secret pattern r1 has a fileContext that is not a regex.");
  assert.equal(refused([{ ...ok, ending: {} }]), "Secret pattern r1 has an ending that is not a function.");
  // The first bad field, in this order, is the one named.
  assert.equal(refused([{ ...ok, validate: 1, normalize: 1, fileContext: 1, ending: 1 }]), "Secret pattern r1 has a validate that is not a function.");
  assert.equal(refused([{ ...ok, normalize: 1, fileContext: 1, ending: 1 }]), "Secret pattern r1 has a normalize that is not a function.");
  assert.equal(refused([{ ...ok, fileContext: 1, ending: 1 }]), "Secret pattern r1 has a fileContext that is not a regex.");
  // null and undefined mean "none".
  assert.equal(refused([{ ...ok, validate: null, normalize: undefined, fileContext: null, ending: null }]), null);
  assert.equal(refused([{ ...ok, validate: () => true, normalize: (s) => s, fileContext: /env/g, ending: () => 0 }]), null);
});

test("a pattern is scanned with g, without y or d, and a string regex finds every match", () => {
  const files = [{ path: "a.txt", text: "k=AAA1 k=AAA2" }];
  for (const regex of [/AAA\d/y, /AAA\d/d, /AAA\d/, "AAA\\d"]) {
    const out = scanSecrets(files, { key, patterns: [{ rule_id: "r", regex }] });
    assert.equal(out.secrets.length, 2, String(regex));
  }
});

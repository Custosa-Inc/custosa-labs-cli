/* Secret detection in the note screen, on the shipped rule file: the CLI
 * twin of core's tests/core/test_t27_c167_secret_cue.py, case for case.
 *
 * A credential word followed by a value refuses whether or not `=` joins them (credential_cue), and two vendor shapes
 * join secret_prefix (Twilio's AC plus 32 hex, Mailgun's key- plus hex). The refuse cases are the 10 notes the fresh
 * held-out set showed leaking, so they are tests now, not the measure; the rest are the design's own
 * examples and hand-written near misses. None comes from the blind secret set. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { defaultNoteRules } from "../lib/inspector/tool.mjs";
import { screenRaw } from "../lib/screen.mjs";

const rules = defaultNoteRules();
const rulesHit = (text) => new Set(screenRaw(text, [], rules).hits.map((h) => h.rule));

// The 10 leaked notes of the fresh blind set (ids f-0027 to f-0574), with the rule each now meets.
const LEAKED = [
  ["f-0027", "Staging db password is Tr0ub4dor&3-clinic, rotate it after the demo.", "credential_cue"],
  ["f-0079", "Twilio SID A\x439f3b2d7e41a6c85b0d2f9e714a3c68d5 and auth token 4c1e8a7b92d05f3e6a1b8c47d29e0f53 are in "
    + "the script.", "credential_cue"],
  ["f-0183", "Deploy key passphrase is blue-Heron-77-vault, don't commit it.", "credential_cue"],
  ["f-0312", "Account sid: A\x43b7e2a41d9c05f38a6b12c4d7e90f1a35 token 8d5f2c91a4b7e03d6c18f9a2b5e47d01", "credential_cue"],
  ["f-0440", "pw=Passw0rd!clinicDB", "credential_cue"],
  ["f-0503", "Datadog API key 9f3a2b7c1d4e5f60a8b9c0d1e2f3a4b5 and app key 1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d.",
    "credential_cue"],
  ["f-0506", "Mailgun key\x2d3f9a2b7c1d4e5f60a8b9c0d1e2f3a4b5 sends the appointment reminders.", "secret_prefix"],
  ["f-0522", "Algolia admin key 4f2a7c91d3b8e05a6c1f9d27b3e80a14 and app id 7XK2LMQ9PR.", "credential_cue"],
  ["f-0555", "Postgres superuser pw: Z7#qLm29!vRtN5 (db host pg-prod-1).", "credential_cue"],
  ["f-0574", "Stored X-Api-Key: 0a1b\x32c3d-4e5f-6789-abcd-ef0123456789-clinicprod in the Postman env.", "credential_cue"],
];

test("the 10 leaked notes refuse", () => {
  for (const [nid, text, rule] of LEAKED) {
    const result = screenRaw(text, [], rules);
    assert.equal(result.decision, "refuse", nid);
    assert.ok(result.hits.some((h) => h.rule === rule), `${nid}: ${JSON.stringify(result.hits)}`);
  }
});

test("a cue then a value refuses, in the four shapes", () => {
  for (const [text, rule] of [
    // Shape 1: a cue word, then a value, with no `=`
    ["the db password is k8Rz2wQp", "credential_cue"],
    ["passphrase is m4ple-Leaf-209", "credential_cue"],
    ["pw: hX93kLq2", "credential_cue"],
    ["pw=hX93kLq2", "credential_cue"],
    ["PW hX93kLq2 for the staging box", "credential_cue"],
    ["the secret was set to 'q9Zt3mWx7'", "credential_cue"],
    ['api_key is "a1B2c3D4e5"', "credential_cue"],
    // Shape 2: hex of 16 or more beside a key word; the hash exemption does not reach inside the window
    ["auth token 0123456789abcdef0123456789abcdef", "credential_cue"],
    ["admin key: deadbeefcafebabe1234", "credential_cue"],
    ["the api key is 9f3a2b7c1d4e5f60", "credential_cue"],
    ["token deadbeefcafebabe", "credential_cue"],
    // Shape 3: vendor prefixes
    ["A\x43b7e2a41d9c05f38a6b12c4d7e90f1a35 is the account", "secret_prefix"],
    ["set MAILGUN to key-0123456789abcdef in prod", "secret_prefix"],
    // Shape 4: a header name
    ["x-api-key: 3c1f\x30d7e-aa21-4b6e-9f4d-2b8c7e5a1d09", "credential_cue"],
    ["sent X_API_KEY=Q7mZ2pL9xR in the header", "credential_cue"],
  ]) assert.ok(rulesHit(text).has(rule), `${text}: ${[...rulesHit(text)]}`);
});

test("near misses send", () => {
  for (const text of [
    // Plain-word values
    "the api key is stored in Secret Manager",
    "rotate the token every 90 days",
    "password must be 12 characters",
    "the passphrase is required on every deploy",
    "token is short-lived and refreshed by the client",
    // the hash exemption holds where the cue is a hash word
    "commit 3f9a2b7c1d4e5f60a8b9c0d1e2f3a4b5c6d7e8f9 fixed the token check",
    "the api key check landed in commit 3f9a2b7c1d4e",
    "token refresh fixed in sha 0123456789abcdef0123",
    "auth token digest 9f86d081884c7d659a2feaa0c55ad015",
    // a word that is not a joiner ends the window
    "token expiry in base64url is fine",
    "the password hash uses bcrypt2b with cost 12",
    "api key rotation moved to v2 in projects/demo/secrets/dd-key/versions/3",
    // env var names and placeholders hold no value
    "the api key env var is DATADOG_API_KEY",
    "the token is YOUR_TOKEN in the example",
    "set pw to the value in Secret Manager",
    // plain hashes and ids with no cue still send
    "etag 5d41402abc4b2a76b9719d911017c592 changed",
    "uuid 3c1f\x30d7e-aa21-4b6e-9f4d-2b8c7e5a1d09 is the tenant",
    // a key- word that is not Mailgun's shape
    "the cache key-prefix setting moved",
  ]) assert.equal(screenRaw(text, [], rules).decision, "pass", `${text}: ${[...rulesHit(text)]}`);
});

test("the rule file carries the cue data", () => {
  assert.ok(rules.ruleIds.has("credential_cue"));
  const cues = rules.lists.credential_cues;
  for (const cue of ["pw", "passphrase", "sid", "auth token", "app key", "admin key", "api key", "x-api-key"]) {
    assert.ok(cues.has(cue), cue);
  }
  assert.equal(rules.limits.credential_cue_window, 3);
  assert.equal(rules.limits.cue_hex_min, 16);
  for (const w of ["is", "was", "set", "to"]) assert.ok(rules.lists.credential_joiners.has(w), w);
  for (const w of rules.lists.credential_joiners) assert.ok(!rules.lists.hash_words.has(w), w);
});

test("the cue scan is linear: cue after cue joined by = reads each value once, capped", () => {
  for (const n of [2_000, 8_000]) {
    const text = "token=".repeat(Math.floor(n / 6)).slice(0, n);
    const t0 = performance.now();
    screenRaw(text, [], rules);
    const took = (performance.now() - t0) / 1000;
    assert.ok(took < 2.0, `${n}: ${took}`);
  }
});

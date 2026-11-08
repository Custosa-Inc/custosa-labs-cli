/* Secret detection round 2, on the shipped rule file: the CLI twin of core's
 * tests/core/test_t27_c174_secret_cue_2.py, case for case.
 *
 * Round 1 left 13 of 60 blind refuse notes passing. Round 2 adds the shapes behind them: a cue, then
 * a few other words, then `is` or `:`; "use X as the password"; `key` after a qualifier and recovery codes; a user and
 * password pair with no host; a password flag joined to its value; a value with no digit after a strong cue; a short
 * PIN after "PIN". Two review lows come with it: a known algorithm or setting name, a dotted config path or an
 * env var reference sends, and one value gives one hit.
 *
 * The first blind set is seen now, so it is a test here, copied row for row to fixtures/secret-blind-1.jsonl.
 * Round 2 is measured on a second blind set. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { defaultNoteRules } from "../lib/inspector/tool.mjs";
import { screenRaw } from "../lib/screen.mjs";

const rules = defaultNoteRules();
const BLIND_1 = new URL("./fixtures/secret-blind-1.jsonl", import.meta.url);
const CUE_RULES = new Set(["credential_cue", "credential_assignment", "secret_prefix"]);
const hitsOf = (text) => screenRaw(text, [], rules).hits.map((h) => [h.rule, text.slice(h.start, h.end)]);
const blind1 = () => readFileSync(BLIND_1, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));

// The fixture writes its fake keys with a JSON escape (scripts/escape-fake-keys.mjs), so the pin is on the parsed
// rows, not the file bytes. The original file, before the escapes, hashed to dbbe145dc331...
test("blind set 1 is the file as written", () => {
  assert.equal(createHash("sha256").update(JSON.stringify(blind1())).digest("hex"),
    "3cf27d1958bd04a0139892d6c552128a4d4b5fb2cc73af3115d79259b1670815");
});

// The one blind refuse note round 2 still lets through: six words sit between the cue and `is`, and the rule asks for up
// to five (credential_cue_gap). Core marks it xfail; here it is pinned as passing, so a change on either side shows.
const BLIND_1_STILL_MISSED = new Set(["s-0043"]);

test("blind set 1: refuse notes refuse", () => {
  for (const row of blind1().filter((r) => r.expect === "refuse")) {
    const want = BLIND_1_STILL_MISSED.has(row.id) ? "pass" : "refuse";
    assert.equal(screenRaw(row.text, [], rules).decision, want, `${row.id}: ${row.text}`);
  }
});

test("blind set 1: send notes get no credential_cue hit", () => {
  for (const row of blind1().filter((r) => r.expect === "send")) {
    const got = hitsOf(row.text);
    assert.deepEqual(got.filter(([r]) => r === "credential_cue"), [], `${row.id}: ${JSON.stringify(got)}`);
  }
});

// Round 1's misses, one per shape, as the blind set showed them.
const BLIND_1_MISSES = ["s-0012", "s-0019", "s-0026", "s-0044", "s-0045", "s-0061", "s-0065", "s-0079", "s-0084",
  "s-0091", "s-0097", "s-0102"];

test("round 1 misses meet credential_cue", () => {
  const rows = blind1();
  for (const nid of BLIND_1_MISSES) {
    const row = rows.find((r) => r.id === nid);
    assert.ok(hitsOf(row.text).some(([r]) => r === "credential_cue"), `${nid}: ${JSON.stringify(hitsOf(row.text))}`);
  }
});

test("round 2 shapes refuse", () => {
  for (const [text, value] of [
    // bullet 1: a cue, then up to 5 other words, then `is` or `:`
    ["The staging password for the billing worker is Fj4mPq8xLw.", "Fj4mPq8xLw"],
    ["token for the nightly export job: 7Hq2Lm9Zx4Rt", "7Hq2Lm9Zx4Rt"],
    ["api key for the maps widget was set to Wq7Rt2Zx9Lp", "Wq7Rt2Zx9Lp"],
    ["secret used by the webhook relay is 1f0e9d8c7b6a5f4e", "1f0e9d8c7b6a5f4e"],
    ["passphrase on the old laptop's keyring is Mx7-Lq2-Rv9", "Mx7-Lq2-Rv9"],
    // "use X as the password", and the as forms
    ["Use r0setta9 as the password for the kiosk.", "r0setta9"],
    ["we picked 'Kq9wLm2x' as our passphrase", "Kq9wLm2x"],
    ["try zebra7Q as a password", "zebra7Q"],
    // bullet 2: `key` after a qualifier, and recovery codes
    ["the signing key is 5f1e0d9c8b7a6f5e4d3c", "5f1e0d9c8b7a6f5e4d3c"],
    ["master key 0f1e2d3c4b5a69788796a5b4c3d2e1f0 is in the safe", "0f1e2d3c4b5a69788796a5b4c3d2e1f0"],
    ["HMAC key: 9a8b\x37c6d5e4f30211203f4e5d6c7b8a9", "9a8b\x37c6d5e4f30211203f4e5d6c7b8a9"],
    ["encryption key for backups: aZ3k\x519mW7xP2", "aZ3k\x519mW7xP2"],
    ["recovery codes: 4k7f2-9q3mx, 8z1pw-5n6rt", "4k7f2-9q3mx"],
    ["Backup codes for the owner account are 71c4e-2b9d0, 3e8a1-6f5c2", "71c4e-2b9d0"],
    // bullet 3: a user and password pair with no host
    ["root / Ch4ngeMe!now", "Ch4ngeMe!now"],
    ["postgres:Tz8Kq2Lm", "Tz8Kq2Lm"],
    ["guest:x7Kp2Lqz for the kiosk", "x7Kp2Lqz"],
    ["ops-bot / Rv8.Mq3.Lz2", "Rv8.Mq3.Lz2"],
    // bullet 4: password flags joined to the value
    ["mysqldump -u app -pR4inyDay9 clinic", "R4inyDay9"],
    ["psql 'dbname=x' && mysql -p'Sn0w#Fall' -h db", "Sn0w#Fall"],
    ["run it with --password=Ld8xQ2mW", "Ld8xQ2mW"],
    // bullet 5: no digit after a strong cue when mixed case with a symbol; short PINs after PIN
    ["the wifi password is Correct#Horse!Staple", "Correct#Horse!Staple"],
    ["pw: Blue$Heron&Kite", "Blue$Heron&Kite"],
    ["PIN 0428 opens the med room", "0428"],
    ["the PIN for the badge printer is 55190", "55190"],
    ["door pin code: 7391", "7391"],
    // a strong cue reads a shorter value
    ["password is h4ppy1", "h4ppy1"],
  ]) {
    const got = hitsOf(text);
    assert.ok(got.some(([r, s]) => r === "credential_cue" && s.endsWith(value))
      || got.some(([r, s]) => CUE_RULES.has(r) && s.includes(value)), `${text}: ${JSON.stringify(got)}`);
  }
});

test("round 2 near misses send", () => {
  for (const text of [
    // a known algorithm or setting name, a dotted config path, an env var reference
    "password is bcrypt12",
    "pw is pbkdf2_sha256",
    "secret is AES256GCM",
    "password set to argon2id",
    "app key is app.config.key2",
    "the token is $TOKEN_V2 in CI",
    "the api key is ${MAPS_API_KEY} at build time",
    "the private key is id_ed25519 in ~/.ssh",
    "the signing key is rsa4096 and the token is hs256",
    "api key for staging is process.env.MAPS_KEY2",
    // bullet 1's wider window still needs a value
    "the password for the admin account is required on first sign-in",
    "token for the export job is refreshed every 15 minutes",
    "the api key for staging is stored in Secret Manager",
    "PIN reset for the badge printer is done by IT",
    // a sentence end, comma or bracket ends the gap
    "Rotate the password. The new build is v2026a11b.",
    "token rotation, release 7 is rc4build22",
    // no-digit values need mixed case and a symbol after a strong cue only
    "the password is Bluebird",
    "the token is Secret_Manager_Path",
    "api key is Correct#Horse!Staple",
    // pairs need a user word, or a spaced slash with a value
    "image postgres:16-alpine3",
    "read/write2024x ratio",
    "root:x:0:0:root:/root:/bin/bash",
    "TCP / IPv6",
    "the build node:20-alpine runs it",
    "admin:true in the role map",
    // a -p flag needs mixed case or a symbol
    "find . -print0 | xargs -0 rm",
    "gcc -pthread -O2 main.c",
    "docker run -p8080:80 nginx",
    // PIN as a verb, and digits that are not a PIN
    "pin numpy to 1.26 in requirements",
    "pin the base image to 2024 tags",
    "PIN entry screen shows 3 tries",
  ]) {
    const got = hitsOf(text);
    assert.deepEqual(got.filter(([r]) => CUE_RULES.has(r)), [], `${text}: ${JSON.stringify(got)}`);
  }
});

test("one value gives one hit", () => {
  for (const [text, n] of [
    // review low 2
    ["auth_token=k8Rz2wQp", 1],
    ["password=Abc12345x", 1],
    ["X-Api-Key: 9f3a\x32b7c1d4e5f60a8b9", 1],
    ["api key for staging is Wq7Rt2Zx9Lp", 1],
    ["auth token Wq7Rt2Zx9Lp and pw Kd8mQ2xZ", 2],
  ]) {
    const got = hitsOf(text).filter(([r]) => r === "credential_cue" || r === "credential_assignment");
    assert.equal(got.length, n, `${text}: ${JSON.stringify(got)}`);
  }
});

test("the rule file carries the round 2 data", () => {
  const { lists, limits } = rules;
  for (const k of ["credential_strong_cues", "credential_links", "credential_as_links", "credential_value_names",
    "credential_user_words", "credential_flags", "pin_cues", "pin_cues_caps"]) {
    assert.ok(lists[k] instanceof Set && lists[k].size > 0, k);
  }
  for (const c of ["encryption key", "master key", "signing key", "hmac key", "recovery codes"]) {
    assert.ok(lists.credential_cues.has(c), c);
  }
  for (const w of ["bcrypt", "argon2id", "pbkdf2_sha256", "aes256gcm"]) assert.ok(lists.credential_value_names.has(w), w);
  for (const w of ["admin", "root", "user", "postgres"]) assert.ok(lists.credential_user_words.has(w), w);
  assert.equal(limits.credential_cue_gap, 5);
  assert.equal(limits.credential_value_min_strong, 6);
  assert.equal(limits.pin_digits_min, 4);
  assert.equal(limits.pin_digits_max, 8);
  for (const w of lists.credential_links) assert.ok(!lists.hash_words.has(w), w);
});

test("the round 2 scan is linear: cue after cue, word runs and pair shapes", () => {
  for (const unit of ["password for the a b c d ", "admin:", "-p", "PIN is "]) {
    for (const n of [2_000, 8_000]) {
      const text = unit.repeat(Math.floor(n / unit.length) + 1).slice(0, n);
      const t0 = performance.now();
      screenRaw(text, [], rules);
      const took = (performance.now() - t0) / 1000;
      assert.ok(took < 2.0, `${unit} ${n}: ${took}`);
    }
  }
});

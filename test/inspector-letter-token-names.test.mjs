/* letterToken (ids.mjs) hashes a 24+ letter run that reads as a random token. A run that splits at case into words is
   a name, and is sent: T29 K013's ConsentRecordsController.ts was hashed (7 vowels in 24, under the 0.3 bar), so the
   finding that cited it couldn't be matched and a person saw a hashed controller name. Random runs stay hashed:
   hashing is what keeps a secret or a record value off the wire. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomInt } from "node:crypto";
import { letterToken, sentIdentifier, sentPath } from "../lib/inspector/ids.mjs";

const KEY = Buffer.alloc(32, 7);

test("letterToken: a run that splits at case into words is a name", () => {
  for (const name of [
    "ConsentRecordsController", "consentRecordsController", "PatientIntakeServiceController", "HIPAAAuditLogRetentionPolicy",
    "ZodCheckStringFormatInternals", "ZodCheckLessThanInternals", "PatientIntakeService", "HIPAAAuditLog",
    "FacilitySubscriptionPayment", "patientmedicationadministrations",
  ]) assert.equal(letterToken(name), false, name);
  assert.equal(sentPath(KEY, "src/Api/Controllers/ConsentRecordsController.ts"), "src/Api/Controllers/ConsentRecordsController.ts");
  assert.equal(sentIdentifier(KEY, "ConsentRecordsController"), "ConsentRecordsController");
});

test("letterToken: random and token-shaped runs stay hashed", () => {
  for (const token of [
    "QwErTyUiOpAsDfGhJkLzXcVbNm", // two-letter humps
    "aZkQmXpLrTbWvNcYdHgFsJeQ", "xYpLmQrTsNbVcXzKwJhGfDdS", // random mixed case
    "qwhsdkfjhwrtplmnbvcxzqrtys", "QWHSDKFJHWRTPLMNBVCXZQRTYS", // one case, one hump
    "BrtxQwvkPlmzNrtvXcvbTrsd", // humps of 3+ letters with too few vowels
    "JWKSMultipleMatchingKeys", // a hump with no vowel (JWKS): read as before, hashed
  ]) assert.equal(letterToken(token), true, token);
  assert.match(sentPath(KEY, "exports/QwErTyUiOpAsDfGhJkLzXcVbNm.json"), /^exports\/u_[0-9a-f]{16}\.json$/);
});

test("letterToken: JWT segments and hex are hashed as before", () => {
  // a JWT's header and claims segments are base64url; any 24+ letter run in them reads as a token
  const seg = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
  assert.equal(letterToken(seg), [...seg.matchAll(/[A-Za-z]{24,}/g)].length > 0);
  assert.equal(letterToken("0123456789abcdef0123456789abcdef"), false); // hex has no 24-letter run: other screens hash it
});

// Random letters only, mixed case: what the words rule spares of the runs the old reading hashed. Fewer than 1 in
// 50,000 at 24 letters in T29-P2's measure, none seen from 32. The bound leaves room for chance in a 20,000 draw.
const oldReading = (run) => {
  const vowels = (run.match(/[aeiouyAEIOUY]/g) ?? []).length / run.length;
  const humps = run.match(/[A-Z]?[a-z]+|[A-Z]+(?![a-z])/g) ?? [run];
  return vowels < 0.3 || humps.filter((h) => h.length <= 2).length * 2 >= humps.length;
};
test("letterToken: random mixed-case letters are almost never read as words", () => {
  const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
  let hashedBefore = 0, spared = 0;
  for (let i = 0; i < 20000; i++) {
    let s = "";
    for (let j = 0; j < 24; j++) s += letters[randomInt(letters.length)];
    if (!oldReading(s)) continue;
    hashedBefore++;
    if (!letterToken(s)) spared++;
  }
  assert.ok(hashedBefore > 18000);
  assert.ok(spared <= 5, `${spared} of ${hashedBefore} random runs read as names`);
});

// T29-P3-C264's probe: random humps, each a capital and 4 to 9 random lower-case letters, are the shape the words rule
// could spare most. About 1 in 400 of those the old reading hashed (T29-P2's measure); the bound is 1 in 100.
test("letterToken: random camel humps are rarely read as words", () => {
  const lower = "abcdefghijklmnopqrstuvwxyz";
  const hump = () => lower[randomInt(26)].toUpperCase() + Array.from({ length: 4 + randomInt(6) }, () => lower[randomInt(26)]).join("");
  let hashedBefore = 0, spared = 0;
  for (let i = 0; i < 10000; i++) {
    const s = Array.from({ length: 3 + randomInt(3) }, hump).join("");
    if (s.length < 24 || !oldReading(s)) continue;
    hashedBefore++;
    if (!letterToken(s)) spared++;
  }
  assert.ok(hashedBefore > 5000);
  assert.ok(spared * 100 <= hashedBefore, `${spared} of ${hashedBefore} random hump runs read as names`);
});

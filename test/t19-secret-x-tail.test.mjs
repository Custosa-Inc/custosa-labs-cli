// T19 (P2, T29-P2-C419): a random key whose last -, _ or . segment is one to three x's is a key, not a placeholder.
// isClearPlaceholder read any all-x last segment as a placeholder, so a Django key drawn from its own alphabet (which
// holds - and _) and ending in _x or -x gave no finding about 1 time in 1,250. That was a false pass, and it made the
// random Django case in inspector-secrets.test.mjs fail now and then. The segment now needs 4 or more x's, as the
// password check already did; a random tail ends in -xxxx about 1 time in 10^9.
import { test } from "node:test";
import assert from "node:assert/strict";

const { scanSecrets } = await import("../lib/inspector/secrets.mjs");
const { isClearPlaceholder } = await import("../lib/inspector/secret-patterns.mjs");

const KEY = Buffer.alloc(32, 7);
const found = (line, path = "settings.py") =>
  scanSecrets([{ path, text: Buffer.from(line + "\n") }], { key: KEY }).secrets.map((s) => s.rule_id);
const BODY = "q7m2k9%v4r!t8w1z(p6n3j@h5g0f*d2s7a)c9b4e";

test("a Django key ending in one to three x's after - or _ is a finding", () => {
  for (const tail of ["_x", "-x", "-xx", "_xxx", "-X"]) {
    const key = BODY + tail.toLowerCase();
    assert.deepEqual(found(`SECRET_KEY = '${key}'`), ["django-secret-key"], tail);
    assert.deepEqual(found(`SECRET_KEY = 'django-insecure-${key}'`), ["django-secret-key"], tail);
    assert.deepEqual(found(`DJANGO_SECRET_KEY=${key}`, "deploy/settings.txt"), ["django-secret-key"], tail);
  }
});

test("an all-x last segment of 4 or more is still a placeholder", () => {
  for (const tail of ["-xxxx", "_xxxxxx", "-xxxxxxx"]) {
    assert.deepEqual(found(`SECRET_KEY = '${BODY}${tail}'`), [], tail);
  }
  assert.equal(isClearPlaceholder("sk_live_xxxx"), true);
  assert.equal(isClearPlaceholder("tok.XXXX"), true);
  assert.equal(isClearPlaceholder("tok-xxx"), false);
  assert.equal(isClearPlaceholder("tok_x"), false);
  // the other clear forms are unchanged
  assert.equal(isClearPlaceholder("a1-your-key"), true);
  assert.equal(isClearPlaceholder("abcxxxxxxxxdef"), true);
  assert.equal(isClearPlaceholder("my_example_key"), true);
});

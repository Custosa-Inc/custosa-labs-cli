/* One keyed name hash. A hashed name is u_ plus the first 16 lowercase hex digits of
 * HMAC-SHA256 with the per-install key over the name's UTF-8 bytes (ids.mjs). The values below were computed before
 * captures.mjs and catalogfacts.mjs gave up their own copies (and checked against openssl), so every name either
 * module hashes must come out byte for byte as it did. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { hashed } from "../lib/inspector/ids.mjs";
import { computeTableName } from "../lib/inspector/captures.mjs";
import { toFactCatalog } from "../lib/inspector/catalogfacts.mjs";

const KEY = Buffer.alloc(32, 7);
const PINNED = [
  ["patients", "u_4d4aadff3bb98de3"],
  ["Patient Notes", "u_ea298ba62493fb43"],
  ["MiXeD_Case", "u_b5eb5a49f61b600e"],
  ["Log ü", "u_2673f610f6e80eaa"],
  ["日本語の表", "u_f2869ceab73348bb"],
  ["café\u0301", "u_ebd84d35c68814f8"], // a combining accent: hashed as written, never normalised
  ["😀 emoji", "u_0838441f991a274c"],
  ["", "u_9dac6a74401b46ed"],
  ["a".repeat(64), "u_7c7031a0e69463a0"],
  ["long name ".repeat(40), "u_1884cd0e03eee664"],
];

test("ids.hashed gives the pinned value for ASCII, mixed case, unicode, empty and long names", () => {
  for (const [name, want] of PINNED) assert.equal(hashed(KEY, name), want, JSON.stringify(name));
});

test("a table name captured in code that doesn't fit pg_name is sent as ids.hashed", () => {
  for (const name of ["Patient Notes", "Log ü", "日本語の表", "café\u0301", "😀 emoji", "", "a".repeat(64), "long name ".repeat(40)]) {
    assert.equal(computeTableName(KEY, name), hashed(KEY, name), JSON.stringify(name));
  }
  assert.equal(computeTableName(KEY, "MiXeD_Case"), "MiXeD_Case");
});

test("a catalog name that doesn't fit pg_name is sent as ids.hashed", () => {
  const names = ["Patient Notes", "Log ü", "日本語の表", "café\u0301", "😀 emoji", "a".repeat(64), "long name ".repeat(40)];
  const out = toFactCatalog({ status: "ok", preflight: { role: names[0], session_user: names[1], database: "MiXeD_Case",
    catalog_extensions: names, passed: true, failed: [] }, queries: [] }, { key: KEY });
  const p = out.catalog.preflight;
  assert.deepEqual([p.role, p.session_user, p.database], [hashed(KEY, names[0]), hashed(KEY, names[1]), "MiXeD_Case"]);
  assert.deepEqual(p.catalog_extensions, names.map((n) => hashed(KEY, n)));
});

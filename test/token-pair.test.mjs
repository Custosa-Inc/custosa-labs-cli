/* A sign-in that fails part way through saving never leaves a token bound to an evaluator that didn't issue
 * it, and never leaves a temporary file with token text behind. The failures are forced with node:test mocks on fs. */
import { test, mock } from "node:test";
import assert from "node:assert/strict";
import fs, { mkdtempSync, readdirSync } from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readToken, writeToken } from "../lib/inspector/auth.mjs";

const OLD = "old-token-0123456789abcdef";
const NEW = "new-token-0123456789abcdef";
const A = "https://a.example.test";
const B = "https://b.example.test";

function failing(name, when) {
  const real = fs[name];
  mock.method(fs, name, (...args) => { if (when(...args)) throw Object.assign(new Error("forced"), { code: "EIO" }); return real(...args); });
  syncBuiltinESMExports();
}

function restore() {
  mock.restoreAll();
  syncBuiltinESMExports();
}

test("a token save that fails after the host file moved leaves no token for the new host", () => {
  const dir = join(mkdtempSync(join(tmpdir(), "custosa-t19-pair-")), "cfg");
  writeToken(OLD, { configDir: dir, host: A });
  assert.deepEqual(readToken({ configDir: dir }), { token: OLD, host: A });
  failing("renameSync", (_from, to) => String(to).endsWith(`${join(dir, "token")}`));
  try {
    assert.throws(() => writeToken(NEW, { configDir: dir, host: B }), /Can't save the sign-in/);
  } finally { restore(); }
  const now = readToken({ configDir: dir });
  assert.ok(!(now.token === OLD && now.host === B), "the old token would go to an evaluator that didn't issue it");
  assert.ok(now.missing || now.refused || (now.token === OLD && now.host === A), JSON.stringify(now));
  assert.deepEqual(readdirSync(dir).filter((f) => f.startsWith(".")), []);
});

test("a write that fails part way leaves no temporary file", () => {
  const dir = join(mkdtempSync(join(tmpdir(), "custosa-t19-pair-")), "cfg");
  failing("writeSync", () => true);
  try {
    assert.throws(() => writeToken(NEW, { configDir: dir, host: B }));
  } finally { restore(); }
  assert.deepEqual(readdirSync(dir).filter((f) => f.startsWith(".")), []);
  assert.ok(readToken({ configDir: dir }).missing || readToken({ configDir: dir }).refused);
});

test("a save that works still binds the new token to the new host", () => {
  const dir = join(mkdtempSync(join(tmpdir(), "custosa-t19-pair-")), "cfg");
  writeToken(OLD, { configDir: dir, host: A });
  writeToken(NEW, { configDir: dir, host: B });
  assert.deepEqual(readToken({ configDir: dir }), { token: NEW, host: B });
  assert.deepEqual(readdirSync(dir).sort(), ["token", "token.host"]);
});

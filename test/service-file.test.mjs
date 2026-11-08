/* setup, the inspector's connection and the environment mark all read the same Postgres service file:
   PGSERVICEFILE when it is set and not empty, else ~/.pg_service.conf. The mark is a fingerprint of the [phisc] entry
   the inspector connects with, so a reader that picked another file would tie the mark to the wrong database. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { main } from "../lib/setup.mjs";
import { readService } from "../lib/inspector/pgservice.mjs";
import { serviceFingerprint } from "../lib/inspector/environment.mjs";

const entry = (host) => `[phisc]\nhost=${host}\nport=5432\ndbname=app\nuser=phisc_ro\n`;

function computer() {
  const home = mkdtempSync(join(tmpdir(), "custosa-service-file-"));
  mkdirSync(join(home, ".cursor"));
  writeFileSync(join(home, ".pg_service.conf"), entry("db.home"));
  writeFileSync(join(home, "other.conf"), entry("db.other"));
  return home;
}

/* what setup's database step says about the service file, for this env */
async function setupSays(home, env) {
  const lines = [];
  const plain = (t) => t;
  const ctx = {
    home, platform: "darwin", env, self: ["custosa"], interactive: false, dryRun: false,
    style: { bold: plain, dim: plain, green: plain, red: plain, yellow: plain },
    which: () => null, run: () => ({ status: 1, stdout: "" }), out: (l = "") => lines.push(l),
    ask: async () => true, input: async () => "", choose: async (q, c, fallback) => fallback,
  };
  assert.equal(await main("setup", { yes: true }, ctx), 0);
  const text = lines.join("\n");
  return text.match(/The phisc entry is in (\S+)\./)?.[1] ?? `none, add it to ${text.match(/The connection entry: add this to (\S+)/)?.[1]}`;
}

const host = (env, home) => { try { return readService("phisc", { env, home }).host; } catch (error) { return error.code; } };

test("service file: ~/.pg_service.conf when PGSERVICEFILE is not set", async () => {
  const home = computer();
  assert.equal(await setupSays(home, {}), "~/.pg_service.conf");
  assert.equal(host({}, home), "db.home");
});

test("service file: an empty PGSERVICEFILE counts as not set", async () => {
  const home = computer();
  assert.equal(await setupSays(home, { PGSERVICEFILE: "" }), "~/.pg_service.conf");
  assert.equal(host({ PGSERVICEFILE: "" }, home), "db.home");
  assert.equal(serviceFingerprint({ env: { PGSERVICEFILE: "" }, home }), serviceFingerprint({ env: {}, home }));
});

test("service file: PGSERVICEFILE wins over the home folder's file", async () => {
  const home = computer();
  const env = { PGSERVICEFILE: join(home, "other.conf") };
  assert.equal(await setupSays(home, env), "~/other.conf");
  assert.equal(host(env, home), "db.other");
  assert.notEqual(serviceFingerprint({ env, home }), serviceFingerprint({ env: {}, home }));
  assert.match(serviceFingerprint({ env, home }), /^[0-9a-f]{64}$/);
});

test("service file: a PGSERVICEFILE that doesn't exist is not replaced by the home folder's file", async () => {
  const home = computer();
  const env = { PGSERVICEFILE: join(home, "missing.conf") };
  assert.equal(await setupSays(home, env), "none, add it to ~/missing.conf");
  assert.equal(host(env, home), "service_file_missing");
  assert.equal(serviceFingerprint({ env, home }), null);
});

// a path shows as ~/... only when it is inside the home folder. The old replace() put ~ wherever the
// home folder's path first appeared, and a sibling folder whose name starts with the home folder's got ~ too.
test("service file: a path that only contains the home folder's path is shown whole", async () => {
  const home = computer();
  const outside = mkdtempSync(join(tmpdir(), "custosa-service-outside-"));
  mkdirSync(join(outside, home), { recursive: true });
  const nested = join(outside, home, "pg.conf");
  writeFileSync(nested, entry("db.nested"));
  assert.equal(await setupSays(home, { PGSERVICEFILE: nested }), nested);
  mkdirSync(`${home}2`);
  const sibling = join(`${home}2`, "pg.conf");
  writeFileSync(sibling, entry("db.sibling"));
  assert.equal(await setupSays(home, { PGSERVICEFILE: sibling }), sibling);
});

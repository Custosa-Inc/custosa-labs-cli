/* catalogFacts with the real collector when the [phisc] service entry can't be used (factdoc.mjs defaultCollectCatalog;
 * every other test passes its own collector): no service file or no entry is not_run service_missing, the wrong login
 * is failed wrong_user and any other entry problem failed service_invalid. The fact document says them as the contract's
 * reasons (catalogfacts.mjs catalogReason): not_configured, preflight_failed, and internal_error, since a failed catalog
 * has no reason for a bad entry. Each query is not_run with the same reason, no connection is tried, and no
 * column is read. PGSERVICEFILE points at a temp file. */
import { afterEach, test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { catalogFacts, loadRuleset, QUERY_IDS } from "../lib/inspector/factdoc.mjs";

const KEY = Buffer.alloc(32, 7);
const RULESET_ID = "2026-10-20.0123abcd";
const ruleset = { id: RULESET_ID, queries: loadRuleset({ bundleDir: "/nonexistent", rulesetId: RULESET_ID }).queries };
const saved = process.env.PGSERVICEFILE;
afterEach(() => { if (saved === undefined) delete process.env.PGSERVICEFILE; else process.env.PGSERVICEFILE = saved; });

/* PGSERVICEFILE set to a temp file holding `text`, or to a path with no file when text is null. */
function serviceFile(text) {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "t19-catalog-")));
  process.env.PGSERVICEFILE = join(dir, "pg_service.conf");
  if (text !== null) writeFileSync(process.env.PGSERVICEFILE, text);
}

async function expectRefused(status, reason) {
  const out = await catalogFacts(ruleset, KEY);
  assert.deepEqual(out.collection, { collector: "catalog", status, count: 0, reason });
  assert.deepEqual(out.catalog.queries.map((q) => [q.query_id, q.status, q.reason]), QUERY_IDS.map((id) => [id, "not_run", reason]));
  assert.deepEqual(out.columns, []);
}

test("no service file: catalog not_run, sent as not_configured", async () => {
  serviceFile(null);
  await expectRefused("not_run", "not_configured");
});

test("a service file with no [phisc] entry: catalog not_run, sent as not_configured", async () => {
  serviceFile("[other]\nhost=localhost\nuser=phisc_ro\n");
  await expectRefused("not_run", "not_configured");
});

test("a [phisc] entry with another login: catalog failed wrong_user, sent as preflight_failed", async () => {
  serviceFile("[phisc]\nhost=localhost\nuser=postgres\ndbname=app\n");
  await expectRefused("failed", "preflight_failed");
});

test("a [phisc] entry that can't be used (bad port, hostaddr, unknown sslmode): failed service_invalid, sent as internal_error", async () => {
  for (const line of ["port=99999", "hostaddr=127.0.0.1", "sslmode=sometimes"]) {
    serviceFile(`[phisc]\nhost=localhost\nuser=phisc_ro\ndbname=app\n${line}\n`);
    await expectRefused("failed", "internal_error");
  }
});

// The catalog collector against a throwaway Postgres: no database, a database that's down, a good phisc_ro, and bad
// roles that can write or read rows (which must fail the preflight and read nothing). The inspector is driven
// through `custosa inspect --stdio` with guard.mjs capturing the evaluator request locally: nothing leaves the
// machine. Every planted value, default, policy literal, view and function body, comment and password is a canary.
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import {
  tmpdir, rmrf, initRepo, inspectStdio, inspectDocument, fakeLogin, assertValid, assertNoCanary, assertNoChildProcess,
  assertNoNetwork, assertWritesConfined, assertBounded, assertHonest, collector, canary,
} from './harness.mjs';
import { PG_AVAILABLE, startCluster, writeConnectionFiles } from './pg.mjs';

const require = createRequire(import.meta.url);
const SKIP = PG_AVAILABLE ? false : 'initdb, pg_ctl and psql are needed for the database tests';

const PASSWORD = `pw${canary('pass')}`;
const V = {
  row: canary('row'), rowEmail: `${canary('rowmail').toLowerCase()}@example.com`, def: canary('default'),
  policy: canary('policy'), view: canary('view'), fn: canary('fnbody'), comment: canary('comment'),
  enumLabel: canary('enumlabel'), check: canary('check'), dbComment: canary('dbcomment'), appName: canary('appname'),
};
const ALL_CANARIES = [PASSWORD, ...Object.values(V)];

// A schema shaped like a small health app, every value-bearing place holding a canary.
const APP_SQL = `
CREATE TYPE visit_kind AS ENUM ('${V.enumLabel}', 'routine');
CREATE TABLE public.patients (
  id serial PRIMARY KEY,
  full_name text NOT NULL DEFAULT '${V.def}',
  email text,
  ssn text CHECK (ssn <> '${V.check}'),
  kind visit_kind,
  owner_id uuid,
  "Odd Column Name" text
);
INSERT INTO public.patients (full_name, email, ssn) VALUES ('${V.row}', '${V.rowEmail}', '123-45-6789');
COMMENT ON TABLE public.patients IS '${V.comment}';
ALTER TABLE public.patients ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_owner ON public.patients USING (full_name = '${V.policy}');
CREATE VIEW public.patient_view AS SELECT full_name FROM public.patients WHERE email <> '${V.view}';
CREATE FUNCTION public.get_secret() RETURNS text LANGUAGE sql SECURITY DEFINER AS $$ SELECT '${V.fn}'::text $$;
REVOKE EXECUTE ON FUNCTION public.get_secret() FROM PUBLIC;
`;

let pg; let base; let repo; let pgClient;

async function runCheck(db, { user = 'phisc_ro', host = '127.0.0.1', sslmode, pgpassMode, port, noFiles = false } = {}) {
  const home = path.join(base, `home-${db}-${Math.random().toString(16).slice(2, 8)}`);
  fs.mkdirSync(home, { recursive: true });
  await fakeLogin(home);
  if (!noFiles) writeConnectionFiles(home, { host, port: port ?? pg.port, db, user, password: PASSWORD, sslmode, pgpassMode });
  const before = scans(db);
  const r = await inspectStdio(repo, { home });
  const afterScans = scans(db);
  const body = r.evaluate[0]?.body ?? null;
  return { r, home, doc: body?.fact_document ?? null, raw: r.evaluate.map((e) => e.raw).join('\n'), before, after: afterScans };
}

// Row reads on the app table, from the statistics collector (a sequential or index scan counts one).
function scans(db) {
  if (!pg || db === 'nodb' || !['good', 'rowread', 'colread', 'write', 'publicread', 'creator', 'super', 'member', 'definer'].includes(db)) return null;
  pg.psql(db, 'SELECT pg_stat_force_next_flush()');
  return pg.psql(db, "SELECT coalesce(seq_scan,0) + coalesce(idx_scan,0) FROM pg_stat_user_tables WHERE relname = 'patients'").trim();
}

function commonStdio(x, label) {
  assertBounded(x.r);
  assertNoChildProcess(x.r.events);
  assertNoNetwork(x.r.events, { allowEvaluate: true });
  assertWritesConfined(x.r.events, x.home);
  assert.ok(x.doc, `${label}: no fact document reached the (stubbed) evaluator; responses: ${JSON.stringify(x.r.results).slice(0, 600)}`);
  assertValid(x.doc, label);
  assertHonest(x.doc);
  assertNoCanary(x.raw, ALL_CANARIES, `${label} evaluator request`);
  const stdout = JSON.stringify(x.r.responses);
  assertNoCanary(stdout, ALL_CANARIES, `${label} MCP responses`);
}

function assertNothingRead(x, label) {
  const cat = collector(x.doc, 'catalog');
  assert.ok(!['ok', 'truncated', 'empty'].includes(cat.status), `${label}: catalog collector says ${cat.status}`);
  for (const q of x.doc.catalog.queries) {
    assert.ok(['failed', 'not_run'].includes(q.status), `${label}: query ${q.query_id} is ${q.status} after a failed preflight`);
    assert.equal(q.rows.length, 0);
  }
  assert.equal(x.doc.catalog.preflight.passed, false, `${label}: preflight passed`);
  assert.equal(x.doc.columns.length, 0);
  if (x.before !== null) assert.equal(x.after, x.before, `${label}: the app table was scanned (rows read) during the run`);
}

function assertNoRowStatements(label) {
  const bad = pg.statementsBy('phisc_ro').filter((l) => /\bpatients\b|patient_view|get_secret|lo_get|lo_export|pg_read_file|\bCOPY\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bCREATE\b|\bDROP\b|\bALTER\b|\bGRANT\b/i.test(l.split('statement:')[1] ?? ''));
  assert.deepEqual(bad, [], `${label}: phisc_ro ran a statement touching app data or writing`);
}

describe('database catalog', { skip: SKIP, concurrency: false }, () => {
  before(async () => {
    base = tmpdir('db');
    repo = path.join(base, 'repo');
    initRepo(repo, { 'package.json': '{"name":"dbapp"}', 'index.js': 'export const a = 1;\n' });
    pg = await startCluster();
    pg.psql('postgres', `CREATE ROLE phisc_ro LOGIN PASSWORD '${PASSWORD}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`);
    for (const db of ['good', 'rowread', 'colread', 'write', 'publicread', 'creator', 'super', 'member', 'definer']) {
      pg.psql('postgres', `CREATE DATABASE ${db}`);
      pg.psql(db, APP_SQL);
      pg.psql(db, `COMMENT ON DATABASE ${db} IS '${V.dbComment}'`);
    }
    pg.psql('rowread', 'GRANT SELECT ON public.patients TO phisc_ro');
    pg.psql('colread', 'GRANT SELECT (email) ON public.patients TO phisc_ro');
    pg.psql('write', 'GRANT INSERT ON public.patients TO phisc_ro');
    pg.psql('publicread', 'GRANT SELECT ON public.patients TO PUBLIC');
    pg.psql('creator', 'GRANT CREATE ON SCHEMA public TO phisc_ro');
    pg.psql('definer', 'GRANT EXECUTE ON FUNCTION public.get_secret() TO phisc_ro');
    // A live app session whose application_name is free text: only a bucket may leave the machine.
    const { Client } = require('pg');
    pgClient = new Client({ host: pg.sock, port: pg.port, user: 'bbadmin', database: 'good', application_name: V.appName });
    await pgClient.connect();
  });

  after(async () => {
    try { await pgClient?.end(); } catch { /* ignore */ }
    pg?.stop();
    rmrf(base);
  });

  it('good phisc_ro: preflight passes, catalog read, no value leaves, no row read', async () => {
    const x = await runCheck('good');
    commonStdio(x, 'good');
    assert.equal(x.doc.catalog.preflight.passed, true, `preflight failed: ${JSON.stringify(x.doc.catalog.preflight.failed)}`);
    assert.ok(['ok', 'truncated'].includes(collector(x.doc, 'catalog').status));
    const cols = x.doc.catalog.queries.find((q) => q.query_id === 'table_columns');
    assert.ok(['ok', 'truncated'].includes(cols.status), `table_columns ${cols.status}`);
    assert.ok(cols.rows.some((row) => JSON.stringify(row).includes('patients')), 'patients table not in the catalog read');
    assert.equal(x.doc.columns.length, cols.rows.length, 'columns must have one entry per table_columns row');
    assert.ok(!JSON.stringify(x.doc).includes('Odd Column Name'), 'an odd column name is sent unhashed');
    assert.match(String(x.before), /^\d+$/, 'scan counter unreadable: the no-row-read check would be vacuous');
    assert.equal(x.after, x.before, 'the app table was scanned during the run');
    assertNoRowStatements('good');
  });

  for (const [db, label] of [['rowread', 'SELECT on an app table'], ['colread', 'SELECT on one column'], ['write', 'INSERT on an app table'],
    ['creator', 'CREATE on schema public']]) {
    it(`bad role (${label}) fails the preflight and reads nothing`, async () => {
      const x = await runCheck(db);
      commonStdio(x, db);
      assertNothingRead(x, db);
      assertNoRowStatements(db);
    });
  }

  // a SELECT granted only to PUBLIC was a bad role; it is now reported (public_readable_tables) and
  // the preflight passes. The inspector still reads no row: its queries read the catalog only.
  it('SELECT granted only to PUBLIC is reported, the preflight passes, and no row is read', async () => {
    const x = await runCheck('publicread');
    commonStdio(x, 'publicread');
    assert.equal(x.doc.catalog.preflight.passed, true);
    assert.equal(x.doc.catalog.preflight.readable_tables, 0);
    assert.equal(x.doc.catalog.preflight.public_readable_tables, 1);
    assertNoRowStatements('publicread');
  });

  it('bad role (superuser) fails the preflight and reads nothing', async () => {
    pg.psql('postgres', 'ALTER ROLE phisc_ro SUPERUSER');
    try {
      const x = await runCheck('super');
      commonStdio(x, 'super');
      assertNothingRead(x, 'super');
      assert.equal(x.doc.catalog.preflight.superuser, true);
    } finally { pg.psql('postgres', 'ALTER ROLE phisc_ro NOSUPERUSER'); }
  });

  it('bad role (member of pg_read_all_data) fails the preflight and reads nothing', async () => {
    pg.psql('postgres', 'GRANT pg_read_all_data TO phisc_ro');
    try {
      const x = await runCheck('member');
      commonStdio(x, 'member');
      assertNothingRead(x, 'member');
    } finally { pg.psql('postgres', 'REVOKE pg_read_all_data FROM phisc_ro'); }
  });

  it('bad role (BYPASSRLS) fails the preflight and reads nothing', async () => {
    pg.psql('postgres', 'ALTER ROLE phisc_ro BYPASSRLS');
    try {
      const x = await runCheck('good');
      commonStdio(x, 'bypassrls');
      assertNothingRead(x, 'bypassrls');
    } finally { pg.psql('postgres', 'ALTER ROLE phisc_ro NOBYPASSRLS'); }
  });

  it('an executable SECURITY DEFINER function is counted, never called', async () => {
    const x = await runCheck('definer');
    commonStdio(x, 'definer');
    assert.ok(x.doc.catalog.preflight.definer_functions_executable >= 1, 'definer function not counted');
    assertNoRowStatements('definer');
  });

  it('a user other than phisc_ro (the admin login) is refused without reading anything', async () => {
    const x = await runCheck('good', { user: 'bbadmin' });
    commonStdio(x, 'wrong user');
    assertNothingRead(x, 'wrong user');
    assert.equal(pg.statementsBy('bbadmin').filter((l) => /pg_catalog|information_schema|current_user/.test(l)).length, 0, 'the inspector queried as the admin login');
  });

  it('no database configured: catalog not_run, preflight failed connect, everything else still collected', async () => {
    const x = await runCheck('nodb', { noFiles: true });
    commonStdio(x, 'nodb');
    const cat = collector(x.doc, 'catalog');
    assert.equal(cat.status, 'not_run');
    assert.equal(cat.reason, 'not_configured');
    assert.deepEqual(x.doc.catalog.preflight.failed, ['connect']);
    assert.ok(['ok', 'empty'].includes(collector(x.doc, 'files').status));
  });

  it('database down (nothing listening): catalog failed unreachable, never ok', async () => {
    const x = await runCheck('good', { port: pg.port + 97 });
    commonStdio(x, 'down');
    const cat = collector(x.doc, 'catalog');
    assert.equal(cat.status, 'failed');
    assert.ok(['unreachable', 'timeout'].includes(cat.reason), `reason ${cat.reason}`);
  });

  it('non-local host without TLS: refused before any connection (tls_required)', async () => {
    const x = await runCheck('good', { host: 'db.example.invalid' });
    commonStdio(x, 'notls');
    const cat = collector(x.doc, 'catalog');
    assert.equal(cat.status, 'failed');
    assert.equal(cat.reason, 'tls_required');
    assert.ok(!x.r.events.some((e) => (e.kind === 'dns' || e.kind === 'connect') && /example\.invalid/.test(e.host)), 'it tried to reach the non-local host');
  });

  it('a .pgpass other users can read is ignored (config_insecure), never used', async () => {
    const x = await runCheck('good', { pgpassMode: 0o644 });
    commonStdio(x, 'insecure pgpass');
    const cat = collector(x.doc, 'catalog');
    assert.ok(cat.status !== 'ok' && cat.status !== 'truncated', `catalog ${cat.status} with a world-readable .pgpass`);
    assert.ok(['config_insecure', 'auth_failed'].includes(cat.reason), `reason ${cat.reason}`);
  });

  it('an unparsable .pg_service.conf: catalog not ok, the run still completes', async () => {
    const home = path.join(base, 'home-badservice');
    fs.mkdirSync(home);
    await fakeLogin(home);
    fs.writeFileSync(path.join(home, '.pg_service.conf'), Buffer.from([0xff, 0xfe, 0x00, 0x5b, 0x70, 0x68, 0x0a, 0x3d, 0x3d, 0x0a, 0x5b, 0x5b, 0x5d]), { mode: 0o600 });
    fs.writeFileSync(path.join(home, '.pgpass'), `garbage:${PASSWORD}\n`, { mode: 0o600 });
    const r = await inspectStdio(repo, { home });
    const x = { r, home, doc: r.evaluate[0]?.body?.fact_document ?? null, raw: r.evaluate.map((e) => e.raw).join('\n'), before: null, after: null };
    commonStdio(x, 'bad service file');
    assert.ok(!['ok', 'truncated', 'empty'].includes(collector(x.doc, 'catalog').status));
  });

  it('--document reads no database even when one is configured', async () => {
    const home = path.join(base, 'home-docmode');
    fs.mkdirSync(home);
    writeConnectionFiles(home, { port: pg.port, db: 'good', password: PASSWORD });
    const n = pg.statementsBy('phisc_ro').length;
    const r = await inspectDocument(repo, { home });
    assertValid(r.doc);
    assert.equal(pg.statementsBy('phisc_ro').length, n, '--document connected to the database');
    assert.equal(collector(r.doc, 'catalog').status, 'not_run');
    assertNoNetwork(r.events);
  });
});

// Concurrency: several first runs racing on one fresh HOME (the per-install key), several check_schema calls in one
// stdio server, and a repository changing while it is walked. Plus determinism: the same tree gives the same document.
import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {
  tmpdir, rmrf, initRepo, inspectDocument, inspectStdio, fakeLogin, assertValid, assertNoChildProcess, assertNoNetwork,
  assertWritesConfined, assertBounded, assertHonest,
} from './harness.mjs';

const made = [];
after(() => { for (const p of made) rmrf(p); });
const APP = 'import express from "express";\nconst app = express();\napp.post("/x", (req, res) => {\n  console.log(req.body.ssn);\n  res.json({});\n});\nconst k = "sk\x5flive_concurrencyabcdefghijklmnop1234";\n';

function setup(tag) {
  const base = tmpdir(tag); made.push(base);
  const root = path.join(base, 'repo'); const home = path.join(base, 'home');
  fs.mkdirSync(home, { recursive: true });
  initRepo(root, { 'package.json': '{"dependencies":{"express":"4"}}', 'src/app.js': APP, 'src/b.js': 'export const b = 2;\n' });
  return { base, root, home };
}

describe('concurrency', { concurrency: 1 }, () => {
  it('four first runs at once on a fresh HOME agree on one install key (same root_id and fingerprints)', async () => {
    const { root, home } = setup('race');
    const runs = await Promise.all([0, 1, 2, 3].map(() => inspectDocument(root, { home })));
    for (const r of runs) {
      assert.equal(r.code, 0, r.stderr.slice(-800));
      assertValid(r.doc); assertHonest(r.doc); assertBounded(r);
      assertNoChildProcess(r.events); assertNoNetwork(r.events); assertWritesConfined(r.events, home);
    }
    const ids = new Set(runs.map((r) => r.doc.root_id));
    assert.equal(ids.size, 1, `concurrent first runs produced ${ids.size} different root_ids (install key race)`);
    const fps = new Set(runs.map((r) => JSON.stringify(r.doc.secrets.map((s) => s.fingerprint))));
    assert.equal(fps.size, 1, 'secret fingerprints differ between concurrent runs');
    const key = path.join(home, '.config', 'custosa', 'install.key');
    assert.ok(fs.existsSync(key));
    assert.equal(fs.statSync(key).mode & 0o077, 0, 'install key readable by others');
    const later = await inspectDocument(root, { home });
    assert.equal(later.doc.root_id, runs[0].doc.root_id, 'the key used by the racing runs is not the one kept');
  });

  it('the same tree gives a byte-identical document twice', async () => {
    const { root, home } = setup('determinism');
    const a = await inspectDocument(root, { home });
    const b = await inspectDocument(root, { home });
    assert.equal(JSON.stringify(a.doc), JSON.stringify(b.doc));
  });

  it('three check_schema calls at once in one stdio server: three answers, three valid documents', async () => {
    const { root, home } = setup('stdiopar');
    await fakeLogin(home);
    const r = await inspectStdio(root, { home, calls: [{ goal: 'check' }, { goal: 'check' }, { goal: 'verify' }] });
    assertBounded(r);
    assertNoChildProcess(r.events);
    assertNoNetwork(r.events, { allowEvaluate: true });
    assert.ok(r.results.every(Boolean), `missing answers: ${JSON.stringify(r.results).slice(0, 400)}`);
    assert.equal(r.evaluate.length, 3, `expected three evaluator requests, saw ${r.evaluate.length}`);
    for (const e of r.evaluate) assertValid(e.body?.fact_document, 'concurrent call document');
    const ids = new Set(r.evaluate.map((e) => e.body.fact_document.root_id));
    assert.equal(ids.size, 1);
  });

  it('files changing during the walk: the run completes with a valid, honest document', async () => {
    const { root, home } = setup('churn');
    for (let i = 0; i < 150; i++) fs.writeFileSync(path.join(root, 'src', `c${i}.js`), APP);
    let stop = false;
    const churn = (async () => {
      let n = 0;
      while (!stop) {
        const p = path.join(root, 'src', `c${n % 150}.js`);
        try { if (n % 2) fs.rmSync(p, { force: true }); else fs.writeFileSync(p, APP.repeat(1 + (n % 5))); } catch { /* racing */ }
        try { fs.mkdirSync(path.join(root, 'tmpdir' + (n % 7)), { recursive: true }); fs.rmSync(path.join(root, 'tmpdir' + ((n + 3) % 7)), { recursive: true, force: true }); } catch { /* racing */ }
        n++;
        await new Promise((res) => setTimeout(res, 5));
      }
    })();
    const r = await inspectDocument(root, { home });
    stop = true; await churn;
    assert.equal(r.code, 0, r.stderr.slice(-800));
    assertValid(r.doc); assertHonest(r.doc); assertBounded(r);
  });
});

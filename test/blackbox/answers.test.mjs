// Location answers: the inspector "confirms the location itself". A location that resolves through a symlink out
// of the root, into a .env file, or into a FIFO must never be followed, read or parsed; an unconfirmed path is never
// forwarded. The evaluator is scripted locally (guard.mjs) to ask one location question.
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import {
  tmpdir, rmrf, write, initRepo, inspectStdio, fakeLogin, assertValid, assertNoChildProcess, assertNoNetwork,
  assertBounded, assertNoCanary, canary,
} from './harness.mjs';
import { validateResponse } from '../../lib/inspector/schema.mjs';

const SESSION = 'ps_bbBlackBoxSession00001';
const C = { outside: canary('ansout'), env: canary('ansenv') };
const TARGETS = {
  inside: 'src/app.js:3',
  outsideLink: 'link_out.js:1',
  dotenv: '.env:1',
  fifo: 'pipe.js:1',
  devlink: 'zero.js:1',
  missing: 'nope.js:1',
  dirlink: 'link_dir/leak.js:1',
};
let base; let root; let home; let r; let answers;

function question(objectId) {
  return { question_id: 'location', object_id: objectId, practice_id: 'access-audit-log', ask: 'Where is it?', answers: ['here', 'not_found', 'not_present'], expects: 'function' };
}

before(async () => {
  base = tmpdir('answers');
  root = path.join(base, 'repo'); home = path.join(base, 'home');
  fs.mkdirSync(home);
  write(base, 'outside/leak.js', `function outsideFn() { return "${C.outside}"; }\n`);
  initRepo(root, { 'src/app.js': '// one\n// two\nfunction inside() { return 1; }\n' });
  write(root, '.env', `function envFn() { return "${C.env}"; }\nSECRET=${C.env}\n`);
  fs.symlinkSync('../outside/leak.js', path.join(root, 'link_out.js'));
  fs.symlinkSync('../outside', path.join(root, 'link_dir'));
  fs.symlinkSync('/dev/zero', path.join(root, 'zero.js'));
  assert.equal(spawnSync('mkfifo', [path.join(root, 'pipe.js')]).status, 0);
  await fakeLogin(home);
  const ids = Object.keys(TARGETS).map((k) => `access-audit-log@${k}`);
  const first = {
    goal: 'check', status: 'in_progress', session: SESSION, ruleset_id: '2026-10-21.8020a370', registry_id: '2026-10-21.8020a370',
    headline: 'black-box', findings: [], fixes: [], questions: ids.map(question), is_fetch_only: false, charged_units: 10,
    next_step: 'Answer the questions.', notice: 'black-box stub', correlation_id: 'bbcorrelation01',
  };
  // The CLI drops a reply its response schema refuses, so a stale script would fail far from its cause.
  assert.equal(validateResponse(first), null, 'the scripted evaluator reply must match response.schema.json');
  const script = path.join(base, 'script.json');
  fs.writeFileSync(script, JSON.stringify([first]));
  const answered = { goal: 'check', session: SESSION, answers: Object.entries(TARGETS).map(([k, loc]) => ({ object_id: `access-audit-log@${k}`, question_id: 'location', answer: 'here', location: loc })) };
  r = await inspectStdio(root, { home, calls: [{ goal: 'check' }, answered], sequential: true, env: { PHISC_BB_EVAL_SCRIPT: script }, timeoutMs: 240_000 });
  const second = r.evaluate[1]?.body?.fact_document;
  answers = Object.fromEntries((second?.answers ?? []).map((a) => [a.object_id.split('@')[1], a]));
});
after(() => rmrf(base));

describe('location answers', () => {
  it('both calls complete in bounded time with no child process or outside network', () => {
    assertBounded(r, { timeoutMs: 240_000 });
    assertNoChildProcess(r.events);
    assertNoNetwork(r.events, { allowEvaluate: true });
    assert.equal(r.evaluate.length, 2, `expected two evaluator requests: ${JSON.stringify(r.results).slice(0, 800)}`);
    assertValid(r.evaluate[1].body?.fact_document, 'answers document');
  });

  it('carries no canary from outside the root or from .env', () => {
    assertNoCanary(r.evaluate.map((e) => e.raw).join('\n') + JSON.stringify(r.responses), Object.values(C), 'requests and responses');
  });

  it('confirms a real location inside the root', () => {
    assert.ok(answers.inside, 'answer missing');
    assert.equal(answers.inside.location, 'src/app.js:3');
    assert.equal(answers.inside.location_kind, 'function');
  });

  for (const k of ['outsideLink', 'dirlink', 'dotenv', 'fifo', 'devlink', 'missing']) {
    it(`never confirms, reads or forwards a location that ${k === 'dotenv' ? 'is a .env file' : `goes through ${k}`}`, () => {
      const a = answers[k];
      assert.ok(a, `answer for ${k} missing`);
      assert.ok(['not_found', 'not_checked'].includes(a.location_kind), `${k}: location_kind ${a.location_kind}: the target was read and parsed`);
      assert.equal(a.location, null, `${k}: unconfirmed location forwarded: ${a.location}`);
    });
  }
});

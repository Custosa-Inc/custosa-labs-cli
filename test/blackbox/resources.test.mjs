// Bounded time and memory on hostile input, and honest statuses when the inspector can't read everything:
// huge files, a huge single line, deep directory nesting, deeply nested syntax, FIFOs, unreadable files, more
// matches and more skipped files than the document can hold, a pathological .gitignore, regex-bait lines, and
// (behind PHISC_BLACKBOX_BIG=1) 100,000 files.
import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import {
  tmpdir, rmrf, write, initRepo, git, inspectDocument, assertValid, assertNoCanary, assertNoChildProcess, assertNoNetwork,
  assertWritesConfined, assertBounded, assertHonest, assertPathsInsideRoot, collector, docText, canary,
} from './harness.mjs';

const HANDLER = (body) => `import express from "express";\nconst app = express();\napp.post("/x", (req, res) => {\n${body}\n  res.json({});\n});\n`;
const LEAK = '  console.log(req.body.ssn);';
const secret = (tag) => `sk\x5flive_${canary(tag)}abcdefghijklmnop`;
const made = [];
after(() => { for (const p of made) rmrf(p); });

function setup(tag) {
  const base = tmpdir(tag);
  made.push(base);
  const root = path.join(base, 'repo');
  const home = path.join(base, 'home');
  fs.mkdirSync(home, { recursive: true });
  return { base, root, home };
}

function common(r, home, root, canaries = [], bounds = {}) {
  assert.equal(r.code, 0, `exit ${r.code} signal ${r.signal} timedOut ${r.timedOut}: ${r.stderr.slice(-1500)}`);
  assertBounded(r, bounds);
  assertValid(r.doc);
  assertHonest(r.doc);
  assertNoChildProcess(r.events);
  assertNoNetwork(r.events);
  assertWritesConfined(r.events, home);
  if (root) assertPathsInsideRoot(r.doc, root);
  assertNoCanary(docText(r.doc), canaries, 'document');
}

// A file the inspector didn't read in full is either listed (not analysed) or its content is accounted for.
function accountedFor(doc, rel) {
  return doc.files.not_analyzed.some((x) => x.path === rel || rel.startsWith(`${x.path}/`))
    || doc.matches.some((m) => m.path === rel);
}

describe('resource bounds', { concurrency: 3 }, () => {
  it('huge source file (60 MB): bounded, listed or analysed, and its secret found or the secret scan truncated', async () => {
    const { root, home } = setup('huge');
    const s = secret('huge');
    initRepo(root, { 'package.json': '{"dependencies":{"express":"4"}}' });
    const fd = fs.openSync(path.join(root, 'huge.js'), 'w');
    const chunk = Buffer.from('const filler = 1;\n'.repeat(10000));
    for (let i = 0; i < Math.ceil(60e6 / chunk.length); i++) fs.writeSync(fd, chunk);
    fs.writeSync(fd, HANDLER(LEAK) + `const k = "${s}";\n`);
    fs.closeSync(fd);
    const r = await inspectDocument(root, { home });
    common(r, home, root, [s]);
    assert.ok(accountedFor(r.doc, 'huge.js'), 'huge.js neither listed in not_analyzed nor matched: silently dropped');
    const sec = collector(r.doc, 'secrets');
    assert.ok(r.doc.secrets.some((x) => x.path === 'huge.js') || sec.status === 'truncated',
      `secret at the end of a 60 MB file missed while secrets is ${sec.status}`);
  });

  it('huge single line (20 MB minified): bounded, and its secret found or the secret scan truncated', async () => {
    const { root, home } = setup('oneline');
    const s = secret('line');
    initRepo(root, {});
    fs.writeFileSync(path.join(root, 'min.js'), `var a=[${'1,'.repeat(10e6)}1];var k="${s}";`);
    const r = await inspectDocument(root, { home });
    common(r, home, root, [s]);
    const sec = collector(r.doc, 'secrets');
    assert.ok(r.doc.secrets.some((x) => x.path === 'min.js') || sec.status === 'truncated',
      `secret at the end of a 20 MB line missed while secrets is ${sec.status}`);
  });

  it('deep directory nesting (600 levels, beyond PATH_MAX): bounded and the deepest file accounted for', async () => {
    const { root, home } = setup('deepdir');
    const s = secret('deep');
    initRepo(root, { 'package.json': '{"dependencies":{"express":"4"}}' });
    // Built with relative paths from a moving cwd, since the full path passes the OS limit.
    const script = `
      const fs=require('fs');process.chdir(process.argv[1]);
      for(let i=0;i<600;i++){fs.mkdirSync('d');process.chdir('d');}
      fs.writeFileSync('leaf.js', process.argv[2]);`;
    const res = spawnSync(process.execPath, ['-e', script, root, HANDLER(LEAK) + `const k = "${s}";\n`]);
    assert.equal(res.status, 0, String(res.stderr));
    const r = await inspectDocument(root, { home });
    common(r, home, root, [s]);
    const deep = r.doc.files.not_analyzed.some((x) => x.path.startsWith('d/') || /^u_[0-9a-f]{16}$/.test(x.path));
    const found = r.doc.matches.length > 0 || r.doc.secrets.length > 0;
    assert.ok(deep || found, 'the file 600 levels down is neither analysed nor listed as not analysed: silently dropped');
    if (!found) assert.ok(collector(r.doc, 'secrets').status !== 'ok' || r.doc.secrets.length > 0, 'deep file skipped, secret scan still ok');
  });

  it('deeply nested syntax (100k brackets in JS, JSON and Python): no crash, bounded', async () => {
    const { root, home } = setup('deepast');
    const n = 100000;
    initRepo(root, {
      'deep.js': `const x = ${'['.repeat(n)}${']'.repeat(n)};\n`,
      'deep.json': `${'['.repeat(n)}${']'.repeat(n)}\n`,
      'deep.py': `x = ${'('.repeat(n)}1${')'.repeat(n)}\n`,
      'deep.yaml': `${'- '.repeat(5000)}x\n`,
      'ok.js': HANDLER(LEAK),
    });
    const r = await inspectDocument(root, { home });
    common(r, home, root);
    // The ordinary file is analysed, unless the run's time budget (which counts loading the rule bundle, slow on a
    // loaded machine such as a shared CI runner) ran out first: then it is listed as time_limit and the rules
    // collector is truncated, timeout. Never silently missing.
    const okEntry = r.doc.files.not_analyzed.find((x) => x.path === 'ok.js');
    if (!r.doc.matches.some((m) => m.path === 'ok.js')) {
      assert.ok(okEntry, 'the ordinary file next to the deep ones was neither analysed nor listed: silently dropped');
      assert.equal(okEntry.reason, 'time_limit', `ok.js not analysed: ${okEntry.reason}`);
      const rules = collector(r.doc, 'rules');
      assert.deepEqual([rules.status, rules.reason], ['truncated', 'timeout'], 'ok.js is time_limit but the rules collector says it finished');
    } else if (okEntry) {
      // Matched and listed is the contract, not a contradiction: a file the rules cut at its time limit keeps its
      // violations (without a handler) and is time_limit (runRules), and the secret scan lists a file it had no time
      // for whatever the rules found. Either way the cut collector says timeout, and time_limit blocks a pass.
      assert.equal(okEntry.reason, 'time_limit', `ok.js matched and listed as ${okEntry.reason}`);
      const timedOut = (c) => {
        const e = collector(r.doc, c);
        return e.status === 'truncated' && e.reason === 'timeout';
      };
      const okMatches = r.doc.matches.filter((m) => m.path === 'ok.js');
      if (okMatches.every((m) => m.handler === null)) {
        // The rules cut it: only what was observed against the code is kept, and the rules collector says timeout.
        assert.ok(okMatches.every((m) => m.kind === 'violation' || (m.kind === 'item' && m.has_control === false)),
          `ok.js was cut by the rules but kept ${okMatches.map((m) => m.kind)}`);
        assert.ok(timedOut('rules'), 'ok.js was cut by the rules, but the rules collector does not say timeout');
      } else assert.ok(timedOut('secrets'), 'ok.js was analysed by the rules and listed time_limit, but the secret scan does not say timeout');
    }
    // The whole picture: each of the five files is analysed or listed, once.
    const five = ['deep.js', 'deep.json', 'deep.py', 'deep.yaml', 'ok.js'];
    const listed = r.doc.files.not_analyzed.filter((x) => x.kind === 'file' && five.includes(x.path)).map((x) => x.path);
    assert.equal(new Set(listed).size, listed.length, `a file listed twice: ${listed}`);
    // (A file the rules analysed can also be listed by the secret scan, so at least, not exactly.)
    assert.ok(r.doc.files.analyzed + listed.length >= five.length, `analysed ${r.doc.files.analyzed}, listed ${listed}`);
  });

  it('FIFOs named like source, .env and config.toml: never opened, run finishes', async () => {
    const { root, home } = setup('fifo');
    initRepo(root, { 'ok.js': HANDLER(LEAK) });
    for (const p of ['pipe.js', '.env.local', 'supabase/config.toml', 'data.sql']) {
      fs.mkdirSync(path.dirname(path.join(root, p)), { recursive: true });
      assert.equal(spawnSync('mkfifo', [path.join(root, p)]).status, 0);
    }
    const r = await inspectDocument(root, { home, timeoutMs: 120_000 });
    common(r, home, root);
    const e = r.doc.files.not_analyzed.find((x) => x.path === 'pipe.js');
    assert.ok(e, 'FIFO pipe.js not listed');
    assert.equal(e.reason, 'not_regular_file');
    assert.equal(r.doc.supabase.edge_functions.status, 'failed', 'a supabase/config.toml that is a FIFO was not reported as failed');
  });

  it('unreadable file and folder: listed as unreadable and the secret scan not ok', async () => {
    const { root, home } = setup('unread');
    const s = secret('unread');
    initRepo(root, { 'ok.js': HANDLER(LEAK), 'locked/inner.js': HANDLER(LEAK) });
    write(root, 'secret.js', `const k = "${s}";\n`, 0o000);
    fs.chmodSync(path.join(root, 'locked'), 0o000);
    const r = await inspectDocument(root, { home });
    fs.chmodSync(path.join(root, 'locked'), 0o755);
    common(r, home, null, [s]);
    const f = r.doc.files.not_analyzed.find((x) => x.path === 'secret.js');
    assert.ok(f && f.reason === 'unreadable', `unreadable file reported as ${JSON.stringify(f)}`);
    const d = r.doc.files.not_analyzed.find((x) => x.path === 'locked');
    assert.ok(d && d.reason === 'unreadable', `unreadable folder reported as ${JSON.stringify(d)}`);
    assert.notEqual(collector(r.doc, 'secrets').status, 'ok', 'secrets says ok though a file could not be read');
    assert.notEqual(collector(r.doc, 'secrets').status, 'empty', 'secrets says empty though a file could not be read');
  });

  // Matching cost grows with the square of the matches in one handler: 800 in one handler took about 4 s of CPU, the
  // whole per-file soft limit (0.8 of 5 s), so files went time_limit and the run never showed the cap. 40 handlers of
  // 20 cost about 0.3 s a file and still make more than 20,000 matches in all (30 files of 880).
  const MANY = 'import express from "express";\nconst app = express();\n' + Array.from({ length: 40 }, (_, k) =>
    `app.post("/x${k}", (req, res) => {\n${Array(20).fill(LEAK).join('\n')}\n  res.json({});\n});\n`).join('');

  // The cap, not the clock, is under test here, so both runs get the corpus fixed budget (no time_limit on a slow
  // runner). Under the 45 s product budget, with this suite's other heavy tests beside it, a shared CI runner matched
  // only 22 of the 30 files (23 are needed to pass 20,000) once a larger rule set made each file a little dearer.
  const FIXED = { CUSTOSA_CORPUS_FIXED_BUDGET: '1' };

  it('more than 20,000 matches: rules truncated, kept matches capped, every file that lost a match listed', async () => {
    // What one such file matches on its own, under no cap: the count every file of the big run is held to.
    const one = setup('matches1');
    initRepo(one.root, { 'package.json': '{"dependencies":{"express":"4"}}', 'src/f.js': MANY });
    const r1 = await inspectDocument(one.root, { home: one.home, env: FIXED });
    common(r1, one.home, one.root);
    assert.equal(collector(r1.doc, 'rules').status, 'ok', `one file alone: rules is ${JSON.stringify(collector(r1.doc, 'rules'))}`);
    const full = r1.doc.matches.filter((m) => m.path === 'src/f.js').length;
    assert.ok(full >= 800, `one file alone has ${full} matches`);

    const { root, home } = setup('matches');
    const files = { 'package.json': '{"dependencies":{"express":"4"}}' };
    for (let i = 0; i < 30; i++) files[`src/f${i}.js`] = MANY;
    initRepo(root, files);
    const r = await inspectDocument(root, { home, env: FIXED, timeoutMs: 600_000 });
    common(r, home, root, [], { timeoutMs: 600_000 });
    const na = r.doc.files.not_analyzed;
    const listedAs = (p) => na.filter((x) => x.path === p).map((x) => x.reason);
    const rules = collector(r.doc, 'rules');
    const timedOut = na.filter((x) => x.reason === 'time_limit').map((x) => x.path);
    // item_limit: the cap cut the matches. On a loaded computer some files may run out of time instead: then the
    // collector says timeout (it takes precedence), and those files are listed time_limit, never counted as analysed.
    assert.equal(rules.status, 'truncated', `rules is ${rules.status} with ${r.doc.matches.length} matches`);
    assert.equal(rules.reason, timedOut.length ? 'timeout' : 'item_limit', `rules is truncated, ${rules.reason}, with time_limit ${JSON.stringify(timedOut)}`);
    assert.ok(r.doc.matches.length <= 20000);
    let ranInFull = 0, capped = 0;
    for (let i = 0; i < 30; i++) {
      const p = `src/f${i}.js`;
      const kept = r.doc.matches.filter((m) => m.path === p).length;
      assert.ok(kept <= full, `${p} has ${kept} matches, more than the ${full} it has alone`);
      const reasons = listedAs(p);
      if (!reasons.includes('time_limit')) ranInFull++;
      if (reasons.includes('match_limit')) capped++;
      if (kept < full) {
        assert.ok(reasons.includes('match_limit') || reasons.includes('time_limit'),
          `${p} lost matches (${kept} of ${full}) but isn't listed with match_limit (or time_limit): ${JSON.stringify(reasons)}`);
      }
    }
    // The files matched in full found more than 20,000 between them, so the cap was crossed, and it cut some.
    assert.ok(ranInFull * full > 20000, `only ${ranInFull} files ran before the time limit: the 20,000-match cap was never reached`);
    assert.ok(capped > 0, 'no file is listed match_limit, so the cap was never tested');
  });

  it('more than 20,000 files not analysed: files truncated with item_limit', async () => {
    const { root, home } = setup('manyskip');
    initRepo(root, {});
    for (let i = 0; i < 205; i++) {
      const dir = path.join(root, 'rs', `m${i}`);
      fs.mkdirSync(dir, { recursive: true });
      for (let j = 0; j < 100; j++) fs.writeFileSync(path.join(dir, `f${j}.rs`), 'fn main() {}\n');
    }
    const r = await inspectDocument(root, { home, timeoutMs: 600_000 });
    common(r, home, root, [], { timeoutMs: 600_000 });
    assert.equal(collector(r.doc, 'files').status, 'truncated');
    assert.equal(collector(r.doc, 'files').reason, 'item_limit');
    assert.equal(r.doc.files.not_analyzed.length, 20000);
  });

  it('pathological .gitignore (5,000 wildcard patterns) and regex-bait lines: bounded', async () => {
    const { root, home } = setup('regex');
    const pats = [];
    for (let i = 0; i < 5000; i++) pats.push(`**/a*b*c*d*e*f*g*h*i*j*${i}*/**/*.x${i}`);
    const files = { '.gitignore': pats.join('\n') + '\n', 'ok.js': HANDLER(LEAK) };
    for (let i = 0; i < 20; i++) files[`src/abcdefghij${i}/f${i}.js`] = 'const a = 1;\n';
    initRepo(root, files);
    // Lines full of secret-rule keywords that never complete a match.
    write(root, 'bait.js', `const s = "${'sk-'.repeat(300000)}";\nconst t = "${'xoxb-1'.repeat(200000)}";\nconst u = "${'AKIA'.repeat(300000)}";\nconst v = "${'hooks.slack.com/services/T'.repeat(50000)}";\n`);
    const r = await inspectDocument(root, { home });
    common(r, home, root);
    assert.ok(r.doc.matches.some((m) => m.path === 'ok.js'));
  });

  // A small app laid out ten folders deep: the time a check takes must stay within what an assistant's tool call can
  // wait for, or the walk must stop with time_limit and say so.
  it('200 small files ten folders deep: finishes within 120 s or reports time_limit', async () => {
    const { root, home } = setup('throughput');
    const files = { 'package.json': '{"dependencies":{"express":"4"}}' };
    for (let i = 0; i < 200; i++) files[`${'abcdefghij'.split('').join('/')}/f${i}.js`] = 'export const a = 1;\n';
    initRepo(root, files);
    const r = await inspectDocument(root, { home, timeoutMs: 600_000 });
    const limited = r.doc && (r.doc.files.not_analyzed.some((x) => x.reason === 'time_limit'));
    assert.ok(r.ms <= 120_000 || limited, `took ${r.ms} ms for 200 files with no time_limit reported`);
  });
});

describe('scale', { skip: process.env.PHISC_BLACKBOX_BIG ? false : 'set PHISC_BLACKBOX_BIG=1 for the 100,000-file run' }, () => {
  it('100,000 files: finishes, bounded, statuses honest', async () => {
    const { root, home } = setup('big');
    initRepo(root, { 'package.json': '{"dependencies":{"express":"4"}}' });
    for (let i = 0; i < 1000; i++) {
      const dir = path.join(root, 'src', `m${i}`);
      fs.mkdirSync(dir, { recursive: true });
      for (let j = 0; j < 100; j++) fs.writeFileSync(path.join(dir, `f${j}.js`), j === 0 ? HANDLER(LEAK) : `export const v${j} = ${j};\n`);
    }
    git(root, 'add', '-A');
    git(root, 'commit', '-q', '-m', 'big');
    const bounds = { timeoutMs: 1_800_000, maxRss: 3e9 };
    const r = await inspectDocument(root, { home, timeoutMs: bounds.timeoutMs });
    common(r, home, root, [], bounds);
    const files = collector(r.doc, 'files');
    if (files.status === 'ok') {
      assert.equal(r.doc.files.analyzed + r.doc.files.not_analyzed.filter((x) => x.kind === 'file').length >= 100000, true,
        `files ok but only ${r.doc.files.analyzed} analysed of 100,001`);
    } else {
      assert.ok(['truncated'].includes(files.status), `files ${files.status}`);
    }
    console.log(`# 100k files: ${r.ms} ms, peak ${r.rss} bytes, files ${files.status}, analysed ${r.doc.files.analyzed}`);
  });
});

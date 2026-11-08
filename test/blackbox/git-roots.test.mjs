// Broken or hostile git metadata (a .git that is a file, a gitdir outside the root, a corrupt or hard-linked index)
// must give honest statuses: no tracked set means files truncated with ignore_unverified, never ok. And the project
// root the host hands over (MCP roots) must be one the inspector can identify, not the whole disk.
import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  tmpdir, rmrf, write, git, initRepo, inspectDocument, inspectStdio, fakeLogin, assertValid, assertNoChildProcess,
  assertNoNetwork, assertBounded, assertHonest, collector,
} from './harness.mjs';

const made = [];
after(() => { for (const p of made) rmrf(p); });
const APP = 'import express from "express";\nconst app = express();\napp.post("/x", (req, res) => {\n  console.log(req.body.ssn);\n  res.json({});\n});\n';

// A repository whose ignored folder gen/ holds a tracked file: only the tracked set can say gen/ is app code.
function repoWithIgnoredTracked(tag) {
  const base = tmpdir(tag); made.push(base);
  const root = path.join(base, 'repo'); const home = path.join(base, 'home');
  fs.mkdirSync(home, { recursive: true });
  initRepo(root, { 'src/app.js': APP, '.gitignore': 'gen/\n' });
  write(root, 'gen/app.js', APP);
  git(root, 'add', '-f', 'gen/app.js');
  git(root, 'commit', '-q', '-m', 'tracked ignored');
  return { base, root, home };
}

const CASES = {
  'corrupt index': ({ root }) => fs.writeFileSync(path.join(root, '.git', 'index'), 'garbage index'),
  'truncated index header': ({ root }) => fs.writeFileSync(path.join(root, '.git', 'index'), Buffer.from('DIRC\0\0\0\x02\0\0\0\x05')),
  '.git is a file with garbage': ({ base, root }) => { fs.renameSync(path.join(root, '.git'), path.join(base, 'moved-git')); fs.writeFileSync(path.join(root, '.git'), 'nonsense\n'); },
  '.git is a file pointing outside the root': ({ base, root }) => { fs.renameSync(path.join(root, '.git'), path.join(base, 'outside-git')); fs.writeFileSync(path.join(root, '.git'), `gitdir: ${path.join(base, 'outside-git')}\n`); },
  '.git is a symlink outside the root': ({ base, root }) => { fs.renameSync(path.join(root, '.git'), path.join(base, 'linked-git')); fs.symlinkSync(path.join(base, 'linked-git'), path.join(root, '.git')); },
  'index is a hard link': ({ base, root }) => fs.linkSync(path.join(root, '.git', 'index'), path.join(base, 'index-link')),
};

describe('git metadata', { concurrency: 3 }, () => {
  for (const [name, breakIt] of Object.entries(CASES)) {
    it(`${name}: no tracked set, so files is not ok and gen/ is ignored_unverified`, async () => {
      const ctx = repoWithIgnoredTracked('git');
      breakIt(ctx);
      const r = await inspectDocument(ctx.root, { home: ctx.home });
      assert.equal(r.code, 0, r.stderr.slice(-800));
      assertValid(r.doc); assertHonest(r.doc); assertBounded(r);
      assertNoChildProcess(r.events); assertNoNetwork(r.events);
      const g = collector(r.doc, 'git');
      assert.notEqual(g.status, 'ok', 'git ok from broken metadata');
      const files = collector(r.doc, 'files');
      const genAnalysed = r.doc.matches.some((m) => m.path === 'gen/app.js');
      if (!genAnalysed) {
        assert.equal(files.status, 'truncated', `files ${files.status} though ignored gen/ couldn't be checked against the tracked set`);
        assert.ok(r.doc.files.not_analyzed.some((x) => x.path === 'gen' && x.reason === 'ignored_unverified'), 'gen/ not listed as ignored_unverified');
      }
    });
  }
});

describe('project roots', () => {
  it('stdio started outside any repository refuses to inspect', async () => {
    const base = tmpdir('noroot'); made.push(base);
    const home = path.join(base, 'home'); const dir = path.join(base, 'plain');
    fs.mkdirSync(home); write(dir, 'a.js', APP);
    await fakeLogin(home);
    const r = await inspectStdio(dir, { home, timeoutMs: 60_000 });
    assert.ok(!r.timedOut);
    assert.equal(r.evaluate.length, 0, 'a fact document was built for a folder that is not a project');
  });

  it('an MCP root of "/" is refused or bounded, never a walk of the whole disk', async () => {
    const base = tmpdir('slashroot'); made.push(base);
    const home = path.join(base, 'home'); const repo = path.join(base, 'repo');
    fs.mkdirSync(home); initRepo(repo, { 'a.js': APP });
    await fakeLogin(home);
    const r = await inspectStdio(repo, { home, timeoutMs: 120_000, roots: [{ uri: 'file:///', name: 'disk' }] });
    assert.ok(!r.timedOut, 'no answer within 120 s: the inspector is walking the whole disk');
    assert.equal(r.evaluate.length, 0, 'a fact document was built with / as the project root');
  });

  it('an MCP root that is a plain folder (no repository) is identified as a project or refused, honestly', async () => {
    const base = tmpdir('plainroot'); made.push(base);
    const home = path.join(base, 'home'); const repo = path.join(base, 'repo'); const plain = path.join(base, 'plain');
    fs.mkdirSync(home); initRepo(repo, { 'a.js': APP }); write(plain, 'b.js', APP);
    await fakeLogin(home);
    const r = await inspectStdio(repo, { home, timeoutMs: 120_000, roots: [{ uri: pathToFileURL(plain).href, name: 'plain' }] });
    assertBounded(r, { timeoutMs: 120_000 });
    for (const e of r.evaluate) {
      assertValid(e.body.fact_document);
      assert.notEqual(collector(e.body.fact_document, 'git').status, 'ok');
    }
  });
});

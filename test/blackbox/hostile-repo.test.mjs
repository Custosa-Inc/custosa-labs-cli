// Hostile repository: symlinks out of the root, a malicious git config and .gitattributes, nested repositories,
// odd and secret-bearing file names, binary and NUL files, CRLF and CR line endings, Unicode tricks.
// One repository, one `custosa inspect --document` run, many promises checked against it.
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {
  tmpdir, rmrf, write, git, initRepo, inspectDocument, assertValid, assertNoCanary, assertNoChildProcess,
  assertNoNetwork, assertWritesConfined, assertBounded, assertHonest, assertPathsInsideRoot, collector, docText, canary,
} from './harness.mjs';

const VIOLATION_JS = (tag) => `import express from "express";\nconst app = express();\napp.post("/${tag}", (req, res) => {\n  console.log(req.body.ssn);\n  res.json({ ok: true });\n});\nexport default app;\n`;

const C = {
  code: canary('code'),
  value: canary('value'),
  email: `jane.${canary('mail').toLowerCase()}@example.com`,
  outside: canary('outside'),
  nested: canary('nested'),
  env: canary('env'),
  pwned: canary('pwned'),
};
// Secrets in formats the shipped secret rules recognise, each carrying a canary.
const S = {
  app: `sk\x5flive_${canary('sapp')}abcdefghijklmnop`,
  outside: `sk\x5flive_${canary('sout')}abcdefghijklmnop`,
  nested: `sk\x5flive_${canary('snest')}abcdefghijklmnop`,
  env: `sk\x5flive_${canary('senv')}abcdefghijklmnop`,
  bin: `sk\x5flive_${canary('sbin')}abcdefghijklmnop`,
  crlf: `sk\x5flive_${canary('scrlf')}abcdefghijklmnop`,
  cr: `sk\x5flive_${canary('scr')}abcdefghijklmnop`,
  filename: `sk\x5flive_${canary('sfile')}abcdefghijklmnop`,
  filename2: `sk\x5flive_${canary('sfiletwo')}abcdefghijklmnop`,
  gitdir: `sk\x5flive_${canary('sgitdir')}abcdefghijklmnop`,
  table: `sk\x5flive_${canary('stable')}abcdefgh`,
  include: `sk\x5flive_${canary('sinc')}abcdefghijklmnop`,
};

let base; let root; let outside; let home; let r; let doc; let pwnedMarker;

before(async () => {
  base = tmpdir('hostile');
  root = path.join(base, 'repo');
  outside = path.join(base, 'outside');
  home = path.join(base, 'home');
  fs.mkdirSync(home);
  pwnedMarker = path.join(base, `PWNED-${C.pwned}`);
  const touch = `touch ${pwnedMarker}`;

  // Outside the root: code with a violation and a secret, and a git config include file.
  write(outside, 'leak.js', `${VIOLATION_JS('outside')}const k = "${S.outside}"; // ${C.outside}\n`);
  write(outside, 'evil.gitconfig', `[core]\n\tfsmonitor = ${touch}\n# ${S.include}\n`);

  initRepo(root, {
    'package.json': '{"name":"hostile","dependencies":{"express":"4.19.2"}}\n',
    'src/app.js': `${VIOLATION_JS('app')}const greeting = "${C.code}";\nconst who = "${C.email}";\nconst stripe = "${S.app}";\n// ${C.value}\n`,
    '.gitignore': 'node_modules/\nignored_tracked.js\n',
    '.gitattributes': '* filter=evil diff=evil merge=evil\n*.js text eol=crlf filter=evil\n',
    'vendor/lib.js': VIOLATION_JS('vendor'),
    'src/crlf.js': ['// one', '// two', '// three', '// four', `const k = "${S.crlf}";`, ''].join('\r\n'),
    'src/cr.js': ['// one', '// two', '// three', '// four', `const k = "${S.cr}";`, ''].join('\r'),
    [`patients/${C.email}.csv`]: 'id\n1\n',
    [`config/${S.filename}.json`]: '{"a":1}\n',
    [`docs/${S.filename2}.txt`]: 'notes\n',
    // A secret-shaped string literal where a rule captures a table name: a code value, not a name.
    'src/purge.js': `export async function softDelete(db) {\n  await db.from("${S.table}").update({ deleted_at: new Date() });\n}\n`,
    'src/bin.js': Buffer.concat([Buffer.from(`const k = "${S.bin}";\n`), Buffer.from([0, 0, 1, 2, 0, 255, 254]), Buffer.from('\nconsole.log(1)\n')]),
  });
  write(root, 'ignored_tracked.js', VIOLATION_JS('ignoredtracked'));
  git(root, 'add', '-f', 'ignored_tracked.js');
  git(root, 'commit', '-q', '-m', 'force-add an ignored file');

  // Untracked dependency folder (ignored).
  write(root, 'node_modules/pkg/index.js', VIOLATION_JS('nm'));
  // .env with a secret: name only, contents never read.
  write(root, '.env', `STRIPE_KEY=${S.env}\nNOTE=${C.env}\n`);
  // Nested repository with its own secret.
  initRepo(path.join(root, 'packages', 'inner'), { 'inner.js': `const k = "${S.nested}"; // ${C.nested}\n` });
  // Symlinks: out of the root (dir, file, absolute), loops, device, broken, inside.
  fs.symlinkSync('../outside', path.join(root, 'link_out_dir'));
  fs.symlinkSync('../outside/leak.js', path.join(root, 'link_out_file.js'));
  fs.symlinkSync(outside, path.join(root, 'link_abs_dir'));
  fs.symlinkSync('/etc', path.join(root, 'link_etc'));
  fs.symlinkSync('.', path.join(root, 'link_loop'));
  fs.symlinkSync('loopb', path.join(root, 'loopa'));
  fs.symlinkSync('loopa', path.join(root, 'loopb'));
  fs.symlinkSync('/dev/zero', path.join(root, 'zero.js'));
  fs.symlinkSync('/dev/urandom', path.join(root, 'src', 'random.js'));
  fs.symlinkSync('does-not-exist.js', path.join(root, 'broken.js'));
  fs.symlinkSync('src/app.js', path.join(root, 'link_in.js'));
  // Unicode and odd names, each holding the same violation.
  const odd = ['pätient.js', 'é.js', '‮gnp.js', 'zw​j.js', 'new\nline.js', 'colon:1.js', 'sp ace.js', 'ａpp.js'];
  for (const n of odd) write(root, path.join('odd', n), VIOLATION_JS('odd'));
  git(root, 'add', '-A', 'odd', 'link_in.js');
  git(root, 'commit', '-q', '-m', 'odd names');

  // Malicious git configuration: every command-running key, hooks, an include outside the root and a worktree
  // pointing outside. A pure-JS reader must run none of it and read nothing outside the root.
  const cfg = path.join(root, '.git', 'config');
  fs.appendFileSync(cfg, [
    '[core]', `\tfsmonitor = ${touch}`, `\tpager = ${touch}`, `\tsshCommand = ${touch}`, '\thooksPath = .git/evilhooks',
    `\teditor = ${touch}`, `\taskPass = ${touch}`,
    '[filter "evil"]', `\tclean = ${touch}`, `\tsmudge = ${touch}`, `\tprocess = ${touch}`, '\trequired = true',
    '[diff "evil"]', `\ttextconv = ${touch}`, `\tcommand = ${touch}`,
    '[merge "evil"]', `\tdriver = ${touch}`,
    '[diff]', `\texternal = ${touch}`,
    '[gpg]', `\tprogram = ${touch}`,
    '[credential]', `\thelper = !${touch}`,
    '[include]', `\tpath = ${path.join(outside, 'evil.gitconfig')}`,
    '[alias]', `\tst = !${touch}`,
    '',
  ].join('\n'));
  for (const hook of ['pre-commit', 'post-checkout', 'post-index-change', 'fsmonitor-watchman', 'reference-transaction', 'post-merge']) {
    for (const dir of ['hooks', 'evilhooks']) write(path.join(root, '.git'), path.join(dir, hook), `#!/bin/sh\n${touch}\n`, 0o755);
  }

  // Files planted inside .git itself: version-control metadata must be listed, never read.
  write(path.join(root, '.git'), 'info/evil.js', `${VIOLATION_JS('gitdir')}const k = "${S.gitdir}";\n`);

  r = await inspectDocument(root, { home });
  doc = r.doc;
});

after(() => rmrf(base));

describe('hostile repository', () => {
  it('produces a document that validates against the fact document schema', () => {
    assert.equal(r.code, 0, `exit ${r.code}: ${r.stderr.slice(-1500)}`);
    assertValid(doc);
  });

  it('stays within time and memory', () => assertBounded(r));

  it('runs no child process and nothing from git config, hooks or .gitattributes filters', () => {
    assertNoChildProcess(r.events);
    assert.ok(!fs.existsSync(pwnedMarker), 'a git hook, filter, fsmonitor or pager ran');
  });

  it('makes no network connection and writes only inside its own folders', () => {
    assertNoNetwork(r.events);
    assertWritesConfined(r.events, home);
  });

  it('sends no secret, code, value or outside content (canaries)', () => {
    const text = docText(doc);
    assertNoCanary(text, [C.code, C.value, C.outside, C.nested, C.env, C.pwned, S.app, S.outside, S.nested, S.env, S.bin, S.crlf, S.cr, S.include], 'document');
  });

  it('keeps the statuses honest', () => assertHonest(doc));

  it('names only paths inside the root', () => assertPathsInsideRoot(doc, root));

  it('never follows a symlink out of the root and reports each one', () => {
    for (const p of ['link_out_dir', 'link_out_file.js', 'link_abs_dir', 'link_etc', 'zero.js', 'src/random.js']) {
      const e = doc.files.not_analyzed.find((x) => x.path === p);
      assert.ok(e, `symlink ${p} not reported in files.not_analyzed`);
      assert.ok(['symlink_outside_root', 'symlink', 'not_regular_file'].includes(e.reason), `${p} reported as ${e.reason}`);
    }
    for (const p of ['loopa', 'loopb', 'broken.js']) {
      assert.ok(doc.files.not_analyzed.some((x) => x.path === p), `symlink ${p} not reported`);
    }
    assert.ok(!doc.matches.some((m) => m.path.startsWith('link_') || m.path.startsWith('link_out')), 'a match came through a symlink out of the root');
  });

  it('records the .env file by name and never its secret', () => {
    assert.ok(doc.files.env_files.some((e) => e.path === '.env'), '.env is not listed');
    assert.ok(!doc.secrets.some((s) => s.path === '.env'), 'a secret was reported from .env, so its contents were read');
  });

  it('reports the nested repository as a nested root, not as an excluded or analysed folder', () => {
    const e = doc.files.not_analyzed.find((x) => x.path === 'packages/inner');
    assert.ok(e, 'packages/inner not listed');
    assert.equal(e.reason, 'embedded_git_dir');
    assert.ok(!doc.files.not_analyzed.some((x) => x.path === 'packages/inner/.git' && x.reason === 'excluded_directory'), 'a nested .git is listed as excluded_directory');
    assert.ok(!doc.matches.some((m) => m.path.startsWith('packages/inner/')), 'the nested repository was analysed as part of this root');
  });

  it('lists the untracked dependency folder as excluded with tracked no', () => {
    const e = doc.files.not_analyzed.find((x) => x.path === 'node_modules');
    assert.ok(e, 'node_modules not listed');
    assert.equal(e.reason, 'excluded_directory');
    assert.equal(e.tracked, 'no');
  });

  it('walks a tracked folder with an excluded name (vendor) or reports it as blocking', () => {
    const walked = doc.matches.some((m) => m.path === 'vendor/lib.js');
    const listed = doc.files.not_analyzed.find((x) => x.path === 'vendor');
    assert.ok(walked || (listed && listed.tracked !== 'no'), `tracked vendor/ neither analysed nor listed as blocking: ${JSON.stringify(listed)}`);
  });

  it('analyses a tracked file even though .gitignore matches it', () => {
    assert.ok(doc.matches.some((m) => m.path === 'ignored_tracked.js'), 'tracked-but-ignored file has no match: it was skipped');
  });

  it('git collector stays honest under a malicious config (ok only with the tracked set read)', () => {
    const g = collector(doc, 'git');
    assert.ok(['ok', 'failed', 'truncated'].includes(g.status), `git ${g.status}`);
    if (g.status !== 'ok') {
      for (const e of doc.files.not_analyzed.filter((x) => x.kind === 'directory')) assert.equal(e.tracked, 'not_checked');
    }
  });

  it('a .js file with NUL bytes is not counted as analysed, and its secret is found or the secret scan says so', () => {
    const e = doc.files.not_analyzed.find((x) => x.path === 'src/bin.js');
    assert.ok(e, 'src/bin.js (NUL bytes) is neither listed nor flagged: it was counted as analysed');
    const found = doc.secrets.some((s) => s.path === 'src/bin.js');
    const sec = collector(doc, 'secrets');
    assert.ok(found || sec.status !== 'ok', `secret in a NUL-bearing source file was missed while the secrets collector says ok (reason ${e.reason})`);
  });

  it('reports CRLF line numbers correctly', () => {
    const s = doc.secrets.find((x) => x.path === 'src/crlf.js');
    assert.ok(s, 'secret in CRLF file not found');
    assert.equal(s.line, 5);
  });

  it('reports CR-only line numbers consistently (secret on the fifth line)', () => {
    const s = doc.secrets.find((x) => x.path === 'src/cr.js');
    assert.ok(s, 'secret in CR-only file not found');
    assert.equal(s.line, 5);
  });

  it('hashes odd and Unicode path segments and still analyses those files', () => {
    const oddMatches = doc.matches.filter((m) => m.path.startsWith('odd/'));
    const oddSkipped = doc.files.not_analyzed.filter((x) => x.path.startsWith('odd/'));
    for (const m of oddMatches) assert.match(m.path, /^odd\/u_[0-9a-f]{16}$/, `odd name sent unhashed: ${m.path}`);
    const files = new Set([...oddMatches.map((m) => m.path), ...oddSkipped.map((x) => x.path)]);
    assert.equal(files.size, 8, `expected all 8 odd-named files accounted for (matched or listed), got ${files.size}`);
  });

  it('never sends a secret that appears in a file name', () => {
    const text = docText(doc);
    assert.ok(!text.includes(S.filename), 'a JSON file named after a live Stripe key is sent verbatim');
    assert.ok(!text.includes(S.filename2), 'a text file named after a live Stripe key is sent verbatim (files.not_analyzed path)');
  });

  // The spec accepts names being sent ("If a name is itself sensitive, rename it"), so this is a documented residual
  // risk rather than a broken promise; kept as todo so the behaviour stays visible.
  // A path segment the evaluator's value screen would refuse is hashed before sending.
  it('never sends a record value (an email address) that appears in a file name', () => {
    assert.ok(!docText(doc).includes(C.email), 'a file name holding an email address is sent verbatim');
  });

  it('never reads or analyses files inside .git (listed, never read)', () => {
    const inGit = (p) => p === '.git' || p.startsWith('.git/');
    assert.ok(!doc.matches.some((m) => inGit(m.path)), 'a structural rule matched a file inside .git');
    assert.ok(!doc.secrets.some((x) => inGit(x.path)), 'the secret scan read a file inside .git');
    const under = doc.files.not_analyzed.filter((x) => x.path.startsWith('.git/'));
    assert.deepEqual(under, [], 'the walk descended into .git and listed files there');
  });

  it('never sends a secret-shaped string literal captured as a table name', () => {
    assert.ok(!docText(doc).includes(S.table), 'a string literal holding a live Stripe key is sent as matches[].table');
  });

  it('a truncated secrets collector uses one of the contract\'s secrets reasons', () => {
    const sec = collector(doc, 'secrets');
    if (sec.status === 'truncated') {
      assert.ok(['scan_error', 'joined_view_budget', 'bad_input', 'unreadable', 'match_cut_at_window'].includes(sec.reason),
        `secrets truncated with ${sec.reason}, outside enums.SECRETS_TRUNCATED_REASONS (rule_bundle.md section 6)`);
    }
  });

  it('finds the secret in the ordinary source file', () => {
    assert.ok(doc.secrets.some((s) => s.path === 'src/app.js'), 'stripe key in src/app.js not found');
  });
});

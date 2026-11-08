// A missing or broken sign-in, an unparsable supabase/config.toml, config.toml entrypoints that leave the root, and
// setup against an unparsable Codex config.toml. Nothing goes over the network: guard.mjs refuses every connection.
import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {
  tmpdir, rmrf, write, initRepo, inspectDocument, inspectStdio, runCli, fakeLogin, assertValid, assertNoChildProcess,
  assertNoNetwork, assertWritesConfined, assertBounded, assertHonest, assertPathsInsideRoot, assertNoCanary, docText, canary,
} from './harness.mjs';

const made = [];
after(() => { for (const p of made) rmrf(p); });
function setup(tag, files = { 'index.js': 'export const a = 1;\n' }) {
  const base = tmpdir(tag); made.push(base);
  const root = path.join(base, 'repo'); const home = path.join(base, 'home');
  fs.mkdirSync(home, { recursive: true });
  initRepo(root, files);
  return { base, root, home };
}
// structuredContent on success; an isError result carries the error as JSON on the text's last line (PC4).
const resultOf = (res) => res?.result?.structuredContent ?? (() => { try { return JSON.parse(String(res?.result?.content?.[0]?.text).split('\n').at(-1)); } catch { return null; } })();

describe('sign-in', { concurrency: 3 }, () => {
  it('missing token: check_schema refuses locally, sends nothing, inspects nothing it would send', async () => {
    const { root, home } = setup('notoken');
    const r = await inspectStdio(root, { home });
    assertBounded(r);
    assertNoNetwork(r.events);
    assertNoChildProcess(r.events);
    assert.equal(r.evaluate.length, 0, 'a fact document was sent without a sign-in');
    const res = resultOf(r.results[0]);
    assert.equal(res?.error, 'sign_in_required', JSON.stringify(r.results[0]).slice(0, 400));
  });

  it('a token file other users can read is refused, never sent', async () => {
    const { root, home } = setup('loosetoken');
    await fakeLogin(home);
    fs.chmodSync(path.join(home, '.config', 'custosa', 'token'), 0o644);
    const r = await inspectStdio(root, { home });
    assertNoNetwork(r.events);
    assert.equal(r.evaluate.length, 0, 'a world-readable token was used');
  });

  it('a token file that is a symlink is refused, never sent', async () => {
    const { base, root, home } = setup('linktoken');
    await fakeLogin(home);
    const tok = path.join(home, '.config', 'custosa', 'token');
    fs.renameSync(tok, path.join(base, 'elsewhere-token'));
    fs.chmodSync(path.join(base, 'elsewhere-token'), 0o600);
    fs.symlinkSync(path.join(base, 'elsewhere-token'), tok);
    const r = await inspectStdio(root, { home });
    assertNoNetwork(r.events);
    assert.equal(r.evaluate.length, 0, 'a symlinked token was used');
  });

  it('garbage token file: refused locally with a sign-in error, no crash', async () => {
    const { root, home } = setup('garbagetoken');
    fs.mkdirSync(path.join(home, '.config', 'custosa'), { recursive: true });
    fs.writeFileSync(path.join(home, '.config', 'custosa', 'token'), Buffer.from([0, 255, 10, 13, 0x7b]), { mode: 0o600 });
    const r = await inspectStdio(root, { home });
    assertBounded(r);
    assertNoNetwork(r.events);
    assert.equal(r.evaluate.length, 0);
    assert.ok(/sign_in/.test(resultOf(r.results[0])?.error ?? ''), JSON.stringify(r.results[0]).slice(0, 300));
  });

  it('--document needs no token and makes no request', async () => {
    const { root, home } = setup('docnotoken');
    const r = await inspectDocument(root, { home });
    assert.equal(r.code, 0);
    assertValid(r.doc);
    assertNoNetwork(r.events);
  });

  it('the sign-in token never appears in the fact document or the MCP responses', async () => {
    const { root, home } = setup('tokenleak');
    await fakeLogin(home);
    const token = fs.readFileSync(path.join(home, '.config', 'custosa', 'token'), 'utf8').trim();
    const r = await inspectStdio(root, { home });
    assert.ok(r.evaluate.length >= 1, 'no request captured');
    const tokenValue = token.match(/bbfaketoken_[0-9A-Za-z]+/)?.[0] ?? token;
    assertNoCanary(r.evaluate.map((e) => e.raw).join('\n'), [tokenValue], 'evaluator body');
    assertNoCanary(JSON.stringify(r.responses) + r.stderr, [tokenValue], 'MCP output');
  });
});

describe('supabase/config.toml', { concurrency: 3 }, () => {
  it('unparsable config.toml: edge_functions failed with parse_failed, no items', async () => {
    const { root, home } = setup('badtoml', { 'supabase/config.toml': '[functions.hello\nverify_jwt = = true\n"unterminated\n' });
    const r = await inspectDocument(root, { home });
    assert.equal(r.code, 0, r.stderr.slice(-800));
    assertValid(r.doc); assertHonest(r.doc); assertBounded(r);
    assert.equal(r.doc.supabase.edge_functions.status, 'failed');
    assert.equal(r.doc.supabase.edge_functions.reason, 'parse_failed');
    assert.deepEqual(r.doc.supabase.edge_functions.items, []);
  });

  it('one good and one unparsable config.toml: still failed, never a partial ok', async () => {
    const { root, home } = setup('mixedtoml', {
      'supabase/config.toml': '[functions.good]\nverify_jwt = false\n',
      'apps/b/supabase/config.toml': '[functions.bad\n',
    });
    const r = await inspectDocument(root, { home });
    assertValid(r.doc);
    assert.equal(r.doc.supabase.edge_functions.status, 'failed');
    assert.deepEqual(r.doc.supabase.edge_functions.items, []);
  });

  it('config.toml with a [functions] table of the wrong shape: failed, parse_failed', async () => {
    const { root, home } = setup('shapetoml', { 'supabase/config.toml': 'functions = "nope"\n' });
    const r = await inspectDocument(root, { home });
    assertValid(r.doc);
    assert.equal(r.doc.supabase.edge_functions.status, 'failed');
  });

  it('entrypoints that leave the root are null, never followed or sent', async () => {
    const secretName = canary('entry');
    const { base, root, home } = setup('entrytoml', {
      'supabase/config.toml': [
        '[functions.up]', 'entrypoint = "../../../outside/evil.ts"',
        '[functions.abs]', 'entrypoint = "/etc/passwd"',
        `[functions.${secretName}]`, `entrypoint = "./functions/${secretName}/index.ts"`,
        '[functions.ok]', 'verify_jwt = true',
        '',
      ].join('\n'),
    });
    write(base, 'outside/evil.ts', 'export default 1;\n');
    const r = await inspectDocument(root, { home });
    assert.equal(r.code, 0, r.stderr.slice(-800));
    assertValid(r.doc); assertPathsInsideRoot(r.doc, root);
    const items = r.doc.supabase.edge_functions.items;
    const byName = Object.fromEntries(items.map((i) => [i.name, i]));
    for (const n of ['up', 'abs']) {
      assert.ok(byName[n], `function ${n} missing`);
      assert.equal(byName[n].entrypoint, null, `${n} entrypoint ${byName[n].entrypoint} should be null`);
    }
    assert.equal(byName.ok.entrypoint, 'supabase/functions/ok/index.ts');
    assert.ok(!docText(r.doc).includes('outside/evil'), 'an outside path was sent');
  });

  it('config.toml values other than function names, entrypoints and verify_jwt are never sent', async () => {
    const v = canary('tomlvalue');
    const { root, home } = setup('valtoml', {
      'supabase/config.toml': `project_id = "${v}"\n[auth]\nsite_url = "https://${v}.example.com"\n[functions.f]\nverify_jwt = true\nimport_map = "./${v}.json"\n[functions.f.env]\nSECRET = "sk\x5flive_${v}abcdefghijklmnopqrstuv"\n`,
    });
    const r = await inspectDocument(root, { home });
    assertValid(r.doc);
    assertNoCanary(docText(r.doc), [v], 'document');
  });
});

describe('setup', () => {
  it('setup with an unparsable ~/.codex/config.toml leaves it exactly as it was', async () => {
    const base = tmpdir('setupcodex'); made.push(base);
    const home = path.join(base, 'home');
    const codexCfg = path.join(home, '.codex', 'config.toml');
    const original = '[mcp_servers.other\ncommand = "x"\n# unparsable on purpose\n= = =\n';
    write(home, '.codex/config.toml', original);
    const r = await runCli(['setup', '--client', 'codex', '--yes'], { home, timeoutMs: 60_000 });
    assert.ok(!r.timedOut, 'setup hung');
    assertNoNetwork(r.events);
    assert.equal(fs.readFileSync(codexCfg, 'utf8'), original, 'setup rewrote an unparsable config.toml');
    assert.ok(!/at .*\.mjs:\d+/.test(r.stderr), `setup crashed with a stack trace: ${r.stderr.slice(-600)}`);
  });

  it('setup --dry-run changes nothing in HOME', async () => {
    const base = tmpdir('setupdry'); made.push(base);
    const home = path.join(base, 'home');
    write(home, '.cursor/mcp.json', '{"mcpServers":{}}\n');
    const r = await runCli(['setup', '--dry-run', '--yes'], { home, timeoutMs: 60_000 });
    assert.ok(!r.timedOut);
    assertNoNetwork(r.events);
    assert.equal(fs.readFileSync(path.join(home, '.cursor/mcp.json'), 'utf8'), '{"mcpServers":{}}\n');
    const writes = r.events.filter((e) => e.kind === 'write' && !e.path.startsWith(path.join(home, 'tmp')));
    assert.deepEqual(writes, [], `--dry-run wrote: ${JSON.stringify(writes).slice(0, 400)}`);
  });
});

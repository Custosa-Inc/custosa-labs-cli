// Black-box harness for the custosa local inspector. Written from the spec, the contracts and the CLI's help only.
// It runs the real CLI (`custosa inspect --document <dir>` and `custosa inspect --stdio`) in a child process with
// guard.mjs preloaded, a throwaway HOME, and a minimal environment, and measures wall time and peak memory.
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import assert from 'node:assert/strict';

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));
export const CLI_DIR = path.resolve(here, '..', '..');
export const BIN = path.join(CLI_DIR, 'bin', 'custosa.mjs');
export const GUARD = path.join(here, 'guard.mjs');
// The shipped contract schema (no test copy to go stale); PHISC_FACT_SCHEMA may point at another.
const SCHEMA_PATH = process.env.PHISC_FACT_SCHEMA || path.join(CLI_DIR, 'lib', 'inspector', 'contracts', 'fact_document.schema.json');

const Ajv2020 = require('ajv/dist/2020.js').default;
const ajv = new Ajv2020({ strict: false, allErrors: true });
const validateFn = ajv.compile(JSON.parse(fs.readFileSync(SCHEMA_PATH, 'utf8')));

// Defaults for "bounded time and memory". The spec gives no numbers; these are generous on purpose, so a failure
// means unbounded behaviour, not a slow machine.
export const DEFAULT_TIMEOUT_MS = Number(process.env.PHISC_BB_TIMEOUT_MS || 180_000);
export const DEFAULT_MAX_RSS = Number(process.env.PHISC_BB_MAX_RSS || 1_500_000_000);

export function tmpdir(tag) {
  const base = process.env.PHISC_BB_TMP || os.tmpdir();
  return fs.mkdtempSync(path.join(fs.realpathSync(base), `phisc-bb-${tag}-`));
}

export function rmrf(p) {
  if (!p || !p.includes('phisc-bb-') || process.env.PHISC_BB_KEEP) return; // only ever our own temp folders
  try {
    spawnSync('chmod', ['-R', 'u+rwx', p]);
    fs.rmSync(p, { recursive: true, force: true });
  } catch { /* best effort */ }
  // Folders nested past PATH_MAX defeat fs.rmSync; rm -rf walks them relatively.
  if (fs.existsSync(p)) spawnSync('rm', ['-rf', p]);
}

export function write(root, rel, content, mode) {
  const p = path.join(root, rel);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, content);
  if (mode !== undefined) fs.chmodSync(p, mode);
  return p;
}

export function git(cwd, ...args) {
  const r = spawnSync('git', ['-c', 'user.email=bb@example.invalid', '-c', 'user.name=bb', '-c', 'commit.gpgsign=false',
    '-c', 'core.hooksPath=/dev/null', ...args], { cwd, encoding: 'utf8' });
  if (r.status !== 0) throw new Error(`git ${args.join(' ')} failed: ${r.stderr}`);
  return r.stdout;
}

export function initRepo(root, files = {}, { commit = true } = {}) {
  fs.mkdirSync(root, { recursive: true });
  git(root, 'init', '-q', '-b', 'main');
  for (const [rel, content] of Object.entries(files)) write(root, rel, content);
  if (commit && Object.keys(files).length) {
    git(root, 'add', '-A');
    git(root, 'commit', '-q', '-m', 'init');
  }
  return root;
}

export function makeHome(tag = 'home') {
  const home = tmpdir(tag);
  return home;
}

function baseEnv(home, extra = {}) {
  return {
    PATH: '/usr/bin:/bin',
    HOME: home,
    LANG: 'C',
    TMPDIR: path.join(home, 'tmp'),
    ...extra,
  };
}

function parseRss(stderrText) {
  // macOS /usr/bin/time -l prints "<n>  maximum resident set size" (bytes); GNU time -v prints kbytes.
  const mac = stderrText.match(/(\d+)\s+maximum resident set size/);
  if (mac) return Number(mac[1]);
  const gnu = stderrText.match(/Maximum resident set size \(kbytes\):\s*(\d+)/);
  if (gnu) return Number(gnu[1]) * 1024;
  return null;
}

function timeArgs() {
  if (process.platform === 'darwin') return ['/usr/bin/time', ['-l']];
  if (fs.existsSync('/usr/bin/time')) return ['/usr/bin/time', ['-v']];
  return [null, []];
}

// /usr/bin/time wraps node, so a timeout kills the whole process group, never just the wrapper.
function killGroup(child) {
  try { process.kill(-child.pid, 'SIGKILL'); } catch { try { child.kill('SIGKILL'); } catch { /* gone */ } }
}

function readEvents(logPath) {
  if (!fs.existsSync(logPath)) return [];
  return fs.readFileSync(logPath, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
}

// Runs a CLI command under guard and /usr/bin/time. Resolves with everything a test needs.
export function runCli(args, { home, cwd, timeoutMs = DEFAULT_TIMEOUT_MS, env = {}, input = null, guard = true } = {}) {
  fs.mkdirSync(path.join(home, 'tmp'), { recursive: true });
  const logPath = path.join(home, `guard-${Date.now()}-${Math.random().toString(16).slice(2)}.jsonl`);
  const nodeArgs = [...(guard ? ['--import', GUARD] : []), BIN, ...args];
  const [timeBin, timeFlags] = timeArgs();
  const cmd = timeBin ?? process.execPath;
  const cmdArgs = timeBin ? [...timeFlags, process.execPath, ...nodeArgs] : nodeArgs;
  return new Promise((resolve) => {
    const started = Date.now();
    const child = spawn(cmd, cmdArgs, { cwd: cwd ?? home, env: baseEnv(home, { PHISC_BB_LOG: logPath, ...env }), stdio: ['pipe', 'pipe', 'pipe'], detached: true });
    const out = []; const err = [];
    child.stdout.on('data', (d) => out.push(d));
    child.stderr.on('data', (d) => err.push(d));
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; killGroup(child); }, timeoutMs);
    if (input !== null) child.stdin.end(input); else child.stdin.end();
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      const stdout = Buffer.concat(out).toString('utf8');
      const stderrAll = Buffer.concat(err).toString('utf8');
      const rss = parseRss(stderrAll);
      const stderr = timeBin ? stderrAll.replace(/\n\s+\d+\s+[a-z][a-z ()/-]+$/gm, '').replace(/^\s+[\d.]+ real.*$/m, '') : stderrAll;
      resolve({ code, signal, timedOut, ms: Date.now() - started, rss, stdout, stderr, events: readEvents(logPath) });
    });
  });
}

export async function inspectDocument(dir, opts = {}) {
  const r = await runCli(['inspect', '--document', dir], opts);
  let parsed = null;
  try { parsed = JSON.parse(r.stdout); } catch { /* left null */ }
  return { ...r, parsed, doc: parsed?.document ?? null };
}

// A minimal MCP client over stdio. calls: list of tools/call argument objects, sent together (concurrently) after
// initialize. Returns the JSON-RPC responses by id and the evaluator requests guard.mjs captured.
export function inspectStdio(cwd, { home, calls = [{ goal: 'check' }], timeoutMs = DEFAULT_TIMEOUT_MS, env = {}, sequential = false, roots = null } = {}) {
  fs.mkdirSync(path.join(home, 'tmp'), { recursive: true });
  const logPath = path.join(home, `guard-${Date.now()}-${Math.random().toString(16).slice(2)}.jsonl`);
  const [timeBin, timeFlags] = timeArgs();
  const nodeArgs = ['--import', GUARD, BIN, 'inspect', '--stdio'];
  const cmd = timeBin ?? process.execPath;
  const cmdArgs = timeBin ? [...timeFlags, process.execPath, ...nodeArgs] : nodeArgs;
  return new Promise((resolve) => {
    const started = Date.now();
    const child = spawn(cmd, cmdArgs, { cwd, env: baseEnv(home, { PHISC_BB_LOG: logPath, ...env }), stdio: ['pipe', 'pipe', 'pipe'], detached: true });
    let buf = ''; const responses = {}; const err = [];
    const want = new Set(calls.map((_, i) => 100 + i));
    let timedOut = false;
    const finish = () => { try { child.stdin.end(); } catch { /* closed */ } };
    child.stdout.on('data', (d) => {
      buf += d;
      let i;
      while ((i = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, i); buf = buf.slice(i + 1);
        if (!line.trim()) continue;
        let msg; try { msg = JSON.parse(line); } catch { responses.garbage = (responses.garbage ?? '') + line; continue; }
        if (msg.method) { // a request or notification from the server
          if (msg.method === 'roots/list' && msg.id !== undefined) send({ jsonrpc: '2.0', id: msg.id, result: { roots: roots ?? [] } });
          else if (msg.id !== undefined) send({ jsonrpc: '2.0', id: msg.id, error: { code: -32601, message: 'not supported' } });
          continue;
        }
        if (msg.id !== undefined) { responses[msg.id] = msg; want.delete(msg.id); }
        const call = (k) => send({ jsonrpc: '2.0', id: 100 + k, method: 'tools/call', params: { name: 'check_schema', arguments: calls[k] } });
        if (msg.id === 1) {
          send({ jsonrpc: '2.0', method: 'notifications/initialized' });
          if (sequential) call(0); else calls.forEach((_, k) => call(k));
        } else if (sequential && typeof msg.id === 'number' && msg.id >= 100 && msg.id - 100 + 1 < calls.length) {
          call(msg.id - 100 + 1);
        }
        if (want.size === 0) finish();
      }
    });
    child.stderr.on('data', (d) => err.push(d));
    const send = (m) => child.stdin.write(JSON.stringify(m) + '\n');
    send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: roots ? { roots: { listChanged: false } } : {}, clientInfo: { name: 'phisc-blackbox', version: '1' } } });
    const timer = setTimeout(() => { timedOut = true; killGroup(child); }, timeoutMs);
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      const stderrAll = Buffer.concat(err).toString('utf8');
      const events = readEvents(logPath);
      const evaluate = events.filter((e) => e.kind === 'http' && /\/v1\/evaluate$/.test(e.url)).map((e) => {
        let body = null; try { body = JSON.parse(e.body); } catch { /* raw */ }
        return { raw: e.body, body };
      });
      const results = calls.map((_, k) => responses[100 + k] ?? null);
      resolve({ code, signal, timedOut, ms: Date.now() - started, rss: parseRss(stderrAll), stderr: stderrAll, responses, results, events, evaluate });
    });
  });
}

// Signs in through the real `custosa login`, with guard.mjs answering the device routes locally per
// evaluator_api.md section 3 (nothing leaves the machine), so the token file has its real format.
export async function fakeLogin(home) {
  const r = await runCli(['login'], { home, timeoutMs: 30_000 });
  assert.ok(fs.existsSync(path.join(home, '.config', 'custosa', 'token')), `login stub wrote no token: ${r.stdout}${r.stderr}`);
  return r;
}

export function validate(doc) {
  const ok = validateFn(doc);
  return { ok, errors: ok ? [] : validateFn.errors.slice(0, 10) };
}

export function assertValid(doc, label = 'fact document') {
  assert.ok(doc, `${label}: no document was produced`);
  const { ok, errors } = validate(doc);
  assert.ok(ok, `${label} fails fact_document.schema.json: ${JSON.stringify(errors)}`);
}

// Canaries: every planted secret, value and code fragment must be absent from what the inspector would send.
export function assertNoCanary(text, canaries, label) {
  for (const c of canaries) {
    assert.ok(!text.includes(c), `${label}: carries planted canary ${JSON.stringify(c.slice(0, 24))}...`);
  }
}

export function assertNoChildProcess(events) {
  const cps = events.filter((e) => e.kind === 'child_process');
  assert.deepEqual(cps, [], `the inspector tried to start a child process: ${JSON.stringify(cps)}`);
}

export function assertNoNetwork(events, { allowEvaluate = false } = {}) {
  const bad = events.filter((e) => (e.kind === 'connect' && !/^(127\.0\.0\.1|::1|localhost|::ffff:127\.0\.0\.1|unix:)/.test(e.host))
    || (e.kind === 'dns' && !['localhost', '127.0.0.1', '::1'].includes(e.host))
    || (e.kind === 'http' && !(allowEvaluate && /\/v1\/evaluate$/.test(e.url))));
  assert.deepEqual(bad, [], `network attempt: ${JSON.stringify(bad).slice(0, 600)}`);
}

export function assertWritesConfined(events, home) {
  const allowed = [path.join(home, '.cache', 'custosa'), path.join(home, '.config', 'custosa')];
  const bad = events.filter((e) => e.kind === 'write' && !allowed.some((a) => path.resolve(e.path) === a || path.resolve(e.path).startsWith(a + path.sep)));
  assert.deepEqual(bad, [], `wrote outside ~/.cache/custosa and ~/.config/custosa: ${JSON.stringify(bad).slice(0, 600)}`);
}

export function assertBounded(r, { timeoutMs = DEFAULT_TIMEOUT_MS, maxRss = DEFAULT_MAX_RSS } = {}) {
  assert.ok(!r.timedOut, `did not finish within ${timeoutMs} ms`);
  assert.ok(r.signal === null, `ended by signal ${r.signal}; stderr: ${r.stderr.slice(-800)}`);
  if (r.rss !== null) assert.ok(r.rss <= maxRss, `peak memory ${r.rss} bytes over ${maxRss}`);
}

export const collector = (doc, name) => doc.collection.find((c) => c.collector === name);
export const notAnalyzed = (doc, pred) => doc.files.not_analyzed.filter(pred);

// The invariants every document must keep, whatever the input.
export function assertHonest(doc) {
  const names = doc.collection.map((c) => c.collector).sort();
  assert.deepEqual(names, ['catalog', 'files', 'git', 'platform', 'rules', 'secrets'], 'every collector reports a status');
  const cat = collector(doc, 'catalog');
  if (!['ok', 'truncated'].includes(cat.status)) {
    for (const q of doc.catalog.queries) {
      assert.ok(!['ok', 'truncated'].includes(q.status), `catalog ${cat.status} but query ${q.query_id} is ${q.status}`);
      assert.equal(q.rows.length, 0, `catalog ${cat.status} but query ${q.query_id} carries rows`);
    }
    assert.equal(doc.columns.length, 0, 'no catalog read, yet columns are classified');
  }
  const plat = collector(doc, 'platform');
  if (!['ok', 'empty', 'truncated'].includes(plat.status)) {
    for (const [k, v] of Object.entries(doc.platform.settings)) assert.equal(v, 'not_read', `platform ${plat.status} but ${k} is ${v}`);
  }
  // A truncated or failed collector never sits beside a full count of "analysed" coverage it didn't do.
  const files = collector(doc, 'files');
  if (doc.files.not_analyzed.length >= 20000) assert.equal(files.status, 'truncated', 'not_analyzed hit its cap but files is not truncated');
  if (doc.matches.length >= 20000) assert.equal(collector(doc, 'rules').status, 'truncated', 'matches hit the cap but rules is not truncated');
}

export function docText(doc) { return JSON.stringify(doc); }

// Every path the document names must be under the root: the real file or directory, or a hashed path.
export function assertPathsInsideRoot(doc, root) {
  const paths = [
    ...doc.files.not_analyzed.map((e) => e.path),
    ...doc.files.env_files.map((e) => e.path),
    ...doc.files.data_files.map((e) => e.path),
    ...doc.matches.map((m) => m.path),
    ...doc.secrets.map((s) => s.path),
  ];
  for (const p of paths) {
    assert.ok(!p.startsWith('/') && !p.split('/').includes('..'), `path escapes the root: ${p}`);
    // a hashed segment, with its plain extension kept when it was hashed for a record value
    const hashed = p.split('/').some((seg) => /^u_[0-9a-f]{16}(\.[A-Za-z0-9]{1,8})?$/.test(seg));
    if (!hashed) {
      let exists = false;
      try { fs.lstatSync(path.join(root, p)); exists = true; } catch { /* missing */ }
      assert.ok(exists, `document names a path that isn't in the root: ${p}`);
    }
  }
}

// Plain canary generator. Each one is unique per test so a leak is attributable.
export function canary(tag) {
  return `CANARY${tag.replace(/[^A-Za-z0-9]/g, '')}${Math.random().toString(36).slice(2, 10)}`;
}

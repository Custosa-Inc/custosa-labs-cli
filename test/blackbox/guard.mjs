// Preloaded into the inspector process with `node --import` by the black-box harness. It is not part of the product.
// It records, to the file named by PHISC_BB_LOG (one JSON object per line):
//   - every attempt to start a child process (and makes it fail),
//   - every outbound socket connection (loopback is allowed so the throwaway Postgres works; anything else is refused),
//   - every HTTP request made through fetch, http or https, with its body, answered locally with a canned error so
//     nothing ever leaves this machine.
import fs from 'node:fs';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const LOG = process.env.PHISC_BB_LOG;
const origAppend = fs.appendFileSync;
function log(ev) {
  if (!LOG) return;
  try { origAppend(LOG, JSON.stringify({ pid: process.pid, ...ev }) + '\n'); } catch { /* ignore */ }
}
// Writes: logged (not blocked) so a test can check they stay inside ~/.cache/custosa and ~/.config/custosa.
const WRITE_FLAGS = /[wa+]/;
function isWriteFlag(f) {
  if (f === undefined || f === null) return false;
  if (typeof f === 'number') return (f & (fs.constants.O_WRONLY | fs.constants.O_RDWR | fs.constants.O_CREAT)) !== 0;
  return WRITE_FLAGS.test(String(f));
}
function wrapWrite(obj, name, pathIdx, flagIdx, always) {
  const orig = obj[name];
  if (typeof orig !== 'function') return;
  obj[name] = function wrapped(...args) {
    const p = args[pathIdx];
    if (always || isWriteFlag(args[flagIdx])) {
      const s = typeof p === 'string' ? p : (p instanceof URL ? p.pathname : (Buffer.isBuffer(p) ? p.toString() : null));
      if (s !== null && s !== LOG) log({ kind: 'write', fn: name, path: s.slice(0, 400) });
    }
    return orig.apply(this, args);
  };
}
for (const n of ['open', 'openSync']) wrapWrite(fs, n, 0, 1, false);
for (const n of ['writeFile', 'writeFileSync', 'appendFile', 'mkdir', 'mkdirSync', 'rename', 'renameSync',
  'symlink', 'symlinkSync', 'unlink', 'unlinkSync', 'rm', 'rmSync', 'copyFile', 'copyFileSync', 'createWriteStream',
  'chmod', 'chmodSync', 'truncate', 'truncateSync', 'rmdir', 'rmdirSync']) wrapWrite(fs, n, 0, -1, true);
wrapWrite(fs.promises, 'open', 0, 1, false);
for (const n of ['writeFile', 'appendFile', 'mkdir', 'rename', 'symlink', 'unlink', 'rm', 'copyFile', 'chmod',
  'truncate', 'rmdir']) wrapWrite(fs.promises, n, 0, -1, true);
const cp = require('node:child_process');
const { EventEmitter } = require('node:events');
function enoent(file) {
  const e = new Error(`spawn ${file} ENOENT (black-box guard)`);
  e.code = 'ENOENT'; e.errno = -2; e.syscall = `spawn ${file}`; e.path = String(file);
  return e;
}
// Every attempt is logged; the call then fails as if the program did not exist, so nothing ever runs.
for (const name of ['spawn', 'exec', 'execFile', 'fork']) {
  cp[name] = function guarded(file, ...rest) {
    log({ kind: 'child_process', fn: name, file: String(file).slice(0, 200) });
    const child = new EventEmitter();
    const { PassThrough } = require('node:stream');
    child.stdin = new PassThrough(); child.stdout = new PassThrough(); child.stderr = new PassThrough();
    child.pid = undefined; child.kill = () => false; child.exitCode = null;
    const cb = rest.find((a) => typeof a === 'function');
    process.nextTick(() => {
      const err = enoent(file);
      child.emit('error', err); child.emit('close', -2, null);
      if (cb) cb(err, '', '');
    });
    return child;
  };
}
cp.spawnSync = function guardedSpawnSync(file) {
  log({ kind: 'child_process', fn: 'spawnSync', file: String(file).slice(0, 200) });
  return { pid: 0, output: [null, Buffer.alloc(0), Buffer.alloc(0)], stdout: Buffer.alloc(0), stderr: Buffer.alloc(0),
    status: null, signal: null, error: enoent(file) };
};
for (const name of ['execSync', 'execFileSync']) {
  cp[name] = function guardedSync(file) {
    log({ kind: 'child_process', fn: name, file: String(file).slice(0, 200) });
    throw enoent(file);
  };
}
const LOOPBACK = new Set(['127.0.0.1', '::1', 'localhost', '::ffff:127.0.0.1']);
function hostOf(args) {
  const a = args[0];
  if (Array.isArray(a)) return hostOf(a);
  if (a && typeof a === 'object') return a.path ? `unix:${a.path}` : (a.host ?? 'localhost');
  if (typeof a === 'string' && isNaN(Number(a))) return `unix:${a}`;
  return typeof args[1] === 'string' ? args[1] : 'localhost';
}
const net = require('node:net');
const origConnect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function guardedConnect(...args) {
  const host = hostOf(args);
  log({ kind: 'connect', host: String(host).slice(0, 200) });
  if (!(LOOPBACK.has(host) || String(host).startsWith('unix:'))) {
    const err = new Error(`black-box guard: connection to ${host} refused`);
    err.code = 'ECONNREFUSED';
    process.nextTick(() => this.destroy(err));
    return this;
  }
  return origConnect.apply(this, args);
};
const dns = require('node:dns');
const origLookup = dns.lookup;
dns.lookup = function guardedLookup(hostname, ...rest) {
  log({ kind: 'dns', host: String(hostname).slice(0, 200) });
  if (!LOOPBACK.has(hostname)) {
    const cb = rest[rest.length - 1];
    const err = new Error('black-box guard: dns refused'); err.code = 'ENOTFOUND';
    if (typeof cb === 'function') process.nextTick(() => cb(err));
    return;
  }
  return origLookup.call(this, hostname, ...rest);
};
const CANNED = JSON.stringify({ error: 'internal_error', next_step: 'black-box stub', correlation_id: 'bb' });
const origFetch = globalThis.fetch;
globalThis.fetch = async function guardedFetch(input, init = {}) {
  const url = typeof input === 'string' ? input : (input?.url ?? String(input));
  let body = init.body;
  if (body && typeof body !== 'string') { try { body = Buffer.from(body).toString('utf8'); } catch { body = '[unreadable body]'; } }
  log({ kind: 'http', via: 'fetch', url, method: init.method ?? 'GET', body: body ?? null });
  // The device sign-in routes (evaluator_api.md section 3) are answered per the contract, locally, so `custosa login`
  // can write a token file in its real format without any network.
  if (/\/v1\/device\/start$/.test(url)) {
    return new Response(JSON.stringify({ device_code: 'bb-device-code-0123456789', user_code: 'BBBB-CCCC',
      verification_uri: 'https://login.custosa.com/activate', verification_uri_complete: 'https://login.custosa.com/activate?user_code=BBBB-CCCC',
      expires_in: 600, interval: 1 }), { status: 200, headers: { 'content-type': 'application/json' } });
  }
  if (/\/v1\/device\/poll$/.test(url)) {
    return new Response(JSON.stringify({ access_token: 'bbfaketoken_0123456789abcdefABCDEF0123456789', token_type: 'Bearer' }),
      { status: 200, headers: { 'content-type': 'application/json' } });
  }
  // Scripted evaluator answers (a JSON array file, one per /v1/evaluate call, in order), for tests that need a
  // question to answer; past the end of the script, or without one, the canned error.
  if (/\/v1\/evaluate$/.test(url) && process.env.PHISC_BB_EVAL_SCRIPT) {
    globalThis.__bbEvalN = (globalThis.__bbEvalN ?? 0) + 1;
    let script = [];
    try { script = JSON.parse(fs.readFileSync(process.env.PHISC_BB_EVAL_SCRIPT, 'utf8')); } catch { /* none */ }
    const next = script[globalThis.__bbEvalN - 1];
    if (next) return new Response(JSON.stringify(next), { status: 200, headers: { 'content-type': 'application/json' } });
  }
  return new Response(CANNED, { status: 500, headers: { 'content-type': 'application/json' } });
};
globalThis.fetch.__orig = origFetch;
for (const modName of ['node:http', 'node:https']) {
  const m = require(modName);
  for (const fn of ['request', 'get']) {
    m[fn] = function guardedRequest(...args) {
      const opts = args.find((a) => a && typeof a === 'object' && !(a instanceof URL)) ?? {};
      const url = String(args.find((a) => typeof a === 'string' || a instanceof URL) ?? `${opts.hostname ?? opts.host}${opts.path ?? ''}`);
      const chunks = [];
      const { PassThrough } = require('node:stream');
      const req = new PassThrough();
      req.setHeader = () => {}; req.getHeader = () => undefined; req.removeHeader = () => {};
      req.setTimeout = () => req; req.abort = () => {}; req.flushHeaders = () => {};
      req.on('data', (c) => chunks.push(Buffer.from(c)));
      const origEnd = req.end.bind(req);
      req.end = (...e) => {
        if (e[0] && typeof e[0] !== 'function') chunks.push(Buffer.from(e[0]));
        log({ kind: 'http', via: modName, url, method: opts.method ?? 'GET', body: Buffer.concat(chunks).toString('utf8') });
        process.nextTick(() => req.emit('error', Object.assign(new Error('black-box guard: http refused'), { code: 'ECONNREFUSED' })));
        return origEnd();
      };
      return req;
    };
  }
}

require('node:module').syncBuiltinESMExports();

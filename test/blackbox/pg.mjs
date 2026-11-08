// A throwaway Postgres cluster for the black-box tests: initdb into a temp folder, pg_ctl on a port from 55450,
// statement logging on, deleted afterwards. Admin work goes through psql over the cluster's own socket.
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import { tmpdir, rmrf } from './harness.mjs';

function which(bin) {
  for (const dir of [process.env.PG_BIN, '/opt/homebrew/bin', '/usr/local/bin', '/usr/lib/postgresql/16/bin', '/usr/bin'].filter(Boolean)) {
    const p = path.join(dir, bin);
    if (fs.existsSync(p)) return p;
  }
  return null;
}

export const PG_AVAILABLE = Boolean(which('initdb') && which('pg_ctl') && which('psql'));

async function freePort(start) {
  for (let p = start; p < start + 50; p++) {
    const ok = await new Promise((res) => {
      const s = net.createServer().once('error', () => res(false)).once('listening', () => s.close(() => res(true)));
      s.listen(p, '127.0.0.1');
    });
    if (ok) return p;
  }
  throw new Error('no free port from 55450');
}

export async function startCluster() {
  const base = tmpdir('pg');
  const data = path.join(base, 'data');
  // Unix socket paths are limited to ~103 bytes, so the socket gets its own short folder.
  const sock = fs.mkdtempSync('/tmp/phisc-bb-sock-');
  const port = await freePort(Number(process.env.PHISC_BB_PG_PORT || 55450));
  const run = (bin, args, opts = {}) => {
    const r = spawnSync(which(bin), args, { encoding: 'utf8', env: { ...process.env, LC_ALL: 'C', LANG: 'C' }, ...opts });
    if (r.status !== 0) throw new Error(`${bin} ${args.join(' ')}: ${r.stderr}${r.stdout}`);
    return r.stdout;
  };
  const log = path.join(base, 'postgres.log');
  const cleanup = () => { rmrf(base); rmrf(sock); };
  try {
  run('initdb', ['-D', data, '-U', 'bbadmin', '-A', 'trust', '--no-sync', '-E', 'UTF8', '--locale=C']);
  fs.writeFileSync(path.join(data, 'pg_hba.conf'), [
    'local all bbadmin trust',
    'host all bbadmin 127.0.0.1/32 trust',
    'host all phisc_ro 127.0.0.1/32 scram-sha-256',
    'host all phisc_ro ::1/128 scram-sha-256',
    '',
  ].join('\n'));
  run('pg_ctl', ['-D', data, '-l', log, '-w', '-o',
    `-p ${port} -k ${sock} -c listen_addresses=127.0.0.1 -c log_statement=all -c log_line_prefix='%u|%d|%c| ' -c fsync=off -c track_counts=on`, 'start']);
  } catch (e) { cleanup(); throw e; }
  const psql = (db, sql) => run('psql', ['-h', sock, '-p', String(port), '-U', 'bbadmin', '-d', db, '-v', 'ON_ERROR_STOP=1', '-Atq', '-c', sql]);
  return {
    base, data, sock, port, log, psql,
    stop() {
      try { spawnSync(which('pg_ctl'), ['-D', data, '-m', 'immediate', 'stop'], { encoding: 'utf8' }); } catch { /* ignore */ }
      rmrf(base);
      rmrf(sock);
    },
    statementsBy(user) {
      const text = fs.existsSync(log) ? fs.readFileSync(log, 'utf8') : '';
      return text.split('\n').filter((l) => l.startsWith(`${user}|`));
    },
  };
}

// The connection files the inspector reads, in a throwaway HOME.
export function writeConnectionFiles(home, { host = '127.0.0.1', port, db, user = 'phisc_ro', password, sslmode, pgpassMode = 0o600 }) {
  const service = ['[phisc]', `host=${host}`, `port=${port}`, `dbname=${db}`, `user=${user}`];
  if (sslmode) service.push(`sslmode=${sslmode}`);
  fs.writeFileSync(path.join(home, '.pg_service.conf'), service.join('\n') + '\n', { mode: 0o600 });
  const pgpass = path.join(home, '.pgpass');
  fs.writeFileSync(pgpass, `${host}:${port}:${db}:${user}:${password}\n`);
  fs.chmodSync(pgpass, pgpassMode);
}

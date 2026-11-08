#!/usr/bin/env node
/* Temp-folder guard for the test run: a test run must leave nothing in TMPDIR.
 *
 *   node scripts/tmp-guard.mjs <node args...>     (npm test)  run node with those args, then check
 *
 * It makes an empty folder under the caller's TMPDIR, runs node with TMPDIR (and TMP, TEMP) pointed at it, then lists
 * what is left there. Anything left fails the run (exit 1), with the names printed. The folder is removed either way, so
 * a leaking run never fills the caller's TMPDIR. A failing node run keeps its own exit code.
 *
 * Why: the CLI tests made temp folders and never removed them. On one machine, about 3 GB of them filled a /tmp quota and failed
 * a gate with EDQUOT. test/tmp-sandbox.mjs is the fix; this guard keeps it fixed. */
import { spawn } from "node:child_process";
import { chmodSync, lstatSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SHOW = 20;

/** Remove a folder tree. Some tests chmod a folder to 000 or 500 to test unreadable paths, and rmSync can't empty
 *  those, so on failure give the owner rwx back on every folder and try once more. Symlinks are never followed. */
export function removeTree(dir) {
  try { rmSync(dir, { recursive: true, force: true }); return; } catch { /* opened up below */ }
  const openUp = (d) => {
    try { chmodSync(d, 0o700); } catch { return; }
    let names = [];
    try { names = readdirSync(d); } catch { return; }
    for (const name of names) {
      const p = join(d, name);
      try { if (lstatSync(p).isDirectory()) openUp(p); } catch { /* gone already */ }
    }
  };
  openUp(dir);
  rmSync(dir, { recursive: true, force: true });
}

/** Run node with `args` in a fresh TMPDIR, then list and remove what is left there. Resolves to { status, signal, left }.
 *  SIGINT, SIGTERM and SIGHUP are passed on to node and the guard waits for it, so an interrupted run is cleaned up too. */
export function guard(args) {
  const box = mkdtempSync(join(tmpdir(), "custosa-guard-"));
  return new Promise((done) => {
    const child = spawn(process.execPath, args, { stdio: "inherit", env: { ...process.env, TMPDIR: box, TMP: box, TEMP: box } });
    const forward = (sig) => { try { child.kill(sig); } catch { /* already gone */ } };
    const signals = ["SIGINT", "SIGTERM", "SIGHUP"];
    for (const sig of signals) process.on(sig, forward);
    let finished = false;
    const finish = (status, signal) => {
      if (finished) return;
      finished = true;
      for (const sig of signals) process.off(sig, forward);
      let left = [];
      try { left = readdirSync(box).sort(); } finally { removeTree(box); }
      done({ status, signal, left });
    };
    child.on("error", (err) => { process.stderr.write(`tmp-guard: could not start node: ${err.message}\n`); finish(1, null); });
    child.on("exit", (code, signal) => finish(code ?? 1, signal));
  });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  if (args.length === 0) { process.stderr.write("usage: node scripts/tmp-guard.mjs <node args...>\n"); process.exit(2); }
  const { status, signal, left } = await guard(args);
  if (left.length > 0) {
    const shown = left.slice(0, SHOW).map((n) => `  ${n}\n`).join("");
    const more = left.length > SHOW ? `  ... and ${left.length - SHOW} more\n` : "";
    process.stderr.write(`tmp-guard: the run left ${left.length} entr${left.length === 1 ? "y" : "ies"} in TMPDIR ` +
      `(removed now):\n${shown}${more}Each test must remove what it makes, or run under test/tmp-sandbox.mjs.\n`);
  }
  if (signal) process.stderr.write(`tmp-guard: node stopped on ${signal}\n`);
  process.exit(status !== 0 ? status : left.length > 0 ? 1 : 0);
}

#!/usr/bin/env node
/* npm run test:blackbox: the black-box files two at a time, then resources.test.mjs on its own. Its
 * time-limit cases count how many files finish inside a fixed time, so they must not share the CPU with the database
 * tests. On a CI runner they once did, and the 20,000-match case ran 9 files before its limit (run 41812409438).
 *
 *   node scripts/test-blackbox.mjs [node --test options]   exit 1 if either run fails; both always run */
import { spawnSync } from "node:child_process";
import { readdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const CLI = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const ALONE = ["resources.test.mjs"];

export function blackboxRuns(files) {
  const path = (f) => `test/blackbox/${f}`;
  return [
    { files: files.filter((f) => !ALONE.includes(f)).sort().map(path), concurrency: 2 },
    { files: ALONE.filter((f) => files.includes(f)).map(path), concurrency: 1 },
  ].filter((r) => r.files.length);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const files = readdirSync(resolve(CLI, "test", "blackbox")).filter((f) => f.endsWith(".test.mjs"));
  let failed = false;
  for (const run of blackboxRuns(files)) {
    const args = ["--test", `--test-concurrency=${run.concurrency}`, ...process.argv.slice(2), ...run.files];
    const r = spawnSync(process.execPath, args, { cwd: CLI, stdio: "inherit" });
    if (r.status !== 0) failed = true;
  }
  process.exit(failed ? 1 : 0);
}

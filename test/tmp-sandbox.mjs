/* Preloaded into every test file's process by `npm test` (node --import). The process gets its own empty
 * TMPDIR under the caller's, and that folder is removed when the process exits: a pass, a failure, process.exit or an
 * uncaught throw. So a test that makes a temp folder and never removes it leaves nothing behind. Child processes the
 * tests start inherit the same TMPDIR, so their folders go too. A kill -9 skips the exit hook; scripts/tmp-guard.mjs
 * then still catches and removes what is left.
 *
 * Tests may still clean up after themselves. That only empties the folder sooner. */
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { removeTree } from "../scripts/tmp-guard.mjs";

const sandbox = mkdtempSync(join(tmpdir(), "custosa-t-"));
for (const key of ["TMPDIR", "TMP", "TEMP"]) process.env[key] = sandbox;

process.on("exit", () => {
  try {
    removeTree(sandbox);
  } catch (err) {
    process.stderr.write(`tmp-sandbox: could not remove ${sandbox}: ${err && err.code ? err.code : err}\n`);
  }
});

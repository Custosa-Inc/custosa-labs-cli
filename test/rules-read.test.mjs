/* runRules reads a file it was given without text through walkread.readWalked, as every other reader
   does: a regular file inside the root, its open handle the file that was checked. statSync and readFileSync followed a
   symlink out of the root and would block the main thread on a FIFO. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { loadRules, runRules } from "../lib/inspector/rules.mjs";

const RULES = fileURLToPath(new URL("./fixtures/rules/", import.meta.url));
const KEY = Buffer.from("0123456789abcdef0123456789abcdef");
const CLIENT = `function show(record) {\n  console.log(record.patient);\n  localStorage.setItem("p", record.patient);\n}\n`;

test("a file given without text is read only when it is a regular file inside the root", { skip: process.platform === "win32" }, async () => {
  const base = realpathSync(mkdtempSync(join(tmpdir(), "rules-read-")));
  try {
    const root = join(base, "repo");
    mkdirSync(join(root, "src"), { recursive: true });
    writeFileSync(join(root, "src", "client.js"), CLIENT);
    writeFileSync(join(base, "outside.js"), CLIENT);
    symlinkSync(join(base, "outside.js"), join(root, "src", "linked.js"));
    const rules = loadRules(RULES);
    const res = await runRules(rules, [{ path: "src/client.js" }, { path: "src/linked.js" }], { key: KEY, frameworks: [], root });
    assert.deepEqual(res.notAnalyzed, [{ path: "src/linked.js", reason: "unreadable" }]);
    assert.ok(res.matches.length > 0 && res.matches.every((m) => m.path === "src/client.js"));
  } finally { rmSync(base, { recursive: true, force: true }); }
});

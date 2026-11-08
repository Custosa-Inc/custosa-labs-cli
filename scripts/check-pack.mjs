#!/usr/bin/env node
/* Pack check (audit SC3): what `npm pack` would publish must be exactly the committed list, no more and no less.
 *
 *   node scripts/check-pack.mjs            (npm run check-pack)  compare; exit 1 on any extra or missing file
 *   node scripts/check-pack.mjs --update   (npm run check-pack -- --update)  rewrite the list from the current tree
 *
 * The list is .github/pack-expected-files.txt (one packed path per line, sorted). It runs
 * `npm pack --dry-run --json --ignore-scripts` in cli/, so nothing is written and no package script runs. */
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const CLI_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const LIST = resolve(CLI_DIR, ".github", "pack-expected-files.txt");

function packedFiles() {
  const r = spawnSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], {
    cwd: CLI_DIR, encoding: "utf8", shell: process.platform === "win32", maxBuffer: 64 * 1024 * 1024,
  });
  if (r.status !== 0) throw new Error(`npm pack --dry-run failed (exit ${r.status}):\n${r.stderr}`);
  const [entry] = JSON.parse(r.stdout);
  if (!entry || !Array.isArray(entry.files)) throw new Error("npm pack --dry-run --json printed no file list");
  return { name: entry.name, version: entry.version, files: entry.files.map((f) => f.path.replace(/\\/g, "/")).sort() };
}

const readList = () => readFileSync(LIST, "utf8").split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith("#")).sort();

function main(argv) {
  if (argv.length > 1 || (argv.length === 1 && argv[0] !== "--update")) {
    process.stderr.write("usage: node scripts/check-pack.mjs [--update]\n");
    return 2;
  }
  const { name, version, files } = packedFiles();
  if (argv[0] === "--update") {
    writeFileSync(LIST, `# Files \`npm pack\` publishes for ${name}; checked by scripts/check-pack.mjs. Update with npm run check-pack -- --update.\n${files.join("\n")}\n`);
    process.stdout.write(`wrote ${files.length} paths to ${LIST}\n`);
    return 0;
  }
  const expected = readList();
  const want = new Set(expected), got = new Set(files);
  const extra = files.filter((f) => !want.has(f));
  const missing = expected.filter((f) => !got.has(f));
  if (extra.length || missing.length) {
    process.stderr.write(`${name}@${version}: the packed files differ from .github/pack-expected-files.txt\n`);
    for (const f of extra) process.stderr.write(`  + ${f} (would be published, not in the list)\n`);
    for (const f of missing) process.stderr.write(`  - ${f} (in the list, would not be published)\n`);
    process.stderr.write("If the change is intended, run npm run check-pack -- --update and commit the list.\n");
    return 1;
  }
  process.stdout.write(`${name}@${version}: ${files.length} packed files match .github/pack-expected-files.txt\n`);
  return 0;
}

try { process.exitCode = main(process.argv.slice(2)); } catch (err) { process.stderr.write(`check-pack: ${err.message}\n`); process.exitCode = 1; }

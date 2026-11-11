// T19 (P2): doctor's per-assistant entry lines. An entry file that can't be read (here Codex's config.toml that isn't
// valid TOML) had no test: doctor must warn, name why, go on to the next checks and never change the file.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runDoctor } from "../lib/doctor.mjs";
import { NAME, VERSION } from "../lib/clients.mjs";

/* A home where only Codex is installed (its folder exists), with config.toml holding `toml` (none when null). */
function codexHome(toml) {
  const home = mkdtempSync(join(tmpdir(), "custosa-doctor-entries-"));
  mkdirSync(join(home, ".codex"), { recursive: true });
  if (toml !== null) writeFileSync(join(home, ".codex", "config.toml"), toml);
  return home;
}

/* doctor's lines for that home: no assistant on the PATH, nothing contacted */
async function doctor(home) {
  const lines = [];
  const code = await runDoctor({ env: { CUSTOSA_CONFIG_DIR: join(home, ".config", "custosa"), CUSTOSA_EVALUATOR_URL: "http://127.0.0.1:9",
    PGSERVICEFILE: "/nonexistent", npm_config_cache: join(home, ".npm") },
  home, platform: "linux", out: (l) => lines.push(l), offline: true, which: () => null, run: () => ({ status: 1, stdout: "" }) });
  return { code, lines, entry: lines.filter((l) => /^\w+ +Codex entry:/.test(l)) };
}

const entryToml = (pkg) => `[mcp_servers.${NAME}]\ncommand = "npx"\nargs = ["-y", "${pkg}", "inspect", "--stdio"]\n`;

test("doctor entries: a config.toml that isn't valid TOML warns with the reason, the checks go on, and the file is left as it is", async () => {
  const broken = "model = \"o4\"\n[mcp_servers\n";
  const home = codexHome(broken);
  const { lines, entry } = await doctor(home);
  assert.equal(entry.length, 1, lines.join("\n"));
  assert.match(entry[0], /^WARN  Codex entry: couldn't be read \(.*config\.toml: isn’t valid TOML, so it was left as it is\)\. Run npx custosa@latest setup, or set it up by hand\.$/);
  assert.ok(!lines.some((l) => /^\w+ +Assistants:/.test(l)), "one unreadable entry is not a failure of the whole block");
  // The checks after it still run.
  assert.ok(lines.some((l) => /^\w+ +Sign-in:/.test(l)));
  assert.match(lines.at(-1), /^\d+ passed, \d+ warnings, \d+ failed$/);
  assert.equal(readFileSync(join(home, ".codex", "config.toml"), "utf8"), broken);
});

test("doctor entries: a reason longer than 200 characters is cut at 200", async () => {
  // The reason holds the file's path; a long home folder makes it long.
  const deep = join(mkdtempSync(join(tmpdir(), "custosa-doctor-long-")), "x".repeat(150), "y".repeat(150));
  mkdirSync(join(deep, ".codex"), { recursive: true });
  writeFileSync(join(deep, ".codex", "config.toml"), "[mcp_servers\n");
  const { entry } = await doctor(deep);
  const reason = entry[0].match(/couldn't be read \((.*)\)\. Run/s)[1];
  assert.equal(reason.length, 200);
  assert.ok(reason.startsWith(join(deep, ".codex", "config.toml").slice(0, 100)));
});

test("doctor entries: Codex not set up, set up with this version, and set up with another", async () => {
  assert.deepEqual((await doctor(codexHome(null))).entry, ["WARN  Codex entry: not set up. Run npx custosa@latest setup to add it."]);
  assert.deepEqual((await doctor(codexHome(entryToml(`custosa@${VERSION}`)))).entry, [`PASS  Codex entry: set up (custosa@${VERSION})`]);
  assert.deepEqual((await doctor(codexHome(entryToml("custosa@0.0.1")))).entry,
    ["WARN  Codex entry: set up with a different command or version. Run npx custosa@latest setup to update it (its env and timeouts are kept)."]);
});

test("doctor entries: no assistant installed gives the one Assistants line", async () => {
  const home = mkdtempSync(join(tmpdir(), "custosa-doctor-none-"));
  const { lines } = await doctor(home);
  assert.deepEqual(lines.filter((l) => /^\w+ +(Assistants|[A-Za-z ]+ entry):/.test(l)),
    ["WARN  Assistants: none of the supported assistants was found on this computer."]);
});

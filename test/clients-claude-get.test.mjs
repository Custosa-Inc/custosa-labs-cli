/* how Claude Code's status reads `claude mcp get`. Only an entry whose Command and Args lines are exactly ours is
   set up; the first such line counts, the name is matched as written, and space around the value is ignored. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CLIENTS, NAME, VERSION } from "../lib/clients.mjs";

const claude = CLIENTS.find((c) => c.id === "claude-code");
const ARGS = `-y custosa@${VERSION} inspect --stdio`;
const shown = (...lines) => `${NAME}:\n  Scope: User config\n  Type: stdio\n${lines.join("\n")}\n`;

function status(stdout, { platform = "darwin", settings = null } = {}) {
  const home = mkdtempSync(join(tmpdir(), "custosa-claude-get-"));
  if (settings) writeFileSync(join(home, ".claude.json"), JSON.stringify(settings));
  const ctx = { home, platform, env: {}, run: () => ({ status: 0, stdout }) };
  return claude.status(ctx);
}

const CASES = [
  ["exactly ours", shown("  Command: npx", `  Args: ${ARGS}`), "configured"],
  ["Windows line ends", shown("  Command: npx\r", `  Args: ${ARGS}\r`), "configured"],
  ["tabs and spaces around the values", shown("\tCommand:\tnpx  ", `\t Args:   ${ARGS}\t`), "configured"],
  ["no space after the colon", shown("  Command:npx", `  Args:${ARGS}`), "configured"],
  ["environment lines after", shown("  Command: npx", `  Args: ${ARGS}`, "  Environment:", "    A=1"), "configured"],
  ["args first", shown(`  Args: ${ARGS}`, "  Command: npx"), "configured"],
  ["one more arg", shown("  Command: npx", `  Args: ${ARGS} --extra`), "outdated"],
  ["another version", shown("  Command: npx", "  Args: -y custosa@0.0.1 inspect --stdio"), "outdated"],
  ["another command", shown("  Command: node", `  Args: ${ARGS}`), "outdated"],
  ["no Args line", shown("  Command: npx"), "outdated"],
  ["no Command line", shown(`  Args: ${ARGS}`), "outdated"],
  ["empty Command", shown("  Command:", `  Args: ${ARGS}`), "outdated"],
  ["lower-case names", shown("  command: npx", `  args: ${ARGS}`), "outdated"],
  ["a longer name", shown("  Commands: npx", `  Args: ${ARGS}`), "outdated"],
  ["the first Command line counts (ours)", shown("  Command: npx", "  Command: node", `  Args: ${ARGS}`), "configured"],
  ["the first Command line counts (not ours)", shown("  Command: node", "  Command: npx", `  Args: ${ARGS}`), "outdated"],
  ["a hosted entry", `${NAME}:\n  Scope: User config\n  Type: http\n  URL: https://mcp.custosa.com/mcp\n`, "outdated"],
  ["nothing printed", "", "outdated"],
];

for (const [name, stdout, expected] of CASES) {
  test(`claude mcp get: ${name} is ${expected}`, () => {
    assert.equal(status(stdout), expected);
  });
}

test("claude mcp get: on Windows ours runs through cmd /c", () => {
  assert.equal(status(shown("  Command: cmd", `  Args: /c npx ${ARGS}`), { platform: "win32" }), "configured");
  assert.equal(status(shown("  Command: npx", `  Args: ${ARGS}`), { platform: "win32" }), "outdated");
});

test("claude mcp get: a failed get is ready", () => {
  const home = mkdtempSync(join(tmpdir(), "custosa-claude-get-"));
  assert.equal(claude.status({ home, platform: "darwin", env: {}, run: () => ({ status: 1, stdout: "" }) }), "ready");
});

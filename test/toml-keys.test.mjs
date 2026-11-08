/* config.toml keys may be bare, "double-quoted" or 'single-quoted', with any space around them. Each reader and
   writer in toml.mjs must agree on that, or an entry setup reads as ours could be written twice or not cleaned up. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { codexEnsureTimeouts, codexServer, codexSetCommand } from "../lib/toml.mjs";

const NAME = "phisc";
const QUOTES = [(k) => k, (k) => `"${k}"`, (k) => `'${k}'`];

test("toml keys: command and args are read bare or quoted", () => {
  for (const q of QUOTES) {
    const text = `[mcp_servers.${NAME}]\n  ${q("command")}  =  "npx"\n${q("args")} = ["-y", 'custosa']   # pinned\n`;
    assert.deepEqual(codexServer(text, NAME), { found: true, command: "npx", args: ["-y", "custosa"] }, q("k"));
  }
});

test("toml keys: a key that only starts like ours is not ours", () => {
  const text = `[mcp_servers.${NAME}]\ncommands = "x"\n"args2" = ["y"]\n`;
  assert.deepEqual(codexServer(text, NAME), { found: true, command: null, args: null });
});

test("toml keys: a quoted key with a value we don't read is left for a person", () => {
  for (const q of QUOTES) {
    assert.equal(codexServer(`[mcp_servers.${NAME}]\n${q("command")} = "a\\"b"\n`, NAME).other, true, q("command"));
    assert.equal(codexServer(`[mcp_servers.${NAME}]\n${q("args")} = [\n  "-y",\n]\n`, NAME).other, true, q("args"));
  }
});

test("toml keys: mcp_servers at the root, bare or quoted, as an inline table or dotted keys", () => {
  for (const q of QUOTES) {
    for (const line of [`${q("mcp_servers")} = { x = 1 }`, `${q("mcp_servers")}.x.command = "gh"`, `  ${q("mcp_servers")} .x = 1`]) {
      assert.deepEqual(codexServer(`${line}\n[mcp_servers.${NAME}]\ncommand = "npx"\n`, NAME), { found: true, command: null, args: null, other: true, rootServers: true }, line);
    }
  }
  assert.equal(codexServer(`mcp_servers_x = 1\n[mcp_servers.${NAME}]\ncommand = "npx"\n`, NAME).rootServers, undefined);
});

test("toml keys: setting the command replaces quoted command and args", () => {
  for (const q of QUOTES) {
    const text = `[mcp_servers.${NAME}]\n${q("command")} = "old"\n${q("args")} = ["a"]\n${q("startup_timeout_sec")} = 5\nkeep = 1\n`;
    assert.equal(codexSetCommand(text, NAME, "npx", ["-y", "custosa"]),
      `[mcp_servers.${NAME}]\ncommand = "npx"\nargs = ["-y", "custosa"]\ntool_timeout_sec = 300\n${q("startup_timeout_sec")} = 5\nkeep = 1\n`, q("k"));
  }
});

test("toml keys: a timeout the person set, bare or quoted, is kept", () => {
  for (const q of QUOTES) {
    const text = `[mcp_servers.${NAME}]\ncommand = "npx"\n${q("tool_timeout_sec")} = 900\n`;
    assert.equal(codexEnsureTimeouts(text, NAME), `[mcp_servers.${NAME}]\ncommand = "npx"\n${q("tool_timeout_sec")} = 900\nstartup_timeout_sec = 60\n`, q("k"));
  }
});

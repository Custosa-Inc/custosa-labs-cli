import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, rmSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { main } from "../lib/setup.mjs";
import { writeToken } from "../lib/inspector/auth.mjs";
import { DEFAULT_EVALUATOR_URL } from "../lib/inspector/client.mjs";
import { INSPECT, NAME, VERSION } from "../lib/clients.mjs";
const PKG = `custosa@${VERSION}`; // the pinned package the entries start (CC1)
import { codexAdd, codexRemove, codexServer, codexSetCommand } from "../lib/toml.mjs";
import { parse, winQuote } from "../lib/cli.mjs";
import { ENVIRONMENTS, environmentFor, readEnvironment, serviceFingerprint, writeEnvironment } from "../lib/inspector/environment.mjs";
import { spawnSync } from "node:child_process";

const CURSOR = ".cursor/mcp.json";
const ANTIGRAVITY = ".gemini/config/mcp_config.json";
const ANTIGRAVITY_OLDER = ".gemini/antigravity/mcp_config.json";
const CODEX = ".codex/config.toml";
const VSCODE = "Library/Application Support/Code/User/mcp.json";
const plain = (t) => t;
/* replies in turn, the last one repeating */
const sequence = (...replies) => { let i = 0; return () => replies[Math.min(i++, replies.length - 1)]; };
/* the local inspector, exactly as setup starts it */
const STDIO = { command: "npx", args: ["-y", PKG, "inspect", "--stdio"] };
const OLD = "https://mcp.custosa.com/mcp";
const OLD_STDIO = { command: "npx", args: ["-y", "custosa@0.0.1", "inspect", "--stdio"] };
const CLAUDE_ADD = `claude mcp add --scope user ${NAME} -- npx -y ${PKG} inspect --stdio`;
const CLAUDE_OURS = { status: 0, stdout: `${NAME}:\n  Scope: User config\n  Type: stdio\n  Command: npx\n  Args: -y ${PKG} inspect --stdio\n` };
const CODEX_TIMEOUT_LINES = "startup_timeout_sec = 60\ntool_timeout_sec = 300\n"; // CC1
const CODEX_ENTRY = `[mcp_servers.${NAME}]\ncommand = "npx"\nargs = ["-y", "${PKG}", "inspect", "--stdio"]\n${CODEX_TIMEOUT_LINES}`;

/* A pretend computer: a temporary home folder, the commands on its PATH, and a record of every command run. */
function computer({ bins = [], dirs = [], files = {}, interactive = false, answers = [], replies = {}, picks = [], typed = [] } = {}) {
  const home = mkdtempSync(join(tmpdir(), "custosa-cli-"));
  for (const d of dirs) mkdirSync(join(home, d), { recursive: true });
  for (const [f, text] of Object.entries(files)) { mkdirSync(dirname(join(home, f)), { recursive: true }); writeFileSync(join(home, f), text); }
  const calls = [], lines = [], asked = [], chose = [];
  const ctx = {
    home, platform: "darwin", env: {}, self: ["custosa"], interactive, dryRun: false, now: new Date("2026-10-09T12:00:00Z"),
    style: { bold: plain, dim: plain, green: plain, red: plain, yellow: plain },
    which: (c) => (bins.includes(c) ? `/usr/local/bin/${c}` : null),
    run(cmd, args, options = {}) {
      const line = [cmd, ...args].join(" ");
      calls.push(options.interactive ? `${line} (in terminal)` : line);
      const reply = typeof replies[line] === "function" ? replies[line]() : replies[line];
      return reply ?? { status: line.startsWith("claude mcp get") ? 1 : 0, stdout: "" };
    },
    out: (l = "") => lines.push(l),
    ask: async (q) => { asked.push(q); return answers.length ? answers.shift() : true; },
    input: async (q) => { asked.push(q); return typed.length ? typed.shift() : ""; },
    choose: async (q, choices, fallback) => { chose.push({ q, choices, fallback }); return picks.length ? picks.shift() : fallback; },
  };
  const read = (f) => readFileSync(join(home, f), "utf8");
  const json = (f) => JSON.parse(read(f));
  return { ctx, home, calls, asked, chose, read, json, output: () => lines.join("\n") };
}

test("adds PHI Schema Check to every assistant it finds, each in its own format", async () => {
  const pc = computer({ bins: ["claude"], dirs: [".cursor", ".gemini/config", ".codex"] });
  assert.equal(await main("setup", { yes: true }, pc.ctx), 0);
  assert.deepEqual(pc.calls, [`claude mcp get ${NAME}`, CLAUDE_ADD]);
  assert.deepEqual(pc.json(CURSOR), { mcpServers: { [NAME]: STDIO } });
  assert.deepEqual(pc.json(ANTIGRAVITY), { mcpServers: { [NAME]: STDIO } });
  assert.equal(pc.read(CODEX), CODEX_ENTRY);
  assert.deepEqual(INSPECT, ["npx", "-y", PKG, "inspect", "--stdio"]);
  assert.doesNotMatch(JSON.stringify([pc.calls, pc.read(CURSOR), pc.read(ANTIGRAVITY), pc.read(CODEX)]), /https?:|--transport|serverUrl/);
  assert.match(pc.output(), /Sign in  Run npx custosa login in a terminal/);
  assert.doesNotMatch(pc.output(), /mcp login|\/mcp auth|Authenticate/);
  assert.match(pc.output(), /Use PHI Schema Check to review how this app handles patient data\./  /* the check-first prompt */);
  // top-ups start at $5.
  // the $10 sign-up credit, then top-ups and coupons add to it.
  assert.match(pc.output(), /Add credit  PHI Schema Check is pay per use\. Your account starts with \$10 of credit at your first sign-in\. Top up from \$5 or redeem a coupon/);
  // No per-check estimate: the price is per work unit with no cap .
  assert.match(pc.output(), /\$0\.003 per work unit, prepaid\./);   // it was $0.006
  assert.doesNotMatch(pc.output(), /usually costs|a whole check|\$2 to \$6/);
  assert.match(pc.output(), /Every result is charged, unknown results and practices with no rule for the stack included\./);
  assert.doesNotMatch(pc.output(), /HIPAA gaps|with Custosa\./);
});

test("keeps everything else in a settings file, its indentation, and a backup of the original", async () => {
  const original = JSON.stringify({ mcpServers: { github: { url: "https://example.com/mcp" } }, other: true }, null, 4) + "\n";
  const pc = computer({ files: { [CURSOR]: original } });
  assert.equal(await main("setup", { yes: true, clients: ["cursor"] }, pc.ctx), 0);
  const after = pc.read(CURSOR);
  assert.deepEqual(JSON.parse(after), { mcpServers: { github: { url: "https://example.com/mcp" }, [NAME]: STDIO }, other: true });
  assert.match(after, /^ {4}"mcpServers"/m);
  assert.equal(pc.read(`${CURSOR}.custosa-backup-20261009-120000`), original);
  assert.match(pc.output(), /previous file saved as ~\/\.cursor\/mcp\.json\.custosa-backup-20261009-120000/);
});

test("keeps a byte-order mark that a Windows editor saved", async () => {
  const pc = computer({ files: { [CURSOR]: "\uFEFF{\"mcpServers\":{}}" } });
  assert.equal(await main("setup", { yes: true }, pc.ctx), 0);
  assert.ok(pc.read(CURSOR).startsWith("\uFEFF{"));
  assert.deepEqual(JSON.parse(pc.read(CURSOR).slice(1)).mcpServers[NAME], STDIO);
});

test("keeps an older Antigravity's own settings file in step with the shared one", async () => {
  const pc = computer({ bins: ["agy"], files: { [ANTIGRAVITY_OLDER]: JSON.stringify({ mcpServers: { other: { serverUrl: "https://example.com" } } }) } });
  assert.equal(await main("setup", { yes: true }, pc.ctx), 0);
  assert.deepEqual(pc.json(ANTIGRAVITY), { mcpServers: { [NAME]: STDIO } });
  assert.deepEqual(pc.json(ANTIGRAVITY_OLDER).mcpServers, { other: { serverUrl: "https://example.com" }, [NAME]: STDIO });
  assert.match(pc.output(), /Antigravity\s+added \(covers Antigravity and Antigravity CLI\)/);
  const calls = pc.calls.length;
  assert.equal(await main("setup", { yes: true }, pc.ctx), 0);
  assert.equal(pc.calls.length, calls);
  assert.match(pc.output(), /Antigravity\s+already set up/);
  assert.equal(await main("remove", { yes: true }, pc.ctx), 0);
  assert.deepEqual(pc.json(ANTIGRAVITY).mcpServers, {});
  assert.deepEqual(pc.json(ANTIGRAVITY_OLDER).mcpServers, { other: { serverUrl: "https://example.com" } });
});

test("a second run finds it already set up and changes nothing", async () => {
  const pc = computer({ bins: ["claude"], dirs: [".cursor"], replies: { [`claude mcp get ${NAME}`]: CLAUDE_OURS } });
  await main("setup", { yes: true }, pc.ctx);
  const before = pc.read(CURSOR), calls = pc.calls.length;
  assert.equal(await main("setup", { yes: true }, pc.ctx), 0);
  assert.equal(pc.read(CURSOR), before);
  assert.deepEqual(pc.calls.slice(calls), [`claude mcp get ${NAME}`]);
  assert.match(pc.output(), /Cursor\s+already set up/);
  assert.match(pc.output(), /Sign in  Run npx custosa login in a terminal/);
  assert.equal(readdirSync(join(pc.home, ".cursor")).length, 1, "no backup when nothing changed");
});

/* A foreign entry under our name (an address, or a type other than stdio) is replaced by ours with none of its keys,
   and the next run finds it set up. */
test("replaces a foreign Cursor entry with no type by ours alone, and then counts it as set up", async () => {
  const pc = computer({ files: { [CURSOR]: JSON.stringify({ mcpServers: { [NAME]: { url: OLD, headers: { X: "y" }, env: { A: "1" } } } }) } });
  assert.equal(await main("setup", { yes: true, clients: ["cursor"] }, pc.ctx), 0);
  assert.deepEqual(pc.json(CURSOR).mcpServers[NAME], STDIO);
  assert.equal(await main("setup", { yes: true, clients: ["cursor"] }, pc.ctx), 0);
  assert.match(pc.output(), /Cursor\s+already set up/);
});

test("replaces a foreign typed http entry by ours alone, and then counts it as set up", async () => {
  const pc = computer({ files: { [CURSOR]: JSON.stringify({ mcpServers: { [NAME]: { type: "http", url: OLD, disabled: false } } }) } });
  assert.equal(await main("setup", { yes: true, clients: ["cursor"] }, pc.ctx), 0);
  assert.deepEqual(pc.json(CURSOR).mcpServers[NAME], STDIO);
  assert.equal(await main("setup", { yes: true, clients: ["cursor"] }, pc.ctx), 0);
  assert.match(pc.output(), /Cursor\s+already set up/);
});

test("replaces a foreign VS Code entry by ours alone, and then counts it as set up", async () => {
  const pc = computer({ files: { [VSCODE]: JSON.stringify({ servers: { [NAME]: { type: "sse", url: OLD, headers: { X: "y" } } } }) } });
  assert.equal(await main("setup", { yes: true, clients: ["vscode"] }, pc.ctx), 0);
  assert.deepEqual(pc.json(VSCODE).servers[NAME], { type: "stdio", ...STDIO });
  assert.equal(await main("setup", { yes: true, clients: ["vscode"] }, pc.ctx), 0);
  assert.match(pc.output(), /VS Code\s+already set up/);
});

test("replaces a foreign Codex url table and its sub-tables by ours alone, and then counts it as set up", async () => {
  const text = `[mcp_servers.${NAME}]\nurl = "${OLD}"\nbearer_token_env_var = "T"\n\n[mcp_servers.${NAME}.http_headers]\nX = "y"\n\n# next\n[other]\nurl = "keep"\n`;
  const pc = computer({ dirs: [".codex"], files: { [CODEX]: text } });
  assert.equal(await main("setup", { yes: true, clients: ["codex"] }, pc.ctx), 0);
  assert.equal(pc.read(CODEX), `${CODEX_ENTRY}\n# next\n[other]\nurl = "keep"\n`);
  assert.equal(await main("setup", { yes: true, clients: ["codex"] }, pc.ctx), 0);
  assert.match(pc.output(), /Codex\s+already set up/);
});

test("an entry with our command and args plus the old hosted address is foreign: replaced, not counted as set up", async () => {
  for (const key of ["url", "serverUrl", "httpUrl"]) {
    const pc = computer({ files: { [CURSOR]: JSON.stringify({ mcpServers: { [NAME]: { ...STDIO, [key]: OLD } } }) } });
    assert.equal(await main("setup", { yes: true, clients: ["cursor"] }, pc.ctx), 0);
    assert.deepEqual(pc.json(CURSOR).mcpServers[NAME], STDIO, key);
  }
  const pc = computer({ dirs: [".codex"], files: { [CODEX]: `${CODEX_ENTRY}url = "${OLD}"\n` } });
  assert.equal(await main("setup", { yes: true, clients: ["codex"] }, pc.ctx), 0);
  assert.equal(pc.read(CODEX), CODEX_ENTRY);
});

test("counts only an exact entry as set up: a near miss is replaced", async () => {
  for (const near of [{ command: "npx", args: ["custosa", "inspect", "--stdio"] }, { command: "npx", args: [...STDIO.args, "--extra"] }, { command: "node", args: STDIO.args }]) {
    const pc = computer({ files: { [CURSOR]: JSON.stringify({ mcpServers: { [NAME]: near } }) } });
    assert.equal(await main("setup", { yes: true, clients: ["cursor"] }, pc.ctx), 0);
    assert.deepEqual(pc.json(CURSOR).mcpServers[NAME], STDIO);
  }
  const nearReply = () => sequence(...Array(2).fill({ status: 0, stdout: `  Scope: User config\n  Command: npx\n  Args: -y ${PKG} inspect --stdio --extra\n` }), { status: 1 });
  const nearEntry = { type: "stdio", command: "npx", args: [...STDIO.args, "--extra"], env: { K: "v" } };
  const claude = computer({ bins: ["claude"], files: { ".claude.json": JSON.stringify({ mcpServers: { [NAME]: nearEntry } }) }, replies: { [`claude mcp get ${NAME}`]: nearReply() } });
  assert.equal(await main("setup", { yes: true }, claude.ctx), 0);
  assert.deepEqual(claude.calls.slice(1), [`claude mcp get ${NAME}`, `claude mcp remove ${NAME} --scope user`, `claude mcp get ${NAME}`,
    `claude mcp add-json --scope user ${NAME} ${JSON.stringify({ type: "stdio", ...STDIO, env: { K: "v" } })}`]);
  assert.match(claude.output(), /updated in Claude Code’s user scope, each entry keeping its env and other settings/);
  // M-A: a local inspector entry setup can't read from its file is left alone, with the manual steps, never re-added without its env
  const unread = computer({ bins: ["claude"], replies: { [`claude mcp get ${NAME}`]: nearReply() } });
  assert.equal(await main("setup", { yes: true }, unread.ctx), 1);
  assert.ok(!unread.calls.some((c) => /mcp (remove|add)/.test(c)), unread.calls.join("\n"));
  assert.match(unread.output(), /can’t read it from ~\/\.claude\.json, so it was left as it is rather than lose its env/);
  // with CLAUDE_CONFIG_DIR set, the message names the file setup read there.
  const moved = computer({ bins: ["claude"], replies: { [`claude mcp get ${NAME}`]: nearReply() } });
  moved.ctx.env = { ...moved.ctx.env, CLAUDE_CONFIG_DIR: "/cfg/claude" };
  assert.equal(await main("setup", { yes: true }, moved.ctx), 1);
  assert.match(moved.output(), /can’t read it from \/cfg\/claude\/\.claude\.json, so it was left as it is/);
});

test("leaves a file it can't rewrite exactly alone and points to the manual steps", async () => {
  for (const [text, why] of [["{\n  // mine\n  \"mcpServers\": {}\n}\n", /has comments, so it was left as it is/], ["{ not json", /isn’t valid JSON/]]) {
    const pc = computer({ files: { [CURSOR]: text } });
    assert.equal(await main("setup", { yes: true }, pc.ctx), 1);
    assert.equal(pc.read(CURSOR), text);
    assert.match(pc.output(), why);
    assert.match(pc.output(), /by hand: https:\/\/custosa\.com\/labs\/setup\?assistant=cursor/);
    assert.equal(readdirSync(join(pc.home, ".cursor")).length, 1);
  }
});

test("a dry run changes nothing and runs no command that changes anything", async () => {
  const pc = computer({ bins: ["claude", "gemini"], dirs: [".cursor", ".codex"] });
  assert.equal(await main("setup", { yes: false }, { ...pc.ctx, dryRun: true }), 0);
  assert.deepEqual(pc.calls, [`claude mcp get ${NAME}`]);
  assert.equal(existsSync(join(pc.home, CURSOR)), false);
  assert.equal(existsSync(join(pc.home, CODEX)), false);
  assert.match(pc.output(), /Dry run, so nothing changes\./);
  assert.match(pc.output(), /Cursor\s+would be added/);
});

test("asks before changing anything, and only signs in when the person is at the terminal", async () => {
  const unattended = computer({ dirs: [".cursor"] });
  assert.equal(await main("setup", {}, unattended.ctx), 1);
  assert.match(unattended.output(), /Run again with --yes/);
  assert.equal(existsSync(join(unattended.home, CURSOR)), false);

  const declined = computer({ dirs: [".cursor"], interactive: true, answers: [false] });
  assert.equal(await main("setup", {}, declined.ctx), 0);
  assert.deepEqual(declined.asked, ["Add PHI Schema Check to Cursor?"]);
  assert.equal(existsSync(join(declined.home, CURSOR)), false);

  const here = computer({ bins: ["claude"], dirs: [".cursor"], interactive: true });
  assert.equal(await main("setup", {}, here.ctx), 0);
  assert.deepEqual(here.asked, ["Add PHI Schema Check to Claude Code and Cursor?", "Sign in to PHI Schema Check now? It gives you a code to enter in your browser."]);
  assert.equal(here.calls.at(-1), "custosa login (in terminal)");
  assert.doesNotMatch(here.output(), /Run npx custosa login/);
});

/* The sign-in is `custosa login`, run as its own process; setup only checks whether a sign-in file is there. */
const TOKEN = ".config/custosa/token";

test("signs in once through custosa login, in the terminal, only when the person is there", async () => {
  const here = computer({ dirs: [".cursor"], interactive: true });
  assert.equal(await main("setup", { yes: true }, here.ctx), 0);
  assert.deepEqual(here.calls, ["custosa login (in terminal)"]);
  assert.deepEqual(here.asked, [], "--yes runs the sign-in without asking");

  const failed = computer({ dirs: [".cursor"], interactive: true, replies: { "custosa login": { status: 1 } } });
  assert.equal(await main("setup", { yes: true }, failed.ctx), 0);
  assert.match(failed.output(), /Sign in  Run npx custosa login in a terminal/);

  const notNow = computer({ dirs: [".cursor"], interactive: true, answers: [true, false] });
  assert.equal(await main("setup", {}, notNow.ctx), 0);
  assert.deepEqual(notNow.calls, []);
  assert.match(notNow.output(), /Sign in  Run npx custosa login in a terminal/);

  const unattended = computer({ dirs: [".cursor"] });
  assert.equal(await main("setup", { yes: true }, unattended.ctx), 0);
  assert.deepEqual(unattended.calls, []);
  assert.match(unattended.output(), /Sign in  Run npx custosa login in a terminal/);

  const dry = computer({ dirs: [".cursor"], interactive: true });
  assert.equal(await main("setup", { yes: true }, { ...dry.ctx, dryRun: true }), 0);
  assert.deepEqual(dry.calls, []);
});

const SECRET = `phisc_${"s".repeat(43)}`;
const signIn = (dir, host = new URL(DEFAULT_EVALUATOR_URL).origin) => writeToken(SECRET, { configDir: dir, host });

test("never opens, prints or stores the sign-in token, and skips the sign-in when the sign-in reader accepts one", async () => {
  const pc = computer({ dirs: [".cursor"], interactive: true });
  signIn(join(pc.home, ".config/custosa"));
  assert.equal(await main("setup", { yes: true }, pc.ctx), 0);
  assert.deepEqual(pc.calls, []);
  assert.match(pc.output(), /Signed in on this computer already\. To sign in anew, run npx custosa login\./);
  assert.doesNotMatch(pc.output(), new RegExp(SECRET));
  assert.equal(pc.read(TOKEN).trim(), SECRET);
  assert.equal(await main("remove", { yes: true }, pc.ctx), 0);
  assert.match(pc.output(), /still signed in\. To remove the sign-in too, run npx custosa logout/);

  const fresh = computer({ dirs: [".cursor"], interactive: true });
  await main("setup", { yes: true }, fresh.ctx);
  assert.equal(existsSync(join(fresh.home, TOKEN)), false, "setup itself writes no token");
});

test("a refused sign-in, or one made for another evaluator, counts as not signed in", async () => {
  const loose = computer({ dirs: [".cursor"], interactive: true });
  signIn(join(loose.home, ".config/custosa"));
  chmodSync(join(loose.home, TOKEN), 0o644);
  assert.equal(await main("setup", { yes: true }, loose.ctx), 0);
  assert.deepEqual(loose.calls, ["custosa login (in terminal)"]);

  const other = computer({ dirs: [".cursor"], interactive: true });
  signIn(join(other.home, ".config/custosa"), "https://other.example.test");
  assert.equal(await main("setup", { yes: true }, other.ctx), 0);
  assert.deepEqual(other.calls, ["custosa login (in terminal)"]);

  const notToken = computer({ dirs: [".cursor"], interactive: true, files: { [TOKEN]: "x" } });
  assert.equal(await main("setup", { yes: true }, notToken.ctx), 0);
  assert.deepEqual(notToken.calls, ["custosa login (in terminal)"]);
});

test("reads the sign-in folder from CUSTOSA_CONFIG_DIR when it is set", async () => {
  const pc = computer({ dirs: [".cursor"], interactive: true });
  signIn(join(pc.home, "elsewhere"));
  pc.ctx.env = { CUSTOSA_CONFIG_DIR: join(pc.home, "elsewhere") };
  assert.equal(await main("setup", { yes: true }, pc.ctx), 0);
  assert.deepEqual(pc.calls, []);
});

/* The environment mark (evaluator_api.md 1.4): {value, source: "setup"} in <config dir>/environment.json, 0600. */
const ENV_FILE = ".config/custosa/environment.json";
const mode = (pc, f) => statSync(join(pc.home, f)).mode & 0o777;
const SERVICE = "[phisc]\nhost=db.internal\nport=5432\ndbname=app\nuser=phisc_ro\nsslmode=require\n";
const CONFIRM = "A production mark lets a check earn a production readiness score. Type production to confirm:";
const cfg = (pc) => join(pc.home, ".config/custosa");
const envFor = (pc) => environmentFor({ configDir: cfg(pc), env: {}, home: pc.home });

test("asks which environment the phisc entry points at, ties the mark to that entry and saves it where the inspector reads it", async () => {
  const pc = computer({ dirs: [".cursor"], interactive: true, picks: ["staging"], files: { ".pg_service.conf": SERVICE } });
  signIn(cfg(pc));
  assert.equal(await main("setup", {}, pc.ctx), 0);
  assert.deepEqual(pc.chose[0].choices, ["development", "staging", "production", "unknown"]);
  assert.equal(pc.chose[0].fallback, "unknown");
  assert.match(pc.chose[0].q, /phisc database entry \(~\/\.pg_service\.conf\)/);
  assert.match(pc.chose[0].q, /the evaluator treats production as your own statement/);
  const saved = pc.json(ENV_FILE);
  assert.deepEqual(Object.keys(saved), ["value", "source", "service"]);
  assert.equal(saved.value, "staging");
  assert.equal(saved.source, "setup");
  assert.equal(saved.service, serviceFingerprint({ env: {}, home: pc.home }));
  assert.match(saved.service, /^[0-9a-f]{64}$/);
  assert.doesNotMatch(pc.read(ENV_FILE), /db\.internal|app/, "the fingerprint, not the entry");
  assert.equal(mode(pc, ENV_FILE), 0o600);
  assert.deepEqual(envFor(pc), { environment: { value: "staging", source: "setup" }, note: null });

  // a second run offers the earlier mark as the default and leaves the file alone when it is kept
  assert.equal(await main("setup", {}, { ...pc.ctx, choose: async (q, c, fallback) => fallback }), 0);
  assert.match(pc.output(), /Environment  staging, unchanged\./);

  // the entry now points elsewhere: the inspector reads unknown, says so, and setup asks again
  writeFileSync(join(pc.home, ".pg_service.conf"), SERVICE.replace("dbname=app", "dbname=prod"));
  const after = envFor(pc);
  assert.deepEqual(after.environment, { value: "unknown", source: "setup" });
  assert.match(after.note, /phisc database entry has changed since it was marked staging at setup, so this check is judged as environment unknown/);
  const again = computer({ interactive: true });
  assert.equal(await main("setup", { yes: true }, { ...pc.ctx, out: again.ctx.out }), 0);
  assert.match(again.output(), /The phisc entry has changed since it was marked staging, so it counts as unknown until it is marked again/);
});

test("a production mark is typed out in full by a person at the terminal", async () => {
  const typo = computer({ dirs: [".cursor"], interactive: true, picks: ["production"], typed: ["yes"], files: { ".pg_service.conf": SERVICE } });
  assert.equal(await main("setup", { yes: false }, typo.ctx), 0);
  assert.ok(typo.asked.includes(CONFIRM));
  assert.equal(existsSync(join(typo.home, ENV_FILE)), false);
  assert.match(typo.output(), /Not marked production\./);

  const ok = computer({ dirs: [".cursor"], interactive: true, picks: ["production"], typed: ["production"], files: { ".pg_service.conf": SERVICE } });
  assert.equal(await main("setup", {}, ok.ctx), 0);
  assert.equal(ok.json(ENV_FILE).value, "production");
  assert.deepEqual(envFor(ok).environment, { value: "production", source: "setup" });

  // --environment production in a terminal still asks for the typed word, even with --yes
  const flagged = computer({ dirs: [".cursor"], interactive: true, typed: ["Production"], files: { ".pg_service.conf": SERVICE } });
  assert.equal(await main("setup", { yes: true, environment: "production" }, flagged.ctx), 1);
  assert.equal(existsSync(join(flagged.home, ENV_FILE)), false);
  assert.deepEqual(flagged.chose, []);
});

test("without a terminal, --environment is refused and nothing is marked", async () => {
  for (const value of ["production", "development"]) {
    const pc = computer({ dirs: [".cursor"], files: { ".pg_service.conf": SERVICE } });
    assert.equal(await main("setup", { yes: true, environment: value }, pc.ctx), 1);
    assert.equal(existsSync(join(pc.home, ENV_FILE)), false);
    assert.match(pc.output(), /Environment not marked: the mark is asked at a terminal\. To mark it, run npx custosa setup in a terminal\./);
  }
  const unattended = computer({ dirs: [".cursor"] });
  assert.equal(await main("setup", { yes: true }, unattended.ctx), 0);
  assert.match(unattended.output(), /Environment  Not marked, so results are judged as unknown\. To mark it, run npx custosa setup in a terminal\./);

  const noEntry = computer({ dirs: [".cursor"], interactive: true, typed: ["production"] });
  assert.equal(await main("setup", { yes: true, environment: "production" }, noEntry.ctx), 1);
  assert.equal(existsSync(join(noEntry.home, ENV_FILE)), false);
  assert.match(noEntry.output(), /Not marked production: there is no \[phisc\] entry in ~\/\.pg_service\.conf yet/);

  const flaggedTerminal = computer({ dirs: [".cursor"], interactive: true });
  assert.equal(await main("setup", { yes: true, environment: "development" }, flaggedTerminal.ctx), 0);
  assert.equal(flaggedTerminal.json(ENV_FILE).value, "development");
  assert.equal(flaggedTerminal.json(ENV_FILE).service, null, "no [phisc] entry yet");
  assert.deepEqual(envFor(flaggedTerminal).environment, { value: "development", source: "setup" });
  writeFileSync(join(flaggedTerminal.home, ".pg_service.conf"), SERVICE);
  assert.equal(envFor(flaggedTerminal).environment.value, "unknown", "adding the entry later sets it back to unknown");
  assert.equal(await main("setup", { yes: true }, unattended.ctx), 0);

  const dry = computer({ dirs: [".cursor"], interactive: true });
  assert.equal(await main("setup", { environment: "staging" }, { ...dry.ctx, dryRun: true }), 0);
  assert.equal(existsSync(join(dry.home, ENV_FILE)), false);
  assert.match(dry.output(), /Environment would be marked staging/);
});

test("keeps the environment mark to the sign-in file's safeguards", () => {
  const dir = mkdtempSync(join(tmpdir(), "custosa-env-"));
  chmodSync(dir, 0o700);
  const empty = mkdtempSync(join(tmpdir(), "custosa-env-home-"));
  const forDir = (d) => environmentFor({ configDir: d, env: {}, home: empty });
  assert.deepEqual(readEnvironment({ configDir: dir }), { missing: true });
  assert.deepEqual(forDir(dir), { environment: { value: "unknown", source: "setup" }, note: null });
  assert.deepEqual(readEnvironment({ configDir: join(dir, "none") }), { missing: true });
  assert.throws(() => writeEnvironment("prod", { configDir: dir }), /Unknown environment "prod"/);
  assert.throws(() => writeEnvironment("staging", { configDir: dir, service: "x" }), /phisc entry can't be read/);
  assert.deepEqual(ENVIRONMENTS, ["development", "staging", "production", "unknown"]);

  const file = join(dir, "environment.json");
  for (const text of ['{"value":"production","source":"answer","service":null}', '{"value":"prod","source":"setup","service":null}',
    '{"value":"production","source":"setup","service":null,"extra":1}', '{"value":"production","source":"setup"}', '{"value":"production","source":"setup","service":"abc"}', "production"]) {
    writeFileSync(file, text, { mode: 0o600 });
    assert.match(readEnvironment({ configDir: dir }).refused, /not an environment mark/, text);
    const r = forDir(dir);
    assert.equal(r.environment.value, "unknown");
    assert.match(r.note, /can't be used \(the environment file is not an environment mark\), so this check is judged as environment unknown/);
  }
  writeFileSync(file, '{"value":"staging","source":"setup","service":null}', { mode: 0o600 });
  assert.deepEqual(forDir(dir).environment, { value: "staging", source: "setup" });
  // production names a database: marked with no [phisc] entry, it is sent as unknown with a note
  writeFileSync(file, '{"value":"production","source":"setup","service":null}', { mode: 0o600 });
  assert.deepEqual(forDir(dir).environment, { value: "unknown", source: "setup" });
  assert.match(forDir(dir).note, /marked production at setup when there was no phisc database entry/);
  // an entry that can't be parsed: "couldn't be read", not "has changed"
  writeFileSync(join(empty, ".pg_service.conf"), "[phisc]\nhost = x\n");
  writeFileSync(file, '{"value":"staging","source":"setup","service":null}', { mode: 0o600 });
  assert.match(forDir(dir).note, /The phisc database entry couldn't be read, so the environment marked staging at setup can't be checked/);
  assert.doesNotMatch(forDir(dir).note, /has changed/);
  rmSync(join(empty, ".pg_service.conf"));
  writeFileSync(file, '{"value":"production","source":"setup","service":null}', { mode: 0o600 });
  chmodSync(file, 0o644);
  assert.match(readEnvironment({ configDir: dir }).refused, /readable or writable by other users/);

  // a symlink is refused (O_NOFOLLOW), and writing replaces the link itself, never the file it points at
  const target = join(dir, "elsewhere.json");
  writeFileSync(target, '{"value":"production","source":"setup","service":null}', { mode: 0o600 });
  const link = mkdtempSync(join(tmpdir(), "custosa-env-"));
  chmodSync(link, 0o700);
  symlinkSync(target, join(link, "environment.json"));
  assert.match(readEnvironment({ configDir: link }).refused, /not a regular file/);
  writeEnvironment("development", { configDir: link });
  assert.equal(lstatSync(join(link, "environment.json")).isSymbolicLink(), false);
  assert.equal(readFileSync(target, "utf8"), '{"value":"production","source":"setup","service":null}');
  assert.deepEqual(readEnvironment({ configDir: link }).mark, { value: "development", source: "setup", service: null });

  // a FIFO in its place is refused without blocking
  const fifoDir = mkdtempSync(join(tmpdir(), "custosa-env-"));
  chmodSync(fifoDir, 0o700);
  if (spawnSync("mkfifo", [join(fifoDir, "environment.json")]).status === 0) {
    chmodSync(join(fifoDir, "environment.json"), 0o600);
    assert.match(readEnvironment({ configDir: fifoDir }).refused, /not a regular file/);
  }

  // a folder other users can write is refused for reading and writing
  const open = mkdtempSync(join(tmpdir(), "custosa-env-"));
  chmodSync(open, 0o777);
  assert.match(readEnvironment({ configDir: open }).refused, /writable by other users/);
  assert.throws(() => writeEnvironment("staging", { configDir: open }), /Can't save the environment mark: the config folder is writable by other users/);
  assert.equal(existsSync(join(open, "environment.json")), false);
});

/* The database guidance: E1's SQL from shared.json, printed, never run. */
const COPY_RULES = /—|\bfree\b|HIPAA compliant|HIPAA ready|certified|\bcompliant\b|guarantee|\bsecure\b/i;

test("prints the read-only role, the Postgres 14 step and the read and write checks, and runs none of it", async () => {
  const pc = computer({ dirs: [".cursor"] });
  assert.equal(await main("setup", { yes: true }, pc.ctx), 0);
  const out = pc.output();
  const db = JSON.parse(readFileSync(new URL("../lib/shared.json", import.meta.url), "utf8")).database;
  assert.match(out, /^PHI Schema Check, a Custosa Labs project$/m);
  assert.ok(out.includes("CREATE ROLE phisc_ro LOGIN PASSWORD 'YOUR_PASSWORD'\n      NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;"));
  assert.match(out, /never through a trusted\n     socket \(a trust or peer line in pg_hba\.conf/);
  assert.match(out, /On PostgreSQL 14 or older, and on any database upgraded from one \(pg_upgrade or a dump and restore keeps the/);
  assert.ok(out.includes("    BEGIN;\n    GRANT CREATE ON SCHEMA public TO your_migration_role;\n    REVOKE CREATE ON SCHEMA public FROM PUBLIC;\n    COMMIT;"));
  assert.match(out, /This step needs the owner of the public\n     schema or a superuser/);
  assert.ok(out.includes("    psql -v ON_ERROR_STOP=1 -d your_database -f phisc_setup.sql"));
  assert.ok(out.includes("    GRANT USAGE ON SCHEMA storage TO phisc_ro;\n    GRANT SELECT ON storage.buckets TO phisc_ro;\n    CREATE POLICY phisc_ro_read_buckets ON storage.buckets FOR SELECT TO phisc_ro USING (true);"));
  assert.match(out, /The first leaves out Supabase's storage\.buckets, granted above, as the inspector's own check does/);
  assert.match(out, /On Supabase, also let it read the bucket list's settings \(names, public flag, size and type limits\), never the\n     files in them/);
  assert.ok(out.indexOf("GRANT CREATE ON SCHEMA public TO") < out.indexOf("REVOKE CREATE ON SCHEMA public FROM PUBLIC"));
  const indented = (sql) => sql.split("\n").map((l) => `    ${l}`).join("\n");
  for (const sql of [db.role, db.supabaseBuckets, db.pg14Steps, db.readCheck, db.largeObjectCheck, db.writeCheck, db.service, db.pgpass, db.writeProbe]) assert.ok(out.includes(indented(sql)), sql.slice(0, 40));
  assert.ok(out.indexOf(indented(db.readCheck)) < out.indexOf(indented(db.writeCheck)), "the write check sits after the read checks");
  for (const part of ["'INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER'", "has_schema_privilege('phisc_ro', oid, 'CREATE')", "has_database_privilege('phisc_ro', current_database(), 'CREATE')", "rolcreatedb", "pg_default_acl"]) assert.ok(db.writeCheck.includes(part), part);
  assert.match(out, /no table write grants, no\n     CREATE on any schema or the database, no CREATEDB, and no default privileges that grant a write/);
  for (const m of out.matchAll(/\bpsql\s+(?=-|")/g)) assert.ok(out.slice(m.index).startsWith("psql -v ON_ERROR_STOP=1 "));
  for (const m of out.matchAll(/\bgit\s+-/g)) assert.ok(out.slice(m.index).startsWith("git -c core.fsmonitor=false -c safe.bareRepository=explicit"));
  assert.doesNotMatch(out, COPY_RULES);
  assert.deepEqual(pc.calls, [], "no psql or other command is run");

  const ready = computer({ dirs: [".cursor"], files: { ".pg_service.conf": "[other]\nhost=x\n\n[phisc]\nuser=phisc_ro\n" } });
  assert.equal(await main("setup", { yes: true }, ready.ctx), 0);
  assert.doesNotMatch(ready.output(), /CREATE ROLE/);
  assert.match(ready.output(), /Your database  The phisc entry is in ~\/\.pg_service\.conf\. Its read and write checks: https:\/\/custosa\.com\/labs\/setup#database/);
  // setup reads the entry as libpq, doctor and the inspector do (parseServiceEntry): a comment after the
  // header still names it.
  const commented = computer({ dirs: [".cursor"], files: { ".pg_service.conf": "[phisc] # dev\nuser=phisc_ro\n" } });
  assert.equal(await main("setup", { yes: true }, commented.ctx), 0);
  assert.match(commented.output(), /The phisc entry is in ~\/\.pg_service\.conf\./);
  assert.doesNotMatch(commented.output(), /CREATE ROLE/);
});

test("offers no claude.ai or remote connector path, in its output or its README", async () => {
  const pc = computer({ bins: ["claude", "codex"], dirs: [".cursor"], interactive: true });
  await main("setup", { yes: true }, pc.ctx);
  const readme = readFileSync(new URL("../README.md", import.meta.url), "utf8");
  for (const text of [pc.output(), readme, pc.calls.join("\n")]) assert.doesNotMatch(text, /claude\.ai|connector|https:\/\/mcp\./i);
});

test("keeps every line setup prints to the copy rules", async () => {
  for (const options of [{ yes: true }, { yes: true, environment: "production" }]) {
    const pc = computer({ bins: ["claude", "codex"], dirs: [".cursor", ".gemini/config"], interactive: true });
    await main("setup", options, pc.ctx);
    await main("remove", { yes: true }, pc.ctx);
    assert.doesNotMatch(pc.output() + pc.asked.join("\n") + pc.chose.map((c) => c.q).join("\n"), COPY_RULES);
  }
});

test("uses each assistant's own command when it is installed, and Gemini CLI's settings file", async () => {
  const pc = computer({ bins: ["codex", "code", "gemini"], files: { ".gemini/settings.json": JSON.stringify({ theme: "x" }) } });
  assert.equal(await main("setup", { yes: true }, pc.ctx), 0);
  assert.deepEqual(pc.calls, [
    `codex mcp add ${NAME} -- npx -y ${PKG} inspect --stdio`,
    `code --add-mcp {"name":"${NAME}","type":"stdio","command":"npx","args":["-y","${PKG}","inspect","--stdio"]}`,
  ]);
  assert.deepEqual(pc.json(".gemini/settings.json"), { theme: "x", mcpServers: { [NAME]: STDIO } });
  assert.equal(await main("remove", { yes: true, clients: ["gemini-cli"] }, pc.ctx), 0);
  assert.deepEqual(pc.json(".gemini/settings.json"), { theme: "x", mcpServers: {} });
});

test("edits VS Code's own settings file when the code command isn't on the PATH", async () => {
  const pc = computer({ files: { [VSCODE]: JSON.stringify({ servers: {}, inputs: [] }, null, "\t") } });
  assert.equal(await main("setup", { yes: true }, pc.ctx), 0);
  assert.deepEqual(pc.json(VSCODE), { servers: { [NAME]: { type: "stdio", ...STDIO } }, inputs: [] });
  assert.match(pc.read(VSCODE), /^\t"servers"/m);
});

test("only touches the assistants asked for", async () => {
  const pc = computer({ bins: ["claude"], dirs: [".cursor", ".gemini/config"] });
  assert.equal(await main("setup", { yes: true, clients: ["antigravity"] }, pc.ctx), 0);
  assert.deepEqual(pc.calls, []);
  assert.equal(existsSync(join(pc.home, CURSOR)), false);
  assert.ok(existsSync(join(pc.home, ANTIGRAVITY)));
});

test("writes through a symlinked settings file without replacing the link", async () => {
  const pc = computer({ files: { "dotfiles/cursor.json": "{}\n" }, dirs: [".cursor"] });
  symlinkSync(join(pc.home, "dotfiles/cursor.json"), join(pc.home, CURSOR));
  assert.equal(await main("setup", { yes: true, clients: ["cursor"] }, pc.ctx), 0);
  assert.ok(lstatSync(join(pc.home, CURSOR)).isSymbolicLink());
  assert.deepEqual(JSON.parse(pc.read("dotfiles/cursor.json")).mcpServers[NAME], STDIO);
});

test("remove takes out only our entry", async () => {
  const pc = computer({
    bins: ["claude"],
    files: {
      [CURSOR]: JSON.stringify({ mcpServers: { github: { url: "https://example.com" }, [NAME]: STDIO } }),
      [CODEX]: `model = "o4"\n\n[mcp_servers.github]\nurl = "https://example.com"\n\n${CODEX_ENTRY}`,
    },
    replies: { [`claude mcp get ${NAME}`]: sequence(CLAUDE_OURS, CLAUDE_OURS, { status: 1 }) },
  });
  assert.equal(await main("remove", { yes: true }, pc.ctx), 0);
  assert.deepEqual(pc.json(CURSOR), { mcpServers: { github: { url: "https://example.com" } } });
  assert.equal(pc.read(CODEX), `model = "o4"\n\n[mcp_servers.github]\nurl = "https://example.com"\n`);
  assert.ok(pc.calls.includes(`claude mcp remove ${NAME} --scope user`));
  assert.match(pc.output(), /Cursor\s+removed/);
});

test("says where to go when it finds no assistants", async () => {
  const pc = computer();
  assert.equal(await main("setup", { yes: true }, pc.ctx), 0);
  assert.match(pc.output(), /No supported assistants found\. For other tools, follow https:\/\/custosa\.com\/labs\/setup/);
});

test("reads and edits only our tables in Codex's config.toml", () => {
  assert.deepEqual(codexServer(`[mcp_servers."${NAME}"]\ncommand = "npx" # ours\nargs = ["-y", "${PKG}", "inspect", "--stdio",]\n`, NAME), { found: true, command: "npx", args: STDIO.args });
  assert.deepEqual(codexServer(`[other]\nx = 1\n`, NAME), { found: false, command: null, args: null });
  assert.equal(codexServer(`mcp_servers.${NAME}.url = "${OLD}"\n`, NAME).other, true);
  assert.equal(codexServer(`[mcp_servers.${NAME}]\nargs = [\n  "-y",\n]\n`, NAME).other, true, "args over several lines are left for a person");
  assert.equal(codexAdd(`a = 1`, NAME, "npx", STDIO.args), `a = 1\n\n${CODEX_ENTRY}`);
  assert.equal(codexSetCommand(`[mcp_servers.${NAME}]\ncommand = "old"\nargs = ["a"]\n[x]\nurl = "keep"\n`, NAME, "npx", STDIO.args), `${CODEX_ENTRY}[x]\nurl = "keep"\n`);
  assert.equal(codexRemove(`a = 1\n\n[mcp_servers.${NAME}]\nurl = "u"\n\n[mcp_servers.${NAME}.http_headers]\nX = "y"\n\n[b]\nc = 2\n`, NAME), `a = 1\n\n[b]\nc = 2\n`);
});

test("leaves Codex's config.toml to a person when mcp_servers is an inline table or dotted keys at the root", async () => {
  for (const text of [`model = "o3"\nmcp_servers = { github = { command = "gh" } }\n`, `mcp_servers.github.command = "gh"\n`, `"mcp_servers".github.command = "gh"\n`]) {
    const pc = computer({ dirs: [".codex"], files: { [CODEX]: text } });
    assert.equal(await main("setup", { yes: true, clients: ["codex"] }, pc.ctx), 1);
    assert.equal(pc.read(CODEX), text);
    assert.match(pc.output(), /writes mcp_servers as an inline table or dotted keys, so a table for PHI Schema Check can’t be added safely/);
    assert.match(pc.output(), /by hand: https:\/\/custosa\.com\/labs\/setup\?assistant=codex/);
    assert.equal(readdirSync(join(pc.home, ".codex")).length, 1, "no backup, nothing written");
  }
  // a [mcp_servers] table with inline entries under it is fine: our table is a sibling
  const under = computer({ dirs: [".codex"], files: { [CODEX]: `[mcp_servers]\ngithub = { command = "gh" }\n` } });
  assert.equal(await main("setup", { yes: true, clients: ["codex"] }, under.ctx), 0);
  assert.equal(under.read(CODEX), `[mcp_servers]\ngithub = { command = "gh" }\n\n${CODEX_ENTRY}`);
});

test("leaves an unparsable Codex config.toml exactly as it is, prints the manual steps and exits non-zero", async () => {
  for (const text of ['[mcp_servers.other\ncommand = "x"\n= = =\n', 'model = """unclosed\n', 'a = 1\na = 2\n']) {
    const pc = computer({ dirs: [".codex"], files: { [CODEX]: text } });
    assert.equal(await main("setup", { yes: true, clients: ["codex"] }, pc.ctx), 1);
    assert.equal(pc.read(CODEX), text);
    assert.match(pc.output(), /isn’t valid TOML, so it was left as it is/);
    assert.match(pc.output(), /by hand: https:\/\/custosa\.com\/labs\/setup\?assistant=codex/);
    assert.equal(readdirSync(join(pc.home, ".codex")).length, 1, "no backup, nothing written");
  }
});

test("reads quoted keys, literal strings and CRLF in Codex's config.toml, refuses multi-line strings, and keeps a comment above the next table", async () => {
  assert.deepEqual(codexServer(`[mcp_servers.${NAME}]\n"command" = "node"\n`, NAME), { found: true, command: "node", args: null });
  assert.deepEqual(codexServer(`[mcp_servers.${NAME}]\ncommand = 'npx'\nargs = ['-y', '${PKG}', 'inspect', '--stdio']\n`, NAME), { found: true, command: "npx", args: STDIO.args });
  assert.equal(codexServer(`[mcp_servers.${NAME}]\ncommand = """\nnpx"""\n`, NAME).other, true);
  assert.equal(codexServer(`[mcp_servers.${NAME}]\ncommand = 42\n`, NAME).other, true);
  const crlf = computer({ dirs: [".codex"], files: { [CODEX]: `[profiles.x]\r\nmodel = "o3"\r\n` } });
  assert.equal(await main("setup", { yes: true, clients: ["codex"] }, crlf.ctx), 0);
  assert.equal(crlf.read(CODEX), `[profiles.x]\r\nmodel = "o3"\r\n\r\n${CODEX_ENTRY.replace(/\n/g, "\r\n")}`);
  const note = `${CODEX_ENTRY}\n# GitHub: keep this note\n[mcp_servers.github]\ncommand = "gh"\n`;
  assert.equal(codexRemove(note, NAME), `# GitHub: keep this note\n[mcp_servers.github]\ncommand = "gh"\n`);
  assert.equal(codexSetCommand(`[mcp_servers.${NAME}]\ncommand = "old"\n# next\n[x]\n`, NAME, "npx", STDIO.args), `${CODEX_ENTRY}# next\n[x]\n`);
});

test("keeps every other key on our entry, replaces only command and args, and never calls it an old address", async () => {
  const extra = { disabled: false, trust: true, alwaysAllow: ["check_schema"], cwd: "/x", envFile: ".env.phisc", env: { A: 1, B: "b" }, futureKey: { x: 1 } };
  const kept = computer({ files: { [CURSOR]: JSON.stringify({ mcpServers: { [NAME]: { ...STDIO, ...extra } } }) } });
  assert.equal(await main("setup", { yes: true, clients: ["cursor"] }, kept.ctx), 0);
  assert.match(kept.output(), /Cursor\s+already set up/);
  assert.equal(readdirSync(join(kept.home, ".cursor")).length, 1, "nothing rewritten");

  const other = computer({ files: { [CURSOR]: JSON.stringify({ mcpServers: { [NAME]: { command: "node", args: ["old.js"], ...extra } } }) } });
  assert.equal(await main("setup", { yes: true, clients: ["cursor"] }, other.ctx), 0);
  assert.deepEqual(other.json(CURSOR).mcpServers[NAME], { ...STDIO, ...extra });
  assert.match(other.output(), /Cursor\s+set up with a different command, will update it/);
  assert.doesNotMatch(other.output(), /old address/);
});

test("on Windows, starts npx through cmd /c in every assistant", async () => {
  const win = { command: "cmd", args: ["/c", "npx", "-y", PKG, "inspect", "--stdio"] };
  const pc = computer({ bins: ["claude", "codex", "code"], dirs: [".cursor", ".gemini/config"] });
  pc.ctx.platform = "win32";
  pc.ctx.env = { APPDATA: join(pc.home, "AppData") };
  assert.equal(await main("setup", { yes: true }, pc.ctx), 0);
  assert.deepEqual(pc.calls.filter((c) => !c.startsWith("claude mcp get")), [
    `claude mcp add --scope user ${NAME} -- cmd /c npx -y ${PKG} inspect --stdio`,
    `codex mcp add ${NAME} -- cmd /c npx -y ${PKG} inspect --stdio`,
    `code --add-mcp {"name":"${NAME}","type":"stdio","command":"cmd","args":["/c","npx","-y","${PKG}","inspect","--stdio"]}`,
  ]);
  assert.deepEqual(pc.json(CURSOR).mcpServers[NAME], win);
  assert.deepEqual(pc.json(ANTIGRAVITY).mcpServers[NAME], win);
  const file = computer({ dirs: [".codex"] });
  file.ctx.platform = "win32";
  assert.equal(await main("setup", { yes: true, clients: ["codex"] }, file.ctx), 0);
  assert.equal(file.read(CODEX), `[mcp_servers.${NAME}]\ncommand = "cmd"\nargs = ["/c", "npx", "-y", "${PKG}", "inspect", "--stdio"]\n${CODEX_TIMEOUT_LINES}`);
  assert.equal(await main("setup", { yes: true, clients: ["codex"] }, file.ctx), 0);
  assert.match(file.output(), /Codex\s+already set up/);
});

test("removes an old Claude Code entry only from the scope claude mcp get reports, and never ours when it is shadowed", async () => {
  // an old local entry shadows ours in user scope: only the local one goes, nothing is added
  const oldLocal = { status: 0, stdout: `${NAME}:\n  Scope: Local config (private to you in this project)\n  Type: stdio\n  Command: npx\n  Args: ${OLD_STDIO.args.join(" ")}\n` };
  const shadow = computer({ bins: ["claude"], files: { ".claude.json": JSON.stringify({ projects: { "/repo": { mcpServers: { [NAME]: OLD_STDIO } } } }) },
    replies: { [`claude mcp get ${NAME}`]: sequence(oldLocal, oldLocal, CLAUDE_OURS) } });
  shadow.ctx.cwd = "/repo";
  assert.equal(await main("setup", { yes: true }, shadow.ctx), 0);
  assert.deepEqual(shadow.calls.slice(1), [`claude mcp get ${NAME}`, `claude mcp remove ${NAME} --scope local`, `claude mcp get ${NAME}`]);
  assert.doesNotMatch(shadow.calls.join("\n"), /--scope user|mcp add/);
  assert.match(shadow.output(), /the old entry was removed from Claude Code’s local scope/);

  // the same, with env on the old local entry: it was in effect here, so it comes back in the local scope as ours
  const env = { CUSTOSA_PROJECT_ROOT: "/repo" };
  const kept = computer({ bins: ["claude"], files: { ".claude.json": JSON.stringify({ projects: { "/repo": { mcpServers: { [NAME]: { ...OLD_STDIO, env } } } } }) },
    replies: { [`claude mcp get ${NAME}`]: sequence(oldLocal, oldLocal, CLAUDE_OURS) } });
  kept.ctx.cwd = "/repo";
  assert.equal(await main("setup", { yes: true }, kept.ctx), 0);
  assert.deepEqual(kept.calls.slice(1), [`claude mcp get ${NAME}`, `claude mcp remove ${NAME} --scope local`, `claude mcp get ${NAME}`,
    `claude mcp add-json --scope local ${NAME} ${JSON.stringify({ type: "stdio", ...STDIO, env })}`]);
  assert.doesNotMatch(kept.calls.join("\n"), /--scope user/);
  assert.match(kept.output(), /updated in Claude Code’s local scope, keeping its env and other settings/);

  // no scope we can read: nothing is removed, and the person is told how
  const none = computer({ bins: ["claude"], replies: { [`claude mcp get ${NAME}`]: { status: 0, stdout: `URL: ${OLD}` } } });
  assert.equal(await main("setup", { yes: true }, none.ctx), 1);
  assert.doesNotMatch(none.calls.join("\n"), /mcp remove|mcp add/);
  assert.match(none.output(), /didn’t say which scope holds the entry\. Remove it with claude mcp remove custosa-phi-schema-check --scope <user\|local\|project>/);
});

/* A stateful stand-in for `claude mcp get|add|remove` across its three scopes (local shadows project shadows user). */
const LABEL = { user: "User config (available in all your projects)", local: "Local config (private to you in this project)", project: "Project config (shared via .mcp.json)" };
function claudeState(pc, state) {
  pc.ctx.which = (c) => (c === "claude" ? "/x/claude" : null);
  pc.ctx.cwd = "/repo";
  pc.ctx.run = (cmd, args) => {
    const line = [cmd, ...args].join(" ");
    pc.calls.push(line);
    const [, verb] = args;
    const scopeArg = args[args.indexOf("--scope") + 1];
    if (verb === "get") {
      const scope = ["local", "project", "user"].find((x) => state[x]);
      if (!scope) return { status: 1, stdout: "" };
      const e = state[scope];
      return { status: 0, stdout: `${NAME}:\n  Scope: ${LABEL[scope]}\n` + (e.url ? `  Type: http\n  URL: ${e.url}\n` : `  Type: stdio\n  Command: ${e.command}\n  Args: ${e.args.join(" ")}\n`) };
    }
    if (verb === "remove") { if (!state[scopeArg]) return { status: 1, stdout: "" }; state[scopeArg] = null; return { status: 0, stdout: "" }; }
    if (verb === "add") { if (state[scopeArg]) return { status: 1, stdout: "" }; const dd = args.indexOf("--"); state[scopeArg] = { command: args[dd + 1], args: args.slice(dd + 2) }; return { status: 0, stdout: "" }; }
    if (verb === "add-json") { if (state[scopeArg]) return { status: 1, stdout: "" }; state[scopeArg] = JSON.parse(args.at(-1)); return { status: 0, stdout: "" }; }
    return { status: 2, stdout: "" };
  };
  return state;
}

test("asks before removing an entry from the repository's shared .mcp.json, and without --yes or a terminal leaves it", async () => {
  const inRepo = (pc) => { pc.ctx.cwd = join(pc.home, "repo"); return join(pc.ctx.cwd, ".mcp.json"); };
  const unattended = computer({ files: { "repo/.mcp.json": JSON.stringify({ mcpServers: { [NAME]: OLD_STDIO } }) } });
  const s1 = claudeState(unattended, { project: OLD_STDIO });
  inRepo(unattended);
  assert.equal(await main("setup", { yes: false, clients: ["claude-code"] }, unattended.ctx), 1);
  const asked = computer({ interactive: true, answers: [true, false], files: { "repo/.mcp.json": JSON.stringify({ mcpServers: { [NAME]: OLD_STDIO } }) } });
  const s2 = claudeState(asked, { project: OLD_STDIO });
  const file = inRepo(asked);
  assert.equal(await main("setup", { clients: ["claude-code"] }, asked.ctx), 1);
  assert.deepEqual(asked.asked.slice(0, 2), ["Add PHI Schema Check to Claude Code?", `Remove it from ${file}?`]);
  assert.deepEqual(s2, { project: OLD_STDIO });
  assert.ok(asked.output().includes(`left the project-scope entry in ${file} as it is. Run setup again with --yes to remove it, or edit that file yourself`));
  assert.deepEqual(s1, { project: OLD_STDIO });
});

test("remove takes our entry out of every scope it is in, as claude mcp get reports them", async () => {
  const pc = computer();
  const state = claudeState(pc, { local: STDIO, user: STDIO });
  assert.equal(await main("remove", { yes: true, clients: ["claude-code"] }, pc.ctx), 0);
  assert.deepEqual(state, { local: null, user: null });
  assert.deepEqual(pc.calls.filter((c) => c.includes("remove")), [`claude mcp remove ${NAME} --scope local`, `claude mcp remove ${NAME} --scope user`]);
  assert.match(pc.output(), /removed from Claude Code’s local and user scopes/);
});

test("a dry run says an outdated entry would be updated, and an entry with a non-stdio type is not ours", async () => {
  const pc = computer({ files: { [CURSOR]: JSON.stringify({ mcpServers: { [NAME]: { url: OLD } } }) } });
  assert.equal(await main("setup", { clients: ["cursor"] }, { ...pc.ctx, dryRun: true }), 0);
  assert.match(pc.output(), /Cursor\s+would be updated/);
  // a dry run removes nothing from Claude Code, so it never says the old entry was removed.
  const cc = computer({ files: { ".claude.json": JSON.stringify({ mcpServers: { [NAME]: OLD_STDIO } }) } });
  const ccState = claudeState(cc, { user: OLD_STDIO });
  const ccRc = await main("setup", { clients: ["claude-code"] }, { ...cc.ctx, dryRun: true });
  assert.equal(ccRc, 0, cc.output());
  assert.deepEqual(ccState, { user: OLD_STDIO });
  assert.doesNotMatch(cc.output(), /was removed/);
  assert.match(cc.output(), /the old entry would be removed from Claude Code’s user scope/);
  const typed = computer({ files: { [VSCODE]: JSON.stringify({ servers: { [NAME]: { type: "sse", ...STDIO } } }) } });
  assert.equal(await main("setup", { yes: true, clients: ["vscode"] }, typed.ctx), 0);
  assert.match(typed.output(), /VS Code\s+set up with a different command, will update it/);
  assert.deepEqual(typed.json(VSCODE).servers[NAME], { type: "stdio", ...STDIO });
});

test("keeps numbers whose value survives a rewrite (30.0, 1E2, 1e+21)", async () => {
  const text = `{"mcpServers":{},"a":30.0,"b":1E2,"c":1e+21,"d":0.1}`;
  const pc = computer({ files: { [CURSOR]: text } });
  assert.equal(await main("setup", { yes: true, clients: ["cursor"] }, pc.ctx), 0);
  assert.deepEqual([pc.json(CURSOR).a, pc.json(CURSOR).b, pc.json(CURSOR).c, pc.json(CURSOR).d], [30, 100, 1e21, 0.1]);
});

test("leaves a JSON settings file alone when rewriting it would lose or change something", async () => {
  const cases = [
    [`{"mcpServers":{"gh":{"url":"x"},},}`, /has a trailing comma, so it was left as it is/],
    [`{"mcpServers":{"gh":{"url":"x","env":{"ID":12345678901234567890}}}}`, /has the number 12345678901234567890, whose value would change if setup rewrote the file/],
    [`{"mcpServers":{},"a":1,"a":2}`, /has the key "a" twice in one object/],
    [`{"mcpServers":{},"n":1e400}`, /has the number 1e400, whose value would change if setup rewrote the file/],
    [`{"mcpServers":{},"n":1e-400}`, /has the number 1e-400/],
    [`{"mcpServers":{},"n":-0}`, /has the number -0/],
    [`{"mcpServers": null}`, /has an unexpected "mcpServers"/],
  ];
  for (const [text, why] of cases) {
    const pc = computer({ files: { [CURSOR]: text } });
    assert.equal(await main("setup", { yes: true, clients: ["cursor"] }, pc.ctx), 1, text);
    assert.equal(pc.read(CURSOR), text);
    assert.match(pc.output(), why);
    assert.equal(readdirSync(join(pc.home, ".cursor")).length, 1);
  }
  const ro = computer({ files: { [CURSOR]: `{"mcpServers":{}}` } });
  chmodSync(join(ro.home, CURSOR), 0o444);
  assert.equal(await main("setup", { yes: true, clients: ["cursor"] }, ro.ctx), 1);
  assert.match(ro.output(), /is read-only, so it was left as it is/);
  assert.equal(ro.read(CURSOR), `{"mcpServers":{}}`);
  assert.equal(statSync(join(ro.home, CURSOR)).mode & 0o777, 0o444);

  const dangling = computer({ dirs: [".cursor"] });
  symlinkSync(join(dangling.home, "dotfiles/mcp.json"), join(dangling.home, CURSOR));
  assert.equal(await main("setup", { yes: true, clients: ["cursor"] }, dangling.ctx), 1);
  assert.match(dangling.output(), /is a symbolic link to a file that doesn’t exist/);
  assert.ok(lstatSync(join(dangling.home, CURSOR)).isSymbolicLink());
  assert.equal(existsSync(join(dangling.home, "dotfiles")), false);
});

test("keeps CRLF line endings and a 16-digit number that survives, and never overwrites an earlier backup", async () => {
  const crlf = `{\r\n  "mcpServers": {\r\n    "gh": {"url": "x", "n": 1234567890123456}\r\n  }\r\n}\r\n`;
  const pc = computer({ files: { [CURSOR]: crlf } });
  assert.equal(await main("setup", { yes: true, clients: ["cursor"] }, pc.ctx), 0);
  const after = pc.read(CURSOR);
  assert.ok(after.includes("\r\n") && !/[^\r]\n/.test(after), "every line ends in CRLF");
  assert.equal(JSON.parse(after).mcpServers.gh.n, 1234567890123456);
  // setup then remove in the same second: two backups, the original kept
  assert.equal(await main("remove", { yes: true, clients: ["cursor"] }, pc.ctx), 0);
  const backups = readdirSync(join(pc.home, ".cursor")).filter((f) => f.includes("custosa-backup")).sort();
  assert.deepEqual(backups, ["mcp.json.custosa-backup-20261009-120000", "mcp.json.custosa-backup-20261009-120000-1"]);
  assert.equal(pc.read(`.cursor/${backups[0]}`), crlf);
});

test("reads its options strictly", () => {
  assert.deepEqual(parse([]), { mode: "setup", yes: false, dryRun: false, clients: null, environment: null });
  assert.deepEqual(parse(["remove", "-y", "--client=cursor,codex"]), { mode: "remove", yes: true, dryRun: false, clients: ["cursor", "codex"], environment: null });
  assert.equal(parse(["--environment", "production"]).environment, "production");
  assert.equal(parse(["--environment=unknown"]).environment, "unknown");
  assert.throws(() => parse(["--environment", "prod"]), /Unknown environment "prod"\. Choose from: development, staging, production, unknown\./);
  assert.throws(() => parse(["--environment"]), /Unknown environment ""/);
  assert.deepEqual(parse(["--client", "vscode", "--dry-run"]).clients, ["vscode"]);
  assert.throws(() => parse(["install"]), /Unknown command "install"/);
  assert.throws(() => parse(["--force"]), /Unknown option "--force"/);
  assert.throws(() => parse(["--client", "windsurf"]), /Unknown assistant "windsurf"/);
  assert.throws(() => parse(["--client"]), /Unknown assistant/);
});

test("quotes arguments for Windows command launchers", () => {
  assert.equal(winQuote("mcp"), "mcp");
  assert.equal(winQuote('{"name":"x"}'), '"{\\"name\\":\\"x\\"}"');
  assert.equal(winQuote("C:\\Program Files\\x\\"), '"C:\\Program Files\\x\\\\"');
  assert.equal(winQuote(""), '""');
});

test("shares its prompt and price with the setup page", async () => {
  const shared = JSON.parse(readFileSync(new URL("../lib/shared.json", import.meta.url), "utf8"));
  assert.equal(NAME, shared.name);
  assert.equal(shared.server, undefined, "the hosted address is gone: setup registers the local inspector");
  const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  assert.equal(pkg.version, "0.1.2");
  assert.equal(shared.inspectorVersion, pkg.version, "the setup page's pinned entry is this package's version");
  assert.ok(pkg.files.includes("lib"), "shared.json ships inside lib/");
});

test("remove leaves a lane agent file an earlier version saved: setup no longer knows it", async () => {
  const LANE = ".claude/agents/phisc-lane.md";
  const pc = computer({ dirs: [".cursor"], files: { [LANE]: "lane\n" } });
  assert.equal(await main("remove", { yes: true }, pc.ctx), 0);
  assert.ok(existsSync(join(pc.home, LANE)));
  assert.doesNotMatch(pc.output(), /lane/i);
});

test("offers no lane agent: the response contract has no lanes", async () => {
  const pc = computer({ bins: ["claude"], dirs: [".cursor"], interactive: true });
  assert.equal(await main("setup", {}, pc.ctx), 0);
  assert.equal(existsSync(join(pc.home, ".claude/agents")), false);
  assert.doesNotMatch(pc.output() + pc.asked.join("\n"), /lane/i);
  assert.equal(existsSync(new URL("../lib/lane.mjs", import.meta.url)), false);
  assert.equal(existsSync(new URL("../lib/phisc-lane.md", import.meta.url)), false);
});

/* M1: a version bump keeps what the person set on the entry. */
const UNPINNED = { command: "npx", args: ["-y", "custosa@0.0.9", "inspect", "--stdio"] };
const USER_ENV = { CUSTOSA_PROJECT_ROOT: "/work/app", OTHER: "1" };

test("upgrade, Claude Code: an entry pinned to another version keeps its scope and env (add-json), never moved to user", async () => {
  for (const scope of ["local", "user", "project"]) {
    const old = { type: "stdio", ...UNPINNED, env: USER_ENV };
    const files = scope === "project" ? {} : { ".claude.json": JSON.stringify(scope === "user" ? { mcpServers: { [NAME]: old } } : { projects: { "/repo": { mcpServers: { [NAME]: old } } } }) };
    const pc = computer({ files });
    const state = claudeState(pc, { [scope]: { ...UNPINNED } });
    if (scope === "project") { // the repository's shared file: written back where it was
      mkdirSync(join(pc.home, "repo"), { recursive: true });
      pc.ctx.cwd = join(pc.home, "repo");
      writeFileSync(join(pc.home, "repo", ".mcp.json"), JSON.stringify({ mcpServers: { [NAME]: old } }));
    }
    assert.equal(await main("setup", { yes: true, clients: ["claude-code"] }, pc.ctx), 0, pc.output());
    assert.deepEqual(state[scope], { type: "stdio", ...STDIO, env: USER_ENV }, scope);
    for (const other of ["local", "user", "project"].filter((x) => x !== scope)) assert.ok(!state[other], `${scope}: nothing added in ${other}`);
    assert.ok(pc.calls.some((c) => c.startsWith(`claude mcp add-json --scope ${scope} ${NAME} `)), pc.calls.join("\n"));
  }
});

test("upgrade, Codex with its command installed: config.toml is edited in place; env and a person's timeout stay", async () => {
  const before = `model = "o4"\n\n[mcp_servers.${NAME}]\ncommand = "npx"\nargs = ["-y", "custosa@0.0.9", "inspect", "--stdio"]\ntool_timeout_sec = 900\n\n[mcp_servers.${NAME}.env]\nCUSTOSA_PROJECT_ROOT = "/work/app"\n`;
  const pc = computer({ bins: ["codex"], files: { [CODEX]: before } });
  assert.equal(await main("setup", { yes: true, clients: ["codex"] }, pc.ctx), 0, pc.output());
  assert.deepEqual(pc.calls.filter((c) => c.startsWith("codex")), [], "no codex mcp remove or add");
  assert.equal(pc.read(CODEX), `model = "o4"\n\n[mcp_servers.${NAME}]\ncommand = "npx"\nargs = ["-y", "${PKG}", "inspect", "--stdio"]\nstartup_timeout_sec = 60\ntool_timeout_sec = 900\n\n[mcp_servers.${NAME}.env]\nCUSTOSA_PROJECT_ROOT = "/work/app"\n`);
  assert.equal(await main("setup", { yes: true, clients: ["codex"] }, pc.ctx), 0);
  assert.match(pc.output(), /Codex\s+already set up/);
});

test("M-A: Claude Code upgrades find a local entry keyed at the git root above (or the real path of) the working directory", async () => {
  const repoRoot = realpathSync(mkdtempSync(join(tmpdir(), "custosa-gitroot-")));
  mkdirSync(join(repoRoot, ".git"));
  mkdirSync(join(repoRoot, "packages", "web"), { recursive: true });
  const pc = computer({ files: { ".claude.json": JSON.stringify({ projects: { [repoRoot]: { mcpServers: { [NAME]: { type: "stdio", ...UNPINNED, env: USER_ENV } } } } }) } });
  const state = claudeState(pc, { local: { ...UNPINNED } });
  pc.ctx.cwd = join(repoRoot, "packages", "web");
  assert.equal(await main("setup", { yes: true, clients: ["claude-code"] }, pc.ctx), 0, pc.output());
  assert.deepEqual(state.local, { type: "stdio", ...STDIO, env: USER_ENV });
  // no git root: a key above the working directory is not taken; setup stops with the manual steps
  const loose = computer({ files: { ".claude.json": JSON.stringify({ projects: { "/nowhere-xyz/app": { mcpServers: { [NAME]: { type: "stdio", ...UNPINNED, env: USER_ENV } } } } }) } });
  const s0 = claudeState(loose, { local: { ...UNPINNED } });
  loose.ctx.cwd = "/nowhere-xyz/app/packages/web";
  assert.equal(await main("setup", { yes: true, clients: ["claude-code"] }, loose.ctx), 1);
  assert.deepEqual(s0.local, { ...UNPINNED }, "left as it was");
  // a symlinked working directory: found through its real path
  const real = realpathSync(mkdtempSync(join(tmpdir(), "custosa-real-")));
  const link = join(tmpdir(), `custosa-link-${process.pid}-${Date.now()}`);
  symlinkSync(real, link);
  const viaLink = computer({ files: { ".claude.json": JSON.stringify({ projects: { [real]: { mcpServers: { [NAME]: { type: "stdio", ...UNPINNED, env: USER_ENV } } } } }) } });
  const s2 = claudeState(viaLink, { local: { ...UNPINNED } });
  viaLink.ctx.cwd = link;
  assert.equal(await main("setup", { yes: true, clients: ["claude-code"] }, viaLink.ctx), 0, viaLink.output());
  assert.deepEqual(s2.local, { type: "stdio", ...STDIO, env: USER_ENV });
});

test("M-A: a user entry and a local override are both restored, each with its own env", async () => {
  const userEntry = { type: "stdio", ...UNPINNED, env: { A: "user" } };
  const localEntry = { type: "stdio", ...UNPINNED, env: USER_ENV };
  const pc = computer({ files: { ".claude.json": JSON.stringify({ mcpServers: { [NAME]: userEntry }, projects: { "/repo": { mcpServers: { [NAME]: localEntry } } } }) } });
  const state = claudeState(pc, { user: { ...UNPINNED }, local: { ...UNPINNED } });
  assert.equal(await main("setup", { yes: true, clients: ["claude-code"] }, pc.ctx), 0, pc.output());
  assert.deepEqual(state.user, { type: "stdio", ...STDIO, env: { A: "user" } });
  assert.deepEqual(state.local, { type: "stdio", ...STDIO, env: USER_ENV });
  assert.ok(!state.project);
});

test("The exact key wins over a key that differs only in case (a case-sensitive volume can hold both)", async () => {
  const UPPER = { type: "stdio", ...UNPINNED, env: { CUSTOSA_PROJECT_ROOT: "/Volumes/dev/App" } };
  const LOWER = { type: "stdio", ...UNPINNED, env: { CUSTOSA_PROJECT_ROOT: "/Volumes/dev/app" } };
  const projects = { "/Volumes/dev/App": { mcpServers: { [NAME]: UPPER } }, "/Volumes/dev/app": { mcpServers: { [NAME]: LOWER } } };
  const pc = computer({ files: { ".claude.json": JSON.stringify({ projects }) } });
  const state = claudeState(pc, { local: { ...UNPINNED } });
  pc.ctx.cwd = "/Volumes/dev/app";
  assert.equal(await main("setup", { yes: true, clients: ["claude-code"] }, pc.ctx), 0, pc.output());
  assert.deepEqual(state.local.env, LOWER.env);
});

test("Never takes another project's entry: a differently-cased key, the home folder, an entry that disagrees", async () => {
  const OTHER = { type: "stdio", ...UNPINNED, env: { CUSTOSA_PROJECT_ROOT: "/Users/u/other-clinic" } };
  const MINE = { type: "stdio", ...UNPINNED, env: { CUSTOSA_PROJECT_ROOT: "/Users/u/Work/App" } };
  const projects = { "/Users/u/Work/App": { mcpServers: { [NAME]: MINE } }, "/Users/u": { mcpServers: { [NAME]: OTHER } } };
  // macOS (case-insensitive): Claude Code's key is the same folder spelled with other case: that one, never the home's
  const mac = computer({ files: { ".claude.json": JSON.stringify({ projects }) } });
  const s1 = claudeState(mac, { local: { ...UNPINNED } });
  mac.ctx.cwd = "/Users/u/work/app";
  assert.equal(await main("setup", { yes: true, clients: ["claude-code"] }, mac.ctx), 0, mac.output());
  assert.deepEqual(s1.local.env, MINE.env);
  // Linux (case-sensitive): no exact key, no git root: refused, never other-clinic
  const linux = computer({ files: { ".claude.json": JSON.stringify({ projects }) } });
  linux.ctx.platform = "linux";
  const s2 = claudeState(linux, { local: { ...UNPINNED } });
  linux.ctx.cwd = "/Users/u/work/app";
  assert.equal(await main("setup", { yes: true, clients: ["claude-code"] }, linux.ctx), 1);
  assert.deepEqual(s2.local, { ...UNPINNED });
  // a git root at the home folder (a dotfiles repository): the home folder's own key is never taken
  const home = realpathSync(mkdtempSync(join(tmpdir(), "custosa-home-")));
  mkdirSync(join(home, ".git"));
  mkdirSync(join(home, "proj"));
  const dot = computer({ files: {} });
  dot.ctx.home = home;
  writeFileSync(join(home, ".claude.json"), JSON.stringify({ projects: { [home]: { mcpServers: { [NAME]: OTHER } } } }));
  const s3 = claudeState(dot, { local: { ...UNPINNED } });
  dot.ctx.cwd = join(home, "proj");
  assert.equal(await main("setup", { yes: true, clients: ["claude-code"] }, dot.ctx), 1);
  assert.deepEqual(s3.local, { ...UNPINNED });
  // inside the git root, a key above whose env disagrees with what claude mcp get printed is not taken
  const root = realpathSync(mkdtempSync(join(tmpdir(), "custosa-gr-")));
  mkdirSync(join(root, ".git")); mkdirSync(join(root, "sub"));
  const env = computer({ files: { ".claude.json": JSON.stringify({ projects: { [root]: { mcpServers: { [NAME]: OTHER } } } }) } });
  const s4 = claudeState(env, { local: { ...UNPINNED } });
  const run = env.ctx.run;
  env.ctx.run = (cmd, args) => { const r = run(cmd, args); return args[1] === "get" && r.status === 0 ? { ...r, stdout: `${r.stdout}  Environment:\n    CUSTOSA_PROJECT_ROOT=${root}/sub\n` } : r; };
  env.ctx.cwd = join(root, "sub");
  assert.equal(await main("setup", { yes: true, clients: ["claude-code"] }, env.ctx), 1);
  assert.deepEqual(s4.local, { ...UNPINNED });
});

test("Claude Code's settings are read from $CLAUDE_CONFIG_DIR when it is set", async () => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "custosa-ccd-")));
  writeFileSync(join(dir, ".claude.json"), JSON.stringify({ mcpServers: { [NAME]: { type: "stdio", ...UNPINNED, env: USER_ENV } } }));
  const pc = computer();
  pc.ctx.env = { CLAUDE_CONFIG_DIR: dir };
  const state = claudeState(pc, { user: { ...UNPINNED } });
  assert.equal(await main("setup", { yes: true, clients: ["claude-code"] }, pc.ctx), 0, pc.output());
  assert.deepEqual(state.user, { type: "stdio", ...STDIO, env: USER_ENV });
});

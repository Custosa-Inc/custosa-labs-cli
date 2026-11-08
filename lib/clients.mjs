/* The assistants `custosa setup` knows, how to tell each is installed, and how to add or remove PHI Schema Check.
   Each gets the local inspector, a stdio MCP server started as `npx -y custosa inspect --stdio` (bin/custosa.mjs).
   Where an assistant has its own command for this we use it; otherwise we edit its settings file (lib/files.mjs). An
   entry counts as set up only when it is exactly ours; any other entry under our name is outdated and updated. The
   steps match https://custosa.com/labs/setup. */
import { existsSync, realpathSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { editJson, readSettings, readText, Unreadable, writeSafely } from "./files.mjs";
import { codexAdd, codexEnsureTimeouts, codexRemove, codexServer, codexSetCommand } from "./toml.mjs";
import { parseToml } from "./inspector/tomlparse.mjs";

import { SHARED } from "./shared.mjs";

export const NAME = SHARED.name;
/* The inspector's command, the same one bin/custosa.mjs answers and the setup page prints for adding it by hand. It pins
   this package's version (custosa@<version>), so an assistant starts the inspector setup was run with, never whatever
   the npx cache or the registry holds that day; running a newer setup moves the pin (an entry pinned to another
   version counts as outdated and is updated). */
import { VERSION } from "./version.mjs";

export { VERSION };
export const INSPECT = Object.freeze(["npx", "-y", `custosa@${VERSION}`, "inspect", "--stdio"]);
export const ARGS = Object.freeze(INSPECT.slice(1));
/* On Windows npx is a .cmd script that an assistant can't start directly, so the command runs through cmd /c (as Claude
   Code's and Cursor's own Windows instructions do). */
export const launch = (ctx) => (ctx.platform === "win32" ? ["cmd", "/c", ...INSPECT] : [...INSPECT]);
const stdio = (ctx) => { const [command, ...args] = launch(ctx); return { command, args }; };
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
/* Our entry is the command and its args. Everything else on it is the person's (env, disabled, trust, alwaysAllow, cwd,
   envFile, or keys we don't know): kept when the entry is updated and never a reason to count it as different. A
   foreign entry under our name (one with an address, or a type other than stdio) is replaced by ours, keeping none of
   its keys. */
const isEntry = (v) => Boolean(v) && typeof v === "object" && !Array.isArray(v);
const foreign = (server) => ["url", "serverUrl", "httpUrl"].some((k) => k in server) || ("type" in server && server.type !== "stdio");
function isOurs(server, entry) {
  if (!isEntry(server) || foreign(server)) return false;
  return Object.entries(entry).every(([k, v]) => same(server[k], v));
}
function merged(server, entry) {
  if (!isEntry(server) || foreign(server)) return { ...entry };
  const kept = Object.fromEntries(Object.entries(server).filter(([k]) => !(k in entry)));
  return { ...entry, ...kept }; // kept holds no key of entry, so entry's keys come first and keep their values
}

export class CommandFailed extends Error {
  constructor(command, status) { super(`\`${command.join(" ")}\` exited with ${status}`); }
}

/* a command that changes something; a dry run only says what it would do */
function must(ctx, command, args, options) {
  if (ctx.dryRun) return { status: 0, stdout: "" };
  const result = ctx.run(command, args, options);
  if (result.status !== 0) throw new CommandFailed([command, ...args], result.status);
  return result;
}

/** A client configured through one JSON settings file with a top-level object of servers. */
function jsonFile({ path, group, entry }) {
  const current = (ctx) => readSettings(path(ctx))[group]?.[NAME];
  return {
    status(ctx) {
      const server = current(ctx);
      return !server ? "ready" : isOurs(server, entry(ctx)) ? "configured" : "outdated";
    },
    add(ctx) {
      const { backup } = editJson(path(ctx), (settings) => {
        if (settings[group] !== undefined && (!settings[group] || typeof settings[group] !== "object" || Array.isArray(settings[group]))) throw new Unreadable(path(ctx), `has an unexpected "${group}"`);
        const existing = settings[group]?.[NAME];
        const next = merged(existing, entry(ctx));
        if (same(existing, next)) return false;
        settings[group] = { ...settings[group], [NAME]: next };
      }, ctx);
      return { backup };
    },
    remove(ctx) {
      const { backup } = editJson(path(ctx), (settings) => {
        if (!settings[group]?.[NAME]) return false;
        delete settings[group][NAME];
      }, ctx);
      return { backup };
    },
  };
}

function vscodeSettings(ctx) {
  const base = ctx.platform === "darwin" ? join(ctx.home, "Library", "Application Support")
    : ctx.platform === "win32" ? (ctx.env.APPDATA || join(ctx.home, "AppData", "Roaming"))
    : (ctx.env.XDG_CONFIG_HOME || join(ctx.home, ".config"));
  return join(base, "Code", "User", "mcp.json");
}
const codexHome = (ctx) => ctx.env.CODEX_HOME || join(ctx.home, ".codex");
const codexConfig = (ctx) => join(codexHome(ctx), "config.toml");

const cursor = jsonFile({ path: (ctx) => join(ctx.home, ".cursor", "mcp.json"), group: "mcpServers", entry: stdio });
/* Antigravity and Antigravity CLI share ~/.gemini/config/mcp_config.json (antigravity.google/docs/mcp). Older
   Antigravity versions read ~/.gemini/antigravity/mcp_config.json, which is kept in step when it exists. */
const antigravityFile = (...dirs) => jsonFile({ path: (ctx) => join(ctx.home, ".gemini", ...dirs, "mcp_config.json"), group: "mcpServers", entry: stdio });
const antigravityShared = antigravityFile("config"), antigravityOlder = antigravityFile("antigravity");
const antigravityFiles = (ctx) => [antigravityShared, ...(existsSync(join(ctx.home, ".gemini", "antigravity", "mcp_config.json")) ? [antigravityOlder] : [])];
const eachFile = (ctx, action) => ({ backup: antigravityFiles(ctx).map((f) => f[action](ctx).backup).filter(Boolean).join(", ") || null });
const vscodeFile = jsonFile({ path: vscodeSettings, group: "servers", entry: (ctx) => ({ type: "stdio", ...stdio(ctx) }) });
/* Gemini CLI's user settings; edited directly (its `mcp add` would read the inspector's -y as its own option) */
const geminiFile = jsonFile({ path: (ctx) => join(ctx.home, ".gemini", "settings.json"), group: "mcpServers", entry: stdio });

/* `claude mcp get` prints the entry's Command and Args lines; only exactly ours counts as set up. */
function claudeEntryIsOurs(stdout, ctx) {
  const shown = printed(stdout);
  const [command, ...args] = launch(ctx);
  return shown.command === command && shown.args === args.join(" ");
}
/* The scope `claude mcp get` reports for the entry it shows (the one in effect): "Scope: User config ...", "Local config
   ...", "Project config ...". null when it says none we know. */
export function claudeScope(stdout) {
  const m = String(stdout || "").match(/^\s*Scope:\s*(User|Local|Project)\b/im);
  return m ? m[1].toLowerCase() : null;
}
const MAX_SCOPES = 4; // user, local and project, and one more look to see none is left

/* A project-scope entry lives in the repository's .mcp.json, which teammates share: say so, and change it only with
   --yes or a yes at the terminal. */
async function projectOk(ctx, yes, verb) {
  const file = join(ctx.cwd ?? process.cwd(), ".mcp.json");
  ctx.out(`    The ${NAME} entry in the project scope is in ${file}, the repository’s shared file your teammates use.`);
  if (ctx.dryRun || yes) return true;
  if (ctx.interactive && await ctx.ask(`${verb} it from ${file}?`)) return true;
  throw new Error(`left the project-scope entry in ${file} as it is. Run setup again with --yes to ${verb.toLowerCase()} it, or edit that file yourself`);
}

/* Removes entries under our name, scope by scope, as `claude mcp get` reports the one in effect, until it shows `stop`
   (ours, for setup) or nothing. Each removal is only from the scope get named. Returns the scopes removed and what
   get showed last. */
async function claudeClear(ctx, yes, { keepOurs, onFound = null }) {
  const removed = [];
  for (let i = 0; i < MAX_SCOPES; i++) {
    const found = ctx.run("claude", ["mcp", "get", NAME]);
    if (found.status !== 0) return { removed, last: "none" };
    if (keepOurs && claudeEntryIsOurs(found.stdout, ctx)) return { removed, last: "ours", scope: claudeScope(found.stdout) };
    const scope = claudeScope(found.stdout);
    if (!scope) throw new Error(`\`claude mcp get ${NAME}\` didn’t say which scope holds the entry. Remove it with claude mcp remove ${NAME} --scope <user|local|project>, then run setup again`);
    if (onFound) onFound(found, scope, removed); // before this scope's entry is removed (it may throw to stop here)
    if (scope === "project") await projectOk(ctx, yes, "Remove");
    must(ctx, "claude", ["mcp", "remove", NAME, "--scope", scope]);
    removed.push(scope);
    if (ctx.dryRun) return { removed, last: "dry" };
  }
  throw new Error(`Claude Code still shows a ${NAME} entry after removing it from the ${removed.join(", ")} scopes`);
}
/* "Claude Code’s user scope", "Claude Code’s local and user scopes": the scopes a note names, in the order given. */
const claudeScopes = (scopes) => `Claude Code’s ${scopes.join(" and ")} scope${scopes.length > 1 ? "s" : ""}`;
// A dry run removes nothing, so it says what would go.
const scopesNote = (removed, dryRun) => removed.length
  ? { note: `the old entry ${dryRun ? "would be" : "was"} removed from ${claudeScopes(removed)}` } : {};

/* ~/.claude.json: Claude Code's own settings, read only to see what `claude mcp get` can't (an entry shadowed by the
   one in effect). */
function claudeSettings(ctx) {
  try { return readSettings(claudeSettingsFile(ctx)); } catch { return {}; }
}
// Claude Code keeps it in $CLAUDE_CONFIG_DIR when that is set, else in the home folder.
const claudeSettingsFile = (ctx) => join(ctx.env?.CLAUDE_CONFIG_DIR || ctx.home, ".claude.json");
// The file as a message names it: ~/.claude.json in the home folder, else its full path.
const claudeSettingsShown = (ctx) => (ctx.env?.CLAUDE_CONFIG_DIR ? claudeSettingsFile(ctx) : "~/.claude.json");

/* Where a project's local entry may be keyed, or its .mcp.json kept: first the working directory and its real
   path, exactly (compared without case on a case-insensitive disk, macOS and Windows by default, the usual reason
   Claude Code's key differs); then, only inside the git root (the nearest folder above holding a .git entry), the
   folders between it and the working directory, never the home folder or a folder above it, and only for an entry
   whose command, args and env agree with what `claude mcp get` printed. Anything else is not this project's entry. */
const caseless = (ctx) => (ctx.platform ?? process.platform) === "darwin" || (ctx.platform ?? process.platform) === "win32";
function projectPlaces(ctx) {
  const start = resolve(ctx.cwd ?? process.cwd());
  const exact = [start];
  try { const real = realpathSync(start); if (real !== start) exact.push(real); } catch { /* not on disk */ }
  const home = resolve(ctx.home);
  const within = (dir, top) => dir === top || dir.startsWith(top.endsWith("/") ? top : `${top}/`);
  const ancestors = [];
  for (const first of exact) {
    let git = null;
    for (let dir = first; ; dir = dirname(dir)) {
      if (existsSync(join(dir, ".git"))) { git = dir; break; }
      if (dirname(dir) === dir) break;
    }
    if (!git) continue; // no git root: nothing above the working directory is taken
    for (let dir = dirname(first); within(dir, git) && dir !== first; dir = dirname(dir)) {
      if (!within(home, dir) && !ancestors.includes(dir)) ancestors.push(dir); // never the home folder or above it
      if (dir === git) break;
    }
  }
  return { exact, ancestors };
}
const sameKey = (ctx, a, b) => (caseless(ctx) ? a.toLowerCase() === b.toLowerCase() : a === b);

/* The Command, Args and Environment lines `claude mcp get` printed (Environment only when it shows them). */
function printed(stdout) {
  const text = String(stdout || "");
  const field = (name) => text.split("\n").map((l) => l.match(new RegExp(`^\\s*${name}:\\s*(.*?)\\s*$`))).find(Boolean)?.[1];
  let env = null;
  const lines = text.split("\n");
  const at = lines.findIndex((l) => /^\s*Environment:\s*$/.test(l));
  if (at >= 0) {
    env = {};
    for (const l of lines.slice(at + 1)) {
      const m = l.match(/^\s{4,}([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
      if (!m) break;
      env[m[1]] = m[2];
    }
  }
  return { command: field("Command"), args: field("Args"), env };
}
function agrees(entry, shown) {
  if (shown.command !== undefined && shown.command !== entry.command) return false;
  if (shown.args !== undefined && shown.args !== (Array.isArray(entry.args) ? entry.args.join(" ") : "")) return false;
  if (shown.env) {
    const own = isEntry(entry.env) ? entry.env : {};
    const keys = new Set([...Object.keys(own), ...Object.keys(shown.env)]);
    for (const k of keys) if (String(own[k] ?? "") !== String(shown.env[k] ?? "")) return false;
  }
  return true;
}

/* One scope's entry as its file holds it: {entry} | {missing: true} (C1: see projectPlaces). */
function claudeEntryIn(ctx, scope, found) {
  try {
    if (scope === "user") {
      const e = claudeSettings(ctx).mcpServers?.[NAME];
      return isEntry(e) ? { entry: e } : { missing: true };
    }
    const { projects: all } = claudeSettings(ctx); // read once: the file could change between two reads
    const projects = isEntry(all) ? all : {};
    const shown = printed(found?.stdout);
    const at = (dir) => {
      if (scope === "local") {
        // The exact key wins. A key that differs only in case counts only when it is the one such key that agrees
        // with what `get` printed: a case-sensitive volume can hold both /x/App and /x/app as different projects.
        if (isEntry(projects[dir]?.mcpServers?.[NAME])) return projects[dir].mcpServers[NAME];
        const near = Object.keys(projects).filter((k) => k !== dir && sameKey(ctx, k, dir))
          .map((k) => projects[k]?.mcpServers?.[NAME]).filter((e) => isEntry(e) && agrees(e, shown));
        return near.length === 1 ? near[0] : undefined;
      }
      return existsSync(join(dir, ".mcp.json")) ? readSettings(join(dir, ".mcp.json")).mcpServers?.[NAME] : undefined;
    };
    const { exact, ancestors } = projectPlaces(ctx);
    for (const dir of exact) { const e = at(dir); if (isEntry(e)) return { entry: e }; }
    for (const dir of ancestors) { const e = at(dir); if (isEntry(e) && agrees(e, shown)) return { entry: e }; }
  } catch { /* unreadable: treated as missing */ }
  return { missing: true };
}

/* What `claude mcp get` showed for one scope, before it is removed: the local inspector entry {entry} read from that
   scope's file. A local inspector entry whose
   file can't be read stops setup with the manual steps (M-A), so its env is never dropped silently. */
export class ClaudeEntryUnreadable extends Error {}
function claudePrior(ctx, found, scope) {
  const read = claudeEntryIn(ctx, scope, found);
  if (read.entry) return { scope, entry: read.entry };
  throw new ClaudeEntryUnreadable(`Claude Code has a ${NAME} entry in its ${scope} scope, but setup can’t read it from `
    + `${scope === "user" ? claudeSettingsShown(ctx) : scope === "local" ? `${claudeSettingsShown(ctx)} (under this project’s own folder)` : "the project’s .mcp.json"}, `
    + `so it was left as it is rather than lose its env. Update it by hand: claude mcp get ${NAME} shows its env; then `
    + `claude mcp remove ${NAME} --scope ${scope} and add it again with claude mcp add-json --scope ${scope} ${NAME} '<its JSON with args ${JSON.stringify([...ARGS])}>'`);
}

export const CLIENTS = [
  {
    id: "claude-code",
    label: "Claude Code",
    installed: (ctx) => Boolean(ctx.which("claude")),
    status(ctx) {
      const found = ctx.run("claude", ["mcp", "get", NAME]);
      if (found.status !== 0) return "ready";
      return claudeEntryIsOurs(found.stdout, ctx) ? "configured" : "outdated";
    },
    async add(ctx, status, { yes = false } = {}) {
      if (status !== "outdated") { must(ctx, "claude", ["mcp", "add", "--scope", "user", NAME, "--", ...launch(ctx)]); return {}; }
      // An earlier local inspector entry (another version) keeps its scope and everything on it but command and args
      // (env such as CUSTOSA_PROJECT_ROOT included): read before it is removed, written back with add-json.
      // Every scope that held one is restored with its own entry (M-A case B: a user entry for all projects and a
      // local override here both come back, each with its env).
      const priors = [];
      const restore = (list, { fallback = true } = {}) => {
        const added = new Set();
        for (const p of list) {
          if (p.entry) { must(ctx, "claude", ["mcp", "add-json", "--scope", p.scope, NAME, JSON.stringify(merged(p.entry, { type: "stdio", ...stdio(ctx) }))]); added.add(p.scope); }
        }
        if (!added.size && fallback) must(ctx, "claude", ["mcp", "add", "--scope", "user", NAME, "--", ...launch(ctx)]);
        return [...added];
      };
      let cleared;
      try {
        cleared = await claudeClear(ctx, yes, { keepOurs: true, onFound: (found, scope) => { priors.push(claudePrior(ctx, found, scope)); } });
      } catch (error) {
        // stopped part way (an entry setup can't read): what was already removed goes back as it was
        const back = priors.filter((p) => p.entry);
        if (error instanceof ClaudeEntryUnreadable && back.length) restore(back);
        throw error;
      }
      const { removed, last } = cleared;
      if (last === "none") {
        const kept = restore(priors);
        if (kept.length) return { note: `updated in ${claudeScopes(kept)}, each entry keeping its env and other settings` };
      }
      if (last === "ours") {
        // ours was under an old entry that shadowed it (say a local one with CUSTOSA_PROJECT_ROOT): that entry's env is
        // what was in effect here, so it goes back in its own scope as ours, never spread to a wider scope
        const withEnv = priors.filter((p) => p.entry && !foreign(p.entry) && isEntry(p.entry.env) && Object.keys(p.entry.env).length);
        const kept = restore(withEnv, { fallback: false });
        if (kept.length) return { note: `updated in ${claudeScopes(kept)}, keeping its env and other settings` };
      }
      return scopesNote(removed, ctx.dryRun);
    },
    async remove(ctx, { yes = false } = {}) {
      const { removed } = await claudeClear(ctx, yes, { keepOurs: false });
      return removed.length > 1 ? { note: `removed from ${claudeScopes(removed)}` } : {};
    },
  },
  {
    id: "codex",
    label: "Codex",
    note: "covers the Codex app, CLI and IDE extension",
    installed: (ctx) => Boolean(ctx.which("codex")) || existsSync(codexHome(ctx)),
    status(ctx) {
      const text = readText(codexConfig(ctx));
      // A file that isn't valid TOML is left exactly as it is, and the person gets the manual steps: an entry
      // appended to it could be swallowed by what is broken (an unclosed string or table header).
      if (text) { try { parseToml(text); } catch { throw new Unreadable(codexConfig(ctx), "isn’t valid TOML, so it was left as it is"); } }
      const server = codexServer(text, NAME);
      if (server.rootServers) throw new Unreadable(codexConfig(ctx), "writes mcp_servers as an inline table or dotted keys, so a table for PHI Schema Check can’t be added safely; it was left as it is");
      if (server.other) throw new Unreadable(codexConfig(ctx), `lists ${NAME} in a form this tool doesn’t edit`);
      const [command, ...args] = launch(ctx);
      return !server.found ? "ready" : !server.foreign && server.command === command && same(server.args, args) ? "configured" : "outdated";
    },
    add(ctx, status) {
      // An outdated entry (another version, say) is edited in place in config.toml, never removed
      // and added again: its env table, timeouts and other keys stay as the person set them.
      if (ctx.which("codex") && status !== "outdated") {
        must(ctx, "codex", ["mcp", "add", NAME, "--", ...launch(ctx)]);
        // codex mcp add has no option for timeouts: add ours to the table it wrote (CODEX_TIMEOUTS)
        if (!ctx.dryRun) {
          const file = codexConfig(ctx), text = readText(file);
          const next = codexEnsureTimeouts(text, NAME);
          if (text && next !== text) writeSafely(file, next, ctx);
        }
        return {};
      }
      const file = codexConfig(ctx), text = readText(file);
      const { command, args } = stdio(ctx);
      const next = status === "outdated" ? codexSetCommand(text, NAME, command, args, { fresh: codexServer(text, NAME).foreign }) : codexAdd(text, NAME, command, args);
      return { backup: ctx.dryRun ? null : writeSafely(file, next, ctx) };
    },
    remove(ctx) {
      if (ctx.which("codex")) { must(ctx, "codex", ["mcp", "remove", NAME]); return {}; }
      const file = codexConfig(ctx);
      return { backup: ctx.dryRun ? null : writeSafely(file, codexRemove(readText(file), NAME), ctx) };
    },
  },
  {
    id: "cursor",
    label: "Cursor",
    installed: (ctx) => Boolean(ctx.which("cursor")) || existsSync(join(ctx.home, ".cursor")),
    ...cursor,
  },
  {
    id: "vscode",
    label: "VS Code",
    installed: (ctx) => Boolean(ctx.which("code")) || existsSync(vscodeSettings(ctx)),
    status: vscodeFile.status,
    add(ctx, status) {
      // VS Code's own command when it's on the PATH; it also tidies up a file we couldn't edit
      if (ctx.which("code") && status !== "outdated") { must(ctx, "code", ["--add-mcp", JSON.stringify({ name: NAME, type: "stdio", ...stdio(ctx) })]); return {}; }
      return vscodeFile.add(ctx);
    },
    remove: vscodeFile.remove,
  },
  {
    id: "antigravity",
    label: "Antigravity",
    note: "covers Antigravity and Antigravity CLI",
    installed: (ctx) => Boolean(ctx.which("agy")) || ["config", "antigravity"].some((d) => existsSync(join(ctx.home, ".gemini", d))),
    status(ctx) {
      const states = antigravityFiles(ctx).map((f) => f.status(ctx));
      return states.includes("outdated") ? "outdated" : states.includes("ready") ? "ready" : "configured";
    },
    add: (ctx) => eachFile(ctx, "add"),
    remove: (ctx) => eachFile(ctx, "remove"),
  },
  /* Gemini CLI now only serves company and API-key plans (Google moved people to Antigravity CLI in 2026) */
  {
    id: "gemini-cli",
    label: "Gemini CLI",
    installed: (ctx) => Boolean(ctx.which("gemini")),
    ...geminiFile,
  },
];

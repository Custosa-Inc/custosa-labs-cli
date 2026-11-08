/* Codex keeps its servers in config.toml. When the Codex command isn't available we edit that file directly, but only
   our own [mcp_servers.<name>] tables, found line by line; any other way of writing our entry, or of writing
   mcp_servers itself (an inline table or dotted keys at the root, where a [mcp_servers.<name>] table can't be added),
   is left for a person. Line endings stay as the file has them. */

const header = /^\s*\[\s*([^\]]+?)\s*\]\s*(#.*)?$/;
const key = (part) => part.trim().replace(/^"(.*)"$/, "$1").replace(/^'(.*)'$/, "$1");
/* a key bare or quoted, as a regex source: url, "url", 'url' */
const quotedKey = (k) => `(?:${k}|"${k}"|'${k}')`;
/* a key at the start of a line */
const keyLine = (k) => new RegExp(`^\\s*${quotedKey(k)}\\s*=`);
/* mcp_servers as an inline table or dotted keys: `mcp_servers = {`, `mcp_servers.x.command = ...` (quoted too) */
const ROOT_SERVERS = new RegExp(String.raw`^\s*${quotedKey("mcp_servers")}\s*[.=]`);
const MULTILINE = /"""|'''/;

/** Split into blocks: lines before the first table, then one block per table header. */
function blocks(text) {
  const out = [{ path: null, lines: [] }];
  for (const line of text.split("\n")) {
    const m = line.match(header);
    if (m && !line.trim().startsWith("[[")) out.push({ path: m[1].split(".").map(key), lines: [line] });
    else out[out.length - 1].lines.push(line);
  }
  return out;
}

const ours = (path, name) => path && path[0] === "mcp_servers" && path[1] === name;
const EMPTY = Object.freeze({ found: false, command: null, args: null });
const OTHER = Object.freeze({ found: true, command: null, args: null, other: true });

/* a one-line string value, "basic" (no escapes) or 'literal' */
const STRING = String.raw`(?:"([^"\\]*)"|'([^']*)')`;
const valueOf = (lines, k) => {
  const m = lines.map((l) => l.match(new RegExp(`^\\s*${quotedKey(k)}\\s*=\\s*${STRING}\\s*(#.*)?$`))).find(Boolean);
  return m ? (m[1] ?? m[2]) : null;
};
/* one line `args = ["-y", 'custosa']` */
const ARGS_LINE = new RegExp(String.raw`^\s*${quotedKey("args")}\s*=\s*\[((?:\s*${STRING}\s*,?)*)\s*\]\s*(#.*)?$`);
const ARG = new RegExp(STRING, "g");

/* Splits on \n and restores \r\n afterwards, so a CRLF file stays CRLF. */
const withEol = (text, edit) => {
  const crlf = /\r\n/.test(text ?? "");
  const out = edit(crlf ? text.replace(/\r\n/g, "\n") : (text ?? ""));
  return crlf ? out.replace(/\n/g, "\r\n") : out;
};

/** What config.toml says about our server: missing, its command and args, or "other" when it is written in a
    form we don't edit (a dotted key, an inline table, mcp_servers at the root, a multi-line string, args over several
    lines). */
export function codexServer(text, name) {
  if (!text) return { ...EMPTY };
  const all = blocks(text.replace(/\r\n/g, "\n"));
  if (all[0].lines.some((l) => ROOT_SERVERS.test(l))) return { ...OTHER, rootServers: true };
  if (!text.includes(name)) return { ...EMPTY };
  const main = all.find((b) => ours(b.path, name) && b.path.length === 2);
  const elsewhere = all.some((b) => !ours(b.path, name) && b.lines.some((l) => l.includes(name)));
  if (!main || elsewhere) return { ...OTHER };
  if (all.some((b) => ours(b.path, name) && b.lines.some((l) => MULTILINE.test(l)))) return { ...OTHER };
  const argsAt = main.lines.findIndex((l) => keyLine("args").test(l));
  let args = null;
  if (argsAt >= 0) {
    const m = main.lines[argsAt].match(ARGS_LINE);
    if (!m) return { ...OTHER };
    args = [...m[1].matchAll(ARG)].map((a) => a[1] ?? a[2]);
  }
  if (main.lines.some((l) => keyLine("command").test(l)) && valueOf(main.lines, "command") === null) return { ...OTHER };
  // a table with an address is someone else's server under our name: replaced, keeping none of its keys
  const foreign = main.lines.some((l) => keyLine("url").test(l));
  return { found: true, command: valueOf(main.lines, "command"), args, ...(foreign ? { foreign } : {}) };
}

const quote = (v) => JSON.stringify(v);
/* Codex's per-server timeouts (config.toml mcp_servers.<id>). Its defaults (10 s to start, 60 s per tool call) are too
   short for a first npx download and for a whole check (collection up to 55 s, then the evaluator's answer). */
export const CODEX_TIMEOUTS = Object.freeze({ startup_timeout_sec: 60, tool_timeout_sec: 300 });
const timeoutLines = (except = []) => Object.entries(CODEX_TIMEOUTS).filter(([k]) => !except.some((l) => keyLine(k).test(l))).map(([k, v]) => `${k} = ${v}`);
const entryLines = (command, args) => [`command = ${quote(command)}`, `args = [${args.map(quote).join(", ")}]`];

export function codexAdd(text, name, command, args) {
  return withEol(text, (base) => {
    const gap = !base ? "" : base.endsWith("\n\n") ? "" : base.endsWith("\n") ? "\n" : "\n\n";
    return `${base}${gap}[mcp_servers.${name}]\n${[...entryLines(command, args), ...timeoutLines()].join("\n")}\n`;
  });
}

const OURS_KEYS = ["command", "args"].map(keyLine);

/* Comment lines just before the next table header belong to that table, not to the block above it. */
function splitTrailingComments(lines) {
  let at = lines.length;
  while (at > 1 && /^\s*(#.*)?$/.test(lines[at - 1])) at--;
  const tail = lines.slice(at);
  const first = tail.findIndex((l) => /^\s*#/.test(l));
  return first < 0 ? [lines, []] : [lines.slice(0, at + first), tail.slice(first)];
}

/* The blank and comment lines that end a table (see splitTrailingComments). */
function trailing(lines) {
  let at = lines.length;
  while (at > 1 && /^\s*(#.*)?$/.test(lines[at - 1])) at--;
  return lines.slice(at);
}

/** Points our table at the command: its command and args lines are replaced; any other line in it, and any sub-table,
    is kept. fresh (a foreign table, see codexServer): the table and its sub-tables are written anew, keeping none of
    their keys (a comment above the next table stays with it). */
export function codexSetCommand(text, name, command, args, { fresh = false } = {}) {
  return withEol(text, (t) => blocks(t).map((b) => {
    if (!ours(b.path, name)) return b.lines;
    if (b.path.length !== 2) return fresh ? splitTrailingComments(b.lines)[1] : b.lines;
    const rest = fresh ? trailing(b.lines) : b.lines.slice(1).filter((l) => !OURS_KEYS.some((r) => r.test(l)));
    return [b.lines[0], ...entryLines(command, args), ...timeoutLines(rest), ...rest];
  }).flat().join("\n").replace(/\n{3,}/g, "\n\n"));
}

/** Removes our tables; a comment written above the next table stays with it. */
export function codexRemove(text, name) {
  return withEol(text, (t) => blocks(t).map((b) => (ours(b.path, name) ? splitTrailingComments(b.lines)[1] : b.lines))
    .flat().join("\n").replace(/\n{3,}/g, "\n\n"));
}

/** Adds the Codex timeouts our table lacks (after `codex mcp add`, which has no option for them); a timeout the person
    set is kept as it is. Text without our table is returned unchanged. */
export function codexEnsureTimeouts(text, name) {
  if (!text) return text;
  return withEol(text, (t) => blocks(t).map((b) => {
    if (!ours(b.path, name) || b.path.length !== 2) return b.lines;
    const add = timeoutLines(b.lines);
    if (!add.length) return b.lines;
    let at = b.lines.length;
    while (at > 1 && /^\s*$/.test(b.lines[at - 1])) at--;
    return [...b.lines.slice(0, at), ...add, ...b.lines.slice(at)];
  }).flat().join("\n"));
}

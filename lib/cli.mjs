/* The command line: options, finding and running the assistants' own commands, and the prompts. */
import { spawnSync } from "node:child_process";
import { accessSync, constants, statSync } from "node:fs";
import { homedir } from "node:os";
import { delimiter, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createInterface } from "node:readline/promises";
import { CLIENTS } from "./clients.mjs";
import { main } from "./setup.mjs";
import { ENVIRONMENTS } from "./inspector/environment.mjs";
import { VERSION as version } from "./version.mjs";

const CLIENT_IDS = CLIENTS.map((c) => c.id).join(", ");
const usage = `Usage: npx custosa [setup|remove] [options]

  setup     Add PHI Schema Check to the AI assistants on this computer (the default)
  remove    Take it out again
  login     Sign this computer in (a code to enter in your browser)
  logout    Delete the sign-in here, and revoke it on the server where the evaluator offers that
  doctor    Check this computer's setup (--offline skips the evaluator)

Options:
  --client <ids>     Only these, comma separated: ${CLIENT_IDS}
  --environment <e>  Mark what your phisc database entry points at: ${ENVIRONMENTS.join(", ")}
  --yes, -y          Don't ask before changing anything
  --dry-run          Show what would change, change nothing
  --help, -h         Show this help
  --version, -v      Show the version

Guide: https://custosa.com/labs/setup`;

export function parse(argv) {
  const options = { mode: "setup", yes: false, dryRun: false, clients: null, environment: null };
  const args = [...argv];
  // `name` or `name=value`: whether arg is that option, and its value (after =, else the next argument)
  const named = (arg, name) => arg === name || arg.startsWith(`${name}=`);
  const valueOf = (arg, name) => (arg === name ? args.shift() : arg.slice(name.length + 1));
  if (args[0] && !args[0].startsWith("-")) {
    const mode = args.shift();
    if (!["setup", "remove"].includes(mode)) throw new Error(`Unknown command "${mode}".`);
    options.mode = mode;
  }
  while (args.length) {
    const arg = args.shift();
    if (arg === "--yes" || arg === "-y") options.yes = true;
    else if (arg === "--dry-run") options.dryRun = true;
    else if (arg === "--help" || arg === "-h") options.help = true;
    else if (arg === "--version" || arg === "-v") options.version = true;
    else if (named(arg, "--environment")) {
      const value = valueOf(arg, "--environment");
      if (!ENVIRONMENTS.includes(value)) throw new Error(`Unknown environment "${value ?? ""}". Choose from: ${ENVIRONMENTS.join(", ")}.`);
      options.environment = value;
    } else if (named(arg, "--client")) {
      const value = valueOf(arg, "--client");
      const ids = (value || "").split(",").map((v) => v.trim()).filter(Boolean);
      const unknown = ids.filter((id) => !CLIENTS.some((c) => c.id === id));
      if (!ids.length || unknown.length) throw new Error(`Unknown assistant "${unknown[0] ?? ""}". Choose from: ${CLIENT_IDS}.`);
      options.clients = ids;
    } else throw new Error(`Unknown option "${arg}".`);
  }
  // remove marks no environment: refused, never ignored.
  if (options.mode === "remove" && options.environment !== null) throw new Error("--environment goes with setup, not remove.");
  return options;
}

/* Quote one argument for cmd.exe, which runs the .cmd launchers npm installs on Windows. */
export function winQuote(arg) {
  if (arg && !/[\s"]/.test(arg)) return arg;
  return `"${arg.replace(/(\\*)"/g, '$1$1\\"').replace(/(\\+)$/, "$1$1")}"`;
}

export function which(command) {
  const exts = process.platform === "win32" ? (process.env.PATHEXT || ".EXE;.CMD;.BAT").split(";") : [""];
  for (const dir of (process.env.PATH || "").split(delimiter).filter(Boolean)) {
    for (const ext of exts) {
      const file = join(dir, command + ext.toLowerCase());
      try {
        if (!statSync(file).isFile()) continue;
        if (process.platform !== "win32") accessSync(file, constants.X_OK);
        return file;
      } catch { /* not here */ }
    }
  }
  return null;
}

/* A command that gets the terminal (custosa login): no readline is open while it runs (each question has its own,
   closed again before it returns), so the terminal is back in its normal mode and Ctrl-C reaches the child as a
   signal. Setup ignores that one Ctrl-C itself, so the person stops the sign-in, not the whole setup. */
export function run(command, args, { interactive = false } = {}) {
  const file = which(command) || command;
  const ignore = () => {};
  if (interactive) {
    if (process.stdin.isTTY && process.stdin.isRaw) process.stdin.setRawMode(false);
    process.on("SIGINT", ignore);
  }
  try { return runFile(file, args, interactive); }
  finally { if (interactive) setImmediate(() => process.off("SIGINT", ignore)); }
}

function runFile(file, args, interactive) {
  const viaShell = process.platform === "win32" && /\.(cmd|bat)$/i.test(file);
  const result = spawnSync(viaShell ? winQuote(file) : file, viaShell ? args.map(winQuote) : args, {
    stdio: interactive ? "inherit" : ["ignore", "pipe", "pipe"],
    encoding: "utf8",
    shell: viaShell,
    timeout: interactive ? undefined : 30_000,
  });
  return { status: result.status ?? 1, stdout: result.stdout ?? "" };
}

const color = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code) => (text) => (color ? `\x1b[${code}m${text}\x1b[0m` : text);
const style = { bold: paint(1), dim: paint(2), green: paint(32), red: paint(31), yellow: paint(33) };

export async function start(argv) {
  let options;
  try { options = parse(argv); }
  catch (error) { console.error(`${error.message}\n\n${usage}`); return 2; }
  if (options.help) { console.log(usage); return 0; }
  if (options.version) { console.log(version); return 0; }

  const interactive = Boolean(process.stdin.isTTY && process.stdout.isTTY);
  /* one readline per question, closed before the answer returns, so the terminal is never left in raw mode */
  const question = async (text) => {
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    try { return await rl.question(text); } finally { rl.close(); }
  };
  const out = (line = "") => console.log(line);
  const ctx = {
    home: homedir(), platform: process.platform, env: process.env, which, run, interactive, dryRun: options.dryRun, style,
    // this package's own command line, for `custosa login` (the sign-in runs in its own process, never inside setup)
    self: [process.execPath, fileURLToPath(new URL("../bin/custosa.mjs", import.meta.url))],
    out,
    async ask(q) { const answer = (await question(`${q} ${style.dim("[Y/n]")} `)).trim().toLowerCase(); return answer === "" || answer === "y" || answer === "yes"; },
    /* free text, trimmed (for a typed confirmation) */
    async input(q) { return (await question(`${q} `)).trim(); },
    /* one of `choices`, by name, first letters or number; Enter takes `fallback`; null after three answers it can't read */
    async choose(q, choices, fallback) {
      out(q);
      choices.forEach((c, i) => out(`  ${i + 1}. ${c}${c === fallback ? style.dim(" (Enter)") : ""}`));
      for (let tries = 0; tries < 3; tries++) {
        const answer = (await question(`${style.dim(">")} `)).trim().toLowerCase();
        if (!answer) return fallback;
        const picked = choices[Number(answer) - 1] ?? choices.find((c) => c.startsWith(answer));
        if (picked) return picked;
      }
      return null;
    },
  };
  return main(options.mode, options, ctx);
}

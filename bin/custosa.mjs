#!/usr/bin/env node
/* npx custosa setup: add PHI Schema Check to the AI assistants on this computer. See ../README.md.
 * custosa inspect --stdio: the local inspector, a stdio MCP server the assistants start (../lib/inspector/server.mjs).
 * custosa inspect --document <dir>: the fact document for a checkout, built locally, on stdout (corpus scorer).
 * custosa rules test <dir>: checks a rule set against its fixtures (../lib/inspector/rules.mjs), for CI.
 * custosa login / logout: the device sign-in the inspector's evaluator calls use (../lib/inspector/auth.mjs).
 * custosa doctor: checks this computer's setup, locally (../lib/doctor.mjs).
 * Each path loads only its own modules, so the inspector never loads the setup code (which runs commands). */
import { MIN_NODE, nodeSupported } from "../lib/version.mjs"; // uses only node:fs, so it loads on an older Node.js

if (!nodeSupported(process.versions.node)) {
  process.stderr.write(`custosa needs Node.js ${MIN_NODE.join(".")} or later, and this is Node.js ${process.versions.node}. `
    + "Install a current Node.js LTS (https://nodejs.org), then run the command again. If an AI assistant starts custosa, "
    + "restart the assistant after installing so it finds the new Node.js.\n");
  process.exit(1);
}
const argv = process.argv.slice(2);

if (argv[0] === "inspect") {
  // Stdout belongs to the protocol: anything printed by mistake goes to stderr instead.
  console.log = console.info = console.debug = console.error;
  if (argv.length === 3 && argv[1] === "--document") {
    // custosa inspect --document <dir>: the fact document for one checkout, built locally (no sign-in, no network: the
    // catalog and platform collectors are not_run), printed as {document, handlers} on stdout. handlers is the LOCAL
    // map from handler id to {path, name, line, column}; it is printed here only and never sent to the evaluator.
    // Exits 1 when the document fails its checks. For the corpus scorer (CUSTOSA_CORPUS_BUILDER). With
    // CUSTOSA_CORPUS_FIXED_BUDGET=1 it uses the fixed corpus budget and exits 1 if any time limit was still hit.
    import("node:fs").then(async ({ realpathSync, statSync }) => {
      const root = realpathSync(argv[2]);
      if (!statSync(root).isDirectory()) { console.error("custosa inspect: --document takes a folder (a checkout), not a file."); return 1; }
      const { projectRootProblem } = await import("../lib/inspector/projectroot.mjs");
      const why = await projectRootProblem(root);
      if (why) { console.error(why.message); return 1; }
      const { buildLocalDocuments, corpusBudget, timedOut } = await import("../lib/inspector/factdoc.mjs");
      const budget = corpusBudget(process.env);
      const { documents } = await buildLocalDocuments([root], { handlerMap: true, ...(budget ?? {}) });
      const [own] = documents;
      if (own?.problem?.keyword === "too_large") {
        console.error("custosa inspect: this folder is too large to check in one document (over 5,000,000 bytes of facts even with matches cut). Run it on a narrower folder: one app or service, a repository of its own.");
        return 1;
      }
      if (!own || own.problem || !own.document) {
        console.error(`custosa inspect: the fact document failed its checks at ${own?.problem?.at ?? ""} (${own?.problem?.keyword ?? "internal_error"}).`);
        return 1;
      }
      const files = own.document.collection.find((c) => c.collector === "files");
      if (!files || files.status === "failed" || files.status === "not_run") {
        console.error(`custosa inspect: the folder couldn't be walked (files collector ${files?.status ?? "missing"}, ${files?.reason ?? ""}).`);
        return 1;
      }
      if (budget && timedOut(own.document)) {
        console.error("custosa inspect: a time limit was hit even with the fixed corpus budget, so this document could differ from run to run. Not printed.");
        return 1;
      }
      await new Promise((ok) => process.stdout.write(`${JSON.stringify({ document: own.document, handlers: own.handlers ?? {} })}\n`, ok));
      return 0;
    }).then((code) => { process.exitCode = code; }, (error) => { console.error(`custosa inspect: ${error.message}`); process.exitCode = 1; });
  } else if (argv[1] !== "--stdio" || !(argv.length === 2 || (argv.length === 4 && argv[2] === "--root"))) {
    console.error("Usage: custosa inspect --stdio [--root <dir>]\n       custosa inspect --document <dir>\n\n--stdio starts the local inspector as an MCP server over stdin and stdout (your AI assistant starts it; setup registers it).\n--root (or CUSTOSA_PROJECT_ROOT) names the project folder, an absolute path; it takes precedence over the assistant's roots.\n--document prints the fact document for <dir>, built locally without signing in or sending anything.");
    process.exitCode = 2;
  } else {
    const projectRoot = argv[3] ?? (process.env.CUSTOSA_PROJECT_ROOT || null);
    import("../lib/inspector/server.mjs")
      .then(({ startServer, findGitRoot }) => startServer({ stdin: process.stdin, stdout: process.stdout, root: findGitRoot(process.cwd()), projectRoot }))
      .then(() => { process.exitCode = 0; }, (error) => { console.error(`custosa inspect: ${error.stack || error.message}`); process.exitCode = 1; });
  }
} else if (argv[0] === "login" || argv[0] === "logout") {
  // The device sign-in (evaluator_api.md section 3). The token is stored in the config folder and never printed.
  if (argv.length !== 1) {
    console.error("Usage: custosa login | custosa logout\n\nlogin signs this computer in to PHI Schema Check, a Custosa Labs project, so its tools (check_schema, schema_guidance, get_result) can reach the evaluator. logout removes the saved sign-in from this computer, and asks the evaluator to revoke it where the evaluator offers that (not every evaluator does yet).");
    process.exitCode = 2;
  } else {
    Promise.all([import("../lib/inspector/auth.mjs"), import("../lib/inspector/client.mjs")])
      .then(async ([auth, client]) => {
        if (argv[0] === "logout") {
          // Revoke on the server first (only to the evaluator that issued the token), then always delete locally.
          const saved = auth.readToken();
          let revoked = null;
          if (saved.token) {
            const where = client.evaluatorUrl();
            const base = !where.problem && client.issuedBy(where, saved.host) ? where.url : saved.host;
            revoked = await client.revokeToken({ token: saved.token, baseUrl: base });
          }
          const why = revoked ? ` (${revoked.why === "unreachable" ? "the evaluator couldn't be reached" : revoked.why === "http_404" ? "the evaluator doesn't offer revoking yet" : revoked.why})` : " (the saved sign-in couldn't be read)";
          let removed;
          try { removed = auth.removeToken(); } catch (error) {
            if (!(error instanceof auth.TokenUnremoved)) throw error;
            const server = revoked?.revoked ? "The sign-in was revoked on the server, so it no longer works, but" : `The server revoke didn't happen${why}, and`;
            console.error(`custosa logout: ${server} the saved sign-in is still on this computer: ${error.message}. Delete that file yourself.`);
            return 1;
          }
          if (!removed && !saved.token) { console.log("There was no saved sign-in."); return 0; }
          if (revoked?.revoked) { console.log("Signed out: the sign-in was revoked on the server and removed from this computer."); return 0; }
          console.log(`Signed out on this computer: the saved sign-in was removed. The server revoke didn't happen${why}, so the token stays valid until it expires. To revoke it now, remove it on your billing page (https://custosa.com/billing).`);
          return 0;
        }
        const where = client.evaluatorUrl();
        if (where.problem) { console.error(client.LOCAL[where.problem]); return 1; }
        // An address from evaluator.json other than the default needs a yes typed in a terminal; the env var is explicit.
        const needsYes = where.source === "file" && where.origin !== new URL(client.DEFAULT_EVALUATOR_URL).origin;
        const confirm = !needsYes ? null : async (origin) => {
          if (!process.stdin.isTTY) { console.error(`evaluator.json names ${origin}. Run custosa login in a terminal to confirm it, or set CUSTOSA_EVALUATOR_URL.`); return false; }
          const { createInterface } = await import("node:readline/promises");
          const rl = createInterface({ input: process.stdin, output: process.stdout });
          try { return /^y(es)?$/i.test((await rl.question(`Send your PHI Schema Check sign-in to ${origin}? [y/N] `)).trim()); } finally { rl.close(); }
        };
        return auth.deviceLogin({
          baseUrl: where.url, out: (line) => console.log(line), confirm,
          post: (base, path, json) => client.post(base, path, json, { timeoutMs: 30_000 }),
          sleep: (ms) => new Promise((ok) => setTimeout(ok, ms)),
        });
      })
      .then((code) => { process.exitCode = code; }, (error) => { console.error(`custosa ${argv[0]}: ${error.message}`); process.exitCode = 1; });
  }
} else if (argv[0] === "doctor") {
  // custosa doctor [--offline]: pass, warn and fail lines for this computer's setup; exit 1 on any fail.
  if (argv.length > 2 || (argv.length === 2 && argv[1] !== "--offline")) {
    console.error("Usage: custosa doctor [--offline]\n\nChecks Node.js, the package, each assistant's entry, the sign-in, the evaluator, the [phisc] entry, the database preflight (read-only), the environment mark and the platform token. --offline skips the evaluator's health check. Prints no secrets.");
    process.exitCode = 2;
  } else {
    import("../lib/doctor.mjs")
      .then(({ runDoctor }) => runDoctor({ offline: argv[1] === "--offline" }))
      .then((code) => { process.exitCode = code; }, (error) => { console.error(`custosa doctor: ${error.message}`); process.exitCode = 1; });
  }
} else if (argv[0] === "rules") {
  // custosa rules test <dir>: run every rule in a rule set against its fixtures (CI for the rule set).
  if (argv.length !== 3 || argv[1] !== "test") {
    console.error("Usage: custosa rules test <dir>\n\nChecks each structural rule in <dir> against its fixture file's ruleid and ok markers.");
    process.exitCode = 2;
  } else {
    import("../lib/inspector/rules.mjs")
      .then(({ runFixtures }) => runFixtures(argv[2]))
      .then(({ passed, failed }) => {
        for (const f of failed) console.error(`FAIL ${f.file}${f.line ? `:${f.line}` : ""} ${f.rule_id}: expected ${f.expected}, got ${f.got}`);
        console.log(`${passed} passed, ${failed.length} failed`);
        process.exitCode = failed.length ? 1 : 0;
      }, (error) => { console.error(error.message); process.exitCode = 1; });
  }
} else {
  import("../lib/cli.mjs")
    .then(({ start }) => start(argv))
    .then((code) => { process.exitCode = code; }, (error) => { console.error(error.message); process.exitCode = 1; });
}

/* setup and doctor judge a saved sign-in the same way the inspector does: it counts only for the evaluator whose
   origin issued it (custosa login records that origin). A path on the evaluator's address doesn't change its origin;
   another port or host does; an address that can't be used is no evaluator at all. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { main } from "../lib/setup.mjs";
import { runDoctor } from "../lib/doctor.mjs";
import { writeToken } from "../lib/inspector/auth.mjs";
import { INSPECT, NAME } from "../lib/clients.mjs";

const TOKEN = `phisc_${"a".repeat(43)}`;
const ISSUER = "http://127.0.0.1:9";

/* a home folder with Cursor already set up and a sign-in saved for ISSUER */
function computer() {
  const home = mkdtempSync(join(tmpdir(), "custosa-evaluator-host-"));
  mkdirSync(join(home, ".cursor"));
  const [command, ...args] = INSPECT;
  writeFileSync(join(home, ".cursor", "mcp.json"), JSON.stringify({ mcpServers: { [NAME]: { command, args } } }));
  writeToken(TOKEN, { configDir: join(home, ".config", "custosa"), host: ISSUER });
  return home;
}

async function setupSays(evaluator) {
  const home = computer();
  const lines = [];
  const plain = (t) => t;
  const ctx = {
    home, platform: "darwin", env: { CUSTOSA_EVALUATOR_URL: evaluator, PGSERVICEFILE: "/nonexistent" }, self: ["custosa"],
    interactive: false, dryRun: false, style: { bold: plain, dim: plain, green: plain, red: plain, yellow: plain },
    which: () => null, run: () => ({ status: 1, stdout: "" }), out: (l = "") => lines.push(l),
    ask: async () => true, input: async () => "", choose: async (q, c, fallback) => fallback,
  };
  await main("setup", { yes: true }, ctx);
  return lines.find((l) => /Signed in on this computer already|Sign in {2}Run npx custosa login/.test(l));
}

async function doctorSays(evaluator) {
  const home = computer();
  const lines = [];
  await runDoctor({ env: { CUSTOSA_EVALUATOR_URL: evaluator, PGSERVICEFILE: "/nonexistent", npm_config_cache: join(home, ".npm") },
    home, out: (l) => lines.push(l), offline: true, which: () => null, run: () => ({ status: 1, stdout: "" }) });
  return lines.find((l) => /^\w+ +Sign-in:/.test(l)).replace(/expires about \S+/, "expires about <date>");
}

const SIGNED_IN = "Signed in on this computer already. To sign in anew, run npx custosa login.\n";
const NOT_SIGNED_IN = "Sign in  Run npx custosa login in a terminal, then sign in to Custosa in your browser, or create an account.\n";
const PASS = `PASS  Sign-in: a token is saved for ${ISSUER}, expires about <date> (90 days after sign-in; the token itself carries no date)`;
const OTHER = (origin) => `FAIL  Sign-in: a token is saved for ${ISSUER}, but the evaluator now configured is ${origin}. Run npx custosa login again.`;

const CASES = [
  // [the evaluator configured, what setup says, what doctor says]
  [ISSUER, SIGNED_IN, PASS],
  [`${ISSUER}/`, SIGNED_IN, PASS],
  [`${ISSUER}/base/path`, SIGNED_IN, PASS],
  ["http://127.0.0.1:10", NOT_SIGNED_IN, OTHER("http://127.0.0.1:10")],
  ["http://localhost:9", NOT_SIGNED_IN, OTHER("http://localhost:9")],
  ["https://evaluator.example.test", NOT_SIGNED_IN, OTHER("https://evaluator.example.test")],
  ["http://evaluator.example.test", NOT_SIGNED_IN, PASS], // not https and not this computer: an address that can't be used
];

for (const [evaluator, setup, doctor] of CASES) {
  test(`evaluator host: a sign-in from ${ISSUER} with the evaluator at ${evaluator}`, async () => {
    assert.equal(await setupSays(evaluator), setup);
    assert.equal(await doctorSays(evaluator), doctor);
  });
}

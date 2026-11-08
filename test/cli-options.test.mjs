/* what `custosa` makes of its arguments: the options, or the exact refusal. --client and --environment take their
   value after = or as the next argument, whatever it is. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { parse } from "../lib/cli.mjs";

const CASES = [
  [[], {"mode":"setup","yes":false,"dryRun":false,"clients":null,"environment":null}],
  [["setup"], {"mode":"setup","yes":false,"dryRun":false,"clients":null,"environment":null}],
  [["remove","-y"], {"mode":"remove","yes":true,"dryRun":false,"clients":null,"environment":null}],
  [["bogus"], "refused: Unknown command \"bogus\"."],
  [["--client=cursor,codex"], {"mode":"setup","yes":false,"dryRun":false,"clients":["cursor","codex"],"environment":null}],
  [["--client","cursor"], {"mode":"setup","yes":false,"dryRun":false,"clients":["cursor"],"environment":null}],
  [["--client= cursor , codex ,"], {"mode":"setup","yes":false,"dryRun":false,"clients":["cursor","codex"],"environment":null}],
  [["--client="], "refused: Unknown assistant \"\". Choose from: claude-code, codex, cursor, vscode, antigravity, gemini-cli."],
  [["--client"], "refused: Unknown assistant \"\". Choose from: claude-code, codex, cursor, vscode, antigravity, gemini-cli."],
  [["--client=nope"], "refused: Unknown assistant \"nope\". Choose from: claude-code, codex, cursor, vscode, antigravity, gemini-cli."],
  [["--client","cursor,nope"], "refused: Unknown assistant \"nope\". Choose from: claude-code, codex, cursor, vscode, antigravity, gemini-cli."],
  [["--clientx"], "refused: Unknown option \"--clientx\"."],
  [["--client=cursor","--client=codex"], {"mode":"setup","yes":false,"dryRun":false,"clients":["codex"],"environment":null}],
  [["--environment=staging"], {"mode":"setup","yes":false,"dryRun":false,"clients":null,"environment":"staging"}],
  [["--environment","production"], {"mode":"setup","yes":false,"dryRun":false,"clients":null,"environment":"production"}],
  [["--environment"], "refused: Unknown environment \"\". Choose from: development, staging, production, unknown."],
  [["--environment="], "refused: Unknown environment \"\". Choose from: development, staging, production, unknown."],
  [["--environment=staging=x"], "refused: Unknown environment \"staging=x\". Choose from: development, staging, production, unknown."],
  [["--environment","--yes"], "refused: Unknown environment \"--yes\". Choose from: development, staging, production, unknown."],
  [["--environmentx"], "refused: Unknown option \"--environmentx\"."],
  [["--dry-run","-h","-v"], {"mode":"setup","yes":false,"dryRun":true,"clients":null,"environment":null,"help":true,"version":true}],
  [["setup","remove"], "refused: Unknown option \"remove\"."],
  [["-x"], "refused: Unknown option \"-x\"."],
  // remove marks no environment, so it refuses the option rather than ignore it.
  [["remove","--environment=production"], "refused: --environment goes with setup, not remove."],
  [["--client","--yes"], "refused: Unknown assistant \"--yes\". Choose from: claude-code, codex, cursor, vscode, antigravity, gemini-cli."],
];

for (const [argv, expected] of CASES) {
  test(`custosa ${argv.join(" ") || "(no arguments)"}`, () => {
    let got;
    try { got = parse(argv); } catch (error) { got = `refused: ${error.message}`; }
    assert.deepEqual(got, expected);
  });
}

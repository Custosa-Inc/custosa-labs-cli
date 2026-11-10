# Custosa Labs CLI

The command-line tool for Custosa Labs projects, published to npm as `custosa`. Its first product is PHI Schema
Check, which checks how a health app handles patient data from inside your AI coding assistant. This CLI adds it to
the AI assistants on your computer.

```bash
npx custosa@latest setup
```

It finds Claude Code, Codex, Cursor, VS Code, Antigravity (and Antigravity CLI) and Gemini CLI, shows what it will change, and asks before
changing anything. Then it:

1. registers the local inspector, `npx -y custosa@<version> inspect --stdio` (pinned to the version of custosa you
   ran setup with), as a stdio MCP server named `custosa-phi-schema-check` in each assistant it found (an older entry
   under that name, such as one pinned to another version, is replaced);
2. signs you in once by running `npx custosa login` in your terminal: it gives you a code to enter in your browser and
   saves the sign-in token itself, readable only by you. Setup itself writes no token and never prints it. Without a
   terminal it tells you to run `npx custosa login` yourself;
3. asks you to mark the environment your `phisc` database entry points at (development, staging, production or
   unknown), saved as `~/.config/custosa/environment.json`, mode 0600, with a fingerprint of the entry's host, port and
   database. The mark is asked at the terminal and production is typed out in full; the evaluator treats it as your
   own statement. A production readiness score needs the entry marked production here; if the entry changes later, or
   there was no entry when it was marked production, the inspector counts the environment as unknown. Only an entry
   marked development runs fix proofs: on verify, the inspector runs the test SQL the last fix call gave, as
   `phisc_ro` inside a read-only transaction that is rolled back, and sends only pass, fail or unread for each. On any
   other mark it runs none and sends each as unread;
4. prints the SQL for the read-only `phisc_ro` role, the Postgres 14 step, the read and write checks and the connection
   entry. Setup never runs SQL itself: you run it, once.

PHI Schema Check is pay per use: $0.003 per work unit, prepaid, with no per-check cap. Every result is
charged, including unknown results and practices with no rule for the project's stack. New accounts start with
$10 of credit at the first sign-in. Top up from $5 or redeem a coupon at https://custosa.com/billing to add to it.
Then start a session in your project and send:

```text
Use PHI Schema Check to review how this app handles patient data. Run the check through to the end on your own and answer the questions you can from the code. Then show me the readiness score, the findings and the decisions only I can make, and ask me before you change any code or database.
```

## The tools

The inspector offers three MCP tools:

| Tool | Goals | What it sends | Cost |
| ---- | ----- | ------------- | ---- |
| `check_schema` | check (which also sends answers to its questions), fix, verify | a fact document built from the project: table and column names, settings, rule results and file locations; never code, rows or secret values | $0.003 per work unit, charged exactly the work units a call used; every result is charged, unknown and no-rule-for-the-stack results included |
| `schema_guidance` | plan, pattern, explain | only the advice request: planned table and column names, a stack and need, or a practice id | the advice rate: the same $0.003 per work unit, where a call costs 1 unit per practice check plus 1 unit per started 1,000 characters of content (a guidance answer runs no practice checks), charged exactly the work units it used |
| `get_result` | a read of a result already returned: one selector its index names, and one part | only the goal, session, selector and part | not charged |

Each refuses a goal or argument that belongs to another and names the right one.

Names and paths that look like a record value or a secret (an email address, a phone number, an SSN or another long
number, a card number, an IP address, a date beside a name, a key or token) are hashed before anything is sent, with
the folders around them and a plain extension kept: `patients/john.doe@example.com.json` is sent as
`patients/u_<16 hex>.json`, the same text on every run. The inspector screens the whole fact document the way the
evaluator does and never sends one it would refuse.

```bash
npx custosa setup --client cursor,claude-code   # only these
npx custosa setup --environment staging         # mark the environment (in a terminal)
npx custosa setup --dry-run                      # show what would change
npx custosa remove                               # take it out again
```

## What it changes

| Assistant   | How                                                                    |
| ----------- | ---------------------------------------------------------------------- |
| Claude Code | `claude mcp add --scope user custosa-phi-schema-check -- npx -y custosa@<version> inspect --stdio` |
| Codex       | `codex mcp add custosa-phi-schema-check -- npx -y custosa@<version> inspect --stdio` for a new entry, or `~/.codex/config.toml` when the command isn't installed; an existing entry is always updated in place in `config.toml`. Either way the table gets `startup_timeout_sec = 60` and `tool_timeout_sec = 300`, and a value you set yourself, and the entry's `env`, are kept |
| Cursor      | `~/.cursor/mcp.json`                                                   |
| VS Code     | `code --add-mcp`, or your user `mcp.json`                              |
| Antigravity | `~/.gemini/config/mcp_config.json`, shared with Antigravity CLI (and the older `~/.gemini/antigravity/mcp_config.json` when present) |
| Gemini CLI  | `~/.gemini/settings.json`                                              |

On Windows every entry runs `cmd /c npx -y custosa@<version> inspect --stdio`, since an assistant can't start the npx script directly. Only the `custosa-phi-schema-check` entry is added or removed. Before a settings file is rewritten, the previous version
is saved next to it as `<file>.custosa-backup-<time>`. A file it can't rewrite exactly is left alone and you get the manual steps instead: one with comments or trailing commas,
duplicate keys or a number it can't keep exactly, a read-only file, a link to a missing file, a Codex `config.toml` that isn't valid TOML, or one that
writes `mcp_servers` as an inline table or dotted keys. When an entry is updated, only its command and args are replaced; anything else on it, such as `env`, `disabled`, `cwd` or `envFile`,
is kept. An entry under that name that points at an address (`url`, or a `type` other than `stdio`) is someone else's
server, and is replaced by ours with none of its keys. For Claude Code, an old entry is removed only from the scope `claude mcp get` reports, scope by scope; one in
the project scope lives in the repository's shared `.mcp.json`, so setup says so and asks first (or needs `--yes`).

Setup itself sends nothing to Custosa; `npx custosa login` talks only to the evaluator that issues the sign-in. For other tools, follow https://custosa.com/labs/setup. The prompt, price and steps it
prints come from `lib/shared.json`, the same file the setup page uses.

## What the inspector won't read

The inspector reads the project folder your assistant shares (or the git repository you start it in) and nothing
outside it. It refuses the whole disk, your home folder, a folder above it, and a folder outside any repository that
holds other repositories: open the assistant in the project's own folder instead. One check collects for at most
about 2 minutes; past that, what wasn't read is reported as incomplete, never as passing.

Known limit: a checkout whose `.git` is a file pointing outside the project folder (every `git worktree`, and
submodule checkouts opened on their own) or a `.git` symlink out of it has its git directory outside the folder, which
the inspector never reads. It can't learn which files git tracks, so the files collector is reported as truncated
(`ignore_unverified`) on every run and a coverage-based result can't pass there. Run the check from the main checkout
to get full coverage.

Known limit: SQL files, such as migrations under `supabase/migrations/`, aren't analysed. They are listed as not
analysed (`unsupported_language`), never as passing, and what the database actually holds comes from its catalog
when the inspector can read it.

## Requirements

Node.js 20.3 or later. The inspector checks this when it starts and exits with a message saying so on an older Node.js.

## Timeouts

A whole check can take a few minutes: up to about 140 seconds of local work (2 minutes of it collecting), then the evaluator's answer (the inspector waits up to 150 seconds for one request, matching the evaluator host's request timeout). An evaluation, or a retry of one, starts only while at least 90 seconds are left (the evaluator's own 60-second budget and a margin) of both its own 240 seconds and the call's 290; a further project folder is sent under the same rule, and the folders not sent are listed in the answer (`other_roots.not_sent_root_ids`), never dropped. A request already sent is never cut short by these limits, so one that starts near the end may finish after them (at most 150 seconds after it started).

- Codex: setup writes `startup_timeout_sec = 60` (the first `npx` download can pass Codex's 10-second default) and
  `tool_timeout_sec = 300` (its default is 60) on the `custosa-phi-schema-check` table.
- Claude Code: tool calls are limited by the `MCP_TOOL_TIMEOUT` environment variable (milliseconds), which applies to
  every server; set it to 300000 if a check is cut off. Its entry has no per-server timeout setting.
- Claude Desktop isn't set up by this tool. If you add the inspector to `claude_desktop_config.json` by hand, use the
  same `command` and `args` as above; that file has no timeout setting.

## Choosing the project folder

By default the inspector checks the first project folder your assistant shares (MCP roots), or the git repository it
was started in when the assistant shares none. Further folders are listed and checked only on request
(`include_other_roots`, as many as the call's time budget reaches). To name the folder yourself, set `CUSTOSA_PROJECT_ROOT` to its absolute
path in the server entry's `env` (or add `--root <dir>` after `--stdio`). It takes precedence over the assistant's
roots and is checked by the same rules; a missing or refused folder is an error, never a fallback.

## Commands

```bash
npx custosa login      # sign in this computer (device code in your browser)
npx custosa logout     # delete the sign-in here, and revoke it on the server where the evaluator offers that
npx custosa doctor     # check this computer's setup; add --offline to skip the evaluator
```

`custosa logout` deletes the local copy of the token whatever happens, and first asks the evaluator to revoke it
(`POST /v1/token/revoke`). The route comes with the next evaluator release; an evaluator without it answers 404, and
then logout says the server revoke didn't happen, and the token stays valid until it expires (90 days after sign-in) unless you remove it on your billing
page.

## Upgrading

Run `npx custosa@latest setup`. Each entry is moved to the new pinned version and keeps what you set on it: its
`env` (such as `CUSTOSA_PROJECT_ROOT`), Codex timeouts you changed, and, for Claude Code, the scope it was in (an
earlier local inspector entry is written back with `claude mcp add-json` in the same scope).

## Cancelling a check

A cancel stops collection at once and stops any further evaluation from starting. A request already sent is never
cut off, since the evaluator may charge it: it finishes in the background and is kept (for six hours). A later call
always collects and builds its facts anew; only when it is about to send exactly the same request again does it reuse
that request's Idempotency-Key, so the evaluator answers it once and charges it once. If the project changed, the
kept request is dropped and the answer carries a note with its session, whose results `get_result` reads
without a charge.

`custosa doctor` prints one PASS, WARN or FAIL line per check and exits 1 when any check fails: Node.js, the package
version and the npx cache, each assistant's entry, the sign-in and its estimated expiry (the token itself is never
printed), the evaluator's health check (one unauthenticated GET), the project root setting, the `[phisc]` entry, the
database preflight (read-only, as `phisc_ro`), the environment mark, and the platform token's form.

## Clearing the npx cache

Assistants start the pinned version through `npx`, which keeps a copy in npm's cache. To remove old copies (after
`custosa logout` and `npx custosa remove`, or when doctor reports several versions):

```bash
npm cache npx ls              # list the cached copies; note the keys of custosa ones (npm 11 and later)
npm cache npx rm <key>        # remove one by its key (npm 11 and later)
rm -rf ~/.npm/_npx            # or remove every npx copy (Windows: %LocalAppData%\npm-cache\_npx)
```

## Platform tokens

`~/.config/custosa/platform.json` may hold a token for your hosting platform's API, used only for reads. The inspector
and doctor warn when it is a Supabase personal access token (`sbp_`), which can act as you on every project you can
reach, including writes. Whether an AWS key, a Google OAuth token or an Azure token can write can't be told without
privileged calls (reading or simulating IAM policy), so it isn't judged: give the inspector a read-only credential.
Tokens are never sent to Custosa and never printed.

## MCP protocol version

The inspector serves both current MCP revisions over stdio, through `@modelcontextprotocol/server` 2.3.1: a client that
opens with `initialize` gets 2025-11-25 (or the 2025 revision it asks for), and a client that sends `server/discover`
or a request carrying the per-request `_meta` envelope gets 2026-07-28. The tools and their answers are the same on
both. On 2026-07-28 the inspector asks for your MCP roots in the check_schema result (`input_required`) rather than
with a request of its own; your assistant answers and repeats the call without you seeing it.

The tool list is the same on every run and computer. Its sha256 ships in the package as
`lib/inspector/tools-list.sha256`, so you can check that the tools didn't change between versions.

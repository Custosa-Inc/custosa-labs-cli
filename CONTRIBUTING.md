# Contributing

Thanks for looking. This is the Custosa Labs CLI, published to npm as `custosa`. Custosa maintains it, and its first
product is PHI Schema Check.

- **Bugs and ideas:** open an issue. For a security problem, follow SECURITY.md instead.
- **Pull requests:** welcome for small fixes. Please open an issue first for anything larger, so we can agree on the
  approach before you spend time on it.
- **Tests:** `npm ci --ignore-scripts`, `node .github/scripts/install-scripts.mjs .`, then `npm test`. Node 20.3 or
  later. The database tests need Postgres's `initdb` and `pg_ctl` on your PATH.
- **The rule set:** the files under `rules/` and `lib/inspector/contracts/` are generated from Custosa's evaluator and
  listed in `rules/manifest.json` with their hashes. Please don't edit them by hand; a change there needs a change on
  the evaluator side first. Open an issue instead.
- **Fake keys in tests:** write them so the file bytes don't spell a key, while the value the test reads stays the
  same. In `.mjs`, put a `\x` escape inside the string (`"sk\x5flive_..."`) or split it (`"sk_" + "live_..."`). In
  JSON and JSONL fixtures, run `node scripts/escape-fake-keys.mjs <file>`, which writes one `\u` escape into each
  key-shaped value. Why: GitHub push protection refuses a push that holds a key-shaped string, even a fake one, and
  it would refuse every fork's push too. CI runs gitleaks on its default rules over the whole tree with no
  allowlist, so it fails the same way.
- **License:** by contributing you agree that your contribution is licensed under the Apache License 2.0 (LICENSE).

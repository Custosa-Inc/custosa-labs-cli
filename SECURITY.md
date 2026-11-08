# Security policy

## Reporting a vulnerability

Email **hello@custosa.com** with "security" in the subject. Please include the version (`custosa --version`), what you
found, and the steps to reproduce it. Please don't open a public issue for a security problem.

We reply by email and tell you what we will do about it.

## Supported versions

Fixes ship in a new release of `custosa` on npm. Update with `npx custosa@latest setup`.

## What this package does with your data

The inspector runs on your computer. It reads your code and your database catalog locally, and it sends the Custosa
evaluator only names, settings, counts and file locations, never your code or your records. See
https://custosa.com/privacy.html for the full policy.

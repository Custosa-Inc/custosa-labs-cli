// T19 (P2): a provider token whose tail past its prefix is a made-up shape (one character or a few, one short unit
// repeated, or a near-unbroken ascending run) is a documentation placeholder, not a finding. It matters for T29 C234,
// which lets openai, sendgrid and both AWS rules fail. Every pattern that sets placeholders uses it; a run beside
// random text is still a finding.
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomInt } from "node:crypto";

const { scanSecrets } = await import("../lib/inspector/secrets.mjs");
const { isShapePlaceholder } = await import("../lib/inspector/secret-patterns.mjs");

const KEY = Buffer.alloc(32, 7);
const ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const rand = (n, set = ALNUM) => Array.from({ length: n }, () => set[randomInt(set.length)]).join("");
// Ascending runs are built from RUN, so no literal in this file reads as a key to a secret scanner.
const RUN = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const found = (line, path = "src/config.js") =>
  scanSecrets([{ path, text: Buffer.from(line + "\n") }], { key: KEY }).secrets.map((s) => s.rule_id);

test("placeholder shapes give no finding on the C234 rules and Stripe", () => {
  const shapes = [
    `OPENAI_API_KEY="sk-proj-${"0".repeat(46)}"`,
    `OPENAI_API_KEY="sk-proj-${RUN.slice(0, 44)}"`,
    `OPENAI_API_KEY="sk-proj-${"dummy".repeat(9)}"`,
    `OPENAI_API_KEY="sk-${"ab".repeat(24)}"`,
    `SENDGRID_API_KEY="SG.${"a".repeat(22)}.${"b".repeat(43)}"`,
    `SENDGRID_API_KEY="SG.${RUN.slice(0, 22)}.${RUN.slice(0, 43)}"`,
    "aws_access_key_id = AKIAAAAAAAAAAAAAAAAA",
    "aws_access_key_id = AKIAFAKEFAKEFAKEFAKE",
    `aws_access_key_id = AKIA${RUN.slice(0, 10)}${RUN.slice(36, 42)}`,
    `aws_secret_access_key = ${RUN.slice(10, 36)}${RUN.slice(0, 10)}${RUN.slice(36, 40)}`,
    `aws_secret_access_key = ${"0".repeat(40)}`,
    `const stripe = new Stripe("sk\x5flive_${"1234567890".repeat(3)}");`,
  ];
  for (const line of shapes) assert.deepEqual(found(line), [], line);
});

test("random bodies, and a run beside random text, are still findings", () => {
  const real = [
    ["openai-api-key", `OPENAI_API_KEY="sk-proj-${rand(46)}"`],
    ["openai-api-key", `OPENAI_API_KEY="sk-proj-${"0".repeat(10)}${rand(36)}"`],
    ["openai-api-key", `OPENAI_API_KEY="sk-${rand(48)}"`],
    ["sendgrid-api-key", `SENDGRID_API_KEY="SG.${rand(22)}.${rand(43)}"`],
    ["sendgrid-api-key", `SENDGRID_API_KEY="SG.${"a".repeat(22)}.${rand(43)}"`],
    ["aws-access-key-id", `aws_access_key_id = AKIA${rand(16, BASE32)}`],
    ["aws-access-key-id", `aws_access_key_id = AKIAAAAAAAAA${rand(8, BASE32)}`],
    ["aws-secret-access-key", `aws_secret_access_key = ${rand(40)}`],
    ["stripe-secret-key", `STRIPE_SECRET_KEY=sk\x5flive_AAAAAAAA${rand(24)}`],
  ];
  for (const [rule, line] of real) assert.deepEqual(found(line), [rule], line);
});

test("rules without placeholders keep long runs, as in base64 key material", () => {
  // An OpenSSH ed25519 private key body holds runs of A (zero bytes); its rule doesn't set placeholders.
  assert.equal(isShapePlaceholder("A".repeat(20)), true);
  const pem = ["-----BEGIN OPENSSH PRIVATE\x20KEY-----",
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW",
    `QyNTUxOQAAACD${rand(43)}AAAAJ${rand(40)}`,
    "-----END OPENSSH PRIVATE\x20KEY-----"].join("\n");
  assert.ok(found(pem, "deploy/id_ed25519").length > 0);
});

test("isShapePlaceholder: short bodies and real-looking bodies are not shapes", () => {
  for (const body of ["", "abc", "AAAA", rand(16, BASE32), rand(40), "AAAAAAAA" + rand(24)]) {
    assert.equal(isShapePlaceholder(body), false, body);
  }
});

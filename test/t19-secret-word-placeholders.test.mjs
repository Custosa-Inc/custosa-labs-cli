// T19 (P2, T29-P2-C186 low 1): a provider token whose body spells a placeholder in glued words (YOURSECRETKEYHERE,
// REPLACEWITHYOURKEY, PLACEHOLDER...) is a documentation placeholder, not a finding. Since T29 C234 lists openai,
// sendgrid, AWS and Stripe, such a row in runtime code fails the app. Every pattern that sets placeholders uses it.
// Each word is 8 or more letters, so a random body holds one far below 1e-9 of the time.
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomInt } from "node:crypto";

const { scanSecrets } = await import("../lib/inspector/secrets.mjs");
const { isWordPlaceholder } = await import("../lib/inspector/secret-patterns.mjs");

const KEY = Buffer.alloc(32, 7);
const ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const rand = (n, set = ALNUM) => Array.from({ length: n }, () => set[randomInt(set.length)]).join("");
const found = (line, path = "src/config.js") =>
  scanSecrets([{ path, text: Buffer.from(line + "\n") }], { key: KEY }).secrets.map((s) => s.rule_id);
// Prefixes are joined at run time, so no literal in this file reads as a key to a secret scanner.
const live = (body) => ["sk", "live", body].join("_");

test("placeholder words glued into a provider token give no finding", () => {
  const words = [
    `const stripe = new Stripe("${live("YOURSECRETKEYHERE1234567")}");`,
    `const stripe = new Stripe("${live("REPLACEWITHYOURKEY1234567890")}");`,
    `const stripe = new Stripe("${live("INSERTYOURSTRIPEKEYHERE12")}");`,
    `const stripe = new Stripe("${live("PLACEHOLDER0123456789ABCD")}");`,
    `const stripe = new Stripe("${live("yourkeyhere0000000000000aaaa")}");`,
    `const stripe = new Stripe("${live("ReplaceMe" + rand(20))}");`,
    `const stripe = new Stripe("${live("changeme" + rand(20))}");`,
    `OPENAI_API_KEY="sk-proj-YourApiKeyGoesHere${rand(30)}"`,
    `SENDGRID_API_KEY="SG.${rand(22)}.YOURSENDGRIDKEYPLACEHOLDER${rand(17)}"`,
    `aws_secret_access_key = YourSecretAccessKey${rand(21)}`,
  ];
  for (const line of words) assert.deepEqual(found(line), [], line);
});

test("random bodies, and short words, are still findings", () => {
  const real = [
    ["stripe-secret-key", `const stripe = new Stripe("${live(rand(24))}");`],
    ["stripe-secret-key", `const stripe = new Stripe("${live(rand(99))}");`],
    // a short word in a random body is chance, not a placeholder
    ["stripe-secret-key", `const stripe = new Stripe("${live(`${rand(10)}fake${rand(10)}here${rand(10)}`)}");`],
    ["stripe-secret-key", `const stripe = new Stripe("${live(`${rand(8)}Test${rand(8)}Key${rand(8)}`)}");`],
    ["openai-api-key", `OPENAI_API_KEY="sk-proj-${rand(46)}"`],
    ["sendgrid-api-key", `SENDGRID_API_KEY="SG.${rand(22)}.${rand(43)}"`],
    ["aws-secret-access-key", `aws_secret_access_key = ${rand(40)}`],
  ];
  for (const [rule, line] of real) assert.deepEqual(found(line), [rule], line);
});

test("rules without placeholders keep their findings whatever words they hold", () => {
  // generic-app-secret doesn't set placeholders: a named app secret spelled in words may be a real weak secret.
  assert.deepEqual(found(`SESSION_SECRET=ChangeMe${rand(20)}`, "config/app.env.ts"), ["generic-app-secret"]);
});

test("isWordPlaceholder: no word in 200,000 random 40-character bodies", () => {
  for (const body of ["", "your", "fakekey", rand(40)]) assert.equal(isWordPlaceholder(body), false, body);
  let hits = 0;
  for (let i = 0; i < 200000; i++) if (isWordPlaceholder(rand(40))) hits++;
  assert.equal(hits, 0);
});

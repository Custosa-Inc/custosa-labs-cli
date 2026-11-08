/* more false passes in config-password.
 * - A quoted value may hold the other kind of quote ("it's-pw", 'say "pw"').
 * - One-line JSON: a password key after { or , on the same line.
 * - YAML anchors and tags before a value (&pw "lit", !!str "lit"); an anchor or tag alone is no value.
 * - Quoted scalars inside a YAML flow map ({primary: "lit"}). */
import { test } from "node:test";
import assert from "node:assert/strict";
import { scanSecrets } from "../lib/inspector/secrets.mjs";

const key = Buffer.alloc(32, 9);
const scan = (path, text) => scanSecrets([{ path, text }], { key }).secrets;
const scanEnv = (path, text) => scanSecrets([], { key, envFiles: [{ path, tracked: true, text }] }).secrets;
const rules = (path, text) => scan(path, text).map((s) => s.rule_id);
const envRules = (path, text) => scanEnv(path, text).map((s) => s.rule_id);
const REAL = "Zr7pQwLk2xNv";

test("A quoted value may hold the other kind of quote", () => {
  assert.deepEqual(rules("app.yml", `password: "it's-${REAL}"\n`), ["config-password"]);
  assert.deepEqual(rules("app.yml", `password: 'say "${REAL}"'\n`), ["config-password"]);
  assert.deepEqual(rules("settings.toml", `password = "a'${REAL}"\n`), ["config-password"]);
  assert.deepEqual(envRules(".env", `SMTP_PASSWORD="don't-${REAL}"\n`), ["config-password"]);
  // Still quiet: a reference or a placeholder in quotes, and a command substitution with quotes inside.
  assert.deepEqual(rules("app.yml", `password: "\${SMTP_PW}"\n`), []);
  assert.deepEqual(rules("app.yml", `password: 'your password'\n`), []);
  assert.deepEqual(envRules(".env", `SMTP_PASSWORD="$(cat '/run/secrets/smtp')"\n`), []);
});

test("One-line JSON", () => {
  assert.deepEqual(rules("appsettings.json", `{"Password": "${REAL}"}\n`), ["config-password"]);
  assert.deepEqual(rules("appsettings.json", `{"Smtp": {"Host": "h", "Password": "${REAL}"}}\n`), ["config-password"]);
  assert.deepEqual(rules("config/app.json", `{"name": "x", "db": {"user": "u", "pwd": "${REAL}"}}\n`), ["config-password"]);
  assert.deepEqual(rules("app.json.example", `{"smtpPassword": "${REAL}"}\n`), ["config-password"]);
  // Two keys on a line give one finding for the line.
  assert.deepEqual(rules("app.json", `{\n  "password": "${REAL}", "smtp_pass": "${REAL}x"\n}\n`), ["config-password"]);
  for (const v of ['"${DB_PW}"', '""', '"changeme"', "null", '{"min": 8}', '"<password>"']) {
    assert.deepEqual(rules("appsettings.json", `{"Password": ${v}}\n`), [], v);
  }
  assert.deepEqual(rules("appsettings.json", `{"passwordPolicy": "${REAL}", "label": "password: ${REAL}"}\n`), []);
  assert.deepEqual(rules("locales/de.json", `{"login": {"password": "Passwort eingeben"}}\n`), []);
  assert.deepEqual(rules("app.ts", `const c = {"password": "${REAL}"};\n`), []);   // source code is not config
});

test("YAML anchors and tags before a value", () => {
  for (const v of [`&pw "${REAL}"`, `!!str "${REAL}"`, `&pw !!str "${REAL}"`, `&pw '${REAL}'`, `&pw ${REAL}`,
    `!!str ${REAL}`]) {
    assert.deepEqual(rules("app.yml", `password: ${v}\n`), ["config-password"], v);
  }
  for (const v of ["&pw changeme", '&pw "${DB_PW}"', "&pw", "!!str", "&pw { min: 8 }", "*pw", "!vault |"]) {
    assert.deepEqual(rules("app.yml", `password: ${v}\n`), [], v);
  }
});

test("Quoted scalars in a YAML flow map", () => {
  assert.deepEqual(rules("app.yml", `password: {primary: "${REAL}"}\n`), ["config-password"]);
  assert.deepEqual(rules("app.yml", `password: { primary: '${REAL}', min: 8 }\n`), ["config-password"]);
  assert.deepEqual(rules("app.yml", `password: { primary: "\${DB_PW}", backup: '' }\n`), []);
  assert.deepEqual(rules("app.yml", `password: {primary: "${REAL}"} # rotated\n`), ["config-password"]);
});

/* false passes in the key-anchored password rules.
 * 1. A value is code only when the whole value has a call, index or dotted-name shape; a quoted value never is.
 * 2. A YAML flow map under a password key is skipped only when no scalar inside is a literal. A flow sequence stays
 *    structure.
 * 3. A whole {name} is a placeholder only in a template file (.template, .tmpl), never in other config files.
 * 4. Spring has no required form (:? in .properties is a default), a bare value past the cap is a finding, and
 *    template suffixes (.j2, .local.example) count for config and YAML files alike. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { scanSecrets } from "../lib/inspector/secrets.mjs";

const key = Buffer.alloc(32, 9);
const scan = (path, text) => scanSecrets([{ path, text }], { key }).secrets;
const scanEnv = (path, text) => scanSecrets([], { key, envFiles: [{ path, tracked: true, text }] }).secrets;
const rules = (path, text) => scan(path, text).map((s) => s.rule_id);
const envRules = (path, text) => scanEnv(path, text).map((s) => s.rule_id);
const REAL = "Zr7pQwLk2xNv";

test("brackets inside a password are not code", () => {
  assert.deepEqual(rules("settings.toml", `[db]\npassword = "Zr7p(QwLk2x!"\n`), ["config-password"]);
  assert.deepEqual(rules("app.yml", `password: "k9]Tq2#vLm8z"\n`), ["config-password"]);
  assert.deepEqual(rules("app.properties", `mail.password=Hq3[zR8!pL2w\n`), ["config-password"]);
  assert.deepEqual(rules("appsettings.json", `{\n  "Password": "Wn4)eX7@kP9s"\n}\n`), ["config-password"]);
  assert.ok(rules("application.properties", `spring.datasource.password=Hq3[zR8!pL2w\n`).includes("database-password-config"));
  assert.deepEqual(rules("x.cfg", `smtp_pass = Ab(cd)ef[12\n`), ["config-password"]);
});

test("a whole call, index or dotted name is still code; a quoted one is not", () => {
  // code only on a known function or root; vault.secret.db and cfg.get(pw) are findings now (inspector-secrets-password-6)
  for (const v of ["ENC(AbCdEf123456)", "settings.secret.db", "os.environ[DB_PW]", "getenv(DB_PW)", "env(DB_PW)"]) {
    assert.deepEqual(rules("app.yml", `password: ${v}\n`), [], v);
    assert.deepEqual(rules("app.properties", `mail.password=${v}\n`), [], v);
  }
  assert.deepEqual(rules("app.yml", `password: "vault.secret.db"\n`), ["config-password"]);
  assert.deepEqual(rules("settings.toml", `password = "getenv(DB_PW)"\n`), ["config-password"]);
});

// A fixed-seed generator (mulberry32), so the set of passwords is the same on every run.
const mulberry32 = (seed) => () => {
  seed = (seed + 0x6d2b79f5) | 0;
  let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};
// Printable ASCII without space, quotes, backslash and the comment and separator characters # ; and , (a quote or
// backslash inside a value is a later round; # ; and , end a bare value).
const ALPHABET = [...Array(94)].map((_, i) => String.fromCharCode(33 + i)).filter((c) => !`"'\\#;,`.includes(c)).join("");
const ALNUM = ALPHABET.replace(/[^A-Za-z0-9]/g, "");
const passwords = (n) => {
  const next = mulberry32(58);
  const pick = (chars) => chars[Math.floor(next() * chars.length)];
  return [...Array(n)].map(() => pick(ALNUM) + [...Array(15)].map(() => pick(ALPHABET)).join(""));
};

test("every random printable password under a password key gives a finding", () => {
  const forms = [
    ["settings.toml", (p) => `[db]\npassword = "${p}"\n`],
    ["app.yml", (p) => `smtp:\n  password: "${p}"\n`],
    ["app.yml", (p) => `smtp:\n  password: ${p}\n`],
    ["app.properties", (p) => `mail.password=${p}\n`],
    ["my.ini", (p) => `[client]\npwd=${p}\n`],
    ["x.cfg", (p) => `smtp_pass = ${p}\n`],
    ["appsettings.json", (p) => `{\n  "Smtp": {\n    "Password": "${p}"\n  }\n}\n`],
    ["application.properties", (p) => `spring.datasource.password=${p}\n`],
    ["docker-compose.yml", (p) => `services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: ${p}\n`],
  ];
  const missed = [];
  for (const p of passwords(200)) {
    for (const [path, line] of forms) if (rules(path, line(p)).length === 0) missed.push(`${path}: ${p}`);
    if (envRules(".env", `SMTP_PASSWORD=${p}\n`).length === 0) missed.push(`.env: ${p}`);
  }
  assert.deepEqual(missed, []);
});

test("a YAML flow map holding a literal is a finding", () => {
  for (const v of [`{primary: ${REAL}}`, `{ primary: ${REAL}, backup: x2 }`, `{a: {b: ${REAL}}}`, `{a: [${REAL}]}`,
    `{${REAL}}`]) {
    assert.deepEqual(rules("app.yml", `password: ${v}\n`), ["config-password"], v);
  }
  for (const v of ["{ min: 8 }", "{a: [1, 2], b: {c: 3}}", "{min_length: 12, upper: true, symbols: ~}",
    '{primary: "${DB_PW}", backup: null}', "[]", "{}", "{{ vault_pw }}"]) {
    assert.deepEqual(rules("app.yml", `password: ${v}\n`), [], v);
  }
});

test("a whole {name} is a password outside template files", () => {
  assert.deepEqual(envRules(".env", `SMTP_PASSWORD={${REAL}}\n`), ["config-password"]);
  assert.deepEqual(rules("config.ini", `[mail]\npassword = {${REAL}}\n`), ["config-password"]);
  assert.ok(rules("docker-compose.yml", `environment:\n  POSTGRES_PASSWORD: {${REAL}}\n`).length > 0);
  assert.ok(envRules(".env", `POSTGRES_PASSWORD={${REAL}}\n`).length > 0);
  // A template file's {name} is a slot, as before, and so is an ADO.NET connection string's (string.Format).
  assert.deepEqual(rules("config.ini.template", `[mail]\npassword = {smtp_password}\n`), []);
  assert.deepEqual(envRules(".env.tmpl", `SMTP_PASSWORD={smtp_password}\n`), []);
});

test(":? in a .properties file is a Spring default, not a required form", () => {
  assert.deepEqual(rules("app.properties", `mail.password=\${A:?${REAL}}\n`), ["config-password"]);
  assert.deepEqual(rules("app.properties", `mail.password=\${A:?\${B:${REAL}}}\n`), ["config-password"]);
  // The shell's required form stays quiet where the shell reads it.
  assert.deepEqual(envRules(".env", `SMTP_PASSWORD=\${SMTP_PASSWORD:?must be set}\n`), []);
  assert.deepEqual(rules("app.yml", `password: \${SMTP_PASSWORD:?must be set}\n`), []);
});

test("a bare value past the 256-character cap is a finding", () => {
  const long = (REAL + "Ab3").repeat(30);   // 450 characters
  assert.deepEqual(rules("app.yml", `password: ${long}\n`), ["config-password"]);
  assert.deepEqual(rules("app.properties", `mail.password=${long}\n`), ["config-password"]);
  assert.deepEqual(envRules(".env", `SMTP_PASSWORD=${long}\n`), ["config-password"]);
  assert.deepEqual(rules("app.yml", `password: ${long} # rotated\n`), ["config-password"]);
  assert.deepEqual(rules("app.yml", `password: ${"x".repeat(20000)}Q1\n`), ["config-password"]);
});

test("template suffixes count for config and YAML files alike", () => {
  for (const path of ["app.yml.j2", "app.yml.local.example", "app.yaml.jinja2", "config.ini.j2", "app.properties.dist.example"]) {
    assert.deepEqual(rules(path, `password: ${REAL}\n`).length + rules(path, `a.password=${REAL}\n`).length > 0, true, path);
  }
  assert.deepEqual(rules("app.yml.j2", `password: ${REAL}\n`), ["config-password"]);
  assert.deepEqual(rules("app.yml.local.example", `password: ${REAL}\n`), ["config-password"]);
  // The flow-collection skip follows the same paths.
  assert.deepEqual(rules("app.yml.j2", "password: { min: 8 }\n"), []);
  assert.deepEqual(rules("app.yml.local.example", "password: { min: 8 }\n"), []);
  assert.deepEqual(rules("app.yml.j2", "password: {{ vault_smtp_password }}\n"), []);
});

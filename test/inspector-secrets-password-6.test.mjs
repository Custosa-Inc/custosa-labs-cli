/* misses outside the alphabet and in the code exemption.
 * - A bare value may start with , ; or # in .properties, env and ini-family files (not YAML or TOML).
 * - A password value is code only on a known function (ENC, DEC, getenv, env, ...) or a known root (env., process.env.,
 *   settings., config., os.environ, ENV[...]): a config file never evaluates anything else.
 * - generic-app-secret judges a value in a config file, or a quoted one, by that same code test.
 * - A YAML flow sequence under a password key is judged like a flow map.
 * - Lows: an all-x last segment needs 4 x's, a quoted value over 256 characters is a finding, a {name} slot in a
 *   connection string only for a placeholder-like name, and ${...} or {{...}} inside a flow collection is one scalar. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { scanSecrets } from "../lib/inspector/secrets.mjs";

const key = Buffer.alloc(32, 9);
// An env file goes through envFiles, as the inspector sends it.
const ENV = /(?:^|\/)(?:[^/]*\.)?env(?:\.[^/]*)?$/;
const rules = (path, text) => (ENV.test(path) ? scanSecrets([], { key, envFiles: [{ path, tracked: true, text }] })
  : scanSecrets([{ path, text }], { key })).secrets.map((s) => s.rule_id);
const REAL = "Zr7pQwLk2xNv";

test("A bare value may start with , ; or # in .properties, env and ini files", () => {
  for (const [path, text] of [["app.properties", `mail.password=,${REAL}\n`], [".env", `SMTP_PASSWORD=,${REAL}\n`],
    ["app.properties", `mail.password=;${REAL}\n`], ["my.ini", `[client]\npassword=;${REAL}\n`],
    [".env", `SMTP_PASSWORD=#${REAL}\n`], ["app.properties", `spring.datasource.password=,${REAL}\n`],
    [".env", `POSTGRES_PASSWORD=;${REAL}\n`]]) {
    assert.ok(rules(path, text).length > 0, `${path}: ${text}`);
  }
  for (const [path, text] of [["app.yml", `password: #${REAL}\n`], ["app.yml", `password: ,${REAL}\n`],
    ["settings.toml", `password = ;${REAL}\n`], [".env", "SMTP_PASSWORD=#\n"], [".env", "SMTP_PASSWORD=,\n"]]) {
    assert.deepEqual(rules(path, text), [], `${path}: ${text}`);
  }
});

test("A password value is code only on a known function or root", () => {
  for (const v of ["Correct.Horse.Battery", "Welcome.Home2024", "Summer(2024)", "Hunter2[99]", "vault.secret.db",
    "cfg.get(pw)"]) {
    assert.deepEqual(rules("app.yml", `password: ${v}\n`), ["config-password"], v);
    assert.ok(rules("application.properties", `spring.datasource.password=${v}\n`).length > 0, `spring ${v}`);
    assert.ok(rules(".env", `POSTGRES_PASSWORD=${v}\n`).length > 0, `postgres ${v}`);
  }
  for (const v of ["ENC(AbCdEf123456)", "DEC()", "getenv(DB_PW)", "env(DB_PW)", "os.getenv(DB_PW)",
    "os.environ[DB_PW]", "ENV[DB_PW]", "env.DB_PW", "process.env.DB_PW", "settings.DB_PW", "config.db.password",
    "os.environ.DB_PW"]) {
    assert.deepEqual(rules("app.yml", `password: ${v}\n`), [], v);
    assert.deepEqual(rules(".env", `POSTGRES_PASSWORD=${v}\n`), [], `postgres ${v}`);
  }
});

test("Generic-app-secret in a config file or quoted judges the whole value", () => {
  const long = "Zr7p(QwLk2xNvB8mT4sYd9HcF";
  for (const [path, text] of [[".env", `JWT_SECRET=${long}\n`], [".env", `SECRET_KEY=Zr7pQwLk2xNvB8mT4sYd9HcF[x\n`],
    ["config/secret.yml", `session_secret: "Zr7p)QwLk2xNvB8mT4sYd9HcF"\n`]]) {
    assert.deepEqual(rules(path, text), ["generic-app-secret"], text);
  }
  // in source code a call or index stays a code reference
  for (const text of ["const JWT_SECRET = config.getOrThrow<string>('JWT_SECRET_VALUE_NAME_X');\n",
    "JWT_SECRET = os.environ[\"JWT_SECRET_FROM_THE_ENVIRONMENT\"]\n"]) {
    assert.deepEqual(rules("src/secret.ts", text), [], text);
  }
  assert.deepEqual(rules(".env", "JWT_SECRET=process.env.SOME_LONG_SECRET_NAME_X1\n"), []);
});

test("A YAML flow sequence under a password key", () => {
  for (const v of [`[${REAL}]`, `[${REAL}, other]`, "[a, b]", `["${REAL}"]`]) {
    assert.deepEqual(rules("app.yml", `password: ${v}\n`), ["config-password"], v);
  }
  for (const v of ["[8, 12]", "[]", "[${DB_PW}]", "[ ]"]) {
    assert.deepEqual(rules("app.yml", `password: ${v}\n`), [], v);
  }
});

test("the lows of the second review", () => {
  // an all-x last segment is a placeholder only with 4 or more x's
  assert.deepEqual(rules("app.yml", "password: Zr7pQw-x\n"), ["config-password"]);
  assert.deepEqual(rules("app.yml", "password: Zr7pQw.XX\n"), ["config-password"]);
  assert.deepEqual(rules("app.yml", "password: Zr7pQw-xxxx\n"), []);
  // a quoted value over 256 characters, YAML and TOML
  const over = `Zr7p${"Q".repeat(300)}`;
  assert.deepEqual(rules("app.yml", `password: "${over}"\n`), ["config-password"]);
  assert.deepEqual(rules("settings.toml", `password = '${over}'\n`), ["config-password"]);
  // a {name} slot in a connection string only for a placeholder-like name
  assert.ok(rules("web.config", `<add connectionString="Server=db;User Id=u;Password={${REAL}};" />\n`).length > 0);
  for (const v of ["{password}", "{Password}", "{pwd}", "{pass}", "{secret}", "{dbPassword}"]) {
    assert.deepEqual(rules("web.config", `<add connectionString="Server=db;User Id=u;Password=${v};" />\n`), [], v);
  }
  // ${...} and {{...}} inside a flow collection are one scalar each
  for (const v of ["{primary: ${DB_PW}}", "{primary: {{ vault_pw }}}", "[${A:-}]", "{a: ${B}, b: ${C}}"]) {
    assert.deepEqual(rules("app.yml", `password: ${v}\n`), [], v);
  }
  assert.deepEqual(rules("app.yml", `password: {primary: \${DB_PW}, backup: ${REAL}}\n`), ["config-password"]);
});

// The seeded test of inspector-secrets-password-1.test.mjs, with , and ; in the alphabet for the forms that allow them.
const mulberry32 = (seed) => () => {
  seed = (seed + 0x6d2b79f5) | 0;
  let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};
const ALPHABET = [...Array(94)].map((_, i) => String.fromCharCode(33 + i)).filter((c) => !`"'\\#`.includes(c)).join("");

test("Random passwords with , and ; in .properties, env and ini forms give a finding", () => {
  const next = mulberry32(230);
  const pick = (chars) => chars[Math.floor(next() * chars.length)];
  const forms = [["app.properties", (p) => `mail.password=${p}\n`], ["my.ini", (p) => `[client]\npwd=${p}\n`],
    [".env", (p) => `SMTP_PASSWORD=${p}\n`], ["application.properties", (p) => `spring.datasource.password=${p}\n`]];
  const missed = [];
  for (let n = 0; n < 200; n++) {
    const p = [...Array(16)].map(() => pick(ALPHABET)).join("");
    for (const [path, text] of forms) if (rules(path, text(p)).length === 0) missed.push(`${path}: ${p}`);
  }
  assert.deepEqual(missed, []);
});

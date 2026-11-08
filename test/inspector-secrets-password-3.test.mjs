/* config-password keys, files and interpolation.
 * - .cnf files (MySQL option files) are config files.
 * - passphrase, client secret and Spring's jwt.secret keys are password keys.
 * - Lower-case shell defaults (${db_password-lit}) where the shell reads them: env-named and compose files.
 * - Two or more plain references side by side (${A}${B}) are a reference, not a literal. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { scanSecrets } from "../lib/inspector/secrets.mjs";

const key = Buffer.alloc(32, 9);
const scan = (path, text) => scanSecrets([{ path, text }], { key }).secrets;
const scanEnv = (path, text) => scanSecrets([], { key, envFiles: [{ path, tracked: true, text }] }).secrets;
const rules = (path, text) => scan(path, text).map((s) => s.rule_id);
const envRules = (path, text) => scanEnv(path, text).map((s) => s.rule_id);
const REAL = "Zr7pQwLk2xNv";

test(".cnf files are config files", () => {
  assert.deepEqual(rules("my.cnf", `[client]\npassword=${REAL}\n`), ["config-password"]);
  assert.deepEqual(rules("etc/mysql/conf.d/app.cnf", `password = ${REAL}\n`), ["config-password"]);
  assert.deepEqual(rules("my.cnf", "[client]\npassword=\n"), []);
});

test("passphrase, client secret and jwt.secret keys", () => {
  for (const [path, line] of [["app.yml", `passphrase: ${REAL}`], ["app.yml", `ssl_key_passphrase: '${REAL}'`],
    ["app.yml", `client_secret: ${REAL}`], ["app.yml", `clientSecret: "${REAL}"`],
    ["application.properties", `spring.security.oauth2.client.registration.x.client-secret=${REAL}`],
    ["application.properties", `jwt.secret=${REAL}`], ["app.json", `{"ClientSecret": "${REAL}"}`]]) {
    assert.deepEqual(rules(path, `${line}\n`), ["config-password"], line);
  }
  for (const line of ["client_secret: ${OAUTH_SECRET}", "passphrase: changeme", "client_secret_name: smtp",
    "secret: true", "jwt.secret.ttl: 3600", "client_secret_expires_at: 0", "passphrase_hint: your password"]) {
    assert.deepEqual(rules("app.yml", `${line}\n`), [], line);
  }
});

test("a lower-case shell default is judged where the shell reads it", () => {
  assert.deepEqual(envRules(".env", `SMTP_PASSWORD=\${smtp_password-${REAL}}\n`), ["config-password"]);
  assert.deepEqual(rules("docker-compose.yml", `x:\n  environment:\n    SMTP_PASSWORD: \${smtp_pw-${REAL}}\n`),
    ["config-password"]);
  assert.deepEqual(envRules(".env", "SMTP_PASSWORD=${smtp_password?must be set}\n"), []);
  // In Spring's files ${my-app.pw} is a property name, as before.
  assert.deepEqual(rules("application.yml", `mail:\n  password: \${my-app-${REAL}}\n`), []);
  assert.deepEqual(rules("app.properties", `mail.password=\${db_password-${REAL}}\n`), []);
});

test("plain references side by side are a reference", () => {
  for (const v of ["${A}${B}", "${SMTP_USER}${SMTP_PW}", "$A$B", "${A}$B"]) {
    assert.deepEqual(rules("app.yml", `password: ${v}\n`), [], v);
    assert.deepEqual(envRules(".env", `SMTP_PASSWORD=${v}\n`), [], v);
  }
  for (const v of [`\${A}${REAL}`, `${REAL}\${A}`, `\${A}\${B:${REAL}}`]) {
    assert.deepEqual(rules("app.yml", `password: ${v}\n`), ["config-password"], v);
  }
});

/* Password rules, round 2, part 6: the review of part 5.
 * - A call is code only as ENC(...) or DEC(...) (DEC() only), or getenv or env with an env-style name
 *   (DB_PW, optionally quoted): no config format evaluates a bare lookup(, vault( or secret(.
 * - A sops value (ENC[AES256_GCM,data:...]) is no finding, also past the 256-character cap.
 * - In a connection string {0} to {9} are slots (string.Format).
 * - A ${...} whose whole body is a lower-case dotted property path, with no :, is a reference in every file. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { scanSecrets } from "../lib/inspector/secrets.mjs";

const key = Buffer.alloc(32, 9);
const ENV = /(?:^|\/)(?:[^/]*\.)?env(?:\.[^/]*)?$/;
const rules = (path, text) => (ENV.test(path) ? scanSecrets([], { key, envFiles: [{ path, tracked: true, text }] })
  : scanSecrets([{ path, text }], { key })).secrets.map((s) => s.rule_id);

test("Only ENC, DEC, and getenv or env of an env-style name are code", () => {
  for (const [path, text] of [["app.properties", "mail.password=secret(2024)\n"],
    ["app.properties", "mail.password=vault(Summer2024)\n"], ["app.properties", "mail.password=lookup(hunter2)\n"],
    ["app.properties", "mail.password=env(hunter2)\n"], ["application.properties", "spring.datasource.password=secret(2024)\n"],
    [".env", "POSTGRES_PASSWORD=vault(x9)\n"], ["app.yml", "password: getenv(hunter2)\n"]]) {
    assert.ok(rules(path, text).length > 0, `${path}: ${text}`);
  }
  for (const v of ["ENC(AbCdEf123456)", "DEC()", "getenv(DB_PW)", "env(DB_PW)", "os.getenv(DB_PW)",
    "System.getenv(DB_PW)"]) {
    assert.deepEqual(rules("app.properties", `mail.password=${v}\n`), [], v);
    assert.deepEqual(rules(".env", `POSTGRES_PASSWORD=${v}\n`), [], `postgres ${v}`);
  }
});

test("A sops value is no finding, also past the cap", () => {
  const short = "ENC[AES256_GCM,data:Zr7pQwLk2xNv,iv:AbCd1234,tag:EfGh5678==,type:str]";
  const long = `ENC[AES256_GCM,data:${"Q".repeat(400)},iv:AbCd1234,tag:EfGh5678==,type:str]`;
  for (const v of [short, long]) {
    assert.deepEqual(rules("secrets.enc.yaml", `db:\n  password: ${v}\n`), [], v.slice(0, 40));
    assert.deepEqual(rules("secrets.yaml", `POSTGRES_PASSWORD: ${v}\n`), [], `postgres ${v.slice(0, 40)}`);
  }
  // only the whole sops shape: another ENC[...] or a cut one is a value
  assert.deepEqual(rules("app.yml", "password: ENC[Zr7pQwLk2xNv]\n"), ["config-password"]);
  assert.deepEqual(rules("app.yml", "password: ENC[AES256_GCM,data:Zr7p\n"), ["config-password"]);
});

test("{0} to {9} are slots in a connection string only", () => {
  for (const v of ["{0}", "{1}", "{9}"]) {
    assert.deepEqual(rules("web.config", `<add connectionString="Server=db;User Id=u;Password=${v};" />\n`), [], v);
  }
  assert.ok(rules("web.config", '<add connectionString="Server=db;User Id=u;Password={10};" />\n').length > 0);
  assert.deepEqual(rules("app.yml", "password: \"{0}\"\n"), ["config-password"]);
});

test("A ${...} whose body is a lower-case dotted property path is a reference in every file", () => {
  for (const [path, text] of [["app.yml", "password: ${my-app.pw}\n"], ["myservice-prod.yml", "spring:\n  mail:\n    " +
    "password: ${mail-server.password}\n"], ["config/mail.yml", "spring.mail.password: ${mail-server.password}\n"],
  ["docker-compose.yml", "password: ${smtp.pw}\n"]]) {
    assert.deepEqual(rules(path, text), [], `${path}: ${text}`);
  }
  // a shell default that is not a dotted path, or with a :, is still judged
  assert.deepEqual(rules("docker-compose.yml", "password: ${smtp_pw-Zr7pQwLk2xNv}\n"), ["config-password"]);
  assert.deepEqual(rules("app.yml", "password: ${A:Zr7pQwLk2xNv}\n"), ["config-password"]);
  assert.deepEqual(rules("app.yml", "password: ${my-Zr7pQwLk2x}\n"), ["config-password"]);
});

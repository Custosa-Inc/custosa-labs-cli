/* The review of round 3.
 * - A bare value may hold a quote after its first character (mail.password=Zr7p"Qw); in YAML a value that starts with
 *   a quote once its tag or anchor is set aside belongs to the quoted form.
 * - A sops value in JSON: the quoted capture is the whole sops value, so its closing quote and comma don't matter.
 * - DEC(...) with content is jasypt's plaintext waiting for jasypt:encrypt, a finding; DEC() empty is no value. Only
 *   ENC(...) with no parentheses inside is code.
 * - A ${...} is a property path only in lower case, digits and hyphens: ${postgres_pw-Hunter2.x} is a shell default. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { scanSecrets } from "../lib/inspector/secrets.mjs";

const key = Buffer.alloc(32, 9);
const ENV = /(?:^|\/)(?:[^/]*\.)?env(?:\.[^/]*)?$/;
const rules = (path, text) => (ENV.test(path) ? scanSecrets([], { key, envFiles: [{ path, tracked: true, text }] })
  : scanSecrets([{ path, text }], { key })).secrets.map((s) => s.rule_id);

test("A quote inside a bare value", () => {
  for (const v of ['Zr7p"QwLk2xNv', "Zr7p'QwLk2xNv", "Zr7p'Qw\"Lk2xNv", 'Zr7pQwLk2xNv"']) {
    assert.deepEqual(rules("mail.properties", `mail.password=${v}\n`), ["config-password"], `properties ${v}`);
    assert.deepEqual(rules(".env", `SMTP_PASSWORD=${v}\n`), ["config-password"], `env ${v}`);
    assert.deepEqual(rules("app.yml", `db:\n  password: ${v}\n`), ["config-password"], `yaml ${v}`);
    assert.deepEqual(rules("app.yml", `jwt:\n  secret: ${v}\n`), ["config-password"], `yaml secret ${v}`);
    assert.deepEqual(rules("app.ini", `password = ${v} ; rotated\n`), ["config-password"], `ini ${v}`);
  }
  // the leading , ; or # form, and a bare value over the cap with a quote in it
  assert.deepEqual(rules("mail.properties", "mail.password=;Zr7p\"QwLk2xNv\n"), ["config-password"]);
  assert.deepEqual(rules("mail.properties", `mail.password=Zr7p"${"Q".repeat(300)}\n`), ["config-password"]);
  // CRLF
  assert.deepEqual(rules("mail.properties", "mail.password=Zr7p\"QwLk2xNv\r\n"), ["config-password"]);
});

test("A YAML value that starts with a quote after its tag or anchor is the quoted form's", () => {
  for (const v of ['&pw "${DB_PW}"', '!!str "${DB_PW}"', "&pw '${DB_PW}'", '&pw !!str "${DB_PW}"', '"${DB_PW}" # it\'s']) {
    assert.deepEqual(rules("app.yml", `password: ${v}\n`), [], v);
  }
  for (const v of ['&pw "Zr7pQwLk2xNv"', '!!str "Zr7pQwLk2xNv"', "&pw 'Zr7pQwLk2xNv'", '"it\'s-Zr7pQwLk2xNv"']) {
    assert.deepEqual(rules("app.yml", `password: ${v}\n`), ["config-password"], v);
  }
  // still quiet: a reference, a placeholder, a quoted reference with a comment after it
  for (const v of ["${DB_PW}", "changeme", "'${DB_PW}' # it's set by CI", '"" # "empty"']) {
    assert.deepEqual(rules("app.yml", `password: ${v}\n`), [], v);
  }
  for (const v of ["${DB_PW}", "changeme"]) {
    assert.deepEqual(rules("mail.properties", `mail.password=${v}\n`), [], `properties ${v}`);
  }
});

test("A flow map with a quote gives one finding", () => {
  assert.deepEqual(rules("app.yml", 'password: {primary: "Zr7pQwLk2xNv"}\n'), ["config-password"]);
  assert.deepEqual(rules("app.yml", "password: { primary: 'Zr7pQwLk2xNv', min: 8 }\n"), ["config-password"]);
  assert.deepEqual(rules("app.yml", "password: [\"Zr7pQwLk2xNv\"]\n"), ["config-password"]);
  assert.deepEqual(rules("app.yml", 'password: { primary: "${DB_PW}", backup: \'\' }\n'), []);
});

test("A sops value in JSON is no finding", () => {
  const sops = "ENC[AES256_GCM,data:q1w2,iv:x,tag:y,type:str]";
  const long = `ENC[AES256_GCM,data:${"Q".repeat(400)},iv:AbCd1234,tag:EfGh5678==,type:str]`;
  for (const v of [sops, long]) {
    for (const [path, text] of [
      ["secrets.enc.json", `{\n  "password": "${v}",\n  "sops": {"version": "3.8.1"}\n}\n`],
      ["secrets.enc.json", `{\n  "db": {\n    "password": "${v}"\n  }\n}\n`],
      ["secrets.enc.json", `{"password": "${v}", "sops": {}}\n`],
      ["appsettings.json", `{"Password": "${v}"}\n`],
      ["appsettings.json", `{\r\n  "Password": "${v}",\r\n  "User": "u"\r\n}\r\n`],
      ["secrets.enc.json", `{\n  "DB_PASSWORD": "${v}",\n  "POSTGRES_PASSWORD": "${v}"\n}\n`],
      ["secrets.enc.yaml", `password: '${v}'\n`]]) {
      assert.deepEqual(rules(path, text), [], `${path}: ${text.slice(0, 60)}`);
    }
  }
  // only the whole quoted value: more after the closing ] is a value
  assert.deepEqual(rules("app.json", `{"password": "${sops}Zr7pQwLk2xNv"}\n`), ["config-password"]);
  assert.deepEqual(rules("app.json", `{\n  "password": "ENC[Zr7pQwLk2xNv]",\n}\n`), ["config-password"]);
});

test("DEC(...) with content is plaintext; ENC(...) is code only whole", () => {
  for (const [path, text] of [["app.properties", "mail.password=DEC(Summer2024)\n"],
    ["app.properties", "mail.password=DEC(AbCdEf123456)\n"], ["app.yml", "password: DEC(Zr7pQwLk2xNv)\n"],
    [".env", "POSTGRES_PASSWORD=DEC(AbCdEf123456)\n"],
    ["application.properties", "spring.datasource.password=DEC(Summer2024)\n"],
    ["app.properties", "mail.password=ENC(x)hunter2(y)\n"], ["app.yml", "password: ENC(a)(b)\n"],
    ["app.properties", "mail.password=ENC(AbCd(Ef))\n"]]) {
    assert.ok(rules(path, text).length > 0, `${path}: ${text}`);
  }
  for (const v of ["ENC(AbCdEf123456)", "ENC(G6N718UuyPE5bHyWKyuLQSm02auQPUtm)", "DEC()", "ENC()"]) {
    assert.deepEqual(rules("app.properties", `mail.password=${v}\n`), [], v);
    assert.deepEqual(rules(".env", `POSTGRES_PASSWORD=${v}\n`), [], `postgres ${v}`);
    assert.deepEqual(rules("app.yml", `password: ${v}\n`), [], `yaml ${v}`);
  }
});

test("A property path is lower case, digits and hyphens only", () => {
  for (const [path, text] of [["docker-compose.yml", "services:\n  db:\n    environment:\n      SMTP_PASSWORD: ${postgres_pw-Hunter2.x}\n"],
    [".env", "SMTP_PASSWORD=${postgres_pw-Hunter2.x}\n"], ["app.yml", "password: ${postgres_pw-Hunter2.x}\n"],
    ["app.yml", "password: ${Pg-Hunter2.x}\n"]]) {
    assert.deepEqual(rules(path, text), ["config-password"], `${path}: ${text}`);
  }
  for (const [path, text] of [["app.yml", "password: ${my-app.pw}\n"], ["app.yml", "password: ${mail-server.password}\n"],
    ["docker-compose.yml", "password: ${smtp.pw}\n"], ["app.yml", "password: ${a1.b-2.c3}\n"]]) {
    assert.deepEqual(rules(path, text), [], `${path}: ${text}`);
  }
});

/* the captured quoted value itself must be the whole sops value. Its data can't run past
 * the closing quote, and after that quote only JSON's , } or ], or a comment, may follow. */
test("A quoted sops look-alike that holds plaintext is a finding", () => {
  const sops = "ENC[AES256_GCM,data:q1w2,iv:x,tag:y,type:str]";
  for (const [path, text] of [
    ["app.json", '{"password": "ENC[AES256_GCM,data:Hunter2RealPw", "note": "]"}\n'],
    ["app.yml", 'password: "ENC[AES256_GCM,data:Hunter2RealPw" # ]"\n'],
    ["app.yml", "password: 'ENC[AES256_GCM,data:Hunter2RealPw' # ]'\n"],
    [".env", `DB_PASSWORD='${sops}'Hunter2RealPw\n`],
    [".env", `SMTP_PASSWORD="${sops}"Hunter2RealPw\n`],
    ["app.properties", `mail.password="${sops}"Hunter2RealPw\n`],
    ["app.json", '{"password": "ENC[AES256_GCM,data:Hunter2 RealPw]"}\n'],
    ["app.yml", "password: ENC[AES256_GCM,data:Hunter2RealPw #]\n"]]) {
    assert.ok(rules(path, text).length > 0, `${path}: ${text}`);
  }
  // still quiet: JSON's ", "} and "], a comment after the quote, CRLF
  for (const [path, text] of [
    ["secrets.enc.json", `{"password": "${sops}", "x": 1}\n`], ["secrets.enc.json", `{"password": "${sops}"}\n`],
    ["secrets.enc.json", `{"password": ["${sops}"]}\n`], ["secrets.enc.yaml", `password: "${sops}" # sops\n`],
    ["secrets.enc.yaml", `password: '${sops}'  \r\n`], [".env", `DB_PASSWORD="${sops}"\n`],
    ["app.ini", `password = "${sops}" ; sops\n`]]) {
    assert.deepEqual(rules(path, text), [], `${path}: ${text}`);
  }
});

/* what may follow the closing quote of a sops value depends on the file's format. JSON's
 * , } and ] (and a YAML or TOML flow map or sequence on the line), a comment after a space in YAML, TOML and .env,
 * ; or # in INI, and in .properties only trailing whitespace. Anything else is part of the value. */
test("After a quoted sops value, only what the file's format allows keeps it quiet", () => {
  const sops = "ENC[AES256_GCM,data:q1w2,iv:x,tag:y,type:str]";
  const pw = "Hunter2RealPw";
  for (const [path, text] of [
    [".env", `SMTP_PASSWORD="${sops}",${pw}\n`], [".env", `DB_PASSWORD="${sops}",${pw}\n`],
    [".env", `DB_PASSWORD='${sops}']${pw}\n`], [".env", `DB_PASSWORD='${sops}'}${pw}\n`],
    [".env", `DB_PASSWORD="${sops}"#${pw}\n`],
    ["app.properties", `mail.password="${sops}",${pw}\n`], ["app.properties", `mail.password='${sops}']${pw}\n`],
    ["app.properties", `mail.password="${sops}"}${pw}\n`], ["app.properties", `mail.password="${sops}"#${pw}\n`],
    ["app.properties", `mail.password="${sops}" #${pw}\n`], ["app.properties", `mail.password="${sops}";${pw}\n`],
    ["app.properties", `spring.datasource.password="${sops}",${pw}\n`],
    ["app.ini", `password = "${sops}",${pw}\n`],
    // not valid in their format, and not quiet either
    ["app.yml", `password: "${sops}",${pw}\n`], ["app.json", `{"password": "${sops}"#${pw}}\n`],
    ["app.toml", `password = "${sops}",${pw}\n`],
    // CRLF
    [".env", `DB_PASSWORD="${sops}",${pw}\r\n`], ["app.properties", `mail.password="${sops}";${pw}\r\n`]]) {
    assert.ok(rules(path, text).length > 0, `${path}: ${text}`);
  }
  for (const [path, text] of [
    ["app.yml", `db: {password: "${sops}", user: app}\n`], ["app.yml", `passwords: ["${sops}"]\n`],
    ["app.yml", `password: "${sops}" # sops\n`], ["app.toml", `db = { password = "${sops}", user = "a" }\n`],
    ["app.toml", `password = "${sops}" # sops\n`], [".env", `DB_PASSWORD="${sops}" # sops\n`],
    [".env", `DB_PASSWORD='${sops}'\t\r\n`], ["app.ini", `password = "${sops}" ; sops\n`],
    ["app.ini", `password = "${sops}" # sops\n`], ["app.properties", `mail.password="${sops}"  \n`],
    ["app.properties", `spring.datasource.password='${sops}'\r\n`], ["app.json", `{"password": "${sops}"}\n`]]) {
    assert.deepEqual(rules(path, text), [], `${path}: ${text}`);
  }
});

/* In INI only a ; or # comment after a space may follow the closing
 * quote. configparser reads ";x" right after the quote as value text, so a quiet result there isn't justified. */
test("In INI a comment after a quoted sops value needs a space before it", () => {
  const sops = "ENC[AES256_GCM,data:q1w2,iv:x,tag:y,type:str]";
  for (const [path, text] of [
    ["app.ini", `password = "${sops}";Hunter2RealPw\n`], ["app.ini", `password = "${sops}"#Hunter2RealPw\n`],
    ["app.ini", `password = "${sops}";x\n`], ["app.ini", `password = "${sops}"#x\n`],
    ["app.cfg", `password = "${sops}";x\n`], ["app.conf", `password = "${sops}";x\n`],
    ["my.cnf", `password = "${sops}"#x\n`], ["app.ini.local", `password = "${sops}";x\n`],
    ["app.ini", `password = "${sops}";x\r\n`]]) {
    assert.ok(rules(path, text).length > 0, `${path}: ${text}`);
  }
  for (const [path, text] of [
    ["app.ini", `password = "${sops}" ; sops\n`], ["app.ini", `password = "${sops}" # sops\n`],
    ["app.ini", `password = "${sops}"\t;sops\r\n`], ["app.cfg", `password = "${sops}"  \n`],
    ["my.cnf", `password = "${sops}"\n`]]) {
    assert.deepEqual(rules(path, text), [], `${path}: ${text}`);
  }
});

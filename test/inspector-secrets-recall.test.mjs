/* Scanner recall for committed secrets.
 * - config-password: a password-like key with a literal value in config files (yml, yaml, properties, json, toml,
 *   ini, cfg, conf and env-named files), anchored at the start of its line; the ADO.NET Password=x; form too.
 * - supabase-service-role-config: a literal under a service-role key name, in any file.
 * - url-userinfo-password: scheme://user:password@host for schemes the five database URL rules don't cover.
 * Placeholders give no finding; a doubt errs toward a finding. The three rules fingerprint the location (rule, path
 * and line), never the value. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { scanSecrets, fingerprint } from "../lib/inspector/secrets.mjs";
import { DEFAULT_SECRET_PATTERNS } from "../lib/inspector/secret-patterns.mjs";

const key = Buffer.alloc(32, 9);
const scan = (path, text) => scanSecrets([{ path, text }], { key }).secrets;
const scanEnv = (path, text) => scanSecrets([], { key, envFiles: [{ path, tracked: true, text }] }).secrets;
const hits = (path, text) => scan(path, text).map((s) => `${s.rule_id}:${s.line}`);
const envHits = (path, text) => scanEnv(path, text).map((s) => `${s.rule_id}:${s.line}`);
const REAL = "Wq8vT3rLmZ2k";

test("config-password: a literal under a password key in every config format", () => {
  assert.deepEqual(hits("application.yml", `spring:\n  flyway:\n    user: ehr\n    password: ${REAL}\n`), ["config-password:4"]);
  assert.deepEqual(hits("a/b/app.yaml", `security:\n  authAdminPassword: ${REAL}\n`), ["config-password:2"]);
  assert.deepEqual(hits("app.properties", `spring.flyway.password=${REAL}\n`), ["config-password:1"]);
  assert.deepEqual(hits("app.properties", `mail.smtp.pass = ${REAL}\n`), ["config-password:1"]);
  assert.deepEqual(hits("appsettings.json", `{\n  "Smtp": {\n    "Password": "${REAL}"\n  }\n}\n`), ["config-password:3"]);
  assert.deepEqual(hits("settings.toml", `[db]\npassword = "${REAL}"\n`), ["config-password:2"]);
  assert.deepEqual(hits("my.ini", `[client]\npwd=${REAL}\n`), ["config-password:2"]);
  assert.deepEqual(hits("x.cfg", `ldap_passwd: '${REAL}'\n`), ["config-password:1"]);
  assert.deepEqual(hits("x.conf", `  SMTP_PASS=${REAL}\n`), ["config-password:1"]);
  assert.deepEqual(hits("list.yml", `users:\n  - password: ${REAL}\n`), ["config-password:2"]);
  assert.deepEqual(hits("env.local.example", `export ADMIN_PASSWORD=${REAL}\n`), ["config-password:1"]);
  assert.deepEqual(hits("application.yml.example", `password: ${REAL}\n`), ["config-password:1"]);
  assert.deepEqual(envHits("config/production.env", `SMTP_PASSWORD=${REAL}\n`), ["config-password:1"]);
  assert.deepEqual(envHits(".env", `REDIS_PASS="${REAL}"\n`), ["config-password:1"]);
});

test("config-password: source code, substrings, comments and mid-line keys are not findings", () => {
  for (const name of ["app.ts", "settings.py", "Main.java", "README.md", "app.yml.ts"]) {
    assert.deepEqual(hits(name, `password: ${REAL}\npassword = "${REAL}"\n`), [], name);
  }
  for (const line of [`bypass: ${REAL}`, `password_hash: ${REAL}`, `min-password-length: ${REAL}`, `passwordPolicy: ${REAL}`,
    `BYPASS=${REAL}`, `DBPASSWORD_FILE=${REAL}`, `# password: ${REAL}`, `// password: ${REAL}`, `; password=${REAL}`,
    `dsn: host=db user=u password: ${REAL}`, `note: the password: ${REAL}`, `compass: ${REAL}`]) {
    assert.deepEqual(hits("c.yml", `${line}\n`), [], line);
  }
});

test("config-password: placeholders, references and empty values give no finding", () => {
  const values = ["", '""', "''", "~", "null", "None", "${SMTP_PW}", "${SMTP_PW:}", "$SMTP_PW", "<password>",
    "{{ db_password }}", "*****", "%s", "ENC(AbCdEf123456)", "settings.secret.db", "password", "changeme", "secret",
    "example", "your_password", "xxx", "todo", "TODO", "your-password-here", "xxxxxxxxxx", "|", ">-", "*db_pw",
    "'${SMTP_PW}'"];
  for (const v of values) assert.deepEqual(hits("app.yml", `password: ${v}\n`), [], v);
  for (const v of values.filter((x) => !/^[|>*]/.test(x))) assert.deepEqual(hits("app.properties", `a.password=${v}\n`), [], v);
  // Multi-word placeholders.
  for (const v of ["change me", "your password here", '"your password"', "'change me'", "!vault |"]) {
    assert.deepEqual(hits("app.yml", `password: ${v}\n`), [], v);
  }
});

test("config-password: a translation file is a locale-code name in a translation folder", () => {
  for (const p of ["config/locales/de.yml", "src/i18n/de.json", "lang/pt-BR.json", "public/locales/fr/common.json",
    "translations/es_MX.yaml", "src/main/resources/i18n/messages_fr.properties", "i18n/messages_pt_BR.properties"]) {
    assert.deepEqual(hits(p, "password: Passwort\npassword=Mot de passe\n"), [], p);
  }
  // Not translation files: no locale-code name, or no translation folder right above it (a Spring "it" profile far
  // under lang/ is not Italian).
  for (const p of ["config/lang/db.yml", "lang/java/app/src/main/resources/application.yml", "deploy/en-US.yml", "es_MX.yaml",
    "i18n/app.yml", "locales/settings.json", "lang/java/app/src/main/resources/application-it.yml",
    "locales/deploy/app-de.yml"]) {
    assert.deepEqual(hits(p, "password: Qz7p\x44ummyPw4x\n"), ["config-password:1"], p);
  }
});

test("config-password: a passphrase (several words) is a finding, quoted or bare", () => {
  assert.deepEqual(hits("app.yml", 'password: "correct horse battery staple"\n'), ["config-password:1"]);
  assert.deepEqual(hits("app.yml", "password: correct horse battery\n"), ["config-password:1"]);
  assert.deepEqual(hits("app.yml", "password: correct horse battery # rotated\n"), ["config-password:1"]);
  assert.deepEqual(hits("mail.properties", "mail.password=my secret pw\n"), ["config-password:1"]);
  assert.deepEqual(hits("x.json", '{\n  "password": "Mot de passe",\n}\n'), ["config-password:2"]);
  assert.deepEqual(hits("my.ini", "[client]\npassword = two words\n"), ["config-password:2"]);
  assert.deepEqual(hits("s.toml", "password = 'two words'\n"), ["config-password:1"]);
  assert.deepEqual(hits("app.yml", "password: !!str two words\n"), ["config-password:1"]);
});

test("config-password: a Spring or shell default on a database rule's key is judged by that rule's host logic", () => {
  const PW = "Qz7p\x44ummyPw4x";
  // The lines with a finding (the database rule may also read the name inside ${...}: one line either way).
  const lines = (path, text) => [...new Set(scan(path, text).map((x) => x.line))];
  assert.deepEqual(lines("app.properties", `spring.datasource.password=\${JDBC_PW:${PW}}\n`), [1]);
  assert.deepEqual(lines("application.yml", `spring.datasource.password: "\${DB_PASSWORD:${PW}}"\n`), [1]);
  assert.deepEqual(lines("compose.yml", `services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: \${POSTGRES_PASSWORD:-${PW}}\n`), [4]);
  assert.ok(hits("app.properties", `spring.datasource.password=\${JDBC_PW:${PW}}\n`).includes("config-password:1"));
  // The database rule's own logic: a default word with no host, or loopback only, stays quiet; no default is a reference.
  assert.deepEqual(hits("app.properties", "spring.datasource.password=${JDBC_PW:postgres}\n"), []);
  assert.deepEqual(hits("app.properties", "spring.datasource.url=jdbc:postgresql://localhost/app\nspring.datasource.password=${JDBC_PW:postgres}\n"), []);
  assert.deepEqual(hits("app.properties", "spring.datasource.url=jdbc:postgresql://db.example.org/app\nspring.datasource.password=${JDBC_PW:postgres}\n"),
    ["config-password:2"]);
  assert.deepEqual(hits("app.properties", "spring.datasource.password=${JDBC_PW}\n"), []);
  assert.deepEqual(hits("app.properties", "spring.datasource.password=${JDBC_PW:}\n"), []);
  // A nested default is judged on its innermost default; a nested reference with no literal is no finding
  // from this rule. (The database rule itself still reads ${DB_PASSWORD:} inside a nested form.)
  assert.deepEqual(lines("app.properties", `spring.datasource.password=\${A:\${B:${PW}}}\n`), [1]);
});

test("config-password: a nested default is unwrapped to its innermost default on any key", () => {
  const PW = "Zr7pQwLk2";
  assert.deepEqual(hits("app.properties", `app.mail.password=\${A:\${B:${PW}}}\n`), ["config-password:1"]);
  assert.deepEqual(hits("app.yml", `password: "\${MAIL_PW:\${OTHER_PW:${PW}}}"\n`), ["config-password:1"]);
  assert.deepEqual(hits("app.yml", `password: \${MAIL_PW:\${OTHER_PW:-\${THIRD:${PW}}}}\n`), ["config-password:1"]);
  for (const v of ["${A:${B}}", "${A:${B:}}", "${A:-${B:-}}", '"${A:${B}}"']) {
    assert.deepEqual(hits("app.yml", `password: ${v}\n`), [], v);
  }
});

test("config-password: a required-variable form names no value", () => {
  const lines = (path, text) => [...new Set(scan(path, text).map((x) => x.line))];
  for (const v of ["${POSTGRES_PASSWORD:?required}", "${POSTGRES_PASSWORD?required}"]) {
    assert.deepEqual(lines("compose.yml", `services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: ${v}\n`), [], v);
  }
  for (const v of ["${SMTP_PASSWORD:?SMTP password must be set}", "${SMTP_PASSWORD?must be set}", '"${SMTP_PASSWORD:?}"']) {
    assert.deepEqual(hits("compose.yml", `      SMTP_PASSWORD: ${v}\n`), [], v);
  }
});

test("config-password: a shell ${X-default} is judged on its default", () => {
  const PW = "Zr7pQwLk2";
  const lines = (path, text) => [...new Set(scan(path, text).map((x) => x.line))];
  assert.deepEqual(lines("compose.yml", `services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: \${POSTGRES_PASSWORD-${PW}}\n`), [4]);
  assert.deepEqual(hits("compose.yml", `      SMTP_PASSWORD: \${SMTP_PASSWORD-${PW}}\n`), ["config-password:1"]);
  assert.deepEqual(hits("compose.yml", "      SMTP_PASSWORD: ${SMTP_PASSWORD-}\n"), []);
  // A Spring property name may hold a hyphen: ${my-app.pw} is a reference, not my with the default app.pw, in every
  // file (a lower-case dotted property path).
  assert.deepEqual(hits("application.yml", "password: ${my-app.pw}\n"), []);
  assert.deepEqual(hits("app.yml", "password: ${my-app.pw}\n"), []);
  assert.deepEqual(hits("app.properties", "mail.password=${mail-svc.smtp-pw}\n"), []);
});

test("config-password: a YAML flow map or sequence is structure, not a value", () => {
  for (const v of ["{ min-length: 8 }", "{min: 8, max: 64}", "{}"]) {
    assert.deepEqual(hits("app.yml", `password: ${v}\n`), [], v);
  }
  assert.deepEqual(hits("app.yml", "password: [a, b]\n"), ["config-password:1"]);   // a sequence of literals
  // A bare value that only contains a brace is still a value.
  assert.deepEqual(hits("app.yml", "password: Zr7p{QwLk2\n"), ["config-password:1"]);
});

test("config-password: the flow-collection skip is YAML only, and only for a whole collection", () => {
  const PW = "Zr7pQwLk2x";
  // Outside YAML a leading brace or bracket is the password's first character.
  assert.deepEqual(hits("src/main/resources/application.properties", `spring.security.user.password={noop}${PW}\n`),
    ["config-password:1"]);
  assert.deepEqual(hits("my.ini", `[client]\npwd={${PW}\n`), ["config-password:2"]);
  assert.deepEqual(hits("config.ini", `password = {${PW}\n`), ["config-password:1"]);
  assert.deepEqual(envHits(".env", `SMTP_PASSWORD={${PW}\n`), ["config-password:1"]);
  // In YAML, a value that does not close with its matching bracket at its end is not a collection.
  for (const v of ["{{ vault_pw }}x", `{noop}${PW}`, `{${PW}`]) {
    assert.deepEqual(hits("app.yml", `password: ${v}\n`), ["config-password:1"], v);
  }
  assert.deepEqual(hits("app.yaml.example", "password: { min: 8 }\n"), []);
  assert.deepEqual(hits("app.yml", "password: {a: [1, 2], b: {c: 3}}\n"), []);
});

test("config-password: nesting past the unwrap cap is a finding", () => {
  const PW = "Zr7pQwLk2";
  const nest = (n) => "${A:".repeat(n) + PW + "}".repeat(n);
  for (const n of [8, 9, 12]) {
    assert.deepEqual(hits("app.properties", `app.mail.password=${nest(n)}\n`), ["config-password:1"], `${n}`);
  }
  const lines = (path, text) => [...new Set(scan(path, text).map((x) => x.line))];
  assert.deepEqual(lines("app.properties", `spring.datasource.password=${nest(9)}\n`), [1]);
  // Past the cap the value is judged as a finding even with no literal inside.
  assert.deepEqual(hits("app.yml", `password: ${"${A:".repeat(9)}${"}".repeat(9)}\n`), ["config-password:1"]);
});

test("config-password: Spring has no required form, so ${a.b:?lit} is a default", () => {
  const PW = "Zr7pQwLk2";
  assert.deepEqual(hits("app.properties", `app.mail.password=\${a.b:?${PW}}\n`), ["config-password:1"]);
  assert.deepEqual(hits("app.yml", `password: \${mail.pw:?${PW}}\n`), ["config-password:1"]);
  // The shell forms stay required.
  assert.deepEqual(hits("compose.yml", "      SMTP_PASSWORD: ${SMTP_PASSWORD:?must be set}\n"), []);
  // A Spring name with a hyphen keeps its default.
  assert.deepEqual(hits("app.properties", `app.mail.password=\${A_B-c:${PW}}\n`), ["config-password:1"]);
});

test("config-password: a Spring messages bundle is a translation file wherever it sits", () => {
  for (const p of ["src/main/resources/messages.properties", "src/main/resources/messages_de.properties",
    "i18n/messages.properties", "messages_pt_BR.properties"]) {
    assert.deepEqual(hits(p, "login.password=Enter password here\n"), [], p);
  }
  for (const p of ["src/main/resources/application.properties", "src/main/resources/messages-prod.properties",
    "src/main/resources/messages.yml"]) {
    assert.deepEqual(hits(p, "login.password=Enter password here\n"), ["config-password:1"], p);
  }
});

test("config-password: a YAML boolean under a password key is a flag, not a secret", () => {
  for (const v of ["true", "false", "yes", "no", "on", "off", "True", "FALSE", '"true"']) {
    assert.deepEqual(hits("app.yml", `pass: ${v}\n`), [], v);
    assert.deepEqual(hits("app.properties", `smtp.password=${v}\n`), [], v);
  }
  assert.deepEqual(hits("app.yml", "pass: trueish9X\n"), ["config-password:1"]);
});

test("config-password: Spring ${VAR:default} is judged on its default", () => {
  assert.deepEqual(hits("application.yml", `password: \${SMTP_PW:${REAL}}\n`), ["config-password:1"]);
  assert.deepEqual(hits("application.yml", `password: "\${SMTP_PW:-${REAL}}"\n`), ["config-password:1"]);
  assert.deepEqual(hits("application.yml", "password: ${SMTP_PW:changeme}\n"), []);
  assert.deepEqual(hits("application.yml", "password: ${SMTP_PW:${OTHER_PW}}\n"), []);
});

test("config-password: a local default is skipped only with a host named, every host loopback, and no prod name", () => {
  const local = "datasource:\n  url: jdbc:postgresql://localhost:5432/app\n  password: postgres\n";
  assert.deepEqual(hits("application.yml", local), []);
  for (const word of ["root", "admin", "test", "dev", "sa", "postgres", "mysql", "guest"]) {
    assert.deepEqual(hits("a.yml", `host: 127.0.0.1\npassword: ${word}\n`), [], word);
    // No host named: a finding.
    assert.deepEqual(hits("a.yml", `password: ${word}\n`), ["config-password:1"], word);
  }
  // A non-loopback host anywhere in the file.
  assert.deepEqual(hits("application.yml", local.replace("localhost", "db.internal")), ["config-password:3"]);
  // A prod or production part in the file name or a folder name.
  for (const p of ["application-prod.yml", "config/production/app.yml", "prod.env.local", "app.production.yml"]) {
    assert.deepEqual(hits(p, local), ["config-password:3"], p);
  }
});

test("config-password: on database-password-config's keys it adds only a local default on a prod path", () => {
  // No host named, or only loopback, is local for those keys.
  assert.deepEqual(hits("nohost.cfg", "POSTGRES_PASSWORD=postgres\n"), []);
  assert.deepEqual(hits("compose.yml", "services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: postgres\n"), []);
  // A nested key is not the dotted spring.datasource.password: the prod-path rule applies, and no host named is a finding.
  assert.deepEqual(hits("application.yml", "spring:\n  datasource:\n    password: postgres\n"), ["config-password:3"]);
  assert.deepEqual(hits("config/production.cfg", "POSTGRES_PASSWORD=postgres\n"), ["config-password:1"]);
  assert.deepEqual(hits("docker-compose.prod.yml", "x:\n  DB_HOST: localhost\n  DB_PASSWORD: root\n"), ["config-password:3"]);
  assert.deepEqual(envHits("prod.env", "PGPASSWORD=admin\n"), ["config-password:1"]);
  assert.deepEqual(hits("config/production.cfg", "POSTGRES_PASSWORD=${PW}\n"), []);
});

test("config-password: the database-password-config rule wins on the same line", () => {
  assert.deepEqual(hits("app.properties", "spring.datasource.password=Zx9wQ2vL\n"), ["database-password-config:1"]);
  assert.deepEqual(envHits(".env", "DB_PASSWORD=Zx9wQ2vL\n"), ["database-password-config:1"]);
});

test("config-password: ADO.NET and SQL Server connection strings in config files", () => {
  const cs = (pw, server = "sql.example.org") => `{\n  "ConnectionStrings": {\n    "Main": "Server=${server};Database=app;User Id=sa;Password=${pw};"\n  }\n}\n`;
  assert.deepEqual(hits("appsettings.json", cs(REAL)), ["config-password:3"]);
  assert.deepEqual(hits("web.config", `<add connectionString="Data Source=db1;Initial Catalog=x;Pwd=${REAL};" />\n`), ["config-password:1"]);
  assert.deepEqual(hits("appsettings.json", cs("{password}")), []);
  assert.deepEqual(hits("appsettings.json", cs("$(DB_PW)")), []);
  assert.deepEqual(hits("appsettings.json", cs("sa", "localhost")), []);
  assert.deepEqual(hits("appsettings.json", cs("sa", "(localdb)\\\\MSSQLLocalDB")), []);
  assert.deepEqual(hits("appsettings.json", cs("sa")), ["config-password:3"]);
  // Only beside Server= or Data Source=, and never in source code.
  assert.deepEqual(hits("appsettings.json", `{ "x": "Password=${REAL};" }\n`), []);
  assert.deepEqual(hits("Db.cs", `var s = "Server=db1;Password=${REAL};";\n`), []);
});

test("supabase-service-role-config: a literal under a service-role key name, in any file", () => {
  const LONG = "Aa1B\x622Cc3Dd4Ee5Ff6Gg7Hh8";
  assert.deepEqual(hits("config/env.local.example", `SUPABASE_URL=https://x.supabase.co\nSUPABASE_SERVICE_ROLE_KEY=${LONG}\n`),
    ["supabase-service-role-config:2"]);
  assert.deepEqual(hits("src/admin.ts", `const serviceRoleKey = "${LONG}";\n`), ["supabase-service-role-config:1"]);
  assert.deepEqual(hits("x.yml", `supabase_service_key: ${LONG}\n`), ["supabase-service-role-config:1"]);
  for (const v of ["process.env.SUPABASE_SERVICE_ROLE_KEY", 'Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")', "${SUPABASE_SERVICE_ROLE_KEY}",
    "<your-service-role-key>", "your-service-role-key-here-123", "short123", "xxxxxxxxxxxxxxxxxxxxxxxx", "sb_publishable_Aa1Bb2Cc3Dd4Ee5Ff6Gg7"]) {
    assert.deepEqual(hits("a.env.example", `SERVICE_ROLE_KEY=${v}\n`), [], v);
  }
  // An anon JWT under a service-role name is public by design; a service_role JWT is the JWT rule's.
  const jwt = (role) => ["eyJhbGciOiJIUzI1NiJ9", Buffer.from(JSON.stringify({ role, iss: "supabase" })).toString("base64url"),
    "c2lnbmF0dXJlc2lnbmF0dXJlc2ln"].join(".");
  assert.deepEqual(hits("a.ts", `serviceRoleKey: "${jwt("anon")}"\n`), []);
  assert.deepEqual(hits("a.ts", `serviceRoleKey: "${jwt("service_role")}"\n`), ["supabase-service-role-jwt:1"]);
  assert.deepEqual(hits("a.ts", `serviceRoleKey: "sb\x5fsecret_${LONG}"\n`), ["supabase-secret-key:1"]);
});

test("url-userinfo-password: other schemes with a password in the userinfo", () => {
  for (const scheme of ["https", "http", "smtp", "smtps", "ftp", "sftp", "ldap", "ldaps", "sqlserver", "nats"]) {
    assert.deepEqual(hits("a.ts", `const u = "${scheme}://svc:${REAL}@mail.example.org:25/x";\n`), ["url-userinfo-password:1"], scheme);
  }
  for (const u of ["https://user:password@example.org", "https://user:${TOKEN}@github.com/x.git", "https://user:@h.org",
    "http://localhost:8080/a@b", "https://x-access-token:$GITHUB_TOKEN@github.com", "smtp://u:pass@smtp.example.org",
    "http://admin:admin@localhost:9000", "https://u:<password>@h.org"]) {
    assert.deepEqual(hits("a.ts", `const u = "${u}";\n`), [], u);
  }
  // The database URL rules keep their own schemes.
  assert.deepEqual(hits("a.ts", `const u = "postgresql://u:${REAL}@db.example.org/x";\n`), ["postgres-url-password:1"]);
  assert.deepEqual(hits("a.ts", `const u = "jdbc:mysql://u:${REAL}@db.example.org/x";\n`), ["mysql-url-password:1"]);
  assert.deepEqual(hits("a.ts", `const u = "mongodb+srv://u:${REAL}@c.example.org/x";\n`), ["mongodb-url-password:1"]);
});

test("the three password-location rules fingerprint the location, never the value", () => {
  const LOC = "custosa-secret-location-v1\0";
  const loc = (rule, path, line) => createHmac("sha256", key).update(LOC).update(`${rule}\0${path}\0${line}`, "utf8").digest("hex");
  const [a] = scan("a.yml", `password: ${REAL}\n`);
  assert.equal(a.fingerprint, loc("config-password", "a.yml", 1));
  assert.notEqual(a.fingerprint, fingerprint(key, REAL));
  // The same value in two places gives two fingerprints; two values on one place give the same one.
  const [b] = scan("b.yml", `password: ${REAL}\n`);
  assert.notEqual(a.fingerprint, b.fingerprint);
  assert.equal(scan("a.yml", "password: Other9Value\n")[0].fingerprint, a.fingerprint);
  const [s] = scan("x.env.example", "SERVICE_ROLE_KEY=Aa1B\x622Cc3Dd4Ee5Ff6Gg7Hh8\n");
  assert.equal(s.fingerprint, loc("supabase-service-role-config", "x.env.example", 1));
  const [u] = scan("a.ts", `"smtp://svc:${REAL}@mail.example.org"\n`);
  assert.equal(u.fingerprint, loc("url-userinfo-password", "a.ts", 1));
  // Provider tokens keep the value fingerprint.
  const [g] = scan("a.ts", `"ghp_${"a1".repeat(18)}"\n`);
  assert.equal(g.fingerprint, fingerprint(key, `ghp_${"a1".repeat(18)}`));
  // These patterns are inspector-only and marked as location rules.
  const b58 = DEFAULT_SECRET_PATTERNS.filter((p) => ["config-password", "supabase-service-role-config", "url-userinfo-password"].includes(p.rule_id));
  assert.ok(b58.length >= 3);
  assert.ok(b58.every((p) => p.inspectorOnly === true && p.location === true));
});

test("a pathContext or location that is the wrong type is refused", () => {
  for (const [field, value, problem] of [["pathContext", "x", "a pathContext that is not a regex"], ["location", 1, "a location that is not a boolean"]]) {
    assert.throws(() => scanSecrets([], { key, patterns: [{ rule_id: "r", regex: /a/, [field]: value }] }),
      (err) => err.message === `Secret pattern r has ${problem}.`);
  }
});

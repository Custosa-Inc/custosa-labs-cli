/* the review of part 3.
 * - An XML attribute value runs to its own closing quote: XML allows an unescaped > and the other quote inside it.
 * - Dockerfile ENV and ARG: a pair on a continuation line (after a line ending in \) inside an ENV or ARG block.
 * - The seeded property test covers XML attributes, XML element text and Dockerfile forms, one-line and multi-line. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { scanSecrets } from "../lib/inspector/secrets.mjs";

const key = Buffer.alloc(32, 9);
const rules = (path, text) => scanSecrets([{ path, text }], { key }).secrets.map((s) => s.rule_id);
const REAL = "Zr7pQwLk2xNv";

test("an XML attribute value runs to its own closing quote", () => {
  for (const [path, line] of [["applicationContext.xml", `<property name="password" value="Zr7p>Qw${REAL}"/>`],
    ["applicationContext.xml", `<property name="password" value="'${REAL}"/>`],
    ["applicationContext.xml", `<property name='password' value='Zr7p"${REAL}'/>`],
    ["tomcat-users.xml", `<user username="admin" password="Zr7p>${REAL}" roles="manager"/>`],
    ["tomcat-users.xml", `<user username="admin" password="'${REAL}" roles="manager"/>`],
    ["web.config", `<add key="SmtpPassword" value="${REAL}>x" />`]]) {
    assert.deepEqual(rules(path, `${line}\n`), ["config-password"], line);
  }
  for (const line of ['<property name="password" value="${DB_PW}"/>', '<user username="u" password=""/>',
    '<property name="password" value=""/>', "<user username=\"u\" password='' />"]) {
    assert.deepEqual(rules("settings.xml", `${line}\n`), [], line);
  }
});

test("a Dockerfile ENV or ARG pair on a continuation line", () => {
  for (const text of [`ENV A=1 \\\n    SMTP_PASSWORD=${REAL}\n`, `ENV A=1 \\\n    B=2 \\\n    SMTP_PASSWORD="${REAL}"\n`,
    `ARG A=1 \\\n  ADMIN_PASSWORD=${REAL} \\\n  C=3\n`, `ENV NODE_ENV=production \\\n\tDB_PASS='${REAL}' PORT=80\n`,
    `ENV A=1 \\\n    PORT=80 SMTP_PASSWORD=${REAL}\n`]) {
    assert.ok(rules("Dockerfile", `FROM node:22\n${text}`).length > 0, text);
  }
  for (const text of [`RUN echo a \\\n    SMTP_PASSWORD=${REAL}\n`, `ENV A=1\n    SMTP_PASSWORD=${REAL}\n`,
    "ENV A=1 \\\n    SMTP_PASSWORD=${SMTP_PASSWORD}\n", "ARG A=1 \\\n    SMTP_PASSWORD\n",
    `ENV A=1 \\\n    B=2\nRUN x \\\n    SMTP_PASSWORD=${REAL}\n`]) {
    assert.deepEqual(rules("Dockerfile", `FROM node:22\n${text}`), [], text);
  }
});

// The same fixed-seed generator and alphabet as inspector-secrets-password-1.test.mjs.
const mulberry32 = (seed) => () => {
  seed = (seed + 0x6d2b79f5) | 0;
  let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};
const ALPHABET = [...Array(94)].map((_, i) => String.fromCharCode(33 + i)).filter((c) => !`"'\\#;,`.includes(c)).join("");
const ALNUM = ALPHABET.replace(/[^A-Za-z0-9]/g, "");
const passwords = (n) => {
  const next = mulberry32(5832);
  const pick = (chars) => chars[Math.floor(next() * chars.length)];
  return [...Array(n)].map(() => pick(ALNUM) + [...Array(15)].map(() => pick(ALPHABET)).join(""));
};
// Escaped as each format needs: & and < in XML; $ in a Dockerfile's double quotes.
const xml = (p) => p.replace(/&/g, "&amp;").replace(/</g, "&lt;");
const docker = (p) => p.replace(/\$/g, "\\$");

test("every random printable password in XML and Dockerfile forms gives a finding", () => {
  const forms = [
    ["applicationContext.xml", (p) => `<property name="password" value="${xml(p)}"/>\n`],
    ["applicationContext.xml", (p) => `<property name='password' value='${xml(p)}'/>\n`],
    ["tomcat-users.xml", (p) => `<user username="admin" password="${xml(p)}" roles="manager"/>\n`],
    ["web.config", (p) => `<add key="SmtpPassword" value="${xml(p)}" />\n`],
    ["settings.xml", (p) => `<server><id>x</id><password>${xml(p)}</password></server>\n`],
    ["hibernate.cfg.xml", (p) => `<property name="connection.password">${xml(p)}</property>\n`],
    ["Dockerfile", (p) => `FROM node:22\nENV SMTP_PASSWORD="${docker(p)}" PORT=80\n`],
    ["Dockerfile", (p) => `FROM node:22\nENV A=1 \\\n    SMTP_PASSWORD="${docker(p)}" \\\n    PORT=80\n`],
    ["Dockerfile", (p) => `FROM node:22\nARG A=1 \\\n    ADMIN_PASSWORD="${docker(p)}"\n`],
  ];
  const missed = [];
  for (const p of passwords(200)) {
    for (const [path, text] of forms) if (rules(path, text(p)).length === 0) missed.push(`${path}: ${text(p).trim()}`);
  }
  assert.deepEqual(missed, []);
});

test("XML shapes", () => {
  for (const [path, text] of [["applicationContext.xml", `<property value="${REAL}" name="password"/>\n`],
    ["web.config", `<add value="${REAL}" key="SmtpPassword" />\n`],
    ["applicationContext.xml", `<property\n    name="password"\n    value="${REAL}"/>\n`],
    ["tomcat-users.xml", `<user\n  username="admin"\n  password="${REAL}"\n  roles="manager"/>\n`],
    ["settings.xml", `<password><![CDATA[${REAL}]]></password>\n`],
    ["hibernate.cfg.xml", `<property name="connection.password"><![CDATA[${REAL}]]></property>\n`],
    ["settings.xml", `<password>\n    ${REAL}\n</password>\n`],
    ["applicationContext.xml", `<property name="password"><value>${REAL}</value></property>\n`],
    ["applicationContext.xml", `<property name="password">\n  <value>${REAL}</value>\n</property>\n`]]) {
    assert.deepEqual(rules(path, text), ["config-password"], text);
  }
  for (const text of ['<property value="${DB_PW}" name="password"/>\n', '<add value="strong" key="PasswordPolicy" />\n',
    "<password><![CDATA[${db.password}]]></password>\n", "<password>\n    ${db.password}\n</password>\n",
    '<property name="password"><value>${DB_PW}</value></property>\n', '<property name="password" ref="secretBean"/>\n',
    "<password>\n</password>\n", '<property\n    name="password"\n    value=""/>\n']) {
    assert.deepEqual(rules("applicationContext.xml", text), [], text);
  }
});

test("nested YAML for the client and jwt secrets", () => {
  for (const text of [`jwt:\n  secret: ${REAL}\n`, `oauth:\n  client:\n    secret: "${REAL}"\n`,
    `app:\n  jwt:\n    secret: ${REAL}\n`, `security:\n  oauth2:\n    client:\n      secret: ${REAL}\n`]) {
    assert.deepEqual(rules("application.yml", text), ["config-password"], text);
  }
  for (const text of [`jwt:\n  secret: \${JWT_SECRET}\n`, `jwt:\n  secret:\n    ttl: 3600\n`, `jwt:\n  secret: true\n`,
    `vault:\n  secret: ${REAL}\n`, `secret: ${REAL}\n`, `jwt:\n  ttl: 3\nsecret: ${REAL}\n`,
    `client:\n  id: x\nsecret: ${REAL}\n`]) {
    assert.deepEqual(rules("application.yml", text), [], text);
  }
});

test("shell defaults read in every file but Spring's own", () => {
  for (const path of ["docker-compose-prod.yml", "docker-compose.yml.example", "docker-stack.yml", "compose/prod.yml",
    "deploy/values.yaml", "config.toml"]) {
    const text = path.endsWith(".toml") ? `password = "\${smtp_password-${REAL}}"\n` : `password: \${smtp_password-${REAL}}\n`;
    assert.deepEqual(rules(path, text), ["config-password"], path);
    const required = path.endsWith(".toml") ? 'password = "${smtp_password?set it}"\n' : "password: ${smtp_password?set it}\n";
    assert.deepEqual(rules(path, required), [], `${path} required`);
  }
  // Spring's own files keep ${my-app...} as a property name, and ${A:?lit} as the default ?lit
  assert.deepEqual(rules("application.yml", "password: ${my-app.pw-x}\n"), []);
  assert.deepEqual(rules("application-prod.yml", `password: \${MAIL_PW:?${REAL}}\n`), ["config-password"]);
  assert.deepEqual(rules("bootstrap.yaml", `password: \${MAIL_PW:?${REAL}}\n`), ["config-password"]);
  assert.deepEqual(rules("app.properties", `mail.password=\${MAIL_PW:?${REAL}}\n`), ["config-password"]);
});

test("an Npgsql connection string with Host=", () => {
  for (const path of ["web.config", "appsettings.json"]) {
    const line = path.endsWith(".json") ? `{"ConnectionStrings": {"Db": "Host=db;Username=u;Password=${REAL}"}}\n`
      : `<add name="Db" connectionString="Host=db;Username=u;Password=${REAL};" />\n`;
    assert.ok(rules(path, line).includes("config-password"), line);
  }
  for (const v of ["{password}", "${DB_PW}"]) {   // a slot and a reference, as with Server=
    assert.deepEqual(rules("appsettings.json", `{"Db": "Host=db;Username=u;Password=${v}"}\n`), [], v);
  }
});

test("part 4: the part 2 regressions (review lows)", () => {
  assert.deepEqual(rules("app.properties", "mail.password=$ZR7P$Q\n"), ["config-password"]);
  assert.deepEqual(rules("app.properties", "mail.password=${A}${B}\n"), []);   // two Spring references
  assert.deepEqual(rules(".env", "SMTP_PASSWORD=$A$B\n"), []);
  assert.deepEqual(rules("app.yml", `password: !!map {primary: "${REAL}"}\n`), ["config-password"]);
  assert.deepEqual(rules("app.yml", 'password: !!map {primary: "${DB_PW}"}\n'), []);
});

/* config-password in Dockerfiles and XML.
 * - Dockerfile ENV and ARG: KEY=value pairs, several on a line, quoted or bare, and the one-pair ENV KEY value form.
 * - XML: a password element (<password>lit</password>), a name or key with a value attribute (<property
 *   name="db.password" value="lit"/>, <add key="SmtpPassword" value="lit"/>), and a password attribute (<user
 *   password="lit"/>). References and placeholders stay quiet, as everywhere. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { scanSecrets } from "../lib/inspector/secrets.mjs";

const key = Buffer.alloc(32, 9);
const rules = (path, text) => scanSecrets([{ path, text }], { key }).secrets.map((s) => s.rule_id);
const REAL = "Zr7pQwLk2xNv";

test("Dockerfile ENV and ARG", () => {
  for (const [path, line] of [["Dockerfile", `ENV SMTP_PASSWORD ${REAL}`], ["Dockerfile", `ENV SMTP_PASSWORD=${REAL}`],
    ["Dockerfile", `ENV APP=web SMTP_PASSWORD=${REAL} PORT=80`], ["Dockerfile", `ENV SMTP_PASSWORD="${REAL}" PORT=80`],
    ["docker/api.Dockerfile", `ARG ADMIN_PASSWORD=${REAL}`], ["Dockerfile.prod", `env smtp_pass='${REAL}'`],
    ["Containerfile", `ENV MAIL_PASSWORD ${REAL}`], ["Dockerfile", `ENV POSTGRES_PASSWORD ${REAL}`]]) {
    assert.ok(rules(path, `FROM node:22\n${line}\n`).length > 0, line);
  }
  for (const line of ["ENV SMTP_PASSWORD=${SMTP_PASSWORD}", "ARG SMTP_PASSWORD", "ARG SMTP_PASSWORD=",
    "ENV SMTP_PASSWORD=changeme PORT=80", "ENV SMTP_PASSWORD_FILE=/run/secrets/smtp", "RUN echo password=x",
    'ENV SMTP_PASSWORD=""', "ENV APP=web PORT=80"]) {
    assert.deepEqual(rules("Dockerfile", `FROM node:22\n${line}\n`), [], line);
  }
  assert.deepEqual(rules("notes/Dockerfile.md", `ENV SMTP_PASSWORD ${REAL}\n`), []);   // not a Dockerfile
});

test("XML password elements and attributes", () => {
  for (const [path, line] of [["settings.xml", `<server><id>x</id><password>${REAL}</password></server>`],
    ["pom.xml", `  <db.password>${REAL}</db.password>`], ["context.xml", `<Resource name="jdbc/x" password="${REAL}"/>`],
    ["tomcat-users.xml", `<user username="admin" password="${REAL}" roles="manager"/>`],
    ["applicationContext.xml", `<property name="password" value="${REAL}"/>`],
    ["web.config", `<add key="SmtpPassword" value="${REAL}" />`], ["hibernate.cfg.xml", `<property name="connection.password">${REAL}</property>`],
    ["app.xml.example", `<smtpPassword>${REAL}</smtpPassword>`]]) {
    assert.deepEqual(rules(path, `${line}\n`), ["config-password"], line);
  }
  for (const line of ["<password>${db.password}</password>", "<password></password>", "<password>changeme</password>",
    '<property name="password" value="${DB_PW}"/>', '<add key="PasswordPolicy" value="strong" />',
    '<user username="u" password=""/>', "<passwordLength>12</passwordLength>", '<input type="password" value="x"/>',
    '<property name="password" ref="secretBean"/>']) {
    assert.deepEqual(rules("settings.xml", `${line}\n`), [], line);
  }
  assert.deepEqual(rules("src/App.java", `String x = "<password>${REAL}</password>";\n`), []);   // not XML
});

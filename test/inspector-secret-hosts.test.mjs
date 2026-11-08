/* Pins the database hosts the database-password-config rule reads from a whole file (fileDbHosts in
 * secret-patterns.mjs), in order, including the compose ports reader. The rule's validate asks for them through
 * memo("dbHosts", fn), so a memo that records fn(text) sees the exact list. No secret-shaped literal is used: the
 * password is the local default "postgres". */
import { test } from "node:test";
import assert from "node:assert/strict";

const { DEFAULT_SECRET_PATTERNS } = await import("../lib/inspector/secret-patterns.mjs");

const rule = DEFAULT_SECRET_PATTERNS.find((p) => p.rule_id === "database-password-config");

const hostsOf = (text) => {
  let hosts;
  rule.validate("postgres", { memo: (name, fn) => { assert.equal(name, "dbHosts"); hosts = fn(text); return hosts; } });
  return hosts;
};

const svc = (ports) => `services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: postgres\n${ports}`;

test("compose ports in YAML: short, long, flow, multi-line flow, alias and comments", () => {
  const cases = [
    [svc('    ports:\n      - "5432"\n'), ["0.0.0.0"]],
    [svc('    ports:\n      - "5432:5432"\n      - "127.0.0.1:6379:6379"\n'), ["0.0.0.0", "127.0.0.1"]],
    [svc('    ports:\n      - "[::1]:5432:5432/tcp"\n'), ["[::1]"]],
    [svc('    ports:\n      - "${PG_PORT:-5432}:5432"\n'), ["0.0.0.0"]],
    [svc('    ports:\n      - "127.0.0.1:${PG_PORT:-5432}:5432"\n'), ["127.0.0.1"]],
    [svc("    ports:\n      - 5432:5432 # all interfaces\n"), ["0.0.0.0"]],
    [svc("    ports:\n      - target: 5432\n        published: 5432\n"), ["0.0.0.0"]],
    [svc("    ports:\n      - target: 5432\n        published: 5432\n        host_ip: 127.0.0.1\n"), ["127.0.0.1"]],
    [svc("    ports:\n      - target: 5432\n        host_ip: 10.0.0.9\n"), []],
    [svc("    ports:\n      - target: 5432\n        published: 5432\n      - target: 6379\n        published: 6379\n        host_ip: ${IP:-127.0.0.1}\n"),
      ["0.0.0.0", "127.0.0.1"]],
    [svc('    ports: ["5432:5432", "127.0.0.1:6379:6379"]\n'), ["0.0.0.0", "127.0.0.1"]],
    [svc('    ports: [\n      "5432:5432",\n      "127.0.0.1:6379:6379"\n    ]\n'), ["0.0.0.0", "127.0.0.1"]],
    [svc('    ports: [\n      "5432:5432"\n'), ["0.0.0.0"]],
    [svc("    ports: *dbports\n"), ["0.0.0.0"]],
    [svc('    ports:\n      - "5432:5432"\n    networks: [a]\n  cache:\n    ports:\n      - "127.0.0.1:6379:6379"\n'),
      ["0.0.0.0", "127.0.0.1"]],
    [svc("    ports:\n\n      # none yet\n"), []],
  ];
  for (const [text, hosts] of cases) assert.deepEqual(hostsOf(text), hosts, text);
});

test("compose ports in JSON: strings, numbers and long-form objects", () => {
  const cases = [
    ['{"ports":["5432:5432", 6379]}', ["0.0.0.0", "0.0.0.0"]],
    ['{"ports":["127.0.0.1:5432:5432"]}', ["127.0.0.1"]],
    ['{"ports":[{"target":5432,"published":5432}]}', ["0.0.0.0"]],
    ['{"ports":[{"target":5432,"published":5432,"host_ip":"127.0.0.1"},{"target":1}]}', ["127.0.0.1"]],
    ['{"ports" : [ ]}', []],
  ];
  for (const [text, hosts] of cases) assert.deepEqual(hostsOf(text), hosts, text);
});

// Bug fix: an interpolated host_ip ("${IP:-10.0.0.9}") holds braces; the object around it was cut there and the
// published port was missed, so a default password could read as local.
test("compose ports in JSON: a long-form object whose host_ip is an interpolation is still read", () => {
  const cases = [
    ['{"ports":[{"target":5432,"published":5432,"host_ip":"${IP:-10.0.0.9}"}]}', ["10.0.0.9"]],
    ['{"ports":[{"published":5432,"host_ip":"${IP}"},{"target":1,"published":2}]}', ["\u0001", "0.0.0.0"]],
    ['{"ports":[{"target":5432,"host_ip":"${IP:-10.0.0.9}"}]}', []],
  ];
  for (const [text, hosts] of cases) assert.deepEqual(hostsOf(text), hosts, text);
});

test("other host sources keep their order: URLs, settings, dotted keys, libpq, compose, nested YAML, network_mode", () => {
  const text = [
    "url: postgres://app@db1.example.com:5432,db2.example.com/app?host=db3.example.com",
    "DB_HOST=${DB_HOST:-db4.example.com}",
    "spring.datasource.host=db5.example.com",
    "dsn: host=db6.example.com dbname=app",
    "services:",
    "  db:",
    "    network_mode: host",
    "    ports:",
    '      - "127.0.0.1:5432:5432"',
    "database:",
    "  hostname: db7.example.com",
    "",
  ].join("\n");
  assert.deepEqual(hostsOf(text), [
    "db1.example.com", "db2.example.com", "db3.example.com",
    "db4.example.com",
    "db5.example.com",
    "db3.example.com", "db6.example.com", // the libpq pass also reads the URL's ?host=
    "127.0.0.1",
    "db7.example.com",
    "0.0.0.0",
  ]);
});

/* Smoke test for the inspector's in-memory secret detection. Every test uses a temporary config dir (through
 * CUSTOSA_CONFIG_DIR or the configDir option), never ~/.config/custosa. Fake secrets are generated at run time, so no
 * secret-shaped literal sits in the repository. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomInt } from "node:crypto";
import { chmodSync, mkdirSync, mkdtempSync, readdirSync, realpathSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";

const temp = (prefix) => realpathSync(mkdtempSync(join(tmpdir(), prefix)));
process.env.CUSTOSA_CONFIG_DIR = temp("custosa-secrets-default-");

const { scanSecrets, loadInstallKey, InstallKeyError, BadInputError } = await import("../lib/inspector/secrets.mjs");
const { isEnvFile: isEnvName } = await import("../lib/inspector/files.mjs");
const isEnvFile = (path) => isEnvName(basename(path)); // scanSecrets tests a file path's base name

const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const ALNUM = UPPER + "abcdefghijklmnopqrstuvwxyz0123456789";
const rand = (n, alphabet = UPPER) => Array.from({ length: n }, () => alphabet[randomInt(alphabet.length)]).join("");
// Uppercase-only random body: the serialized output is lowercase hex, rule ids and paths, so a 4-character overlap
// with the output could only come from a leak.
const fakeStripe = () => ["sk", "live", rand(32)].join("_");
const fakeAws = () => "AKIA" + rand(16);
const b64url = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const fakeJwt = (role) => [b64url({ alg: "HS256", typ: "JWT" }), b64url({ iss: "supabase", role, iat: 1700000000 }),
  rand(43, ALNUM)].join(".");

/* CPU time of fn in ms: wall-clock time on a loaded machine (other test files run in parallel) says little about
 * the scan itself. */
const cpuMs = (fn) => {
  const before = process.cpuUsage();
  fn();
  const used = process.cpuUsage(before);
  return (used.user + used.system) / 1000;
};

/* The secrets of a scan that must have covered every file in full. */
const scan = (...args) => {
  const result = scanSecrets(...args);
  assert.deepEqual(Object.keys(result).sort(), ["secrets", "truncated"]);
  assert.deepEqual(result.truncated, []);
  for (const secret of result.secrets) assert.match(secret.fingerprint, CONTRACT_HASH);
  return result.secrets;
};
// The contract's hash ($defs/hash): the full HMAC-SHA256 as lowercase hex.
const CONTRACT_HASH = /^[0-9a-f]{64}$/;

const SECRET_FIELDS = ["fingerprint", "in_history", "line", "path", "rule_id"];

function substrings(s, min = 4) {
  const out = new Set();
  for (let i = 0; i < s.length; i++) for (let j = i + min; j <= s.length; j++) out.add(s.slice(i, j));
  return out;
}

/* Run fn while capturing everything written to the console and stderr/stdout. */
function captureLogs(fn) {
  const logs = [];
  const saved = {};
  for (const k of ["log", "info", "warn", "error", "debug"]) {
    saved[k] = console[k];
    console[k] = (...args) => logs.push(args.map(String).join(" "));
  }
  const out = process.stdout.write, err = process.stderr.write;
  process.stdout.write = (chunk, ...rest) => { logs.push(String(chunk)); return true; };
  process.stderr.write = (chunk, ...rest) => { logs.push(String(chunk)); return true; };
  try {
    return { result: fn(), logs };
  } finally {
    Object.assign(console, saved);
    process.stdout.write = out;
    process.stderr.write = err;
  }
}

test("a committed .env with a fake key gives one finding, stable, with no part of the key in the output", () => {
  const configDir = temp("custosa-secrets-");
  const key = fakeStripe();
  const envFiles = [{ path: ".env", tracked: true, text: `# app\nPORT=3000\nSTRIPE_SECRET_KEY=${key}\n` }];

  // The whole return value (secrets and truncated) is what gets serialized.
  const full = (r) => ({ ...r, result: r.result.secrets, raw: r.result });
  const first = full(captureLogs(() => scanSecrets([], { envFiles, configDir })));
  const second = full(captureLogs(() => scanSecrets([], { envFiles, configDir })));

  assert.equal(first.result.length, 1);
  const [s] = first.result;
  assert.deepEqual(Object.keys(s).sort(), SECRET_FIELDS);
  assert.equal(s.rule_id, "stripe-secret-key");
  assert.equal(s.path, ".env");
  assert.equal(s.line, 3);
  assert.equal(s.in_history, false);
  assert.match(s.fingerprint, CONTRACT_HASH);
  assert.deepEqual(second.result, first.result, "fingerprint stable across runs with the same key");

  const serialized = JSON.stringify(first.raw) + JSON.stringify(second.raw) + first.logs.join("") +
    second.logs.join("");
  for (const sub of substrings(key)) assert.ok(!serialized.includes(sub), "output contains part of the key");

  // The install key was created 0600 with 32 bytes, and a different install gives a different fingerprint.
  assert.equal(statSync(join(configDir, "install.key")).mode & 0o777, 0o600);
  assert.equal(statSync(join(configDir, "install.key")).size, 32);
  const other = scan([], { envFiles, configDir: temp("custosa-secrets-other-") });
  assert.notEqual(other[0].fingerprint, s.fingerprint);
});

test("an untracked .env is not scanned, and a .env path in files is bad input, not scanned", () => {
  const configDir = temp("custosa-secrets-");
  const text = `STRIPE_SECRET_KEY=${fakeStripe()}\n`;
  assert.deepEqual(scan([], { envFiles: [{ path: ".env.local", tracked: false, text }], configDir }), []);
  assert.deepEqual(scanSecrets([{ path: "app/.env.production", text }], { configDir }),
    { secrets: [], truncated: [{ path: "app/.env.production", in_history: false, reason: "bad_input" }] });
  assert.ok(isEnvFile(".env") && isEnvFile("web/.env.local") && !isEnvFile("env.js") && !isEnvFile("src/x.env.ts"));
});

test("key names without values and example placeholders are not findings", () => {
  const configDir = temp("custosa-secrets-");
  const text = [
    "STRIPE_SECRET_KEY=",
    "AWS_ACCESS_KEY_ID=",
    "GITHUB_TOKEN=",
    "SUPABASE_SERVICE_ROLE_KEY=",
    "STRIPE_SECRET_KEY=sk\x5flive_xxx",
    "STRIPE_SECRET_KEY=sk\x5flive_xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "STRIPE_SECRET_KEY=sk\x5flive_YOUR_SECRET_KEY_GOES_HERE_PLEASE",
    "AWS_ACCESS_KEY_ID=AKIAEXAMPLE",
    "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
    "const SK_LIVE_PREFIX = 'sk\x5flive_';",
    "DATABASE_URL=postgres://user:password@localhost:5432/db",
    "DATABASE_URL=postgres://app:${PGPASSWORD}@db/app",
    "DATABASE_URL=postgresql://app:<password>@db/app",
    "\x2d----BEGIN RSA PRIVATE KEY-----",
    "...",
    "-----END RSA PRIVATE KEY-----",
    `SUPABASE_ANON_KEY=${fakeJwt("anon")}`,
  ].join("\n");
  const found = scan([{ path: "README.md", text }], { envFiles: [{ path: ".env.example", tracked: true, text }],
    configDir });
  assert.deepEqual(found, []);
});

test("each default pattern finds its secret; history blobs are marked in_history", () => {
  const configDir = temp("custosa-secrets-");
  const pemBody = Array.from({ length: 4 }, () => rand(64, ALNUM)).join("\n");
  const files = [
    { path: "src/aws.js", text: `const id = "${fakeAws()}";\n` },
    { path: "src/gh.js", text: `\n\ntoken = '${"ghp_" + rand(36, ALNUM)}'\n` },
    { path: "keys/id_rsa", text: `\x2d----BEGIN RSA PRIVATE KEY-----\n${pemBody}\n-----END RSA PRIVATE KEY-----\n` },
    { path: "src/supa.ts", text: `export const k = "${fakeJwt("service_role")}";` },
    { path: "docker-compose.yml", text: `x:\n  url: postgres://app:${rand(20, ALNUM)}@db:5432/app\n` },
  ];
  const historyBlobs = [{ path: ".env", text: `\nSTRIPE_SECRET_KEY=${fakeStripe()}\n`, commit: "a".repeat(40) }];
  const found = scan(files, { historyBlobs, configDir });
  const brief = found.map((s) => [s.rule_id, s.path, s.line, s.in_history]);
  assert.deepEqual(brief, [
    ["stripe-secret-key", ".env", 2, true],
    ["postgres-url-password", "docker-compose.yml", 2, false],
    ["pem-private-key", "keys/id_rsa", 1, false],
    ["aws-access-key-id", "src/aws.js", 1, false],
    ["github-token", "src/gh.js", 3, false],
    ["supabase-service-role-jwt", "src/supa.ts", 1, false],
  ]);
});

test("caller patterns are used; a throwing validate counts as a finding without the value", () => {
  const configDir = temp("custosa-secrets-");
  const value = "TOK-" + rand(20);
  const patterns = [
    { rule_id: "custom-token", regex: "TOK-[A-Z]{20}" },
    { rule_id: "custom-throws", regex: /TOK-[A-Z]{20}/, validate: (v) => { throw new Error(v); } },
  ];
  const { result, logs } = captureLogs(() => scan([{ path: "a.txt", text: value }], { patterns, configDir }));
  // The throwing validate fails closed: it counts as a finding, still without the value.
  assert.deepEqual(result.map((s) => s.rule_id), ["custom-throws", "custom-token"]);
  assert.equal(result[0].fingerprint, result[1].fingerprint);
  assert.ok(!(JSON.stringify(result) + logs.join("")).includes(value.slice(4, 8)));
});

test("a group-readable install.key is refused, and the message says so", () => {
  const configDir = temp("custosa-secrets-");
  const keyPath = join(configDir, "install.key");
  writeFileSync(keyPath, Buffer.alloc(32, 7), { mode: 0o600 });
  chmodSync(keyPath, 0o640);
  assert.throws(() => loadInstallKey({ configDir }), (err) => err instanceof InstallKeyError &&
    /group or world readable/.test(err.message));
  assert.throws(() => scan([], { configDir }), InstallKeyError);
  chmodSync(keyPath, 0o604);
  assert.throws(() => loadInstallKey({ configDir }), /group or world readable/);
  chmodSync(keyPath, 0o600);
  assert.deepEqual(loadInstallKey({ configDir }), Buffer.alloc(32, 7));
});

test("the default config dir follows CUSTOSA_CONFIG_DIR", () => {
  loadInstallKey();
  assert.equal(statSync(join(process.env.CUSTOSA_CONFIG_DIR, "install.key")).size, 32);
});

const rules = (found) => found.map((s) => [s.rule_id, s.path, s.line]);
const hex = (n) => rand(n, "0123456789abcdef");
const pemOf = (lines, nl = "\n", indent = "") => [`\x2d----BEGIN PRIVATE KEY-----`, ...lines,
  `-----END PRIVATE KEY-----`].map((l, i) => (i ? indent : "") + l).join(nl);

test("(a, b) a PEM key with escaped \\n, on one line, or indented in YAML is found, with one fingerprint", () => {
  const configDir = temp("custosa-secrets-");
  const body = Array.from({ length: 5 }, () => rand(64, ALNUM));
  const files = [
    { path: "id.pem", text: pemOf(body) + "\n" },
    { path: "service-account.json", text: JSON.stringify({ type: "service_account", private_key: pemOf(body) }, null, 2) },
    { path: "deploy/app.env.sh", text: `export PRIVATE_KEY="${pemOf(body, "\\n")}"\n` },
    { path: "charts/values.yaml", text: `tls:\n  key: |\n    ${pemOf(body, "\n", "    ")}\n` },
    { path: "oneline.txt", text: `KEY=${pemOf(body, " ")}\n` },
    { path: "rsa.key", text: ["\x2d----BEGIN RSA PRIVATE KEY-----", "Proc-Type: 4,ENCRYPTED",
      `DEK-Info: AES-128-CBC,${hex(32).toUpperCase()}`, "", ...body, "-----END RSA PRIVATE KEY-----"].join("\n") },
  ];
  const found = scan(files, { configDir });
  assert.deepEqual(rules(found), [["charts/values.yaml", 3], ["deploy/app.env.sh", 1], ["id.pem", 1],
    ["oneline.txt", 1], ["rsa.key", 1], ["service-account.json", 3]].map(([p, l]) => ["pem-private-key", p, l]));
  assert.equal(new Set(found.map((s) => s.fingerprint)).size, 1, "same key body, same fingerprint");

  const serialized = JSON.stringify(found);
  for (const line of body) for (const sub of substrings(line.slice(0, 12))) assert.ok(!serialized.includes(sub));
});

test("adversarial input (PEM headers with long whitespace, many string literals) is scanned quickly", () => {
  const configDir = temp("custosa-secrets-");
  const H = "\x2d----BEGIN PRIVATE KEY-----";
  const text = H + " ".repeat(200000) + "\n" +
    (H + ("\nProc-Type: " + " ".repeat(150)).repeat(4) + "\n").repeat(500) + (H + "\n \n \n".repeat(1000));
  // The joined view on many small literals: one huge array, and many two-literal groups.
  const arr = JSON.stringify(Array.from({ length: 40000 }, () => rand(8, ALNUM)));
  const pairs = '"name": "x", '.repeat(40000);
  let found;
  const ms = cpuMs(() => {
    found = scan([{ path: "big.txt", text }, { path: "arr.json", text: arr }, { path: "pairs.json", text: pairs }],
      { configDir });
  });
  assert.deepEqual(found, []);
  assert.ok(ms < 2000, `took ${ms} ms of CPU`);
});

test("(c, d) postgres passwords: $, %, / and \" values and human-chosen words are found; only true references are not", () => {
  const configDir = temp("custosa-secrets-");
  const found = [
    "postgres://app:$ecretPw9@h", "postgresql://app:%23Secr3tPw@h:5432/db", "postgres://app:Ab/cd9xyz@h",
    'postgres://app:Ab"cd9q@h', "postgres://app:dummyPass77Q@h", "postgres://app:myexamplePw1@h",
    "postgres://app:redacted99@h", "postgres://app:changeme2024@h", "postgres://app:xxxxpw12@h",
    "postgres://app:aaaaaaaa1@h", "postgres://postgres:postgres@db:5432/app", "postgres://app:*Star9@h",
  ];
  const notFound = [
    "postgres://app:${DB_PASSWORD}@h", "postgres://app:$DB_PASSWORD@h", "postgres://app:<password>@h",
    "postgres://app:{{pw}}@h", "postgres://app:%s@h", "postgres://app:%(pw)s@h", "postgres://app:$(cat pw)@h",
    "postgres://app:$PGPASS_1@h",
    "postgres://app:password@h", "postgres://app:Password@h", "postgres://app:pass@h", "postgres://app:secret@h",
    "postgres://app:changeme@h", "postgres://app:example@h", "postgres://app:****@h",
    "postgres://postgres:postgres@localhost/db",
  ];
  const text = [...found, ...notFound].join("\n");
  const result = scan([{ path: "db.txt", text }], { configDir });
  assert.deepEqual(result.map((s) => s.line), found.map((_, i) => i + 1));
  assert.ok(result.every((s) => s.rule_id === "postgres-url-password"));
});

test("(d) provider tokens drop only clear placeholders", () => {
  const configDir = temp("custosa-secrets-");
  const real = ["sk", "live", "AAAAAAAA" + rand(24)].join("_"); // a run of one letter is not a placeholder
  const text = [real, "sk\x5flive_" + "x".repeat(30), "ghp_" + "X".repeat(36), "AKIA" + "X".repeat(16),
    "AKIAIOSFODNN7EXAMPLE", "sk-proj-YOUR_KEY_" + "x".repeat(40)].join("\n");
  assert.deepEqual(rules(scan([{ path: "t.txt", text }], { configDir })), [["stripe-secret-key", "t.txt", 1]]);
});

test("(e) each added provider pattern finds its secret and ignores key names and docs keys", () => {
  const configDir = temp("custosa-secrets-");
  const positives = [
    ["supabase-secret-key", `SUPABASE_SECRET_KEY=sb\x5fsecret_${rand(32, ALNUM)}`],
    ["aws-secret-access-key", `AWS_SECRET_ACCESS_KEY=${rand(40, ALNUM)}`],
    ["aws-secret-access-key", `aws_secret_access_key = ${rand(38, ALNUM)}/+`],
    ["aws-secret-access-key", `  "SecretAccessKey": "${rand(40, ALNUM)}",`],
    ["openai-api-key", `OPENAI_API_KEY=sk-proj-${rand(64, ALNUM)}`],
    ["openai-api-key", `openai.api_key = "sk-${rand(48, ALNUM)}"`],
    ["anthropic-api-key", `ANTHROPIC_API_KEY=sk-ant-api03-${rand(80, ALNUM)}`],
    ["slack-token", `SLACK_BOT_TOKEN=xoxb-${rand(12, "0123456789")}-${rand(13, "0123456789")}-${rand(24, ALNUM)}`],
    ["google-api-key", `const key = "AIza${rand(35, ALNUM)}";`],
    ["twilio-api-key", `TWILIO_API_KEY=SK${hex(32)}`],
    ["sendgrid-api-key", `SENDGRID_API_KEY=SG.${rand(22, ALNUM)}.${rand(43, ALNUM)}`],
    ["supabase-jwt-secret", `SUPABASE_JWT_SECRET=${rand(40, ALNUM)}`],
    ["aws-access-key-id", `keyid${fakeAws()}`], // glued to lowercase letters
  ];
  const negatives = [
    "SUPABASE_SECRET_KEY=", "AWS_SECRET_ACCESS_KEY=", "OPENAI_API_KEY=", "ANTHROPIC_API_KEY=", "SLACK_BOT_TOKEN=",
    "GOOGLE_API_KEY=", "TWILIO_API_KEY=", "SENDGRID_API_KEY=", "SUPABASE_JWT_SECRET=",
    "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "SUPABASE_JWT_SECRET=${JWT_SECRET}",
    "SUPABASE_JWT_SECRET=your-super-secret-jwt-token-with-at-least-32-characters-long",
    `SECRET=${rand(40, ALNUM)}`, // 40 characters without the AWS context
    "SLACK_BOT_TOKEN=xoxb-your-token", "sb\x5fsecret_" + "x".repeat(30), `X${fakeAws()}`,
  ];
  const text = [...positives.map(([, l]) => l), ...negatives].join("\n");
  const found = scan([{ path: "cfg.txt", text }], { configDir });
  assert.deepEqual(found.map((s) => [s.line, s.rule_id]), positives.map(([r], i) => [i + 1, r]));
  // SK + 32 hex in a file that never names Twilio is not a finding.
  assert.deepEqual(scan([{ path: "ids.py", text: `api_key_sid = "SK${hex(32)}"\n` }], { configDir }), []);
});

test("(f) UTF-16 LE, UTF-16 BE and UTF-8 files with a byte-order mark are decoded", () => {
  const configDir = temp("custosa-secrets-");
  const text = `# config\nSTRIPE_SECRET_KEY=${fakeStripe()}\n`;
  const le = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(text, "utf16le")]);
  const be = Buffer.concat([Buffer.from([0xfe, 0xff]), Buffer.from(text, "utf16le").swap16()]);
  const u8 = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(text, "utf8")]);
  const found = scan([{ path: "le.txt", text: le }, { path: "be.txt", text: be }, { path: "u8.txt", text: u8 },
    { path: "plain.txt", text: new Uint8Array(Buffer.from(text)) }], { configDir });
  assert.deepEqual(rules(found), ["be.txt", "le.txt", "plain.txt", "u8.txt"].map((p) => ["stripe-secret-key", p, 2]));
  assert.equal(new Set(found.map((s) => s.fingerprint)).size, 1);
});

test("install key: unwritable home, open config dir, partial write and no hard links", (t) => {
  // An EACCES while creating the config dir is an InstallKeyError, not a raw Error.
  if (process.getuid?.() !== 0) {
    const home = temp("custosa-secrets-ro-");
    chmodSync(home, 0o500);
    t.after(() => chmodSync(home, 0o700));
    assert.throws(() => scan([], { configDir: join(home, ".config", "custosa") }),
      (err) => err instanceof InstallKeyError && /EACCES/.test(err.message));
  }

  // A group- or world-writable config dir is refused.
  const open = temp("custosa-secrets-open-");
  chmodSync(open, 0o770);
  assert.throws(() => loadInstallKey({ configDir: open }), (err) => err instanceof InstallKeyError &&
    /group or world writable/.test(err.message));
  chmodSync(open, 0o702);
  assert.throws(() => loadInstallKey({ configDir: open }), /group or world writable/);

  // A write that fails partway leaves no temporary file behind.
  const partial = temp("custosa-secrets-partial-");
  const eio = () => Object.assign(new Error("write failed"), { code: "EIO" });
  assert.throws(() => loadInstallKey({ configDir: partial, fsOverrides: { writeSync: () => { throw eio(); } } }),
    (err) => err instanceof InstallKeyError && /EIO/.test(err.message));
  assert.deepEqual(readdirSync(partial), []);

  // Without hard links (EPERM), the key is written with O_EXCL to its final name.
  const nolink = temp("custosa-secrets-nolink-");
  const eperm = () => Object.assign(new Error("no links"), { code: "EPERM" });
  const key = loadInstallKey({ configDir: nolink, fsOverrides: { linkSync: () => { throw eperm(); } } });
  assert.equal(key.length, 32);
  assert.deepEqual(readdirSync(nolink), ["install.key"]);
  assert.equal(statSync(join(nolink, "install.key")).mode & 0o777, 0o600);
  assert.deepEqual(loadInstallKey({ configDir: nolink }), key);

  // A new config dir is created 0700.
  const fresh = join(temp("custosa-secrets-fresh-"), "a", "custosa");
  loadInstallKey({ configDir: fresh });
  assert.equal(statSync(fresh).mode & 0o777, 0o700);
});

/* Round 3: more real leak shapes. Each case is one line, so the expected line numbers follow the list. */
const expectLines = (found, cases) =>
  assert.deepEqual(found.map((s) => [s.line, s.rule_id]), cases.map(([r], i) => [i + 1, r]));
const pw = () => rand(6, ALNUM) + "9aQ" + rand(6, ALNUM);

test("(1) postgres: +driver, JDBC and query passwords, libpq keywords, a quote in the password, upper-case scheme", () => {
  const configDir = temp("custosa-secrets-");
  const found = [
    ["postgres-url-password", `DATABASE_URL=postgresql+psycopg2://u:${pw()}@db.example.net/app`],
    ["postgres-url-password", `url = "postgresql+asyncpg://u:${pw()}@db.internal:5432/app"`],
    ["postgres-url-password", `jdbc.url=jdbc:postgresql://h:5432/app?user=app&password=${pw()}`],
    ["postgres-url-password", `jdbc:postgresql://h:5432/app?password=${pw()}&user=u`],
    ["postgres-url-password", `postgres://u@h/db?password=${pw()}`],
    ["postgres-keyword-password", `conn = psycopg2.connect("host=h user=u password=${pw()} dbname=d")`],
    ["postgres-keyword-password", `dsn: password=${pw()} host=db.internal dbname=app`],
    ["postgres-url-password", `postgres://u:Ab'${pw()}@h/db`],
    ["postgres-url-password", `POSTGRES://u:${pw()}@h/db`],
  ];
  const result = scan([{ path: "db.txt", text: found.map(([, l]) => l).join("\n") }], { configDir });
  expectLines(result, found);
});

test("(2) mysql, mariadb, mongodb, mongodb+srv, redis, rediss and amqp URLs with passwords", () => {
  const configDir = temp("custosa-secrets-");
  const found = [
    ["mysql-url-password", `mysql://app:${pw()}@db:3306/app`],
    ["mysql-url-password", `mysql+pymysql://app:${pw()}@db/app`],
    ["mysql-url-password", `mariadb://app:${pw()}@db/app`],
    ["mysql-url-password", `jdbc:mysql://db:3306/app?user=app&password=${pw()}`],
    ["mongodb-url-password", `MONGO_URL=mongodb://app:${pw()}@mongo:27017/app`],
    ["mongodb-url-password", `mongodb+srv://app:${pw()}@cluster0.abcde.mongodb.net/app`],
    ["redis-url-password", `redis://:${pw()}@cache:6379/0`],
    ["redis-url-password", `rediss://default:${pw()}@cache.upstash.io:6379`],
    ["amqp-url-password", `amqp://app:${pw()}@rabbit:5672/vhost`],
  ];
  const notFound = [
    "mysql://app:${MYSQL_PASSWORD}@db/app", "mongodb://app:<password>@mongo/app",
    "mongodb+srv://app:[YOUR-PASSWORD]@cluster0.mongodb.net", "redis://:password@cache:6379",
    "amqp://guest:guest@localhost:5672", "mysql://root:root@127.0.0.1:3306/app", "redis://localhost:6379",
  ];
  const text = [...found.map(([, l]) => l), ...notFound].join("\n");
  expectLines(scan([{ path: "urls.txt", text }], { configDir }), found);
});

test("(3) AWS secret: YAML blocks, prefixed and suffixed names, Terraform, ECS and Kubernetes name/value pairs", () => {
  const configDir = temp("custosa-secrets-");
  const v = () => rand(38, ALNUM) + "/+";
  const files = [
    { path: "a.yml", text: `env:\n  AWS_SECRET_ACCESS_KEY: >-\n    ${v()}\n  OTHER: |\n    x\n` },
    { path: "b.yml", text: `AWS_SECRET_ACCESS_KEY: |\n  ${v()}\n` },
    { path: "c.cfg", text: [`PROD_AWS_SECRET_ACCESS_KEY=${v()}`, `NEXT_AWS_SECRET_ACCESS_KEY=${v()}`,
      `AWS_SECRET_ACCESS_KEY_PROD=${v()}`, `aws-secret-access-key: ${v()}`].join("\n") },
    { path: "main.tf", text: `provider "aws" {\n  region     = "us-east-1"\n  secret_key = "${v()}"\n}\n` },
    { path: "creds.tf", text: `locals {\n  access_key = "${fakeAws()}"\n  secret_key = "${v()}"\n}\n` },
    { path: "rev.tf", text: `locals {\n  secret_key = "${v()}"\n  access_key = var.key\n}\n` },
    { path: "task.json", text: JSON.stringify({ environment: [{ name: "AWS_SECRET_ACCESS_KEY", value: v() }] }, null, 2) },
    { path: "task-inline.json", text: `{"environment":[{"name":"AWS_SECRET_ACCESS_KEY","value":"${v()}"}]}` },
    { path: "deploy.yaml", text: `env:\n  - name: AWS_SECRET_ACCESS_KEY\n    value: "${v()}"\n` },
    // Quiet: a Terraform secret_key outside an aws provider with no access_key nearby, and a 40-character value with
    // no AWS context.
    { path: "other.tf", text: `resource "x" "y" {\n  secret_key = "${v()}"\n}\n` },
    { path: "plain.yaml", text: `env:\n  - name: OTHER\n    value: "${v()}"\n` },
  ];
  const found = scan(files, { configDir }).filter((s) => s.rule_id === "aws-secret-access-key");
  assert.deepEqual(found.map((s) => [s.path, s.line]), [
    ["a.yml", 3], ["b.yml", 2], ["c.cfg", 1], ["c.cfg", 2], ["c.cfg", 3], ["c.cfg", 4], ["creds.tf", 3],
    ["deploy.yaml", 3], ["main.tf", 3], ["rev.tf", 2], ["task-inline.json", 1], ["task.json", 5],
  ]);
});

test("(4) PEM split across a JSON array, Python implicit concatenation, JS + concatenation, or with \\\\n", () => {
  const configDir = temp("custosa-secrets-");
  const body = Array.from({ length: 4 }, () => rand(64, ALNUM));
  const lines = ["\x2d----BEGIN PRIVATE KEY-----", ...body, "-----END PRIVATE KEY-----"];
  const files = [
    { path: "pretty.json", text: JSON.stringify({ key: lines }, null, 2) },
    { path: "inline.json", text: JSON.stringify({ key: lines }) },
    { path: "conf.py", text: `KEY = (\n${lines.map((l) => `    "${l}\\n"`).join("\n")}\n)\n` },
    { path: "conf.js", text: `const key =\n${lines.map((l) => `  '${l}\\n'`).join(" +\n")};\n` },
    { path: "double.cfg", text: `PRIVATE_KEY="${lines.join("\\\\n")}"\n` },
  ];
  const found = scan(files, { configDir });
  assert.deepEqual(rules(found), [["conf.js", 2], ["conf.py", 2], ["double.cfg", 1], ["inline.json", 1],
    ["pretty.json", 3]].map(([p, l]) => ["pem-private-key", p, l]));
  assert.equal(new Set(found.map((s) => s.fingerprint)).size, 1);
  const serialized = JSON.stringify(found);
  for (const line of body) for (const sub of substrings(line.slice(0, 12))) assert.ok(!serialized.includes(sub));
});

test("(5) Twilio auth token and file-level SK, Slack webhooks, xapp and xoxe tokens, generic app secrets", () => {
  const configDir = temp("custosa-secrets-");
  const found = [
    ["twilio-auth-token", `TWILIO_AUTH_TOKEN=${hex(32)}`],
    ["twilio-auth-token", `  authToken: "${hex(32)}",`],
    ["twilio-api-key", `const sid = "SK${hex(32)}";`],
    ["slack-webhook-url", `SLACK_WEBHOOK=https://hooks.slack.com/services/T${rand(10)}/B${rand(10)}/${rand(24, ALNUM)}`],
    ["slack-token", `SLACK_APP_TOKEN=xapp-1-A${rand(10)}-${rand(13, "0123456789")}-${hex(64)}`],
    ["slack-token", `refresh = "xoxe.xoxp-1-${rand(40, ALNUM)}"`],
    ["slack-token", `rotate = "xoxe-1-${rand(40, ALNUM)}"`],
    ["generic-app-secret", `JWT_SECRET=${hex(64)}`],
    ["generic-app-secret", `DJANGO_SECRET_KEY='${rand(40, ALNUM)}'`],
    ["generic-app-secret", `SESSION_SECRET: "${rand(32, ALNUM)}"`],
  ];
  const notFound = [
    "JWT_SECRET=my-super-secret-session-value-here", // one character class
    "SECRET_KEY=${SECRET_KEY}", "SECRET_KEY=process.env.APPLICATION_SECRET_KEY_VALUE",
    "SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY_FROM_ENV')", "SESSION_SECRET=Short1",
    "JWT_SECRET=your_jwt_secret_goes_here_123ABC",
    `SLACK_WEBHOOK=https://hooks.slack.com/services/TXXXXXXXX/BXXXXXXXX/${"X".repeat(24)}`,
  ];
  const text = ["// uses twilio", ...found.map(([, l]) => l), ...notFound].join("\n");
  const result = scan([{ path: "app.js", text }], { configDir });
  assert.deepEqual(result.map((s) => [s.line, s.rule_id]), found.map(([r], i) => [i + 2, r]));
  // authToken without Twilio anywhere in the file is not a finding; STRIPE_SECRET_KEY gives only the Stripe rule.
  assert.deepEqual(scan([{ path: "x.js", text: `authToken: "${hex(32)}"\n` }], { configDir }), []);
  assert.deepEqual(scan([{ path: "s.cfg", text: `STRIPE_SECRET_KEY=${fakeStripe()}\n` }], { configDir })
    .map((s) => s.rule_id), ["stripe-secret-key"]);
});

test("(5b) a Twilio auth token passed by position after a literal account SID", () => {
  const configDir = temp("custosa-secrets-");
  const sid = `AC${hex(32)}`;
  const found = [
    `const client = twilio("${sid}", "${hex(32)}");`, // the salus form
    `const client = new Twilio('${sid}', '${hex(32)}');`,
    `client = Client("${sid}",\n    "${hex(32)}")`,
    `Twilio.init(\`${sid}\`, \`${hex(32)}\`);`,
  ];
  const notFound = [
    "const client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);",
    `const client = twilio("${sid}", process.env.TWILIO_AUTH_TOKEN);`,
    `client = Client(os.environ["TWILIO_ACCOUNT_SID"], os.environ["TWILIO_AUTH_TOKEN"])`,
    `twilio("AC${"0".repeat(32)}", "${"0".repeat(32)}");`,
    `twilio("${sid}", "${"ab".repeat(16)}");`,
    `twilio("ACXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", "your_auth_token");`,
    `twilio("${sid}", "${hex(33)}");`, // not a token's length
  ];
  for (const line of found) {
    const result = scan([{ path: "sms.ts", text: `import twilio from "twilio";\n${line}\n` }], { configDir });
    assert.deepEqual(result.map((s) => s.rule_id), ["twilio-auth-token"], line);
    assert.equal(result[0].line, line.includes("\n") ? 3 : 2, line);
  }
  for (const line of notFound) {
    assert.deepEqual(scan([{ path: "sms.ts", text: `import twilio from "twilio";\n${line}\n` }], { configDir }), [], line);
  }
  // The same call in a file that never names Twilio is not a finding.
  assert.deepEqual(scan([{ path: "x.ts", text: `const c = sms("${sid}", "${hex(32)}");\n` }], { configDir }), []);
});

test("(6, 7) templates and loopback local defaults are quiet; compose services and the Supabase default are not", () => {
  const configDir = temp("custosa-secrets-");
  const found = [
    ["postgres-url-password", "postgres://postgres:postgres@db:5432/app"], // compose service name: not loopback
    ["mysql-url-password", "mysql://root:root@mysql/app"],
    ["postgres-url-password", `postgres://postgres:${pw()}@localhost/app`], // loopback, but not a default
    ["supabase-jwt-secret", "SUPABASE_JWT_SECRET=super-secret-jwt-token-with-at-least-32-characters-long"],
  ];
  const notFound = [
    "postgresql://postgres:[YOUR-PASSWORD]@db.abcdefghijklmnop.supabase.co:5432/postgres",
    "DATABASE_URL: postgres://app:${{ secrets.DB_PASSWORD }}@db/app",
    "DATABASE_URL: postgres://app:${{secrets.DB_PASSWORD}}@db/app",
    'url = f"postgresql://app:{password}@db/app"', 'url = "postgresql://app:{db_password}@{host}/app".format(**c)',
    "postgres://app:your-password@db/app", "postgres://app:YOUR_PASSWORD@db/app", "postgres://app:your_password@db/app",
    "postgres://postgres:postgres@localhost:5432/app", "postgres://postgres:password@127.0.0.1/app",
    "postgresql://admin:admin@[::1]:5432/app", "postgres://postgres:example@host.docker.internal/app",
    "mysql://root:mysql@localhost/app", "host=localhost user=postgres password=postgres dbname=app",
    "password=postgres dbname=app",
  ];
  const text = [...found.map(([, l]) => l), ...notFound].join("\n");
  expectLines(scan([{ path: "cfg.txt", text }], { configDir }), found);
});

test("(6b) the Supabase CLI's demo service-role key (iss supabase-demo) is not a finding", () => {
  const configDir = temp("custosa-secrets-");
  // The signature holds a "-", as the CLI's demo key's does, so the value is never read as a dotted code name and
  // the service-role-config fallback sees it too.
  const sig = () => `${rand(20, ALNUM)}-${rand(22, ALNUM)}`;
  const jwt = (payload) => [b64url({ alg: "HS256", typ: "JWT" }), b64url(payload), sig()].join(".");
  const demo = jwt({ iss: "supabase-demo", role: "service_role", exp: 1983812996 });
  const real = jwt({ iss: "supabase", ref: rand(20).toLowerCase(), role: "service_role", iat: 1700000000, exp: 2015000000 });
  const rows = (path, text) => (isEnvFile(path) ? scan([], { configDir, envFiles: [{ path, tracked: true, text }] })
    : scan([{ path, text }], { configDir })).map((s) => `${s.rule_id}:${s.line}`);
  const forms = (k) => [
    ["src/supa.ts", `export const k = "${k}";\n`],
    [".env", `SUPABASE_URL=http://127.0.0.1:54321\nSUPABASE_SERVICE_ROLE_KEY=${k}\n`],
    ["src/admin.ts", `const serviceRoleKey = "${k}";\n`],
    ["src/client.ts", `const h = \`Bearer ${k}\`;\n`],
    ["src/client.ts", `fetch(\`\${url}/rest/v1\`, { headers: { apikey: \`${k}\` } });\n`],
  ];
  for (const [path, text] of forms(demo)) assert.deepEqual(rows(path, text), [], `demo in ${path}`);
  for (const [path, text] of forms(real)) {
    assert.deepEqual(rows(path, text), [`supabase-service-role-jwt:${path === ".env" ? 2 : 1}`], `real in ${path}`);
  }
  // Only the exact issuer is the demo key; a payload that only resembles it is still a finding.
  for (const payload of [{ iss: "supabase-demo-2", role: "service_role" }, { iss: "Supabase-Demo", role: "service_role" },
    { iss: ["supabase-demo"], role: "service_role" }, { role: "service_role" }, { iss: "supabase", role: "service_role",
      note: "supabase-demo" }]) {
    assert.deepEqual(rows("a.ts", `const k = "${jwt(payload)}";\n`), ["supabase-service-role-jwt:1"], JSON.stringify(payload));
  }
  // Anon keys, demo or real, stay quiet, also under a service-role name.
  for (const iss of ["supabase-demo", "supabase"]) {
    const anon = jwt({ iss, role: "anon", exp: 1983812996 });
    assert.deepEqual(rows("a.ts", `const k = "${anon}";\nconst serviceRoleKey = "${anon}";\n`), [], iss);
  }
  // A malformed payload is not a JWT finding; under a service-role name the fallback still reports the location.
  const broken = [b64url({ alg: "HS256" }), Buffer.from('{"iss":"supabase-demo","role":"service_role"').toString("base64url"),
    sig()].join(".");
  assert.deepEqual(rows("a.ts", `const k = "${broken}";\n`), []);
  assert.deepEqual(rows(".env", `SUPABASE_SERVICE_ROLE_KEY=${broken}\n`), ["supabase-service-role-config:1"]);
  // A key split across a template string's lines is not seen, demo or real (as before this change).
  for (const k of [demo, real]) {
    const [h, p, s] = k.split(".");
    assert.deepEqual(rows("a.ts", `const k = \`${h}.\n${p}.\n${s}\`;\n`), []);
    assert.deepEqual(rows("a.ts", `const k = \`${h}.\${p}.${s}\`;\n`.replace("${p}", `\${"${p}"}`)), []);
  }
});

/* Round 4. */
test("(A) each adversarial 1 MB input scans in under 2 s of CPU", () => {
  const configDir = temp("custosa-secrets-");
  const MB = 1024 * 1024;
  const fill = (unit) => unit.repeat(Math.ceil(MB / unit.length));
  const utf16 = (s) => Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(s, "utf16le")]);
  const inputs = {
    "escaped double quotes": fill('\\"'),
    "escaped single quotes": fill("\\'"),
    "escaped double quotes, UTF-16": utf16(fill('\\"')),
    "name: AWS_SECRET_ACCESS_KEY + spaces": "name: AWS_SECRET_ACCESS_KEY" + " ".repeat(MB),
    "JSON name + spaces": '{"name": "AWS_SECRET_ACCESS_KEY", ' + " ".repeat(MB),
    "postgres URLs on one line": fill("postgres://u:pw1@h "),
    "eyJ segments": fill("eyJ" + rand(20, ALNUM) + "."),
    "postgres:// repeated": fill("postgres://"),
    "provider aws repeated": fill('provider "aws" {'),
    // Also: one secret on every line (many distinct findings), local defaults (every one validated), Terraform
    // pairs, and many tiny joined groups.
    "a URL on every line": fill("postgres://u:pw1@h\n"),
    "local default URLs": fill("postgres://postgres:postgres@localhost "),
    "Terraform pairs": fill(`access_key = 1\nsecret_key = "${rand(40, ALNUM)}"\n`),
    "name/value pairs": fill('"name": "x", '),
  };
  for (const [name, text] of Object.entries(inputs)) {
    const ms = cpuMs(() => scanSecrets([{ path: "big.txt", text }], { configDir }));
    assert.ok(ms < 2000, `${name} took ${ms} ms of CPU`);
  }
});

test("(B) a local default counts as local only when every host is loopback", () => {
  const configDir = temp("custosa-secrets-");
  const found = [
    ["postgres-url-password", "postgres://postgres:postgres@[::1]:5432,prod.example.com:5432/app"],
    ["postgres-url-password", "postgres://postgres:postgres@localhost,prod.example.com/app"],
    ["postgres-url-password", "postgres://postgres:postgres@localhost/app?host=prod.example.com"],
    ["postgres-url-password", "postgres://postgres:postgres@localhost/app?sslmode=require&hostaddr=10.0.0.5"],
    ["postgres-url-password", "postgres://postgres:postgres@localhost@prod.example.com/app"],
    ["postgres-url-password", "jdbc:postgresql://localhost:5432/app?password=postgres&host=prod.example.com"],
    ["postgres-url-password", "jdbc:postgresql://localhost,db.prod.net:5432/app?user=u&password=postgres"],
    ["postgres-keyword-password", "host=localhost,prod.example.com user=u password=postgres dbname=d"],
    ["mysql-url-password", "mysql://root:root@127.0.0.1,10.1.2.3/app"],
  ];
  const notFound = [
    "postgres://postgres:postgres@localhost,127.0.0.1:5433/app",
    "postgres://postgres:postgres@localhost/app?host=/var/run/postgresql",
    "postgres://postgres:postgres@/app?host=%2Fvar%2Frun%2Fpostgresql",
    "jdbc:postgresql://localhost:5432/app?user=postgres&password=postgres",
    "host=localhost hostaddr=127.0.0.1 user=u password=postgres dbname=d",
  ];
  const text = [...found.map(([, l]) => l), ...notFound].join("\n");
  expectLines(scan([{ path: "hosts.txt", text }], { configDir }), found);
});

test("(C) password settings, Stripe webhook secrets, Rails and Django keys, any-case generic names", () => {
  const configDir = temp("custosa-secrets-");
  const DJANGO = "abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*(-_=+)";
  const django = () => "q7" + rand(48, DJANGO);
  const found = [
    ["database-password-config", `    POSTGRES_PASSWORD: ${pw()}`],
    ["database-password-config", `MYSQL_ROOT_PASSWORD=${pw()}`],
    ["database-password-config", `  - MYSQL_PASSWORD=${pw()}`],
    ["database-password-config", `APP_DB_PASSWORD="${pw()}"`],
    ["database-password-config", `DATABASE_PASSWORD=${pw()}`],
    ["database-password-config", `spring.datasource.password=${pw()}`],
    ["aws-secret-access-key", `cloud.aws.credentials.secret-key=${rand(40, ALNUM)}`],
    ["stripe-webhook-secret", `STRIPE_WEBHOOK_SECRET=whsec_${rand(32, ALNUM)}`],
    ["rails-secret-key-base", `  secret_key_base: ${hex(128)}`],
    ["django-secret-key", `SECRET_KEY = 'django-insecure-${django()}'`],
    ["django-secret-key", `SECRET_KEY = "${django()}"`],
    ["django-secret-key", `DJANGO_SECRET_KEY=${django()}`],
    ["generic-app-secret", `  jwtSecret: "${rand(32, ALNUM)}",`],
    ["generic-app-secret", `jwt_secret = "${rand(32, ALNUM)}"`],
    ["generic-app-secret", `config.secretKey = '${rand(32, ALNUM)}';`],
  ];
  const notFound = [
    "POSTGRES_PASSWORD: postgres", "MYSQL_ROOT_PASSWORD=root", "DB_PASSWORD=", "DB_NAME=app_production_database",
    "DB_PASSWORD=${DB_PASSWORD}", "spring.datasource.password=${SPRING_DB_PASSWORD}",
    "DB_PASSWORD: process.env.DB_PASSWORD", "POSTGRES_PASSWORD_FILE=/run/secrets/db", "MYSQL_PASSWORD=changeme",
    "DATABASE_PASSWORD=your_password", `secret_key_base: <%= ENV["SECRET_KEY_BASE"] %>`,
    `SECRET_KEY = "django-insecure-${"x".repeat(50)}"`, "STRIPE_WEBHOOK_SECRET=whsec_xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "jwtSecret: process.env.JWT_SECRET_VALUE_FROM_ENV",
  ];
  const text = [...found.map(([, l]) => l), ...notFound].join("\n");
  expectLines(scan([{ path: "settings.txt", text }], { configDir }), found);
});

test("(A) windowed scan: a secret across a window boundary on a long line is found once, with the same fingerprint", () => {
  const configDir = temp("custosa-secrets-");
  const key = fakeStripe();
  const ref = scan([{ path: "a", text: key }], { configDir })[0].fingerprint;
  const body = Array.from({ length: 50 }, () => rand(64, ALNUM));
  const pem = pemOf(body);
  const pemRef = scan([{ path: "p", text: pem }], { configDir })[0].fingerprint;
  for (const at of [12 * 1024 - 10, 12 * 1024 - 256, 24 * 1024 - 5, 36 * 1024 + 3, 100000]) {
    const text = "a ".repeat(at / 2 | 0) + key + " " + "b ".repeat(30000);
    const found = scan([{ path: "long.txt", text }], { configDir });
    assert.deepEqual(found.map((s) => [s.rule_id, s.line, s.fingerprint]), [["stripe-secret-key", 1, ref]], `at ${at}`);
    const withPem = "a\n".repeat(at / 2 | 0) + pem + "\n" + "b\n".repeat(5000);
    const pf = scan([{ path: "k.txt", text: withPem }], { configDir });
    assert.deepEqual(pf.map((s) => [s.rule_id, s.line, s.fingerprint]), [["pem-private-key", (at / 2 | 0) + 1, pemRef]],
      `PEM at ${at}`);
  }
});

/* Review round 2. */
const fpOf = (configDir, text) => scan([{ path: "ref.txt", text }], { configDir })[0].fingerprint;

test("a generic secret is kept when a specific rule hits a different secret on the same line", () => {
  const configDir = temp("custosa-secrets-");
  const jwt = rand(32, ALNUM);
  const text = `{"aws_access_key_id":"${fakeAws()}","jwt_secret":"${jwt}"}`;
  const found = scan([{ path: "creds.json", text }], { configDir });
  assert.deepEqual(found.map((s) => s.rule_id), ["aws-access-key-id", "generic-app-secret"]);
  assert.equal(found[1].fingerprint, fpOf(configDir, `JWT_SECRET=${jwt}`));
  // The same secret, or an overlapping match, still gives only the specific rule.
  assert.deepEqual(scan([{ path: "s.cfg", text: `STRIPE_SECRET_KEY=${fakeStripe()}` }], { configDir })
    .map((s) => s.rule_id), ["stripe-secret-key"]);
});

test("a match in a window's look-back never hides one starting in the window (offset sweep)", () => {
  const configDir = temp("custosa-secrets-");
  const jwt = fakeJwt("service_role");
  const jwtRef = fpOf(configDir, jwt);
  const secret = rand(32, ALNUM);
  const secretRef = fpOf(configDir, `jwt_secret=${secret}`);
  const offsets = [];
  for (let n = 12288 - 300; n <= 12288 + 40; n += 9) offsets.push(n);
  offsets.push(12031, 12032, 12287, 12288, 24576 - 257, 24576 - 256);
  for (const n of offsets) {
    const a = "z".repeat(n) + "Q" + "eyJ" + rand(300, ALNUM) + "." + jwt + " " + "p ".repeat(20000);
    assert.deepEqual(scan([{ path: "a.txt", text: a }], { configDir }).map((s) => [s.rule_id, s.fingerprint]),
      [["supabase-service-role-jwt", jwtRef]], `JWT at ${n}`);
    const b = "z ".repeat(n / 2 | 0) + "Xjwt_secret=" + rand(250, ALNUM) + "/jwt_secret=" + secret + " " + "p ".repeat(20000);
    assert.deepEqual(scan([{ path: "b.txt", text: b }], { configDir }).map((s) => [s.rule_id, s.fingerprint]),
      [["generic-app-secret", secretRef]], `jwt_secret at ${n}`);
  }
});

test("a PEM split across JSON array items is found however long the array before it is", () => {
  const configDir = temp("custosa-secrets-");
  const body = Array.from({ length: 20 }, () => rand(64, ALNUM));
  const lines = ["\x2d----BEGIN PRIVATE KEY-----", ...body, "-----END PRIVATE KEY-----"];
  const ref = fpOf(configDir, lines.join("\n"));
  for (let L = 1; L <= 40; L++) {
    const items = [...Array(488).fill("x".repeat(66)), "y".repeat(L), ...lines];
    const found = scan([{ path: "keys.json", text: JSON.stringify(items, null, 1) }], { configDir });
    assert.deepEqual(found.map((s) => [s.rule_id, s.line, s.fingerprint]), [["pem-private-key", 491, ref]], `L ${L}`);
  }
});

test("a default password under a config key is a finding when the file names a non-loopback host", () => {
  const configDir = temp("custosa-secrets-");
  const files = [
    { path: "application-prod.properties",
      text: "spring.datasource.url=jdbc:mysql://prod-db.example.com:3306/app\nspring.datasource.password=root\n" },
    { path: "compose.yml", text: 'services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: postgres\n    ports:\n      - "5432:5432"\n' },
    { path: "compose-any.yml", text: "services:\n  db:\n    environment:\n      - MYSQL_ROOT_PASSWORD=root\n    ports:\n      - 0.0.0.0:3306:3306\n" },
    { path: "app.cfg", text: "DB_HOST=db\nDB_PASSWORD=postgres\n" },
    { path: "pg.cfg", text: "PGHOST=prod.internal.example.com\nPGPASSWORD=postgres\n" },
    { path: "multi.properties", text: "url=postgres://u@localhost,db.prod.example.com/app\nDATABASE_PASSWORD=admin\n" },
    // Quiet: loopback only, or no host at all.
    { path: "local.cfg", text: "DB_HOST=localhost\nDB_PASSWORD=postgres\n" },
    { path: "compose-local.yml", text: 'services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: postgres\n    ports:\n      - "127.0.0.1:5432:5432"\n' },
    { path: "nohost.cfg", text: "POSTGRES_PASSWORD=postgres\n" },
    { path: "var.cfg", text: "DB_HOST=${DB_HOST}\nDB_PASSWORD=postgres\n" },
  ];
  assert.deepEqual(scan(files, { configDir }).map((s) => [s.path, s.line, s.rule_id]), [
    ["app.cfg", 2, "database-password-config"], ["application-prod.properties", 2, "database-password-config"],
    ["compose-any.yml", 4, "database-password-config"], ["compose.yml", 4, "database-password-config"],
    ["multi.properties", 2, "database-password-config"], ["pg.cfg", 2, "database-password-config"],
  ]);
});

test("a URL password containing // is found, and fingerprinted whole", () => {
  const configDir = temp("custosa-secrets-");
  const password = `${rand(10, ALNUM)}//${rand(10, ALNUM)}`;
  const found = scan([{ path: "u.txt", text: `DATABASE_URL=postgres://app:${password}@db.prod.example.com/app` }],
    { configDir });
  assert.deepEqual(found.map((s) => [s.rule_id, s.fingerprint]),
    [["postgres-url-password", fpOf(configDir, `DB_PASSWORD=${password}`)]]);
});

test("pydantic annotated settings and up to 200 aligned spaces before =", () => {
  const configDir = temp("custosa-secrets-");
  const found = [
    ["generic-app-secret", `    secret_key: str = "${rand(40, ALNUM)}"`],
    ["generic-app-secret", `    jwt_secret: Optional[str] = '${rand(40, ALNUM)}'`],
    ["aws-secret-access-key", `AWS_SECRET_ACCESS_KEY${" ".repeat(150)}= ${rand(40, ALNUM)}`],
    ["aws-secret-access-key", `AWS_SECRET_ACCESS_KEY${" ".repeat(200)}= ${rand(40, ALNUM)}`],
  ];
  expectLines(scan([{ path: "settings.py", text: found.map(([, l]) => l).join("\n") }], { configDir }), found);
  const ms = cpuMs(() => scanSecrets([{ path: "big.txt", text: ("AWS_SECRET_ACCESS_KEY" + " ".repeat(199) + "\n" +
    "secret_key: " + "a".repeat(59) + " \n").repeat(4000) }], { configDir }));
  assert.ok(ms < 2000, `took ${ms} ms of CPU`);
});

test("files not scanned in full are reported as truncated, never as clean", () => {
  const configDir = temp("custosa-secrets-");
  const big = ["\x2d----BEGIN PRIVATE KEY-----", ...Array.from({ length: 300 }, () => rand(64, ALNUM)),
    "-----END PRIVATE KEY-----"].join("\n");
  const result = scanSecrets([
    { path: "huge.pem", text: "a\n".repeat(5000) + big },
    { path: "small.pem", text: [...big.split("\n").slice(0, 30), "-----END PRIVATE KEY-----"].join("\n") },
    { path: "weird.bin", text: 12345 },
  ], { historyBlobs: [{ path: "old.pem", text: "a\n".repeat(5000) + big, commit: "b".repeat(40) }], configDir });
  assert.deepEqual(result.truncated, [
    { path: "huge.pem", in_history: false, reason: "match_cut_at_window" },
    { path: "old.pem", in_history: true, reason: "match_cut_at_window" },
    { path: "weird.bin", in_history: false, reason: "unreadable" },
  ]);
  // The cut key is still a finding; the whole small key is not truncated.
  assert.deepEqual(result.secrets.map((s) => [s.path, s.rule_id]), [["huge.pem", "pem-private-key"],
    ["old.pem", "pem-private-key"], ["small.pem", "pem-private-key"]]);
  for (const s of result.secrets) assert.match(s.fingerprint, CONTRACT_HASH);
});

/* Review round 3. */
test("huge string arrays do not overflow the stack; an error in one file is scan_error and the others return", () => {
  const configDir = temp("custosa-secrets-");
  const key = fakeStripe();
  for (const n of [65000, 120000]) {
    const text = JSON.stringify(Array.from({ length: n }, (_, i) => `s${i}`));
    assert.deepEqual(scan([{ path: "big.json", text }], { configDir }), []);
  }
  const broken = Object.create(Uint8Array.prototype); // reading its bytes throws inside the scan
  const result = scanSecrets([{ path: "broken.bin", text: broken }, { path: "ok.env.sh", text: `K=${key}` }],
    { configDir });
  assert.deepEqual(result.truncated, [{ path: "broken.bin", in_history: false, reason: "scan_error" }]);
  assert.deepEqual(result.secrets.map((s) => [s.path, s.rule_id]), [["ok.env.sh", "stripe-secret-key"]]);
});

test("a long PEM key is flagged truncated or found whole at every offset, with one fingerprint", () => {
  const configDir = temp("custosa-secrets-");
  const body = Array.from({ length: 300 }, () => rand(64, ALNUM));
  const lines = ["\x2d----BEGIN PRIVATE KEY-----", ...body, "-----END PRIVATE KEY-----"];
  const forms = {
    plain: lines.join("\n"),
    escaped: JSON.stringify({ private_key: lines.join("\n") }),
    indented: "key: |\n" + lines.map((l) => "      " + l).join("\n"),
  };
  const ref = scan([{ path: "alone.pem", text: lines.slice(0, 80).join("\n") + "\n" + lines.at(-1) }], { configDir });
  for (const [name, pem] of Object.entries(forms)) {
    const alone = scanSecrets([{ path: "alone", text: pem }], { configDir });
    assert.equal(alone.secrets[0].fingerprint, ref[0].fingerprint, `${name} alone`);
    for (let i = 0; i < 130; i++) {
      const offset = i * 199 + (i % 7) * 13;
      const result = scanSecrets([{ path: "k", text: "#".repeat(offset) + "\n" + pem + "\n" + "z\n".repeat(3000) }],
        { configDir });
      const pemHits = result.secrets.filter((s) => s.rule_id === "pem-private-key");
      assert.equal(pemHits.length, 1, `${name} at ${offset}`);
      assert.equal(pemHits[0].fingerprint, ref[0].fingerprint, `${name} fingerprint at ${offset}`);
      const cut = result.truncated.some((t) => t.reason === "match_cut_at_window");
      const whole = !cut && result.truncated.length === 0;
      assert.ok(cut || whole, `${name} at ${offset}`);
    }
  }
  // A key past the pattern's line bound (more than 400 body lines) is reported as cut even with no window edge near.
  const longKey = ["\x2d----BEGIN PRIVATE KEY-----", ...Array.from({ length: 420 }, () => rand(40, ALNUM)),
    "-----END PRIVATE KEY-----"].join("\n");
  assert.ok(scanSecrets([{ path: "long.pem", text: longKey }], { configDir }).truncated
    .some((t) => t.reason === "match_cut_at_window"));
});

test("past the joined-view budget the joined view is skipped and reported; the plain scan still runs", () => {
  const configDir = temp("custosa-secrets-");
  const key = fakeStripe();
  const many = '"ab",'.repeat(210000) + `\nK=${key}\n`;
  const result = scanSecrets([{ path: "many.json", text: many }], { configDir });
  assert.deepEqual(result.truncated, [{ path: "many.json", in_history: false, reason: "joined_view_budget" }]);
  assert.deepEqual(result.secrets.map((s) => [s.rule_id, s.line]), [["stripe-secret-key", 2]]);
  const long = `"${"x".repeat(4.5 * 1024 * 1024)}", "${"y".repeat(4.5 * 1024 * 1024)}"`;
  assert.deepEqual(scanSecrets([{ path: "long.json", text: long }], { configDir }).truncated,
    [{ path: "long.json", in_history: false, reason: "joined_view_budget" }]);
});

test("more ways a file names a non-loopback host for a default password", () => {
  const configDir = temp("custosa-secrets-");
  const pw = "POSTGRES_PASSWORD: postgres\n";
  const flagged = {
    "interp.cfg": "DB_HOST=${DB_HOST:-db.prod.example.com}\nDB_PASSWORD=postgres\n",
    "server.cfg": "POSTGRES_SERVER=pg.prod.example.com\nPOSTGRES_PASSWORD=postgres\n",
    "dbserver.cfg": "DB_SERVER=10.0.0.12\nDB_PASSWORD=postgres\n",
    "dotted.properties": "db.host=prod.example.com\nDB_PASSWORD=postgres\n",
    "dsn.cfg": 'DATABASE_DSN="host=pg.prod.example.com dbname=app"\nPOSTGRES_PASSWORD=postgres\n',
    "short.yml": `services:\n  db:\n    environment:\n      ${pw}    ports:\n      - "5432"\n`,
    "long.yml": `services:\n  db:\n    environment:\n      ${pw}    ports:\n      - target: 5432\n        published: 5432\n`,
    "flow.yml": `services:\n  db:\n    environment:\n      ${pw}    ports: ["5432:5432"]\n`,
    "varport.yml": `services:\n  db:\n    environment:\n      ${pw}    ports:\n      - "\${PG_PORT:-5432}:5432"\n`,
    "hostnet.yml": `services:\n  db:\n    network_mode: host\n    environment:\n      ${pw}`,
  };
  const quiet = {
    "interp-local.cfg": "DB_HOST=${DB_HOST:-localhost}\nDB_PASSWORD=postgres\n",
    "interp-nodefault.cfg": "DB_HOST=${DB_HOST}\nDB_PASSWORD=postgres\n",
    "long-local.yml": `services:\n  db:\n    environment:\n      ${pw}    ports:\n      - target: 5432\n        published: 5432\n        host_ip: 127.0.0.1\n`,
    "flow-local.yml": `services:\n  db:\n    environment:\n      ${pw}    ports: ["127.0.0.1:5432:5432"]\n`,
    "var-local.yml": `services:\n  db:\n    environment:\n      ${pw}    ports:\n      - "127.0.0.1:\${PG_PORT:-5432}:5432"\n`,
  };
  const files = Object.entries({ ...flagged, ...quiet }).map(([path, text]) => ({ path, text }));
  assert.deepEqual(scan(files, { configDir }).map((s) => s.path).sort(), Object.keys(flagged).sort());
});

test("NUL-interleaved text (UTF-16 without a byte-order mark, UTF-32) is scanned NUL-stripped", () => {
  const configDir = temp("custosa-secrets-");
  const key = fakeStripe();
  const text = `# config\nSTRIPE_SECRET_KEY=${key}\n`;
  const ref = fpOf(configDir, key);
  const utf32 = Buffer.alloc(4 + text.length * 4);
  utf32.set([0xff, 0xfe, 0, 0]);
  for (let i = 0; i < text.length; i++) utf32.writeUInt32LE(text.charCodeAt(i), 4 + i * 4);
  const cjk = "\u6570\u636e\u5e93\u914d\u7f6e".repeat(4000); // CJK-heavy: few NULs overall
  const files = [
    { path: "u32.txt", text: utf32 },
    { path: "u16le.txt", text: Buffer.from(text, "utf16le") },
    { path: "u16be.txt", text: Buffer.from(text, "utf16le").swap16() },
    { path: "cjk-le.txt", text: Buffer.from(cjk + "\n" + text, "utf16le") },
    { path: "cjk-be.txt", text: Buffer.from(cjk + "\n" + text, "utf16le").swap16() },
    { path: "late.txt", text: Buffer.concat([Buffer.from("a".repeat(70000) + "\n"), Buffer.from(text, "utf16le")]) },
    { path: "one-nul.txt", text: text + "\0" },
  ];
  const result = scanSecrets(files, { configDir });
  assert.deepEqual(result.truncated, []);
  assert.deepEqual(result.secrets.map((s) => [s.path, s.line, s.fingerprint]), [
    ["cjk-be.txt", 3, ref], ["cjk-le.txt", 3, ref], ["late.txt", 3, ref], ["one-nul.txt", 2, ref],
    ["u16be.txt", 2, ref], ["u16le.txt", 2, ref], ["u32.txt", 2, ref],
  ]);
  // Binary (many NULs, no interleaved text) cannot be scanned: unreadable, not clean.
  const binary = Buffer.alloc(4096);
  for (let i = 0; i < binary.length; i += 3) binary[i] = 0x80 + (i % 50);
  assert.deepEqual(scanSecrets([{ path: "blob.bin", text: binary }], { configDir }).truncated,
    [{ path: "blob.bin", in_history: false, reason: "unreadable" }]);
});

test("malformed entries are reported as bad_input, and only .env and .env.<suffix> are env files", () => {
  const configDir = temp("custosa-secrets-");
  const key = fakeStripe();
  const result = scanSecrets([{ path: "a.txt", text: "x" }, null, { path: 7, text: "x" }, { path: ".envrc", text: `K=${key}` },
    { path: "src/.environment.ts", text: `const k = "${key}"` }], {
    envFiles: [{ path: ".env", tracked: "yes", text: `K=${key}` }, { path: "config/.env.example", tracked: true, text: `K=${key}` },
      undefined],
    historyBlobs: [null],
    configDir,
  });
  assert.deepEqual(result.truncated, [
    { path: ".env", in_history: false, reason: "bad_input" },
    { path: "envFiles[2]", in_history: false, reason: "bad_input" },
    { path: "files[1]", in_history: false, reason: "bad_input" },
    { path: "files[2]", in_history: false, reason: "bad_input" },
    { path: "historyBlobs[0]", in_history: true, reason: "bad_input" },
  ]);
  assert.deepEqual(result.secrets.map((s) => s.path), [".envrc", "config/.env.example", "src/.environment.ts"]);
  assert.ok(!isEnvFile(".envrc") && !isEnvFile("src/.environment.ts") && isEnvFile("config/.env.example") &&
    isEnvFile(".env") && !isEnvFile("x.cfg"));
});

test("a generic value strictly containing a provider token reports both; Annotated settings are read", () => {
  const configDir = temp("custosa-secrets-");
  const token = fakeStripe();
  const whole = `${token}-${rand(10, ALNUM)}`;
  const found = scan([{ path: "a.cfg", text: `JWT_SECRET=${whole}` }], { configDir });
  assert.deepEqual(found.map((s) => [s.rule_id, s.fingerprint]), [
    ["generic-app-secret", fpOf(configDir, `SESSION_SECRET=${whole}`)],
    ["stripe-secret-key", fpOf(configDir, token)],
  ].sort((a, b) => (a[0] < b[0] ? -1 : 1)));
  const annotated = scan([{ path: "settings.py", text: `    jwt_secret: Annotated[str, Field(min_length=32)] = "${rand(40, ALNUM)}"` }],
    { configDir });
  assert.deepEqual(annotated.map((s) => s.rule_id), ["generic-app-secret"]);
});

test("the fingerprint is HMAC-SHA256 with the install key over the domain-separated secret", async () => {
  const configDir = temp("custosa-secrets-");
  const { createHmac } = await import("node:crypto");
  const token = fakeStripe();
  const [s] = scan([{ path: "k.txt", text: token }], { configDir });
  const expected = createHmac("sha256", loadInstallKey({ configDir }))
    .update(Buffer.from(`custosa-secret-fingerprint-v1\0${token}`, "utf8")).digest("hex");
  assert.equal(s.fingerprint, expected);
});

/* Review round 4. */
test("a list that is not an array throws; a throwing entry is bad_input for that entry only", () => {
  const configDir = temp("custosa-secrets-");
  for (const bad of [null, { path: "a.js", text: "x" }, "a.js", new Set([{ path: "a.js", text: "x" }]), 7]) {
    assert.throws(() => scanSecrets(bad, { configDir }), BadInputError);
    assert.throws(() => scanSecrets([], { envFiles: bad, configDir }), BadInputError);
    assert.throws(() => scanSecrets([], { historyBlobs: bad, configDir }), BadInputError);
  }
  const key = fakeStripe();
  const throwingPath = { get path() { throw new Error("boom"); }, text: "x" };
  const throwingText = { path: "t.txt", get text() { throw new Error("boom"); } };
  const proxy = new Proxy({}, { get() { throw new Error("boom"); } });
  const throwingTracked = { path: ".env", text: "x", get tracked() { throw new Error("boom"); } };
  const result = scanSecrets([throwingPath, throwingText, proxy, { path: "ok.txt", text: `K=${key}` }],
    { envFiles: [throwingTracked], configDir });
  assert.deepEqual(result.truncated, [
    { path: ".env", in_history: false, reason: "bad_input" },
    { path: "files[0]", in_history: false, reason: "bad_input" },
    { path: "files[2]", in_history: false, reason: "bad_input" },
    { path: "t.txt", in_history: false, reason: "bad_input" },
  ]);
  assert.deepEqual(result.secrets.map((s) => s.path), ["ok.txt"]);
});

test("more host forms: compose alias, multi-line flow and JSON ports, *ADDR keys, nested YAML, spaces, escaped URL", () => {
  const configDir = temp("custosa-secrets-");
  const pw = "      POSTGRES_PASSWORD: postgres\n";
  const flagged = {
    "alias.yml": `x-ports: &dbports\n  - "5432:5432"\nservices:\n  db:\n    environment:\n${pw}    ports: *dbports\n`,
    "flowml.yml": `services:\n  db:\n    environment:\n${pw}    ports: [\n      "5432:5432",\n      "6379:6379"\n    ]\n`,
    "compose.json": '{"services":{"db":{"environment":{"POSTGRES_PASSWORD":"postgres"},"ports":["5432:5432"]}}}',
    "long.json": '{"services":{"db":{"environment":{"POSTGRES_PASSWORD":"postgres"},"ports":[{"target":5432,"published":5432}]}}}',
    "hostnet.json": '{"services":{"db":{"network_mode": "host","environment":{"POSTGRES_PASSWORD":"postgres"}}}}',
    "hostaddr.cfg": "PGHOSTADDR=10.1.2.3\nPGPASSWORD=postgres\n",
    "addr.cfg": "DB_ADDR=db.prod.example.com\nDB_PASSWORD=postgres\n",
    "nested.yml": "database:\n  primary:\n    host: db.prod.example.com\n    port: 5432\nenv:\n  POSTGRES_PASSWORD: postgres\n",
    "spaces.cfg": 'DB_HOST = " db.prod.example.com "\nDB_PASSWORD=postgres\n',
    "escaped.json": '{"url":"postgres:\\/\\/app@db.prod.example.com:5432\\/app","DB_PASSWORD":"postgres"}',
  };
  const quiet = {
    "local.json": '{"services":{"db":{"environment":{"POSTGRES_PASSWORD":"postgres"},"ports":["127.0.0.1:5432:5432"]}}}',
    "nested-local.yml": "database:\n  host: localhost\nenv:\n  POSTGRES_PASSWORD: postgres\n",
    "escaped-local.json": '{"url":"postgres:\\/\\/app@localhost:5432\\/app","DB_PASSWORD":"postgres"}',
  };
  const files = Object.entries({ ...flagged, ...quiet }).map(([path, text]) => ({ path, text }));
  assert.deepEqual([...new Set(scan(files, { configDir }).map((s) => s.path))].sort(), Object.keys(flagged).sort());
});

test("comment-prefixed PEM keys, armour headers and long one-line bodies give the key's fingerprint", () => {
  const configDir = temp("custosa-secrets-");
  const body = Array.from({ length: 80 }, () => rand(64, ALNUM));
  const lines = ["\x2d----BEGIN PRIVATE KEY-----", ...body, "-----END PRIVATE KEY-----"];
  const ref = fpOf(configDir, lines.join("\n"));
  for (const prefix of ["# ", "// ", " * ", "; ", "> ", "#"]) {
    const found = scan([{ path: "c.txt", text: "/**\n" + lines.map((l) => prefix + l).join("\n") + "\n */" }], { configDir });
    assert.deepEqual(found.map((s) => [s.rule_id, s.line, s.fingerprint]), [["pem-private-key", 2, ref]], `prefix ${JSON.stringify(prefix)}`);
  }
  const armoured = ["\x2d----BEGIN RSA PRIVATE KEY-----", "Proc-Type: 4,ENCRYPTED", "DEK-Info: AES-128-CBC,ABCDEF0123456789",
    "Comment: abcdefghijklmnopqrstuvwxyz", "", ...body, "-----END RSA PRIVATE KEY-----"].join("\n");
  assert.equal(fpOf(configDir, armoured), ref);
  const oneLine = ["\x2d----BEGIN PRIVATE KEY-----", body.join(""), "-----END PRIVATE KEY-----"].join("\n");
  assert.equal(fpOf(configDir, oneLine), ref, "a 5120-character one-line body");
  const tooLong = ["\x2d----BEGIN PRIVATE KEY-----", rand(9000, ALNUM), "-----END PRIVATE KEY-----"].join("\n");
  assert.deepEqual(scanSecrets([{ path: "long.pem", text: tooLong }], { configDir }).truncated,
    [{ path: "long.pem", in_history: false, reason: "match_cut_at_window" }]);
});

test("env file names follow the walker's predicate: case-insensitive, .env.<x> and <x>.env", () => {
  const configDir = temp("custosa-secrets-");
  const key = fakeStripe();
  const names = [".ENV", "cfg/.Env.local", "prod.env", ".env.", "deploy/STAGING.ENV"];
  const normal = [".envrc", "src/.environment.ts", ".envoy.yaml"];
  const result = scanSecrets([...names, ...normal].map((path) => ({ path, text: `K=${key}` })), { configDir });
  assert.deepEqual(result.truncated.map((t) => [t.path, t.reason]),
    names.map((n) => [n, "bad_input"]).sort((a, b) => (a[0] < b[0] ? -1 : 1)));
  assert.deepEqual(result.secrets.map((s) => s.path), [...normal].sort());
  for (const n of names) assert.ok(isEnvFile(n), n);
  for (const n of normal) assert.ok(!isEnvFile(n), n);
});

/* Review round 5. */
const B64 = ALNUM + "+/";
const pemLines = (bodyChars) => {
  const body = rand(bodyChars - 2, B64) + "==";
  const lines = [];
  for (let i = 0; i < body.length; i += 64) lines.push(body.slice(i, i + 64));
  return ["\x2d----BEGIN PRIVATE KEY-----", ...lines, "-----END PRIVATE KEY-----"];
};

test("comment-prefixed PEM keys with + and / in a short body give the plain fingerprint", () => {
  const configDir = temp("custosa-secrets-");
  const prefixes = ["# ", "// ", " * ", "; ", "> ", "#"];
  for (let k = 0; k < 25; k++) {
    const lines = pemLines(1600);
    const ref = fpOf(configDir, lines.join("\n"));
    const variants = prefixes.map((p) => lines.map((l) => p + l));
    variants.push(lines.map((l, i) => prefixes[i % prefixes.length] + l)); // mixed prefixes
    variants.push(["//", ...lines.map((l) => "// " + l), "//"]); // bare prefix lines around it
    for (const v of variants) {
      const text = "/**\n" + v.join("\n") + "\n */\n";
      const found = scan([{ path: "c.txt", text }], { configDir });
      assert.deepEqual(found.map((s) => [s.rule_id, s.fingerprint]), [["pem-private-key", ref]],
        `key ${k}, prefix ${JSON.stringify(v[1].slice(0, 3))}`);
    }
  }
});

test("NUL-separated fields stay separate; UTF-32 without a byte-order mark in both byte orders", () => {
  const configDir = temp("custosa-secrets-");
  const token = "ghp_" + rand(36, ALNUM);
  const utf16Run = [..."some interleaved ascii text"].map((c) => c + "\0").join("");
  const fields = `rec\0abc\0${token}\0xyz\n${utf16Run}\n`;
  assert.deepEqual(scan([{ path: "rec.dat", text: fields }], { configDir }).map((s) => [s.rule_id, s.line, s.fingerprint]),
    [["github-token", 1, fpOf(configDir, token)]]);
  const key = fakeStripe();
  const text = `# config\nSTRIPE_SECRET_KEY=${key}\n`;
  const le = Buffer.alloc(text.length * 4), be = Buffer.alloc(text.length * 4);
  for (let i = 0; i < text.length; i++) { le.writeUInt32LE(text.charCodeAt(i), i * 4); be.writeUInt32BE(text.charCodeAt(i), i * 4); }
  assert.deepEqual(scan([{ path: "u32le.txt", text: le }, { path: "u32be.txt", text: be }], { configDir })
    .map((s) => [s.path, s.line, s.fingerprint]), [["u32be.txt", 2, fpOf(configDir, key)], ["u32le.txt", 2, fpOf(configDir, key)]]);
});

test("a host key under any YAML parent counts, whatever the parent's name", () => {
  const configDir = temp("custosa-secrets-");
  const file = (parent, key = "host") => `${parent}:\n  ${key}: db.prod.example.com\nenv:\n  POSTGRES_PASSWORD: postgres\n`;
  const parents = ["database", "db", "mydb", "appdb", "userdb", "postgres14", "mysql8", "pgsql", "dbserver", "PrimaryDB",
    "feedback", "smtp"];
  const files = parents.map((p) => ({ path: `${p}.yml`, text: file(p) }));
  files.push({ path: "hostname.yml", text: file("x", "hostname") }, { path: "address.yml", text: file("x", "address") });
  files.push({ path: "local.yml", text: "mydb:\n  host: localhost\nenv:\n  POSTGRES_PASSWORD: postgres\n" });
  assert.deepEqual(scan(files, { configDir }).map((s) => s.path).sort(),
    [...parents.map((p) => `${p}.yml`), "address.yml", "hostname.yml"].sort());
});

test("a PEM key with no END line is reported truncated and does not take in the text after it", () => {
  const configDir = temp("custosa-secrets-");
  const lines = pemLines(1600);
  const ref = fpOf(configDir, lines.join("\n"));
  const noEnd = lines.slice(0, -1);
  const cases = {
    "prose.js": noEnd.map((l) => "// " + l).join("\n") + "\n// see the docs for rotating this key\n",
    "block.js": "/*\n" + noEnd.map((l) => " * " + l).join("\n") + "\n */\nconst x = 1;\n",
    "plain.txt": noEnd.join("\n") + "\nthanks for reading this note\n",
  };
  for (const [path, text] of Object.entries(cases)) {
    const result = scanSecrets([{ path, text }], { configDir });
    assert.deepEqual(result.secrets.map((s) => [s.rule_id, s.fingerprint]), [["pem-private-key", ref]], path);
    assert.deepEqual(result.truncated, [{ path, in_history: false, reason: "match_cut_at_window" }], path);
  }
});

test("an array Proxy whose length throws is BadInputError", () => {
  const configDir = temp("custosa-secrets-");
  const evil = new Proxy([], { get(target, key) { if (key === "length") throw new Error("boom"); return Reflect.get(target, key); } });
  assert.throws(() => scanSecrets(evil, { configDir }), BadInputError);
  assert.throws(() => scanSecrets([], { envFiles: evil, configDir }), BadInputError);
});

/* Review round 6. */
test("trailing spaces, tabs and CRLF on BEGIN, body and END lines neither drop nor cut a key", () => {
  const configDir = temp("custosa-secrets-");
  for (let k = 0; k < 5; k++) {
    const lines = pemLines(1600);
    const ref = fpOf(configDir, lines.join("\n"));
    const tails = ["  ", "\t", " \t ", ""];
    const variants = [
      lines.map((l, i) => l + tails[i % tails.length]).join("\n"),
      lines.join("\r\n"),
      lines.map((l, i) => l + tails[i % tails.length]).join("\r\n"),
      lines.map((l) => "    " + l + "  ").join("\n"),
      JSON.stringify({ k: lines.map((l) => l + "  ").join("\n") }),
    ];
    for (const text of variants) {
      assert.deepEqual(scan([{ path: "k.txt", text }], { configDir }).map((s) => [s.rule_id, s.fingerprint]),
        [["pem-private-key", ref]]);
    }
  }
});

test("a key whose first literal holds BEGIN and some body lines gives one finding when joined, else a cut", () => {
  const configDir = temp("custosa-secrets-");
  const lines = pemLines(1600);
  const ref = fpOf(configDir, lines.join("\n"));
  const lit = (ls) => `"${ls.map((l) => l + "\\n").join("")}"`;
  const joined = `const key = ${lit(lines.slice(0, 5))} +\n  ${lit(lines.slice(5, 15))} +\n  ${lit(lines.slice(15))};\n`;
  assert.deepEqual(scan([{ path: "key.js", text: joined }], { configDir }).map((s) => [s.rule_id, s.line, s.fingerprint]),
    [["pem-private-key", 1, ref]]);
  const broken = `const key = ${lit(lines.slice(0, 5))} + middle +\n  ${lit(lines.slice(15))};\n`;
  const result = scanSecrets([{ path: "broken.js", text: broken }], { configDir });
  assert.deepEqual(result.truncated, [{ path: "broken.js", in_history: false, reason: "match_cut_at_window" }]);
  assert.ok(result.secrets.some((s) => s.rule_id === "pem-private-key"));
});

test("a string that closes with no END line is truncated; up to 8 blank lines before END, not 9", () => {
  const configDir = temp("custosa-secrets-");
  const lines = pemLines(1600);
  const ref = fpOf(configDir, lines.join("\n"));
  const noEnd = `KEY = """${lines.slice(0, -1).join("\n")}\n"""\n`;
  const result = scanSecrets([{ path: "k.py", text: noEnd }], { configDir });
  assert.deepEqual(result.truncated, [{ path: "k.py", in_history: false, reason: "match_cut_at_window" }]);
  assert.deepEqual(result.secrets.map((s) => s.fingerprint), [ref]);
  const withEnd = `KEY = """${lines.join("\n")}\n"""\n`;
  assert.deepEqual(scan([{ path: "ok.py", text: withEnd }], { configDir }).map((s) => s.fingerprint), [ref]);
  for (const blanks of [3, 5, 8]) {
    const text = [...lines.slice(0, -1), ...Array(blanks).fill("   "), lines.at(-1)].join("\n");
    assert.deepEqual(scan([{ path: "b.txt", text }], { configDir }).map((s) => s.fingerprint), [ref], `${blanks} blank lines`);
  }
  const nine = [...lines.slice(0, -1), ...Array(9).fill("   "), lines.at(-1)].join("\n");
  assert.deepEqual(scanSecrets([{ path: "nine.txt", text: nine }], { configDir }).truncated,
    [{ path: "nine.txt", in_history: false, reason: "match_cut_at_window" }]);
});

test("// with no space on every line, and a bare // line inside a key, are comment prefixes", () => {
  const configDir = temp("custosa-secrets-");
  for (let k = 0; k < 10; k++) {
    const lines = pemLines(1600);
    const ref = fpOf(configDir, lines.join("\n"));
    const noSpace = lines.map((l) => "//" + l).join("\n");
    const bare = ["// " + lines[0], ...lines.slice(1, 6).map((l) => "// " + l), "//", ...lines.slice(6).map((l) => "// " + l)].join("\n");
    for (const text of [noSpace, bare]) {
      assert.deepEqual(scan([{ path: "c.js", text }], { configDir }).map((s) => [s.rule_id, s.fingerprint]),
        [["pem-private-key", ref]]);
    }
  }
});

/* Review round 7. */
test("a key cut at a closing quote is dropped only for the same key found whole by the joined view", () => {
  const configDir = temp("custosa-secrets-");
  const esc = (ls) => ls.map((l) => l + "\\n").join("");
  const k1 = pemLines(1000), k2 = pemLines(1000), k3 = pemLines(1000);
  const [r1, r2, r3] = [k1, k2, k3].map((k) => fpOf(configDir, k.join("\n")));
  const partial = `const x = "${esc(k1.slice(0, -1))}";`; // no END line: incomplete
  const split = `const y = "${esc(k2.slice(0, 8))}" + "${esc(k2.slice(8))}";`; // whole when joined
  const whole = `const z = "${esc(k3)}";`;
  const cases = {
    "xy.js": [partial + " " + split, [r1, r2]],
    "yx.js": [split + " " + partial, [r1, r2]],
    "three.js": [partial + " " + split + " " + whole, [r1, r2, r3]],
    "keys.json": [JSON.stringify({ a: k2, b: k1.slice(0, -1).join("\n") }), [r1, r2]],
  };
  for (const [path, [text, refs]] of Object.entries(cases)) {
    const result = scanSecrets([{ path, text }], { configDir });
    assert.deepEqual(result.secrets.map((s) => s.fingerprint).sort(), [...refs].sort(), path);
    assert.deepEqual(result.truncated, [{ path, in_history: false, reason: "match_cut_at_window" }], path);
  }
  // The split key alone is still one finding and clean.
  assert.deepEqual(scan([{ path: "y.js", text: split }], { configDir }).map((s) => s.fingerprint), [r2]);
});

test("YAML host keys with NBSP, vertical tab, form feed or a space before the colon", () => {
  const configDir = temp("custosa-secrets-");
  const pw = "env:\n  POSTGRES_PASSWORD: postgres\n";
  const files = [
    ["nbsp.yml", `db:\n  host: db.prod.example.com\n${pw}`],
    ["vt.yml", `db:\n \u000bhost:\u000bdb.prod.example.com\n${pw}`],
    ["ff.yml", `db:\n \u000chost: db.prod.example.com\n${pw}`],
    ["space.yml", `db:\n  host : db.prod.example.com\n${pw}`],
  ].map(([path, text]) => ({ path, text }));
  assert.deepEqual(scan(files, { configDir }).map((s) => s.path).sort(), ["ff.yml", "nbsp.yml", "space.yml", "vt.yml"]);
});

test("// with no space on a key with a single body line", () => {
  const configDir = temp("custosa-secrets-");
  const lines = ["\x2d----BEGIN PRIVATE KEY-----", "MC4C\x41QAwBQYDK2VwBCIEI" + rand(27, ALNUM), "-----END PRIVATE KEY-----"];
  assert.deepEqual(scan([{ path: "ed.js", text: lines.map((l) => "//" + l).join("\n") }], { configDir })
    .map((s) => s.fingerprint), [fpOf(configDir, lines.join("\n"))]);
});

/* Review round 8. */
const BEGIN = "\x2d----BEGIN PRIVATE KEY-----", END = "-----END PRIVATE KEY-----";

test("many partial keys in one huge joined literal map in linear time", () => {
  const configDir = temp("custosa-secrets-");
  const MB = 1 << 20;
  const fill = (unit) => { let s = ""; while (s.length < MB) s += unit(); return s; };
  const cases = {
    "quote hits in one big joined literal": `x = "${fill(() => `${BEGIN}\\n${rand(48, B64)}'`)}" + "y";\n`,
    "heavy escapes before": `x = "${"\\t\\u00e9\\\\".repeat(60000)}${fill(() => `${BEGIN}\\n${rand(48, B64)}'`).slice(0, MB / 2)}" + "y";\n`,
  };
  for (const [name, text] of Object.entries(cases)) {
    const ms = cpuMs(() => scanSecrets([{ path: "a.js", text }], { configDir }));
    assert.ok(ms < 2000, `${name} took ${ms} ms of CPU`);
  }
});

test("backslashes before BEGIN map to the same joined offset (no duplicate, no false truncation)", () => {
  const configDir = temp("custosa-secrets-");
  const lines = pemLines(1000);
  const ref = fpOf(configDir, lines.join("\n"));
  const esc = (ls) => ls.map((l) => l + "\\n").join("");
  for (const lead of ["\\", "\\\\\\"]) {
    const text = `x = "${lead}${esc(lines.slice(0, 6))}" + "${esc(lines.slice(6))}";\n`;
    assert.deepEqual(scan([{ path: "a.js", text }], { configDir }).map((s) => s.fingerprint), [ref], JSON.stringify(lead));
  }
});

test("// is stripped only when BEGIN, END and every body line carry it (never for ciphertext alone)", () => {
  const configDir = temp("custosa-secrets-");
  const l1 = "//" + rand(62, B64), l2 = rand(64, B64);
  const whole = fpOf(configDir, `${BEGIN}\n${l1}\n${l2}\n${END}`);
  // F3x: the same key split across literals, first body line starting //: same fingerprint as whole.
  assert.deepEqual(scan([{ path: "a.js", text: `x = "${BEGIN}\\n${l1}\\n" + "${l2}\\n${END}";\n` }], { configDir })
    .map((s) => s.fingerprint), [whole]);
  // F3y: a legacy encrypted key whose one ciphertext line starts with //: the // stays in the body.
  const RB = "\x2d----BEGIN RSA PRIVATE KEY-----", RE = "-----END RSA PRIVATE KEY-----";
  const enc = `${RB}\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00112233445566778899AABBCCDDEEFF\n\n${l1}\n${RE}\n`;
  const [y] = scan([{ path: "k.pem", text: enc }], { configDir });
  assert.equal(y.fingerprint, fpOf(configDir, `${BEGIN}\n${l1}\n${END}`));
  assert.notEqual(y.fingerprint, fpOf(configDir, `${BEGIN}\n${l1.slice(2)}\n${END}`));
  // The whole block commented with //: stripped.
  assert.equal(fpOf(configDir, [BEGIN, l1, l2, END].map((l) => "//" + l).join("\n")), fpOf(configDir, `${BEGIN}\n${l1}\n${l2}\n${END}`));
});

test("an identical partial next to a split key is reported in either order; one key split twice is clean", () => {
  const configDir = temp("custosa-secrets-");
  const k = pemLines(1000);
  const esc = (ls) => ls.map((l) => l + "\\n").join("");
  const split = `a = "${esc(k.slice(0, 6))}" + "${esc(k.slice(6))}";`;
  const partial = `b = "${esc(k.slice(0, 6))}";`;
  const full = fpOf(configDir, k.join("\n"));
  const part = scanSecrets([{ path: "p.js", text: partial }], { configDir }).secrets[0].fingerprint;
  for (const [path, text] of [["ab.js", split + " " + partial], ["ba.js", partial + " " + split]]) {
    const result = scanSecrets([{ path, text }], { configDir });
    assert.deepEqual(result.secrets.map((s) => s.fingerprint).sort(), [full, part].sort(), path);
    assert.deepEqual(result.truncated, [{ path, in_history: false, reason: "match_cut_at_window" }], path);
  }
  assert.deepEqual(scan([{ path: "twice.js", text: split + " " + split }], { configDir }).map((s) => s.fingerprint), [full]);
});

test("\\u000a, \\x0a and \\012 newline escapes in one literal and split across literals", () => {
  const configDir = temp("custosa-secrets-");
  const k = pemLines(1000);
  const ref = fpOf(configDir, k.join("\n"));
  for (const nl of ["\\u000a", "\\u000A", "\\x0a", "\\012"]) {
    const one = `x = "${k.join(nl)}${nl}";\n`;
    const split = `x = "${k.slice(0, 6).join(nl)}${nl}" + "${k.slice(6).join(nl)}${nl}";\n`;
    for (const text of [one, split]) {
      assert.deepEqual(scan([{ path: "a.js", text }], { configDir }).map((s) => s.fingerprint), [ref], nl);
    }
  }
});

test("a lone CR counts as a line break, like LF and CRLF, and a rule match is numbered the same way", async () => {
  const key = Buffer.alloc(32, 7);
  const secret = `sk\x5flive_51H${rand(32)}`; // random: an alphabet run is a placeholder (isShapePlaceholder)
  const lines = ["// one", "// two", "// three", "// four", `const k = "${secret}";`, ""];
  for (const eol of ["\n", "\r\n", "\r"]) {
    const out = scanSecrets([{ path: "src/a.js", text: lines.join(eol) }], { key });
    assert.deepEqual(out.secrets.map((s) => s.line), [5], JSON.stringify(eol));
  }
  const { matchRoot, normalizeBreaks } = await import("../lib/inspector/rules-worker.mjs");
  const { parseSync } = await import("../lib/inspector/parse.mjs");
  const text = normalizeBreaks(["// a", "// b", "console.log(x);", ""].join("\r"));
  assert.ok(!text.includes("\r") && text.length === 26); // one for one
  const found = [];
  matchRoot(parseSync("javascript", text).root(), "a.js", "javascript", [{ id: "x.javascript-generic.y", practice_id: "x", kind: "evidence", rule: { pattern: "console.log($A)" } }], key,
    { started: Date.now(), softMs: 10000, post: (m) => found.push(...m), text });
  assert.deepEqual(found.map((m) => m.line_start), [3]);
});

/* One isEnvFile (gitread.mjs, a base name). Pins today's results for both callers: the walker and readers
 * pass a base name, scanSecrets a file path whose base name (node:path basename, so a trailing slash is dropped) is
 * tested. */
test("isEnvFile on a base name, and scanSecrets on a path's base name, give the same results as before", () => {
  const cases = [
    // [input, as a base name, as a scanSecrets path]
    [".env", true, true], [".env.local", true, true], [".env.example", true, true], [".envrc", false, false],
    ["env", false, false], [".ENV", true, true], ["x.env", true, true], ["prod.ENV", true, true], [".env.", true, true],
    [".environment.ts", false, false], [".envoy.yaml", false, false], ["env.js", false, false],
    [".env/", false, true], ["x.env/", false, true], ["foo/.env", true, true], ["foo/.env/", false, true],
    ["a/b/.env.production", false, true], ["web/.env.local", false, true], ["src/x.env.ts", false, false],
    ["a\\.env.local", false, false],
  ];
  const configDir = temp("custosa-secrets-");
  const text = `K=${fakeStripe()}`;
  for (const [input, asName, asPath] of cases) {
    assert.equal(isEnvName(input), asName, `name ${input}`);
    const r = scanSecrets([{ path: input, text }], { configDir });
    assert.deepEqual([r.truncated.some((t) => t.reason === "bad_input"), r.secrets.length > 0], [asPath, !asPath], `path ${input}`);
  }
});

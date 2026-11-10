/* Smoke test for the platform collectors. Every HTTP call goes to an injected fetch that serves recorded
 * fixtures (test/fixtures/platform); nothing touches the network. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Ajv2020Module from "ajv/dist/2020.js";
import { collectPlatform, loadPlatformConfig, signV4, SETTING_KEYS, toFactPlatform, CONTRACT_KEYS, parseLogFilter, gcsKeeps,
  bigqueryKeeps, azurePolicyKeeps, SUPABASE_PAT_NOTE } from "../lib/inspector/platform.mjs";

const FIXTURES = new URL("./fixtures/platform/", import.meta.url);
const fixture = (name) => readFileSync(new URL(name, FIXTURES), "utf8");

const SUPABASE_TOKEN = "sb\x70_\x30123456789abcdef0123456789abcdef01234567";
const AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const AWS_SESSION = "FwoGZXIvYXdzEXAMPLESESSIONTOKEN0123456789";
const GCP_TOKEN = "ya29.a0AfB_fixtureAccessToken0123456789";
const AZURE_TOKEN = "eyJ0eXAiOiJKV1QiFIXTUREazureAccessToken0123456789";
const SECRETS = [SUPABASE_TOKEN, AWS_SECRET, AWS_SESSION, GCP_TOKEN, AZURE_TOKEN, "FIXTURE-PROVIDER-SECRET", "FIXTURE-SMTP-PASSWORD"];

const SUPABASE = { provider: "supabase", token: SUPABASE_TOKEN, project_ref: "abcdefghijklmnopqrst" };
const RDS = { provider: "rds", access_key_id: "AKIAIOSFODNN7EXAMPLE", secret_access_key: AWS_SECRET,
  session_token: AWS_SESSION, region: "us-east-1", db_instance_identifier: "clinic-prod" };
const CLOUDSQL = { provider: "cloudsql", access_token: GCP_TOKEN, project: "clinic-project", instance: "clinic-prod" };
const FIREBASE = { provider: "firebase", access_token: GCP_TOKEN, project: "clinic-project" };
const AZ_SUB = "00000000-0000-0000-0000-00000000aaaa";
const AZURE = { provider: "azure", access_token: AZURE_TOKEN, subscription_id: AZ_SUB, resource_group: "clinic-rg", server_name: "clinic-pg" };
const NOW = () => new Date("2026-10-20T12:00:00Z");

/* A fetch stub: route(url) returns {status, body} or undefined (an unexpected URL fails the test). Error responses
 * echo the token in their body, so a collector that read it would leak it. */
function stub(route) {
  const calls = [];
  const fetch = async (url, init) => {
    calls.push({ url, init });
    const hit = route(new URL(url), init);
    if (hit && hit.status === 999) throw new TypeError("network down"); // a read that never answers
    assert.ok(hit, `unexpected request ${url}`);
    return new Response(hit.body, { status: hit.status ?? 200 });
  };
  return { fetch, calls };
}

const SUPABASE_ROUTES = {
  "": "supabase-project.json",
  "/ssl-enforcement": "supabase-ssl-enforcement.json",
  "/network-restrictions": "supabase-network-restrictions.json",
  "/billing/addons": "supabase-addons.json",
  "/database/backups": "supabase-backups.json",
  "/config/database/postgres": "supabase-postgres-config.json",
  "/config/auth": "supabase-auth-config.json",
  "/advisors/security": "supabase-advisors-security.json",
};
function supabaseRoute(overrides = {}) {
  return (u) => {
    assert.equal(u.hostname, "api.supabase.com");
    const prefix = "/v1/projects/abcdefghijklmnopqrst";
    assert.ok(u.pathname.startsWith(prefix));
    const rest = u.pathname.slice(prefix.length);
    if (rest in overrides) return overrides[rest];
    return rest in SUPABASE_ROUTES ? { body: fixture(SUPABASE_ROUTES[rest]) } : undefined;
  };
}

function rdsRoute(overrides = {}) {
  return (u, init) => {
    if (u.hostname === "logs.us-east-1.amazonaws.com") {
      assert.equal(init.method, "POST");
      assert.equal(init.headers["x-amz-target"], "Logs_20140328.DescribeLogGroups");
      assert.equal(init.headers["content-type"], "application/x-amz-json-1.1");
      const body = JSON.parse(init.body);
      if ("DescribeLogGroups" in overrides) return typeof overrides.DescribeLogGroups === "function" ? overrides.DescribeLogGroups(body) : overrides.DescribeLogGroups;
      assert.equal(body.logGroupNamePrefix, "/aws/rds/instance/clinic-prod/postgresql");
      return { body: fixture("aws-describe-log-groups.json") };
    }
    assert.equal(u.hostname, "rds.us-east-1.amazonaws.com");
    const action = u.searchParams.get("Action");
    if (action in overrides) return overrides[action];
    if (action === "DescribeDBInstances") return { body: fixture("rds-describe-db-instances.xml") };
    if (action === "DescribeDBClusters") return { body: fixture("rds-describe-db-clusters.xml") };
    if (action === "DescribeDBParameters") {
      assert.equal(u.searchParams.get("DBParameterGroupName"), "clinic-pg16");
      return { body: fixture(u.searchParams.get("Marker") === "page-two-marker"
        ? "rds-describe-db-parameters-2.xml" : "rds-describe-db-parameters-1.xml") };
    }
    return undefined;
  };
}

/* The Google reads behind the log settings, by host and path (a value: {status, body}, or a fixture name). */
const GCP_ROUTES = {
  "cloudresourcemanager.googleapis.com/v1/projects/clinic-project:getAncestry": "gcp-ancestry.json",
  "cloudresourcemanager.googleapis.com/v1/projects/clinic-project:getIamPolicy": "gcp-iam-project.json",
  "cloudresourcemanager.googleapis.com/v3/folders/111111111111:getIamPolicy": "gcp-iam-folder.json",
  "cloudresourcemanager.googleapis.com/v3/organizations/222222222222:getIamPolicy": "gcp-iam-org.json",
  "logging.googleapis.com/v2/projects/clinic-project/sinks": "gcp-sinks-project.json",
  "logging.googleapis.com/v2/folders/111111111111/sinks": "gcp-sinks-folder.json",
  "logging.googleapis.com/v2/organizations/222222222222/sinks": "gcp-sinks-org.json",
  "logging.googleapis.com/v2/projects/clinic-project/locations/global/buckets/_Default": "gcp-bucket-default.json",
  "logging.googleapis.com/v2/projects/clinic-project/locations/us-central1/buckets/phi-logs": "gcp-bucket-phi-logs.json",
  "firestore.googleapis.com/v1/projects/clinic-project/databases": { body: "{}" },
  "storage.googleapis.com/storage/v1/b/clinic-audit-logs": "gcp-gcs-bucket.json",
};
function gcpRoute(overrides = {}) {
  return (u, init) => {
    const key = `${u.hostname}${u.pathname}`;
    if (u.hostname === "cloudresourcemanager.googleapis.com") {
      assert.equal(init.method, "POST");
      if (key.endsWith(":getIamPolicy")) assert.deepEqual(JSON.parse(init.body), { options: { requestedPolicyVersion: 3 } });
    } else assert.equal(init.method, "GET");
    const hit = key in overrides ? overrides[key] : GCP_ROUTES[key];
    if (hit === undefined) return undefined;
    return typeof hit === "string" ? { body: fixture(hit) } : hit;
  };
}
const gcpJson = (name, edit) => { const v = JSON.parse(fixture(name)); edit(v); return { body: JSON.stringify(v) }; };
const P = "logging.googleapis.com/v2/projects/clinic-project";
const CRM = "cloudresourcemanager.googleapis.com";
/* Firebase: a Firestore database, Data Access audit logs on for datastore at the project, and a sink of the Data
 * Access log to a Cloud Storage bucket whose lifecycle deletes at 400 days. */
const FIREBASE_ROUTES = {
  "firestore.googleapis.com/v1/projects/clinic-project/databases": "gcp-firestore-databases.json",
  [`${CRM}/v1/projects/clinic-project:getIamPolicy`]: gcpJson("gcp-iam-project.json", (v) => {
    v.auditConfigs = [{ service: "datastore.googleapis.com", auditLogConfigs: [{ logType: "DATA_READ" }, { logType: "DATA_WRITE" }] }];
  }),
  [`${P}/sinks`]: gcpJson("gcp-sinks-project.json", (v) => {
    v.sinks[2] = { name: "firestore-audit", destination: "storage.googleapis.com/clinic-audit-logs",
      filter: 'LOG_ID("cloudaudit.googleapis.com/data_access")' };
  }),
};

function cloudsqlRoute(override, gcpOverrides = {}) {
  const google = gcpRoute(gcpOverrides);
  return (u, init) => {
    if (u.hostname !== "sqladmin.googleapis.com") return google(u, init);
    assert.equal(u.pathname, "/v1/projects/clinic-project/instances/clinic-prod");
    return override ?? { body: fixture("cloudsql-instance.json") };
  };
}

const AZ_RG = `/subscriptions/${AZ_SUB}/resourceGroups/clinic-rg/providers`;
const AZURE_ROUTES = {
  [`${AZ_RG}/Microsoft.DBforPostgreSQL/flexibleServers/clinic-pg`]: "azure-server.json",
  [`${AZ_RG}/Microsoft.DBforPostgreSQL/flexibleServers/clinic-pg/providers/Microsoft.Insights/diagnosticSettings`]: "azure-diagnostic-settings.json",
  [`${AZ_RG}/Microsoft.OperationalInsights/workspaces/clinic-logs`]: "azure-workspace.json",
  [`${AZ_RG}/Microsoft.OperationalInsights/workspaces/clinic-logs/tables/AzureDiagnostics`]: "azure-workspace-table.json",
  [`${AZ_RG}/Microsoft.Storage/storageAccounts/clinicaudit/managementPolicies/default`]: "azure-storage-policy.json",
};
function azureRoute(overrides = {}) {
  return (u, init) => {
    assert.equal(u.hostname, "management.azure.com");
    assert.equal(init.method, "GET");
    assert.match(u.searchParams.get("api-version"), /^\d{4}-\d{2}-\d{2}(-preview)?$/);
    const hit = u.pathname in overrides ? overrides[u.pathname] : AZURE_ROUTES[u.pathname];
    if (hit === undefined) return undefined;
    return typeof hit === "string" ? { body: fixture(hit) } : hit;
  };
}
const azJson = (name, edit) => { const v = JSON.parse(fixture(name)); edit(v); return { body: JSON.stringify(v) }; };

function assertNoSecrets(value) {
  const text = JSON.stringify(value);
  for (const s of SECRETS) assert.ok(!text.includes(s), `result carries a secret: ${s.slice(0, 6)}...`);
}

function assertEnumLike(settings) {
  for (const [k, v] of Object.entries(settings)) {
    assert.ok(v === null || typeof v === "boolean" || Number.isInteger(v) || /^[A-Za-z0-9_]{1,64}$/.test(v),
      `${k} is not enum-like: ${v}`);
  }
}

// --- SigV4 against AWS's published examples ---------------------------------------------------------------------

test("SigV4 matches the AWS test suite's get-vanilla vector", () => {
  const signed = signV4({ host: "example.amazonaws.com", region: "us-east-1", service: "service",
    accessKeyId: "AKIDEXAMPLE", secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
    date: new Date("2015-08-30T12:36:00Z") });
  assert.equal(signed.canonicalRequest, "GET\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\n"
    + "host;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  assert.equal(signed.signature, "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31");
  assert.equal(signed.headers.authorization, "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/"
    + "aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31");
  assert.equal(signed.headers.host, undefined);
});

test("SigV4 matches the IAM user guide's ListUsers example", () => {
  const signed = signV4({ host: "iam.amazonaws.com", region: "us-east-1", service: "iam",
    query: [["Version", "2010-05-08"], ["Action", "ListUsers"]],
    headers: { "Content-Type": "application/x-www-form-urlencoded; charset=utf-8" },
    accessKeyId: "AKIDEXAMPLE", secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
    date: new Date("2015-08-30T12:36:00Z") });
  assert.equal(signed.canonicalQuery, "Action=ListUsers&Version=2010-05-08");
  assert.equal(signed.signature, "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7");
});

// --- Providers ---------------------------------------------------------------------------------------------------

test("Supabase: the Management API settings the practices need", async () => {
  const { fetch, calls } = stub(supabaseRoute());
  const out = await collectPlatform(SUPABASE, { fetch });
  assert.equal(out.provider, "supabase");
  assert.equal(out.status, "ok");
  assert.equal(out.reason, undefined);
  assert.deepEqual(out.settings, {
    ssl_enforced: true, network_restricted: true, pitr_enabled: true, pitr_retention_days: 14, backups_enabled: true,
    high_compliance: null, auth_mfa_enabled: true, auth_webauthn_enabled: false, leaked_password_protection: false,
    email_confirmation_required: true, anonymous_sign_ins_enabled: false, password_min_length: 15,
    otp_expiry_seconds: 3600, refresh_token_rotation: true, captcha_enabled: false,
  });
  assert.deepEqual(Object.keys(out.settings), [...SETTING_KEYS.supabase]);
  assert.equal(calls.length, 5);
  for (const c of calls) {
    assert.equal(c.init.method, "GET");
    assert.equal(c.init.redirect, "error");
    assert.equal(c.init.headers.authorization, `Bearer ${SUPABASE_TOKEN}`);
    assert.ok(!c.url.includes(SUPABASE_TOKEN));
  }
  assertEnumLike(out.settings);
  assertNoSecrets(out);
});

test("Supabase: open network ranges and no PITR add-on read as false", async () => {
  const { fetch } = stub(supabaseRoute({
    "/network-restrictions": { body: JSON.stringify({ entitlement: "allowed", status: "applied",
      config: { dbAllowedCidrs: ["0.0.0.0/0"], dbAllowedCidrsV6: ["::/0"] } }) },
    "/billing/addons": { body: JSON.stringify({ selected_addons: [], available_addons: [] }) },
    "/database/backups": { body: JSON.stringify({ region: "us-east-1", walg_enabled: true, pitr_enabled: false, backups: [] }) },
    "/ssl-enforcement": { body: JSON.stringify({ currentConfig: { database: false }, appliedSuccessfully: true }) },
  }));
  const out = await collectPlatform(SUPABASE, { fetch });
  assert.equal(out.settings.network_restricted, false);
  assert.equal(out.settings.pitr_enabled, false);
  assert.equal(out.settings.pitr_retention_days, 0);
  assert.equal(out.settings.ssl_enforced, false);
});

test("Supabase: a partial read reports what it read and marks the rest unknown", async () => {
  const { fetch } = stub(supabaseRoute({
    "/billing/addons": { status: 403, body: `{"message":"forbidden for ${SUPABASE_TOKEN}"}` },
    "/database/backups": { status: 403, body: "{}" },
    "/config/auth": { status: 500, body: "{}" },
  }));
  const out = await collectPlatform(SUPABASE, { fetch });
  assert.equal(out.status, "ok");
  assert.equal(out.reason, "partial");
  assert.deepEqual(out.errors, [
    { read: "addons", reason: "http_403" }, { read: "backups", reason: "http_403" },
    { read: "auth_config", reason: "http_500" },
  ]);
  assert.equal(out.settings.ssl_enforced, true);
  assert.equal(out.settings.pitr_enabled, null);
  assert.equal(out.settings.backups_enabled, null);
  assert.equal(out.settings.auth_mfa_enabled, null);
  assert.equal(out.settings.leaked_password_protection, null);
  assertNoSecrets(out);
});

test("RDS: DescribeDBInstances and the parameter group, signed with SigV4", async () => {
  const { fetch, calls } = stub(rdsRoute());
  const out = await collectPlatform(RDS, { fetch, now: NOW });
  assert.equal(out.provider, "rds");
  assert.equal(out.status, "ok");
  assert.deepEqual(out.settings, {
    engine: "postgres", postgres_major_version: 16, storage_encrypted: true, backup_retention_days: 7,
    pitr_enabled: true, backups_enabled: true, publicly_accessible: false, network_restricted: true,
    iam_auth_enabled: true, deletion_protection: false, ssl_enforced: true, log_connections: true,
    log_disconnections: null, log_export: true, log_retention: true,
  });
  assert.equal(calls.length, 4); // the instance, its log group, then two parameter pages
  for (const c of calls) {
    const auth = c.init.headers.authorization;
    const logs = new URL(c.url).hostname.startsWith("logs.");
    assert.match(auth, logs
      ? /^AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE\/20261020\/us-east-1\/logs\/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target, Signature=[0-9a-f]{64}$/
      : /^AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE\/20261020\/us-east-1\/rds\/aws4_request, SignedHeaders=host;x-amz-date;x-amz-security-token, Signature=[0-9a-f]{64}$/);
    assert.equal(c.init.headers["x-amz-date"], "20261020T120000Z");
    assert.equal(c.init.headers["x-amz-security-token"], AWS_SESSION); // sent as a header, never put in a result
    assert.ok(!c.url.includes(AWS_SECRET) && !c.url.includes(encodeURIComponent(AWS_SECRET)));
  }
  // The signature on the wire is the one signV4 computes for that request.
  const first = new URL(calls[0].url);
  const again = signV4({ host: first.hostname, query: [...first.searchParams], region: "us-east-1", service: "rds",
    accessKeyId: RDS.access_key_id, secretAccessKey: AWS_SECRET, sessionToken: AWS_SESSION, date: NOW() });
  assert.equal(calls[0].init.headers.authorization, again.headers.authorization);
  // The CloudWatch Logs POST is signed over its body.
  const post = calls.find((c) => new URL(c.url).hostname.startsWith("logs."));
  const signedPost = signV4({ method: "POST", host: "logs.us-east-1.amazonaws.com", body: post.init.body, region: "us-east-1",
    service: "logs", headers: { "content-type": "application/x-amz-json-1.1", "x-amz-target": "Logs_20140328.DescribeLogGroups" },
    accessKeyId: RDS.access_key_id, secretAccessKey: AWS_SECRET, sessionToken: AWS_SESSION, date: NOW() });
  assert.equal(post.init.headers.authorization, signedPost.headers.authorization);
  assertEnumLike(out.settings);
  assertNoSecrets(out);
});

test("RDS: no rds:DescribeDBParameters permission leaves TLS and logging unknown", async () => {
  const { fetch } = stub(rdsRoute({ DescribeDBParameters: { status: 403, body: "<ErrorResponse/>" } }));
  const out = await collectPlatform(RDS, { fetch, now: NOW });
  assert.equal(out.status, "ok");
  assert.equal(out.reason, "partial");
  assert.deepEqual(out.errors, [{ read: "DescribeDBParameters", reason: "http_403" }]);
  assert.equal(out.settings.storage_encrypted, true);
  assert.equal(out.settings.ssl_enforced, null);
  assert.equal(out.settings.log_connections, null);
});

test("Cloud SQL: instances.get settings", async () => {
  const { fetch, calls } = stub(cloudsqlRoute());
  const out = await collectPlatform(CLOUDSQL, { fetch });
  assert.equal(out.provider, "cloudsql");
  assert.equal(out.status, "ok");
  assert.deepEqual(out.settings, {
    engine: "postgres", postgres_major_version: 16, ssl_enforced: true, ssl_mode: "ENCRYPTED_ONLY",
    public_ip_enabled: true, authorized_network_count: 2, network_restricted: false, backups_enabled: true,
    pitr_enabled: true, transaction_log_retention_days: 7, backup_retention_count: 14, storage_encrypted: true,
    storage_key: "platform_default", deletion_protection: true, iam_auth_enabled: true, pgaudit_enabled: false,
    log_connections: true, log_disconnections: false, log_export: true, log_retention: true,
  });
  assert.equal(calls.length, 11); // the instance, then the log reads (ancestry, three policies, three sink lists,
  // Firestore, and the two log buckets the sinks write to; the folder's Pub/Sub and folder-only sinks aren't read)
  for (const c of calls) assert.equal(c.init.headers.authorization, `Bearer ${GCP_TOKEN}`);
  assertEnumLike(out.settings);
  assertNoSecrets(out);
});

// --- Failures and config -----------------------------------------------------------------------------------------

test("401 and 403 give failed with a code, never the body or the token", async () => {
  const echo = (status) => ({ status, body: `denied: ${SUPABASE_TOKEN} ${AWS_SECRET} ${GCP_TOKEN}` });
  const cases = [
    [SUPABASE, supabaseRoute({ "": echo(401), "/ssl-enforcement": echo(401), "/network-restrictions": echo(401),
      "/billing/addons": echo(401), "/database/backups": echo(401), "/config/database/postgres": echo(401),
      "/config/auth": echo(401), "/advisors/security": echo(401) }), "http_401"],
    [RDS, rdsRoute({ DescribeDBInstances: echo(403) }), "http_403"],
    [CLOUDSQL, cloudsqlRoute(echo(401)), "http_401"],
  ];
  for (const [config, route, reason] of cases) {
    const { fetch } = stub(route);
    const out = await collectPlatform(config, { fetch, now: NOW });
    // A Supabase personal access token (sbp_) also gets the local LI7 warning, which never holds the token.
    const notes = config.provider === "supabase" ? { notes: [SUPABASE_PAT_NOTE] } : {};
    assert.deepEqual(out, { provider: config.provider, status: "failed", settings: {}, reason, ...notes });
    assertNoSecrets(out);
  }
});

test("a fetch error carrying the token gives network_error without its message", async () => {
  const fetch = async () => { throw new TypeError(`fetch failed for ${GCP_TOKEN}`); };
  const out = await collectPlatform(CLOUDSQL, { fetch });
  assert.deepEqual(out, { provider: "cloudsql", status: "failed", settings: {}, reason: "network_error" });
});

test("no token gives not_run with no_token", async () => {
  const dir = mkdtempSync(join(tmpdir(), "custosa-platform-"));
  const fetch = async () => assert.fail("no request without a token");
  assert.deepEqual(await collectPlatform(undefined, { dir, fetch }),
    { provider: null, status: "not_run", settings: {}, reason: "no_token" });
  assert.deepEqual(await collectPlatform({ provider: "supabase", project_ref: "abcdefghijklmnopqrst" }, { fetch }),
    { provider: "supabase", status: "not_run", settings: {}, reason: "no_token" });
  assert.deepEqual(await collectPlatform({ ...RDS, secret_access_key: "" }, { fetch }),
    { provider: "rds", status: "not_run", settings: {}, reason: "no_token" });
});

test("platform.json is read from CUSTOSA_CONFIG_DIR only when 0600", async () => {
  const dir = mkdtempSync(join(tmpdir(), "custosa-platform-"));
  const file = join(dir, "platform.json");
  writeFileSync(file, JSON.stringify(SUPABASE));
  const fetch = stub(supabaseRoute()).fetch;

  chmodSync(file, 0o640);
  const refused = loadPlatformConfig({ dir });
  assert.equal(refused.result.status, "failed");
  assert.equal(refused.result.reason, "config_insecure");
  assert.match(refused.result.message, /chmod 600/);
  assertNoSecrets(refused);
  chmodSync(file, 0o604);
  assert.equal(loadPlatformConfig({ dir }).result.reason, "config_insecure");

  chmodSync(file, 0o600);
  const previous = process.env.CUSTOSA_CONFIG_DIR;
  process.env.CUSTOSA_CONFIG_DIR = dir;
  try {
    const out = await collectPlatform(undefined, { fetch });
    assert.equal(out.status, "ok");
    assert.equal(out.settings.ssl_enforced, true);
  } finally {
    if (previous === undefined) delete process.env.CUSTOSA_CONFIG_DIR; else process.env.CUSTOSA_CONFIG_DIR = previous;
  }
});

test("a region or name that would change the host is refused before any request", async () => {
  const fetch = async () => assert.fail("no request for an invalid config");
  for (const config of [
    { ...RDS, region: "us-east-1.attacker.example" },
    { ...RDS, region: "cn-north-1" },
    { ...RDS, db_instance_identifier: "x&Action=DeleteDBInstance" },
    { ...SUPABASE, project_ref: "../../v1/organizations" },
    { ...CLOUDSQL, project: "clinic-project/instances/x?" },
    { provider: "neon", token: SUPABASE_TOKEN },
  ]) {
    const out = await collectPlatform(config, { fetch, now: NOW });
    assert.equal(out.status, "failed");
    assert.equal(out.reason, "config_invalid");
    assertNoSecrets(out);
  }
});

// --- Review round 1: settings that could read as true when not observed or not in effect ---------------------------

test("RDS: parameter-group settings count only when the group is in-sync", async () => {
  for (const status of ["pending-reboot", "applying"]) {
    const instances = fixture("rds-describe-db-instances.xml").replace("<ParameterApplyStatus>in-sync<", `<ParameterApplyStatus>${status}<`);
    const { fetch } = stub(rdsRoute({ DescribeDBInstances: { body: instances } }));
    const out = await collectPlatform(RDS, { fetch, now: NOW });
    assert.equal(out.status, "ok");
    assert.equal(out.settings.ssl_enforced, null);
    assert.equal(out.settings.log_connections, null);
    assert.equal(out.settings.log_disconnections, null);
    assert.equal(out.settings.storage_encrypted, true);
  }
});

test("network ranges: parsed strictly, broad entries and large unions are not restricted", async () => {
  const cases = [
    [["10.0.0.0/8"], [], true],
    [["203.0.113.7/32", "198.51.100.0/24"], ["2001:db8::/32"], true],
    [["10.0.0.0/7"], [], false],
    [["10.0.0.0/8", "11.0.0.0/8"], [], false], // two /8s: more than 2^24 addresses together
    [[], ["::ffff:0:0/96"], false], // all of IPv4, written as IPv6
    [[], ["::ffff:10.0.0.0/104"], true], // IPv4 /8 written as IPv6
    [[], ["::ffff:10.0.0.0/103"], false], // IPv4 /7
    [["10.0.0.0/8"], ["::ffff:11.0.0.0/104"], false], // mapped entries add to the IPv4 total
    [[], ["::/80"], false], // holds ::ffff:0:0/96
    [[], ["2001:db8::/15"], false],
    [[], ["2001::/17", "2002::/17", "2003::/17"], false], // more than 2^112 addresses together
    [["0.0.0.0/0"], ["::/0"], false],
    [["10.0.0/8"], [], null],
    [["256.0.0.0/8"], [], null],
    [["10.0.0.0/33"], [], null],
    [["010.0.0.0/8"], [], null],
    [["10.0.0.0/08"], [], null],
    [["10.0.0.0"], [], null],
    [[], ["2001:db8:::/32"], null],
    [[], ["1:2:3:4:5:6:7:8:9/64"], null],
    [[], ["2001:db8::/129"], null],
    [[], ["fe80::1%eth0/64"], null],
    [["anywhere"], [], null],
  ];
  for (const [v4, v6, expected] of cases) {
    const { fetch } = stub(supabaseRoute({ "/network-restrictions": { body: JSON.stringify({ entitlement: "allowed",
      status: "applied", config: { dbAllowedCidrs: v4, dbAllowedCidrsV6: v6 } }) } }));
    const out = await collectPlatform(SUPABASE, { fetch });
    assert.equal(out.settings.network_restricted, expected, `${JSON.stringify([v4, v6])}`);
  }
  // Cloud SQL authorized networks go through the same check.
  const instance = JSON.parse(fixture("cloudsql-instance.json"));
  instance.settings.ipConfiguration.authorizedNetworks = [{ value: "198.51.100.0/24" }, { value: "office" }];
  const { fetch } = stub(cloudsqlRoute({ body: JSON.stringify(instance) }));
  assert.equal((await collectPlatform(CLOUDSQL, { fetch })).settings.network_restricted, null);
});

test("Cloud SQL: a response that isn't an instance is bad_response with no settings", async () => {
  for (const body of [{ error: { code: 200 } }, { kind: "sql#operation", databaseVersion: "POSTGRES_16" },
    { kind: "sql#instance" }, []]) {
    const { fetch } = stub(cloudsqlRoute({ body: JSON.stringify(body) }));
    const out = await collectPlatform(CLOUDSQL, { fetch });
    assert.deepEqual(out, { provider: "cloudsql", status: "failed", settings: {}, reason: "bad_response" });
  }
});

test("Supabase: PITR is on only when both reads say so, and off when either clearly says off", async () => {
  const addonOff = { body: JSON.stringify({ selected_addons: [], available_addons: [] }) };
  const backupsOff = { body: JSON.stringify({ walg_enabled: true, pitr_enabled: false }) };
  const cases = [
    [{ "/billing/addons": addonOff, "/database/backups": { status: 403, body: "{}" } }, false],
    [{ "/billing/addons": { status: 500, body: "{}" }, "/database/backups": backupsOff }, false],
    [{ "/billing/addons": addonOff, "/database/backups": backupsOff }, false],
    [{ "/billing/addons": { status: 403, body: "{}" }, "/database/backups": { status: 403, body: "{}" } }, null],
    [{}, true],
    [{ "/database/backups": { status: 403, body: "{}" } }, null],
    [{ "/billing/addons": { status: 500, body: "{}" } }, null],
    [{ "/billing/addons": addonOff }, false],
    [{ "/database/backups": { body: JSON.stringify({ walg_enabled: true, pitr_enabled: false }) } }, false],
    [{ "/database/backups": { body: JSON.stringify({ walg_enabled: true }) } }, null],
  ];
  for (const [overrides, expected] of cases) {
    const { fetch } = stub(supabaseRoute(overrides));
    assert.equal((await collectPlatform(SUPABASE, { fetch })).settings.pitr_enabled, expected, JSON.stringify(overrides));
  }
});

test("Supabase: MFA counts only when enrollment and verification are on for the same factor", async () => {
  const base = JSON.parse(fixture("supabase-auth-config.json"));
  const cases = [
    [{ mfa_totp_enroll_enabled: true, mfa_totp_verify_enabled: false, mfa_web_authn_enroll_enabled: false, mfa_web_authn_verify_enabled: true }, false],
    [{ mfa_totp_enroll_enabled: false, mfa_totp_verify_enabled: false, mfa_web_authn_enroll_enabled: true, mfa_web_authn_verify_enabled: true }, true],
    [{ mfa_totp_enroll_enabled: true, mfa_totp_verify_enabled: true, mfa_web_authn_enroll_enabled: false, mfa_web_authn_verify_enabled: false }, true],
    [{ mfa_totp_enroll_enabled: true, mfa_totp_verify_enabled: null, mfa_web_authn_enroll_enabled: false, mfa_web_authn_verify_enabled: false }, null],
  ];
  for (const [flags, expected] of cases) {
    const { fetch } = stub(supabaseRoute({ "/config/auth": { body: JSON.stringify({ ...base, ...flags }) } }));
    assert.equal((await collectPlatform(SUPABASE, { fetch })).settings.auth_mfa_enabled, expected, JSON.stringify(flags));
  }
});

test("the 4 MB response cap counts bytes, not characters", async () => {
  const body = JSON.stringify({ kind: "sql#instance", databaseVersion: "POSTGRES_16", pad: "é".repeat(2_200_000) });
  assert.ok(body.length < 4 * 1024 * 1024 && Buffer.byteLength(body) > 4 * 1024 * 1024);
  const { fetch } = stub(cloudsqlRoute({ body }));
  const out = await collectPlatform(CLOUDSQL, { fetch });
  assert.deepEqual(out, { provider: "cloudsql", status: "failed", settings: {}, reason: "too_large" });
});

test("a platform.json that is a symbolic link is refused", () => {
  const dir = mkdtempSync(join(tmpdir(), "custosa-platform-"));
  const real = join(dir, "real.json");
  writeFileSync(real, JSON.stringify(SUPABASE));
  chmodSync(real, 0o600);
  symlinkSync(real, join(dir, "platform.json"));
  const refused = loadPlatformConfig({ dir });
  assert.equal(refused.result.status, "failed");
  assert.equal(refused.result.reason, "config_insecure");
  assert.match(refused.result.message, /symbolic link/);
});

// --- toFactPlatform against the contract schema -------------------------------------------------------------------

// The contract's fact document schema (contract v2.1), copied in test/fixtures/contracts.
const SCHEMA = JSON.parse(fixture("../contracts/fact_document.schema.e106f9fb.json"));
const Ajv2020 = Ajv2020Module.default ?? Ajv2020Module;
const ajv = new Ajv2020({ strict: false, allErrors: true });
ajv.addSchema(SCHEMA);
// The platform block, the collection entry, and the rule tying the settings to the platform entry's status.
const validateFact = ajv.compile({
  type: "object", additionalProperties: false, required: ["platform", "collection"],
  properties: {
    platform: { $ref: `${SCHEMA.$id}#/properties/platform` },
    collection: { type: "array", items: { $ref: `${SCHEMA.$id}#/$defs/collection_entry` } },
  },
  allOf: [{ $ref: `${SCHEMA.$id}#/allOf/0` }], // the rule tying the settings to the platform entry's status
});
function fact(res) {
  const out = toFactPlatform(res);
  const doc = { platform: out.platform, collection: [out.collection] };
  assert.ok(validateFact(doc), JSON.stringify(validateFact.errors));
  assert.deepEqual(Object.keys(out.platform.settings), [...SCHEMA.properties.platform.properties.settings.required]);
  if (!["ok", "empty", "truncated"].includes(out.collection.status)) {
    assert.ok(Object.values(out.platform.settings).every((v) => v === "not_read"));
  }
  assert.ok(!(out.collection.status === "ok" && out.collection.reason !== null));
  assertNoSecrets(out);
  return out;
}

/* The v2.1 settings block: every key not_read except those given. */
const v2 = (given) => Object.fromEntries(CONTRACT_KEYS.map((k) => [k, given[k] ?? "not_read"]));

test("toFactPlatform: Supabase, RDS, Cloud SQL, Azure and Firebase results fit the contract", async () => {
  assert.deepEqual(CONTRACT_KEYS, SCHEMA.properties.platform.properties.settings.required);
  let out = fact(await collectPlatform(SUPABASE, { fetch: stub(supabaseRoute()).fetch }));
  assert.deepEqual(out, {
    platform: { provider: "supabase", settings: v2({ ssl_enforced: "on", network_restricted: "on", pitr_enabled: "on",
      auth_mfa_enabled: "on", leaked_password_protection: "off", log_retention: "not_offered" }) },
    collection: { collector: "platform", status: "ok", count: 5, reason: null },
  });
  out = fact(await collectPlatform(RDS, { fetch: stub(rdsRoute()).fetch, now: NOW }));
  assert.deepEqual(out, {
    platform: { provider: "aws", settings: v2({ ssl_enforced: "on", network_restricted: "on", pitr_enabled: "on",
      high_compliance: "not_offered", auth_mfa_enabled: "not_offered", leaked_password_protection: "not_offered",
      log_export: "on", log_retention: "on" }) },
    collection: { collector: "platform", status: "ok", count: 5, reason: null },
  });
  out = fact(await collectPlatform(CLOUDSQL, { fetch: stub(cloudsqlRoute()).fetch }));
  assert.deepEqual(out, {
    platform: { provider: "gcp", settings: v2({ ssl_enforced: "on", network_restricted: "off", pitr_enabled: "on",
      high_compliance: "not_offered", auth_mfa_enabled: "not_offered", leaked_password_protection: "not_offered",
      log_export: "on", log_retention: "on" }) },
    collection: { collector: "platform", status: "ok", count: 5, reason: null },
  });
  out = fact(await collectPlatform(AZURE, { fetch: stub(azureRoute()).fetch }));
  assert.deepEqual(out, {
    platform: { provider: "azure", settings: v2({ high_compliance: "not_offered", log_export: "on", log_retention: "on" }) },
    collection: { collector: "platform", status: "ok", count: 2, reason: null },
  });
  out = fact(await collectPlatform(FIREBASE, { fetch: stub(gcpRoute(FIREBASE_ROUTES)).fetch }));
  assert.deepEqual(out, {
    platform: { provider: "firebase", settings: v2({ high_compliance: "not_offered", log_export: "on", log_retention: "on" }) },
    collection: { collector: "platform", status: "ok", count: 2, reason: null },
  });
});

async function insecureConfig() {
  const dir = mkdtempSync(join(tmpdir(), "custosa-platform-"));
  writeFileSync(join(dir, "platform.json"), JSON.stringify(SUPABASE));
  chmodSync(join(dir, "platform.json"), 0o644);
  return collectPlatform(undefined, { dir, fetch: async () => assert.fail("no request") });
}

test("toFactPlatform: a partial read is truncated, failures and no token map to the contract's reasons", async () => {
  // A failed read a contract key rests on: truncated, with that read's reason.
  let out = fact(await collectPlatform(SUPABASE, { fetch: stub(supabaseRoute({
    "/billing/addons": { status: 403, body: "{}" } })).fetch }));
  assert.deepEqual(out.collection, { collector: "platform", status: "truncated", count: 4, reason: "not_permitted" });
  assert.equal(out.platform.settings.pitr_enabled, "not_read");
  // The advisors are no longer read, so their failure can't touch the contract block.
  out = fact(await collectPlatform(SUPABASE, { fetch: stub(supabaseRoute({
    "/advisors/security": { status: 500, body: "{}" } })).fetch }));
  assert.equal(out.collection.status, "ok");
  // RDS parameter group unreadable: truncated, TLS not_read.
  out = fact(await collectPlatform(RDS, { fetch: stub(rdsRoute({
    DescribeDBParameters: { status: 429, body: "" } })).fetch, now: NOW }));
  assert.deepEqual(out.collection, { collector: "platform", status: "truncated", count: 4, reason: "rate_limited" });
  assert.equal(out.platform.settings.ssl_enforced, "not_read");

  const cases = [
    [await collectPlatform(CLOUDSQL, { fetch: stub(cloudsqlRoute({ status: 401, body: "" })).fetch }), "gcp", "failed", "auth_failed"],
    [await collectPlatform(CLOUDSQL, { fetch: stub(cloudsqlRoute({ status: 403, body: "" })).fetch }), "gcp", "failed", "not_permitted"],
    [await collectPlatform(CLOUDSQL, { fetch: stub(cloudsqlRoute({ status: 400, body: "" })).fetch }), "gcp", "failed", "internal_error"],
    [await insecureConfig(), "unknown", "failed", "config_insecure"],
    [await collectPlatform(RDS, { fetch: stub(rdsRoute({ DescribeDBInstances: { status: 503, body: "" } })).fetch, now: NOW }), "aws", "failed", "unreachable"],
    [await collectPlatform(RDS, { fetch: stub(rdsRoute({ DescribeDBInstances: { status: 404, body: "" } })).fetch, now: NOW }), "aws", "failed", "platform_mismatch"],
    [await collectPlatform(CLOUDSQL, { fetch: stub(cloudsqlRoute({ body: "{}" })).fetch }), "gcp", "failed", "internal_error"],
    [await collectPlatform(CLOUDSQL, { fetch: async () => { throw Object.assign(new Error("t"), { name: "TimeoutError" }); } }), "gcp", "failed", "timeout"],
    [await collectPlatform(undefined, { dir: mkdtempSync(join(tmpdir(), "custosa-platform-")) }), "unknown", "not_run", "not_configured"],
    [await collectPlatform({ provider: "supabase", project_ref: "abcdefghijklmnopqrst" }), "supabase", "not_run", "not_configured"],
    [await collectPlatform({ provider: "rds", region: "nowhere" , access_key_id: "AKIAIOSFODNN7EXAMPLE", secret_access_key: AWS_SECRET }), "aws", "failed", "not_configured"],
  ];
  for (const [res, provider, status, reason] of cases) {
    out = fact(res);
    assert.equal(out.platform.provider, provider);
    assert.deepEqual(out.collection, { collector: "platform", status, count: 0, reason });
    assert.ok(Object.values(out.platform.settings).every((v) => v === "not_read"));
  }
});

// --- Log settings (contract v2.1, evaluator_api.md section 1.7) -------------------------------------------------------

const logs = (out) => [out.settings.log_export, out.settings.log_retention];

test("AWS log settings: CloudWatch export and the log group's retention", async () => {
  const run = async (overrides) => logs(await collectPlatform(RDS, { fetch: stub(rdsRoute(overrides)).fetch, now: NOW }));
  const group = (extra) => ({ body: JSON.stringify({ logGroups: [{ logGroupName: "/aws/rds/instance/clinic-prod/postgresql", ...extra }] }) });
  assert.deepEqual(await run({}), [true, true]); // 400 days
  assert.deepEqual(await run({ DescribeLogGroups: group({ retentionInDays: 30 }) }), [true, true]); // any retention period counts.
  assert.deepEqual(await run({ DescribeLogGroups: group({ retentionInDays: 365 }) }), [true, true]);
  assert.deepEqual(await run({ DescribeLogGroups: group({}) }), [true, true]); // never expires
  // A group with a longer name sharing the prefix is not the export's group: no destination read.
  assert.deepEqual(await run({ DescribeLogGroups: { body: JSON.stringify({ logGroups: [
    { logGroupName: "/aws/rds/instance/clinic-prod/postgresql-old", retentionInDays: 3650 }] }) } }), [true, null]);
  // No log group read: retention not_read, and the failure is reported.
  const failed = await collectPlatform(RDS, { fetch: stub(rdsRoute({ DescribeLogGroups: { status: 403, body: "{}" } })).fetch, now: NOW });
  assert.deepEqual(logs(failed), [true, null]);
  assert.deepEqual(failed.errors, [{ read: "DescribeLogGroups", reason: "http_403" }]);
  assert.deepEqual(fact(failed).collection, { collector: "platform", status: "truncated", count: 4, reason: "not_permitted" });
  // postgresql not exported (the pending change doesn't count): export off, and with no destination retention is
  // not_read, never off; no log group is read.
  const noExport = fixture("rds-describe-db-instances.xml").replace(/<EnabledCloudwatchLogsExports>[\s\S]*?<\/EnabledCloudwatchLogsExports>\s*/, "");
  assert.deepEqual(await run({ DescribeDBInstances: { body: noExport }, DescribeLogGroups: () => assert.fail("no log group read") }), [false, null]);
  const upgradeOnly = fixture("rds-describe-db-instances.xml").replace(/(<EnabledCloudwatchLogsExports>\s*)<member>postgresql<\/member>/, "$1");
  assert.deepEqual(await run({ DescribeDBInstances: { body: upgradeOnly } }), [false, null]);
  // Another engine is out of scope: not_read.
  const mysql = fixture("rds-describe-db-instances.xml").replace("<Engine>postgres</Engine>", "<Engine>mysql</Engine>");
  assert.deepEqual(await run({ DescribeDBInstances: { body: mysql } }), [null, null]);
});

/* db-logs-exported passes when any retention period is set, so
   the setting is log_retention (log_retention is gone), and a destination counts when it keeps the logs for any
   period of a day or more, or never deletes them. gcp's _Default counts with its retention observed. */
test("log_retention: any retention period of a day or more is on, with no 365-day floor", async () => {
  for (const p of ["rds", "cloudsql", "azure", "firebase"]) {
    assert.ok(SETTING_KEYS[p].includes("log_retention") && !SETTING_KEYS[p].includes("log_retention_365d"), p);
  }
  const aws = async (days) => { const o = await collectPlatform(RDS, { fetch: stub(rdsRoute({ DescribeLogGroups: { body: JSON.stringify({ logGroups: [
    { logGroupName: "/aws/rds/instance/clinic-prod/postgresql", retentionInDays: days }] }) } })).fetch, now: NOW });
    return [o.settings.log_export, o.settings.log_retention]; };
  assert.deepEqual(await aws(30), [true, true]);
  assert.deepEqual(await aws(1), [true, true]);
  const gcp = async (overrides) => { const o = await collectPlatform(CLOUDSQL, { fetch: stub(cloudsqlRoute(undefined, overrides)).fetch });
    return [o.settings.log_export, o.settings.log_retention]; };
  const onlyDefault = { [`${P}/sinks`]: gcpJson("gcp-sinks-project.json", (v) => { v.sinks.pop(); }),
    "logging.googleapis.com/v2/folders/111111111111/sinks": { body: "{}" } };
  assert.deepEqual(await gcp(onlyDefault), [true, true]); // _Default at its 30-day default
  assert.equal(gcsKeeps({ lifecycle: { rule: [{ action: { type: "Delete" }, condition: { age: 30 } }] } }), true);
  assert.equal(gcsKeeps({ lifecycle: { rule: [{ action: { type: "Delete" }, condition: { age: 0 } }] } }), false);
  assert.equal(gcsKeeps({ retentionPolicy: { retentionPeriod: String(7 * 86400) } }), true);
  assert.equal(bigqueryKeeps({ defaultTableExpirationMs: String(30 * 86400000) }, []), true);
  assert.equal(bigqueryKeeps({ defaultTableExpirationMs: String(3600000) }, []), false);
  const rule = (days) => ({ properties: { policy: { rules: [{ enabled: true, definition: { filters: { blobTypes: ["appendBlob"] },
    actions: { baseBlob: { delete: { daysAfterModificationGreaterThan: days } } } } }] } } });
  assert.equal(azurePolicyKeeps(rule(30)), true);
  assert.equal(azurePolicyKeeps(rule(0)), false);
});

test("AWS log settings: an Aurora instance reads its cluster's export and log group", async () => {
  const seen = [];
  const route = rdsRoute({
    DescribeDBInstances: { body: fixture("rds-describe-db-instances-aurora.xml") },
    DescribeLogGroups: (body) => {
      seen.push(body.logGroupNamePrefix);
      return { body: JSON.stringify({ logGroups: [{ logGroupName: "/aws/rds/cluster/clinic-cluster/postgresql", retentionInDays: 731 }] }) };
    },
  });
  const out = await collectPlatform(RDS, { fetch: stub(route).fetch, now: NOW });
  assert.deepEqual(logs(out), [true, true]);
  assert.deepEqual(seen, ["/aws/rds/cluster/clinic-cluster/postgresql"]);
  const off = await collectPlatform(RDS, { fetch: stub(rdsRoute({ DescribeDBInstances: { body: fixture("rds-describe-db-instances-aurora.xml") },
    DescribeDBClusters: { body: fixture("rds-describe-db-clusters.xml").replace("<member>postgresql</member>", "") } })).fetch, now: NOW });
  assert.deepEqual(logs(off), [false, null]);
  const unread = await collectPlatform(RDS, { fetch: stub(rdsRoute({ DescribeDBInstances: { body: fixture("rds-describe-db-instances-aurora.xml") },
    DescribeDBClusters: { status: 403, body: "" } })).fetch, now: NOW });
  assert.deepEqual(logs(unread), [null, null]);
  assert.deepEqual(unread.errors, [{ read: "DescribeDBClusters", reason: "http_403" }]);
});

test("GCP log settings: the _Default bucket counts with its retention observed; _Required never", async () => {
  const run = async (overrides) => logs(await collectPlatform(CLOUDSQL, { fetch: stub(cloudsqlRoute(undefined, overrides)).fetch }));
  const onlyDefault = { [`${P}/sinks`]: gcpJson("gcp-sinks-project.json", (v) => { v.sinks.pop(); }),
    "logging.googleapis.com/v2/folders/111111111111/sinks": { body: "{}" } };
  // _Default at its 30-day default counts for export, and it keeps the logs a retention period.
  assert.deepEqual(await run(onlyDefault), [true, true]);
  // With the folder's Pub/Sub sink (a filter this module can't evaluate), retention is never off.
  assert.deepEqual(await run({ [`${P}/sinks`]: onlyDefault[`${P}/sinks`] }), [true, true]); // _Default keeps every log 30 days, so the stream no longer decides.
  const longDefault = { ...onlyDefault, [`${P}/locations/global/buckets/_Default`]: gcpJson("gcp-bucket-default.json", (v) => { v.retentionDays = 400; }) };
  assert.deepEqual(await run(longDefault), [true, true]);
  // The _Default bucket's retention unread: export and retention not_read.
  assert.deepEqual(await run({ ...onlyDefault, [`${P}/locations/global/buckets/_Default`]: { status: 403, body: "" } }), [null, null]);
  // Only _Required: no sink routes the logs.
  assert.deepEqual(await run({ [`${P}/sinks`]: gcpJson("gcp-sinks-project.json", (v) => { v.sinks = [v.sinks[0]]; }),
    "logging.googleapis.com/v2/folders/111111111111/sinks": { body: "{}" } }), [false, null]);
});

test("GCP log settings: the audit config is the union up the ancestry; an unreadable ancestor is not_read", async () => {
  const run = async (overrides) => logs(await collectPlatform(CLOUDSQL, { fetch: stub(cloudsqlRoute(undefined, overrides)).fetch }));
  // DATA_WRITE comes from the folder's allServices config: without the folder, export is off.
  assert.deepEqual(await run({ [`${CRM}/v3/folders/111111111111:getIamPolicy`]: gcpJson("gcp-iam-folder.json", (v) => { v.auditConfigs = []; }) }), [false, true]);
  // An ancestor whose policy couldn't be read: not_read, never on (the sinks and retention still read).
  const unread = await collectPlatform(CLOUDSQL, { fetch: stub(cloudsqlRoute(undefined, {
    [`${CRM}/v3/organizations/222222222222:getIamPolicy`]: { status: 403, body: "" } })).fetch });
  assert.deepEqual(logs(unread), [null, true]);
  assert.deepEqual(fact(unread).collection.status, "truncated");
  // ... even when another level says off.
  assert.deepEqual(await run({ [`${CRM}/v3/organizations/222222222222:getIamPolicy`]: { status: 403, body: "" },
    [`${CRM}/v3/folders/111111111111:getIamPolicy`]: gcpJson("gcp-iam-folder.json", (v) => { v.auditConfigs = []; }) }), [null, true]);
  // A member exempted from Data Access logs at any level: whether it is the app's identity isn't known, so not_read.
  const exempt = (logType) => ({ [`${CRM}/v3/organizations/222222222222:getIamPolicy`]: gcpJson("gcp-iam-org.json", (v) => {
    v.auditConfigs = [{ service: "cloudsql.googleapis.com", auditLogConfigs: [{ logType, exemptedMembers: ["user:dba@example.com"] }] }];
  }) });
  assert.deepEqual(await run(exempt("DATA_READ")), [null, true]);
  // An exemption on ADMIN_READ doesn't touch the Data Access logs.
  assert.deepEqual(await run(exempt("ADMIN_READ")), [true, true]);
  // The ancestry itself unreadable: the levels above aren't known, and their sinks (one could intercept) aren't seen.
  assert.deepEqual(await run({ [`${CRM}/v1/projects/clinic-project:getAncestry`]: { status: 403, body: "" } }), [null, null]);
  assert.deepEqual(await run({ [`${CRM}/v1/projects/clinic-project:getAncestry`]: { body: JSON.stringify({ ancestor: [{ resourceId: { type: "folder", id: "../x" } }] }) } }), [null, null]);
  // An ancestor's sink list unreadable: never on.
  assert.deepEqual(await run({ "logging.googleapis.com/v2/organizations/222222222222/sinks": { status: 403, body: "" } }), [null, null]);
});

test("GCP log settings: sink filters and exclusions this module can't show cover the logs are never on", async () => {
  const run = async (overrides) => logs(await collectPlatform(CLOUDSQL, { fetch: stub(cloudsqlRoute(undefined, overrides)).fetch }));
  // _Default at its 30-day default now counts, so it is disabled here and the filter under test
  // decides alone.
  const custom = (edit) => ({ [`${P}/sinks`]: gcpJson("gcp-sinks-project.json", (v) => { v.sinks[1].disabled = true; edit(v.sinks[2]); }),
    "logging.googleapis.com/v2/folders/111111111111/sinks": { body: "{}" } });
  assert.deepEqual(await run(custom((sk) => { sk.filter = 'severity>=WARNING'; })), [null, null]);
  assert.deepEqual(await run(custom((sk) => { sk.filter = 'resource.type="cloudsql_database" AND textPayload:"x"'; })), [null, null]);
  assert.deepEqual(await run(custom((sk) => { sk.filter = 'resource.type="gce_instance"'; })), [false, null]); // no destination left
  assert.deepEqual(await run(custom((sk) => { sk.filter = 'LOG_ID("cloudsql.googleapis.com/postgres.log")'; })), [false, false]);
  assert.deepEqual(await run(custom((sk) => { sk.filter = 'LOG_ID("cloudsql.googleapis.com/postgres.log") OR LOG_ID("cloudaudit.googleapis.com/data_access")'; })), [true, true]);
  assert.deepEqual(await run(custom((sk) => { sk.filter = ""; })), [true, true]);
  // An exclusion that drops the audit log, or one this module can't evaluate.
  assert.deepEqual(await run(custom((sk) => { sk.exclusions = [{ name: "x", filter: 'LOG_ID("cloudaudit.googleapis.com/data_access")' }]; })), [false, false]);
  assert.deepEqual(await run(custom((sk) => { sk.exclusions = [{ name: "x", filter: "sample(insertId, 0.5)" }]; })), [null, null]);
  assert.deepEqual(await run(custom((sk) => { sk.exclusions = [{ name: "x", filter: "sample(insertId, 0.5)", disabled: true }]; })), [true, true]);
  assert.deepEqual(await run(custom((sk) => { sk.disabled = true; })), [false, null]); // no destination left
  // A sink to Pub/Sub routes to no destination this module reads: export off, retention never off.
  assert.deepEqual(await run(custom((sk) => { sk.destination = "pubsub.googleapis.com/projects/clinic-project/topics/logs"; })), [false, null]);
  // A destination name that won't go in a URL is followed nowhere.
  assert.deepEqual(await run(custom((sk) => { sk.destination = "storage.googleapis.com/../../v1/b/x"; })), [null, null]);
  // The project's sink list unreadable: never on.
  assert.deepEqual(await run({ [`${P}/sinks`]: { status: 403, body: "" } }), [null, null]);
});

test("GCP log settings: Cloud Storage and BigQuery destinations, read at the destination", async () => {
  const run = async (overrides) => logs(await collectPlatform(CLOUDSQL, { fetch: stub(cloudsqlRoute(undefined, overrides)).fetch }));
  const to = (destination) => ({ [`${P}/sinks`]: gcpJson("gcp-sinks-project.json", (v) => { v.sinks[2].destination = destination; }),
    "logging.googleapis.com/v2/folders/111111111111/sinks": { body: "{}" } });
  assert.deepEqual(await run(to("storage.googleapis.com/clinic-audit-logs")), [true, true]);
  assert.deepEqual(await run({ ...to("storage.googleapis.com/clinic-audit-logs"),
    "storage.googleapis.com/storage/v1/b/clinic-audit-logs": { body: JSON.stringify({ lifecycle: { rule: [{ action: { type: "Delete" }, condition: { age: 90 } }] } }) } }), [true, true]); // any retention period counts.
  const bq = to("bigquery.googleapis.com/projects/clinic-project/datasets/phi_logs");
  bq["bigquery.googleapis.com/bigquery/v2/projects/clinic-project/datasets/phi_logs"] = { body: JSON.stringify({ id: "clinic-project:phi_logs" }) };
  bq["bigquery.googleapis.com/bigquery/v2/projects/clinic-project/datasets/phi_logs/tables"] = { body: JSON.stringify({ tables: [
    { id: "t1", creationTime: "1700000000000", timePartitioning: { type: "DAY" } }] }) };
  assert.deepEqual(await run(bq), [true, true]);
  bq["bigquery.googleapis.com/bigquery/v2/projects/clinic-project/datasets/phi_logs"] = { body: JSON.stringify({ defaultPartitionExpirationMs: String(30 * 86400000) }) };
  assert.deepEqual(await run(bq), [true, true]); // any expiration of a day or more.
});

test("GCP log settings: Firestore is in scope when the project has a database", async () => {
  const run = async (overrides) => logs(await collectPlatform(CLOUDSQL, { fetch: stub(cloudsqlRoute(undefined, overrides)).fetch }));
  // A Firestore database whose Data Access logs aren't turned on: off.
  // its logs reach _Default, whose 30-day retention now counts.
  assert.deepEqual(await run({ "firestore.googleapis.com/v1/projects/clinic-project/databases": "gcp-firestore-databases.json" }), [false, true]);
  // The Firestore list unread (403 or any error): the in-scope set is unknown, so the Cloud SQL instance, read as on,
  // can't make either setting on alone (not_read); the failed read truncates the collection.
  for (const status of [403, 500]) {
    const out = await collectPlatform(CLOUDSQL, { fetch: stub(cloudsqlRoute(undefined, {
      "firestore.googleapis.com/v1/projects/clinic-project/databases": { status, body: "" } })).fetch });
    assert.deepEqual(logs(out), [null, null], String(status));
    assert.equal(fact(out).collection.status, "truncated");
  }
  // Only a 403 whose structured reason says the API is disabled means no database: Cloud SQL alone decides. The
  // message text is never read (a message saying "SERVICE_DISABLED" with another reason is still unknown).
  const disabled = (body) => collectPlatform(CLOUDSQL, { fetch: stub(cloudsqlRoute(undefined, {
    "firestore.googleapis.com/v1/projects/clinic-project/databases": { status: 403, body } })).fetch });
  for (const body of [
    JSON.stringify({ error: { code: 403, message: "x", details: [{ "@type": "type.googleapis.com/google.rpc.ErrorInfo", reason: "SERVICE_DISABLED" }] } }),
    JSON.stringify({ error: { code: 403, errors: [{ reason: "accessNotConfigured", message: "y" }] } }),
  ]) assert.deepEqual(logs(await disabled(body)), [true, true], body);
  for (const body of [
    JSON.stringify({ error: { code: 403, message: "SERVICE_DISABLED", details: [{ reason: "IAM_PERMISSION_DENIED" }] } }),
    JSON.stringify({ error: { code: 403, status: "PERMISSION_DENIED" } }), "not json", `${GCP_TOKEN} SERVICE_DISABLED`,
  ]) {
    const out = await disabled(body);
    assert.deepEqual(logs(out), [null, null], body);
    assertNoSecrets(out);
  }
  // An observed off on the Cloud SQL instance still gives off.
  const offSinks = { "firestore.googleapis.com/v1/projects/clinic-project/databases": { status: 403, body: "" },
    [`${P}/sinks`]: gcpJson("gcp-sinks-project.json", (v) => { v.sinks.pop(); v.sinks[1].disabled = true; }), // _Default off
    "logging.googleapis.com/v2/folders/111111111111/sinks": { body: "{}" } };
  assert.deepEqual(await run(offSinks), [false, null]);
});

test("Firebase log settings: the gcp definition for its Firestore", async () => {
  const run = async (overrides) => collectPlatform(FIREBASE, { fetch: stub(gcpRoute({ ...FIREBASE_ROUTES, ...overrides })).fetch });
  const out = await run({});
  assert.equal(out.status, "ok");
  assert.deepEqual(out.settings, { firestore_database_count: 1, log_export: true, log_retention: true });
  assertNoSecrets(out);
  // The audit config only for DATA_READ at the project: on through the folder's allServices DATA_WRITE, off without it.
  const readOnly = { [`${CRM}/v1/projects/clinic-project:getIamPolicy`]: gcpJson("gcp-iam-project.json", (v) => {
    v.auditConfigs = [{ service: "datastore.googleapis.com", auditLogConfigs: [{ logType: "DATA_READ" }] }];
  }) };
  assert.deepEqual(logs(await run(readOnly)), [true, true]);
  assert.deepEqual(logs(await run({ ...readOnly, [`${CRM}/v3/folders/111111111111:getIamPolicy`]: gcpJson("gcp-iam-folder.json", (v) => {
    v.auditConfigs[0].service = "cloudsql.googleapis.com";
  }) })), [false, true]);
  // No database: nothing in scope, never on.
  assert.deepEqual(logs(await run({ "firestore.googleapis.com/v1/projects/clinic-project/databases": { body: "{}" } })), [null, null]);
  // A resource.type filter on the Firestore log: its type isn't settled here, so not_read.
  assert.deepEqual(logs(await run({ [`${P}/sinks`]: gcpJson("gcp-sinks-project.json", (v) => {
    v.sinks[1].disabled = true; // _Default would count now; the filter under test decides alone
    v.sinks[2] = { name: "fs", destination: "storage.googleapis.com/clinic-audit-logs", filter: 'resource.type="audited_resource"' };
  }), "logging.googleapis.com/v2/folders/111111111111/sinks": { body: "{}" } })), [null, null]);
  // Every read refused: failed.
  const refused = await collectPlatform(FIREBASE, { fetch: stub(() => ({ status: 401, body: GCP_TOKEN })).fetch });
  assert.equal(refused.status, "failed");
  assert.equal(refused.reason, "http_401");
  assertNoSecrets(refused);
});

test("Azure log settings: diagnostic settings, workspace and storage retention, event hubs never settle it", async () => {
  const DIAG = `${AZ_RG}/Microsoft.DBforPostgreSQL/flexibleServers/clinic-pg/providers/Microsoft.Insights/diagnosticSettings`;
  const run = async (overrides) => logs(await collectPlatform(AZURE, { fetch: stub(azureRoute(overrides)).fetch }));
  const settings = (list) => ({ [DIAG]: { body: JSON.stringify({ value: list }) } });
  const ws = { name: "ws", properties: { workspaceId: `${AZ_RG}/Microsoft.OperationalInsights/workspaces/clinic-logs`,
    logs: [{ category: "PostgreSQLLogs", enabled: true }] } };
  const st = { name: "st", properties: { storageAccountId: `${AZ_RG}/Microsoft.Storage/storageAccounts/clinicaudit`,
    logs: [{ categoryGroup: "allLogs", enabled: true }] } };
  const eh = { name: "eh", properties: { eventHubAuthorizationRuleId: `${AZ_RG}/Microsoft.EventHub/namespaces/clinic/authorizationRules/send`,
    eventHubName: "pglogs", logs: [{ category: "PostgreSQLLogs", enabled: true }] } };
  const table = (total, retention = 90) => ({ [`${AZ_RG}/Microsoft.OperationalInsights/workspaces/clinic-logs/tables/AzureDiagnostics`]:
    { body: JSON.stringify({ properties: { retentionInDays: retention, totalRetentionInDays: total } }) } });
  const short = table(90);

  const out = await collectPlatform(AZURE, { fetch: stub(azureRoute()).fetch });
  assert.equal(out.status, "ok");
  assert.deepEqual(out.settings, { log_export: true, log_retention: true });
  assertNoSecrets(out);
  assert.deepEqual(await run({ ...settings([ws]) }), [true, true]); // the table's total retention, 400 days
  assert.deepEqual(await run({ ...settings([ws]), ...short }), [true, true]); // any retention period counts.
  // The diagnostic setting's own retention field is retired and never counts.
  assert.deepEqual(await run({ ...settings([{ ...ws, properties: { ...ws.properties, logs: [{ category: "PostgreSQLLogs", enabled: true,
    retentionPolicy: { enabled: true, days: 3650 } }] } }]), // with the table unread, the field doesn't settle it.
    [`${AZ_RG}/Microsoft.OperationalInsights/workspaces/clinic-logs/tables/AzureDiagnostics`]: { status: 403, body: "" } }), [true, null]);
  // Table-level retention overrides the workspace default: a 365-day workspace with a 0-day table is off (
  // item 6: a 30-day table now counts, so the off case is 0 days); a table
  // whose retention can't be read is not_read, never the workspace's; a table that inherits takes the workspace's.
  const ws365 = { [`${AZ_RG}/Microsoft.OperationalInsights/workspaces/clinic-logs`]: azJson("azure-workspace.json", (v) => { v.properties.retentionInDays = 365; }) };
  const tableProps = (p) => ({ [`${AZ_RG}/Microsoft.OperationalInsights/workspaces/clinic-logs/tables/AzureDiagnostics`]: { body: JSON.stringify({ properties: p }) } });
  assert.deepEqual(await run({ ...settings([ws]), ...ws365, ...tableProps({ retentionInDays: 0, totalRetentionInDays: 0 }) }), [true, false]);
  assert.deepEqual(await run({ ...settings([ws]), ...ws365, ...tableProps({ retentionInDays: 0, totalRetentionInDays: -1 }) }), [true, false]);
  assert.deepEqual(await run({ ...settings([ws]), ...ws365, ...tableProps({ retentionInDays: 0 }) }), [true, false]);
  assert.deepEqual(await run({ ...settings([ws]), ...ws365, ...tableProps({ retentionInDays: 30 }) }), [true, true]);
  assert.deepEqual(await run({ ...settings([ws]), ...ws365, ...tableProps({}) }), [true, null]);
  assert.deepEqual(await run({ ...settings([ws]), ...ws365, ...tableProps({ retentionInDays: "30" }) }), [true, null]);
  assert.deepEqual(await run({ ...settings([ws]), ...ws365, [`${AZ_RG}/Microsoft.OperationalInsights/workspaces/clinic-logs/tables/AzureDiagnostics`]: { status: 403, body: "" } }), [true, null]);
  assert.deepEqual(await run({ ...settings([ws]), ...ws365, ...tableProps({ retentionInDays: -1, totalRetentionInDays: -1 }) }), [true, true]);
  assert.deepEqual(await run({ ...settings([ws]), ...ws365, ...tableProps({ retentionInDays: 365, retentionInDaysAsDefault: true }) }), [true, true]);
  // An event hub: export on; its retention never settles the setting, and an instance sending to one is never off.
  assert.deepEqual(await run(settings([eh])), [true, null]);
  assert.deepEqual(await run({ ...settings([ws, eh]), ...table(0, 0) }), [true, null]); // a 90-day table now keeps them
  assert.deepEqual(await run({ ...settings([ws, eh]) }), [true, true]);
  // A storage account counts only with a lifecycle policy read that deletes nothing sooner; with none, not_read.
  assert.deepEqual(await run(settings([st])), [true, true]);
  const policy = `${AZ_RG}/Microsoft.Storage/storageAccounts/clinicaudit/managementPolicies/default`;
  assert.deepEqual(await run({ ...settings([st]), [policy]: { status: 404, body: "" } }), [true, null]);
  assert.deepEqual(await run({ ...settings([st]), [policy]: { status: 403, body: "" } }), [true, null]);
  assert.deepEqual(await run({ ...settings([st]), [policy]: azJson("azure-storage-policy.json", (v) => {
    v.properties.policy.rules[0].definition.actions.baseBlob.delete = { daysAfterCreationGreaterThan: 0 }; // 180 days now keeps them
  }) }), [true, false]);
  // No setting sends PostgreSQLLogs: export off, and with no destination retention is not_read.
  assert.deepEqual(await run(settings([{ name: "m", properties: { workspaceId: ws.properties.workspaceId, logs: [{ category: "PostgreSQLLogs", enabled: false }] } }])), [false, null]);
  assert.deepEqual(await run(settings([])), [false, null]);
  // The audit category group: not shown to include PostgreSQLLogs.
  assert.deepEqual(await run(settings([{ name: "a", properties: { ...ws.properties, logs: [{ categoryGroup: "audit", enabled: true }] } }])), [null, null]);
  // A workspace transformation could drop rows: never on.
  assert.deepEqual(await run({ ...settings([ws]), [`${AZ_RG}/Microsoft.OperationalInsights/workspaces/clinic-logs`]: azJson("azure-workspace.json", (v) => {
    v.properties.defaultDataCollectionRuleResourceId = `${AZ_RG}/Microsoft.Insights/dataCollectionRules/drop-some`;
  }) }), [null, null]);
  // The settings unreadable: not_read, collection truncated.
  const unread = await collectPlatform(AZURE, { fetch: stub(azureRoute({ [DIAG]: { status: 403, body: AZURE_TOKEN } })).fetch });
  assert.deepEqual(logs(unread), [null, null]);
  assert.deepEqual(fact(unread).collection, { collector: "platform", status: "truncated", count: 0, reason: "not_permitted" });
  assertNoSecrets(unread);
});

test("Azure: the server must exist and be a flexible server; config names are validated before any request", async () => {
  const server = `${AZ_RG}/Microsoft.DBforPostgreSQL/flexibleServers/clinic-pg`;
  assert.deepEqual(await collectPlatform(AZURE, { fetch: stub(azureRoute({ [server]: { status: 404, body: "" } })).fetch }),
    { provider: "azure", status: "failed", settings: {}, reason: "not_found" });
  assert.deepEqual(await collectPlatform(AZURE, { fetch: stub(azureRoute({ [server]: azJson("azure-server.json", (v) => { v.type = "Microsoft.Sql/servers"; }) })).fetch }),
    { provider: "azure", status: "failed", settings: {}, reason: "bad_response" });
  const fetch = async () => assert.fail("no request for an invalid config");
  for (const config of [{ ...AZURE, subscription_id: "../x" }, { ...AZURE, resource_group: "rg/../../x" }, { ...AZURE, server_name: "Clinic_PG" },
    { ...FIREBASE, project: "x/y" }]) {
    assert.equal((await collectPlatform(config, { fetch })).reason, "config_invalid");
  }
  assert.deepEqual(await collectPlatform({ ...AZURE, access_token: "" }, { fetch }), { provider: "azure", status: "not_run", settings: {}, reason: "no_token" });
  assert.deepEqual(await collectPlatform({ ...FIREBASE, access_token: undefined }, { fetch }), { provider: "firebase", status: "not_run", settings: {}, reason: "no_token" });
  for (const res of [await collectPlatform({ ...AZURE, access_token: "" }, { fetch }), await collectPlatform({ ...FIREBASE, access_token: "" }, { fetch })]) {
    const out = fact(res);
    assert.deepEqual(out.collection, { collector: "platform", status: "not_run", count: 0, reason: "not_configured" });
  }
});

test("Supabase log settings: export has no API read (not_read), retention is never offered", async () => {
  const out = fact(await collectPlatform(SUPABASE, { fetch: stub(supabaseRoute()).fetch }));
  assert.equal(out.platform.settings.log_export, "not_read");
  assert.equal(out.platform.settings.log_retention, "not_offered");
});

test("parseLogFilter reads the subset it can evaluate and refuses the rest", () => {
  for (const ok of ['LOG_ID("a/b")', 'NOT LOG_ID("a")', '-LOG_ID("a")', 'resource.type="cloudsql_database"', "resource.type = cloudsql_database",
    'logName="projects/p/logs/cloudsql.googleapis.com%2Fpostgres.log"', '(LOG_ID("a") OR LOG_ID("b")) AND resource.type!="x"',
    'LOG_ID("a") resource.type="b"', ""]) assert.ok(parseLogFilter(ok), ok);
  for (const bad of ['LOG_ID("a") AND LOG_ID("b") OR LOG_ID("c")', "severity>=ERROR", "textPayload:x", 'labels.x="y"', "foo",
    'LOG_ID("a\\"b")', '"unterminated', "(LOG_ID(\"a\")", 'resource.type=~"x"', 'LOG_ID("a") and LOG_ID("b")', 'sample(insertId, 0.1)']) {
    assert.equal(parseLogFilter(bad), null, bad);
  }
});

test("destination retention readers: Cloud Storage lifecycle, BigQuery expiration, Azure lifecycle policy", () => {
  assert.equal(gcsKeeps({}), true);
  assert.equal(gcsKeeps({ retentionPolicy: { retentionPeriod: String(400 * 86400) }, lifecycle: { rule: [{ action: { type: "Delete" }, condition: { age: 1 } }] } }), true);
  assert.equal(gcsKeeps({ lifecycle: { rule: [{ action: { type: "Delete" }, condition: { age: 364 } }] } }), true); // any retention period counts.
  assert.equal(gcsKeeps({ lifecycle: { rule: [{ action: { type: "Delete" }, condition: { age: 30, isLive: false } }] } }), true);
  assert.equal(gcsKeeps({ lifecycle: { rule: [{ action: { type: "Delete" }, condition: { age: 30, matchesPrefix: ["tmp/"] } }] } }), true); // a day or more whatever it matches.
  assert.equal(gcsKeeps({ lifecycle: { rule: [{ action: { type: "Delete" }, condition: { createdBefore: "2025-01-01" } }] } }), null);
  assert.equal(gcsKeeps({ lifecycle: { rule: [{ action: { type: "SomethingNew" }, condition: { age: 1 } }] } }), null);
  assert.equal(bigqueryKeeps({}, []), true);
  assert.equal(bigqueryKeeps({ defaultTableExpirationMs: String(400 * 86400000) }, []), true);
  // any expiration of a day or more keeps them; under a day doesn't.
  assert.equal(bigqueryKeeps({ defaultTableExpirationMs: String(30 * 86400000) }, []), true);
  assert.equal(bigqueryKeeps({ defaultTableExpirationMs: String(3600000) }, []), false);
  assert.equal(bigqueryKeeps({}, [{ creationTime: "0", expirationTime: String(100 * 86400000) }]), true);
  assert.equal(bigqueryKeeps({}, [{ creationTime: "0", expirationTime: String(3600000) }]), false);
  assert.equal(bigqueryKeeps({}, [{ expirationTime: "5" }]), null);
  assert.equal(bigqueryKeeps({}, [{ timePartitioning: { expirationMs: String(7 * 86400000) } }]), true);
  assert.equal(bigqueryKeeps({}, [{ timePartitioning: { expirationMs: String(3600000) } }]), false);
  const rule = (filters, del) => ({ properties: { policy: { rules: [{ enabled: true, type: "Lifecycle", definition: { filters, actions: { baseBlob: { delete: del } } } }] } } });
  assert.equal(azurePolicyKeeps({ properties: { policy: { rules: [] } } }), true);
  // a delete after 30 days keeps them a retention period; after 0 days doesn't.
  assert.equal(azurePolicyKeeps(rule({ blobTypes: ["appendBlob"] }, { daysAfterModificationGreaterThan: 30 })), true);
  assert.equal(azurePolicyKeeps(rule({ blobTypes: ["appendBlob"] }, { daysAfterModificationGreaterThan: 0 })), false);
  assert.equal(azurePolicyKeeps(rule({ blobTypes: ["appendBlob"], prefixMatch: ["insights-logs-postgresqllogs"] }, { daysAfterCreationGreaterThan: 0 })), false);
  assert.equal(azurePolicyKeeps(rule({ blobTypes: ["appendBlob"], prefixMatch: ["other-container/"] }, { daysAfterModificationGreaterThan: 30 })), true);
  assert.equal(azurePolicyKeeps(rule({ blobTypes: ["blockBlob"] }, { daysAfterModificationGreaterThan: 30 })), true);
  assert.equal(azurePolicyKeeps(rule({ blobTypes: ["appendBlob"], blobIndexMatch: [{ name: "a", op: "==", value: "b" }] }, { daysAfterModificationGreaterThan: 30 })), null);
  assert.equal(azurePolicyKeeps(rule({ blobTypes: ["appendBlob"] }, { daysAfterLastAccessTimeGreaterThan: 400 })), true);
  assert.equal(azurePolicyKeeps({}), null);
});

test("GCP log settings (review): case-insensitive filters, intercepting ancestor sinks, deleted buckets", async () => {
  const run = async (overrides) => logs(await collectPlatform(CLOUDSQL, { fetch: stub(cloudsqlRoute(undefined, overrides)).fetch }));
  // _Default at its 30-day default now counts, so it is disabled here and the filter under test
  // decides alone.
  const custom = (edit) => ({ [`${P}/sinks`]: gcpJson("gcp-sinks-project.json", (v) => { v.sinks[1].disabled = true; edit(v.sinks[2]); }),
    "logging.googleapis.com/v2/folders/111111111111/sinks": { body: "{}" } });
  // Logging compares without regard to case: an upper-case exclusion drops every Cloud SQL log.
  assert.deepEqual(await run(custom((sk) => { sk.exclusions = [{ name: "x", filter: 'resource.type="CLOUDSQL_DATABASE"' }]; })), [false, null]); // no destination left
  assert.deepEqual(await run(custom((sk) => { sk.filter = '-logName="projects/CLINIC-PROJECT/logs/cloudaudit.googleapis.com%2FDATA_ACCESS"'; })), [false, false]);
  assert.deepEqual(await run(custom((sk) => { sk.filter = 'LOG_ID("CloudSQL.googleapis.com/postgres.log") OR LOG_ID("cloudaudit.googleapis.com/Data_Access")'; })), [true, true]);
  // An intercepting folder sink that may match an in-scope log: both not_read, whatever the project's own sinks say.
  const intercept = (filter) => ({ "logging.googleapis.com/v2/folders/111111111111/sinks": { body: JSON.stringify({ sinks: [
    { name: "central", destination: "logging.googleapis.com/projects/central-logs", includeChildren: true, interceptChildren: true, filter }] }) } });
  assert.deepEqual(await run(intercept(undefined)), [null, null]);
  assert.deepEqual(await run(intercept('resource.type="cloudsql_database"')), [null, null]);
  assert.deepEqual(await run(intercept("severity>=ERROR")), [null, null]); // can't show it matches none
  assert.deepEqual(await run(intercept('resource.type="gce_instance"')), [true, true]); // provably matches none
  // A bucket pending deletion receives nothing.
  assert.deepEqual(await run({ ...custom(() => {}), [`${P}/locations/us-central1/buckets/phi-logs`]: gcpJson("gcp-bucket-phi-logs.json", (v) => {
    v.lifecycleState = "DELETE_REQUESTED"; }) }), [false, null]); // no destination left
  // The bucket unread: export not shown either.
  assert.deepEqual(await run({ ...custom(() => {}), [`${P}/locations/us-central1/buckets/phi-logs`]: { status: 403, body: "" } }), [null, null]);
});

test("AWS (review): the log group is named from the identifier AWS returns", async () => {
  const seen = [];
  const out = await collectPlatform({ ...RDS, db_instance_identifier: "Clinic-Prod" }, { fetch: stub(rdsRoute({
    DescribeLogGroups: (body) => { seen.push(body.logGroupNamePrefix); return { body: fixture("aws-describe-log-groups.json") }; } })).fetch, now: NOW });
  assert.deepEqual(seen, ["/aws/rds/instance/clinic-prod/postgresql"]);
  assert.deepEqual(logs(out), [true, true]);
});

test("Azure (review): a workspace daily cap leaves retention not_read", async () => {
  const DIAG = `${AZ_RG}/Microsoft.DBforPostgreSQL/flexibleServers/clinic-pg/providers/Microsoft.Insights/diagnosticSettings`;
  const ws = { name: "ws", properties: { workspaceId: `${AZ_RG}/Microsoft.OperationalInsights/workspaces/clinic-logs`,
    logs: [{ category: "PostgreSQLLogs", enabled: true }] } };
  const capped = async (quota) => logs(await collectPlatform(AZURE, { fetch: stub(azureRoute({ [DIAG]: { body: JSON.stringify({ value: [ws] }) },
    [`${AZ_RG}/Microsoft.OperationalInsights/workspaces/clinic-logs`]: azJson("azure-workspace.json", (v) => { v.properties.workspaceCapping = { dailyQuotaGb: quota }; }) })).fetch }));
  assert.deepEqual(await capped(5), [true, null]);
  assert.deepEqual(await capped(-1), [true, true]); // -1: no cap
});

test("past the check's time budget no platform request is made; each read is a timeout", async () => {
  let calls = 0;
  const out = await collectPlatform(SUPABASE, { fetch: async () => { calls++; throw new Error("no"); }, deadline: Date.now() - 1 });
  assert.equal(calls, 0);
  assert.notEqual(out.status, "ok");
});

test("RDS: the regions the config accepts are the regions whose rds and logs hosts may be called", async () => {
  const accepted = ["us-east-1", "us-gov-west-1", "eu-central-2", "ap-southeast-4", "sa-east-1", "ca-west-1",
    "me-central-1", "af-south-1", "il-central-1", "mx-central-1"];
  const refused = ["cn-north-1", "us-iso-east-1", "us-east-0", "US-east-1", "us-east-1x", "us-east-10", "useast-1",
    "us-gov-west", "xx-east-1", "us-east-1.evil.com", ""];
  for (const region of accepted) {
    const hosts = new Set();
    const inner = stub(rdsRoute()).fetch; // answers as us-east-1 does
    const fetch = (url, init) => {
      const u = new URL(url);
      hosts.add(u.hostname);
      u.hostname = u.hostname.replace(region, "us-east-1");
      return inner(u.href, init);
    };
    const out = await collectPlatform({ ...RDS, region }, { fetch, now: NOW });
    assert.equal(out.status, "ok", region);
    assert.deepEqual([...hosts].sort(), [`logs.${region}.amazonaws.com`, `rds.${region}.amazonaws.com`], region);
  }
  for (const region of refused) {
    let called = 0;
    const out = await collectPlatform({ ...RDS, region }, { fetch: async () => { called++; return new Response("{}"); }, now: NOW });
    assert.deepEqual([out.status, out.reason, called], ["failed", "config_invalid", 0], region);
  }
});

// the project, postgres_config and security_advisors reads fed only settings the fact document never
// takes (toFactPlatform maps CONTRACT_KEYS only), so the collector no longer makes them.
test("Supabase makes only the reads a contract setting rests on", async () => {
  const { fetch, calls } = stub(supabaseRoute());
  const out = await collectPlatform(SUPABASE, { fetch });
  assert.equal(out.status, "ok");
  const prefix = "https://api.supabase.com/v1/projects/abcdefghijklmnopqrst";
  assert.deepEqual(calls.map((c) => c.url.slice(prefix.length)).sort(),
    ["/billing/addons", "/config/auth", "/database/backups", "/network-restrictions", "/ssl-enforcement"]);
  for (const k of ["postgres_major_version", "log_connections", "log_disconnections", "advisor_error_count", "advisor_warn_count"]) {
    assert.ok(!(k in out.settings), k);
  }
});

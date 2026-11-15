/* platform.mjs pgSwitch: how a Postgres logging or TLS switch read from Cloud SQL flags or an RDS parameter group
 * becomes true, false or unknown. Only "on" and "1" ran in a test; off, the other spellings, and PostgreSQL 18's
 * log_connections list (lines 475 to 482) ran in none. Every read goes to a stub fetch, as in inspector-platform. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { collectPlatform } from "../lib/inspector/platform.mjs";

const FIXTURES = new URL("./fixtures/platform/", import.meta.url);
const fixture = (name) => readFileSync(new URL(name, FIXTURES), "utf8");
const NOW = () => new Date("2026-10-20T12:00:00Z");
const CLOUDSQL = { provider: "cloudsql", access_token: "ya29.a0AfB_fixtureAccessToken0123456789", project: "clinic-project",
  instance: "clinic-prod" };
const RDS = { provider: "rds", access_key_id: "AKIAIOSFODNN7EXAMPLE", secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  region: "us-east-1", db_instance_identifier: "clinic-prod" };

/* Any read but the one under test fails with 403, which leaves its own settings unknown and touches no switch. */
const fetchFor = (route) => async (url) => {
  const hit = route(new URL(url));
  return new Response(hit?.body ?? "{}", { status: hit ? 200 : 403 });
};

async function cloudsql(flags) {
  const instance = JSON.parse(fixture("cloudsql-instance.json"));
  instance.settings.databaseFlags = Object.entries(flags).map(([name, value]) => ({ name, value }));
  const body = JSON.stringify(instance);
  const out = await collectPlatform(CLOUDSQL, { fetch: fetchFor((u) => (u.hostname === "sqladmin.googleapis.com" ? { body } : null)), now: NOW });
  return out.settings;
}

const xml = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;");
async function rds(params) {
  const page = `<DescribeDBParametersResponse><DescribeDBParametersResult><Parameters>${Object.entries(params).map(([name, value]) =>
    `<Parameter><ParameterName>${name}</ParameterName><ParameterValue>${xml(value)}</ParameterValue></Parameter>`).join("")}` +
    "</Parameters></DescribeDBParametersResult></DescribeDBParametersResponse>";
  const route = (u) => {
    if (u.hostname !== "rds.us-east-1.amazonaws.com") return null;
    const action = u.searchParams.get("Action");
    if (action === "DescribeDBInstances") return { body: fixture("rds-describe-db-instances.xml") };
    return action === "DescribeDBParameters" ? { body: page } : null;
  };
  return (await collectPlatform(RDS, { fetch: fetchFor(route), now: NOW })).settings;
}

// [value, as log_connections (a list setting on PostgreSQL 18), as log_disconnections or rds.force_ssl]
const CASES = [
  ["on", true, true], ["ON", true, true], [" on ", true, true], ["1", true, true], ["true", true, true], ["yes", true, true],
  ["off", false, false], ["Off", false, false], ["0", false, false], ["false", false, false], ["no", false, false],
  // PostgreSQL 18: an empty list is off; all, or every one of receipt, authentication and authorization, is on.
  ["", false, null],
  ["all", true, null], ["setup_durations,all", true, null],
  ["receipt,authentication,authorization", true, null], [" Authorization , receipt,authentication, setup_durations", true, null],
  ["receipt", false, null], ["receipt,authentication", false, null], ["setup_durations", false, null],
  // Not a value this reads with certainty: unknown, never on or off. Not checked (undefined) for log_connections: as a
  // list, "t", "of" and "on,off" are words that aren't all three, so it reads off. "t" and "of" are boolean prefixes
  // that PostgreSQL 17 and older read as on and off; "on,off" Postgres refuses.
  ["t", undefined, null], ["of", undefined, null], ["2", null, null], ["receipt;authentication;authorization", null, null],
  ["receipt,authentication,authorization,", null, null], ["on,off", undefined, null],
];

test("Cloud SQL flags: each switch value reads as Postgres reads it, else unknown", async () => {
  for (const [value, connections, other] of CASES) {
    const s = await cloudsql({ log_connections: value, log_disconnections: value });
    if (connections !== undefined) assert.equal(s.log_connections, connections, `log_connections ${JSON.stringify(value)}`);
    assert.equal(s.log_disconnections, other, `log_disconnections ${JSON.stringify(value)}`);
  }
  // A flag that isn't text is unknown; a flag left out has the engine default, off.
  const odd = await cloudsql({ log_connections: true, log_disconnections: 1 });
  assert.equal(odd.log_connections, true);
  assert.equal(odd.log_disconnections, null);
  const none = await cloudsql({});
  assert.equal(none.log_connections, false);
  assert.equal(none.log_disconnections, false);
});

test("RDS parameter group: each switch value reads as Postgres reads it, else unknown", async () => {
  for (const [value, connections, other] of CASES) {
    const s = await rds({ log_connections: value, log_disconnections: value, "rds.force_ssl": value });
    const what = JSON.stringify(value);
    if (connections !== undefined) assert.equal(s.log_connections, connections, `log_connections ${what}`);
    assert.equal(s.log_disconnections, other, `log_disconnections ${what}`);
    assert.equal(s.ssl_enforced, other, `rds.force_ssl ${what}`);
  }
});

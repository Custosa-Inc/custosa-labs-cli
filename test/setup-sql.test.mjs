/* The SQL setup prints (shared.json's database blocks), run as printed on a throwaway Postgres cluster with a minimal
 * Supabase Storage shape (fixtures/supabase-storage-init.sql): the role, the Supabase bucket grants and policy, then the
 * read and write checks as the admin, and the shipped storage_buckets query through the real collector. A cluster made
 * with initdb in a temp dir (127.0.0.1 only, a free port, no socket); skipped with the reason when initdb or pg_ctl is
 * missing or the cluster won't start. */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import pg from "pg";
import { collectCatalog } from "../lib/inspector/catalog.mjs";
import { shippedQuerySql } from "../lib/inspector/catalogfacts.mjs";

const DB = JSON.parse(readFileSync(new URL("../lib/shared.json", import.meta.url), "utf8")).database;
const INIT = readFileSync(new URL("./fixtures/supabase-storage-init.sql", import.meta.url), "utf8");
const secret = () => randomBytes(18).toString("base64url");
const cleanups = [];
after(() => { for (const fn of cleanups.reverse()) { try { fn(); } catch { /* best effort */ } } });

async function freePort() {
  return new Promise((ok, no) => {
    const srv = createServer(); srv.unref(); srv.on("error", no);
    srv.listen(0, "127.0.0.1", () => { const { port } = srv.address(); srv.close(() => ok(port)); });
  });
}

async function startCluster() {
  const env = { ...process.env, LC_ALL: "C", LANG: "C" };
  const oneLine = (t) => String(t || "").replace(/\s+/g, " ").trim().slice(-300);
  const probe = spawnSync("initdb", ["--version"], { encoding: "utf8", env });
  if (probe.error || probe.status !== 0) return { skip: "initdb is not on PATH, so no throwaway Postgres cluster can be made" };
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "custosa-setup-pg-")));
  const data = join(dir, "data");
  const adminPw = secret();
  writeFileSync(join(dir, "pw"), adminPw + "\n", { mode: 0o600 });
  const init = spawnSync("initdb", ["-D", data, "-U", "postgres", "-A", "scram-sha-256", `--pwfile=${join(dir, "pw")}`,
    "-E", "UTF8", "--no-locale", "--no-sync"], { encoding: "utf8", env });
  rmSync(join(dir, "pw"), { force: true });
  if (init.status !== 0) { rmSync(dir, { recursive: true, force: true }); return { skip: `initdb failed: ${oneLine(init.stderr)}` }; }
  const port = await freePort();
  const start = spawnSync("pg_ctl", ["-D", data, "-l", join(dir, "log"), "-w", "-t", "30", "-o",
    `-p ${port} -c listen_addresses=127.0.0.1 -c unix_socket_directories='' -c fsync=off`, "start"], { encoding: "utf8", env });
  if (start.status !== 0) { rmSync(dir, { recursive: true, force: true }); return { skip: `pg_ctl could not start a temporary cluster: ${oneLine(start.stderr)}` }; }
  cleanups.push(() => { spawnSync("pg_ctl", ["-D", data, "-m", "immediate", "-w", "stop"], { env }); rmSync(dir, { recursive: true, force: true }); });
  const admin = new pg.Client({ host: "127.0.0.1", port, user: "postgres", database: "postgres", password: () => adminPw, ssl: false });
  await admin.connect();
  return { port, admin };
}

const cluster = await startCluster();
after(async () => { if (cluster.admin) await cluster.admin.end().catch(() => {}); });

test("the printed Supabase bucket SQL lets the shipped storage_buckets query read, and the read and write checks stay empty", { skip: cluster.skip || false }, async () => {
  const { admin, port } = cluster;
  const roPw = secret();
  await admin.query(INIT);
  await admin.query(DB.role.replace("YOUR_PASSWORD", roPw));
  const ro = { host: "127.0.0.1", port, dbname: "postgres", user: "phisc_ro", sslmode: "disable", sslrootcert: null };
  Object.defineProperty(ro, "password", { value: roPw, enumerable: false });
  const buckets = () => collectCatalog(ro, [{ query_id: "storage_buckets", sql: shippedQuerySql("storage_buckets"), row_limit: 500 }], { provider: "supabase" });

  // the policy alone isn't enough: without the grants the query can't read storage.buckets
  const policyOnly = DB.supabaseBuckets.split("\n").filter((l) => l.startsWith("CREATE POLICY")).join("\n");
  await admin.query(policyOnly);
  const before = await buckets();
  assert.notEqual(before.queries[0].status, "ok", JSON.stringify(before.queries[0]));
  await admin.query("DROP POLICY phisc_ro_read_buckets ON storage.buckets");

  // all three, in the printed order
  assert.deepEqual(DB.supabaseBuckets.split("\n").map((l) => l.split(" ").slice(0, 2).join(" ")), ["GRANT USAGE", "GRANT SELECT", "CREATE POLICY"]);
  await admin.query(DB.supabaseBuckets);
  const r = await buckets();
  assert.equal(r.preflight.passed, true, JSON.stringify(r.preflight));
  assert.equal(r.queries[0].status, "ok", JSON.stringify(r.queries[0]));
  assert.deepEqual(r.queries[0].rows.map((row) => row.bucket).sort(), ["avatars", "records"]);

  // the admin's checks, as printed
  assert.deepEqual((await admin.query(DB.readCheck)).rows, []);
  assert.deepEqual((await admin.query(DB.writeCheck)).rows, []);

  // the files stay closed: phisc_ro can't read storage.objects
  const asRo = new pg.Client({ host: "127.0.0.1", port, user: "phisc_ro", database: "postgres", password: () => roPw, ssl: false });
  await asRo.connect();
  try {
    await assert.rejects(asRo.query("SELECT * FROM storage.objects"), /permission denied for table objects/);
  } finally { await asRo.end(); }

  // a table inheriting from storage.buckets (its rows could be any data, read through the parent): the read check lists
  // storage.buckets again, and the inspector's preflight refuses it, so the query doesn't run
  await admin.query("CREATE TABLE public.child () INHERITS (storage.buckets)");
  try {
    assert.deepEqual((await admin.query(DB.readCheck)).rows.map((x) => `${x.nspname}.${x.relname}`), ["storage.buckets"]);
    const refused = await buckets();
    assert.equal(refused.preflight.passed, false, JSON.stringify(refused.preflight));
    assert.notEqual(refused.queries[0].status, "ok");
  } finally { await admin.query("DROP TABLE public.child"); }
});

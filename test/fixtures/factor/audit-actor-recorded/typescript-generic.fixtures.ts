// Fixtures for audit-actor-recorded (TypeScript). Made-up code only.
import knex from "knex";
import { Pool } from "pg";

// A knexfile's pool hook runs per connection, not per request (round bypass: knexfile.js is not a per-request file).
export const db = knex({
  client: "pg",
  pool: {
    afterCreate: (conn, done) => {
      // ruleid: audit-actor-recorded.typescript-generic.pool-context
      conn.query("SET app.user_id = 'service'", done);
    },
  },
});

// A pool's connect event is connection setup, never the signed-in user.
export const pool = new Pool({ connectionString: process.env.DATABASE_URL });
pool.on("connect", (client) => {
  // ruleid: audit-actor-recorded.typescript-generic.pool-context
  client.query("SELECT set_config('app.user_id', 'service', false)");
});

// A connection option fixes one actor for every request.
export const fixed = new Pool({
  // ruleid: audit-actor-recorded.typescript-generic.pool-context
  options: "-c app.user_id=00000000-0000-0000-0000-000000000000",
});

// Evidence: in one transaction that also writes, the signed-in user is set for the audit trigger to read.
export async function updateVisit(prisma, req, id, data) {
  return prisma.$transaction(async (tx) => {
    // ruleid: audit-actor-recorded.typescript-generic.request-context
    await tx.$executeRaw`SELECT set_config('app.user_id', ${req.user.id}, true)`;
    await tx.visit.update({ where: { id }, data });
  });
}

// Evidence: a checked-out client that began a transaction.
export async function withActor(req, res) {
  const client = await pool.connect();
  await client.query("BEGIN");
  // ruleid: audit-actor-recorded.typescript-generic.request-context-client
  // ok: audit-actor-recorded.typescript-generic.pool-context
  // ok: audit-actor-recorded.typescript-generic.session-level-context
  await client.query("SELECT set_config('app.user_id', $1, true)", [req.user.id]);
  await client.query("UPDATE visits SET status = 'seen' WHERE id = $1", [req.params.id]);
  await client.query("COMMIT");
  client.release();
}

// Evidence: concatenation of a request-scoped value inside a writing transaction.
export async function concatenated(knexdb, req) {
  await knexdb.transaction(async (trx) => {
    // ruleid: audit-actor-recorded.typescript-generic.request-context
    await trx.raw("SET LOCAL app.user_id = '" + req.user.id + "'");
    await trx("visits").insert({ status: "new" });
  });
}

// Bypasses (none is evidence).
export async function bypasses(req, prisma, client) {
  // The value comes from the body, the query string or a header.
  // ok: audit-actor-recorded.typescript-generic.request-context
  await db.query("select set_config('app.user_id', $1, true)", [req.body.userId]);
  // ok: audit-actor-recorded.typescript-generic.request-context
  await db.query("select set_config('app.user_id', $1, true)", [req.query.as]);
  // ok: audit-actor-recorded.typescript-generic.request-context
  await db.query("select set_config('app.user_id', $1, true)", [req.headers["x-user-id"]]);
  // The patient's id.
  const patient = await getPatient(req.params.id);
  // ok: audit-actor-recorded.typescript-generic.request-context
  await db.query("select set_config('app.user_id', $1, true)", [patient.id]);
  // A plain pool query with no transaction.
  // ok: audit-actor-recorded.typescript-generic.request-context
  await db.query("select set_config('app.user_id', $1, true)", [req.user.id]);
  // A transaction that sets the actor but writes nothing (the write runs in another one).
  await db.transaction(async () => {
    // ok: audit-actor-recorded.typescript-generic.request-context
    await db.query("select set_config('app.user_id', $1, true)", [req.user.id]);
  });
  await db.transaction(async () => {
    await db.query("insert into audit_log(action) values ('read')");
  });
  // A nested function nobody calls.
  function neverCalled() {
    return prisma.$transaction(async (tx) => {
      // ok: audit-actor-recorded.typescript-generic.request-context
      await tx.$executeRaw`select set_config('app.user_id', ${req.user.id}, true)`;
      await tx.visit.create({ data: {} });
    });
  }
  // Under an environment condition.
  if (process.env.NEVER_TRUE) {
    await prisma.$transaction(async (tx) => {
      // ok: audit-actor-recorded.typescript-generic.request-context
      await tx.$executeRaw`select set_config('app.user_id', ${req.user.id}, true)`;
      await tx.visit.create({ data: {} });
    });
  }
  // A constant actor, an unrelated setting, a logged string, dead code.
  // ok: audit-actor-recorded.typescript-generic.request-context
  await db.query("select set_config('app.user_id', 'system', true)");
  // ok: audit-actor-recorded.typescript-generic.request-context
  await db.query("select set_config('app.timezone', $1, true)", [req.user.id]);
  // ok: audit-actor-recorded.typescript-generic.request-context
  console.log("select set_config('app.user_id', $1, true)");
  // A client that never began a transaction.
  // ok: audit-actor-recorded.typescript-generic.request-context-client
  await client.query("SELECT set_config('app.user_id', $1, true)", [req.user.id]);
  // A concatenated body value; a body under another request name.
  await prisma.$transaction(async (tx) => {
    // ok: audit-actor-recorded.typescript-generic.request-context
    await tx.$executeRawUnsafe("select set_config('app.user_id', '" + req.body.userId + "', true)");
    // ok: audit-actor-recorded.typescript-generic.request-context
    await tx.$executeRaw`select set_config('app.user_id', ${r.body.uid}, true)`;
    // Commented-out SQL.
    // ok: audit-actor-recorded.typescript-generic.request-context
    await tx.query("/* select set_config('app.user_id', $1, true) */ select 1", [req.user.id]);
    await tx.visit.create({ data: {} });
  });
  // A logger's query method.
  // ok: audit-actor-recorded.typescript-generic.request-context
  logger.query("select set_config('app.user_id', $1, true)", [req.user.id]);
  return neverCalled;
}

// A seed script with constant actors.
export async function seed() {
  await db.transaction(async (tx) => {
    // ok: audit-actor-recorded.typescript-generic.request-context
    await tx.query("select set_config('app.user_id', $1, true)", ["system"]);
    // ok: audit-actor-recorded.typescript-generic.request-context
    await tx.query("select set_config('app.user_id', $1, true)", [SYSTEM_ID]);
    await tx.query("insert into visits(status) values ('new')");
  });
}

// A body value in a serverless handler.
export async function lambdaHandler(event) {
  await sql.begin(async (tx) => {
    // ok: audit-actor-recorded.typescript-generic.request-context
    await tx`select set_config('app.user_id', ${event.body.userId}, true)`;
    await tx`insert into visits(status) values ('new')`;
  });
}

// Session-level set_config on a pooled connection carries one user's id into the next request.
export async function leaky(req, client) {
  // ruleid: audit-actor-recorded.typescript-generic.session-level-context
  await client.query("SELECT set_config('app.user_id', $1, false)", [req.user.id]);
}

export async function recordAccess(req, prisma, supabase, patient, actor, user, me, session, claims, p) {
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { actorUserId: req.user.id, entityId: patient.id, action: "READ" } });
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { userId: req.user.id, action: "read", patientId: p } });
  // Prisma relation connect to the signed-in user.
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { user: { connect: { id: req.user.id } }, action: "read" } });
  // A write with no actor says nothing about who acted.
  // No actor key, or an actor through a local name, drops the row (no item).
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { entityId: patient.id, action: "READ" } });
  // The actor key sits under select, not data.
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { action: "read" }, select: { userId: true } });
  // A literal behind as.
  // ruleid: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { action: "read", userId: "system" as string } }); // ts-only
  // The key nested under another object and holding the patient's id.
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { action: "read", meta: { userId: patient.id } } });
  // A local name, whatever it holds.
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { userId: user.id, action: "read" } });
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { actorId: actor.id, action: "read" } });
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { userId: user, action: "read" } });
  // Conditionals and calls on the body.
  // ruleid: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { userId: req.user ? req.user.id : req.body.userId, action: "read" } });
  // ruleid: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { userId: req.user?.id ?? req.body.userId, action: "read" } });
  // ruleid: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { userId: getUser(req.body), action: "read" } });
  // ruleid: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { userId: auth(req.body.token).sub, action: "read" } });
  // A key holding the request user makes the others subjects; claims and the session id are not the user.
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { doctorId: req.user.id, userId: req.body.u, action: "read" } });
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { who: claims.sub, action: "read" } });
  // ruleid: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { userId: req.session.id, action: "read" } });
  // Shorthand data built elsewhere: an item, never controlled.
  const data = { action: "read" };
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data });
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor-many
  await prisma.auditLog.createMany({ data: [{ action: "read" }] });
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor-many
  await prisma.auditLog.createMany({ data: [{ action: "read", userId: req.user.id }] });
  // A query-string object and a bare session.
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor-from
  await supabase.from("audit_logs").insert({ user_id: me.id, action: "read" });
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor-from
  await supabase.from("audit_log").insert({ performed_by: session, action: "read" });
  await supabase.from("audit_log").insert({ action: "read", user_id: null! }); // ts-only
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor-from
  await supabase.from("audit_log").insert([{ action: "read" }]);
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor-from
  await supabase.from("access_logs").insert({ patient_id: patient.id, doctor_id: (await supabase.auth.getUser()).data.user.id });
  // A row built elsewhere can't be read here: not an item (dataflow, needs_review).
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor-from
  await supabase.from("ai_audit_log").insert(entry);
}

// A helper whose ctx comes from anywhere.
async function audit(prisma, ctx) {
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { userId: ctx.user.id, action: "read" } });
}

// More cases (none is evidence or a control).
// h1a: set_config before BEGIN; h1e: after COMMIT; h1h: ROLLBACK before the write; h1f: BEGIN on another client.
export async function h1a(req) {
  const c = await pool.connect();
  // ok: audit-actor-recorded.typescript-generic.request-context-client
  await c.query("select set_config('app.user_id', $1, true)", [req.user.id]);
  await c.query("BEGIN");
  await c.query("update patients set name = $1 where id = $2", [req.body.name, req.params.id]);
}
export async function h1e(req) {
  const c = await pool.connect();
  await c.query("BEGIN");
  await c.query("COMMIT");
  // ok: audit-actor-recorded.typescript-generic.request-context-client
  await c.query("select set_config('app.user_id', $1, true)", [req.user.id]);
}
export async function h1f(req) {
  const c = await pool.connect();
  const d = await pool.connect();
  await d.query("BEGIN");
  // ok: audit-actor-recorded.typescript-generic.request-context-client
  await c.query("select set_config('app.user_id', $1, true)", [req.user.id]);
}
export async function h1h(req) {
  const c = await pool.connect();
  await c.query("BEGIN");
  // ok: audit-actor-recorded.typescript-generic.request-context-client
  await c.query("select set_config('app.user_id', $1, true)", [req.user.id]);
  await c.query("ROLLBACK");
  await c.query("update patients set name = $1 where id = $2", [req.body.name, req.params.id]);
}
// h1b, h1g: the handler's real write runs outside the transaction.
export async function h1b(req) {
  await db.transaction(async (tx) => {
    // ok: audit-actor-recorded.typescript-generic.request-context
    await tx.query("select set_config('app.user_id', $1, true)", [req.user.id]);
    await tx.query("insert into cache_entries (k, v) values ($1, $2)", ["k", "v"]);
  });
  await db.query("update patients set name = $1 where id = $2", [req.body.name, req.params.id]);
}
// h1c: the write isn't on the transaction; h1d: set_config isn't on the transaction.
export async function h1c(req) {
  await db.transaction(async (tx) => {
    // ok: audit-actor-recorded.typescript-generic.request-context
    await tx.query("select set_config('app.user_id', $1, true)", [req.user.id]);
    await db.query("insert into audit_log (action) values ($1)", ["read"]);
  });
}
export async function h1d(req) {
  await db.transaction(async (tx) => {
    // ok: audit-actor-recorded.typescript-generic.request-context
    await db.query("select set_config('app.user_id', $1, true)", [req.user.id]);
    await tx.patient.update({ where: { id: req.params.id }, data: req.body });
  });
}
// h2b, h2e: req.user replaced from the body before the write: the rows are not items, and no evidence.
export async function h2b(req, prisma, supabase) {
  req.user = req.body.user;
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { userId: req.user.id, action: "update" } });
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor-from
  await supabase.from("audit_log").insert({ user_id: req.user.id, action: "update" });
}
export async function h2e(req) {
  Object.assign(req, { user: req.body.user });
  const c = await pool.connect();
  await c.query("BEGIN");
  // ok: audit-actor-recorded.typescript-generic.request-context-client
  await c.query("select set_config('app.user_id', $1, true)", [req.user.id]);
}
// h2a: the whole user object where an id belongs.
export async function h2a(req, prisma) {
  // No actor key, or an actor through a local name, drops the row (no item).
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { userId: req.user, action: "read" } });
}
// u1, u2: non-ASCII audit table and model names are items too.
export async function u1(supabase, prisma) {
  // ruleid: audit-actor-recorded.typescript-generic.audit-write-actor-from
  await supabase.from("auditoría_log").insert({ user_id: "system", action: "read" });
  // ruleid: audit-actor-recorded.typescript-generic.audit-write-actor-from
  await supabase.from("journal_d_audit_accès").insert({ user_id: "system", action: "read" });
  // ruleid: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditoría.create({ data: { userId: "system", action: "read" } });
}

// More cases.
// The actor set after the transaction's write attributes nothing to that write.
export async function setAfterWrite(prisma, req) {
  await prisma.$transaction(async (tx) => {
    await tx.visit.update({ where: { id: req.params.id }, data: { status: "seen" } });
    // ok: audit-actor-recorded.typescript-generic.request-context
    await tx.$executeRaw`SELECT set_config('app.user_id', ${req.user.id}, true)`;
  });
}
// A write before the set_config, even with another after it.
export async function writeBeforeAndAfter(prisma, req) {
  await prisma.$transaction(async (tx) => {
    await tx.visit.update({ where: { id: req.params.id }, data: { status: "seen" } });
    // ok: audit-actor-recorded.typescript-generic.request-context
    await tx.$executeRaw`SELECT set_config('app.user_id', ${req.user.id}, true)`;
    await tx.note.create({ data: { body: "x" } });
  });
}
// END closes the transaction like COMMIT.
export async function endedFirst(req) {
  const c = await pool.connect();
  await c.query("BEGIN");
  await c.query("END");
  // ok: audit-actor-recorded.typescript-generic.request-context-client
  await c.query("select set_config('app.user_id', $1, true)", [req.user.id]);
  await c.query("update patients set name = $1 where id = $2", [req.body.name, req.params.id]);
}
export async function endTransactionFirst(req) {
  const c = await pool.connect();
  await c.query("BEGIN");
  await c.query("END TRANSACTION");
  // ok: audit-actor-recorded.typescript-generic.request-context-client
  await c.query("select set_config('app.user_id', $1, true)", [req.user.id]);
  await c.query("update patients set name = $1 where id = $2", [req.body.name, req.params.id]);
}
// A write between BEGIN and the set_config.
export async function writeBetween(req) {
  const c = await pool.connect();
  await c.query("BEGIN");
  await c.query("update patients set name = $1 where id = $2", [req.body.name, req.params.id]);
  // ok: audit-actor-recorded.typescript-generic.request-context-client
  await c.query("select set_config('app.user_id', $1, true)", [req.user.id]);
  await c.query("update visits set status = 'seen' where id = $1", [req.params.id]);
}
// req["user"] replaced in the same handler, before the write: no evidence, and the audit row is not an item.
export async function bracketReassign(req, prisma) {
  req["user"] = req.body.user;
  const c = await pool.connect();
  await c.query("BEGIN");
  // ok: audit-actor-recorded.typescript-generic.request-context-client
  await c.query("select set_config('app.user_id', $1, true)", [req.user.id]);
  await c.query("update patients set name = $1 where id = $2", [req.body.name, req.params.id]);
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { userId: req.user.id, action: "update" } });
}
// An audit write on the outer client inside a transaction callback: a row carrying the request user's id keeps its
// control.
export async function outerWrite(prisma, req) {
  await prisma.$transaction(async (tx) => {
    await tx.$executeRaw`SELECT set_config('app.user_id', ${req.user.id}, true)`;
    // ok: audit-actor-recorded.typescript-generic.audit-write-actor
    await prisma.auditLog.create({ data: { userId: req.user.id, action: "update" } });
    // ok: audit-actor-recorded.typescript-generic.audit-write-actor-many
    await prisma.auditLog.createMany({ data: [{ userId: req.user.id, action: "update" }] });
    // ok: audit-actor-recorded.typescript-generic.audit-write-actor
    await tx.auditLog.create({ data: { userId: req.user.id, action: "update" } });
  });
}

// More cases.
// A logout after the audit write leaves the row controlled.
export async function logoutAfter(req, prisma) {
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { userId: req.user.id, action: "logout" } });
  req.user = null;
}
// A user loaded from the session before the write: the row is not an item.
export async function loadedBefore(req, prisma) {
  req.user = await prisma.user.findUnique({ where: { id: req.session.userId } });
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { userId: req.user.id, action: "read" } });
}
// Other reassignments and shadowing before the write.
export async function otherReassign(req, prisma, x, y) {
  if (x) req.user = y;
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { userId: req.user.id, action: "read" } });
}
export async function idReassign(req, prisma) {
  req.user.id = req.body.id;
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { userId: req.user.id, action: "read" } });
}
export async function nullishReassign(req, prisma, y) {
  req.user ??= y;
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { userId: req.user.id, action: "read" } });
}
export async function definePropertyReassign(req, prisma, y) {
  Object.defineProperty(req, "user", { value: y });
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { userId: req.user.id, action: "read" } });
}
export async function shadowedJob(job, prisma) {
  const req = job.data;
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { userId: req.user.id, action: "read" } });
}
// The actor or bound value from the request body.
export async function bodyActor(req, prisma) {
  // ruleid: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { userId: req.body.userId, action: "read" } });
  await prisma.$transaction(async (tx) => {
    // ok: audit-actor-recorded.typescript-generic.request-context
    await tx.$executeRaw`SELECT set_config('app.user_id', ${req.body.userId}, true)`;
    await tx.visit.update({ where: { id: req.params.id }, data: { status: "seen" } });
  });
}
// A write on the outer client, a helper call or pool.query inside the transaction callback,
// or a helper outside it: none is evidence.
export async function b1(prisma, req) {
  await prisma.$transaction(async (tx) => {
    // ok: audit-actor-recorded.typescript-generic.request-context
    await tx.$executeRaw`SELECT set_config('app.user_id', ${req.user.id}, true)`;
    await tx.visit.update({ where: { id: req.params.id }, data: { status: "seen" } });
    await prisma.patient.update({ where: { id: req.params.id }, data: req.body });
  });
}
export async function b2(prisma, req) {
  await prisma.$transaction(async (tx) => {
    // ok: audit-actor-recorded.typescript-generic.request-context
    await tx.$executeRaw`SELECT set_config('app.user_id', ${req.user.id}, true)`;
    await tx.visit.update({ where: { id: req.params.id }, data: { status: "seen" } });
    await savePatient(req.body);
  });
}
export async function b2outside(prisma, req) {
  await prisma.$transaction(async (tx) => {
    // ok: audit-actor-recorded.typescript-generic.request-context
    await tx.$executeRaw`SELECT set_config('app.user_id', ${req.user.id}, true)`;
    await tx.visit.update({ where: { id: req.params.id }, data: { status: "seen" } });
  });
  await savePatient(req.body);
}
export async function b4(prisma, req) {
  await prisma.$transaction(async (tx) => {
    // ok: audit-actor-recorded.typescript-generic.request-context
    await tx.$executeRaw`SELECT set_config('app.user_id', ${req.user.id}, true)`;
    await tx.visit.update({ where: { id: req.params.id }, data: { status: "seen" } });
    await pool.query("update patients set name = $1 where id = $2", [req.body.name, req.params.id]);
  });
}
// A conditional reassignment before the client sequence voids the evidence too.
export async function clientAfterReassign(req, x, y) {
  if (x) req.user = y;
  const c = await pool.connect();
  await c.query("BEGIN");
  // ok: audit-actor-recorded.typescript-generic.request-context-client
  await c.query("select set_config('app.user_id', $1, true)", [req.user.id]);
  await c.query("update patients set name = $1 where id = $2", [req.body.name, req.params.id]);
}

// An item only when the actor seen is wrong (or right).
export async function ruling2(req, prisma, userId) {
  // Through a local name: no item.
  const session = await getServerSession(authOptions);
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { userId: session.user.id, action: "read" } });
  const { user } = req;
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { userId: user.id, action: "read" } });
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { userId, action: "read" } });
  // Wrong values seen: a body fallback, params, a header.
  // ruleid: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { userId: req.body.as || req.user.id, action: "read" } });
  // ruleid: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { userId: req.params.uid, action: "read" } });
  // ruleid: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { userId: req.headers["x-user-id"], action: "read" } });
  // ruleid: audit-actor-recorded.typescript-generic.audit-write-actor-many
  await prisma.auditLog.createMany({ data: [{ userId: req.body.u, action: "read" }] });
}

// Evidence false controls closed.
// A concatenated fallback mixing a body value is not the session value.
export async function a7(knexdb, req) {
  await knexdb.transaction(async (trx) => {
    // ok: audit-actor-recorded.typescript-generic.request-context
    await trx.raw("SET LOCAL app.user_id = '" + (req.body.as || req.user.id) + "'");
    await trx("visits").insert({ status: "new" });
  });
}
// The actor is set on the client but a write goes through pool.query.
export async function b4client(req) {
  const c = await pool.connect();
  await c.query("BEGIN");
  // ok: audit-actor-recorded.typescript-generic.request-context-client
  await c.query("select set_config('app.user_id', $1, true)", [req.user.id]);
  await c.query("update visits set status = 'seen' where id = $1", [req.params.id]);
  await pool.query("update patients set name = $1 where id = $2", [req.body.name, req.params.id]);
}
// Variants: a helper whose result is kept or returned, or a repository save, inside the callback.
export async function b2const(prisma, req) {
  await prisma.$transaction(async (tx) => {
    // ok: audit-actor-recorded.typescript-generic.request-context
    await tx.$executeRaw`SELECT set_config('app.user_id', ${req.user.id}, true)`;
    await tx.visit.update({ where: { id: req.params.id }, data: { status: "seen" } });
    const saved = await savePatient(req.body);
  });
}
export async function b2return(prisma, req) {
  await prisma.$transaction(async (tx) => {
    // ok: audit-actor-recorded.typescript-generic.request-context
    await tx.$executeRaw`SELECT set_config('app.user_id', ${req.user.id}, true)`;
    await tx.visit.update({ where: { id: req.params.id }, data: { status: "seen" } });
    return savePatient(req.body);
  });
}
export class VisitService {
  async b2repo(prisma, req) {
    await prisma.$transaction(async (tx) => {
      // ok: audit-actor-recorded.typescript-generic.request-context
      await tx.$executeRaw`SELECT set_config('app.user_id', ${req.user.id}, true)`;
      await tx.visit.update({ where: { id: req.params.id }, data: { status: "seen" } });
      await this.repo.save(req.body);
    });
  }
}
// return prisma.$transaction(...) with a helper write before it.
export async function returnedTx(prisma, req) {
  await savePatient(req.body);
  return prisma.$transaction(async (tx) => {
    // ok: audit-actor-recorded.typescript-generic.request-context
    await tx.$executeRaw`SELECT set_config('app.user_id', ${req.user.id}, true)`;
    await tx.visit.update({ where: { id: req.params.id }, data: { status: "seen" } });
  });
}

// A service actor held in a local object that shadows req, in an outer block. No item.
export async function serviceJob(prisma) {
  const req = { user: { id: "service-account" } };
  await runInBatch(async () => {
    // ok: audit-actor-recorded.typescript-generic.audit-write-actor
    await prisma.auditLog.create({ data: { userId: req.user.id, action: "sync" } });
  });
}
export async function serviceJobLet(prisma) {
  let req = { user: { id: "service-account" } };
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { userId: req.user.id, action: "sync" } });
}
export async function overwrittenParam(req, prisma) {
  req = { user: { id: "service-account" } };
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { userId: req.user.id, action: "sync" } });
}

// Subject keys beside an explicit actor key holding the request user.
export async function subjects(req, prisma, supabase) {
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { performedBy: req.user.id, staffId: req.params.staffId, action: "update" } });
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { actorId: req.user.id, userId: req.params.userId, action: "update" } });
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor-from
  await supabase.from("audit_log").insert({ actor_id: req.user.id, user_id: req.params.userId, action: "update" });
  // Without an explicit actor key, a userId from params is the actor and is wrong.
  // ruleid: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { userId: req.params.userId, action: "update" } });
  // An explicit actor key that is wrong still fails.
  // ruleid: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { actorId: req.body.actorId, userId: req.user.id, action: "update" } });
}
// A helper after the transaction (kept, returned, or on this.repo) means no evidence.
export async function helperAfterConst(prisma, req) {
  await prisma.$transaction(async (tx) => {
    // ok: audit-actor-recorded.typescript-generic.request-context
    await tx.$executeRaw`SELECT set_config('app.user_id', ${req.user.id}, true)`;
    await tx.visit.update({ where: { id: req.params.id }, data: { status: "seen" } });
  });
  const saved = await savePatient(req.body);
  return saved;
}
export async function helperAfterReturn(prisma, req) {
  await prisma.$transaction(async (tx) => {
    // ok: audit-actor-recorded.typescript-generic.request-context
    await tx.$executeRaw`SELECT set_config('app.user_id', ${req.user.id}, true)`;
    await tx.visit.update({ where: { id: req.params.id }, data: { status: "seen" } });
  });
  return savePatient(req.body);
}
export class PatientsController {
  async helperAfterRepo(prisma, req) {
    await prisma.$transaction(async (tx) => {
      // ok: audit-actor-recorded.typescript-generic.request-context
      await tx.$executeRaw`SELECT set_config('app.user_id', ${req.user.id}, true)`;
      await tx.visit.update({ where: { id: req.params.id }, data: { status: "seen" } });
    });
    this.repo.update(req.params.id, req.body);
  }
}
// return await prisma.$transaction(...) with nothing else in the handler is evidence.
export async function returnedAwaitTx(prisma, req) {
  return await prisma.$transaction(async (tx) => {
    // ruleid: audit-actor-recorded.typescript-generic.request-context
    await tx.$executeRaw`SELECT set_config('app.user_id', ${req.user.id}, true)`;
    await tx.visit.update({ where: { id: req.params.id }, data: { status: "seen" } });
  });
}

// Case u1.
export class S {
  async get(user) {
    await this.prisma.auditLog.create({ data: { actorUserId: user.userId, actorStaffId: user.staffId ?? undefined, actionName: "READ" } });
  }
}
// Case u2.
export class S {
  async get(user) {
    await this.prisma.auditLog.create({ data: { actorUserId: user.userId, actorStaffId: user.staffId, actionName: "READ" } });
  }
}
// Case u3.
export async function handler(req, res) {
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { actorId: req.user?.id ?? null, action: "login_failed" } });
}
// Case b1.
export async function handler(req, res) {
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { actorId: req.user.id, staffId: patient.assignedStaffId, action: "read" } });
}
// Case b2.
export async function handler(req, res) {
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { actorId: req.user!.id, action: "read" } }); // ts-only
}
// Case b3.
export async function handler(req, res) {
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { actorId: (req.user as User).id, patientId: req.params.id, userId: req.params.uid } }); // ts-only
}
// Case b4.
export async function handler(req, res) {
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { actorId: req.user!.id, userId: req.body.userId, action: "update" } }); // ts-only
}
// Case b5.
export async function handler(req, res) {
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { actorId: String(req.user.id), userId: req.body.userId, action: "update" } });
}
// Case b6.
export async function handler(req, res) {
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { actorId: req.user.id, user_id: patient.userId, action: "read" } });
}
// Case b7.
export async function handler(req, res) {
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { actorId: req.session.user.id, userId: req.body.userId, action: "update" } });
}
// Case b8.
export async function handler(req, res) {
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { actorUserId: req.user.id, doctorId: patient.doctorId, action: "read" } });
}
// Case c3.
export async function handler(req, res) {
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { actorId: req.user?.id!, userId: req.body.userId, action: "update" } }); // ts-only
}
// Case c4.
export async function handler(req, res) {
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { userId: req.user.id, doctorId: patient.doctorId, action: "view" } });
}
// Case a1.
export async function handler(ctx) {
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { actorId: ctx.state.user.id, action: "read" } });
}
// Case a2.
export async function handler(req, res) {
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { actorId: req.user.id, userId: req.params.userId, action: "update" } });
}
// Case a3.
export async function handler(req, res) {
  // ruleid: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { actorId: req.body.actorId, userId: req.user.id, action: "update" } });
}
// Case a4.
export async function handler(req, res) {
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor-many
  await prisma.auditLog.createMany({ data: [{ actorId: req.user.id, patientId: p.id, action: "read" }] });
}
// Case a5.
export async function handler(req, res) {
  // ruleid: audit-actor-recorded.typescript-generic.audit-write-actor-many
  await prisma.auditLog.createMany({ data: [{ actorId: "system", action: "read" }] });
}
// Case a6.
export async function handler(req, res) {
  // ruleid: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { actorId: req.user.id, performedBy: req.body.by, action: "read" } });
}
// Case a7.
export async function handler(req, res) {
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { actorId: req.user.id, userId: "system", action: "read" } });
}
// Case a9.
export async function handler(req, res) {
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { actor: { connect: { id: req.user.id } }, userId: req.query.uid, action: "read" } });
}
// Case a10.
export async function handler(req, res) {
  // ruleid: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { who: req.user.id, actorId: req.headers["x-actor"], action: "read" } });
}
// Case a11.
export async function handler(req, res) {
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { actorId: req.user!.id, staffId: patient.assignedStaffId, action: "read" } }); // ts-only
}
// Case a12.
export async function handler(req, res) {
  // ruleid: audit-actor-recorded.typescript-generic.audit-write-actor
  await db.auditLog.create({ data: { actorId: req.user?.id ?? "anonymous", action: "read" } });
}
// Case a13.
export async function handler(req, res) {
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { userId: req.user.id, actorId: req.user.id, targetUserId: req.body.id } });
}
// Case a14.
export async function handler(req, res) {
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { actor_id: req.user.id, user: req.body.user, action: "read" } });
}
// Case a15.
export async function handler(req, res) {
  await prisma.auditLog.create({ data: { actorId: req.user.id, ...req.body } });
}
// Case x1.
export async function handler(req, res) {
  const actor = req.body.actor;
  await prisma.auditLog.create({ data: { actorId: actor, userId: req.body.userId } });
}
// Case x2.
export async function handler(req, res) {
  // ruleid: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { actorId: req.user.id, actor: "system" } });
}
// Case x3.
export async function handler(req, res) {
  // ruleid: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { actorId: req.user.id, changed_by: req.cookies.uid } });
}
// Case x4.
export async function handler(req, res) {
  // ruleid: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { actorId: req.auth.sub, userId: req.params.id, actor_user_id: patientRecord.ownerId } });
}

// Case u1.
export async function handler(req, res) {
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { actorId: req.user.id, performedBy: req.user.id, action: "read" } });
}
// Case u2.
export async function handler(req, res) {
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { actorId: req.user.id, performedBy: req.session.user.id, action: "read" } });
}
// Case u3.
export async function handler(req, res) {
  await prisma.auditLog.create({ data: { actorId: req.user?.id ?? req.session.user.id, action: "read" } });
}
// Case u4.
export async function handler(req, res) {
  await prisma.auditLog.create({ data: { actorId: req.auth?.userId ?? req.user.id, action: "read" } });
}
// Case u5.
export async function handler(req, res) {
  await prisma.auditLog.create({ data: { actorId: req.user ? req.user.id : req.session.user.id, action: "read" } });
}
// Case u6.
export async function handler(req, res) {
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await Promise.all([prisma.patient.findMany(), prisma.auditLog.create({ data: { actorId: req.user.id, action: "read" } })]);
}
// Case u7.
export async function handler(req, res) {
  await prisma.auditLog.create({ data: { actorId: res.locals.user.id, action: "read" } });
}
// Case u8.
export async function handler(req, res) {
  const user = req.user; await prisma.auditLog.create({ data: { actorId: user.id, action: "read" } });
}
// Case u9.
export async function handler(req, res) {
  const userId = req.user.id; await prisma.auditLog.create({ data: { actorId: userId, userId: req.params.id, action: "read" } });
}
// Case u10.
export async function handler(req, res) {
  const { id } = req.user; await prisma.auditLog.create({ data: { actorId: id, action: "read" } });
}
// Case u11.
export async function handler(req, res) {
  const session = await getServerSession(authOptions); await prisma.auditLog.create({ data: { actorId: session.user.id, action: "read" } });
}
// Case u12.
export async function handler(req, res) {
  const { userId } = auth(); await prisma.auditLog.create({ data: { actorId: userId, patientId: req.params.id, action: "read" } });
}
// Case u13.
export async function handler(req, res) {
  await prisma.auditLog.create({ data: { actorId: getActor(req), userId: req.body.userId, action: "update" } });
}
// Case u14.
export async function handler(req, res) {
  await prisma.auditLog.create({ data: { actorId: actorOf(req), action: "read" } });
}
function actorOf(req) { return req.user.id; }
// Case u15.
export async function handler(req, res) {
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { performedBy: req.user.id, actorId: req.user?.id ?? null, action: "read" } });
}
// Case u16.
export async function handler(req, res) {
  await prisma.auditLog.create({ data: { actorId: req.user.id, performedBy: req.user.email, action: "read" } });
}
// Case u17.
export async function handler(req, res) {
  await prisma.auditLog.create({ data: { actorEmail: req.user.email, action: "read" } });
}
// Case u18.
export async function handler(req, res) {
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { userId: req.user.id, targetUserId: req.params.id, ipAddress: req.ip, userAgent: req.headers["user-agent"], action: "read" } });
}
// Case u19.
export async function handler(req, res) {
  await prisma.auditLog.create({ data: { actorId: ctx.session.user.id, action: "read" } });
}
// Case u20.
export async function handler(req, res) {
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { actorId: req.user.sub, action: "read" } });
}
// Case u21.
export async function handler(req, res) {
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { actorId: req.auth.userId, action: "read" } });
}
// Case u22.
export async function handler(req, res) {
  await prisma.auditLog.create({ data: { actorId: user.id, action: "read" } });
}
// Case u23.
export async function handler(req, res) {
  await prisma.auditLog.create({ data: { actorId: req.user._id, action: "read" } });
}
// Case u24.
export async function handler(req, res) {
  await AuditLog.create({ actor: req.user._id, action: "read" });
}
// Case u25.
export async function handler(req, res) {
  await prisma.auditLog.create({ data: { actorId: session?.user?.id, action: "read" } });
}
// Case u26.
export async function handler(req, res) {
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { actorId: req.user.id, actorRole: req.user.role, action: "read" } });
}
// Case u27.
export async function handler(req, res) {
  await prisma.auditLog.create({ data: { actorId: actor.id, action: "read", userId: req.body.userId } });
}
// Case u28.
export async function handler(req, res) {
  await prisma.auditLog.create({ data: { userId: session.user.id, action: "read", details: { userId: req.body.userId } } });
}
// Case x1.
export async function handler(req, res) {
  await prisma.auditLog.create({ data: { actorId: `${req.user.id}`, action: "read" } });
}
// Case x2.
export async function handler(req, res) {
  await prisma.auditLog.create({ data: { actorId: req.session.userId, action: "read" } });
}
// Case x3.
export async function handler(req, res) {
  await prisma.auditLog.create({ data: { actorId: req.user ? req.user.id : null, action: "read" } });
}
// Case x4.
export async function handler(req, res) {
  // ruleid: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { actorId: req.user?.id ?? undefined, performedBy: req.user?.email ?? "unknown", action: "read" } });
}
// Case x5.
export async function handler(req, res) {
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { actorId: req.user.id, details: { by: req.body.by }, action: "read" } });
}
// Case x6.
export async function handler(req, res) {
  await prisma.auditLog.create({ data: { actorId: lodashGet(req, "user.id"), action: "read" } });
}
// Case x7.
export async function handler(req, res) {
  await prisma.auditLog.create({ data: { actorId: Number(req.user.id), action: "read" } });
}
// Case x8.
export async function handler(req, res) {
  await prisma.auditLog.create({ data: { actorId: req.user.id.toString(), action: "read" } });
}
// Case x9.
export async function handler(req, res) {
  await prisma.auditLog.create({ data: { actor: req.user.email, action: "read" } });
}
// Case x10.
export async function handler(req, res) {
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { userId: req.user?.id || null, action: "read" } });
}
// Case x11.
export async function handler(req, res) {
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { user: { connect: { id: req.user.id } }, action: "read" } });
}
// Case x12.
export async function handler(req, res) {
  // ok: audit-actor-recorded.typescript-generic.audit-write-actor
  await prisma.auditLog.create({ data: { actorId: req.user.id, actorType: "USER", action: "read" } });
}
// Case x13.
export async function handler(req, res) {
  await prisma.auditLog.create({ data: { actorId: req.user?.id ?? req.session?.userId ?? null, action: "read" } });
}
// Case x14.
export async function handler(req, res) {
  await prisma.auditLog.create({ data: { actorId: parseInt(req.user.id, 10), action: "read" } });
}

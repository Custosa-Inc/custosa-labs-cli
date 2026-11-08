// Fixtures for access-audit-log (Next.js route handlers). Made-up code only.

// A read of patient data with no access record.
// ruleid: access-audit-log.tsx-nextjs.read-handler
export async function GET(request) {
  const visits = await db.visit.findMany({ where: { patientId: request.nextUrl.searchParams.get("id") } });
  return Response.json(visits);
}

// ok: access-audit-log.tsx-nextjs.read-handler
export const GET = async (request, { params }) => {
  const patient = await db.patient.findUnique({ where: { id: params.id } });
  await supabase.from("access_logs").insert({ patient_id: patient.id, user_id: session.userId, action: "read" });
  return Response.json(patient);
};

// A wrapped handler is a read handler; its control is inside the wrapped function or an audit wrapper.
// ruleid: access-audit-log.tsx-nextjs.read-handler
export const GET = withAuth(async (req) => Response.json(await prisma.patient.findMany()));
// An audit-named middleware, wrapper or decorator drops the item (never a fail).
// ok: access-audit-log.tsx-nextjs.read-handler
export const GET = withAudit(async (req) => Response.json(await prisma.patient.findMany()));

// A function re-exported as GET.
// ruleid: access-audit-log.tsx-nextjs.read-handler-reexport
async function handler(req) { return Response.json(await prisma.patient.findMany()); }
// An audit-named call in the handler is evidence for review, never a fail: no item.
// ok: access-audit-log.tsx-nextjs.read-handler-reexport
async function auditedHandler(req) { await recordAccess(req, "patients"); return Response.json(await prisma.patient.findMany()); }
// ruleid: access-audit-log.tsx-nextjs.read-handler-reexport
function plainHandler(req) { return Response.json([]); }
// ok: access-audit-log.tsx-nextjs.read-handler-reexport
function helper(req) { return Response.json([]); }
export { handler as GET, auditedHandler as GET, plainHandler as GET };

// A write handler is judged by its own trigger or audit write, not as a read.
// ok: access-audit-log.tsx-nextjs.read-handler
export async function POST(request) {
  return Response.json(await db.visit.create({ data: await request.json() }));
}

export async function readChart(db, patient) {
  // A query flagged not to be logged is counter-evidence.
  // ruleid: access-audit-log.tsx-nextjs.log-flag-off
  await db.query("select * from patients where id = $1", [patient.id], { log: false });
  // ruleid: access-audit-log.tsx-nextjs.log-flag-off
  await db.patients.findOne(patient.id, { audit: false });
  // A dialog or logger option is not an audit flag.
  // ok: access-audit-log.tsx-nextjs.log-flag-off
  openModal({ dialog: false, logger: false });
}


// Case n1.
export async function POST(req) {
  await auditLog('create');
  return Response.json({});
}
// ruleid: access-audit-log.tsx-nextjs.read-handler
export async function GET(req) {
  return Response.json(await prisma.patient.findMany());
}
// Case n4.
// ok: access-audit-log.tsx-nextjs.read-handler
export const GET = async (req) => {
  const unused = async () => { await auditLog('read'); };
  return Response.json(await prisma.patient.findMany());
};
// ruleid: access-audit-log.tsx-nextjs.read-handler
export async function HEAD(req) {
  return new Response(JSON.stringify(await prisma.patient.findMany()));
}

// Case n3copy.
// ok: access-audit-log.tsx-nextjs.read-handler
export async function GET(req) {
  const data = await prisma.patient.findMany();
  try { return Response.json(data); } catch (e) { await auditLog('fail'); throw e; }
}

// A real audit-table write is the control.
// ok: access-audit-log.tsx-nextjs.read-handler
export async function GET(req) {
  await supabase.from("access_logs").insert({ patient_id: req.nextUrl.searchParams.get("id"), action: "read" });
  return Response.json(await prisma.patient.findMany());
}

// A nested audit wrapper drops the handler.
// ok: access-audit-log.tsx-nextjs.read-handler
export const GET = withAuth(withAudit(async (req) => Response.json(await prisma.patient.findMany())));

// Case n1.

export async function GET(req, { params }) {
  const p = await prisma.patient.findUnique({ where: { id: params.id } });
  const entry = new AuditLog({ action: "read" });
  await entry.save();
  return Response.json(p);
}
// Case n2.

async function logView(id) {
  await prisma.auditLog.create({ data: { action: "read", patientId: id } });
}
export async function GET(req, { params }) {
  const p = await prisma.patient.findUnique({ where: { id: params.id } });
  await logView(p.id);
  return Response.json(p);
}
// Case n3.

// ok: access-audit-log.tsx-nextjs.read-handler
export async function GET(req, { params }) {
  const p = await prisma.patient.findUnique({ where: { id: params.id } });
  await supabase.from("audit_logs").insert({ action: "read" });
  return Response.json(p);
}
// Case n4.

export async function GET(req, { params }) {
  const [p] = await Promise.all([
    prisma.patient.findUnique({ where: { id: params.id } }),
    prisma.auditLog.create({ data: { action: "read" } }),
  ]);
  return Response.json(p);
}
// Case n5.

export async function GET(req, { params }) {
  const p = await prisma.patient.findUnique({ where: { id: params.id } });
  const audit = await prisma.auditLog.create({ data: { action: "read" } });
  return Response.json(p);
}
// Case n6.

export async function GET(req, { params }) {
  const p = await prisma.patient.findUnique({ where: { id: params.id } });
  void prisma.auditLog.create({ data: { action: "read" } });
  return Response.json(p);
}

// Case m1.
import { prisma } from "@/lib/db";
async function logView(id) {
  await prisma.auditLog.create({ data: { action: "read", patientId: id } });
}
export async function GET(req, { params }) {
  const p = await prisma.patient.findUnique({ where: { id: Number(params.id) } });
  await logView(p.id);
  return Response.json(p);
}
// Case m2.
import { prisma } from "@/lib/db";
export async function GET(req, { params }) {
  const p = await prisma.patient.findUnique({ where: { id: params.id } });
  await logView(p.id);
  return Response.json(p);
}
const logView = async (id) => {
  await prisma.auditLog.create({ data: { action: "read", patientId: id } });
};

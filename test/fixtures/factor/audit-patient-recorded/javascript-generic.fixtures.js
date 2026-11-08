// Fixtures for audit-patient-recorded (JavaScript). Made-up code only.

export async function recordAccess(prisma, supabase, user, patient, report, entry, db) {
  // ok: audit-patient-recorded.javascript-generic.audit-write-patient-from
  await supabase.from("access_logs").insert({ patient_id: patient.id, doctor_id: user.id });
  // A record keyed only by a generic entity id (or a report id) can't answer "who read this patient".
  // ok: audit-patient-recorded.javascript-generic.audit-write-patient
  await prisma.auditLog.create({ data: { actorUserId: user.userId, patientId: patient.id, action: "READ" } });
  // ruleid: audit-patient-recorded.javascript-generic.audit-write-patient
  await prisma.auditLog.create({ data: { actorUserId: user.userId, entityId: report.id, action: "READ" } });
  // ruleid: audit-patient-recorded.javascript-generic.audit-write-patient-from
  await supabase.from("ai_audit_log").insert({ user_id: user.id, report_id: report.id });
  // A fixed patient id (0) is no patient.
  // ruleid: audit-patient-recorded.javascript-generic.audit-write-patient-from
  await supabase.from("access_logs").insert({ patient_id: 0, doctor_id: user.id });
  // ruleid: audit-patient-recorded.javascript-generic.audit-write-patient-many
  await prisma.auditLog.createMany({ data: [{ action: "READ", patientId: patient.id }, { action: "READ" }] });
  // ok: audit-patient-recorded.javascript-generic.audit-write-patient-many
  await prisma.auditLog.createMany({ data: [{ action: "READ", patientId: patient.id }] });
  // The patient key nested under another object is not the record's key.
  // ruleid: audit-patient-recorded.javascript-generic.audit-write-patient
  await prisma.auditLog.create({ data: { action: "READ", meta: { patientId: patient.id } } });
  // A row built elsewhere can't be read here: not an item (dataflow, needs_review).
  // ok: audit-patient-recorded.javascript-generic.audit-write-patient-from
  await supabase.from("ai_audit_log").insert(entry);

  // A query flagged not to be logged is counter-evidence.
  // ruleid: audit-patient-recorded.javascript-generic.log-flag-off
  await db.query("select * from patients where id = $1", [patient.id], { log: false });
  // ruleid: audit-patient-recorded.javascript-generic.log-flag-off
  await db.patients.findOne(patient.id, { skipAudit: true });
  // A dialog or logger option is not an audit flag.
  // ok: audit-patient-recorded.javascript-generic.log-flag-off
  openModal({ dialog: false, logger: false });
}

// Request handlers: evidence that makes the handler an object of its own, whatever it calls (a helper
// in another file may read or change the patient's data).
// With no audit-write item in it, the handler is unknown: whether its reads and changes are recorded with the patient
// may be decided in a service, an interceptor or a database trigger out of view. Never a pass (the practice is capped
// at needs_review), never a fail.
// ruleid: audit-patient-recorded.javascript-generic.request-handler
export async function GET(request) {
  const supabase = await createClient();
  const { data } = await supabase
    .from("emergency_profiles")
    .select("*")
    .eq("id", request.url);
  return Response.json(data);
}
// ruleid: audit-patient-recorded.javascript-generic.request-handler
export const DELETE = async (request) => {
  await db.query("delete from reports where id = $1", [request.url]);
  return new Response(null, { status: 204 });
};
// A route handler that only hands the request to a helper is one too.
// ruleid: audit-patient-recorded.javascript-generic.request-handler
export async function POST(request) {
  return Response.json({ echo: await request.json() });
}
// A function that only looks like a handler (not exported, or not named for a method) is not one.
// ok: audit-patient-recorded.javascript-generic.request-handler
async function GETTER(id) {
  return prisma.patient.findUnique({ where: { id } });
}
export function PatientPage() {
  // An inline server action (its body opens with 'use server').
  // ruleid: audit-patient-recorded.javascript-generic.request-handler
  async function inlineAction(id) {
    "use server";
    return prisma.patient.findUnique({ where: { id } });
  }
  return inlineAction;
}


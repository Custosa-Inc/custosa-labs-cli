import { db } from "./db";

export async function save(row: unknown) {
  // ruleid: access-audit-log.typescript-generic.audit-write
  await db.from("audit_log").insert({ action: "read", row });

  // ok: access-audit-log.typescript-generic.audit-write
  await db.from("patients").insert(row);

  try {
    await db.from("patients").update(row);
  } catch (error) {
    // ok: access-audit-log.typescript-generic.audit-write
    await db.from("audit_log").insert({ action: "failed" });
  }
}

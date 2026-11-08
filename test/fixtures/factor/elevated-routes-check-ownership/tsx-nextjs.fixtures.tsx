"use server";
// Made-up Server Actions in TSX with the Firebase Admin SDK.
import { getFirestore } from "firebase-admin/firestore";

// ruleid: elevated-routes-check-ownership.tsx-nextjs.elevated-handler
export async function loadChart(patientId: string) {
  const snap = await getFirestore().collection("charts").doc(patientId).get();
  return <Chart data={snap.data()} />;
}

// ok: elevated-routes-check-ownership.tsx-nextjs.elevated-handler
export async function loadMine(patientId: string) {
  const session = await getServerSession(authOptions);
  const snap = await getFirestore().collection("charts").where("ownerId", "==", session.user.id).get();
  const doc = snap.docs.find((d) => d.id === patientId);
  if (doc?.data().owner_id !== session.user.id) throw new Error("Forbidden");
  return <Chart data={doc.data()} />;
}

// No elevated client: not an item.
// ok: elevated-routes-check-ownership.tsx-nextjs.elevated-handler
export async function loadPublic(slug: string) {
  return <Page slug={slug} />;
}

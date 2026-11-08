// Made-up Next.js handlers in JavaScript.

// ok: write-fields-allowlisted.javascript-nextjs.write
export async function POST(request) {
  const { name, dob } = VisitInput.parse(await request.json());
  return Response.json(await prisma.visit.create({ data: { name, dob, ownerId: user.id } }));
}

// ruleid: write-fields-allowlisted.javascript-nextjs.write
export async function PUT(request, { params }) {
  // ruleid: write-fields-allowlisted.javascript-nextjs.body-spread
  await supabase.from("patients").update({ ...(await request.json()) }).eq("id", params.id);
  return new Response(null, { status: 204 });
}

// ruleid: write-fields-allowlisted.javascript-nextjs.write
export default async function handler(req, res) {
  const body = req.body;
  // ruleid: write-fields-allowlisted.javascript-nextjs.body-spread
  res.json(await prisma.note.upsert({ where: { id: body.id }, create: body, update: body, data: body }));
}

// Explicit fields from the body.
// ok: write-fields-allowlisted.javascript-nextjs.write
export async function PATCH(request) {
  const body = await request.json();
  // ok: write-fields-allowlisted.javascript-nextjs.body-spread
  await prisma.visit.update({ where: { id: body.id }, data: { note: body.note } });
}

// Entry points of a write whose write is in a helper: an item each, held for a person by its twin unless a schema
// parses the body in the handler.
// ok: write-fields-allowlisted.javascript-nextjs.entry
// ruleid: write-fields-allowlisted.javascript-nextjs.fields-unobserved-entry
export async function POST(request) {
  const input = NoteInput.parse(await request.json());
  return Response.json(await saveNote(input));
}

// ruleid: write-fields-allowlisted.javascript-nextjs.entry
// ruleid: write-fields-allowlisted.javascript-nextjs.fields-unobserved-entry
export async function PUT(request) {
  const form = await request.formData();
  return Response.json(await uploadAttachment(String(form.get("visitId")), form.get("file")));
}

// JSON.parse is no schema.
// ruleid: write-fields-allowlisted.javascript-nextjs.entry
// ruleid: write-fields-allowlisted.javascript-nextjs.fields-unobserved-entry
export const PATCH = async (req) => {
  const raw = await req.json();
  return Response.json(await saveNote(JSON.parse(raw.payload)));
};

// A handler reading no request body (a fetched response's json() is not one): not an entry point.
// ok: write-fields-allowlisted.javascript-nextjs.entry
// ok: write-fields-allowlisted.javascript-nextjs.fields-unobserved-entry
export async function GET(req) {
  const res = await fetch(feedUrl);
  return Response.json(await res.json());
}

// A write in view with no field list: no entry item and no hold; the write item fails.
// ok: write-fields-allowlisted.javascript-nextjs.entry
// ok: write-fields-allowlisted.javascript-nextjs.fields-unobserved-entry
// ruleid: write-fields-allowlisted.javascript-nextjs.write
export async function POST(request) {
  const body = await request.json();
  // ruleid: write-fields-allowlisted.javascript-nextjs.body-spread
  await prisma.visit.create({ data: body });
  return new Response(null, { status: 201 });
}

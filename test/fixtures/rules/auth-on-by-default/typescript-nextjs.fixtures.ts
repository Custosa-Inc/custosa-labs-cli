import { requireUser } from "@/lib/auth";

// ruleid: auth-on-by-default.typescript-nextjs.route-handler
export async function GET(request: Request) {
  return Response.json(await load(request));
}

// ok: auth-on-by-default.typescript-nextjs.route-handler
export async function POST(request: Request) {
  const user = await requireUser(request);
  return Response.json(await save(user, request));
}

// ok: auth-on-by-default.typescript-nextjs.route-handler
async function helper() {
  return 1;
}

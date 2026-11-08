/* helper modules (files.helpers). A module whose exported functions do elevated or
 * patient-scoped work is listed with every file that imports it, so the core can tell a helper no handler reaches
 * (plumbing-gaps src/files.ts) from one a route calls. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { scanImports } from "../lib/inspector/imports.mjs";
import { exportedFunctions, helperModules, resolveLocal, summarize, workIn } from "../lib/inspector/helpers.mjs";

function tree(files) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "c114-")));
  const list = [];
  for (const [path, text] of Object.entries(files)) {
    mkdirSync(join(root, dirname(path)), { recursive: true });
    writeFileSync(join(root, path), text);
    const ext = path.split(".").pop();
    list.push({ disk: path, path, lang: { ts: "typescript", tsx: "tsx", js: "javascript", py: "python" }[ext] ?? null });
  }
  return { root, list };
}
const scan = async (files, opts) => { const t = tree(files); return scanImports(t.root, t.list, opts); };

// The plumbing-gaps module, as the corpus app has it.
const FILES_TS = `// File storage for patient scans and the clinic logo (fake app).
import { createClient } from "@supabase/supabase-js";

const storage = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!,
).storage;

export const SCANS = "scans";

export async function uploadScan(patientId: string, file: File) {
  const { error } = await storage.from(SCANS).upload(\`\${patientId}/\${file.name}\`, file, { upsert: true });
  if (error) throw error;
}

export async function listScans(patientId: string) {
  return (await storage.from(SCANS).list(patientId)).data;
}
`;
const ROUTE = `import { NextResponse } from "next/server";
export async function GET() { return NextResponse.json({}); }
`;

test("plumbing-gaps: the scan helpers no route imports are listed with no importer", async () => {
  const out = await scan({ "src/files.ts": FILES_TS, "app/api/notes/[id]/route.ts": ROUTE });
  assert.deepEqual(out.helpers, [{ path: "src/files.ts", language: "typescript", functions: ["uploadScan", "listScans"],
    work: ["elevated_client", "storage"], importers: [], importers_complete: true }]);
});

test("control: a route importing the helper, directly or through another module, is an importer", async () => {
  const direct = await scan({ "src/files.ts": FILES_TS,
    "app/api/scans/route.ts": 'import { uploadScan } from "@/src/files";\nexport async function POST() { await uploadScan("p", null); }\n' });
  assert.deepEqual(direct.helpers.map((h) => [h.path, h.importers]), [["src/files.ts", ["app/api/scans/route.ts"]]]);
  const through = await scan({ "src/files.ts": FILES_TS,
    "src/scans.ts": 'export { uploadScan as save } from "./files.js";\n',
    "app/api/scans/route.ts": 'import { save } from "../../../src/scans";\nexport async function POST() { await save("p", null); }\n' });
  assert.deepEqual(through.helpers.map((h) => [h.path, h.importers]), [["src/files.ts", ["app/api/scans/route.ts", "src/scans.ts"]]]);
});

test("a client made in another module elevates the module that uses it", async () => {
  const out = await scan({
    "src/lib/admin.ts": 'import { createClient } from "@supabase/supabase-js";\nexport const admin = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY);\n',
    "src/lib/patients.ts": 'import { admin } from "./admin";\nexport const readPatient = async (id: string) => admin.from("patients").select().eq("id", id);\n',
  });
  // admin.ts exports a client, no function: not a helper; patients.ts is, through it.
  assert.deepEqual(out.helpers.map((h) => [h.path, h.work, h.functions]), [["src/lib/patients.ts", ["elevated_client"], ["readPatient"]]]);
});

test("entry files, browser files, tests and migrations are not helpers", async () => {
  const write = 'export async function save(x) { await db.from("notes").insert(x); }\n';
  const out = await scan({
    "app/api/x/route.ts": write, "app/notes/page.tsx": write, "pages/api/a.ts": write,
    "supabase/functions/hello/index.ts": write, "src/actions.ts": `"use server";\n${write}`,
    "src/form.tsx": `'use client';\n${write}`, "src/a.test.ts": write, "db/migrations/001.ts": write,
    "scripts/seed.ts": write, "src/lib/notes.ts": write,
  });
  assert.deepEqual(out.helpers.map((h) => h.path), ["src/lib/notes.ts"]);
});

test("the work: elevated clients, storage and writes; plain reads and anon clients are none", () => {
  const w = (code, lang = "typescript") => [...workIn(code, lang).work].sort();
  assert.deepEqual(w('createClient(u, process.env.SUPABASE_SERVICE_ROLE_KEY)'), ["elevated_client"]);
  assert.deepEqual(w('const key = env.SECRET_KEY;\nconst c = createClient(u, key);'), ["elevated_client"]);
  assert.deepEqual(w('import admin from "firebase-admin";'), ["elevated_client"]);
  assert.deepEqual(w('createClient(u, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY)'), []);
  assert.deepEqual(w('sb.storage.from("b").upload(p, f)'), ["storage"]);
  assert.deepEqual(w('s3.send(new PutObjectCommand({}))'), ["storage"]);
  assert.deepEqual(w('sb.from("notes").update({ a: 1 })'), ["write"]);
  assert.deepEqual(w('prisma.patient.create({ data })'), ["write"]);
  assert.deepEqual(w('pool.query("INSERT INTO notes VALUES ($1)")'), ["write"]);
  assert.deepEqual(w('sb.from("notes").select("*")'), []);
  assert.deepEqual(w('supabase.table("notes").insert(row)', "python"), ["write"]);
  // supabase-py's from_() and Django QuerySet writes.
  assert.deepEqual(w('supabase.from_("notes").insert(row).execute()', "python"), ["write"]);
  assert.deepEqual(w('sb.from_("notes").delete().eq("id", 1).execute()', "python"), ["write"]);
  assert.deepEqual(w('Note.objects.filter(owner=u).update(seen=True)', "python"), ["write"]);
  assert.deepEqual(w('Note.objects.filter(Q(a=1) | Q(b=2)).delete()', "python"), ["write"]);
  assert.deepEqual(w('Note.objects.all().delete()', "python"), ["write"]);
  assert.deepEqual(w('Note.objects.filter(owner=u).first()', "python"), []);
  assert.deepEqual(w('Note.objects\n    .filter(owner=u).update(seen=True)', "python"), ["write"]);
  assert.deepEqual(w('Note.objects.filter(owner=u)\nlog.update(1)', "python"), []);
  assert.deepEqual(w('a = A.objects.get(id=1); B.objects\n    .filter(x=1).delete()', "python"), ["write"]);
  assert.deepEqual(w('sb.from_("notes").select("*").execute()', "python"), []);
  assert.deepEqual(w('from firebase_admin import auth', "python"), ["elevated_client"]);
  assert.deepEqual(w('create_client(url, os.environ["SUPABASE_SERVICE_ROLE_KEY"])', "python"), ["elevated_client"]);
});

// the QuerySet write test is linear. A lazy gap after each .objects. was quadratic on one long line.
test("the QuerySet write test stays fast on a long line of .objects.", () => {
  const line = ".objects.x".repeat(20000);
  const started = performance.now();
  assert.deepEqual([...workIn(line, "python").work], []);
  assert.deepEqual([...workIn(`${line}.update(1)`, "python").work], ["write"]);
  assert.ok(performance.now() - started < 500, `took ${Math.round(performance.now() - started)} ms`);
});

test("exported functions in every form; constants and private functions are not", () => {
  const js = [
    "export async function a() {}", "export function* b() {}", "export const c = async (x) => x;",
    "export const d = function () {};", "export const e = y => y;", "export const K = 1;", "function f() {}",
    "const g = () => 1;", "export { f, g as h, K2 };", "exports.i = function () {};", "export default function j() {}",
  ].join("\n");
  assert.deepEqual(exportedFunctions(js, "typescript"), ["a", "b", "c", "d", "e", "f", "h", "i", "j"]);
  assert.deepEqual(exportedFunctions("export default async () => 1;\n", "javascript"), ["default"]);
  assert.deepEqual(exportedFunctions("def save(x):\n    pass\ndef _hidden():\n    pass\n    def inner():\n        pass\n", "python"), ["save"]);
});

test("local specifiers resolve to walked files; packages and unknown paths don't", () => {
  const paths = new Set(["src/files.ts", "src/lib/index.ts", "lib/util.js", "svc/store.py", "svc/__init__.py", "pkg/db/__init__.py"]);
  assert.equal(resolveLocal("../src/files", "app/route.ts", paths, "typescript"), "src/files.ts");
  assert.equal(resolveLocal("./files.js", "src/x.ts", paths, "typescript"), "src/files.ts");
  assert.equal(resolveLocal("@/lib", "app/route.ts", paths, "typescript"), "src/lib/index.ts");
  assert.equal(resolveLocal("~/lib/util", "app/route.ts", paths, "typescript"), "lib/util.js");
  assert.equal(resolveLocal("next/server", "app/route.ts", paths, "typescript"), null);
  assert.equal(resolveLocal("../../../../x", "app/route.ts", paths, "typescript"), null);
  assert.equal(resolveLocal(".store", "svc/api.py", paths, "python"), "svc/store.py");
  assert.equal(resolveLocal("pkg.db", "app.py", paths, "python"), "pkg/db/__init__.py");
  assert.equal(resolveLocal("requests", "app.py", paths, "python"), null);
});

test("Python: a module a view imports is reached, one nothing imports is not", async () => {
  const out = await scan({
    "svc/store.py": "def save(row):\n    supabase.table('notes').insert(row).execute()\n",
    "svc/orphan.py": "def wipe():\n    db.execute('DELETE FROM notes')\n",
    "svc/views.py": "from .store import save\n",
  });
  assert.deepEqual(out.helpers.map((h) => [h.path, h.importers]), [["svc/orphan.py", []], ["svc/store.py", ["svc/views.py"]]]);
});

test("the list is null when a file wasn't read, and past its cap", async () => {
  const t = tree({ "src/files.ts": FILES_TS });
  const out = await scanImports(t.root, [...t.list, { disk: "gone.ts", path: "gone.ts", lang: "typescript" }]);
  assert.equal(out.helpers, null);
  const many = Array.from({ length: 5001 }, (_, i) => summarize(`src/m${i}.ts`, "typescript", "export function f() { sb.from('x').delete(); }"));
  assert.equal(helperModules(many), null);
  assert.equal(helperModules(many.slice(0, 5000)).length, 5000);
});

test("a cut importer list says so", () => {
  const files = [summarize("src/h.ts", "typescript", "export function f() { sb.from('x').delete(); }")];
  for (let i = 0; i < 1001; i++) files.push(summarize(`src/u${i}.ts`, "typescript", 'import { f } from "./h";\n'));
  const [h] = helperModules(files);
  assert.equal(h.importers.length, 1000);
  assert.equal(h.importers_complete, false);
});

test("the fact document carries files.helpers with sent paths and names, and passes its schema", async () => {
  const { buildFactDocuments, checkDocument } = await import("../lib/inspector/factdoc.mjs");
  const t = tree({ "app/api/notes/[id]/route.ts": ROUTE, "src/files.ts": FILES_TS });
  const runRules = async () => ({ matches: [], links: [], notAnalyzed: [], analyzed: 2,
    analyzedPaths: ["app/api/notes/[id]/route.ts", "src/files.ts"], languages: ["typescript"], status: "ok", count: 0 });
  const out = await buildFactDocuments([t.root], { configDir: mkdtempSync(join(tmpdir(), "c114-cfg-")), runRules,
    ruleset: { id: "2026-10-20.0123abcd", rules: [], queries: [] },
    collectCatalog: async () => ({ status: "not_run", count: 0, reason: "service_missing", preflight: null, queries: [] }),
    collectPlatform: async () => ({ provider: null, status: "not_run", reason: "no_token", settings: {} }) });
  const doc = out.documents[0].document;
  assert.deepEqual(doc.files.derived_frameworks, ["nextjs", "supabase"]);
  assert.deepEqual(doc.files.helpers, [{ path: "src/files.ts", language: "typescript", functions: ["uploadScan", "listScans"],
    work: ["elevated_client", "storage"], importers: [], importers_complete: true }]);
  assert.equal(checkDocument(doc), null);
});

test("Drizzle writes and generic arrow exports make a helper", () => {
  const w = (code) => [...workIn(code, "typescript").work].sort();
  assert.deepEqual(w("await db.insert(patients).values(row);"), ["write"]);
  assert.deepEqual(w("await db.update(patients).set({ name }).where(eq(patients.id, id));"), ["write"]);
  assert.deepEqual(w("await tx.delete(patients).where(eq(patients.id, id));"), ["write"]);
  assert.deepEqual(w("cache.delete(key); map.set(k, v);"), []);
  const js = [
    "export const save = <T,>(row: T) => db.insert(t).values(row);",
    "export const load = async <T extends object>(id: string): Promise<T> => get(id);",
    "const keep = <T>(x: T) => x;", "export { keep };",
  ].join("\n");
  assert.deepEqual(exportedFunctions(js, "typescript"), ["save", "load", "keep"]);
});

// a bare Drizzle delete (every row), an insert from a select, and a generic arrow with a default.
test("a bare Drizzle delete, insert().select() and a generic with a default are seen", () => {
  const w = (code) => [...workIn(code, "typescript").work].sort();
  assert.deepEqual(w("await db.delete(patients);"), ["write"]);
  assert.deepEqual(w("await tx.delete(schema.notes)"), ["write"]);
  assert.deepEqual(w('import { eq } from "drizzle-orm";\nawait conn.delete(patients);'), ["write"]);
  assert.deepEqual(w("await db.insert(archive).select(db.select().from(patients));"), ["write"]);
  // Not a database: a Map, a Set or a cache.
  assert.deepEqual(w("cache.delete(key); seen.delete(id); headers.delete(\"x\");"), []);
  const js = [
    "export const f = <T = string>(x: T) => db.insert(t).values(x);",
    "export const g = async <K extends string = \"id\", V = Map<K, number>>(k: K): Promise<V> => get(k);",
    "const h = <T = unknown,>(x: T) => x;", "export { h };",
  ].join("\n");
  assert.deepEqual(exportedFunctions(js, "typescript"), ["f", "g", "h"]);
});

// A NestJS or tRPC receiver chain that ends in db,
// tx, trx or database deletes rows with no drizzle-orm import in the file. A chain that ends in another name stays a
// Map or a cache, and a name that only ends in those letters is not the receiver.
test("a delete on a db, tx, trx or database member chain is write work with no drizzle-orm import", () => {
  const w = (code) => [...workIn(code, "typescript").work].sort();
  assert.deepEqual(w("await this.db.delete(patients);"), ["write"]);
  assert.deepEqual(w("await ctx.db.delete(schema.notes).where(eq(id, 1))"), ["write"]);
  assert.deepEqual(w("await ctx.db\n  .delete(patients);"), ["write"]);
  assert.deepEqual(w("await this.#db.delete(patients);"), ["write"]);
  assert.deepEqual(w("await opts.ctx.tx.delete(t);"), ["write"]);
  assert.deepEqual(w("await this.trx.delete(t);"), ["write"]);
  assert.deepEqual(w("await app.database.delete(t);"), ["write"]);
  assert.deepEqual(w("this.cache.delete(k); ctx.seen.delete(id); cache.delete(k);"), []);
  assert.deepEqual(w("this.mydb.delete(k); ctx.sandbox.delete(id); this.db_cache.delete(k);"), []);
});

// optional chaining on the receiver, this.db?.delete(t), is the same write. A
// cache's ?.delete(k) stays none.
test("a delete through ?. on a db, tx, trx or database receiver is write work with no drizzle-orm import", () => {
  const w = (code) => [...workIn(code, "typescript").work].sort();
  assert.deepEqual(w("await this.db?.delete(t);"), ["write"]);
  assert.deepEqual(w("await ctx.tx?.delete(t);"), ["write"]);
  assert.deepEqual(w("await db ?. delete(t);"), ["write"]);
  assert.deepEqual(w("this.cache?.delete(k);"), []);
  assert.deepEqual(w("this.mydb?.delete(k);"), []);
});

// An optional call, delete?.(t), is the same delete, on a db receiver and in a
// file that imports drizzle-orm. A cache's delete?.(k) stays none.
test("an optional call delete?.(t) is write work on a db receiver or in a drizzle-orm file", () => {
  const w = (code) => [...workIn(code, "typescript").work].sort();
  assert.deepEqual(w("await db?.delete?.(t);"), ["write"]);
  assert.deepEqual(w("await this.db.delete?.(t);"), ["write"]);
  assert.deepEqual(w('import { eq } from "drizzle-orm";\nawait client.delete?.(t);'), ["write"]);
  assert.deepEqual(w("this.cache?.delete?.(k); this.mydb.delete?.(k);"), []);
});

// a delete called by bracket name, db["delete"](t), is the same delete, on a db, tx,
// trx or database receiver and in a file that imports drizzle-orm. A cache's ["delete"](k) stays none.
test("a delete called by bracket name is write work on a db receiver or in a drizzle-orm file", () => {
  const w = (code) => [...workIn(code, "typescript").work].sort();
  assert.deepEqual(w('await db["delete"](t);'), ["write"]);
  assert.deepEqual(w("await this.db['delete'](t);"), ["write"]);
  assert.deepEqual(w("await ctx.tx[ `delete` ](t).where(x);"), ["write"]);
  assert.deepEqual(w('await this.trx?.["delete"](t); await app.database["delete"]?.(t);'), ["write"]);
  assert.deepEqual(w('import { eq } from "drizzle-orm";\nawait getDb()["delete"](t);'), ["write"]);
  assert.deepEqual(w('cache["delete"](k); this.cache?.["delete"](k); this.mydb["delete"](k);'), []);
  assert.deepEqual(w('db["deleted"](t); db[deleteKey](t);'), []);
});

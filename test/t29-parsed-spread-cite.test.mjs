/* T29-P1-C189 item 1: core reads a write_fields parser fact of strips_unknown_keys anywhere in the candidate's own
 * file, so the inspector sends that cite as ok only when it names the schema the handler parses: the cited line lies
 * inside the handler (from the candidate's line to the data_shape cite's line), or it declares a name one of those lines
 * uses. The red case: two schemas in one file, the handler parses the .passthrough() one, and the cite names the strict
 * one. That cite is failed, so the fact is not usable and the candidate can't pass. keeps_unknown_keys is not checked:
 * it only decides toward fail. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { citedFactRows } from "../lib/inspector/cite.mjs";

const FILES = {
  "app/notes/route.ts": [
    'import { z } from "zod";',
    "const Strict = z.object({ title: z.string() }).strict();",
    "const Loose = z.object({ title: z.string() }).passthrough();",
    "",
    "export async function POST(req) {",
    "  const session = await auth();",
    "  const input = Loose.parse(await req.json());",
    "  return db.note.create({ data: { ...input, ownerId: session.user.id } });",
    "}",
  ].join("\n"),
  "app/journal/route.ts": [
    'import { z } from "zod";',
    "export const JournalInput = z.object({ body: z.string() });",
    "",
    "export async function POST(req) {",
    "  const session = await auth();",
    "  const input = JournalInput.parse(await req.json());",
    "  return db.entry.create({ data: { ...input, ownerId: session.user.id } });",
    "}",
  ].join("\n"),
  "app/schemas.ts": "export const JournalInput = z.object({ body: z.string() });\n",
  // P2 T29-C199: an alias, a passthrough on the alias line, two schemas the handler parses, a name only in a comment.
  "app/alias/route.ts": [
    "const Base = z.object({ title: z.string() }).passthrough();",
    "const Input = Base;",
    "const Loose = Base.passthrough();",
    "export async function POST(req) {",
    "  const input = Input.parse(await req.json());",
    "  return db.note.create({ data: { ...input, ownerId: (await auth()).user.id } });",
    "}",
  ].join("\n"),
  "app/two/route.ts": [
    "const Query = z.object({ page: z.string() }).strict();",
    "const Body = z.object({ title: z.string() }).passthrough();",
    "export async function POST(req) {",
    "  const q = Query.parse(Object.fromEntries(new URL(req.url).searchParams));",
    "  const input = Body.parse(await req.json());",
    "  return db.note.create({ data: { ...input, ownerId: (await auth()).user.id } });",
    "}",
  ].join("\n"),
  "app/multi/route.ts": [
    "const Input = z.object({",
    "  title: z.string(),",
    "})",
    "  .passthrough();",
    "const Other = z.object({",
    "  title: z.string(),",
    "}).catchall(z.any());",
    "export async function POST(req) {",
    "  const input = Input.parse(await req.json());",
    "  return db.note.create({ data: { ...input, ownerId: (await auth()).user.id } });",
    "}",
    "export async function PUT(req) {",
    "  const input = Other.parse(await req.json());",
    "  return db.note.create({ data: { ...input, ownerId: (await auth()).user.id } });",
    "}",
  ].join("\n"),
  "app/comment/route.ts": [
    "const Strict = z.object({ title: z.string() }).strict();",
    "const Loose = z.object({ title: z.string() }).passthrough();",
    "export async function POST(req) {",
    "  // was Strict before",
    "  const input = Loose.parse(await req.json());",
    "  return db.note.create({ data: { ...input, ownerId: (await auth()).user.id } });",
    "}",
  ].join("\n"),
  "src/items.controller.ts": [
    "export class CreateItemDto {",
    "  name: string;",
    "}",
    "export class ItemsController {",
    "  create(@Body() data: CreateItemDto, @Req() req) {",
    "    return this.prisma.item.create({ data: { ...data, ownerId: req.user.id } });",
    "  }",
    "}",
  ].join("\n"),
  "api/notes.py": [
    "class NoteIn(BaseModel):",
    "    title: str",
    "",
    "@router.post('/notes')",
    "def create_note(body: NoteIn, user=Depends(current_user)):",
    "    return db.add(Note(**body.dict(), owner_id=user.id))",
  ].join("\n"),
  // P2 T29-C203 med 1: a Python model that keeps unknown keys in its class body (pydantic v2, then v1), and one that
  // forbids them.
  "api/v2.py": [
    "class NoteIn(BaseModel):",
    "    model_config = ConfigDict(extra=\"allow\")",
    "    title: str",
    "",
    "@router.post('/notes')",
    "def create_note(body: NoteIn, user=Depends(current_user)):",
    "    return db.add(Note(**body.dict(), owner_id=user.id))",
  ].join("\n"),
  "api/v1.py": [
    "class NoteIn(BaseModel):",
    "    title: str",
    "",
    "    class Config:",
    "        extra = Extra.allow",
    "",
    "@router.post('/notes')",
    "def create_note(body: NoteIn, user=Depends(current_user)):",
    "    return db.add(Note(**body.dict(), owner_id=user.id))",
  ].join("\n"),
  // P2 T29-C205 med 1: the class header over several lines, as black writes a long one.
  "api/split.py": [
    "class NoteIn(",
    "    BaseModel,",
    "):",
    "    model_config = ConfigDict(extra=\"allow\")",
    "    title: str",
    "",
    "@router.post('/notes')",
    "def create_note(body: NoteIn, user=Depends(current_user)):",
    "    return db.add(Note(**body.dict(), owner_id=user.id))",
  ].join("\n"),
  "api/split-ok.py": [
    "class NoteIn(",
    "    BaseModel,",
    "):",
    "    title: str",
    "",
    "@router.post('/notes')",
    "def create_note(body: NoteIn, user=Depends(current_user)):",
    "    return db.add(Note(**body.dict(), owner_id=user.id))",
  ].join("\n"),
  "api/forbid.py": [
    "class NoteIn(BaseModel):",
    "    model_config = ConfigDict(extra=\"forbid\")",
    "    title: str",
    "",
    "@router.post('/notes')",
    "def create_note(body: NoteIn, user=Depends(current_user)):",
    "    return db.add(Note(**body.dict(), owner_id=user.id))",
  ].join("\n"),
  // P2 T29-C203 med 2: a strict schema made loose at the parse call, outside and inside the handler; .strict() at the
  // call stays ok.
  "app/atparse/route.ts": [
    "const Input = z.object({ title: z.string() }).strict();",
    "export async function POST(req) {",
    "  const input = Input.passthrough().parse(await req.json());",
    "  return db.note.create({ data: { ...input, ownerId: (await auth()).user.id } });",
    "}",
    "export async function PUT(req) {",
    "  const Inline = z.object({ title: z.string() }).strict();",
    "  const input = Inline",
    "    .passthrough()",
    "    .parse(await req.json());",
    "  return db.note.create({ data: { ...input, ownerId: (await auth()).user.id } });",
    "}",
    "export async function PATCH(req) {",
    "  const input = Input.strict().parse(await req.json());",
    "  return db.note.create({ data: { ...input, ownerId: (await auth()).user.id } });",
    "}",
  ].join("\n"),
};

const root = mkdtempSync(join(tmpdir(), "parsed-spread-"));
for (const [p, text] of Object.entries(FILES)) {
  mkdirSync(dirname(join(root, p)), { recursive: true });
  writeFileSync(join(root, p), `${text}\n`);
}
const files = new Map(Object.keys(FILES).map((p) => [p, { path: p }]));
const key = Buffer.alloc(32, 9);

const cite = (file, line, token) => ({ file, line, token });
function write(candidate, shape, parser, value = "strips_unknown_keys") {
  const [file, line] = candidate.split(":");
  return {
    rule: "write_fields", candidate,
    handler: { value: "declared", ...cite(file, Number(line), "export") },
    data_shape: shape ? { value: "spread_parsed", ...shape } : { value: "unknown" },
    parser: { value, ...parser },
    owner_source: { value: "session", ...(shape ?? cite(file, Number(line), "export")) },
  };
}
async function parserCite(record) {
  const rows = await citedFactRows(root, files, key, [record]);
  return rows.find((r) => r.field === "parser").cite;
}

const NOTES = "app/notes/route.ts";
const NOTES_SHAPE = cite(NOTES, 8, "...input");

test("C189 red case: a cite naming the strict schema, while the handler parses the .passthrough() one, is failed", async () => {
  assert.equal(await parserCite(write(`${NOTES}:5`, NOTES_SHAPE, cite(NOTES, 2, "const Strict"))), "failed");
  assert.equal(await parserCite(write(`${NOTES}:5`, NOTES_SHAPE, cite(NOTES, 2, "z.object({"))), "failed");
});

test("a cite of the schema the handler parses, outside the handler, stays ok", async () => {
  const shape = cite("app/journal/route.ts", 7, "...input");
  assert.equal(await parserCite(write("app/journal/route.ts:4", shape, cite("app/journal/route.ts", 2, "z.object({"))), "ok");
});

test("a cite inside the handler, from its line to the data shape's, stays ok", async () => {
  assert.equal(await parserCite(write(`${NOTES}:5`, NOTES_SHAPE, cite(NOTES, 7, "Loose.parse"))), "ok");
});

test("a cite in another file is left ok: core reads a parser fact only in the candidate's own file, and holds it", async () => {
  const shape = cite("app/journal/route.ts", 7, "...input");
  assert.equal(await parserCite(write("app/journal/route.ts:4", shape, cite("app/schemas.ts", 1, "JournalInput"))), "ok");
});

test("with no usable data_shape cite only the candidate's own line counts", async () => {
  assert.equal(await parserCite(write("app/journal/route.ts:4", null, cite("app/journal/route.ts", 2, "JournalInput"))), "failed");
});

test("a line that declares no name is failed outside the handler", async () => {
  assert.equal(await parserCite(write(`${NOTES}:5`, NOTES_SHAPE, cite(NOTES, 1, "import"))), "failed");
});

test("keeps_unknown_keys is not checked: it only decides toward fail", async () => {
  assert.equal(await parserCite(write(`${NOTES}:5`, NOTES_SHAPE, cite(NOTES, 2, "const Strict"), "keeps_unknown_keys")), "ok");
  assert.equal(await parserCite(write(`${NOTES}:5`, NOTES_SHAPE, cite("app/schemas.ts", 1, "JournalInput"), "keeps_unknown_keys")), "ok");
});

test("a DTO class the handler's signature names, and a Python model, stay ok", async () => {
  const nest = "src/items.controller.ts";
  assert.equal(await parserCite(write(`${nest}:5`, cite(nest, 6, "...data"), cite(nest, 1, "class CreateItemDto"))), "ok");
  assert.equal(await parserCite(write("api/notes.py:5", cite("api/notes.py", 6, "**body"), cite("api/notes.py", 1, "class NoteIn"))), "ok");
});

test("P2 C199 med 1: an alias line, or a line that keeps unknown keys, is failed", async () => {
  const f = "app/alias/route.ts";
  const shape = cite(f, 6, "...input");
  assert.equal(await parserCite(write(`${f}:4`, shape, cite(f, 2, "const Input = Base"))), "failed");
  assert.equal(await parserCite(write(`${f}:4`, shape, cite(f, 3, "Base.passthrough()"))), "failed");
  assert.equal(await parserCite(write(`${f}:4`, shape, cite(f, 1, "const Base"))), "failed");
});

test("P2 C199 med 2: a handler that parses two schemas of this file holds, whichever is cited", async () => {
  const f = "app/two/route.ts";
  const shape = cite(f, 6, "...input");
  assert.equal(await parserCite(write(`${f}:3`, shape, cite(f, 1, "const Query"))), "failed");
  assert.equal(await parserCite(write(`${f}:3`, shape, cite(f, 2, "const Body"))), "failed");
});

test("P2 C199 low 1: a name seen only in a comment is not used", async () => {
  const f = "app/comment/route.ts";
  assert.equal(await parserCite(write(`${f}:3`, cite(f, 6, "...input"), cite(f, 1, "const Strict"))), "failed");
});

test("a schema built over many lines that keeps unknown keys on a later line is failed", async () => {
  const f = "app/multi/route.ts";
  assert.equal(await parserCite(write(`${f}:8`, cite(f, 10, "...input"), cite(f, 1, "const Input"))), "failed");
  assert.equal(await parserCite(write(`${f}:12`, cite(f, 14, "...input"), cite(f, 5, "const Other"))), "failed");
  // the journal schema closes on one line with no passthrough: still ok
  const j = "app/journal/route.ts";
  assert.equal(await parserCite(write(`${j}:4`, cite(j, 7, "...input"), cite(j, 2, "z.object({"))), "ok");
});

test("P2 C203 med 1: a Python model that keeps unknown keys in its class body is failed", async () => {
  for (const f of ["api/v2.py", "api/v1.py"]) {
    const line = f === "api/v1.py" ? 8 : 6;
    assert.equal(await parserCite(write(`${f}:${line}`, cite(f, line + 1, "**body"), cite(f, 1, "class NoteIn"))), "failed", f);
  }
  const f = "api/forbid.py";
  assert.equal(await parserCite(write(`${f}:6`, cite(f, 7, "**body"), cite(f, 1, "class NoteIn"))), "ok");
});

test("P2 C203 med 2: a handler that makes the cited schema loose where it parses it is failed", async () => {
  const f = "app/atparse/route.ts";
  assert.equal(await parserCite(write(`${f}:2`, cite(f, 4, "...input"), cite(f, 1, "const Input"))), "failed");
  // inside the handler, the call over three lines
  assert.equal(await parserCite(write(`${f}:6`, cite(f, 11, "...input"), cite(f, 7, "const Inline"))), "failed");
  // .strict() at the call keeps it strict
  assert.equal(await parserCite(write(`${f}:13`, cite(f, 15, "...input"), cite(f, 1, "const Input"))), "ok");
});

test("P2 C205 med 1: a class header over several lines is read to its body", async () => {
  assert.equal(await parserCite(write("api/split.py:8", cite("api/split.py", 9, "**body"), cite("api/split.py", 1, "class NoteIn("))), "failed");
  assert.equal(await parserCite(write("api/split-ok.py:7", cite("api/split-ok.py", 8, "**body"), cite("api/split-ok.py", 1, "class NoteIn("))), "ok");
});

/* T29 line item h, h2 (T29-P3-C85, decided in C87; P2 C63 point 2): the inspector checks each citation the assistant
 * gives for a fact on the machine, and forwards only ok, failed or none. ok needs a file the walk analysed, a line that
 * exists when lines are counted on \n alone (a CR before it is stripped), and the token, at least 3 characters with
 * no line break, on that line. Anything else is failed, never ok; no citation is none. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { checkCitation, citeLines, MIN_CITE_TOKEN_CHARS } from "../lib/inspector/cite.mjs";

function project() {
  const root = mkdtempSync(join(tmpdir(), "cite-"));
  mkdirSync(join(root, "app"));
  writeFileSync(join(root, "app", "route.ts"), "export async function GET(req) {\n  const session = await auth();\n  return x;\n}\n");
  writeFileSync(join(root, "app", "crlf.ts"), "line one\r\nconst user = await auth();\r\nend\r\n");
  // old Mac line ends: with \n alone this is one long line, so a cite to line 1 would find a token from anywhere
  writeFileSync(join(root, "app", "mac.ts"), "line one\rconst user = await auth();\rend\n");
  // U+2028 and U+0085 and a form feed are line breaks to Python's splitlines, not to an editor or this check
  writeFileSync(join(root, "app", "seps.ts"), "a b\u0085c\fd\nconst owner = session.user.id;\n");
  writeFileSync(join(root, "app", "big.ts"), "const owner = session.user.id;\n");
  writeFileSync(join(root, "app", "bin.ts"), Buffer.from([0x63, 0x6f, 0x6e, 0x73, 0x74, 0x00, 0x0a]));
  const outside = mkdtempSync(join(tmpdir(), "cite-out-"));
  writeFileSync(join(outside, "secret.ts"), "const owner = session.user.id;\n");
  symlinkSync(join(outside, "secret.ts"), join(root, "app", "link.ts"));
  // the walk's entries by path; big.ts was skipped, so it has none
  const files = new Map(["app/route.ts", "app/crlf.ts", "app/mac.ts", "app/seps.ts", "app/bin.ts", "app/link.ts"].map((p) => [p, { path: p }]));
  return { root, files };
}

const P = project();
const check = async (cite) => (await checkCitation(P.root, P.files, cite)).cite;

test("a token of 3 or more characters on the cited line of a walked file is ok", async () => {
  assert.equal(MIN_CITE_TOKEN_CHARS, 3);
  assert.equal(await check({ file: "app/route.ts", line: 2, token: "await auth()" }), "ok");
  assert.equal(await check({ file: "app/route.ts", line: 1, token: "GET" }), "ok");
});

test("no citation is none, never ok", async () => {
  for (const cite of [undefined, null, {}, { value: "none" }]) assert.equal(await check(cite), "none");
});

const FAILED = {
  "the token on another line": { file: "app/route.ts", line: 1, token: "await auth()" },
  "a line past the end": { file: "app/route.ts", line: 6, token: "await auth()" },
  "line 0": { file: "app/route.ts", line: 0, token: "export" },
  "a line that is not a whole number": { file: "app/route.ts", line: 1.5, token: "export" },
  "a line given as text": { file: "app/route.ts", line: "2", token: "await auth()" },
  "a token under 3 characters": { file: "app/route.ts", line: 2, token: "aw" },
  "a token with a line break": { file: "app/route.ts", line: 1, token: "{\n  const" },
  "a token absent from the file": { file: "app/route.ts", line: 2, token: "requireOwner(" },
  "no token": { file: "app/route.ts", line: 2 },
  "a path outside the root": { file: "../outside.ts", line: 1, token: "const" },
  "an absolute path": { file: "/etc/passwd", line: 1, token: "root" },
  "a symlink out of the root": { file: "app/link.ts", line: 1, token: "session.user.id" },
  "a file the walk skipped": { file: "app/big.ts", line: 1, token: "session.user.id" },
  "a file not in the project": { file: "app/none.ts", line: 1, token: "const" },
  "a binary file": { file: "app/bin.ts", line: 1, token: "const" },
  "no line": { file: "app/route.ts", token: "export" },
};

for (const [name, cite] of Object.entries(FAILED)) {
  test(`failed, never ok: ${name}`, async () => {
    assert.equal(await check(cite), "failed");
  });
}

test("lines are counted on \\n alone, so U+2028, U+0085 and a form feed before the cited line don't move it", async () => {
  assert.equal(await check({ file: "app/seps.ts", line: 2, token: "session.user.id" }), "ok");
  assert.equal(await check({ file: "app/seps.ts", line: 5, token: "session.user.id" }), "failed");
  assert.deepEqual(citeLines("a b\nc"), ["a b", "c"]);
});

test("a CRLF file counts the same lines, and the CR is not part of the line", async () => {
  assert.equal(await check({ file: "app/crlf.ts", line: 2, token: "await auth();" }), "ok");
  assert.equal(await check({ file: "app/crlf.ts", line: 3, token: "end" }), "ok");
  assert.equal(await check({ file: "app/crlf.ts", line: 3, token: "end\r" }), "failed");
  assert.deepEqual(citeLines("x\r\ny\r\n"), ["x", "y", ""]);
});

// T29-P1-C73 point 2 (P2 C70): a file with a lone CR (one not before \n) fails every citation, so the check's line
// count (\n alone) and the answers' (normalizeBreaks, which counts a lone CR) never disagree in a way that passes.
test("a file with a lone CR fails every citation, even a token on its first line", async () => {
  assert.equal(await check({ file: "app/mac.ts", line: 1, token: "await auth()" }), "failed");
  assert.equal(await check({ file: "app/mac.ts", line: 1, token: "line one" }), "failed");
  assert.equal(await check({ file: "app/crlf.ts", line: 2, token: "await auth();" }), "ok", "CRLF is not a lone CR");
});

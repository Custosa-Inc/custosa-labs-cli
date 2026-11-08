// files.elevated_imports lists each read
// file that names a binding it imports, through local imports, from a module that makes an elevated client itself.
import { test } from "node:test";
import assert from "node:assert/strict";
import { elevatedImports, summarize, ELEVATED_IMPORTS_MAX } from "../lib/inspector/helpers.mjs";

const ADMIN = 'import { createClient } from "@supabase/supabase-js";\nexport const supabaseAdmin = createClient(process.env.URL, process.env.SUPABASE_SERVICE_ROLE_KEY);\n';
const summaries = (files) => Object.entries(files).map(([path, code]) => summarize(path, path.endsWith(".py") ? "python" : "typescript", code));

test("a route naming an imported elevated client is a depth-1 row at the line that uses it", () => {
  const out = elevatedImports(summaries({
    "lib/admin.ts": ADMIN,
    "app/api/notes/route.ts": 'import { supabaseAdmin } from "@/lib/admin";\n\nexport async function GET() {\n  const { data } = await supabaseAdmin.from("notes").select();\n  return Response.json(data);\n}\n',
  }));
  assert.deepEqual(out.rows, [{ path: "app/api/notes/route.ts", line: 4, module: "lib/admin.ts", depth: 1 }]);
  assert.equal(out.complete, true);
});

test("through a barrel the row is depth 2 and names the module that makes the client; the barrel itself has none", () => {
  const out = elevatedImports(summaries({
    "lib/admin.ts": ADMIN,
    "lib/index.ts": 'export { supabaseAdmin } from "./admin";\n',
    "app/api/visits/route.ts": 'import { supabaseAdmin as db } from "@/lib";\nexport async function POST() {\n  return db.from("visits").insert({});\n}\n',
  }));
  assert.deepEqual(out.rows, [{ path: "app/api/visits/route.ts", line: 3, module: "lib/admin.ts", depth: 2 }]);
});

test("no row for a side-effect import, an unused binding, a test, a 'use client' file or the module itself", () => {
  const out = elevatedImports(summaries({
    "lib/admin.ts": ADMIN,
    "app/a/route.ts": 'import "@/lib/admin";\nexport async function GET() { return new Response(); }\n',
    "app/b/route.ts": 'import { supabaseAdmin } from "@/lib/admin";\nexport async function GET() { return new Response(); }\n',
    "tests/admin.test.ts": 'import { supabaseAdmin } from "../lib/admin";\nsupabaseAdmin.from("x");\n',
    "components/Panel.tsx": '"use client";\nimport { supabaseAdmin } from "@/lib/admin";\nsupabaseAdmin.from("x");\n',
  }));
  assert.deepEqual(out.rows, []);
});

test("a default, namespace or require binding counts, and Python's from-import too", () => {
  const out = elevatedImports(summaries({
    "lib/admin.ts": ADMIN,
    "server/a.ts": 'import * as admin from "../lib/admin";\nadmin.supabaseAdmin.from("x");\n',
    "server/b.ts": 'const { supabaseAdmin } = require("../lib/admin");\n\nsupabaseAdmin.from("x");\n',
    "app/db.py": 'from supabase import create_client\nadmin = create_client(URL, SUPABASE_SERVICE_ROLE_KEY)\n',
    "app/routes.py": 'from app.db import admin\n\n\ndef read():\n    return admin.table("notes").select().execute()\n',
  }));
  assert.deepEqual(out.rows, [
    { path: "app/routes.py", line: 5, module: "app/db.py", depth: 1 },
    { path: "server/a.ts", line: 2, module: "lib/admin.ts", depth: 1 },
    { path: "server/b.ts", line: 3, module: "lib/admin.ts", depth: 1 },
  ]);
});

test("past ELEVATED_IMPORTS_MAX rows the list is cut and marked incomplete", () => {
  const files = { "lib/admin.ts": ADMIN };
  for (let i = 0; i <= ELEVATED_IMPORTS_MAX; i++) files[`app/r${String(i).padStart(4, "0")}/route.ts`] = 'import { supabaseAdmin } from "@/lib/admin";\nsupabaseAdmin.from("x");\n';
  const out = elevatedImports(summaries(files));
  assert.equal(ELEVATED_IMPORTS_MAX, 500);
  assert.equal(out.rows.length, 500);
  assert.equal(out.complete, false);
});

// the forms black and isort write, and the forms the reader can't follow. A missing
// row must never read as nothing imported: a form that isn't followed marks the list incomplete.
const PY_ADMIN = 'from supabase import create_client\nadmin = create_client(URL, SUPABASE_SERVICE_ROLE_KEY)\n';
const USE = '\n\ndef read():\n    return admin.table("notes").select().execute()\n';

test("a parenthesised multi-line Python from-import is read", () => {
  const out = elevatedImports(summaries({
    "app/db.py": PY_ADMIN,
    "app/routes.py": `from app.db import (\n    admin,\n    other,\n)${USE}`,
    "app/cont.py": `from app.db import other, \\\n    admin${USE}`,
  }));
  assert.deepEqual(out.rows, [
    { path: "app/cont.py", line: 5, module: "app/db.py", depth: 1 },
    { path: "app/routes.py", line: 7, module: "app/db.py", depth: 1 },
  ]);
  assert.equal(out.complete, true);
});

test("import of several modules on one line is read", () => {
  const out = elevatedImports(summaries({
    "app/db.py": PY_ADMIN,
    "app/routes.py": 'import os, app.db\n\n\ndef read():\n    return app.db.admin.table("notes").select().execute()\n',
  }));
  assert.deepEqual(out.rows, [{ path: "app/routes.py", line: 5, module: "app/db.py", depth: 1 }]);
  assert.equal(out.complete, true);
});

test("a literal dynamic import or require is a row at its own line", () => {
  const out = elevatedImports(summaries({
    "lib/admin.ts": ADMIN,
    "app/api/a/route.ts": 'export async function GET() {\n  const { supabaseAdmin } = await import("../../../lib/admin");\n  return supabaseAdmin.from("x").select();\n}\n',
    "app/api/b/route.ts": 'export async function GET() {\n  return require("../../../lib/admin").supabaseAdmin.from("x").select();\n}\n',
    "app/py.py": 'import importlib\n\nadmin = importlib.import_module("app.db").admin\n',
    "app/db.py": PY_ADMIN,
  }));
  assert.deepEqual(out.rows, [
    { path: "app/api/a/route.ts", line: 2, module: "lib/admin.ts", depth: 1 },
    { path: "app/api/b/route.ts", line: 2, module: "lib/admin.ts", depth: 1 },
    { path: "app/py.py", line: 3, module: "app/db.py", depth: 1 },
  ]);
  assert.equal(out.complete, true);
});

test("an import the reader can't follow marks the list incomplete, never complete", () => {
  for (const [path, code] of [
    ["app/api/a/route.ts", 'export async function GET(name) {\n  const m = await import(`../../../lib/${name}`);\n  return m.default;\n}\n'],
    ["app/api/b/route.ts", 'const m = require(process.env.ADMIN_MODULE);\n'],
    ["app/routes.py", 'import importlib\n\nmod = importlib.import_module(NAME)\n'],
    ["app/other.py", 'mod = __import__(name)\n'],
  ]) {
    const out = elevatedImports(summaries({ "lib/admin.ts": ADMIN, [path]: code }));
    assert.equal(out.complete, false, path);
  }
  // A test file's dynamic import doesn't count: tests are left out of the rows.
  assert.equal(elevatedImports(summaries({ "lib/admin.ts": ADMIN, "tests/a.test.ts": 'await import(name);\n' })).complete, true);
});

// a star import binds names the reader can't list. One that reaches a module making an elevated
// client marks the list incomplete; a star import of a module that reaches none changes nothing.
test("a Python star import that reaches an elevated client marks the list incomplete", () => {
  const out = elevatedImports(summaries({
    "app/db.py": PY_ADMIN,
    "app/routes.py": `from app.db import *${USE}`,
  }));
  assert.deepEqual(out.rows, []);
  assert.equal(out.complete, false);
  const plain = elevatedImports(summaries({
    "app/db.py": PY_ADMIN,
    "app/util.py": "def helper():\n    return 1\n",
    "app/routes.py": `from app.util import *${USE}`,
  }));
  assert.equal(plain.complete, true);
});

// a package that re-exports by star import (app/__init__.py `from app.db import *`) uses none of
// the names it binds, so its star import hides nothing. The route's row is found and the list is complete. A star
// import in a file with any other code still counts, since that code may use a name it binds.
test("a barrel that only re-exports by star import keeps the list complete, with its route's row", () => {
  const files = {
    "app/db.py": PY_ADMIN,
    "app/__init__.py": '"""The app package."""\nfrom __future__ import annotations\nfrom app.db import *\nfrom . import util\n__all__ = ["admin", "util"]\n',
    "app/util.py": "def helper():\n    return 1\n",
    "app/routes.py": "from app import admin\n\ndef read():\n    return admin.table(\"notes\").select().execute()\n",
  };
  const out = elevatedImports(summaries(files));
  assert.deepEqual(out.rows, [{ path: "app/routes.py", line: 4, module: "app/db.py", depth: 2 }]);
  assert.equal(out.complete, true);
  // The same barrel with code of its own may use a star-bound name: incomplete, as before.
  const used = elevatedImports(summaries({ ...files, "app/__init__.py": "from app.db import *\n\ndef ping():\n    return admin\n" }));
  assert.equal(used.complete, false);
  const assigned = elevatedImports(summaries({ ...files, "app/__init__.py": "from app.db import *\nclient = admin\n" }));
  assert.equal(assigned.complete, false);
});

// A comment uses no name, so a barrel with `# noqa: F403` or a comment line stays complete;
// a `#` inside a string opens no comment. An f-string's braces are code: a barrel whose only other line is
// f"{admin}" may use a star-bound name, so the list is incomplete. `{{` is a literal brace and uses nothing.
test("a barrel's comments use no name, and an f-string's braces do", () => {
  const files = {
    "app/db.py": PY_ADMIN,
    "app/util.py": "def helper():\n    return 1\n",
    "app/routes.py": "from app import admin\n\ndef read():\n    return admin.table(\"notes\").select().execute()\n",
  };
  const barrel = (code) => elevatedImports(summaries({ ...files, "app/__init__.py": code }));
  for (const code of [
    "# Package exports\nfrom app.db import *  # noqa: F403\n",
    "from app.db import *  # re-export admin\n__all__ = ['admin']  # the public names\n",
    '"""Exports # every name."""\nfrom app.db import *\n',
    "from app.db import *\nf'{{admin}} is a literal'\n",
  ]) {
    assert.equal(barrel(code).complete, true, code);
  }
  for (const code of [
    'from app.db import *\nf"{admin}"\n',
    "from app.db import *\nF'''{admin.table}'''\n",
    'from app.db import *\nrf"{admin}" # uses admin\n',
    'from app.db import *\n"# not a comment"; admin\n',
  ]) {
    assert.equal(barrel(code).complete, false, code);
  }
});

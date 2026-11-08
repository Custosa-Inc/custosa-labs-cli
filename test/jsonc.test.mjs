/* a settings file with comments or trailing commas is read without changing a string. The old reader
   dropped every comma before ] or } with one regex, inside strings too, so "x,]" read as "x]". */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseJsonc, readSettings } from "../lib/files.mjs";

test("trailing commas are dropped only outside strings", () => {
  assert.deepEqual(parseJsonc('{"a":"x,]","b":"y, }"}'), { a: "x,]", b: "y, }" });
  assert.deepEqual(parseJsonc('{"a":[1,2,],"b":{"c":"\\",]",},}'), { a: [1, 2], b: { c: '",]' } });
  assert.deepEqual(parseJsonc('{"a": [1, 2 ,\n ] , // note\n}'), { a: [1, 2] });
  const file = join(mkdtempSync(join(tmpdir(), "jsonc-")), "settings.json");
  writeFileSync(file, '{\n  // the server\n  "args": ["--flag=a,]"],\n}\n');
  assert.deepEqual(readSettings(file), { args: ["--flag=a,]"] });
});

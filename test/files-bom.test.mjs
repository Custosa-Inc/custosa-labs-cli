/* Bug fix: reading a settings file drops a byte-order mark only at the start of the file, as editing it does. A
   BOM character inside a string value is part of that value and survives the read. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readSettings } from "../lib/files.mjs";

const BOM = "﻿";
const file = (text) => { const f = join(mkdtempSync(join(tmpdir(), "custosa-bom-")), "settings.json"); writeFileSync(f, text); return f; };

test("a BOM at the start of the file is dropped", () => {
  assert.deepEqual(readSettings(file(`${BOM}{"a":1}`)), { a: 1 });
  assert.deepEqual(readSettings(file(`${BOM}`)), {});
  assert.deepEqual(readSettings(file(`${BOM}  \n`)), {});
});

test("a BOM inside a string value is kept", () => {
  assert.deepEqual(readSettings(file(`{"a":"x${BOM}y"}`)), { a: `x${BOM}y` });
  assert.deepEqual(readSettings(file(`${BOM}{"a":"${BOM}y"}`)), { a: `${BOM}y` });
  assert.deepEqual(readSettings(file(`{"mcpServers":{"s":{"args":["${BOM}-y"]}}}`)), { mcpServers: { s: { args: [`${BOM}-y`] } } });
});

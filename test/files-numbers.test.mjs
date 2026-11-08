/* which JSON numbers setup refuses to rewrite (their value would change), and what else JSON.parse would lose. A
   settings file holding one of these is left as it is. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { lossyJson, numberChanges } from "../lib/files.mjs";

const KEPT = ["0", "0.0", "00", "0001", "1", "-1", "-5", "-5.0", "30", "30.0", "30.00", "3e1", "3E+1", "3e+1", "300e-1",
  "0.3e2", "0.001e3", "1e2", "1E2", "100", "1e21", "1e+21", "1e-6", "1e-07", "1e-7", "0.0000001", "0.1", "0.10", "1.5",
  "1.50", "123.456e3", "9007199254740992", "0.30000000000000004", "5e-324", "1.7976931348623157e308"];
const CHANGED = ["-0", "-0.0", "1e-400", "2e-324", "1e400", "-1e400", "1.7976931348623159e308", "9007199254740993",
  "123456789012345678", "12345678901234567890"];

test("numbers whose value survives a rewrite are kept", () => {
  for (const n of KEPT) assert.equal(numberChanges(n), false, n);
});

test("numbers whose value would change are refused: -0, out of range, or rounded", () => {
  for (const n of CHANGED) assert.equal(numberChanges(n), true, n);
});

test("lossyJson names the first key given twice or number that would change, else null", () => {
  const cases = [
    ["{}", null], ["[]", null], ['{"a":1}', null], ['[{"x":1},{"x":1}]', null], ['{"a":30.0}', null],
    ['{"a":"\\u0041","A":1}', null], ['{ "k" : [ true , false , null , "s" ] }', null],
    ['{"a":1,"a":2}', 'has the key "a" twice in one object'],
    ['{"a":{"b":1,"b":2}}', 'has the key "b" twice in one object'],
    ['{"a\\"b":1,"a\\"b":2}', 'has the key "a"b" twice in one object'],
    ['{"x":{},"y":[],"x":1}', 'has the key "x" twice in one object'],
    ['{"a":1e400}', "has the number 1e400, whose value would change if setup rewrote the file"],
    ['{"a":[1,-0]}', "has the number -0, whose value would change if setup rewrote the file"],
    ['{"a":12345678901234567890}', "has the number 12345678901234567890, whose value would change if setup rewrote the file"],
  ];
  for (const [text, expected] of cases) assert.equal(lossyJson(text), expected, text);
});

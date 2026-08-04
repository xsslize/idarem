import assert from "node:assert/strict";
import test from "node:test";

import { NAME_REF, eaAdd, findFunctionByAddress, toHex, type FunctionEntry } from "../src/api.ts";

test("normalizes 64-bit addresses without losing precision", () => {
  assert.equal(toHex("0x140001000"), "0x140001000");
  assert.equal(toHex("FFFFFFFFFFFFFFFF"), "0xFFFFFFFFFFFFFFFF");
});

test("adds byte offsets using bigint arithmetic", () => {
  assert.equal(eaAdd("0x140001000", 0x28), "0x140001028");
});

test("recognizes navigable IDA names only", () => {
  assert.equal(NAME_REF.test("sub_140001000"), true);
  assert.equal(NAME_REF.test("loc_140001020"), true);
  assert.equal(NAME_REF.test("__int64"), false);
});

test("finds the function containing an address with end-exclusive bounds", () => {
  const functions: FunctionEntry[] = [
    { ea: "0x1000", name: "first", size: 0x20 },
    { ea: "0x2000", name: "second", size: 0x10 },
  ];
  assert.equal(findFunctionByAddress(functions, "0x101F")?.name, "first");
  assert.equal(findFunctionByAddress(functions, "0x1020"), undefined);
  assert.equal(findFunctionByAddress(functions, "0x2000")?.name, "second");
  assert.equal(findFunctionByAddress(functions, "invalid"), undefined);
});

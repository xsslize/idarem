import assert from "node:assert/strict";
import test from "node:test";

import { NAME_REF, eaAdd, toHex } from "../src/api.ts";

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

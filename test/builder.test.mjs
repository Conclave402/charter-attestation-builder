// Acceptance tests for the Charter attestation builder (LAX seat f7ac7d66).
//
// Each test is named after an acceptance item and each fails without the change.
// Fixture texts are small stand-ins for the charter, constitution and soul; no
// real bundle is stored and no secret is used.

import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  buildAttestation,
  decodeCharterData,
  digestOf,
  SCHEMA,
} from "../src/builder.mjs";

const TEXTS = [
  "# Founding Charter\nWe the agents.",
  "# Constitution\nArticle one.",
  "# SOUL\nBe useful.",
];
const CIDS = [
  "bafybeicharter000000000000000000000000000000000000000000000000",
  "bafybeiconstitution0000000000000000000000000000000000000000000",
  "bafybeisoul00000000000000000000000000000000000000000000000000",
];
const VERSION = "1.0.0";
const DATE = "2026-10-22";

function sha256Hex(text) {
  return "0x" + createHash("sha256").update(Buffer.from(text, "utf8")).digest("hex");
}

test("A1 digests match sha256 of the given texts", () => {
  const { digests } = buildAttestation({ texts: TEXTS, cids: CIDS, version: VERSION, date: DATE });
  assert.equal(digests.length, TEXTS.length);
  TEXTS.forEach((t, i) => assert.equal(digests[i], sha256Hex(t)));
  assert.match(digests[0], /^0x[0-9a-f]{64}$/);
});

test("A2 the schema string is stable and carried on the payload", () => {
  const out = buildAttestation({ texts: TEXTS, cids: CIDS, version: VERSION, date: DATE });
  assert.equal(out.schema, SCHEMA);
  assert.equal(out.schema, "string version,string date,string[] names,bytes32[] digests,string[] cids");
  // Building twice yields the identical schema and data, no hidden state.
  const again = buildAttestation({ texts: TEXTS, cids: CIDS, version: VERSION, date: DATE });
  assert.equal(again.schema, out.schema);
  assert.equal(again.data, out.data);
});

test("A3 a changed text changes its digest and the encoded data", () => {
  const base = buildAttestation({ texts: TEXTS, cids: CIDS, version: VERSION, date: DATE });
  const changedTexts = TEXTS.slice();
  changedTexts[1] = "# Constitution\nArticle one (amended).";
  const changed = buildAttestation({ texts: changedTexts, cids: CIDS, version: VERSION, date: DATE });
  assert.notEqual(changed.digests[1], base.digests[1], "the changed text must change its digest");
  assert.equal(changed.digests[0], base.digests[0], "the other texts must not change");
  assert.equal(changed.digests[2], base.digests[2]);
  assert.notEqual(changed.data, base.data, "the encoded data must differ");
});

test("A4 buildAttestation rejects mismatched or empty input", () => {
  assert.throws(() => buildAttestation({ texts: TEXTS, cids: CIDS.slice(1), version: VERSION, date: DATE }), RangeError);
  assert.throws(() => buildAttestation({ texts: [], cids: [], version: VERSION, date: DATE }), RangeError);
  assert.throws(() => buildAttestation({ texts: TEXTS, cids: CIDS, version: 1, date: DATE }), TypeError);
});

test("A5 decodeCharterData reads back exactly what the schema encodes", () => {
  const out = buildAttestation({ texts: TEXTS, cids: CIDS, version: VERSION, date: DATE });
  const back = decodeCharterData(out.data);
  assert.equal(back.version, VERSION);
  assert.equal(back.date, DATE);
  assert.deepEqual(back.names, ["charter", "constitution", "soul"]);
  assert.deepEqual(back.digests, out.digests);
  assert.deepEqual(back.cids, CIDS);
});

test("A6 names are positional and parallel to digests and cids", () => {
  const out = buildAttestation({ texts: TEXTS, cids: CIDS, version: VERSION, date: DATE });
  const back = decodeCharterData(out.data);
  assert.equal(back.names.length, back.digests.length);
  assert.equal(back.names.length, back.cids.length);
  back.digests.forEach((d, i) => assert.equal(d, sha256Hex(TEXTS[i])));
  // A single text uses only the first name.
  const one = buildAttestation({ texts: [TEXTS[0]], cids: [CIDS[0]], version: VERSION, date: DATE });
  assert.deepEqual(decodeCharterData(one.data).names, ["charter"]);
});

test("A7 digestOf is the exact sha256 as 0x plus 64 lowercase hex", () => {
  assert.equal(digestOf("hello"), "0x" + createHash("sha256").update("hello").digest("hex"));
  assert.match(digestOf(""), /^0x[0-9a-f]{64}$/);
  // A string and a Buffer of its bytes hash the same.
  assert.equal(digestOf("abc"), digestOf(Buffer.from("abc", "utf8")));
});

test("A8 round trip survives unicode and empty strings", () => {
  const texts = ["", "Kognai \u2014 charter", "\u00e9\u00e8\u00ea"];
  const cids = ["cid0", "cid1", "cid2"];
  const out = buildAttestation({ texts, cids, version: VERSION, date: DATE });
  const back = decodeCharterData(out.data);
  assert.deepEqual(back.cids, cids);
  assert.deepEqual(back.digests, texts.map(sha256Hex));
});

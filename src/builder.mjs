// Charter attestation builder for LAX seat f7ac7d66.
//
// "A builder that hashes the Charter, the Constitution and the SOUL texts,
//  takes their IPFS ids, and outputs one EAS attestation payload for one
//  schema (with the schema string)."
//
//   buildAttestation({texts, cids, version, date}) -> {schema, data, digests}
//
// Pure: no RPC, no clock, no keys, no network. The texts and cids are passed in.
// `data` is ABI encoded for the schema the verifier seat a0d6e8f1 decodes:
//
//   string version, string date, string[] names, bytes32[] digests, string[] cids
//
// names, digests and cids are parallel arrays with one entry per text, in the
// order the caller supplies. Each digest is the sha256 of the exact UTF-8 bytes
// of that text, returned as 0x plus 64 lowercase hex, and ABI encoded as bytes32.

import { createHash } from "node:crypto";

export const SCHEMA =
  "string version,string date,string[] names,bytes32[] digests,string[] cids";

export const DEFAULT_NAMES = ["charter", "constitution", "soul"];

// sha256 of the UTF-8 bytes, as 0x + 64 lowercase hex.
export function digestOf(text) {
  if (typeof text !== "string" && !Buffer.isBuffer(text)) {
    throw new TypeError("digestOf requires a string or Buffer");
  }
  const bytes = Buffer.isBuffer(text) ? text : Buffer.from(text, "utf8");
  return "0x" + createHash("sha256").update(bytes).digest("hex");
}

// ---- minimal ABI encoder for the one schema ------------------------------
// Only the types in SCHEMA are supported, which keeps this dependency free and
// auditable. The layout follows the ABI spec: head slots of 32 bytes, then the
// tail, where a dynamic value is an offset from the start of the encoding.

function word(n) {
  return BigInt(n).toString(16).padStart(64, "0");
}

function hexWord(hex) {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  return h.padStart(64, "0");
}

function encString(s) {
  const b = Buffer.from(s, "utf8");
  const padded = Math.ceil(b.length / 32) * 32;
  const body = Buffer.alloc(padded);
  b.copy(body);
  return hexWord(word(b.length)) + body.toString("hex");
}

function encStringArray(arr) {
  const len = word(arr.length);
  const parts = arr.map((s) => encString(s));
  const n = parts.length;
  // Each element offset is relative to the start of the offsets area, which
  // begins right after the length word. So the first offset is the size of the
  // whole offsets area (n slots), and each later offset adds the byte size of
  // every preceding element (with its padding), not a fixed stride.
  const offsets = [];
  let cursor = 32 * n;
  for (const p of parts) {
    offsets.push(word(cursor));
    cursor += p.length / 2;
  }
  return len + offsets.join("") + parts.join("");
}

function encBytes32Array(arr) {
  const len = word(arr.length);
  return len + arr.map((h) => hexWord(h)).join("");
}

// Encode the five fields in schema order.
export function encodeCharterData({ version, date, names, digests, cids }) {
  const headSlots = 5;
  // Each dynamic field contributes one 32-byte head slot; the tail is laid out
  // in field order, and its offset is counted from the start of the encoding.
  const fields = [
    encString(version),
    encString(date),
    encStringArray(names),
    encBytes32Array(digests),
    encStringArray(cids),
  ];
  let offset = headSlots * 32;
  const head = [];
  const tail = [];
  for (const f of fields) {
    head.push(word(offset));
    tail.push(f);
    offset += f.length / 2;
  }
  return "0x" + head.join("") + tail.join("");
}

// ---- buildAttestation ----------------------------------------------------

export function buildAttestation({ texts, cids, version, date } = {}) {
  if (!Array.isArray(texts) || !Array.isArray(cids)) {
    throw new TypeError("buildAttestation: texts and cids must be arrays");
  }
  if (texts.length !== cids.length || texts.length === 0) {
    throw new RangeError("buildAttestation: texts and cids must be parallel and non-empty");
  }
  if (typeof version !== "string" || typeof date !== "string") {
    throw new TypeError("buildAttestation: version and date must be strings");
  }
  if (texts.length > DEFAULT_NAMES.length) {
    throw new RangeError(
      `buildAttestation: at most ${DEFAULT_NAMES.length} texts (charter, constitution, soul)`
    );
  }
  const names = DEFAULT_NAMES.slice(0, texts.length);
  const digests = texts.map((t) => digestOf(t));
  const data = encodeCharterData({ version, date, names, digests, cids });
  return { schema: SCHEMA, data, digests };
}

// decodeCharterData: the inverse, so the builder's output is self checking and
// interoperates with the a0d6e8f1 verifier. Returns {version, date, names,
// digests, cids} with digests as 0x + 64 lowercase hex.
export function decodeCharterData(dataHex) {
  if (typeof dataHex !== "string") throw new TypeError("decodeCharterData requires a hex string");
  const hex = dataHex.startsWith("0x") ? dataHex.slice(2) : dataHex;
  const buf = Buffer.from(hex, "hex");
  const readWord = (i) => parseInt(buf.slice(i * 32, i * 32 + 32).toString("hex"), 16);
  const at = (off) => off * 2; // char index into `hex` for byte offset `off`

  const versionOff = readWord(0);
  const dateOff = readWord(1);
  const namesOff = readWord(2);
  const digestsOff = readWord(3);
  const cidsOff = readWord(4);

  const readStringAt = (byteOff) => {
    const len = readWord(byteOff / 32);
    const start = at(byteOff + 32);
    return Buffer.from(hex.slice(start, start + len * 2), "hex").toString("utf8");
  };
  const readStringArrayAt = (byteOff) => {
    const n = readWord(byteOff / 32);
    const out = [];
    for (let i = 0; i < n; i++) {
      const itemOff = byteOff + 32 + readWord(byteOff / 32 + 1 + i);
      out.push(readStringAt(itemOff));
    }
    return out;
  };
  const readBytes32ArrayAt = (byteOff) => {
    const n = readWord(byteOff / 32);
    const out = [];
    for (let i = 0; i < n; i++) {
      const start = at(byteOff + 32 + i * 32);
      out.push("0x" + hex.slice(start, start + 64).toLowerCase());
    }
    return out;
  };

  return {
    version: readStringAt(versionOff),
    date: readStringAt(dateOff),
    names: readStringArrayAt(namesOff),
    digests: readBytes32ArrayAt(digestsOff),
    cids: readStringArrayAt(cidsOff),
  };
}

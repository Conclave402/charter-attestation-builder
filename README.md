# charter-attestation-builder

Build one EAS attestation payload from the Founding Charter, the Constitution and
the SOUL texts and their IPFS ids, for LAX job
`f7ac7d66-1708-46dc-99ce-47d74b3ece7e` (60 USDC).

Pure: no RPC, no clock, no keys, no network. The texts and cids are passed in,
and the module returns the schema string, the ABI encoded payload and the
per-text digests.

## Interface

```js
import { buildAttestation } from "charter-attestation-builder";

const { schema, data, digests } = buildAttestation({
  texts: [charterText, constitutionText, soulText], // the exact texts, in order
  cids:  [charterCid, constitutionCid, soulCid],    // their IPFS ids, parallel
  version: "1.0.0",
  date: "2026-10-22",
});
```

- `schema` is the EAS schema string:
  `string version,string date,string[] names,bytes32[] digests,string[] cids`.
- `data` is the ABI encoded payload for that schema, `0x` plus hex.
- `digests` are the sha256 of each text's exact UTF-8 bytes, as `0x` plus 64
  lowercase hex, in the same order as `texts`.

`buildAttestation` throws on mismatched or empty `texts`/`cids`, on a non string
`version` or `date`, and above three texts (the schema names charter, constitution
and soul).

`digestOf(text)` returns the sha256 digest on its own, and
`decodeCharterData(dataHex)` is the inverse of the encoding, returning
`{version, date, names, digests, cids}` so the payload is self checking and
interoperates with the verifier that reads the same schema.

## Encoding

The `data` value is a standard ABI encoding of the five schema fields. `names`,
`digests` and `cids` are parallel arrays with one entry per text; each digest is
encoded as `bytes32` and each of the others as its ABI type. The encoder is hand
written and dependency free, and the layout is covered by a round trip test and a
mutation test that pins a fixed stride (the classic `string[]` offset bug).

## Tests

```
node --test test/*.test.mjs
```

Eight tests, each named after an acceptance item and each failing without the
change: digests match sha256, the schema string is stable, a changed text changes
its digest and the data, input validation, the decode round trip, positional
parallel arrays, the exact digest format, and a unicode and empty string round
trip. No install, no network, Node 20 or later.

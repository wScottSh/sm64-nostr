# QR handoff spec: sm64-nostr reader decoder (format v3)

**Audience:** an author building a reader. **Goal:** given the QR frames the
cabinet shows after a star grab, produce a complete, broadcast-ready Nostr event
and publish it to a relay. This document is self-contained. You do not need repo
access to implement against it.

> **Status:** this spec defines **format v3** (`FORMAT_TAG 0x03`), which the ROM
> in `master` emits. A v3 reader must reject v1 (`0x01`) and v2 (`0x02`)
> payloads. The reader is a generic phone camera that opens a URL, plus the web
> page at that URL (ADR-0005). The page reassembles multi-frame payloads in the
> browser (ADR-0006). The invariant is **zero far-side reconstruction**: the
> reader decodes bytes and recomputes `id`, and invents no other value.

## 0. The one thing to internalize

Every QR frame is a plain `https://` URL. The packed binary payload is
base32-encoded, cut into numbered chunks, and each chunk rides in the URL's
`#` fragment. The reader collects every chunk, joins them in index order,
base32-decodes the result, and gets the packed payload back byte for byte. It
then re-inflates that payload into the canonical Nostr event the cabinet already
signed, and broadcasts it. The reader adds no value and performs no
verification. The relay and the leaderboard verify downstream. Every signed
value is fixed on-cartridge before the first frame is drawn.

## 1. QR frames and the URL envelope

### 1.1 QR-code parameters

Use any standard QR reader. Every frame has the same fixed symbol parameters:

| Parameter | Value |
|---|---|
| Version | **4** (33×33 modules) |
| Error correction | **MEDIUM** (~15%) |
| Mask | fixed (mask 0; recoverable from the format-info bits, as always) |
| Segments | two: a **BYTE** segment for `<BASE>#`, then an **ALPHANUMERIC** segment for the fragment |
| On-screen size | 3 px per module, 4-module quiet zone per side, 123×123 px image |
| Count | **1 to 8** frames per event (§1.4) |

A standard QR library returns the two segments concatenated as one text string,
which is the frame's full URL. A camera-based reader **must** perform
Reed–Solomon error correction (standard in every QR library). The repo's
`tools/pipeline_test/qr_host_decode.c` is a reference bit-walker that omits RS
because it decodes a clean in-memory bitmap. Do **not** model a camera app on it
for the bitmap-to-text step. Use a real reader.

When a payload needs more than one frame, the cabinet cycles through the frames
in index order and holds each one for 10 render ticks (about 0.33 s at 30 Hz).
Frames can be captured in any order.

### 1.2 URL template

Each frame's text is one URL:

```
<BASE>#<SEQ>/<TOTAL>/<PAYLOAD>
```

| Part | Format |
|---|---|
| `<BASE>` | The build's base URL, emitted verbatim (case preserved). Absolute `https://` URL, at most 36 characters, never contains `#`. Default `https://sm64nostr.pages.dev`. |
| `#` | Literal separator. The first `#` in the URL starts the fragment. |
| `<SEQ>` | 0-based frame index, 2 base36 digits (`0-9A-Z`, uppercase), zero-padded. |
| `/` | Literal field separator. |
| `<TOTAL>` | Total frame count, 2 base36 digits, zero-padded. Value `1..1295`. |
| `/` | Literal field separator. |
| `<PAYLOAD>` | This frame's slice of the base32 text (§1.3). |

Example frame: `https://sm64nostr.pages.dev#00/05/AMHQMZAB...`.

Do not compare `<BASE>` against an expected host. Split the URL once on the
first `#` and parse everything after it. Frames wrapped around different bases
reassemble the same way.

### 1.3 Base32 text and chunking

The cabinet base32-encodes the packed payload (§2) with the RFC 4648 §6
alphabet `ABCDEFGHIJKLMNOPQRSTUVWXYZ234567`, uppercase, MSB-first, **no `=`
padding**. A trailing partial group is zero-padded in its low bits. The encoded
length is `ceil(8 × payload_len / 5)` characters.

The cabinet cuts that text into chunks of a fixed per-build length. Every
chunk except the last has that length. The last chunk holds the remainder and
is never longer than the others. Chunk `i` is the `<PAYLOAD>` of frame `i`.

### 1.4 How many frames

The chunk length depends only on the length of `<BASE>`, because both segments
share one version-4 MEDIUM symbol (64 data codewords, 512 bits):

```
alnum_bits = 512 - 12 - 8 × (len(BASE) + 1) - 13
fragment_chars = 2 × floor(alnum_bits / 11) + (1 if alnum_bits mod 11 >= 6 else 0)
chunk_len = fragment_chars - 6
TOTAL = ceil(base32_len / chunk_len)
```

`12` and `13` are the BYTE and ALPHANUMERIC segment headers (mode indicator plus
character count). `6` is the `SS/TT/` header. With the 27-character default base,
each chunk holds 41 base32 characters. The 36-character base cap keeps the
worst-case payload (140 B, 224 base32 characters) at 8 frames or fewer. A reader
does not need this formula. It reads `<TOTAL>` from any frame.

### 1.5 Reassembly

1. Start from the URL the phone camera opened. Its `#` fragment is the first
   frame. If `<TOTAL>` is 1, that frame is the whole payload, so skip to step 4.
2. Scan further frames, for example with `getUserMedia` and a QR library in the
   page. Parse each frame's header. Keep the first chunk seen for each index.
3. Stop when every index `0..TOTAL-1` is present.
4. Concatenate the chunks in index order and base32-decode the text. The result
   is the packed payload (§2).

Reject a frame set that mixes events (§6). A set with missing indexes is
incomplete, not a shorter payload.

## 2. Payload layout (format v3)

Fixed-order binary, **big-endian** for multibyte integers, no delimiters, no
compression, two variable-length fields (`TAG` and `NAME`). Total =
`113 + TAG_LEN + NAME_LEN` bytes, so 113 to 140 bytes.

| Offset | Field | Size | Type | Notes |
|---|---|---|---|---|
| 0 | `FORMAT_TAG` | 1 | u8 | **MUST be `0x03`**. Reject otherwise. |
| 1 | `COURSE` | 1 | u8 | run field, becomes `content.course` |
| 2 | `ACT` | 1 | u8 | run field, becomes `content.act` |
| 3 | `COINS` | 1 | u8 | run field, becomes `content.coins` |
| 4 | `FRAMES` | 4 | u32 BE | in-course elapsed frames, becomes `content.frames` (`0` = no in-course time) |
| 8 | `NONCE16` | 2 | u16 BE | run field, becomes `content.nonce` |
| 10 | `KEY_ID` | 1 | u8 | star index, becomes `content.keyId` |
| 11 | `CREATED_AT` | 4 | u32 BE | unix seconds (the build epoch), becomes `event.created_at` |
| 15 | `PUBKEY` | 32 | bytes | x-only pubkey, becomes `event.pubkey` (hex) |
| 47 | `TAG_LEN` | 1 | u8 | length of `TAG`, `0..10` |
| 48 | `TAG` | `TAG_LEN` | ASCII | per-game `t` tag value |
| 48+`TAG_LEN` | `NAME_LEN` | 1 | u8 | length of `NAME`, `0..17` |
| 49+`TAG_LEN` | `NAME` | `NAME_LEN` | ASCII | event name, the `n` tag value |
| 49+`TAG_LEN`+`NAME_LEN` | `SIG` | 64 | bytes | BIP-340 Schnorr sig, becomes `event.sig` (hex) |

Notes:
- `TAG_LEN` and `NAME_LEN` caps are per-field limits of format v3. A larger value
  is malformed. Reject it.
- `PUBKEY` and `SIG` are raw bytes on the wire. Hex-encode them (lowercase) for
  the JSON event.
- `docs/format-v3-spec.md` defines how the cabinet computes `FRAMES`.

## 3. Reconstructing the event

Build this object (this is what you broadcast):

```json
{
  "id":         "<see §4>",
  "pubkey":     "<lowercase hex of PUBKEY, 64 chars>",
  "created_at": <CREATED_AT as integer>,
  "kind":       8064,
  "tags":       [["t","ag-lb"], ["t","<TAG>"], ["n","<NAME>"]],
  "content":    "<see §3.1>",
  "sig":        "<lowercase hex of SIG, 128 chars>"
}
```

Spec constants, pinned by `FORMAT_TAG 0x03` and **not** on the wire:
- `kind` = **8064**
- the first tag is always `["t","ag-lb"]` (airgapped-leaderboard), **before** the
  per-game tag and the name tag. Tag order is significant. It is part of the
  signed serialization.

### 3.1 The `content` string

`content` is itself a JSON object, serialized to a string with **exact key order**
and **shortest decimal** integers (no leading zeros, no `+`, no spaces):

```json
{"course":<COURSE>,"act":<ACT>,"coins":<COINS>,"frames":<FRAMES>,"nonce":<NONCE16>,"keyId":<KEY_ID>}
```

`frames` and `nonce` are the decimal values of the big-endian integers (for
example, `FRAMES` bytes `01 02 03 04` give `16909060` and `NONCE16` bytes
`CA FE` give `51966`). The JSON key is `nonce`, though the wire field is
`NONCE16`.

When embedded in the event's `content` field this string is JSON-escaped normally
(the inner `"` become `\"`). It is a JSON string whose value is the object text
above. This double serialization must be byte-exact or the `id` will not match.

## 4. Computing `id`

`id` is the `sha256` of the NIP-01 canonical serialization, a compact
(no-whitespace) UTF-8 JSON array:

```
[0,"<pubkey_hex>",<created_at>,8064,[["t","ag-lb"],["t","<TAG>"],["n","<NAME>"]],"<escaped content>"]
```

`<escaped content>` is the string from §3.1 with NIP-01 escaping (`"` becomes
`\"`, `\` becomes `\\`, plus the control-character rules in NIP-01). Any
standard Nostr library's `getEventHash` or `serializeEvent` does this for you.
Feed it the object from §3 without `id` and take the hash. Hex-encode it
(lowercase) into `event.id`.

There is no packed id. You compute it. Relays reject an event whose `id` doesn't
equal the recomputed hash.

## 5. Broadcast

Publish the assembled event over a relay `EVENT` message (NIP-01). You do not
verify the signature. The relay does. For a local sanity check, you may run
`schnorr.verify(sig, id, pubkey)` (BIP-340), but it is optional and must never
gate broadcast.

## 6. Rejection rules (a conforming reader MUST)

- Reject a frame whose URL has no `#`, or whose header is not two base36 digits,
  `/`, two base36 digits, `/`.
- Reject a frame whose `<TOTAL>` is 0 or whose `<SEQ>` is not less than `<TOTAL>`.
- Reject a frame set whose frames disagree on `<TOTAL>`, whose non-last chunks
  differ in length, or whose last chunk is longer than a non-last chunk. Such a
  set mixes frames from two events.
- Reject a `<PAYLOAD>` character outside the base32 alphabet.
- Reject if `FORMAT_TAG != 0x03`.
- Reject if `TAG_LEN > 10` or `NAME_LEN > 17`.
- Reject if the decoded byte length `!= 113 + TAG_LEN + NAME_LEN`.
- Never guess or substitute a value not present in the payload or pinned by this
  spec. Never re-sign, mutate, or add fields.

## 7. Conformance vector

This vector is real cabinet output. `build_event()` produced the frames, and
`tools/pipeline_test/gen_reader_fixture.c` recorded them. The `id` and `sig`
also match the `nostr-tools` and `@noble/curves` oracles for the repo's "vector
A" (§7.1).

Input fields:

```
COURSE=15 ACT=6 COINS=100 FRAMES=16909060 NONCE16=51966 KEY_ID=0
CREATED_AT=1700000000  TAG="sm64"  NAME="TEST"
privkey=0x0000...0003  → PUBKEY=f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9
BASE="https://Sm64Nostr.Pages.Dev"
```

The five frames (121 B payload, 194 base32 characters, 41-character chunks):

```
https://Sm64Nostr.Pages.Dev#00/05/AMHQMZABAIBQJSX6ABSVH4IA7EYIUAMSLDBRASJUJ
https://Sm64Nostr.Pages.Dev#01/05/6C7RHKSFG2TDSCFQNXZTMEGAHYRHPHAG34QI43NGY
https://Sm64Nostr.Pages.Dev#02/05/2AIVCFKNKA6S5IBLRT7DUODPSAQOD7B2HCGO5CY6Y
https://Sm64Nostr.Pages.Dev#03/05/HSEQOBQJINWLVAN2ZKP2PCWEHK6GPI2J2HLKFI34J
https://Sm64Nostr.Pages.Dev#04/05/TYLWWESTTGGZ73Z2RIM5XL4GP5ISWA
```

The packed bytes they reassemble to (§2's wire layout, 121 B = 113 + 4-byte
`TAG` + 4-byte `NAME`), hex-encoded:

```
030f066401020304cafe006553f100f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f904736d363404544553540f4ba80ae33f8e8e1be408387f0e8e233ba2c7b079120e0c1286d9750375953f4f15887578cf4693a3ad4546f899e176b1253998d9fef3a8a19dbaf867f512b0
```

The resulting reference event (what a conforming reader reconstructs from those
frames and broadcasts):

```json
{
  "id":         "91ff8df59c339bf5c643750cdb1c7edf99c48aa9ce7879a22c9a52da7b84362f",
  "pubkey":     "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
  "created_at": 1700000000,
  "kind":       8064,
  "tags":       [["t","ag-lb"], ["t","sm64"], ["n","TEST"]],
  "content":    "{\"course\":15,\"act\":6,\"coins\":100,\"frames\":16909060,\"nonce\":51966,\"keyId\":0}",
  "sig":        "0f4ba80ae33f8e8e1be408387f0e8e233ba2c7b079120e0c1286d9750375953f4f15887578cf4693a3ad4546f899e176b1253998d9fef3a8a19dbaf867f512b0"
}
```

A reader is conformant if, from the frames above in any order, it produces the
exact `id`, `pubkey`, `tags`, `content`, and `sig` of the reference event.

### 7.1 Reproducing this vector (repo access required)

Everything above is enough to validate a reader without touching this repo.
This subsection is for maintainers regenerating the vector.

The frames live in `reader/test/fixtures/multiframe_fixture.json`. Regenerate
them with `cd tools/pipeline_test && make reader-fixture`, and run
`cd reader && npm ci && npm test` to check that `reader/reader.js` decodes them
to the expected `id` and that the `sig` verifies. The same capture is "vector A" in `tools/pipeline_test/main.c`.
Three checks must agree on its `id` and `sig`: (1)
`node tools/reference_event_id.js` (the `nostr-tools` `getEventHash` oracle,
requires `npm install nostr-tools` in `tools/`); (2)
`node tools/verify_schnorr_reference.js` (the `@noble/curves` BIP-340 oracle,
requires `npm install @noble/curves`); (3)
`cd tools/pipeline_test && make clean && make test` (the pipeline test). On a
machine without a local C toolchain, run the last step inside the repo's build
image (see the `docker build` and `docker run` invocations in `README.md`).

### 7.2 Format v2 live captures (must be rejected)

`tools/pipeline_test/fixtures/qr_v2_live_captures.json` holds real format-v2
payloads photographed off a running device before v3 landed. They carry
`FORMAT_TAG 0x02`, so a v3 reader must reject them. `main.c`'s
`test_live_wire_vectors_round_trip()` asserts that rejection. No v3 live
capture is frozen yet.

## 8. References

- `docs/adr/0005`: reader is a phone camera plus a URL-carried QR, with zero
  far-side reconstruction.
- `docs/adr/0006`: adaptive multi-frame transport, and its issue #152
  amendment to version 4 at 3 px per module.
- `docs/adr/0007` and `docs/format-v3-spec.md`: format v3 content and the
  `FRAMES` timer.
- `docs/research/qr-density-tradeoffs.md`: capacity and ECC analysis, with the
  version sweep in section 9.
- NIP-01 (event structure, serialization, `id`), BIP-340 (Schnorr sig and pubkey).

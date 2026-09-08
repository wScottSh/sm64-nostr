# QR handoff spec — sm64-nostr companion decoder (format v2)

**Audience:** an author building the companion app. **Goal:** given a photo of the
on-screen QR, produce a complete, broadcast-ready Nostr event and publish it to a
relay. This document is self-contained — you do not need repo access to implement
against it.

> **Status:** this spec defines **format v2**, the self-contained layout. The ROM
> in `master` currently emits **format v1** (`FORMAT_TAG 0x01`, 75 B, no pubkey /
> created_at / tag on the wire). A v2 companion must reject v1. Do not ship a
> companion against this spec until the ROM emits `FORMAT_TAG 0x02`.

## 0. The one thing to internalize

The QR does **not** contain JSON, bech32, an `nevent`/`naddr`, or a URI. It
contains a **raw binary blob** in a QR BYTE segment. The companion is **read-only**:
it decodes the blob, re-inflates it into the canonical Nostr event the cartridge
already signed, and broadcasts it. The companion **adds no value** and performs
**no verification** — the relay/leaderboard verifies downstream. Every signed
value is fixed on-cartridge before the QR is drawn. (See `docs/adr/0001`.)

## 1. QR-code parameters

Use any standard QR reader. The symbol is fixed:

| Parameter | Value |
|---|---|
| Version | **7** (45×45 modules) |
| Error correction | **MEDIUM** (~15%) |
| Encoding mode | **BYTE** (8-bit) — a single segment, raw bytes |
| Mask | fixed (recoverable from the format-info bits, as always) |
| Count | **one** QR, never chunked |
| Payload | 112–122 bytes (see §2) |

A camera-based reader **must** perform Reed–Solomon error correction (standard in
every QR library). The repo's `tools/pipeline_test/qr_host_decode.c` is a
reference bit-walker that omits RS because it decodes a clean in-memory bitmap —
do **not** model a camera app on it for the bitmap→bytes step; use a real reader.

## 2. Payload layout (format v2)

Fixed-order binary, **big-endian** for multibyte integers, no delimiters, no
compression, one variable-length field (the tag). Total = `112 + TAG_LEN` bytes.

| Offset | Field | Size | Type | Notes |
|---|---|---|---|---|
| 0 | `FORMAT_TAG` | 1 | u8 | **MUST be `0x02`** — reject otherwise |
| 1 | `COURSE` | 1 | u8 | run field → `content.course` |
| 2 | `ACT` | 1 | u8 | run field → `content.act` |
| 3 | `COINS` | 1 | u8 | run field → `content.coins` |
| 4 | `FRAMES` | 4 | u32 BE | run field → `content.frames` |
| 8 | `NONCE16` | 2 | u16 BE | run field → `content.nonce` |
| 10 | `KEY_ID` | 1 | u8 | star index → `content.keyId` |
| 11 | `CREATED_AT` | 4 | u32 BE | unix seconds → `event.created_at` |
| 15 | `PUBKEY` | 32 | bytes | x-only pubkey → `event.pubkey` (hex) |
| 47 | `TAG_LEN` | 1 | u8 | length of `TAG`, `0..10` |
| 48 | `TAG` | `TAG_LEN` | ASCII | per-game `t` tag value |
| 48+`TAG_LEN` | `SIG` | 64 | bytes | BIP-340 Schnorr sig → `event.sig` (hex) |

Notes:
- `TAG_LEN` is capped at **10** for v7-MEDIUM. A value >10 means a future format
  (v8-MEDIUM allows ≤40); reject anything you don't recognize.
- `PUBKEY` and `SIG` are raw bytes on the wire; hex-encode them (lowercase) for
  the JSON event.

## 3. Reconstructing the event

Build this object (this is what you broadcast):

```json
{
  "id":         "<see §4>",
  "pubkey":     "<lowercase hex of PUBKEY, 64 chars>",
  "created_at": <CREATED_AT as integer>,
  "kind":       8064,
  "tags":       [["t","ag-lb"], ["t","<TAG>"]],
  "content":    "<see §3.1>",
  "sig":        "<lowercase hex of SIG, 128 chars>"
}
```

Spec constants — pinned by `FORMAT_TAG 0x02`, **not** on the wire:
- `kind` = **8064**
- first tag is always `["t","ag-lb"]` (airgapped-leaderboard), **before** the
  per-game tag. Order is significant — it is part of the signed serialization.

### 3.1 The `content` string

`content` is itself a JSON object, serialized to a string with **exact key order**
and **shortest decimal** integers (no leading zeros, no `+`, no spaces):

```json
{"course":<COURSE>,"act":<ACT>,"coins":<COINS>,"frames":<FRAMES>,"nonce":<NONCE16>,"keyId":<KEY_ID>}
```

`frames` and `nonce` are the decimal values of the big-endian integers (e.g.
`FRAMES` bytes `01 02 03 04` → `16909060`; `NONCE16` bytes `CA FE` → `51966`).
Note the JSON key is `nonce`, though the wire field is `NONCE16`.

When embedded in the event's `content` field this string is JSON-escaped normally
(the inner `"` become `\"`), i.e. it is a JSON string whose value is the object
text above. This double-serialization must be byte-exact or the `id` will not
match.

## 4. Computing `id`

`id` = `sha256` of the NIP-01 canonical serialization — a compact (no-whitespace)
UTF-8 JSON array:

```
[0,"<pubkey_hex>",<created_at>,8064,[["t","ag-lb"],["t","<TAG>"]],"<escaped content>"]
```

where `<escaped content>` is the string from §3.1 with NIP-01 escaping (`"`→`\"`,
`\`→`\\`, and the control-char rules in NIP-01). Any standard Nostr library's
`getEventHash` / `serializeEvent` does this for you — feed it the object from §3
(minus `id`) and take the hash. Hex-encode (lowercase) into `event.id`.

Do **not** trust a packed id — there isn't one; you compute it. Relays reject an
event whose `id` doesn't equal the recomputed hash.

## 5. Broadcast

Publish the assembled event over a relay `EVENT` message (NIP-01). You do not
verify the signature; the relay does. If you want a local sanity check, you may
optionally run `schnorr.verify(sig, id, pubkey)` (BIP-340) — but it is not
required and must never gate broadcast.

## 6. Rejection rules (a conforming companion MUST)

- Reject if `FORMAT_TAG != 0x02`.
- Reject if `TAG_LEN > 10` (unknown/oversized for this version).
- Reject if the decoded byte length `!= 112 + TAG_LEN`.
- Never guess or substitute a value not present in the payload or pinned by this
  spec. Never re-sign, mutate, or add fields.

## 7. Conformance vector

The `id` and `sig` below are **oracle-verified, not hand-written**: computed by
the repo's v2 pipeline test (`tools/pipeline_test`), then independently
cross-checked against `nostr-tools`' `getEventHash` (for `id`) and
`@noble/curves`' BIP-340 Schnorr (for `sig`) — see §7.1 for how to reproduce
this yourself.

Input fields for the canonical vector:

```
COURSE=15 ACT=6 COINS=100 FRAMES=16909060 NONCE16=51966 KEY_ID=0
CREATED_AT=1700000000  TAG="sm64"
privkey=0x0000...0003  → PUBKEY=f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9
```

The packed bytes (§2's wire layout, 116 B = 112 + 4-byte `TAG`), hex-encoded:

```
020f066401020304cafe006553f100f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f904736d363469676d63728cd3d1cc1f918678547779e917b03db54832e8f71a0232eb4beedd804ca767605597381ca4a2a9f81d1ff8f20737bd1ec187cb2999ea9b2270487b
```

The resulting reference event (what a conforming companion reconstructs from
those bytes and broadcasts):

```json
{
  "id":         "da41e3231cbb228dd6a68ddd57fb54dc00528d62a35990d2ef5870bc832aa4ee",
  "pubkey":     "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
  "created_at": 1700000000,
  "kind":       8064,
  "tags":       [["t","ag-lb"], ["t","sm64"]],
  "content":    "{\"course\":15,\"act\":6,\"coins\":100,\"frames\":16909060,\"nonce\":51966,\"keyId\":0}",
  "sig":        "69676d63728cd3d1cc1f918678547779e917b03db54832e8f71a0232eb4beedd804ca767605597381ca4a2a9f81d1ff8f20737bd1ec187cb2999ea9b2270487b"
}
```

A companion is conformant if, from the packed bytes above, it produces the
exact `id`, `pubkey`, `tags`, `content`, and `sig` of the reference event.

### 7.1 Reproducing this vector (repo access required)

Everything above is enough to validate a companion without touching this repo.
The rest of this subsection is for maintainers regenerating the vector itself,
the same way §1 flags `qr_host_decode.c` as a repo-only reference tool, not
something a companion author needs.

This vector is "vector A" in `tools/pipeline_test/main.c`. Three independent
checks must agree: (1) `node tools/reference_event_id.js` (the `nostr-tools`
`getEventHash` oracle for `id`, requires `npm install nostr-tools` in `tools/`);
(2) `node tools/verify_schnorr_reference.js` (the `@noble/curves` BIP-340
oracle for `sig`, requires `npm install @noble/curves`); (3)
`cd tools/pipeline_test && make clean && make test` (the actual pipeline test;
`test_build_event_end_to_end()` builds this exact vector and asserts its `id`
and `sig` equal the two oracle values — see the file's own header comment for
the KAT privkey/aux_rand). On a machine without a local C toolchain, run that
last step inside the repo's build image instead (see `README.md`'s
`docker build`/`docker run` invocations for building and mounting it).

### 7.2 Live on-device capture vectors

The vector above is synthetic (KAT privkey `3`, fixed `created_at`). For a
second, independent check against **real hardware output**, the repo also
freezes actual format-v2 QR payloads photographed off a running device:

- `tools/pipeline_test/fixtures/qr_v2_live_captures.json` — each real wire
  payload (`wire_hex`) paired with the exact broadcast-ready event it decodes
  to. This is the ground-truth shape of decoded data; build a companion
  decoder against it, don't infer.
- `tools/pipeline_test/fixtures/gen_live_vectors.mjs` — regenerator. Takes only
  the wire bytes, decodes, and **refuses to write any vector whose sig doesn't
  verify** (`node tools/pipeline_test/fixtures/gen_live_vectors.mjs`). It also
  emits `live_vectors.h`, which `test_live_wire_vectors_round_trip()` in
  `main.c` asserts against: unpack the on-device bytes, recompute the `id` from
  only those fields, and verify the wire sig — pinning the ROM encoder to real
  device output.

Current live vectors (both `t` tag `sm64`, kind `8064`):

| Vector | id |
|---|---|
| `capture_1` | `29ae1dd77d3baa3e72ab608e554af44e9d241e7c1f07bb48aa50c1660fc64f87` |
| `capture_2` | `0eda86203f3868a271af8756ca282aa825a33bcd49728d31700d5b94f06fbd41` |

## 8. References

- `docs/adr/0001` — read-only companion / self-contained QR.
- `docs/adr/0002` — format v2 wire layout, v7/MEDIUM rationale.
- `docs/research/qr-density-tradeoffs.md` — capacity and ECC analysis (primary-sourced).
- NIP-01 (event structure, serialization, `id`), BIP-340 (Schnorr sig/pubkey).

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

> **TODO (fill on v2 landing):** the concrete `id`/`sig` must be produced by the
> repo's reference oracles (`tools/reference_event_id.js` via nostr-tools
> `getEventHash`, and `tools/verify_schnorr_reference.js` via `@noble/curves`)
> against the actual v2 pipeline — they are **not** hand-written here, to avoid
> shipping an unverified hash.

Input fields for the canonical vector (once computed, the expected hex `id` and
`sig` go here):

```
COURSE=15 ACT=6 COINS=100 FRAMES=16909060 NONCE16=51966 KEY_ID=0
CREATED_AT=1700000000  TAG="sm64"
privkey=0x0000...0003  → PUBKEY=f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9
```

A companion is conformant if, from the packed bytes for the above, it produces the
exact `id`, `pubkey`, `tags`, `content`, and `sig` of the reference event.

## 8. References

- `docs/adr/0001` — read-only companion / self-contained QR.
- `docs/adr/0002` — format v2 wire layout, v7/MEDIUM rationale.
- `docs/research/qr-density-tradeoffs.md` — capacity and ECC analysis (primary-sourced).
- NIP-01 (event structure, serialization, `id`), BIP-340 (Schnorr sig/pubkey).

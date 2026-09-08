# QR density vs. robustness for a self-contained, broadcast-ready nostr event

Research doc. Every claim is tied to a primary source: a spec section, a
primary-vendor page, or a `file:line` in this repo's vendored code. Where a
number is *derived* rather than quoted, the derivation is shown so it can be
re-checked. Absence of evidence is called out explicitly.

**Frame (design decision already made, not relitigated here):** the QR carries a
COMPLETE, already-signed, broadcast-ready nostr event; the companion app is
strictly READ-ONLY (decode bytes -> broadcast to relay, injects no value). The
current on-wire payload is a 75-byte packed blob at QR version 6 / ECC MEDIUM /
BYTE mode that OMITS `pubkey` and `created_at` (baked out-of-band in
`event_profile.h`) — that omission is the defect. Goal: the smallest fully
self-contained single QR, with the simplest/cheapest possible in-game encoder.

Sources used repeatedly, cited short below:
- **BIP-340** = https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
- **NIP-01** = https://github.com/nostr-protocol/nips/blob/master/01.md
- **qrcodegen.c/.h** = `src/pipeline/qrcodegen.c`, `src/pipeline/qrcodegen.h`
  (this repo's vendored C99 port of Project Nayuki's generator — authoritative
  for what THIS encoder actually does)
- **Denso Wave** = https://www.qrcode.com/en/about/error_correction.html (QR
  code inventor's own guidance)
- **nostr-tools** = https://github.com/nbd-wtf/nostr-tools (`pure.ts`) — the most
  widely used client library, cited as evidence of what "standard clients" do.

---

## 1. Signature & pubkey floor — can either shrink or be omitted?

**Answer: No. Signature is necessarily 64 bytes and pubkey necessarily 32 bytes
(x-only). There is no relay-acceptable way to reduce or omit either.**

- BIP-340 fixes the signature at **64 bytes** and the public key at **32 bytes**
  (x-only): *"Encoding only the X coordinate, resulting in 32-byte public keys
  and 64-byte signatures."* The signature is `bytes(R) || bytes((k + ed) mod n)`
  — two 32-byte halves = 64 bytes; DER is explicitly rejected in favor of *"a
  simple fixed 64-byte format."* (BIP-340.)
- NIP-01 requires both fields in every event: `pubkey` = *"32-bytes lowercase
  hex-encoded public key"* and `sig` = *"64-bytes lowercase hex..."* (NIP-01
  event structure). Over the wire we can pack the raw bytes (32 / 64) rather
  than hex, but the *values* are irreducible.
- Omission is not an option: the companion is read-only and injects nothing, so
  it cannot supply a pubkey or re-sign. NIP-01's `id`/`sig` are a cryptographic
  commitment over `pubkey` (see §6); a missing or altered pubkey changes the
  `id` and invalidates the signature. Standard verifiers reject
  (nostr-tools `verifyEvent`, see §6).

**Floor = 64 (sig) + 32 (pubkey) = 96 bytes that MUST be on the wire, raw.**
No further compression is available: a Schnorr signature and a secp256k1 x-only
key are effectively incompressible random 256-bit / 512-bit values.

---

## 2. QR BYTE-mode capacity table (the core lever)

The vendored encoder computes usable data codewords as
`getNumDataCodewords(v,e) = getNumRawDataModules(v)/8 - ECC_CODEWORDS_PER_BLOCK[e][v] * NUM_ERROR_CORRECTION_BLOCKS[e][v]`
(`qrcodegen.c:368-374`), with the raw-module formula at `qrcodegen.c:380-391`
and the two ECC tables at `qrcodegen.c:169-176` and `qrcodegen.c:181-188`.

**Raw data codewords** (`getNumRawDataModules(v)/8`, derived from
`qrcodegen.c:380-391`): v5 = 1079/8 = **134**; v6 = 1383/8 = **172**;
v7 = 1568/8 = **196**; v8 = 1936/8 = **242**.

**Total DATA codewords per version/ECC** (derived; each also matches the
published ISO/IEC 18004 capacity tables — cross-checked, identical):

| Ver (size) | L | M | Q | H |
|---|---|---|---|---|
| 5 (37x37) | 108 | 86 | 62 | 46 |
| 6 (41x41) | 136 | 108 | 76 | 60 |
| 7 (45x45) | 156 | 124 | 88 | 66 |
| 8 (49x49) | 194 | 154 | 110 | 86 |

**Usable BYTE-mode PAYLOAD** = `floor((dataCodewords*8 - 4 - charCountBits)/8)`.
The 4-bit mode indicator + BYTE-mode char-count header is charged in
`getTotalBits` (`qrcodegen.c:873-889`); for versions 1-9 the byte-mode count
field is **8 bits** (`numCharCountBits`, `qrcodegen.c:894-900`), so overhead =
12 bits and payload = `dataCodewords - 2` bytes for v5-v8:

| Ver (size) | L | M | Q | H |
|---|---|---|---|---|
| 5 (37x37) | 106 | 84 | 60 | 44 |
| 6 (41x41) | **134** | 106 | 74 | 58 |
| 7 (45x45) | 154 | 122 | 86 | 64 |
| 8 (49x49) | 192 | 152 | 108 | 84 |

Cross-check against this repo's own asserted number: `qr_adapter.h:29-33,51-58`
states v6/MEDIUM usable payload = **106 bytes** ("106 B round-trips, 107 B is
cleanly rejected"). The formula above gives v6-M = 108-2 = 106. Matches.

**Direct answers to the posed questions:**
- **Does ~110-145 bytes fit in version 6 (41x41) at ECC LOW?** Partly. v6-LOW
  usable payload = **134 bytes**. So **110-134 B fit**; **135-145 B do NOT** and
  force version 7.
- **Payload size at which version 6 overflows (forcing v7/v8), per ECC level:**
  - v6-**LOW**: overflows above **134 B** (135+ -> v7-LOW cap 154, else v8).
  - v6-**MEDIUM**: overflows above **106 B** (107+ -> v7-M cap 122).
  - v6-**QUARTILE**: overflows above **74 B**.
  - v6-**HIGH**: overflows above **58 B**.

Note the encoder searches upward for the smallest fitting version in
`[minVersion, maxVersion]` (`qrcodegen.c:236-247`); if `boostEcl` is set it will
*raise* ECC (never lower) while the data still fits (`qrcodegen.c:250-255`).

---

## 3. ECC level for a screen->camera scan

**What each level protects against.** ISO/IEC 18004's four Reed-Solomon levels
give an approximate recoverable fraction of codewords: **L ~7%, M ~15%,
Q ~25%, H ~30%** (Denso Wave). Reed-Solomon corrects *codeword* errors
regardless of cause — the recovered percentage is the share of total codewords
that may be corrupted/erased and still decode (the mechanism is the RS remainder
math in `qrcodegen.c:398-438`). It protects against localized damage, occlusion,
dead pixels, glare spots, dirt — anything that flips or hides modules.

**Vendor guidance by use case (Denso Wave, the inventor):**
- *"Level L may be selected for clean environment with the large amount of
  data."*
- *"Level Q or H may be selected for factory environment where QR Code get
  dirty."*
- *"Typically, Level M (15%) is most frequently selected"* — the default when
  conditions aren't extreme.

**Is ECC LOW defensible for a clean, well-lit emulator/CRT/LCD screen scanned at
close range?** By the inventor's own rule, a clean-environment display with a lot
of data is the textbook case for **Level L**. So LOW is *defensible in
principle*. Caveats that argue for keeping MEDIUM (these are the real-world
screen-scan degradations, not covered by Denso Wave's "clean vs factory"
dichotomy; treat as engineering judgment, not spec-quoted):
- **Screen glare / specular highlights** can wipe out a contiguous block of
  modules — exactly the localized-loss case ECC exists for.
- **Moiré / aliasing** between the display's pixel grid and the camera sensor,
  worst on low-DPI panels and when module size is near the camera's resolving
  limit.
- **CRT scanlines / phosphor bloom / sub-pixel rendering** blur module edges;
  an emulator on a CRT is materially worse than a print label.
- **Low display resolution** may render each QR module as very few pixels,
  raising per-module decode error probability across the whole symbol.

Net: LOW is justifiable *only* if rendering guarantees crisp, high-contrast,
several-device-pixels-per-module output with no glare. MEDIUM buys a large
robustness margin (15% vs 7%) that specifically covers glare/moiré/CRT artifacts
that a "clean environment" label never sees. This is the crux of the §8 tradeoff.

---

## 4. In-game encoder cost vs. version/ECC

All costs below are read from `qrcodegen.c`. A smaller version + lower ECC is
**materially cheaper**, in both compute and RAM. Quantified:

**RAM (buffers).** Two buffers of `qrcodegen_BUFFER_LEN_FOR_VERSION(v)` each
(`qrcodegen.h:75`, `= ((v*4+17)^2 + 7)/8 + 1`), one for `dataAndTemp`, one for
`qrcode`:
- v6 (41x41): (1681+7)/8+1 = **212 bytes** each → ~424 B for the pair.
- v7 (45x45): (2025+7)/8+1 = **254 bytes** each → ~508 B.
- v8 (49x49): (2401+7)/8+1 = **301 bytes** each → ~602 B.
Cost grows ~ with the square of the side length. ECC level does not change these
buffer sizes (they depend only on version).

**Reed-Solomon compute.** ECC work scales with the RS generator **degree** =
`blockEccLen` = `ECC_CODEWORDS_PER_BLOCK[e][v]` (`qrcodegen.c:337`), times the
number of blocks (`qrcodegen.c:336`). `reedSolomonComputeDivisor` is O(degree^2)
GF(256) multiplies (`qrcodegen.c:398-419`) and `reedSolomonComputeRemainder` is
O(dataLen * degree) multiplies (`qrcodegen.c:425-438`), each multiply being an
8-iteration Russian-peasant loop (`qrcodegen.c:444-453`). Higher ECC = larger
degree AND more/ smaller blocks = more RS work. Concrete degrees (from
`qrcodegen.c:169-176`) and block counts (`qrcodegen.c:181-188`):
- v6-**LOW**: degree 18 x 2 blocks. Total ECC codewords = 36.
- v6-**MEDIUM**: degree 16 x 4 blocks. Total ECC codewords = 64 (**~1.8x** the
  RS output of LOW, and 4 divisor-polynomial builds instead of 2).
- v6-**QUARTILE**: degree 24 x 4 = 96 ECC codewords.
- v6-**HIGH**: degree 28 x 4 = 112 ECC codewords.
So at fixed version, LOW is the cheapest ECC by a clear margin.

**Masking (dominant compute term).** With `mask == AUTO` the encoder runs **all
8 mask patterns**, and for each one applies the mask, draws format bits, and
computes a full-grid penalty score, then un-applies (`qrcodegen.c:304-320`).
`getPenaltyScore` is several O(size^2) passes over the module grid
(`qrcodegen.c:681-757`). This is the single biggest cost and scales with
version (grid area), not ECC. **On constrained hardware the cheapest single
lever is to pin one fixed mask (pass `qrcodegen_Mask_0..7`, not
`qrcodegen_Mask_AUTO`), eliminating ~8x the masking+penalty work.** Note this
repo's current adapter path does not expose the mask arg (`qr_adapter.h`), so
today it inherits whatever `pipeline_qr_encode` passes.

**Bottom line for constrained/archaic targets:** minimize version first (grid
area drives buffers + masking + placement), then drop ECC (drops RS degree and
block count), then consider fixing the mask to kill the 8x AUTO overhead.
Version 6 vs 7 is ~40 bytes less scratch per buffer and a smaller grid on every
O(size^2) pass; LOW vs MEDIUM at v6 roughly halves RS output work.

---

## 5. `created_at` compression

- NIP-01: `created_at` is *"<unix timestamp in seconds>"* — a JSON **number**
  (integer seconds), and it is one of the six elements of the signed
  serialization array `[0, pubkey, created_at, kind, tags, content]` (NIP-01,
  "To obtain the `event.id`, we `sha256` the serialized event.").
- It is baked per build; in this repo it is `PIPELINE_EVENT_CREATED_AT
  1788881857u` (`build/us/include/event_profile.h:28`) — a full 32-bit value.
- **Can it travel in <4 bytes?** Yes, *mechanically*, without breaking the
  signature — because the signature commits to the reconstructed integer, not to
  the bytes on the wire. If the cartridge sends a **3-byte offset from a fixed
  baked epoch base** and the companion adds the base back to recover the exact
  seconds integer before serializing, the recomputed `id` and the `sig` still
  verify (§6). The transmitted encoding is free to differ from the serialized
  form as long as the companion reconstructs the identical integer.
- **Real saving: exactly 1 byte** (4 -> 3). A `u32` covers absolute time through
  year 2106; a 3-byte offset covers only **2^24 s ≈ 194 days** from the chosen
  base. For a cartridge shipped and scanned over multiple years, 194 days of
  range is almost certainly insufficient unless the base is refreshed each build
  AND all scans happen within ~6 months of that build — a fragile assumption for
  an arcade cabinet.
- **Tradeoff (not decided here):** save 1 byte vs. add a fixed-epoch constant to
  both encoder and companion spec, plus a hard 194-day validity ceiling and a
  new failure mode (offset overflow). Given the payload is dominated by the
  incompressible 96-byte sig+pubkey floor (§1), 1 byte is ~0.9% of a ~115 B
  payload and does not change the chosen QR version/ECC in any config in §8. So
  the complexity almost certainly is not worth it — but the choice is the
  human's.

---

## 6. `id`: recompute vs. pack

**Answer: never pack the 32-byte `id`. Recompute on the companion. That is a
clean 32-byte density win with no downside.**

- NIP-01: the `id` is *"sha256"* of the canonical serialization
  `[0, pubkey, created_at, kind, tags, content]` — it is a pure function of the
  other fields.
- Standard client libraries recompute it and reject mismatches. nostr-tools
  `verifyEvent` (`pure.ts`): computes `getEventHash(event)` (=
  `sha256(serializeEvent(event))`), then **`if (hash !== event.id)` fails**, and
  also runs `schnorr.verify(sig, hash, pubkey)`. So a packed `id` is redundant:
  the verifier ignores it in favor of the recomputed hash.
- Relays reject bad events via the `OK` message: *"`OK` messages MUST be sent in
  response to `EVENT` messages ... the 3rd parameter set to `true` when an event
  has been accepted ... `false` otherwise"*, with a machine-readable prefix from
  the standardized set that includes **`invalid`** (NIP-01: prefixes are
  `duplicate, pow, blocked, rate-limited, invalid, restricted, mute, error`). A
  wrong `id`/`sig` is the `invalid:` case. (NIP-01 gives the timestamp example
  `"invalid: event creation date is too far off..."`; it does not spell out a
  distinct string for a bad hash/sig, but the mechanism and prefix set are the
  primary-source facts. The recompute-and-reject behavior is confirmed directly
  in nostr-tools above.)

**Conclusion:** since the companion reconstructs pubkey, created_at, kind, tags,
content and re-serializes, it can (and standard libs do) recompute `id` for
free. Packing it would spend 32 bytes — a third of the incompressible floor — to
transmit a value the verifier discards. Do not pack it.

---

## 7. Tag encoding minimalism (`t` tag)

**Constraints from NIP-01 (primary):**
- A tag is *"an array of one or more strings ... The first element ... is
  referred to as the tag name or key."* For a hashtag-style tag the name is
  `"t"` and the value is element 2 (e.g. `["t", "sm64"]`).
- *"all single-letter (only english alphabet letters: a-z, A-Z) key tags are
  expected to be indexed by relays"* — `t` qualifies, so the value is relay-
  indexed/queryable. NIP-01 places **no charset or length limit on the tag
  *value*** (it is an arbitrary JSON string; the only constraints are JSON string
  validity and the serialization escaping rules used for the `id` hash). The
  conventional lowercase-hashtag semantics of `t` come from NIP-24/NIP-12
  (hashtags), which is a convention layered on NIP-01, not a hard NIP-01 rule.
- The value is signed on-cartridge and must appear **verbatim** in the broadcast
  event (it is inside the serialized array that both `id` and `sig` commit to),
  so the companion must transmit and re-serialize the exact bytes.

> **Superseded by format v2 (ADR-0002, spec #52 sub-issue #54):** the analysis
> below reflects the pre-v2 state, when both `t` tags were baked out-of-band.
> Format v2 acted on exactly this recommendation — the fixed constant tag (now
> `["t","ag-lb"]`) stays a spec constant off the wire, while the per-game tag
> (`["t","sm64"]`) is now packed inline (`TAG_LEN`+`TAG`, see
> `docs/qr-handoff-spec.md` §2). The capacity figures here remain current.

At research time this repo baked two `t` tags out-of-band: a fixed
constant tag and a per-game `["t","sm64"]`. The fixed constant is a
known-to-both-sides value and need not travel on the wire; only a genuinely
**per-game** value must be inline.

**Byte cost of representations for the per-game identifier** (as the UTF-8 bytes
that go into the event; on the wire add 1 length-prefix byte if variable-length):

| Representation | Example value | Value bytes | +1 len prefix |
|---|---|---|---|
| Short slug | `sm64` | 4 | 5 |
| Short slug | `oot` | 3 | 4 |
| Integer-as-string | `64` | 2 | 3 |
| Integer-as-string | `1048576` | 7 | 8 |
| UUID (hex, hyphenated) | `550e8400-...` | 36 | 37 |

**Recommendation direction (not a decision):** a **short lowercase slug**
(`"sm64"`, 4 B; add 1 length byte if variable) is both minimal and a valid,
human-meaningful, relay-queryable `t` value. An integer-as-string is 1-2 bytes
smaller but loses human meaning and querying convenience; a UUID is
disqualifyingly large (37 B ≈ a third of the whole budget) for no benefit. If
only ONE game per cartridge/build ever ships, the per-game tag could even be a
*fixed* baked constant (0 wire bytes) like `cabinet-leaderboard` — inline cost is
only paid if the value must vary at scan time.

---

## 8. Synthesis — byte budget and the density/robustness frontier

**Irreducible + near-fixed budget (raw bytes on the wire):**

| Field | Bytes | Source |
|---|---|---|
| sig (Schnorr) | 64 | §1 (BIP-340) — mandatory, incompressible |
| pubkey (x-only) | 32 | §1 (BIP-340/NIP-01) — mandatory, incompressible |
| created_at | 4 (or 3) | §5 — 3 B only with fragile epoch-offset trick |
| per-game `t` value | ~4-5 | §7 — short slug `sm64` + optional len byte |
| id | 0 | §6 — recomputed by companion, never packed |
| run metadata (course/act/coins/frames/nonce16 [+format tag]) | ~10-11 | current packed layout minus sig, `format_descriptor.json` |
| key_id | 0-1 | removable once pubkey is inline (§1) |

**Floor = 96 B (sig+pubkey).** Realistic self-contained total ≈ **110-120 B**:
- Lean: 64 + 32 + 4 + 5 (tag) + 10 (metadata, drop key_id) = **115 B**.
- With key_id kept and 3-byte created_at: 64+32+3+5+11 = **115 B** also.
- Tightest plausible (3-byte created_at, 2-byte int tag, drop key_id):
  64+32+3+3+10 = **112 B**.

Against the §2 payload caps, three points on the frontier (do NOT pick — laid
out for the human):

| Config | Fits payload up to | Symbol size | ECC recovery | vs. today |
|---|---|---|---|---|
| **A. v6 / LOW** | 134 B | 41x41 (**same as today**) | ~7% | Zero size increase; drops from MEDIUM to LOW. Only defensible if render is crisp/high-contrast/glare-free (§3). Cheapest encoder (§4). |
| **B. v7 / MEDIUM** | 122 B | 45x45 (+4 modules/side) | ~15% | Keeps inventor-default robustness for screen glare/moiré/CRT (§3); ~40 B more scratch/buffer and a larger O(size^2) grid (§4). Safest realistic scan. |
| **C. v7 / LOW** | 154 B | 45x45 | ~7% | Big headroom (room for a longer human tag or future fields) at LOW ECC; same size as B but less robust. Or **v8/MEDIUM** (cap 152, 49x49) for the same headroom at MEDIUM robustness and a larger symbol. |

**The single decision that dominates:** a self-contained payload (~112-120 B)
**exceeds v6-MEDIUM's 106-byte cap** (§2). So you cannot keep BOTH today's 41x41
size AND MEDIUM ECC. You must choose one:
- keep the **size** (v6) and pay with **ECC LOW** (Config A), or
- keep **MEDIUM ECC** and pay with a **larger symbol** (v7, Config B).

Encoder cost favors A (smaller grid, less RS, §4); scan robustness on a real
CRT/LCD favors B (§3). The `created_at` 3-byte trick (§5) and integer-vs-slug tag
(§7) shave 1-3 bytes but do not, by themselves, move any config across a version
boundary — they are not decisive.

---

## Verification notes / limits

- The v5-v8 capacity numbers were **derived** from `qrcodegen.c` and
  independently match the published ISO/IEC 18004 total-data-codeword tables; the
  v6-M = 106 B usable figure additionally matches this repo's own empirically
  confirmed value (`qr_adapter.h:29`). I did **not** re-run the encoder to
  re-confirm 133 B vs 134 B at v6-LOW at the exact boundary; the boundary is
  computed, and the one boundary this repo has actually exercised (v6-M: 106 ok /
  107 rejected) matches the same formula.
- NIP-01's raw text (as fetched) does **not** contain an explicit sentence
  "relays MUST reject events with an invalid id/sig." The primary evidence for
  recompute-and-reject is (a) the `id`-is-sha256 definition + the standardized
  `invalid` OK-prefix in NIP-01, and (b) nostr-tools `verifyEvent` recomputing
  the hash and failing on mismatch. Stated as such in §6 rather than overclaimed.
- The screen-scan degradation caveats in §3 (glare/moiré/CRT/sub-pixel) are
  engineering judgment, not quoted from ISO/IEC 18004 or Denso Wave, which only
  frame it as "clean" vs "factory/dirty." Flagged inline.

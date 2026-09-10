# NIP-01 Signed-Event Floor vs. Frozen QR v7-MEDIUM

**Question:** Can a fully-honest, event-name-bearing, cartridge-pre-signed Nostr event
fit inside a frozen QR v7-MEDIUM footprint (~864 data-bits), given the hard invariant
that the far side may only losslessly decode packed bytes into canonical JSON and
recompute the `id` (SHA-256) — inventing / baking / defaulting **nothing** that enters
the signed serialization?

**Bottom line (spoiler):** **No.** The signature core alone (pubkey 32 B + sig 64 B =
96 B) costs ~771 QR numeric-bits. Adding the two other unbakeable signed scalars
(`created_at` 4 B, `kind` 2 B) reaches ~819 bits, leaving **~45 bits** of the 864-bit
budget for the score, the event-name slug, the numeric-segment mode overhead, **and**
the alphanumeric URL prefix. It does not fit. See the byte-budget table and the closing
paragraph.

Sources are PRIMARY only: NIP-01 (`nostr-protocol/nips/01.md`) and BIP-340
(`bitcoin/bips/bip-0340.mediawiki`). Verified against the raw spec text on
`raw.githubusercontent.com/.../master` (2026-09-10). Where a value is inferred/computed
rather than quoted, it is flagged.

---

## 1. Mandatory fields

NIP-01 defines the event object with exactly seven fields, all required for a valid,
verifiable event:

| Field | Spec type (NIP-01, verbatim) |
|---|---|
| `id` | "32-bytes lowercase hex-encoded sha256 of the serialized event data" |
| `pubkey` | "32-bytes lowercase hex-encoded public key of the event creator" |
| `created_at` | "unix timestamp in seconds" |
| `kind` | "integer between 0 and 65535" |
| `tags` | array of arrays of strings |
| `content` | "arbitrary string" |
| `sig` | "64-bytes lowercase hex of the signature of the sha256 hash … which is the same as the `id` field" |

**Omittable?** No. A relay verifies an event by (a) recomputing `id` from
`[0,pubkey,created_at,kind,tags,content]` and (b) checking `sig` against `id` and
`pubkey`. Every one of the seven fields participates in that check (`id`/`sig`
directly; the other five feed the `id` hash). Dropping any of the six signed fields
changes the hash → signature fails → relay rejects. So none is omittable for a valid
event.

- **`content` empty string:** Legal. It is an "arbitrary string"; `""` is a valid
  string and is common (e.g. reaction/relay-list kinds routinely use `""`).
- **`tags` empty array:** Legal. `[]` is a valid value and serializes as `[]`.

So the *structural* NIP-01 floor is: `content:""`, `tags:[]`. Our use case cannot use
that floor because the score and the event-name slug must be *signed*, hence must live
in `content` and/or `tags` (see §4).

---

## 2. `id` serialization (far side recomputes; invents nothing)

NIP-01, verbatim, computes `id` as the SHA-256 of the UTF-8 JSON serialization of a
**6-element array**:

```
[
  0,
  <pubkey, as a lowercase hex string>,
  <created_at, as a number>,
  <kind, as a number>,
  <tags, as an array of arrays of strings>,
  <content, as a string>
]
```

Whitespace / escaping rules, verbatim:

> "UTF-8 should be used for encoding, and the resulting UTF-8 byte array `id`."
> "To prevent implementation differences from creating a different event ID for the
> same event, the following rules MUST be followed while serializing:
> No whitespace, line breaks or other unnecessary formatting should be included in
> the output JSON."

Required in-string escapes (and **only** these), verbatim list:
`\n` (0x0A), `\"` (0x22), `\\` (0x5C), `\r` (0x0D), `\t` (0x09), `\b` (0x08),
`\f` (0x0C). All other characters are included verbatim.

> "The `id` is the sha256 hash of this serialization."

This is a **pure function** of the six signed fields: given the exact
pubkey/created_at/kind/tags/content, the far side deterministically produces the
canonical byte string and SHA-256s it. It supplies no value — it only (a) formats the
decoded values into canonical minified JSON and (b) hashes. That is exactly what the
invariant permits, and nothing more. ✔ Invariant-compatible.

---

## 3. Minimum size of each signed field (raw information bytes, not hex)

### pubkey — 32 bytes (irreducible)
BIP-340, verbatim: "Encoding only the X coordinate, resulting in **32-byte public
keys** and 64-byte signatures." x-only is already the *shortest* standard form; there is
no shorter legal Nostr pubkey (NIP-01 mandates the 32-byte x-only key, hex-encoded on
the wire but 32 raw bytes of entropy). **Floor: 32 B.**

### sig — 64 bytes (irreducible; no shorter form)
BIP-340, verbatim: "…32-byte public keys and **64-byte signatures**." The signature is
`(r,s)`, r = 32-byte x-coordinate of R, s = 32-byte scalar. BIP-340 explicitly gives up
recovery: it notes the scheme lacks "the ability for public key recovery or verifying
signatures against a short public key hash." So there is **no** 65-byte-recoverable
trick that lets you drop the pubkey, and **no** compressed/short signature form.
**Floor: 64 B.** (pubkey + sig = **96 B irreducible crypto core**.)

### created_at — Unix seconds, JSON integer
- Type/range: "unix timestamp in seconds" — a JSON number (integer). NIP-01 places no
  explicit upper bound; practically a positive 32-bit-ish integer.
- Current value (Sept 2026) ≈ 1.757×10⁹ → **31 bits → 4 raw bytes** packed. Can't be
  smaller without baking an epoch-offset on the far side, which would *supply a value
  entering the event* → **forbidden by the invariant**. **Floor: 4 B.**
- Relay drift/stale-window policy: NIP-01 lists, among machine-readable rejection
  reasons, **verbatim** the standardized `invalid:` message *"event creation date is too
  far off from the current time."* NIP-01 itself does not fix the numeric window; relays
  set it (commonly a few minutes to ~1 hour of skew, sometimes a bounded past). This
  matters operationally: an airgapped cabinet's clock must be within the receiving
  relay's accepted window, or the honestly-signed event is rejected for drift even
  though it is cryptographically valid. (Window value is relay policy, not spec —
  flagged as not-in-spec.)

### kind — integer, and where 8064 falls
- Range: "an integer between 0 and 65535" → ≤ 16 bits → **2 raw bytes** packed. Can't be
  baked (would supply a signed value). **Floor: 2 B.**
- Classification, from the verbatim NIP-01 ranges:
  `1000 <= n < 10000 || 4 <= n < 45 || n == 1 || n == 2` ⇒ **regular**;
  `10000 <= n < 20000 || n==0 || n==3` ⇒ replaceable;
  `20000 <= n < 30000` ⇒ ephemeral; `30000 <= n < 40000` ⇒ addressable.
  **8064 satisfies `1000 <= 8064 < 10000` ⇒ `kind` 8064 is a REGULAR event.**
  (Note: a first-pass web summary mislabeled 8064 "addressable" — that is wrong;
  addressable is 30000–40000.)
- Storage semantics of that range, verbatim: regular events "are all expected to be
  stored by relays." This is the desired behavior for a score event: every run is a
  distinct, permanently-stored record (contrast replaceable/addressable, where "only the
  latest event MUST be stored … older versions MAY be discarded," and ephemeral, which
  are "not expected to be stored"). So 8064 is the right regime for a persistent
  scoreboard.

### tags — array of arrays of strings
- Structure, verbatim: "each tag is an array of one or more strings, with some
  conventions around them." So `tags` is `string[][]`; **every element is a JSON
  string** — **no raw binary**. Binary score bytes must therefore be UTF-8-representable
  (e.g. base-N / printable encoding) before entering a tag string.
- Indexing / filterability, verbatim: single-letter tag names (`a`–`z`, `A`–`Z`) are
  the ones relays index, and "Only the first value in any given tag is indexed," queried
  via filters like `{"#e": [...]}`. **Consequence for the event-name slug:** to be
  *filterable*, the tag's first element must be a **single letter** (e.g. `["n","<slug>"]`
  or the addressable-style `["d","<slug>"]`), and the slug goes in the **second**
  position (the indexed value). A multi-letter key like `["name","<slug>"]` is *legal*
  but **not relay-indexed**, so it fails the owner's "filter on it" requirement.
- Minimum byte cost of adding one tag `["n","<slug>"]` to the *serialization*: the JSON
  punctuation is `[["n",""]]` vs an empty `[]` — i.e. the fixed structural cost is
  `[["n",""]]` minus `[]` = **8 serialization bytes** (`[`,`"`,`n`,`"`,`,`,`"`,`"`,`]`
  accounting) **plus the slug's own bytes**. (Serialization bytes ≠ QR bytes; see §5 for
  the packed cost, which drops reconstructable JSON punctuation.)

### content — free-form string, UTF-8/JSON constrained
- "arbitrary string," but it is a **JSON string**, so it must be valid Unicode and obey
  the escape rules of §2. **Raw arbitrary bytes cannot be placed directly in `content`**
  (they may not be valid UTF-8, and control bytes must be escaped). Packed score bytes
  must be **encoded** (hex/base64/etc.) into a valid-UTF-8 string before signing.
- Key point for our budget: the *signed* content is that encoded string, but the **QR
  carries only the underlying entropy** (~6–8 packed bytes). The far side losslessly
  expands those bytes back into the exact encoded string (lossless decompression — the
  invariant permits it), then hashes. So content-as-encoded-score costs the QR **only
  the raw score entropy**, not the inflated ASCII length.

---

## 4. Where the score must live, and the cheapest honest form

To be *honestly signed*, course/act/coins/frames/nonce **must be inside**
`[0,pubkey,created_at,kind,tags,content]` — i.e. in `content` or in `tags`. Tradeoffs:

- **In `tags`:** filterable if placed as the indexed value of a single-letter tag, but
  every tag costs the `[["x",""]]`-style JSON-array overhead (~8 serialization bytes per
  tag) and the value must be a UTF-8 string. Good when you *need to filter on that value*
  (the event-name slug is exactly this case).
- **In `content`:** cheapest structurally — no per-item array overhead, one string — but
  **not filterable** and still UTF-8-constrained (must encode binary).

**Most byte-efficient placement for the ~6–8 bytes of packed score:** put the score in
**`content`** as a single encoded string (no tag-array overhead, not needed for
filtering), OR pack it as the indexed value of the *same* single-letter tag you already
pay for the name — but that overloads the filter key. Cleanest: **event-name slug →
single-letter indexed tag** (`["n","<slug>"]`) for filterability; **packed score →
`content`**. In *packed QR* terms both reduce to their raw entropy (score ≈ 6–8 B; slug
≈ its character count); the JSON punctuation is reconstructed for free on the far side.

---

## 5. Irreducible floor — byte budget

**Frozen target:** QR **version 7, EC level M** = 108 data codewords × 8 =
**864 data-bits** total. Two-segment layout: alphanumeric URL prefix + numeric decimal
payload. Numeric packing of arbitrary bytes costs **~8.03 QR-bits/byte**
(2.408 decimal digits/byte × 3.33 bits/digit). Segment/mode overhead for v7 (verified
against the QR spec's version 1–9 group): alphanumeric = 4-bit mode + 9-bit count;
numeric = 4-bit mode + 10-bit count; + 4-bit terminator.

### Packed QR payload (raw information bytes → numeric-segment bits)

| Field | Why unavoidable | Raw bytes | ≈ QR bits @8.03/B |
|---|---|---:|---:|
| `pubkey` | BIP-340 x-only, irreducible | 32 | 257.0 |
| `sig` | BIP-340 Schnorr, irreducible, no recovery | 64 | 514.0 |
| `created_at` | 31-bit unix seconds, unbakeable (invariant) | 4 | 32.1 |
| `kind` (8064) | ≤16-bit, unbakeable (invariant) | 2 | 16.1 |
| **Crypto+scalars subtotal** | | **102** | **819.1** |
| score (course/act/coins/frames/nonce) | must be signed | 6–8 | 48–64 |
| event-name tag key (single letter, signed) | unbakeable | 1 | 8.0 |
| event-name slug (indexed value) | the requirement | L | 8.03·L |

**Numeric-segment overhead:** +14 bits (mode+count) +4 (terminator) ≈ **+18 bits**.
**Alphanumeric URL prefix:** e.g. a ~12–16 char `https://host/#` prefix ≈ **80–100 bits**
(incl. its 13-bit mode+count overhead).

### The verdict math

- **Crypto core + scalars only (no score, no name, no URL):** 102 B → **~819 bits**.
  Remaining in 864: **~45 bits (~5.6 bytes)** — must cover numeric overhead (18 bits),
  the score, the name, *and* the entire URL-prefix segment. Impossible.
- **Barest honest event, score in content (6 B), NO event name:**
  102 + 6 = **108 B → ~867 QR-bits**, +18 overhead = **~885 bits** with **zero** URL
  prefix. Already **> 864**. Overflows by ~21 bits before you add the mandatory URL.
- **Honest + event-name slug (1 B key + 10 B slug) + 8 B score:**
  102 + 8 + 1 + 10 = **121 B → ~972 QR-bits**, +18 numeric overhead + ~90 URL-prefix ≈
  **~1080 bits**. Budget 864 → **overflow ≈ 216 bits ≈ 27 bytes** (roughly a whole extra
  QR version's worth of data).

**Fit? No.** A fully-honest, event-name-bearing, cartridge-signed event overflows
frozen v7-M by roughly **200+ bits (~25–27 bytes)**. Even *stripping the name entirely*,
the barest honest signed event (~885 bits with no URL) still exceeds 864.

---

## 6. Honest tradeoff — what the invariant costs

Split the floor by *what forces each byte*:

| Bytes | Forced by | Truly irreducible? |
|---:|---|---|
| pubkey 32 + sig 64 = **96** | **NIP-01 + BIP-340 themselves** | Yes — any valid Schnorr-signed Nostr event over a real key must carry these. |
| created_at 4 + kind 2 + tags(name) + content(score) | **Our on-wire invariant** (cartridge signs; phone may bake nothing) | No — a *relay* doesn't care where these came from; the invariant forces them onto the wire. |

**Pricing the invariant.** A "relay-legal but invariant-violating" minimum is the
scenario where the phone/website is *allowed* to supply values: the cleanest such design
lets the **phone generate and sign its own event** (its own key, `created_at=now`,
constant `kind`, score stuffed into content) and the QR carries **only the ~6–8 bytes of
score**. That is a perfectly relay-legal event (~64 QR-bits of payload). The delta —
**~102 bytes / ~819 QR-bits** (the entire 96 B crypto core + created_at 4 B + kind 2 B) —
is the **price the invariant charges** to keep the signing airgapped-and-honest on the
cartridge instead of on the phone.

Note *why* the invariant is not arbitrary: because `sig` cryptographically binds
created_at/kind/tags/content, a valid cartridge signature can only verify if those exact
bytes are reproduced on the far side. You therefore cannot "bake created_at = now" and
still have the cartridge's signature verify — baking breaks the hash. So within the
honest-signing model, all ~102 bytes are genuinely unavoidable; the only way to shrink
below them is to abandon cartridge-side signing (the very thing the invariant protects).
**This report prices that; it does not recommend relaxing it.**

---

## Bottom line

**No — a fully-honest, event-name-bearing, cartridge-pre-signed Nostr event cannot fit a
frozen QR v7-MEDIUM (864 data-bit) footprint.** The irreducible Schnorr crypto core
(pubkey 32 B + sig 64 B = 96 B) already consumes ~771 of the 864 bits; the two remaining
unbakeable signed scalars (created_at 4 B, kind 2 B) push that to ~819 bits, leaving only
~45 bits — before any score, any event-name slug, the numeric-segment overhead, or the
alphanumeric URL prefix. The barest honest signed event with no name (~108 B / ~885 bits)
already exceeds 864; adding a filterable event-name slug and score pushes the floor to
~121 B / ~1080 bits, overflowing frozen v7-M by roughly **200+ bits (~25–27 bytes)**. The
practical floor for a *named, honest* event is ~119–121 raw bytes, which needs a larger
QR version (or a lower EC level / different geometry) than the frozen v7-M can provide.

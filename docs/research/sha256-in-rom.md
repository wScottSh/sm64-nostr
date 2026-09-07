# Research: SHA-256 (and hashing) landscape in-ROM

**Ticket:** [#6](https://github.com/wScottSh/sm64-nostr/issues/6) — part of map [#4](https://github.com/wScottSh/sm64-nostr/issues/4)
**Posture:** map the solution landscape + trade-offs. NOT implementation, NOT a go/no-go call.
**Lens:** Ackoff solve / resolve / **dissolve** (can the hashing problem be reframed away?).
**Target:** N64 / NEC VR4300, MIPS III, 32-bit, big-endian, ~93.75 MHz, no HW crypto, no RTC, IDO toolchain.

> Trust note: repo claims below were checked against the checked-out tree. Cycle-cost
> numbers are **first-principles estimates, not measured** on hardware/emulator, and are
> flagged as such. Protocol facts are quoted from primary specs (NIP-01, BIP-340) and
> the referenced source files.

---

## 1. What the tree already contains (searched — nothing usable)

Searched the whole worktree for `sha`, `md5`, `sha1`, `hmac`, `digest`, `ripemd`, `blake`,
`keccak`, `bignum`, `secp256k1`, `schnorr`, `bip340`, `ecc`, `hash`, `checksum`.

**No cryptographic hash primitive exists anywhere in game or library code.** What the hits are:

- `lib/src/crc.c` — `__osContAddressCrc` (5-bit) and `__osContDataCrc` (8-bit): libultra
  **controller-pak CRCs**. Bit-serial LFSR-style integrity checks for the accessory bus.
  Non-cryptographic, tiny, wrong shape and wrong width for our needs. Not reusable.
- `sm64.*.sha1` (repo root) and `sha256` in `tools/sdk-tools/adpcm/Makefile` — **build-host**
  ROM/artifact verification only. Never compiled into the ROM.
- `tools/sm64tools/n64cksum.c` — the N64 **CIC boot checksum** (host tool). Not SHA, not in-ROM.
- Remaining `hash`/`ecc` hits are substring noise (animation data, `osInitialize`, third-party
  host tools under `tools/`).

**Conclusion:** there is zero head start. A SHA-256 core must be added from scratch. There is
also **no bignum / no field arithmetic** in-tree — relevant to the sibling EC ticket, not this one.

---

## 2. Where hashing is actually needed in the pipeline

Two, and only two, consumers — and **both need SHA-256 and nothing else**:

### 2a. Nostr event `id` (NIP-01)
The `id` is `lowercase hex of sha256` of the UTF-8 JSON serialization of the array, in this exact order:
```
[0, <pubkey hex>, <created_at number>, <kind number>, <tags array-of-arrays>, <content string>]
```
No whitespace/line breaks; UTF-8. Content escapes only: `\n \" \\ \r \t \b \f` (0x0A,0x22,0x5C,0x0D,0x09,0x08,0x0C).
Source: NIP-01 (`nostr-protocol/nips/01.md`). One SHA-256 over a short preimage (a few hundred bytes → a handful of 64-byte blocks).

### 2b. BIP-340 tagged hashes for signing
Tagged hash: `hash_tag(x) = SHA256(SHA256(tag) || SHA256(tag) || x)`, tag UTF-8.
Default signing uses three tags: `BIP0340/aux`, `BIP0340/nonce`, `BIP0340/challenge`.
Steps (BIP-340 "Default Signing"):
1. `t = bytes(d) XOR hash_BIP0340/aux(a)`
2. `rand = hash_BIP0340/nonce(t || bytes(P) || m)`
3. `e = int(hash_BIP0340/challenge(bytes(R) || bytes(P) || m)) mod n`
Source: BIP-340 (`bitcoin/bips/bip-0340.mediawiki`).

Here `m` = the 32-byte event id from 2a (BIP-340 supports variable-length `m`; Nostr signs the 32-byte id).
So every input to every tagged hash is short and **fixed-length** (aux: 32B; nonce: 96B; challenge: 96B).

### 2c. Nothing else needs a hash
- **QR rendering** uses Reed–Solomon error correction (GF(256)), **not** a hash — separate ticket.
- **npub/bech32** uses a BCH polymod checksum, **not** SHA — and is unnecessary in-ROM if the QR
  carries the raw event JSON / hex rather than a bech32-encoded entity.
- Nostr keys are **x-only pubkeys**: no base58check, no HASH160, so **no SHA-1 and no RIPEMD-160**.

**Landscape takeaway:** a single SHA-256 primitive services the entire in-ROM pipeline. One module,
one dependency. No second hash function is ever required.

---

## 3. Candidate compact SHA-256 implementations (portable to IDO / MIPS III)

All are ~one small `.c` + `.h`, C89-friendly, self-contained (no `stdint`/OS deps needed after a typedef).

| Impl | License | Rough size | Portability notes |
|---|---|---|---|
| **Brad Conte `crypto-algorithms/sha256.c`** | Public domain ("as is", unrestricted) | ~150 LOC; ~2–3 KB `.text` + 256 B K-table | **Best fit.** Own `WORD`/`BYTE` typedefs (no stdint). Builds the message schedule by **explicit byte assembly** (`data[j]<<24 | ...`), so it is **endian-neutral** — works as-is on big-endian N64. No 64-bit ops. Rotations via `ROTRIGHT/ROTLEFT` shift+or macros. |
| **RFC 6234 reference `sha224-256.c`** | IETF (BSD-like/permissive) | Larger (~400+ LOC, multi-alg framework) | Correct/canonical but carries SHA-1/384/512 baggage; trim to SHA-256 only. |
| **LibTomCrypt `sha256.c`** | Public domain / Unlicense | Medium | Clean, well-tested; macro-heavy; strip the descriptor/registration framework. |
| **Bitcoin Core `crypto/sha256.cpp` (pure-C fallback path)** | MIT | Small core, but C++ + SIMD dispatch | Provenance-matching for BIP-340, but the dispatcher/SIMD is dead weight on N64; only the scalar `Transform` is portable. |

**Recommendation for the landscape:** port **Brad Conte's** file (or an equivalent byte-assembly impl).
Rationale: public domain, endian-neutral by construction (critical on big-endian MIPS with an old
IDO compiler), no stdint, no 64-bit math, trivially auditable at ~150 LOC. Wrap with a
`sha256(out32, in, len)` one-shot and a streaming ctx for the tagged-hash prefix trick (§5).

### Code-size / cycle cost (ESTIMATES — not measured)
- **Static footprint:** ~2–3 KB compiled `.text` + the 64×`u32` K-table = **256 B rodata**. Negligible in a ~8 MB ROM.
- **Per 64-byte block:** message schedule (48 words × ~4 ops) + 64 rounds (~10–15 ops each)
  ≈ **~1.5–2 k arithmetic ops/block**. On VR4300 at ~1 IPC that is very roughly **~2–3 k cycles ≈ 25–35 µs/block** (ignoring cache/memory stalls; unverified).
- **Whole pipeline per star event:** event-id (a few blocks) + aux/nonce/challenge tagged hashes
  (2 blocks of payload each; see §5) ≈ order **10–20 block-compressions total ⇒ well under 1 ms**.

**This is the load-bearing finding: SHA-256 is cheap here.** The pipeline's real cost is the
secp256k1 scalar multiplication in signing (separate EC ticket), which dwarfs all hashing by orders
of magnitude. Optimizing SHA-256 is not where the cycle budget goes.

### MIPS III specifics
- **No `ROTR`/`ROTRV` instruction.** ROTR was added in MIPS32 **Release 2** (2002); VR4300 is
  MIPS III. Every SHA-256 rotation therefore compiles to **shift + shift + or** (3 insns). Already
  the case in portable macro impls — no code change, just a modest per-op cost baked into the estimate above.
  (Sources: N64brew MIPS III instruction list; WikiChip MIPS32 R2.)
- **Big-endian is a gift.** SHA-256 is defined big-endian. On N64 you *may* load 32-bit words directly
  from a word-aligned buffer with no byte-swap. The byte-assembly impls don't even need that — they're
  correct on both endianness. Either way, **no endianness conversion code is required** in-ROM.
- No 64-bit arithmetic is needed for SHA-**256** (message length counter fits fine as two 32-bit words,
  handled by portable impls); avoids any MIPS III 64-bit-op concerns.

---

## 4. Ackoff lens

### Solve (brute the stated problem)
Port a compact SHA-256, call it for the event id and inside the three BIP-340 tagged hashes. Correct,
small, cheap. Works. Nothing clever required.

### Resolve (good-enough, exploit the situation)
- **Fixed-length preimages.** Every hash input in the pipeline is bounded and mostly constant-shape
  (aux 32 B; nonce/challenge 96 B; event id a short bounded JSON). Padding and block count can be
  precomputed/hardcoded rather than computed generically — a specialized, partially-unrolled compressor
  is possible, though §3 shows the payoff is tiny.
- **`aux_rand = 0` is spec-legal.** BIP-340: if randomness is unavailable, "even the constant array
  with 32 null bytes" may be used; signatures stay **cryptographically valid** ("the normal security
  properties (excluding side-channel attacks) do not depend on the quality of the signing-time RNG").
  The N64 has no RNG and no RTC, so this is the natural choice. It makes signing **deterministic** for a
  given (key, message) — fine for a single-shot airgapped QR, and it removes the need to source entropy.
  (It does not remove the aux tagged hash itself, and it trades away side-channel hardening — flag for
  the key-hardening ticket, but note the map's honest threat model already concedes key extraction.)

### Dissolve (reframe the hashing work away)
- **Precompute the tag midstates (the real dissolve of BIP-340 hashing overhead).** In
  `hash_tag(x) = SHA256(SHA256(tag)||SHA256(tag)||x)`, the 64-byte prefix `SHA256(tag)||SHA256(tag)`
  is **constant per tag** and is exactly **one 64-byte block**. Compute the SHA-256 **midstate** after
  that first block **at build time** for each of the three BIP0340 tags, bake the three 32-byte
  initial states into ROM as `const`, and at runtime resume compression from the midstate over just
  `x`. This **removes all repeated tag hashing at runtime** (turns each tagged hash from 3 blocks into
  ~1–2 blocks) with zero runtime cost and ~96 B of rodata. Standard technique for constrained targets.
- **One primitive, not a suite (dissolve the "and any other hashing" clause).** §2c shows nothing in
  the pipeline needs SHA-1, RIPEMD-160, or a bech32/base58 hash if the QR carries the raw event.
  Choosing x-only keys + raw-JSON/hex payload **dissolves every hash requirement except a single
  SHA-256 core.** The ticket's "any other hashing Nostr/BIP-340 needs" answer is: **none.**
- **What cannot be dissolved:** the event-id SHA-256 and the BIP-340 challenge hash are protocol-defining.
  The map requires a *fully-valid, signed* event, so these cannot be faked, skipped, or swapped for a
  cheaper function without producing an invalid event. Hashing's *existence* is non-negotiable; only its
  *cost and multiplicity* are reducible (and, per §3, already negligible).

**Net dissolve conclusion:** the honest reframing is **"there is no SHA-256 problem here."** It is a
solved, tiny, ~150-LOC public-domain port that big-endian MIPS actively favors, and the tag-midstate
precompute erases most of the BIP-340 hashing overhead at build time. The scarce N64 cycle/complexity
budget belongs to secp256k1 point multiplication (separate ticket), not to hashing.

---

## 5. Feeds back to map #4

- **New downstream facts:** SHA-256 is the *only* hash primitive the whole pipeline needs; it is small
  and cheap on this target; big-endianness helps; MIPS III lacks a rotate op (already handled by portable
  macros). Concrete candidate to port: **Brad Conte `crypto-algorithms` sha256.c** (public domain, endian-neutral).
- **Build-time tag-midstate precompute** is a recommended technique for the eventual BIP-340 signing ticket.
- **`aux_rand = 0`** is the natural, spec-valid choice given no RNG/RTC — hand to the key-hardening / nonce ticket.
- **Cost warning for the map:** do not spend optimization effort on hashing; the EC scalar multiply is the bottleneck.

## Sources (primary)
- NIP-01 event serialization & id: https://github.com/nostr-protocol/nips/blob/master/01.md
- BIP-340 tagged hash, signing steps, aux_rand guidance: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
- Brad Conte SHA-256 (public domain): https://github.com/B-Con/crypto-algorithms/blob/master/sha256.c
- MIPS III instruction set (no ROTR): https://n64brew.dev/wiki/MIPS_III_instructions ; MIPS32 R2 added ROTR: https://en.wikichip.org/wiki/mips/mips32_instruction_set
- In-tree scan: `lib/src/crc.c` (controller-pak CRC), `tools/sm64tools/n64cksum.c` (CIC checksum), `sm64.*.sha1` (build verification) — all non-cryptographic / host-only.

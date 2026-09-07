# Schnorr / secp256k1 signing landscape on the VR4300

Research findings for [issue #5](https://github.com/wScottSh/sm64-nostr/issues/5) (part of the
Wayfinder map, issue #4). This maps the **solution landscape** for producing a BIP-340
Schnorr signature over secp256k1 inside the SM64 N64 ROM. It is planning, not a go/no-go and
not an implementation. Applies Ackoff's solve / resolve / **dissolve** lens throughout.

> Method note: findings below are traced to primary sources (BIP-340 text, Nostr NIPs,
> bitcoin-core/secp256k1 source, VR4300 datasheets). Where a number is an *extrapolation*
> rather than a measured figure on N64 hardware, it is labeled as such. Nothing here has been
> compiled or run on a VR4300; the cycle estimates are order-of-magnitude reasoning, not
> benchmarks.

---

## 0. TL;DR

- **The scheme is fixed, not a choice.** Nostr (NIP-01) hard-codes 64-byte BIP-340 Schnorr over
  secp256k1 for both event `id` signing and pubkey encoding. Swapping to a cheaper curve
  (ed25519, etc.) is **not** a Nostr-valid option — that dissolve path is closed.
- **In-ROM signing is clearly feasible.** The VR4300 has a fast hardware 32x32->64 integer
  multiply (~5 cycles), 4 MB+ RAM, and an 8 MB+ cartridge. The "tight embedded budget" framing
  is looser here than on a typical MCU: code size and RAM are non-issues; the only real cost is
  CPU cycles for one signature, which is off the hot path and one-shot.
- **The strong dissolve is precomputed nonces.** BIP-340 *verification* checks only
  `s*G = R + e*P`; it does **not** constrain how the nonce was derived. So the signer may use
  per-event nonces `(k_i, R_i = k_i*G)` generated **offline at build time** and embedded in the
  ROM. Runtime then collapses from a full EC scalar multiply to **one SHA-256 tagged hash + one
  256-bit modular multiply + one modular add**. This removes ~99% of the cost. The one iron rule:
  **each nonce used at most once** (reuse across two different events algebraically leaks the
  private key).
- **Constant-time is largely unnecessary** for this threat model (offline, single-user,
  air-gapped, one QR render). The real threat is key extraction from the open-source ROM — a
  different ticket. Nonce uniqueness, not timing side-channels, is the security-critical property.

---

## 1. What Nostr actually requires (constrains the whole space)

Per **NIP-01**, an event's `id` is the SHA-256 of the serialized event, and `sig` is the
64-byte Schnorr signature of that `id`; signatures and pubkeys follow the Schnorr standard for
curve **secp256k1**. Pubkeys are the 32-byte x-only form. ([NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md))

**BIP-340** defines that 64-byte format: `sig = bytes(R) || bytes(s)`, a fixed 64 bytes (vs.
DER's variable ~72), x-only 32-byte pubkeys. ([BIP-340](https://bips.dev/340/))

Consequence for the landscape:
- **No alternative signature scheme is Nostr-valid.** Any "dissolve via cheaper scheme"
  (ed25519, ECDSA-DER, HMAC) produces events that Nostr relays/clients reject. Dead end —
  worth stating explicitly so it is not revisited.
- The primitives the ROM must contain are exactly: SHA-256 (already surveyed separately),
  secp256k1 field + scalar arithmetic, one fixed-base scalar multiply `k*G` (or a precomputed
  substitute — see §5), and the BIP-340 tagged-hash challenge.

## 2. BIP-340 signing algorithm (what has to run in-ROM)

From the BIP-340 spec, signing `m` with secret `d` (pubkey `P = d*G`):

1. `t = bytes(d) XOR hash_{BIP0340/aux}(a)` — `a` is 32 bytes of auxiliary randomness.
2. `rand = hash_{BIP0340/nonce}(t || bytes(P) || m)`, `k' = int(rand) mod n`, `k = k'` (with a
   parity flip so `R` has even y).
3. `R = k*G` — **the single expensive elliptic-curve operation.**
4. `e = int(hash_{BIP0340/challenge}(bytes(R) || bytes(P) || m)) mod n`.
5. `s = (k + e*d) mod n`. Output `bytes(R) || bytes(s)`.

([BIP-340](https://bips.dev/340/))

Tagged hashes use `SHA256(SHA256(tag) || SHA256(tag) || data)` with tags `BIP0340/aux`,
`BIP0340/nonce`, `BIP0340/challenge` — cheap; a handful of SHA-256 blocks each.

**Key observation for the dissolve (§5):** steps 1-2 are the *spec's recommended* nonce
derivation, chosen so that a broken RNG cannot cause catastrophic nonce reuse. They are **not
checked by verifiers.** A verifier only recomputes `e` from the transmitted `R` and checks
`s*G == R + e*P`. So the signer is free to obtain `k` any way it likes, provided `k` is secret
and never reused. This is the hinge the precomputation dissolve turns on.

## 3. Candidate implementations to port

| Option | Code size | RAM/stack | Portability | Notes |
|---|---|---|---|---|
| **bitcoin-core/secp256k1** (schnorrsig module) | Core tens of KB + precomp table selectable **2 / 22 / 86 KiB** | A few KB context + stack | Modern C89/C99; endian-neutral (explicit byte I/O) | Reference-grade, constant-time, has 32-bit field/scalar reps. Heaviest but most correct. |
| **micro-ecc (uECC)** | ~small (single .c) | small stack | Very portable C | Ships secp256r1 **and secp256k1**, but **ECDSA only — no Schnorr**. Would need a Schnorr layer on top of its field/point ops, or use only its bigint core. |
| **Hand-rolled** (8x32 field + BIP-340 on top) | smallest possible | tunable | Full control | Highest correctness risk; only attractive if paired with the precompute dissolve, which shrinks the required surface dramatically. |

Sources: bitcoin-core precomp table sizes **2 / 22 / 86 KiB** are the currently-supported
`ecmult_gen` options (v0.5.0 reduced the old 32/64/512 KiB set to 2/22/86 KiB), configurable and
static-embeddable for embedded targets.
([secp256k1 ecmult_gen](https://github.com/bitcoin-core/secp256k1/blob/master/src/ecmult_gen_impl.h),
[libsecp256k1 v0.5.0 notes](https://www.nobsbitcoin.com/libsecp256k1-v0-5-0/))
micro-ecc scope (curves incl. secp256k1, ECDSA/ECDH, no Schnorr): [micro-ecc](https://github.com/kmackay/micro-ecc).

**Footprint reality on N64:** SM64 ships on an 8 MB cartridge (carts go to 64 MB) and the N64
has 4 MB RAM (8 MB with Expansion Pak). Tens of KB of code + an 86 KiB table + a few KB of
stack are all comfortably affordable. **Code size and RAM do not gate this feature** — a notable
softening of the ticket's "tight ROM/RAM budget" premise. The gate, if any, is CPU cycles (§4)
and the open-source key-extraction problem (separate ticket).

### Toolchain / IDO portability
- SM64 decomp builds "matching" ROMs with the old **IDO** compiler, but *new enhancement code
  that does not need to reproduce original ROM bytes* is normally built with **GCC**, which
  handles modern C fine. So the crypto need **not** pass through IDO — the IDO portability worry
  is largely dissolved for a new feature module. (Confirm against this repo's `Makefile` /
  `enhancements/` build path before committing to it.)
- **N64 is big-endian.** secp256k1 and BIP-340 serialize via explicit big-endian byte functions,
  so endianness is a non-issue if the library's byte-I/O helpers are used (don't `memcpy` raw
  limbs).
- **VR4300 `mulmul` errata / `-mfix4300`:** this hardware bug affects a **floating-point**
  multiply followed by a multiply/branch; the compiler inserts a NOP to avoid it. Integer
  `MULT`/`MULTU` (what bignum code uses) are **not** affected, so the errata is not a concern for
  field arithmetic. ([LLVM -mfix4300 patch](https://www.mail-archive.com/cfe-commits@lists.llvm.org/msg259414.html))

## 4. Big-integer / field arithmetic on the VR4300

The VR4300 is 32-bit MIPS III with a **hardware integer multiplier**, contradicting the "no fast
multiply" framing:
- `MULTU` (32x32 -> 64 in HI/LO) ≈ **5 cycles**; `DMULT` (64x64) ≈ **8 cycles**.
  ([R4300 spec / SGI R4300 Processor Specification Rev 2.2](https://ultra64.ca/files/documentation/silicon-graphics/SGI_R4300_RISC_Processor_Specification_REV2.2.pdf))
- Integer `DIV`/`DDIV` are slow (~30-70 cycles) — but real bignum code **never** uses hardware
  divide for modular reduction; it uses Montgomery/Barrett reduction (multiplies + shifts). So
  the slow-divide fact is moot.

**Representation:** 256-bit values as **8 x 32-bit limbs**. bitcoin-core already ships 32-bit
representations — `field_10x26` (26-bit limbs to leave carry headroom) and `scalar_8x32` — which
are the correct reps to select for MIPS. A schoolbook 256x256 product is 64 `MULTU`s (~320
cycles of multiply) plus adds/carries; **secp256k1's prime `p = 2^256 - 2^32 - 977` has a
special form** enabling fast reduction (a few multiplies by the small constant, no division).
The scalar field order `n` has no special form -> Montgomery reduction for scalar ops.
([field_10x26 / scalar_8x32 in secp256k1 source](https://github.com/bitcoin-core/secp256k1))

**Cost of one signature (extrapolation, not measured on N64):**
- The dominant term is the fixed-base multiply `R = k*G`: ~256 point additions naively, far
  fewer with a precomputed comb table (bitcoin-core's default). A point op is ~10-20 field
  mults; a field mult is ~64 `MULTU` + reduction. Order **10^6-10^7 cycles** for a full,
  unoptimized in-ROM sign.
- Calibration point: micro-ecc on an ARM **Cortex-M0 @ 48 MHz with a 32-cycle 32x32 multiply**
  does a P-256 keygen (one scalar mult) in ~**426 ms** and a 192-bit ECDH in ~175 ms.
  ([micro-ecc perf / SAMR21/M0+ eval refs](https://github.com/kmackay/micro-ecc)).
  The VR4300 has a **~5-cycle** multiply (≈6x faster per multiply) and runs at ~**93.75 MHz**
  (≈2x clock), so a comparable scalar multiply should land **well under ~100 ms**, plausibly
  tens of ms. **This is an extrapolation from ARM figures, not a VR4300 benchmark.**
- **Frame budget:** at 30 fps one frame is on the order of a few million cycles. A full sign at
  10^6-10^7 cycles is ~0.5-6 frames — but since it is **one-shot and off the hot path**, it can
  occupy a brief "computing…" pause or be spread across frames. There is no realtime constraint
  to satisfy. With the precompute dissolve (§5) the runtime drops to a few SHA-256 blocks + one
  modmul (~10^4 cycles), i.e. **a fraction of a single frame** — effectively free.

## 5. Constant-time vs. size/speed, given the threat model

Threat model (from issue #4): offline, air-gapped, single-user, renders one ephemeral QR; the
signature proves *provenance* ("came from a ROM holding the key"), not honest play. There is
**no remote adversary observing signing timing, power, or cache** during the operation.

Therefore:
- **Constant-time execution buys almost nothing here.** Timing/power side-channels require an
  attacker measuring the signer; an offline console rendering a QR has none. A non-constant-time
  (smaller, simpler, faster) path is defensible.
- **The genuinely security-critical invariant is nonce uniqueness / non-reuse.** Two signatures
  over different messages with the same `k` let anyone solve `d = (s1 - s2)/(e1 - e2)`. This
  matters *especially* for the precompute dissolve, where nonces are a finite embedded pool.
- Key **extraction** from the open-source ROM is the dominant risk and is out of scope for this
  ticket (key-hardening ticket owns it). No amount of constant-time signing helps there.

## 6. Ackoff: solve / resolve / dissolve

**Solve (brute force):** Port bitcoin-core/secp256k1 schnorrsig wholesale, run the full BIP-340
sign in-ROM including `k*G`. Works, correct, ~tens of KB + table, ~tens of ms one-shot.
Over-engineered for the threat model (constant-time we don't need) but the safe default.

**Resolve (optimize within the frame):** Keep in-ROM signing but (a) drop constant-time, (b) use
the 2 KiB precomp table, (c) hand-tune the 8x32 field for VR4300's 5-cycle multiply and fast
`p`-reduction, (d) use non-spec but valid nonce derivation. Smaller and faster; still does one
scalar multiply per sign.

**Dissolve (reframe the cost away) — three escalating options:**

1. **Precomputed nonces (recommended primary dissolve).** Generate a pool of one-time nonces
   `(k_i, R_i = k_i*G)` **offline at build time**; embed them in the ROM. Because BIP-340
   verification never inspects nonce derivation (§2), the resulting signatures are fully valid.
   Runtime per event reduces to: compute `e` (a few SHA-256 blocks) and `s = (k_i + e*d) mod n`
   (**one 256-bit modmul + one modadd**). **All elliptic-curve scalar multiplication is gone from
   the ROM.** Cost: ~64 B per stored `(k_i, R_i)`; SM64 has 120 stars, so ~120-150 nonces
   ≈ **~10 KB** covers a full playthrough, and issue #4's ephemeral single-session design means
   even a small pool suffices. **Hard constraint:** consume each nonce exactly once; if the pool
   can be exhausted, define the behavior (stop signing / recycle keys — must NOT reuse a nonce
   with a live key). Note: embedding secret `k_i` in an open-source ROM is no weaker than
   embedding the private key `d` itself, which issue #4 already accepts as a build-time shared
   secret.

2. **Full precomputation of signatures (maximal dissolve, constrains the event).** If the entire
   event were deterministic and enumerable at build time, whole signatures could be precomputed
   offline and the ROM would just emit bytes — **zero crypto in ROM.** Blocker: event content
   varies per play (which star, score/frame-count) and Nostr events carry a timestamp — and the
   N64 has **no RTC** (issue #4). This only works if (a) the timestamp is fixed/omitted and (b)
   the variable payload is drawn from a small enumerable set. Feasible in principle for a
   constrained event schema; flagged as the far end of the spectrum, trades event expressiveness
   for eliminating the crypto entirely.

3. **Alternative scheme / delegation — dead ends, documented so.**
   - Cheaper curve (ed25519): rejected by Nostr. Not valid.
   - NIP-26 delegation: the ROM would still have to Schnorr-sign a delegation/event, so the
     signing primitive is not removed; NIP-26 is also deprecated/contested. Not a real dissolve.

**Recommended landscape position:** default to **Dissolve #1 (precomputed nonces)** layered on a
**resolved** (non-constant-time, minimal) field/scalar core. This preserves a valid, immutable,
self-signed BIP-340 event while cutting the in-ROM cost to effectively a hash plus one modular
multiply — trivially within any frame budget — and reduces the code that must be ported to the
scalar/field arithmetic plus the challenge hash, no `ecmult_gen` needed. Keep the full solve
(bitcoin-core wholesale) as the fallback if the nonce-pool lifecycle proves awkward.

## 7. Open questions handed back to the map

- Nonce-pool lifecycle: pool size, exhaustion behavior, and how it interacts with the ephemeral
  "one QR, never re-displayable" flow.
- Whether the event schema can be constrained enough (fixed/omitted timestamp given no RTC) to
  reach Dissolve #2 for some or all fields.
- Confirm this repo's build path lets a new module compile under GCC (not IDO) — checked in
  principle here, needs a `Makefile`/`enhancements/` confirmation.
- Exact VR4300 sign cost: the ~tens-of-ms figure is extrapolated from ARM; a real measurement
  (or cycle-accurate estimate) would firm up the frame-budget story, though the dissolve makes
  it moot.

---

## Sources

- [NIP-01: Basic protocol](https://github.com/nostr-protocol/nips/blob/master/01.md) — event `id`/`sig`, secp256k1 Schnorr, x-only pubkeys.
- [BIP-340: Schnorr Signatures for secp256k1](https://bips.dev/340/) — 64-byte format, signing algorithm, tagged hashes, verification equation.
- [bitcoin-core/secp256k1](https://github.com/bitcoin-core/secp256k1) — reference library, 32-bit field/scalar representations.
- [secp256k1 ecmult_gen_impl.h](https://github.com/bitcoin-core/secp256k1/blob/master/src/ecmult_gen_impl.h) — precomputation table / comb algorithm.
- [libsecp256k1 v0.5.0 notes](https://www.nobsbitcoin.com/libsecp256k1-v0-5-0/) — supported precomp table sizes 2 / 22 / 86 KiB.
- [micro-ecc (kmackay)](https://github.com/kmackay/micro-ecc) — small ECDH/ECDSA lib; curves incl. secp256k1; no Schnorr; Cortex-M0 perf reference.
- [SGI R4300 RISC Processor Specification Rev 2.2](https://ultra64.ca/files/documentation/silicon-graphics/SGI_R4300_RISC_Processor_Specification_REV2.2.pdf) — MULTU/DMULT cycle counts.
- [NEC VR4300 datasheet](http://www.bitsavers.org/components/nec/mips/Vr4300-ds_200011.pdf) / [N64brew VR4300](https://n64brew.dev/wiki/VR4300) — CPU spec.
- [LLVM -mfix4300 patch](https://www.mail-archive.com/cfe-commits@lists.llvm.org/msg259414.html) — VR4300 FP `mulmul` errata (not integer).

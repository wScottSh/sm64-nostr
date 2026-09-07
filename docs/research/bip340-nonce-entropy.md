# BIP-340 deterministic-nonce & on-N64 entropy landscape

Research findings for [issue #7](https://github.com/wScottSh/sm64-nostr/issues/7) — part of the Wayfinder map [#4](https://github.com/wScottSh/sm64-nostr/issues/4).

**Posture:** map the landscape, not a go/no-go call. Applies Ackoff's solve / resolve / **dissolve** lens.

**Bottom line up front:** BIP-340 explicitly blesses signing with a *constant all-zero* `aux_rand`. The result is a fully spec-valid, secure signature — the auxiliary randomness is *supplemental only*. This **dissolves** the entropy problem: on a machine with no RNG, no RTC, and no hardware crypto, the correct move is to not have an entropy problem at all. Every N64 "entropy source" surveyed below is either deterministic (useless as a secret) or a hardware-timing value whose only defensive value is against physical fault/side-channel attacks that are out of scope for this threat model.

---

## 1. Can we sign fully deterministically and stay spec-valid?

**Yes, unambiguously.** BIP-340's signing algorithm takes a third input `aux_rand` (32 bytes), but the spec designs the scheme so that this input can be a fixed constant.

### What the spec actually says (BIP-340, primary source)

Source: <https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki> ("Default Signing" and its "Optimizations / notes").

Nonce derivation (verbatim structure):

- `t = bytes(d) XOR hash_BIP0340/aux(aux_rand)`
- `rand = hash_BIP0340/nonce(t || bytes(P) || m)`
- `k' = int(rand) mod n`, and the nonce point is `R = k'·G`.

The spec on making `aux_rand` cheap or absent (verbatim):

> "If obtaining randomness is expensive, 16 random bytes can be padded with 16 null bytes to obtain a 32-byte array. If randomness is not available at all at signing time, a simple counter wide enough to not repeat in practice (e.g., 64 bits or wider) and padded with null bytes to a 32 byte-array can be used, **or even the constant array with 32 null bytes**." (emphasis added)

The spec on why randomness is only supplemental (verbatim):

> "Using any non-repeating value increases protection against fault injection attacks. Using unpredictable randomness additionally increases protection against other side-channel attacks, and is recommended whenever available. Note that while this means the resulting nonce is not deterministic, the randomness is only supplemental to security. **The normal security properties (excluding side-channel attacks) do not depend on the quality of the signing-time RNG.**" (emphasis added)

And the rationale for hashing `aux_rand` at all (verbatim):

> "The auxiliary random data is hashed (with a unique tag) as a precaution against situations where the randomness may be correlated with the private key itself."

### Why deterministic nonces are safe here (the core argument)

The nonce `k'` is a deterministic function of `(d, P, m)` — secret key, public key, message. With `aux_rand = 0x00…00`, the `hash_BIP0340/aux(0…0)` term is a fixed constant, so `t` is just `bytes(d) XOR <constant>` and the whole nonce reduces to `hash(constant_masked_d || P || m)`.

The one catastrophic failure mode for Schnorr/ECDSA is **nonce reuse across two *different* messages** (it leaks the private key via simple algebra). A deterministic nonce derived from the message *cannot* reuse a nonce across different messages: different `m` ⇒ different `rand` ⇒ different `k'`. Signing the *same* message twice reproduces the *same* signature, which is harmless (an observer already had that signature).

This is the same reasoning behind RFC 6979 (deterministic ECDSA), which the Bitcoin ecosystem has used in production for years. BIP-340 goes one step further by folding in *optional* aux randomness, but the deterministic core is the security foundation, not the randomness.

### Security implications of omitting / zeroing aux_rand

| Attack class | Protected by deterministic core? | Protected by aux_rand? | In scope for this project? |
|---|---|---|---|
| Nonce reuse / bad-RNG key leak | **Yes** (fully) | n/a | The whole point |
| Chosen/known-message forgery | Yes (EUF-CMA of Schnorr) | n/a | Yes — still holds |
| Fault-injection attacks (glitch a signing op, compare outputs) | No | Partially (non-repeating value helps) | **No** — attacker with physical glitching of an N64 also just dumps the key |
| Power / EM side-channel leakage during scalar mult | No | Partially (unpredictable randomness helps) | **No** — same reasoning; and see key-hardening ticket |

The residual risk of `aux_rand = 0` is **exclusively** physical fault / side-channel attacks. In this project's threat model (open-source decomp, the private key is *in the ROM* and the honest-threat-model position per map #4 is that the key is not truly unextractable), an attacker capable of fault/side-channel analysis on the console can extract the key directly and doesn't need to attack the nonce. So the marginal security loss from zeroing aux_rand is effectively **zero** for us.

---

## 2. Entropy sources on N64 / SM64 (if aux randomness is nonetheless wanted)

The N64 has **no RTC, no hardware RNG, no crypto peripheral** (per map #4). Everything below is either deterministic or a cycle-timing artifact. Quality is judged as "unpredictability to an external observer of the QR/event," which is the only property that matters for aux_rand.

### 2a. Game PRNG — `random_u16()` / `gRandomSeed16`
Source: `src/engine/behavior_script.c:31-66`.

- 16-bit custom LFSR-like PRNG. State is `static u16 gRandomSeed16` (`behavior_script.c:31`).
- **Never externally seeded.** Grep for all assignments shows `gRandomSeed16` is written *only inside `random_u16()` itself* (lines 44, 50, 57, 59, 62) — there is no seeding from time, input, or hardware anywhere in the tree. As a BSS static it is **0 at power-on**.
- Consequence: the entire RNG stream is a fixed sequence from boot, advancing only when game logic calls `random_u16()`. This is the well-documented property TAS runs exploit to make RNG-dependent behavior frame-perfectly reproducible.
- **Entropy quality: ~0 for our purposes.** Only 16 bits of state, deterministic from boot, and its position in the stream is a deterministic function of gameplay events. An observer who knows the play trace knows the seed. Useless as a secret; also useless as a mere non-repeating counter unless we track calls.

### 2b. Frame counter — `gGlobalTimer`
Source: `src/game/game_init.c:62` (`u32 gGlobalTimer = 0`), incremented at `game_init.c:342` and `:382` (per-frame).

- Starts at 0, increments once per rendered frame. Fully deterministic given identical boot + input timing.
- As a **non-repeating counter** it is decent (32-bit, monotonic within a session), which is exactly the "simple counter … padded with null bytes" the spec suggests. But it resets to 0 every power-on, so it repeats across sessions.
- **Entropy quality: low** (predictable), but **adequate as a fault-injection-only non-repeating value within a session.** Not a secret.

### 2c. VR4300 CP0 Count register — `osGetCount()` / `osGetTime()`
Source: `include/PR/os_misc.h:7` (`u32 osGetCount(void)`), `lib/src/osGetTime.c` (builds `OSTime` from `osGetCount()` + base). `osGetCount()` reads the CP0 Count register (`$9`), which increments at half the CPU clock (~46.875 MHz on a ~93.75 MHz VR4300).

- This is the **closest thing to a real entropy source** on the machine. Its low bits at any given wall-clock instant depend on precise cycle timing since boot and are not predictable to an outside observer of the QR.
- Caveats: (1) It is *timing*, not randomness — on a deterministic boot+input path it is reproducible in an emulator/TAS. (2) It is only "unpredictable" relative to an observer who doesn't control the execution environment; anyone running the ROM in an emulator controls it completely. (3) Its distribution is not uniform and it is correlated with frame timing.
- **Entropy quality: best available, but weak and non-secret.** Good enough for the spec's "non-repeating value" / supplemental role; **not** good enough to be relied on as a secret, and unnecessary given §1.

### 2d. Controller / input timing — `gControllerPads[]`, `osContGetReadData()`
Source: `src/game/game_init.h:28` (`extern OSContPad gControllerPads[4]`), `lib/src/osContStartReadData.c:44` (`osContGetReadData`).

- Human input timing (which frame a button is pressed, analog stick jitter) carries a few bits of real-world unpredictability *per session*, harvestable by mixing button state / stick values / the frame index of the star-completion event.
- Caveats: emulators and TAS replay make it fully deterministic; a human replaying "the same run" reproduces most of it; the quantity of entropy is small and hard to quantify honestly.
- **Entropy quality: a few real bits per live human session, ~0 under replay.** Non-secret.

### 2e. RCP / VI state
- The Reality Co-Processor's video-interface line counter (`osCreateViManager.c` uses `osGetCount()` for retrace timing) is just another view of cycle timing (§2c). No independent entropy beyond the Count register. **No separate value.**

### Summary of source quality

| Source | Bits | Unpredictable to external observer? | Deterministic under emulation/TAS? | Fit for aux_rand's supplemental role |
|---|---|---|---|---|
| `random_u16` / `gRandomSeed16` | 16 | No (known from boot+trace) | Yes | Poor |
| `gGlobalTimer` | 32 (counter) | No | Yes | OK as non-repeating counter only |
| `osGetCount` (CP0 Count) | ~32 | Somewhat (real hardware only) | Yes | Best available, still weak |
| Controller/input timing | few | Somewhat (live human only) | Yes | Marginal |
| RCP/VI | — | = Count register | Yes | None (redundant) |

**Every source collapses to "deterministic under emulation."** None is a secret. The best real-hardware entropy (`osGetCount`) buys protection only against attack classes that are out of scope.

---

## 3. Ackoff dissolve: does deterministic signing dissolve the entropy problem?

**Yes — this is the textbook dissolve.**

- **Solve** would be: hunt for the "best" entropy source on N64 and engineer an RNG/whitening pipeline (mix `osGetCount` + input timing + PRNG, hash it, seed a CSPRNG). High effort, and it still produces something an emulator reproduces — a false sense of security.
- **Resolve** would be: pick the least-bad source (`osGetCount`) and accept "good enough" aux randomness. Still adds code, still doesn't help our threat model.
- **Dissolve** is: recognize that BIP-340 was explicitly designed so that `aux_rand` can be the 32-zero constant, making the signature deterministic and fully valid. The entropy question then simply *does not arise* — there is no RNG to build, seed, test, or defend. The machine's lack of entropy stops being a problem because we stopped needing entropy.

### What the dissolve costs

Small and mostly acceptable, but state it honestly:

1. **Same message ⇒ same signature (byte-identical event/QR).** Two players who complete the identical star with an identical serialized event payload produce the *identical* Nostr event id and signature. **Mitigation is already in the design, not the crypto:** the Nostr event includes a `created_at` timestamp and content that varies per run — and per map #4 the *timestamp source is itself an open research ticket*. As long as any field in the signed payload differs (timestamp, frame count, a per-session nonce field in the event content), the messages differ and so do the nonce and signature. **Note the dependency:** the "no entropy needed" conclusion assumes the *message* is unique per meaningful submission; uniqueness must live in the event payload, not in the nonce. If the payload could be bit-identical across two legitimately-distinct submissions, revisit.
2. **No fault/side-channel hardening.** As argued in §1, out of scope given the key already lives in an extractable ROM.
3. **Determinism is arguably a *feature* here.** A deterministic signer is far easier to unit-test (fixed key + fixed message ⇒ known-answer test vectors), which matters a lot for an on-N64 crypto port with no debugger. BIP-340 even ships test vectors with `aux_rand = 0`.

### Recommendation space (not a decision)

- **Baseline (recommended to spec):** sign with `aux_rand = 32 × 0x00`. Zero entropy code. Spec-valid. Testable against BIP-340's own zero-aux test vectors.
- **If a belt-and-suspenders non-repeating value is wanted for near-free:** feed `gGlobalTimer` (or `osGetCount`) into `aux_rand` — pure upside per the spec, but adds a tiny amount of non-determinism that complicates known-answer testing. Judge against the test-vector benefit.
- **Do NOT** build an entropy-mixing/CSPRNG pipeline. It is effort spent buying protection this threat model doesn't need, and it forfeits deterministic testability.
- **Cross-ticket flag for the map:** payload uniqueness (timestamp/nonce field) is the real dependency created by choosing deterministic signing. This couples issue #7's answer to the timestamp research ticket. Surface it there.

---

## Sources

- BIP-340 (Schnorr signatures for secp256k1), "Default Signing" + notes — <https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki> (primary spec; quotes above are verbatim from that document).
- RFC 6979 (Deterministic ECDSA) — precedent for message-derived nonces being production-safe.
- Repo primary sources (this tree):
  - `src/engine/behavior_script.c:31-66` — `gRandomSeed16`, `random_u16()`; confirmed never externally seeded (grep of all `gRandomSeed16 =` sites).
  - `src/game/game_init.c:62,342,382` — `gGlobalTimer` init + per-frame increment.
  - `include/PR/os_misc.h:7`, `lib/src/osGetTime.c` — `osGetCount()` (CP0 Count register), `osGetTime()`.
  - `src/game/game_init.h:28`, `lib/src/osContStartReadData.c:44` — controller read path.

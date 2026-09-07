# Power-on ephemeral key & per-event uniqueness on the VR4300

Research findings for [issue #21](https://github.com/wScottSh/sm64-nostr/issues/21) — part of the Wayfinder map [#4](https://github.com/wScottSh/sm64-nostr/issues/4). Explores **Model B** (ephemeral runtime key, provenance offloaded) and blocks the key-provenance decision [#10](https://github.com/wScottSh/sm64-nostr/issues/10). Builds on [#7](https://github.com/wScottSh/sm64-nostr/issues/7) (N64 has no good entropy) and [#12](https://github.com/wScottSh/sm64-nostr/issues/12) (`created_at` is a fixed build-epoch constant).

**Posture:** map the landscape, not a go/no-go call. Applies Ackoff's solve / resolve / **dissolve** lens.

**Bottom line up front:** In Model B the key is not a trust anchor, so it need not be *strong* — only **unique per event**. But *every* boot-state source surveyed below is deterministic under the only condition that matters for uniqueness: a **cold power cycle on a reproducible platform (an emulator, or a cold boot with zeroed RAM)**. The decomp itself zeroes its entire BSS at boot (`asm/entry.s`), and the two reference emulators fill RDRAM with a *fixed constant* every power-on (mupen64plus → `0x00`, ares → `0xFF`). So a keypair "randomly" generated at power-on collides byte-for-byte across power cycles on the same emulator, and with a deterministic input trace the whole run collides — reproducing exactly the payload-uniqueness failure Model B was meant to avoid. Boot-state entropy therefore **cannot guarantee** uniqueness. The only sources that carry genuine, non-reproducible variability are **live human interaction timing** and the **VR4300 Count register sampled at a human-triggered moment** — and even those vanish under TAS/emulator replay. The **dissolve**: stop trying to make the *key* unique at power-on. Instead, guarantee uniqueness in the **signed payload** by mixing in a value captured at the moment of star completion (frame counter `gGlobalTimer` + first/continuous controller input + `osGetCount`). Uniqueness then rides on the human-and-time-specific act of completing the star, not on unknowable boot state.

---

## 1. The constraint, restated precisely

Model B wants a *fresh keypair per power-on*, discarded with the QR. The security bar is low (not a trust anchor), but there is a hard **payload-uniqueness** constraint inherited from the deterministic-signing decision in #7/#12:

- BIP-340 signing is deterministic given `(d, P, m)` with `aux_rand = 0` (see [`docs/research/bip340-nonce-entropy.md`](./bip340-nonce-entropy.md), §1).
- Identical event *contents* ⇒ identical `id` (SHA-256 of the serialized event) ⇒ identical signature ⇒ **an identical Nostr event** (a duplicate that relays dedupe/drop).
- `created_at` is a fixed build-epoch constant (#12), so it is **not** a uniqueness source.

So the question "can we make a unique ephemeral *key* per event without persistence?" is really "**is there any boot-derived value that differs across two legitimate submissions, and does it survive the adversarial/replay environments we care about?**" A per-power-on key only helps if `P` (the pubkey, which is part of the signed event's author field / affects the payload) actually differs per submission.

---

## 2. Landscape survey — boot & runtime variability sources on the VR4300/N64

Judged on one axis: **does this value differ across two distinct legitimate star completions, and does it survive (a) cold boot with zeroed RAM, (b) a deterministic emulator, (c) reset-vs-power-cycle?** "Deterministic" here means *useless for uniqueness*, the mirror image of #7's "useless as a secret."

### 2a. Uninitialized RDRAM contents
- **Real hardware:** On power-on the CPU PC is set to `0xBFC00000` (PIF ROM); IPL3 performs RDRAM "current calibration," maps the chips, then loads 1 MiB of game code (ROM `0x10001000`–`0x10101000`) into RDRAM and jumps to it. IPL3 initializes RDRAM electrically but the *data cells* it does not load into are not guaranteed to any value — classic uninitialized DRAM. Source: [n64brew, Initial Program Load](https://n64brew.dev/wiki/Initial_Program_Load); [RetroReversing, N64 Boot Code Analysis](https://www.retroreversing.com/n64bootcode).
- **The decomp erases most of this anyway:** `asm/entry.s` (the game entry point) zeroes the *entire* noload/BSS segment before calling `main_func` — a tight `sw $zero` loop from `_mainSegmentNoloadStart` for `_mainSegmentNoloadSize` bytes (`asm/entry.s:30-44`). So any BSS-resident buffer a key routine might read is deterministically **0** at the first instruction of game code. To harvest "uninitialized RDRAM" a key routine would have to deliberately read RAM *outside* the loaded + zeroed regions — an unusual, fragile move.
- **Emulators fill it with a constant — this is the killer.** Boot state that looks "random" on a warm-rebooted physical unit is a *fixed constant* on the platforms most likely to run this ROM:
  - **mupen64plus:** `poweron_rdram()` does `memset(rdram->dram, 0, rdram->dram_size)` — RDRAM is **all-zero** every power-on. Source: [`src/device/rdram/rdram.c`](https://raw.githubusercontent.com/mupen64plus/mupen64plus-core/master/src/device/rdram/rdram.c) (`poweron_rdram`).
  - **ares:** `RDRAM::power(reset=false)` calls `ram.fill()`, and `Writable::fill(T fill = ~0ull)` defaults to all-ones — RDRAM is **all-`0xFF`** every power-on. Sources: [`ares/n64/rdram/rdram.cpp`](https://raw.githubusercontent.com/ares-emulator/ares/master/ares/n64/rdram/rdram.cpp) (`RDRAM::power`), [`ares/ares/memory/writable.hpp`](https://raw.githubusercontent.com/ares-emulator/ares/master/ares/ares/memory/writable.hpp) (`allocate`/`fill` default `~0ull`).
- **Verdict:** Uninitialized RDRAM is (a) mostly zeroed by the game's own entry code, and (b) a fixed constant on both reference emulators. **Zero uniqueness across power cycles in emulation.** On real hardware it carries *some* warm-reboot residue but is not reliably present at a cold boot and is inaccessible after BSS-zeroing. Not a dependable uniqueness source.

### 2b. PIF RAM
- PIF RAM (64 bytes at the top of the PIF address space) holds boot/CIC handshake state: the PIF-SM5 firmware writes boot flags and the CIC-derived seed/checksum region during IPL. Source: [n64brew, PIF-NUS](https://n64brew.dev/wiki/PIF-NUS); [n64brew, Initial Program Load](https://n64brew.dev/wiki/Initial_Program_Load).
- These values are a **deterministic function of the console region + CIC variant** (six documented CIC bootcode variants, [RetroReversing](https://www.retroreversing.com/n64bootcode)). They do not vary between two boots of the same unit, and emulators reproduce them exactly (the whole point of CIC emulation). During gameplay the SI/PIF path repeatedly memsets `__osContPifRam` for controller polling (`lib/src/osContStartReadData.c:28-31,80`), so any boot residue there is overwritten early.
- **Verdict:** deterministic per console; **no per-event uniqueness.**

### 2c. VI (video interface) & AI (audio interface) counters
- The VI current-vertical-line counter and AI DMA length/status advance with the RCP clock. libultra's VI manager derives retrace timing from the CPU Count register rather than exposing a fresh entropy source (`osCreateViManager` uses `osGetCount()` for scheduling — same underlying clock as §2e). These counters are *phase* relative to boot: on a deterministic boot+input path an emulator reproduces them cycle-for-cycle.
- **Verdict:** just another view of cycle-timing (§2e); **deterministic under emulation, no independent uniqueness.**

### 2d. Controller / PIF polling timing & input
- Controller state is read each frame via `osContStartReadData`/`osContGetReadData` into `gControllerPads[]` (`lib/src/osContStartReadData.c:14,44-57`). The **content** (which buttons, analog-stick raw X/Y) and the **frame index at which a given input first arrives** carry genuine real-world, per-session unpredictability when a *live human* is playing.
- Caveats: a TAS/replay reproduces inputs and their frame timing exactly (this is precisely how TAS determinism works); a human "repeating the same run" reproduces most of it; the quantity of entropy is small and hard to quantify. But unlike everything above, it is **not a fixed boot constant** — two genuinely-distinct live completions almost always differ here.
- **Verdict:** the **best real, non-reproducible variability available**, but only for *live* play; ~0 under replay. Non-secret, and that's fine for Model B.

### 2e. VR4300 CP0 Count register (`osGetCount`)
- On non-iQue builds `osGetCount` is literally `mfc0 $v0, $9; jr $ra` — a raw read of CP0 Count register `$9` (`lib/asm/osGetCount.s:76-79`). Count increments at half the CPU issue rate (~46.875 MHz on the ~93.75 MHz VR4300); the "increment every two clocks" behavior is the standard MIPS CP0 counter design ([MIPS32 PRA / WikiChip, MIPS Coprocessor 0](https://en.wikichip.org/wiki/mips/coprocessor_0); NEC [VR4300 User's Manual](https://datasheets.chipdb.org/NEC/Vr-Series/Vr43xx/U10504EJ7V0UMJ1.pdf)).
- Sampled *at the moment of a human-triggered event* (star grab), its low bits depend on precise cycle count since boot and are not predictable to an observer of the QR. This is the closest thing to a hardware entropy source (same conclusion as #7 §2c).
- Caveats: (1) it is *timing*, not randomness; (2) on a deterministic boot+input path an emulator reproduces it exactly; (3) whoever runs the ROM in an emulator controls it completely.
- **Verdict:** best hardware value, real variability on live hardware, **fully reproducible under a deterministic emulator/TAS.** Excellent as *one ingredient* of a payload-uniqueness value, insufficient alone.

### 2f. Game PRNG (`gRandomSeed16`) and frame counter (`gGlobalTimer`)
- `gRandomSeed16` is a `static u16` (BSS) → **0 at power-on** (zeroed by `asm/entry.s`), a 16-bit LFSR advanced only by gameplay calls (`src/engine/behavior_script.c:31-65`). Deterministic from boot; the TAS-known property. Useless for uniqueness on its own.
- `gGlobalTimer` starts at 0 (`src/game/game_init.c:62`) and increments once per rendered frame (`game_init.c:342,382`). Monotonic within a session, resets to 0 every power-on. As a **non-repeating counter within a session** it is decent; across sessions it repeats.
- **Verdict:** deterministic; useful only as *counter* ingredients, and only meaningful when combined with a genuinely-variable input (§2d/§2e).

### Summary table

| Source | Differs per live completion? | Survives cold boot (zeroed RAM)? | Survives deterministic emulator? | Reset vs power-cycle |
|---|---|---|---|---|
| Uninitialized RDRAM (§2a) | Rarely (warm residue only) | **No** (zeroed / fixed constant) | **No** (mupen→0x00, ares→0xFF) | reset may retain; power-cycle re-fills |
| PIF RAM (§2b) | No | No (deterministic per CIC) | No | n/a (overwritten by polling) |
| VI/AI counters (§2c) | Via timing only | No | No | tracks Count |
| Controller input + timing (§2d) | **Yes (live human)** | **Yes** | **No (replay reproduces)** | survives both |
| CP0 Count `osGetCount` (§2e) | **Yes (live hardware)** | **Yes** | **No (replay reproduces)** | keeps counting across soft reset |
| `gRandomSeed16` / `gGlobalTimer` (§2f) | No (deterministic) | No (BSS→0) | No | reset to 0 on cold boot |

**Every purely-boot-state source collapses to a fixed constant under emulation.** Only human-driven timing (§2d/§2e) carries non-reproducible variability, and even that dies under TAS/replay.

---

## 3. Where uniqueness breaks (the three failure modes the ticket asks about)

1. **Cold boot with zeroed RAM.** The decomp zeroes its whole BSS (`asm/entry.s:30-44`) and emulators fill RDRAM with a constant (§2a). A power-on key derived from "uninitialized" memory is therefore **the same key every cold boot** on a given platform. This is the primary break: it re-creates the exact duplicate-payload problem (identical `P` ⇒ identical event for identical star/content). **Uniqueness across power cycles from boot state alone: broken.**
2. **Deterministic emulator / TAS.** Emulators are *designed* to be reproducible: mupen64plus zeroes RDRAM (`poweron_rdram`), ares fills `0xFF` (`RDRAM::power`), and both reproduce Count and input traces cycle-for-cycle given the same inputs. A recorded run replays to a bit-identical event and QR. **Any boot-or-runtime "entropy" is fully controllable by whoever runs the ROM.** This also means an attacker/griefer can *intentionally* reproduce someone's event.
3. **Reset vs power-cycle.** Soft reset (NMI) does **not** reset the CPU Count register (it keeps counting) and does not necessarily clear RDRAM — ares' `RDRAM::power(reset=true)` skips `ram.fill()`, retaining RAM ([`rdram.cpp`](https://raw.githubusercontent.com/ares-emulator/ares/master/ares/n64/rdram/rdram.cpp)); real NMI likewise leaves RDRAM intact. So a *soft reset* preserves more prior state than a *cold power cycle*, but the decomp's BSS-zeroing runs on both paths (it is unconditional in `entry.s`), so the game-visible starting state is the same either way. Net: reset-vs-power-cycle does not rescue uniqueness — and for the "fresh key per power-on" model, a player who soft-resets between stars would *not* even get the residual-RAM difference the model assumes.

---

## 4. What would GUARANTEE uniqueness

Boot state cannot. What can, in decreasing order of robustness:

1. **Persistence + monotonic counter (the only *guarantee* that survives all three failure modes).** Store a counter in cartridge SRAM/EEPROM/FlashRAM/Controller Pak, increment and save on each event, mix into the payload. This survives cold boot, emulation, and reset because it is *stateful*. But it violates the ticket's explicit "WITHOUT persistence" constraint and depends on save hardware. Flagged as the fallback that *does* guarantee uniqueness if the no-persistence constraint is ever relaxed. (Note: even persistence can be rolled back by an emulator save-state, so this guarantees uniqueness for *honest* play, not against a determined replay attacker.)
2. **Mix human-driven capture-time values into the signed payload (best fit for Model B's constraints).** At the instant of star completion, fold into a dedicated payload field (e.g. event content or a tag): `osGetCount()` (§2e) + `gGlobalTimer` (§2f) + a rolling hash of `gControllerPads[]` inputs and the frame indices at which they arrived (§2d). This differs across two genuine live completions with overwhelming probability, because it binds the value to *when a specific human did a specific thing on real timing*. It does **not** survive a deterministic replay — but a replay is, by definition, re-submitting a value the player already produced, so the only "collision" it creates is a player duplicating their own event, which is the harmless case (an observer already had that event; cf. #7 §1). It is the honest, low-cost answer within "no persistence."
3. **Derive the ephemeral key from that same capture-time value** (if Model B specifically wants key-level freshness). Since the key is not a trust anchor, seed the keypair from `hash(osGetCount || gGlobalTimer || input_digest)`. This makes `P` itself differ per live completion. But note this **buys nothing over option 2** for uniqueness — the same underlying variability is doing the work, and putting it in the payload directly is simpler and testable. Prefer 2.

**The honest ceiling:** *nothing* on this machine can make an event unique against an adversary who controls the execution environment (emulator/TAS), because such an adversary can reproduce or hand-pick every input. Uniqueness is only ever achievable *for honest, live play* — which matches Model B's premise that the key is not a trust anchor and provenance is offloaded downstream.

---

## 5. Ackoff lens: solve / resolve / dissolve

- **Solve** — hunt for the "best" boot-state entropy (uninitialized RDRAM, PIF RAM, Count at boot) and derive the key from it. **Fails:** §2/§3 show every boot-state source is a fixed constant under emulation and mostly zeroed by `entry.s`. This produces *identical keys per power-on* — the opposite of the goal — while feeling like it did something. The most dangerous option.
- **Resolve** — accept the least-bad boot source (Count at power-on) and call the key "probably unique enough." **Fails honestly:** at *power-on* Count is near-constant (few cycles since reset) and fully reproducible in an emulator. "Good enough" here is a false sense of uniqueness.
- **Dissolve** — stop requiring the *key* to be unique at *power-on*. Recognize that (a) the key is not a trust anchor in Model B, and (b) uniqueness is a property of the **payload at the moment of the human event**, not of boot state. Move the uniqueness value to a capture-time field fed by human timing (option 4.2). The "no entropy at boot" problem then **does not arise**: there is nothing to harvest at power-on because uniqueness is sourced from the star-completion event itself. This mirrors #7's dissolve (deterministic signing) and composes with it: deterministic signer + capture-time-varied payload = unique-per-honest-event, fully testable.

### What the dissolve costs / implies
1. **Uniqueness holds for honest live play only.** Against emulator/TAS replay, events are reproducible — acceptable because the key isn't a trust anchor and Model B offloads provenance (#10).
2. **A payload field must carry the capture-time value.** This couples #21 to the event-schema/timestamp tickets (#12): since `created_at` is fixed, the uniqueness field must be an explicit, separate part of the signed content. Surface this dependency on #10/#12.
3. **Model B's "fresh key per power-on" framing is arguably the wrong lever.** The research suggests uniqueness should live in the payload regardless of whether the key is per-power-on or fixed-in-ROM (Model A). This weakens Model B's distinct advantage: a per-power-on key does **not** by itself buy uniqueness (it collides across cold boots), so its cost (needing entropy the machine lacks) buys little. Feed this into the #10 provenance decision.
4. **Determinism stays testable.** Capturing `osGetCount`/inputs only at the star event keeps the rest of the pipeline deterministic and unit-testable with fixed inputs, preserving #7's known-answer-test benefit.

### Recommendation space (not a decision)
- **Recommended within "no persistence":** dissolve — add a capture-time uniqueness field to the signed payload sourced from `osGetCount()` + `gGlobalTimer` + a digest of controller input/timing at star completion (option 4.2). Keep the signer deterministic (`aux_rand = 0`).
- **If Model B insists on a per-power-on key:** seed it from that same capture-time value (option 4.3), but understand it adds no uniqueness beyond 4.2 and complicates testing. Prefer 4.2.
- **If the no-persistence constraint is ever relaxed:** a saved monotonic counter (option 4.1) is the only mechanism that *guarantees* uniqueness across cold boot / reset for honest play.
- **Do NOT** derive uniqueness from uninitialized RDRAM / PIF RAM / boot Count — §3 shows these are fixed constants under the platforms that matter.
- **Cross-ticket flags for the map:** (a) uniqueness must live in an explicit signed-payload field, coupling #21 → #12/#10; (b) a per-power-on key does not itself deliver uniqueness — reconsider what Model B actually buys in the #10 decision.

---

## Sources

- Primary decomp sources (this tree):
  - `asm/entry.s:30-44` — game entry point zeroes the entire noload/BSS segment before `main_func` (unconditional on power-on and reset).
  - `lib/asm/osGetCount.s:76-79` — `osGetCount` = raw `mfc0 $v0, $9` read of CP0 Count register (non-iQue path).
  - `lib/src/osContStartReadData.c:14,28-31,44-57,80` — controller read path; `__osContPifRam` memset each poll.
  - `src/engine/behavior_script.c:31-65` — `gRandomSeed16` 16-bit LFSR, BSS static (0 at boot).
  - `src/game/game_init.c:62,342,382` — `gGlobalTimer` init to 0 + per-frame increment.
  - Related prior research: [`docs/research/bip340-nonce-entropy.md`](./bip340-nonce-entropy.md) (#7 — deterministic signing, entropy landscape).
- N64 hardware / boot (primary references):
  - n64brew Wiki, Initial Program Load — <https://n64brew.dev/wiki/Initial_Program_Load> (IPL3 RDRAM current-calibration, game-code load, memory-size write to 0x80000318).
  - n64brew Wiki, RDRAM — <https://n64brew.dev/wiki/RDRAM>.
  - n64brew Wiki, PIF-NUS — <https://n64brew.dev/wiki/PIF-NUS> (PIF-SM5 firmware, CIC handshake, PIF RAM).
  - n64brew Wiki, VR4300 — <https://n64brew.dev/wiki/VR4300>.
  - RetroReversing, N64 Boot Code Analysis — <https://www.retroreversing.com/n64bootcode> (six CIC bootcode variants; boot zeroes RSP DMEM/IMEM + cache init).
  - NEC VR4300 User's Manual — <https://datasheets.chipdb.org/NEC/Vr-Series/Vr43xx/U10504EJ7V0UMJ1.pdf>; MIPS CP0 counter (increments at half issue rate) — <https://en.wikichip.org/wiki/mips/coprocessor_0>.
- Emulator boot-state determinism (primary source code):
  - mupen64plus-core, `src/device/rdram/rdram.c` `poweron_rdram()` — `memset(rdram->dram, 0, ...)` (RDRAM zeroed each power-on) — <https://raw.githubusercontent.com/mupen64plus/mupen64plus-core/master/src/device/rdram/rdram.c>. Related fix PR #1111 — <https://github.com/mupen64plus/mupen64plus-core/pull/1111>.
  - ares, `ares/n64/rdram/rdram.cpp` `RDRAM::power()` — `ram.fill()` on power (not reset); reset preserves RAM — <https://raw.githubusercontent.com/ares-emulator/ares/master/ares/n64/rdram/rdram.cpp>.
  - ares, `ares/ares/memory/writable.hpp` — `allocate`/`fill` default `~0ull` (RDRAM filled with 0xFF) — <https://raw.githubusercontent.com/ares-emulator/ares/master/ares/ares/memory/writable.hpp>.

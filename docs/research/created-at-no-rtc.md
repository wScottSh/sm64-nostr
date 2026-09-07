# Research: `created_at` without a real-time clock — landscape

**Ticket:** [#12](https://github.com/wScottSh/sm64-nostr/issues/12) (part of map #4) · **Posture:** map the landscape, not a go/no-go. Applies Ackoff's solve / resolve / **dissolve** lens.

## Problem statement

A Nostr event requires a `created_at` unix-timestamp-in-seconds that is **part of the event id hash and therefore covered by the signature**. It must be fixed at signing time, inside the ROM. The N64 has **no real-time clock**: nothing on the console knows wall-clock time. So the ROM cannot read "now." This ticket maps how a `created_at` value could be sourced, what relays actually do with it, and whether the requirement can be reframed away.

---

## Part A — What the protocol actually requires (primary sources)

### `created_at` is a signed integer

NIP-01 defines the field as `"created_at": <unix timestamp in seconds>`, and the event `id` is the `sha256` of the serialized array:

```
[0, <pubkey hex>, <created_at, as a number>, <kind>, <tags>, <content>]
```

`created_at` is serialized **as a number**, the `id` is the sha256 of that array, and `sig` signs the same sha256 that is the `id`. So `created_at` is immutable once signed — any value chosen in-ROM is baked into a valid, verifiable id/signature.
Source: NIP-01 — https://github.com/nostr-protocol/nips/blob/master/01.md

**Consequence:** at the cryptographic layer, *any* integer is legal. There is no such thing as an "invalid" `created_at` for signing purposes — a fixed constant, `0`, or a build epoch all produce a perfectly valid signed event. The entire constraint lives downstream, at relays (Part C).

### The protocol mandates NO bounds

Nothing in NIP-01 constrains the range of `created_at`.
Source: NIP-01 (as above).

### NIP-22 "Event created_at Limits" was DELETED

There was once a NIP-22 titled "Event created_at Limits." It was **removed from the spec** in PR #897 ("delete NIP-22 … because it is useless and no one cares about it"), merged 2023-12-01. **NIP-22 today is a different, unrelated spec ("Comment").**
Sources:
- Deletion PR (merged): https://github.com/nostr-protocol/nips/pull/897
- Current NIP-22 ("Comment"): https://github.com/nostr-protocol/nips/blob/master/22.md

When it existed, it was **optional (SHOULD, not MUST)**: relays *may* define upper/lower limits and *should* return an `OK: false` when an event falls outside them (historical text mirror: https://nostr-nips.com/nip-22). **Net: no active NIP mandates any timestamp window today.** Enforcement is now purely per-relay config.

### NIP-11 advertises per-relay windows

NIP-11 (relay information document) defines two **optional** metadata fields in the `limitation` object: `created_at_lower_limit` and `created_at_upper_limit`. They advertise the relay's accepted timestamp window (informational; not a mandate on authors).
Source: NIP-11 — https://github.com/nostr-protocol/nips/blob/master/11.md

---

## Part B — In-ROM timestamp option landscape

All options below produce a spec-legal signed event (Part A). They differ in whether real relays accept them (Part C) and in second-order effects (ordering, Part D). Grounding for the SM64/N64 primitives is from this repo.

| # | Option | In-ROM source | Real-time? | Relay-acceptance risk | Notes |
|---|--------|---------------|-----------|-----------------------|-------|
| 1 | **Fixed constant / ROM build epoch** | A `#define` baked at build time (e.g. the build's real wall-clock date) | Approximate at build; frozen forever | **Low if build date is recent-era**; every ROM emits the same date | Simplest. Value drifts from "now" as the ROM ages, but stays inside multi-year past windows for a long time. |
| 2 | **Degenerate constant (`0` / epoch 1970)** | `#define CREATED_AT 0` | No | **High** — far-past; dropped by strfry default (~3yr past) and any `created_at_lower_limit` | Spec-legal but practically rejected by common defaults. |
| 3 | **In-game frame / timer counter** | `gGlobalTimer` (u32, starts at 0, `++` per frame — `src/game/game_init.c:62,342,382`) or `osGetTime()` (VR4300 count register, **cycles since console boot**, not wall clock — `include/PR/os.h`, `include/PR/os_time.h`) | No | Value is tiny (seconds/frames since boot ≈ near-1970 when treated as unix seconds) → **far-past, high rejection risk** unless offset | Monotonic *within a session*, resets every boot. Cannot represent an absolute date. Could be added to a build-epoch base (option 1 + 3). |
| 4 | **Controller-derived** | Player input timing/entropy from the pad | No | Same as #3 — no absolute reference | Gives entropy/variation, not a real date. Useful for a nonce, not a timestamp. |
| 5 | **Derive from save data** | Save file (`src/game/save_file.c/.h`) — star counts, coin-score ages, playtime-like counters | No | No wall-clock anchor in the save format → far-past | Save data has no RTC-backed date either; only relative counters. Same absolute-time problem as #3. |
| 6 | **Build epoch + session monotonic (hybrid)** | Build-time constant base (#1) plus per-session `gGlobalTimer/`frames as a within-run tiebreaker | Base is real-ish; increments are fake seconds | Low, if base is recent | Keeps events inside relay windows *and* gives distinct, monotonically increasing values within a play session (helps Part D ordering). Best of the practical set. |

**Key hardware fact (verified in-repo):** there is no wall-clock source on the N64. `osGetTime()` returns time since *boot*, not since epoch (`include/PR/os.h` `OS_CYCLES_TO_*` macros operate on the CPU count register). `gGlobalTimer` is a frame counter initialized to `0`. So every "live" source (#3–#5) yields a value with **no absolute anchor** — it can only ever be turned into a real date by adding a build-time constant.

---

## Part C — What real relays enforce (verified defaults)

No NIP mandates a window (Part A), so acceptance is per-relay config. Verified defaults from relay source/config:

**strfry** (config: https://github.com/hoytech/strfry/blob/master/strfry.conf):
- `rejectEventsNewerThanSeconds = 900` → rejects events **more than 15 min in the future**.
- `rejectEventsOlderThanSeconds = 94608000` → rejects events **more than ~3 years (1095 days) in the past**.
- `rejectEphemeralEventsOlderThanSeconds = 60`.

**nostr-rs-relay** (config: https://github.com/scsibug/nostr-rs-relay/blob/master/config.toml):
- `reject_future_seconds` — sample config uses `1800` (30 min future), but the **built-in default allows any future date**, and there is **no past-limit option at all**. So a far-past constant is accepted by default here.

**Not verified:** exact live windows for `relay.damus.io` and `nostr.wine` — no authoritative published config located. Treat their specific values as unknown.

**Practical read:**
- A **recent-era** value (build epoch, option 1/6) passes both relays comfortably.
- A **far-past** value (`0`, or raw frame/boot counters, options 2/3/5) is **rejected by strfry's ~3yr past window and by any relay advertising `created_at_lower_limit`**, though accepted by default nostr-rs-relay. Not portable.
- A **far-future** value (>15 min on strfry, >configured `reject_future_seconds` on rs-relay) is rejected.

---

## Part D — Second-order effect: ordering & replaceable events

NIP-01: for replaceable events, relays SHOULD keep the one with the **greatest `created_at`**, and "in case of replaceable events with the same timestamp, the event with the lowest id (first in lexical order) should be retained, and the other discarded."
Source: NIP-01 — https://github.com/nostr-protocol/nips/blob/master/01.md

**Hazard of a fixed constant:** if the ROM emits replaceable events (same kind, same pubkey) all sharing one constant `created_at`, they can never supersede each other by time — resolution collapses to the **lowest-id lexical tiebreak**, so a genuinely-later event with a numerically higher id would be *discarded, never winning*. This only bites if the leaderboard uses replaceable kinds; per map #4 the QR events are ephemeral one-shots, so this may be moot — but it argues for option 6 (a within-session monotonic increment) if any replaceable/latest-wins semantics are ever wanted.

---

## Part E — Ackoff lens: solve / resolve / dissolve

- **Solve (optimal):** find the "correct" real time on-console. **Impossible** — no RTC, no wall-clock source exists (Part B, verified). There is nothing to optimize.
- **Resolve (good-enough):** pick a value that clears real relay windows. Practically = **option 1 or 6: a build-time recent-era epoch**, optionally plus a session-monotonic increment. Clears strfry's past/future windows and any `created_at_lower_limit`; degrades gracefully as the ROM ages (a build-epoch stays inside a multi-year past window for years). This is the low-risk landing spot if the requirement stands.
- **Dissolve (reframe away):** **Can the timestamp requirement be removed from the problem?** Largely, yes — and this is the strongest reframe:
  - The game's signed event is **immutable**; its `created_at` is baked in at signing and cannot be corrected later without breaking the id/sig. So the in-ROM value can *never* be a trustworthy wall-clock time regardless of how it's sourced — chasing accuracy on-console is a category error.
  - The out-of-scope **companion app (B)** (map #4) scans the QR and emits a **second, associating Nostr event** on a real device that *does* have real time. That associating event carries an honest wall-clock `created_at`, so **the real timestamp lives in the companion event, not the game event.**
  - This does **not** break the game event's immutability: the game event keeps whatever fixed `created_at` it was signed with; the companion event is a separate signed object that references it. The leaderboard (C) can order by the companion event's real time.
  - **Net dissolve:** the game event's `created_at` is demoted from "must be real time" to "must merely be a fixed integer that clears relay windows." That reduces the whole problem to option 1/6 (a recent-era build constant) with **no accuracy requirement at all** — the accuracy concern is relocated to a component (B) that can actually satisfy it.
  - **Residual (not dissolved):** the game event must still exist on relays to be associated, so its constant must still clear relay windows (Part C) — i.e. avoid the `0`/far-past trap. The build-epoch constant handles this. The immutability tradeoff is explicit and acceptable: the game event self-attests *provenance*, not *time*; time is attested by the companion event.

---

## Bottom line

1. Any integer `created_at` is spec-legal and signable; the N64 has no wall-clock source, so no in-ROM value can be genuinely real (verified in-repo).
2. No active NIP mandates timestamp windows (old NIP-22 deleted 2023); enforcement is per-relay config. Verified defaults: strfry rejects `>15min` future and `>~3yr` past; nostr-rs-relay has no past bound by default.
3. A far-past/degenerate constant (`0`, raw counters) is spec-legal but **rejected by common relay defaults** — avoid.
4. Practical resolve: a **build-time recent-era epoch constant** (optionally + session-monotonic increment) clears real windows and ages gracefully.
5. Ackoff dissolve: the **companion app's associating event carries the real timestamp**; the game event's `created_at` need only be a window-clearing constant. Immutability is preserved (two separate signed events; game event attests provenance, companion attests time).

## Sources
- NIP-01: https://github.com/nostr-protocol/nips/blob/master/01.md
- NIP-11: https://github.com/nostr-protocol/nips/blob/master/11.md
- NIP-22 deletion PR #897 (merged 2023-12-01): https://github.com/nostr-protocol/nips/pull/897
- NIP-22 today ("Comment"): https://github.com/nostr-protocol/nips/blob/master/22.md
- Historical NIP-22 text mirror: https://nostr-nips.com/nip-22
- strfry config: https://github.com/hoytech/strfry/blob/master/strfry.conf
- nostr-rs-relay config: https://github.com/scsibug/nostr-rs-relay/blob/master/config.toml
- In-repo: `src/game/game_init.c` (`gGlobalTimer`), `include/PR/os.h` + `include/PR/os_time.h` (`osGetTime` = cycles since boot), `src/game/save_file.c/.h`
- *Unverified:* exact live `created_at` windows for `relay.damus.io` and `nostr.wine`.

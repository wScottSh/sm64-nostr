# Format v3: honest in-course timing, legible star identity, signed event-name tag

Format **v3** (`FORMAT_TAG 0x02 → 0x03`) is a **content** revision of the packed
payload and the signed NIP-01 event, **superseding ADR-0002**. It is not a
capacity or encoding revision: ADR-0006's adaptive multi-frame transport removed
the single-frame byte ceiling that drove every v2 field-sizing decision, so v3 is
chosen for *what the event honestly says*, not for how few bytes it costs. Byte
count, QR encoding mode, ECC, mask, and fragment geometry are unchanged and out of
scope here (per-frame geometry stays v7-MEDIUM per ADR-0002/0006); this ADR governs
only the event's content and the cabinet-side computation behind it.

Everything here concerns the **left side of the airgap** — what the cabinet
computes, signs, and emits. The far side is untouched and out of scope.

## What v3 changes from v2

### 1. `frames` becomes in-course elapsed time, not since-boot

v2 packed `gGlobalTimer` verbatim — the console's monotonic since-power-on frame
counter (`src/game/game_init.c:63`, 30 fps, never reset on level load). That number
is meaningless as a leaderboard metric: it measures time since the cabinet was
switched on, not time to earn the star.

v3 redefines `frames` as **elapsed frames from course start to star grab**:
`frames = gGlobalTimer_at_grab − courseStartFrame`, where `courseStartFrame` is a
new cabinet-side snapshot taken when Mario gains control on course entry. Because
`gGlobalTimer` is monotonic and never resets, the subtraction is always well-defined.
The counter is **pause-inclusive** (it ticks during pause/menus); pausing can only
inflate a player's own time, never shorten it, so it is not a cheat and the simpler
single-snapshot design is kept.

`frames` is only meaningful for a star grabbed **inside a level**
(`gCurrCourseNum != COURSE_NONE` — all 15 main courses and every secret/bonus course,
including the time-based slide PSS), **plus MIPS** (the castle-basement rabbit),
which is timed from **entry to his room** rather than from a course start. Every
other castle-grounds grab (Toad stars, etc.) has no course start to measure from and
carries the sentinel **`frames = 0`** — an impossible real value (a grab always costs
more than zero frames), so it is an unambiguous "no in-course time" marker.

The precise snapshot hooks and the MIPS special case are specified in
`docs/format-v3-spec.md`.

### 2. Star identity stays legible — `star_coord` is rejected

The capacity work (#103) proposed packing course + act + star index into a single
`star_coord` byte (`(course<<3)|starIndex`). That existed **solely** to save bytes.
With capacity no longer a constraint, its rationale is gone, and it costs legibility
and independent queryability for nothing. v3 keeps the three fields **separate and
legible**: `course`, `act`, `keyId` (the star index). `star_coord` is not adopted.

### 3. The event name becomes a signed, filterable tag

v2's `PIPELINE_EVENT_NAME` (spec #75/#76) was **display-only**: baked into the castle
HUD corner and, per `tools/gen_event_profile.py`, *"never packed onto the wire, never
enters the NIP-01 event."* v3 **promotes it to a signed, filterable indexed tag**
`["n","<event name>"]`, realizing #94. It rides the wire (so the generic far side can
reconstruct the exact signed serialization) and remains the HUD display name. NIP-01
only indexes single-letter tag keys, so `n` is chosen for filterability. The existing
class markers stay: v3 tags are
`[["t","cabinet-leaderboard"],["t","sm64"],["n","<event name>"]]`.

### 4. `created_at` is the frozen build epoch — and that is the honest value

An airgapped N64 has no RTC and no network clock; it cannot know when a star was
grabbed. v3 therefore keeps `created_at` as the **frozen build epoch** baked at ROM
build time (`PIPELINE_EVENT_CREATED_AT`). This is deliberately *not* the capture time
and does not pretend to be: fabricating a live-advancing clock (e.g. build-epoch +
seconds-since-boot) would inject a value that lies about when the run happened, and
the real competitive timing already lives in `frames` (§1). `created_at` honestly
means "when this build was signed." Relay staleness windows (NIP-01's "creation date
too far off" rejection) are a **deploy-side** concern the cabinet cannot resolve
airgapped, not a wire-format decision.

### 5. `FORMAT_TAG` bumps `0x02 → 0x03`

The signed serialization and the field semantics differ from v2, so the in-band
version discriminator advances. A decoder MUST reject unknown tags rather than guess.

## What does not change

- **The zero-far-side-reconstruction invariant (ADR-0005/0006) holds verbatim.** The
  far side losslessly decodes packed bytes into canonical JSON and recomputes `id`
  (SHA-256) — inventing, baking, or defaulting no signed value. Per-build values
  (pubkey, `created_at`, the per-game tag, and now the event name) ride the wire;
  only genuine published-standard universal constants (`kind` 8064, the
  `["t","cabinet-leaderboard"]` class marker) are baked identically on both sides.
- **One npub per build.** The keypair is baked at build time; a build *is* a Nostr
  identity. (Not "per cabinet" — per build.)
- **The nonce.** A 16-bit hash of layered capture entropy
  (`created_at` + `gGlobalTimer` + `osGetCount()` + raw stick X/Y + buttons), unchanged.
  Its only job is to keep two byte-identical runs from collapsing to one `id`; the
  layered entropy makes a full collision (same star/act/coins/`frames` *and* nonce)
  negligible, so its width is not a lever.
- **kind** 8064 (baked), and **per-frame QR geometry** (v7-MEDIUM, fixed mask).

## Considered and rejected

- **`star_coord` single-byte star identity** — rejected: pure byte-thrift, now
  worthless, costs legibility. (§2)
- **A live-advancing `created_at`** (build epoch + seconds-since-boot) — rejected as
  dishonest: it would assert a capture time the cabinet cannot know. (§4)
- **Keeping `frames = gGlobalTimer`** — rejected: since-boot time is not a
  leaderboard metric. (§1)

## Consequences

- The cabinet gains one new piece of glue: a `courseStartFrame` snapshot on course
  entry (and a guarded MIPS-room-entry snapshot), plus a small change at the star-grab
  hook to emit the delta (or the `0` sentinel). Specified in `docs/format-v3-spec.md`.
- `PIPELINE_EVENT_NAME` now enters the signed event and the wire; its validation
  (charset A-Z/0-9/space, ≤15 chars) already exists and is unchanged, but its
  "never reaches the wire" contract in `gen_event_profile.py` is retired by v3.
  (The ≤15 cap itself is later raised to ≤20 by spec #91, sub-issue #126; see
  `docs/format-v3-spec.md` for the current figure -- this ADR's numbers are a
  point-in-time historical record, not re-edited here.)
- The signed content shape and the packed-wire layout both change, so
  `src/pipeline/event_id.c` (serialization), `src/pipeline/format_descriptor.json`
  (+ its generator and pack/unpack), and the capture glue all move together to v3 in
  the follow-on build effort. This ADR + `docs/format-v3-spec.md` are that effort's
  input; no code changes here.
- A decoder that sees `FORMAT_TAG 0x02` and `0x03` must treat them as distinct
  layouts; v2 and v3 events are not interchangeable.

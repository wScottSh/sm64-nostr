# Format v3 wire + timing spec (build-handoff)

Precise, build-ready specification of packed-payload format **v3** and the
cabinet-side computation behind it. Decision rationale is in
`docs/adr/0007-format-v3-honest-in-course-timing-legible-star-signed-name-tag.md`
(supersedes ADR-0002). This document is the input to the v3 **build effort**; it
prescribes changes but makes none. Left-side-of-airgap only.

Citations are `file:line` against the tree at authoring time; re-verify before
editing.

## 1. The signed NIP-01 event

Canonical serialization (NIP-01), the exact 6-element array the cabinet hashes for
`id` and the far side reproduces verbatim:

```
[0, <pubkey-hex>, <created_at>, 8064, <tags>, <content>]
```

- **kind** = `8064` — baked published constant, off-wire.
- **created_at** = `PIPELINE_EVENT_CREATED_AT`, the frozen build epoch (off-wire,
  known to the far side via the wire? No — see §2: it is packed). Honestly = build
  signing time, not capture time (ADR-0007 §4).
- **tags** = `[["t","cabinet-leaderboard"],["t","sm64"],["n","<EVENT NAME>"]]`
  - `["t","cabinet-leaderboard"]` — cross-game class marker, baked, off-wire.
  - `["t","sm64"]` — per-game tag (`gen_event_profile.py --tag`, default `sm64`),
    on-wire (as v2's `TAG`).
  - `["n","<EVENT NAME>"]` — **new in v3**: the promoted `PIPELINE_EVENT_NAME`
    (charset A-Z/0-9/space, ≤20 chars as of spec #91 sub-issue #126, raised
    from ≤15; `gen_event_profile.py` normalization otherwise unchanged).
    Signed and on-wire; filterable (single-letter key `n`). Retires the
    "never reaches the wire" contract at `tools/gen_event_profile.py:42-51,82-83`.
- **content** = the run facts, fixed key order (legible star identity kept):

  ```
  {"course":<u8>,"act":<u8>,"coins":<u8>,"frames":<u32>,"nonce":<u16>,"keyId":<u8>}
  ```

  Same shape as v2 (`src/pipeline/event_id.c` `pipeline_event_build_content`); the
  only change is the **meaning of `frames`** (§3). `star_coord` is **not** adopted.

## 2. Packed wire payload (fields)

Byte widths are unchanged from v2 (capacity is no longer a constraint; there is no
reason to churn them). The wire carries every per-build / per-run value the generic
far side needs to rebuild §1 with zero reconstruction:

| field | width | notes vs v2 |
|---|---|---|
| `FORMAT_TAG` | 1 | **`0x03`** (was `0x02`) |
| `COURSE` | 1 | unchanged (legible; `star_coord` rejected) |
| `ACT` | 1 | unchanged |
| `COINS` | 1 | unchanged |
| `FRAMES` | 4 | **semantics changed** → in-course elapsed (§3); width u32 unchanged |
| `NONCE16` | 2 | unchanged |
| `KEY_ID` | 1 | unchanged (star index) |
| `CREATED_AT` | 4 | unchanged (frozen build epoch) |
| `PUBKEY` | 32 | unchanged (x-only) |
| `TAG_LEN` + `TAG` | 1 + var | the per-game `["t","sm64"]` value, unchanged |
| `NAME_LEN` + `NAME` | 1 + var | **new**: the `["n",…]` event-name value, on-wire |
| `SIG` | 64 | unchanged |

`format_descriptor.json` (and its generator + `pack_adapter`/unpack) gain
`FORMAT_TAG=3`, the `NAME_LEN`/`NAME` length-prefixed pair (mirroring `TAG_LEN`/`TAG`,
placed before `SIG`), and no other field changes. `star_coord` is not introduced.

> Note on `CREATED_AT` above: it is packed on the wire (as in v2) so the generic far
> side can reconstruct — it is a per-build value, not a universal constant.

## 3. In-course frame timer (the one behavioral change)

### 3.1 State

Add one global, e.g. `static u32 sCourseStartFrame;` alongside the level-update
timer state (`src/game/level_update.c:164-171`).

### 3.2 Snapshot on course entry

At the moment Mario gains control on course/level entry, set
`sCourseStartFrame = gGlobalTimer`. `init_level()` (`src/game/level_update.c:1156`)
is the single choke point for whole-level entry (it already resets `sTimerRunning`
at :1165); the control-gain moment is the `set_mario_action(gMarioState, ACT_IDLE, …)`
at `:1183/:1190`. Snapshot there (control-gain) per ADR-0007 §1.

`gGlobalTimer` is monotonic and never resets (`src/game/game_init.c:63,343,394`), so
`sCourseStartFrame` is simply the frame index at entry. Intra-course area changes go
through `warp_area()`/`change_area()` and do **not** re-run `init_level`
(`level_update.c:462-473,530-566`) — correct: a multi-area course keeps timing from
course entry, not per-area.

### 3.3 MIPS special case — snapshot on basement-room entry

MIPS grabs are course-less (`gCurrCourseNum == COURSE_NONE`) but must be timed from
**entering his room**, which `init_level` does *not* capture (basement entry is an
intra-castle area change). Add a **guarded** snapshot: when an area change makes the
current area `LEVEL_CASTLE` **area 3** (the basement, `levels/castle_inside/script.c:290`),
set `sCourseStartFrame = gGlobalTimer`. Hook the area-change path
(`load_area()`/`change_area()`, `level_update.c:463-468,557`), testing
`gCurrLevelNum == LEVEL_CASTLE && <new area index> == 3`.

The guard is essential: this snapshot must fire **only** for castle area 3, never for
general area transitions (which would wrongly reset an in-course timer mid-run).

### 3.4 Emit at the grab hook

At the star-grab capture site (`src/game/interaction.c:930`, the
`pipeline_capture_build(...)` call whose 4th arg is currently `gGlobalTimer`),
replace that `frames` argument with:

```
if (gCurrCourseNum != COURSE_NONE) {
    frames = gGlobalTimer - sCourseStartFrame;              // any real course (main + secret/bonus, incl. PSS)
} else if (starIndex == 3 || starIndex == 4) {              // MIPS stars 1 & 2 (Toad stars are 0-2)
    frames = gGlobalTimer - sCourseStartFrame;              // basement-entry snapshot from §3.3
} else {
    frames = 0;                                             // sentinel: no in-course time
}
```

`starIndex` is already computed at `interaction.c:867`
(`(o->oBhvParams >> 24) & 0x1F`). The MIPS test is valid only under
`gCurrCourseNum == COURSE_NONE` (starIndex is course-relative). MIPS star indices
3/4 come from `bhv_spawn_star_no_level_exit(STAR_INDEX_ACT_4 + bp)`
(`src/game/behaviors/mips.inc.c:192-196`, `sparkle_spawn_star.inc.c:128-133`);
constants `STAR_INDEX_ACT_4=3`, `STAR_INDEX_ACT_5=4` (`include/object_constants.h:128-129`).

The 7th `pipeline_capture_build` arg (`gGlobalTimer` as nonce entropy) is unchanged —
the nonce still hashes the raw since-boot counter, independent of the `frames` value.

### 3.5 Sentinel

`frames == 0` means "no in-course time." A legitimate grab always costs > 0 frames
(control-gain precedes the grab), so `0` never collides with a real time.

## 4. Out of scope

Far side / decoder, QR encoding mode / ECC / mask / fragment header, transport
frame count — all unchanged and untouched (ADR-0002 geometry, ADR-0006 transport).
This spec changes event content and the cabinet timer only.

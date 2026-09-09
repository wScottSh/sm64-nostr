# Star-count gates: complete enumeration

**Purpose.** Authoritative list of every site in the decomp whose availability/behavior is
gated on the player's **total star count** (not per-course flags). Backs the sandbox build where
total star count is pinned at 0. For each site: threshold, what it gates, ACCESS GATE vs.
REWARD/COSMETIC, and whether it already routes through the fork's `save_file_star_gate_is_open()`
sandbox seam (seam B) or bypasses it with a raw comparison.

All repo citations are the live `src\` tree only (`.claude\` worktrees ignored).

**Bottom line.** Ten distinct sites read the total star count. Four ACCESS GATES already route
through seam B and are open at 0 stars (star doors, endless-staircase warp, MIPS, message
Toads). **Two ACCESS GATES bypass seam B and are still closed at 0 stars — they need fixing:**
the **castle-grounds cannon grate** (`castle_cannon_grate.inc.c:4`, raw `>= 120`) and the
**look-up warp** to Wing Mario Over the Rainbow (`mario_actions_stationary.c:1070`, raw `>= 10`).
The remaining four are REWARD/COSMETIC (Yoshi, fat penguin, staircase music, milestone dialog);
they stay dormant at 0 stars, which is correct sandbox behavior and needs no change.

---

## The seam

`save_file_star_gate_is_open(numStars, requiredStars)` — `src\game\save_file.c:509-511` — returns
`TRUE` unconditionally in the sandbox, so any comparison routed through it passes at 0 stars.
Header `src\game\save_file.h:163`. Doc comment (`save_file.c:502-508`) names its four substituted
sites: star-count doors, castle endless-staircase instant-warp gate, MIPS activation, and the
message-Toad checks. It does **not** touch `save_file_get_total_star_count()`, which keeps feeding
the HUD/level-select honestly (`save_file.c:469`).

The raw source of the count everywhere is
`save_file_get_total_star_count(gCurrSaveFileNum - 1, COURSE_MIN - 1, COURSE_MAX - 1)`
(`src\game\save_file.c:469`). `gMarioState->numStars` is a cached copy of that total, refreshed on
level init (`src\game\mario.c:1882-1883`) and on every star grab (`src\game\interaction.c:976-977`);
in the sandbox, with recording gated off (seam F, `interaction.c:970-974`) and the total pinned at
0, `numStars` stays 0.

---

## ACCESS GATES

### 1. Star-count doors — routed through seam B ✅
`interact_door`, `src\game\interaction.c:1161-1226`. Required count is per-object
(`o->oBhvParams >> 24`); the canonical door thresholds are **1, 3, 8, 30, 50, 70** (dialog switch
`interaction.c:1193-1211`; the 8- and 30-star doors are the two Bowser-basement doors, 50 is the
third-floor Big Star Door, 70 is the final door before the endless staircase). The open/blocked
decision is `save_file_star_gate_is_open(numStars, requiredNumStars)` at **`interaction.c:1166`** →
passes at 0 stars. If closed it instead shows the "you need N more stars" dialog (`:1190-1217`).
Gates: physical passage through every star door.
Cross-check: door/Bowser-door thresholds and the 70-star final door match canonical SM64.
[Big Star Door — MarioWiki](https://www.mariowiki.com/Big_Star_Door),
[Bowser in the Sky — StrategyWiki](https://strategywiki.org/wiki/Super_Mario_64/Bowser_in_the_Sky)

### 2. Endless-staircase warp — routed through seam B ✅
`check_instant_warp`, `src\game\level_update.c:530-538`. In LEVEL_CASTLE, if
`save_file_star_gate_is_open(total, 70)` is true the function **returns early** (skips the
instant-warp that otherwise teleports Mario back down the stairs), so the staircase becomes
climbable. Seam call at **`level_update.c:535`** → passes at 0 stars. Threshold **70**.
Gates: physical ascent of the endless staircase to Bowser in the Sky.
Cross-check: 70-star endless-stairs threshold is canonical.
[Endless stairs — MarioWiki](https://www.mariowiki.com/Endless_stairs)

### 3. MIPS (15 / 50) — routed through seam B ✅
`bhv_mips_init`, `src\game\behaviors\mips.inc.c:10-34`. MIPS spawns holding a grabbable star; if
neither branch qualifies he is deactivated (`:33`). Both branches use the seam:
`save_file_star_gate_is_open(total, 15)` at **`mips.inc.c:15-16`** and
`save_file_star_gate_is_open(total, 50)` at **`mips.inc.c:24-25`** (each also `&&` a per-course
"not yet collected this MIPS star" flag). Thresholds **15** and **50** → both pass at 0 stars
(the 15-star branch wins, so MIPS is catchable with his first star).
Classified ACCESS GATE: gates whether the MIPS star is reachable at all.
Cross-check: MIPS appears at 15 stars, returns at 50.
[MIPS — GamerGuides](https://www.gamerguides.com/super-mario-3d-all-stars/guide/super-mario-64/the-castle-s-secret-stars/mips-the-yellow-rabbit)

### 4. Message Toads (12 / 25 / 35) — routed through seam B ✅
`bhv_toad_message_init`, `src\game\mario_misc.c:182-217`. Each castle Toad gives a star; if the
count check fails the Toad object is deleted (`obj_mark_for_deletion`, `:215`). Thresholds are
`TOAD_STAR_1_REQUIREMENT 12`, `TOAD_STAR_2_REQUIREMENT 25`, `TOAD_STAR_3_REQUIREMENT 35`
(`mario_misc.c:28-30`), each evaluated via `save_file_star_gate_is_open(starCount, ...)` at
**`mario_misc.c:190, 196, 202`** → all pass at 0 stars.
Classified ACCESS GATE: gates whether each Toad (and its star) exists.

### 5. Castle-grounds cannon grate (120) — BYPASSES seam B ❌ NEEDS FIXING
`bhv_castle_cannon_grate_init`, `src\game\behaviors\castle_cannon_grate.inc.c:3-7`:
```c
if (save_file_get_total_star_count(...) >= 120) {
    o->activeFlags = ACTIVE_FLAG_DEACTIVATED;   // remove the grate -> cannon usable
}
```
Raw `>= 120` comparison at **`castle_cannon_grate.inc.c:4`** — does **not** use the seam. The grate
is an *inverted* gate: it is present (blocking the castle-grounds cannon that fires Mario onto the
castle roof) until 120 stars deactivate it. At 0 stars the condition is false, so **the grate stays
in place and the roof cannon is unreachable.** This is a genuine ACCESS GATE that is still closed in
the sandbox. Fix: route through the seam, e.g. `if (save_file_star_gate_is_open(total, 120)) { ...
deactivate ... }`, so the grate is removed at 0 stars.
Cross-check: the castle-grounds grate opens at 120 stars, exposing the cannon to the roof (Yoshi).
[The Castle — Ukikipedia](https://ukikipedia.net/wiki/The_Castle),
[Super Mario 64/Secrets — StrategyWiki](https://strategywiki.org/wiki/Super_Mario_64/Secrets)

### 6. Look-up warp / Wing Mario Over the Rainbow (10) — BYPASSES seam B ❌ NEEDS FIXING
`act_first_person`, `src\game\mario_actions_stationary.c:1069-1076`:
```c
if (m->floor->type == SURFACE_LOOK_UP_WARP
    && save_file_get_total_star_count(...) >= 10) {
    ... level_trigger_warp(m, WARP_OP_UNKNOWN_01);   // warp up to the rainbow
}
```
Raw `>= 10` comparison at **`mario_actions_stationary.c:1070`** — does **not** use the seam.
Standing on the `SURFACE_LOOK_UP_WARP` tile (castle lobby) and looking straight up triggers the warp
to Wing Mario Over the Rainbow, but only at ≥10 stars. At 0 stars **the warp never fires**, so that
secret area is unreachable via this route. Genuine ACCESS GATE, still closed in the sandbox. Fix:
route through the seam, e.g. `&& save_file_star_gate_is_open(total, 10)`.

---

## REWARD / COSMETIC (dormant at 0 stars — no fix needed)

### 7. Yoshi on the roof (120) — BYPASSES seam B (reward)
`bhv_yoshi_init`, `src\game\behaviors\yoshi.inc.c:8-18`. Raw `total < 120` (or `sYoshiDead`)
deactivates Yoshi (**`yoshi.inc.c:14-16`**). Yoshi is the 120-star reward NPC (100 lives + flavor);
he blocks nothing. Reaching him already depends on the cannon grate (site 5), so his own gate is
downstream cosmetic. At 0 stars he stays deactivated — acceptable sandbox behavior.

### 8. Fat penguin race variant (120) — BYPASSES seam B (cosmetic)
`bhv_racing_penguin_init`, `src\game\behaviors\racing_penguin.inc.c:14-20`. Raw
`gMarioState->numStars == 120` at **`racing_penguin.inc.c:15`** swaps the Cool-Cool-Mountain
slide-race penguin to the larger "fat" model/hitbox variant. Same race either way; purely the
opponent's appearance/size. At 0 stars → thin variant. Cosmetic.

### 9. Endless-staircase music (< 70) — BYPASSES seam B (cosmetic)
`play_infinite_stairs_music`, `src\game\sound_init.c:202-217`. Raw
`gMarioState->numStars < 70` at **`sound_init.c:206`** decides whether the "endless stairs" music
sting plays while on the staircase. Flavor tied to the site-2 warp; does not gate movement. At 0
stars the music plays — harmless.

### 10. Star-collection milestone dialog (1/3/8/30/50/70) — raw (cosmetic)
`get_star_collection_dialog`, `src\game\mario_actions_cutscene.c:232-247`, over
`sStarsNeededForDialog[] = {1, 3, 8, 30, 50, 70}` (`mario_actions_cutscene.c:51`). On a star grab,
if `prevNumStarsForDialog < threshold <= numStars`, shows a congratulatory dialog
(`DIALOG_141`+). Congratulation text only; gates nothing. In the sandbox (`numStars` pinned 0) it
never fires.

---

## Summary table

| # | Site (file:line) | Threshold / cmp | Gates what | GATE vs REWARD | Seam B? | Needs fix for sandbox? |
|---|---|---|---|---|---|---|
| 1 | `interaction.c:1166` (`interact_door`) | 1/3/8/30/50/70 via seam | passage through star doors | **ACCESS GATE** | ✅ yes | no (open) |
| 2 | `level_update.c:535` (`check_instant_warp`) | `≥70` via seam | climbing endless staircase | **ACCESS GATE** | ✅ yes | no (open) |
| 3 | `mips.inc.c:15,24` (`bhv_mips_init`) | `≥15` / `≥50` via seam | MIPS star reachable | **ACCESS GATE** | ✅ yes | no (open) |
| 4 | `mario_misc.c:190,196,202` (`bhv_toad_message_init`) | `≥12/25/35` via seam | message-Toad stars exist | **ACCESS GATE** | ✅ yes | no (open) |
| 5 | `castle_cannon_grate.inc.c:4` | raw `≥120` | opens grounds cannon to roof | **ACCESS GATE** | ❌ no | **YES** |
| 6 | `mario_actions_stationary.c:1070` (`act_first_person`) | raw `≥10` | warp to Wing Mario/Rainbow | **ACCESS GATE** | ❌ no | **YES** |
| 7 | `yoshi.inc.c:14` (`bhv_yoshi_init`) | raw `<120` | Yoshi roof reward NPC | REWARD | ❌ no | no (dormant OK) |
| 8 | `racing_penguin.inc.c:15` | raw `==120` | fat penguin variant | COSMETIC | ❌ no | no |
| 9 | `sound_init.c:206` | raw `<70` | endless-stairs music | COSMETIC | ❌ no | no |
| 10 | `mario_actions_cutscene.c:239` | 1/3/8/30/50/70 | milestone congrats dialog | COSMETIC | ❌ no | no |

## Sources

- Repo `src\` tree (authoritative for this fork), cited inline by file:line.
- [Big Star Door — Super Mario Wiki](https://www.mariowiki.com/Big_Star_Door)
- [Bowser in the Sky — StrategyWiki](https://strategywiki.org/wiki/Super_Mario_64/Bowser_in_the_Sky)
- [Endless stairs — Super Mario Wiki](https://www.mariowiki.com/Endless_stairs)
- [MIPS the Yellow Rabbit — GamerGuides](https://www.gamerguides.com/super-mario-3d-all-stars/guide/super-mario-64/the-castle-s-secret-stars/mips-the-yellow-rabbit)
- [The Castle — Ukikipedia](https://ukikipedia.net/wiki/The_Castle)
- [Super Mario 64/Secrets — StrategyWiki](https://strategywiki.org/wiki/Super_Mario_64/Secrets)
- Canonical upstream decomp cross-reference: [n64decomp/sm64](https://github.com/n64decomp/sm64) — the fork's gate sites and thresholds match upstream; the only divergence is the fork's insertion of the `save_file_star_gate_is_open()` seam at sites 1–4.

# Star persistence vs. collectability

**Verdict: NO.** Skipping `save_file_collect_star_or_key()` (and never writing the per-course
star bit) does **not** block any star from spawning, appearing, or being grabbed. Every star
stays fully collectable on every attempt. The recorded star bit is read in exactly one place
that touches a star object — and there it only swaps the graphics **model** (opaque vs.
transparent), never the hitbox, never the interaction gate. I found **no** case where an
un-recorded star becomes un-grabbable; the risk is the opposite direction (a *recorded* star
renders transparent), which never happens if we skip the write.

All citations are the live `src\` tree only (worktrees ignored).

---

## Q1 — Star object spawn logic: does an un-recorded star ever spawn un-grabbable?

No. The star bitfield (`save_file_get_star_flags`) is read by star behaviors only to pick the
**model**; the collision hitbox and the interaction type are set unconditionally.

**`bhvStarSpawnCoordinates` init** — `src\game\behaviors\spawn_star.inc.c:15-26`:
```c
void bhv_collect_star_init(void) {
    s8 starIndex = (o->oBhvParams >> 24) & 0xFF;
    u8 currentLevelStarFlags = save_file_get_star_flags(gCurrSaveFileNum - 1, COURSE_NUM_TO_INDEX(gCurrCourseNum));
    if (currentLevelStarFlags & (1 << starIndex)) {
        o->header.gfx.sharedChild = gLoadedGraphNodes[MODEL_TRANSPARENT_STAR];   // collected -> transparent
    } else {
        o->header.gfx.sharedChild = gLoadedGraphNodes[MODEL_STAR];               // not collected -> solid
    }
    obj_set_hitbox(o, &sCollectStarHitbox);   // <-- hitbox set in BOTH branches, unconditionally
}
```
`sCollectStarHitbox` (line 3) is `INTERACT_STAR_OR_KEY` with radius 80 / height 50. The flag
only chooses solid vs. transparent art; a transparent (already-collected) star is *still*
grabbable. Skipping the write means the flag is always clear, so the star always renders solid —
the strictly-grabbable state.

**`bhvSpawnedStar` init** (the cutscene/red-coin/100-coin/boss stars) —
`src\game\behaviors\sparkle_spawn_star.inc.c:15-30`:
```c
if (bit_shift_left(starIndex)
    & save_file_get_star_flags(gCurrSaveFileNum - 1, COURSE_NUM_TO_INDEX(gCurrCourseNum))) {
    cur_obj_set_model(MODEL_TRANSPARENT_STAR);   // only effect: swap to transparent model
}
```
Again model-only. The hitbox is applied later in `set_sparkle_spawn_star_hitbox()`
(`sparkle_spawn_star.inc.c:32-38`) unconditionally, once the spawn cutscene parks.

**The interaction gate itself** — `interact_star_or_key`,
`src\game\interaction.c:809-993`. The *only* precondition to grabbing is Mario being alive:
```c
if (m->health >= 0x100) {         // interaction.c:831 — the sole gate
    ...
    o->oInteractStatus = INT_STATUS_INTERACTED;   // :863 grab registered
    ...
    starIndex = (o->oBhvParams >> 24) & 0x1F;     // :867
    ...
    save_file_collect_star_or_key(m->numCoins, starIndex);  // :970 — persistence, AFTER the grab
    return set_mario_action(m, starGrabAction, ...);        // :989 star dance
}
```
There is **no** read of `save_file_get_star_flags` / the star bit anywhere in this function. The
persistence call at :970 happens strictly *after* the grab is already committed. Removing it (or
neutering the bit write inside it) cannot affect whether the grab occurs.

## Q2 — 100-coin star: does spawning it depend on coin high-score or prior collection?

No. It is gated purely on the **live, per-attempt** coin counter crossing 100.

`interact_coin`, `src\game\interaction.c:783-792`:
```c
m->numCoins += o->oDamageOrCoinValue;
...
if (COURSE_IS_MAIN_COURSE(gCurrCourseNum)
    && m->numCoins - o->oDamageOrCoinValue < 100 && m->numCoins >= 100) {
    bhv_spawn_star_no_level_exit(STAR_INDEX_100_COINS);
}
```
The condition reads only `m->numCoins` (Mario's in-level coin count) and the course number.
`m->numCoins` is reset to 0 on every course entry (`src\game\level_update.c:1295`), so this is
per-attempt. It does **not** consult `courseCoinScores`, `save_file_get_max_coin_score`, or
whether the 100-coin star was previously collected. Skipping persistence has no effect on it —
the 100-coin star spawns every time you reach 100 coins.

(The spawned object routes through `bhv_spawn_star_no_level_exit` →
`sparkle_spawn_star.inc.c:128-133` → `bhv_spawned_star_init`, whose only flag use is the
model swap covered in Q1; hitbox is unconditional.)

Note: the red-coin star path (`bhv_hidden_red_coin_star_*`, `spawn_star.inc.c:142-178`) is
likewise driven only by the live count of `bhvRedCoin` objects, not by any saved flag.

## Q3 — Side-effect globals written by `save_file_collect_star_or_key`: do any gate spawn/interaction?

The write sets: the star flag; the coin high score (only if higher); and
`gLastCompletedCourseNum` / `gLastCompletedStarNum` (`src\game\save_file.c:364-365`, unconditional
on every call). Readers of those:

- **`gLastCompletedCourseNum` / `gLastCompletedStarNum`** — read only by the star-grab cutscene
  camera (`src\game\camera.c:5079, 5090, 7778-7902`), the course-complete/star HUD name & fanfare
  (`src\game\ingame_menu.c:2767-3281`), and the key-vs-star exit branch in
  `src\game\mario_actions_cutscene.c:1169-1170`. All are camera framing, HUD text, and
  door/key-exit routing — **none** decide whether a star object spawns or whether
  `interact_star_or_key` fires. (Camera/HUD and key progression are explicitly out of scope.)
- **Coin high score** (`save_file_get_max_coin_score`, `courseCoinScores`) — read only in
  `src\game\ingame_menu.c:972` and `src\game\menu\file_select.c:2794-2799` (score display). Never
  by a star spawn or interaction path.
- **`gCurrCourseStarFlags`** (loaded from the star bitfield on course entry,
  `src\game\level_update.c:1297`) — read in exactly one place, the HUD star-flash check
  `src\game\ingame_menu.c:3156`. Not a spawn/interaction gate.
- **Star bitfield** (`save_file_get_star_flags`) readers across `src\`: the two star behaviors
  (Q1, model-only), plus non-collectability consumers — `star_select.c` (star-select menu),
  `file_select.c` (file menu), `ingame_menu.c` (HUD), `skybox.c:307` / `moving_texture.c:650`
  (JRB whirlpool cosmetics), `paintings.c:1112` (DDD painting), `camera.c:9870`, `level_update.c:266`
  (dialog "already-got-it" suppression), and `mips.inc.c` / `snowman.inc.c` / `ukiki_cage.inc.c`
  which use it only to swap those objects' star **model** to transparent, exactly like Q1 (hitbox
  still set). None make a star un-grabbable.

---

## Bottom line

Persistence is downstream of the grab. Star spawn is driven by level scripts, live object
counts, and the live coin counter — never by "was this star recorded." The star bit's only
object-facing effect is opaque-vs-transparent art, and skipping the write keeps every star in the
opaque/solid (grabbable) state permanently. No un-recorded star can become un-grabbable.

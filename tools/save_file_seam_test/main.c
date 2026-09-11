/*
 * Host test tool for sandbox seams E, F & G (spec #80/#90, sub-issues
 * #81, #82 & #138): cannon suppression, star-collection suppression, and
 * lives-consequence suppression.
 *
 * Links the SAME src/game/save_file.c compiled into the ROM, unmodified, a
 * second time into a native host binary -- mirroring tools/pipeline_test's
 * own convention (see its Makefile header comment) of proving a seam is a
 * real, exercised interface rather than a reimplementation. save_file.c's
 * non-seam externs (gCurrCourseNum, gSaveBuffer, osEepromLongRead, etc.) are
 * satisfied by save_file_host_stubs.c, a host-only shim that never enters
 * the ROM's object graph (same reason qr_host_decode.c lives under
 * tools/pipeline_test rather than src/pipeline).
 *
 * Seam E: asserts save_file_is_cannon_unlocked() reports open regardless of
 * the stored per-course cannon bit:
 *   - on a fresh/zeroed save (every byte, including the cannon bit, 0), and
 *   - on a save whose cannon bit is explicitly cleared while other course
 *     star bits are set (proving it isn't open merely because the whole
 *     buffer happens to be zero).
 * Also asserts the seam-E predicate, save_file_cannons_are_forced_open(),
 * itself reports TRUE directly.
 *
 * Seam F: asserts save_file_star_collection_is_recorded() reports FALSE
 * directly, and behaviorally, that the interaction.c grab-site guard this
 * predicate gates -- `if (save_file_star_collection_is_recorded())
 * save_file_collect_star_or_key(...)` -- is exercised the same way the real
 * call site is: since the predicate is FALSE, save_file_collect_star_or_key()
 * is never actually invoked, so the stored star bitfield and the live star
 * total (save_file_get_total_star_count()) are asserted unchanged across a
 * simulated grab. This is the same behavior the milestone-dialog chooser
 * relies on never crossing a threshold.
 *
 * Seam G: asserts save_file_lives_are_consumed() reports FALSE directly,
 * and behaviorally, that the guard this predicate feeds -- `if
 * (save_file_lives_are_consumed()) { m->numLives--; }`, substituted for the
 * bare m->numLives-- in the reachable death-exit landing actions
 * (act_death_exit/act_falling_death_exit/act_special_death_exit,
 * mario_actions_cutscene.c) -- leaves numLives unchanged across any number
 * of simulated deaths. mario_actions_cutscene.c can't be linked into this
 * host tool (it pulls in the whole MarioState/object/animation graph), so
 * this is a deliberate reimplementation of just the guard's one-line shape,
 * NOT a call into the real call sites, mirroring seam F's own
 * simulate_guarded_star_grab() above. What IS exercised for real, against
 * the same save_file.c the ROM links, is save_file_lives_are_consumed()
 * itself. The tests also mirror the two numLives==0 Game-Over predicates
 * from level_update.c (WARP_OP_DEATH / WARP_OP_WARP_FLOOR) to confirm they
 * never see numLives reach 0 -- i.e. Game Over is suppressed transitively,
 * with no second gate -- including at the former 0-lives boundary.
 */

#include <stdio.h>
#include <string.h>

#include "sm64.h"
#include "area.h"
#include "save_file.h"

static int g_failures = 0;

static void check(int ok, const char *what) {
    if (ok) {
        printf("PASS: %s\n", what);
    } else {
        printf("FAIL: %s\n", what);
        g_failures++;
    }
}

extern struct SaveBuffer gSaveBuffer;

// The cannon-open bit lives in the top bit of the byte *following* each
// course's star flags (see save_file.h's own comment on SaveFile::courseStars
// and save_file_is_cannon_unlocked()'s vanilla read).
#define CANNON_OPEN_BIT (1 << 7)

// Shared fixture reset: zero the save buffer and point the globals at file 1 /
// the given course, so each behavioral test starts from a known blank save.
static void reset_save_fixture(s16 courseNum) {
    memset(&gSaveBuffer, 0, sizeof(gSaveBuffer));
    gCurrSaveFileNum = 1;
    gCurrCourseNum = courseNum;
}

static void test_cannons_are_forced_open_predicate(void) {
    check(save_file_cannons_are_forced_open() == TRUE,
          "save_file_cannons_are_forced_open() returns TRUE");
}

static void test_cannon_unlocked_on_fresh_zeroed_save(void) {
    reset_save_fixture(/* courseNum */ 0);

    check(save_file_is_cannon_unlocked() == TRUE,
          "save_file_is_cannon_unlocked() is open on a fresh/zeroed save");
}

static void test_cannon_unlocked_with_bit_explicitly_unset(void) {
    reset_save_fixture(/* courseNum */ 2);

    // Set some unrelated star-collection bits, but leave the cannon-open bit
    // (bit 7) explicitly clear, on the exact course under test.
    gSaveBuffer.files[gCurrSaveFileNum - 1][0].courseStars[gCurrCourseNum] = 0x3F;
    check((gSaveBuffer.files[gCurrSaveFileNum - 1][0].courseStars[gCurrCourseNum] & CANNON_OPEN_BIT) == 0,
          "setup: cannon-open bit is actually unset for this check");

    check(save_file_is_cannon_unlocked() == TRUE,
          "save_file_is_cannon_unlocked() is open even with the stored cannon bit unset");
}

static void test_star_collection_is_recorded_predicate(void) {
    check(save_file_star_collection_is_recorded() == FALSE,
          "save_file_star_collection_is_recorded() returns FALSE");
}

// Hand-mirrors the grab-site guard in interact_star_or_key (interaction.c:
// 970-973) -- interact_star_or_key itself can't be linked into this host
// tool (it pulls in the whole object/camera/pipeline graph), so this is a
// deliberate reimplementation of just the guard's shape, NOT a call into the
// real call site:
//   if (save_file_star_collection_is_recorded()) {
//       save_file_collect_star_or_key(m->numCoins, starIndex);
//   }
//   m->numStars = save_file_get_total_star_count(...);
// What IS exercised for real, against the same save_file.c the ROM links, is
// both functions the guard calls: save_file_star_collection_is_recorded()
// and (if it ever returned TRUE) save_file_collect_star_or_key(). Since the
// guard's own logic is one `if` with no branches this file doesn't already
// cover, the reimplementation risk is low, but it is a reimplementation.
static void simulate_guarded_star_grab(s16 coinScore, s16 starIndex) {
    if (save_file_star_collection_is_recorded()) {
        save_file_collect_star_or_key(coinScore, starIndex);
    }
}

static void test_star_grab_leaves_stored_star_bitfield_unchanged(void) {
    reset_save_fixture(/* courseNum */ 1);
    gCurrLevelNum = LEVEL_BOB;

    u32 starFlagsBefore = save_file_get_star_flags(gCurrSaveFileNum - 1, COURSE_NUM_TO_INDEX(gCurrCourseNum));

    simulate_guarded_star_grab(/* coinScore */ 42, /* starIndex */ 0);

    u32 starFlagsAfter = save_file_get_star_flags(gCurrSaveFileNum - 1, COURSE_NUM_TO_INDEX(gCurrCourseNum));

    check(starFlagsAfter == starFlagsBefore,
          "simulated star grab leaves the stored star bitfield unchanged");
    check(starFlagsAfter == 0, "simulated star grab leaves the stored star bitfield at 0");
}

static void test_star_grab_leaves_live_star_total_unchanged(void) {
    reset_save_fixture(/* courseNum */ 3);
    gCurrLevelNum = LEVEL_WF;

    s16 totalBefore = save_file_get_total_star_count(gCurrSaveFileNum - 1, COURSE_MIN - 1, COURSE_MAX - 1);

    simulate_guarded_star_grab(/* coinScore */ 100, /* starIndex */ 5);

    s16 totalAfter = save_file_get_total_star_count(gCurrSaveFileNum - 1, COURSE_MIN - 1, COURSE_MAX - 1);

    check(totalAfter == totalBefore,
          "simulated star grab leaves the live star total unchanged");
    check(totalAfter == 0, "simulated star grab leaves the live star total at 0");
}

static void test_lives_are_consumed_predicate(void) {
    check(save_file_lives_are_consumed() == FALSE,
          "save_file_lives_are_consumed() returns FALSE");
}

// Hand-mirrors the guard substituted for the bare m->numLives-- in each
// reachable death-exit landing action (act_death_exit, act_falling_death_exit,
// act_special_death_exit, mario_actions_cutscene.c:1273/1315/1365):
//   if (save_file_lives_are_consumed()) {
//       m->numLives--;
//   }
static void simulate_guarded_death_exit_decrement(s8 *numLives) {
    if (save_file_lives_are_consumed()) {
        (*numLives)--;
    }
}

// Hand-mirrors the two numLives==0 Game-Over decision points in
// level_trigger_warp (level_update.c:823 WARP_OP_DEATH, :835
// WARP_OP_WARP_FLOOR). Both read the same condition, so one helper covers
// both call sites.
static int would_trigger_game_over(s8 numLives) {
    return numLives == 0;
}

static void test_death_exit_leaves_lives_unchanged_across_many_deaths(void) {
    s8 numLives = 4; // init_mario's starting value (mario.c)
    int deathNum;

    for (deathNum = 0; deathNum < 10; deathNum++) {
        simulate_guarded_death_exit_decrement(&numLives);
        check(numLives == 4, "simulated death-exit decrement leaves numLives unchanged");
        check(!would_trigger_game_over(numLives),
              "simulated death never brings numLives to the Game-Over boundary");
    }
}

static void test_former_zero_lives_boundary_produces_no_game_over(void) {
    // In vanilla, Game Over fires on the death that finds numLives already
    // at 0 -- reached only because the *previous* death's landing decremented
    // the last life down to it. Start one life short of that former
    // boundary and drive several simulated deaths at it: with the decrement
    // blocked, numLives never actually reaches 0, so the boundary this
    // predicate depends on is never crossed and Game Over never fires.
    s8 numLives = 1;
    int deathNum;

    for (deathNum = 0; deathNum < 10; deathNum++) {
        simulate_guarded_death_exit_decrement(&numLives);

        check(numLives == 1, "simulated death-exit decrement never drives the last life to 0");
        check(!would_trigger_game_over(numLives),
              "the former 0-lives Game-Over boundary is never reached");
    }
}

// 1-up increments (mushroom_1up.inc.c, yoshi.inc.c, ingame_menu.c) are a bare
// numLives++ with no predicate guard -- out of scope for seam G by design
// (#132). There is nothing to link/simulate here: the increment sites don't
// call save_file_lives_are_consumed() at all, so this is a documentation
// note rather than a check() -- there is no seam-G behavior for a test to
// exercise on the increment path.

int main(void) {
    test_cannons_are_forced_open_predicate();
    test_cannon_unlocked_on_fresh_zeroed_save();
    test_cannon_unlocked_with_bit_explicitly_unset();

    test_star_collection_is_recorded_predicate();
    test_star_grab_leaves_stored_star_bitfield_unchanged();
    test_star_grab_leaves_live_star_total_unchanged();

    test_lives_are_consumed_predicate();
    test_death_exit_leaves_lives_unchanged_across_many_deaths();
    test_former_zero_lives_boundary_produces_no_game_over();

    if (g_failures != 0) {
        printf("%d check(s) FAILED\n", g_failures);
        return 1;
    }

    printf("All save_file seam-E/F/G host tests PASSED\n");
    return 0;
}

/*
 * Host test tool for sandbox seam E -- cannon suppression (spec #80,
 * sub-issue #81).
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
 * Asserts save_file_is_cannon_unlocked() reports open regardless of the
 * stored per-course cannon bit:
 *   - on a fresh/zeroed save (every byte, including the cannon bit, 0), and
 *   - on a save whose cannon bit is explicitly cleared while other course
 *     star bits are set (proving it isn't open merely because the whole
 *     buffer happens to be zero).
 * Also asserts the new seam predicate, save_file_cannons_are_forced_open(),
 * itself reports TRUE directly.
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

static void test_cannons_are_forced_open_predicate(void) {
    check(save_file_cannons_are_forced_open() == TRUE,
          "save_file_cannons_are_forced_open() returns TRUE");
}

static void test_cannon_unlocked_on_fresh_zeroed_save(void) {
    memset(&gSaveBuffer, 0, sizeof(gSaveBuffer));
    gCurrSaveFileNum = 1;
    gCurrCourseNum = 0;

    check(save_file_is_cannon_unlocked() == TRUE,
          "save_file_is_cannon_unlocked() is open on a fresh/zeroed save");
}

static void test_cannon_unlocked_with_bit_explicitly_unset(void) {
    memset(&gSaveBuffer, 0, sizeof(gSaveBuffer));
    gCurrSaveFileNum = 1;
    gCurrCourseNum = 2;

    // Set some unrelated star-collection bits, but leave the cannon-open bit
    // (bit 7) explicitly clear, on the exact course under test.
    gSaveBuffer.files[gCurrSaveFileNum - 1][0].courseStars[gCurrCourseNum] = 0x3F;
    check((gSaveBuffer.files[gCurrSaveFileNum - 1][0].courseStars[gCurrCourseNum] & CANNON_OPEN_BIT) == 0,
          "setup: cannon-open bit is actually unset for this check");

    check(save_file_is_cannon_unlocked() == TRUE,
          "save_file_is_cannon_unlocked() is open even with the stored cannon bit unset");
}

int main(void) {
    test_cannons_are_forced_open_predicate();
    test_cannon_unlocked_on_fresh_zeroed_save();
    test_cannon_unlocked_with_bit_explicitly_unset();

    if (g_failures != 0) {
        printf("%d check(s) FAILED\n", g_failures);
        return 1;
    }

    printf("All save_file seam-E host tests PASSED\n");
    return 0;
}

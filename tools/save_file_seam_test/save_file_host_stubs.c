// save_file_host_stubs.c
//
// Host-only shim for the sandbox-seam host test tool (sub-issue #81, seam E).
// Mirrors tools/pipeline_test/qr_host_decode.c's convention: this file lives
// under tools/, NOT under src/game/, so it can never be pulled into the
// ROM's object graph. Its only job is to provide definitions for the
// externs src/game/save_file.c references outside of the two seam-E
// functions under test (save_file_cannons_are_forced_open,
// save_file_is_cannon_unlocked), so that save_file.c -- the SAME source
// compiled into the ROM, unmodified -- links as a native host binary.
// None of these stubbed globals/functions are exercised by the seam-E
// assertions in main.c; they exist only to satisfy the linker.

#include <ultra64.h>

#include "sm64.h"
#include "game_init.h"
#include "main.h"
#include "engine/math_util.h"
#include "area.h"
#include "level_update.h"
#include "save_file.h"
#include "sound_init.h"

struct SaveBuffer gSaveBuffer;

s16 gCurrCourseNum;
s16 gCurrActNum;
s16 gCurrAreaIndex;
s16 gSavedCourseNum;
s16 gCurrSaveFileNum;
s16 gCurrLevelNum;

s8 gEepromProbe;
struct DemoInput *gCurrDemoInput;
struct CreditsEntry *gCurrCreditsEntry;
OSMesgQueue gSIEventMesgQueue;

s32 osEepromLongRead(UNUSED OSMesgQueue *mq, UNUSED u8 address, UNUSED u8 *buffer, UNUSED int nBytes) {
    return 0;
}

s32 osEepromLongWrite(UNUSED OSMesgQueue *mq, UNUSED u8 address, UNUSED u8 *buffer, UNUSED int nBytes) {
    return 0;
}

void set_sound_mode(UNUSED u16 soundMode) {
}

void *vec3s_copy(Vec3s dest, Vec3s src) {
    dest[0] = src[0];
    dest[1] = src[1];
    dest[2] = src[2];
    return dest;
}

void *vec3s_set(Vec3s dest, s16 x, s16 y, s16 z) {
    dest[0] = x;
    dest[1] = y;
    dest[2] = z;
    return dest;
}

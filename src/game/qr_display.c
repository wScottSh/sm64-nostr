/*
 * See qr_display.h. Pure C89 (matching src/pipeline/'s and qr_render.c's
 * own convention): no MarioState, no globals, no N64 headers, no
 * <string.h>. Compiled unmodified into both the ROM build (src/game is a
 * SRC_DIRS entry) and, a second time, into tools/pipeline_test, so the
 * debounce/erase/never-re-summonable logic is a real, exercised seam.
 */

#include "qr_display.h"

void qr_display_init(QrDisplayState *state) {
    int i;
    for (i = 0; i < (int) sizeof(state->bitmap); i++) {
        state->bitmap[i] = 0;
    }
    state->active = 0;
    state->everPresented = 0;
    state->seenRelease = 0;
    state->pressFrames = 0;
}

int qr_display_present(QrDisplayState *state, const pipeline_u8 bitmap[PIPELINE_BUILT_QR_BITMAP_SIZE]) {
    int i;

    if (state->everPresented || state->active) {
        return 0;
    }

    for (i = 0; i < (int) sizeof(state->bitmap); i++) {
        state->bitmap[i] = bitmap[i];
    }
    state->active = 1;
    state->everPresented = 1;
    state->seenRelease = 0;
    state->pressFrames = 0;
    return 1;
}

int qr_display_is_active(const QrDisplayState *state) {
    return state->active;
}

int qr_display_update(QrDisplayState *state, int aButtonHeld) {
    int i;

    if (!state->active) {
        return 0;
    }

    if (!aButtonHeld) {
        state->seenRelease = 1;
        state->pressFrames = 0;
        return 0;
    }

    if (!state->seenRelease) {
        /* Still the original press that triggered the dance (or any press
         * observed before a release ever happened) -- ignored by design;
         * see qr_display.h's header comment, acceptance behavior (a). */
        return 0;
    }

    state->pressFrames++;
    if (state->pressFrames < QR_DISPLAY_MIN_HOLD_FRAMES) {
        return 0;
    }

    /* One-shot erase: zero the held bitmap byte-by-byte (the memset-erase
     * the parent spec calls for, hand-rolled per this file's header
     * comment) so the dismissed QR is genuinely unrecoverable from this
     * state, not just marked inactive. state->everPresented is
     * deliberately left set. */
    for (i = 0; i < (int) sizeof(state->bitmap); i++) {
        state->bitmap[i] = 0;
    }
    state->active = 0;
    return 1;
}

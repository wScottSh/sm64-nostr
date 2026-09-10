/*
 * See qr_display_n64.h. Thin N64-only shell -- see that header's comment.
 * Not compiled by tools/pipeline_test (host build); ROM-only, via src/game
 * being one of the Makefile's SRC_DIRS.
 */

#include <ultra64.h>

#include "game_init.h"
#include "qr_display.h"
#include "qr_display_n64.h"
#include "qr_render_n64.h"

/*
 * The ONE shared QrDisplayState, re-armed once per star grab (spec #24,
 * sub-issue #33: "the never-re-summonable invariant lives once"). A
 * file-static global zero-initializes in BSS at boot -- bitmap all zero,
 * active/everPresented/seenRelease/pressFrames all 0 -- which is exactly
 * qr_display_init()'s own reset value (see qr_display.c), so no explicit
 * init call is needed at boot.
 *
 * "Session", for qr_display_present()'s own never-re-summonable latch,
 * means the display lifecycle of ONE star's QR -- present once, dismiss
 * once, done -- not the whole ROM power-on session: acceptance criterion
 * "Fires for every star -- exit and no-exit alike" (parent spec #24)
 * requires each of possibly many star grabs in a play session to get its
 * OWN full present-then-dismiss cycle. qr_display_n64_present() below
 * re-arms sQrDisplay (qr_display_init()) ONLY when it is not currently
 * active, giving each NEW grab a fresh state once the previous one has
 * been dismissed, while a present() call arriving while a QR is still up
 * is correctly rejected by qr_display_present()'s own active check --
 * re-initializing unconditionally here would silently wipe out an
 * in-progress display instead of rejecting the stray call, which would
 * defeat that check entirely.
 */
static QrDisplayState sQrDisplay;

int qr_display_n64_present(const BuiltEvent *event) {
    if (!qr_display_is_active(&sQrDisplay)) {
        qr_display_init(&sQrDisplay);
    }
    /*
     * ADR-0006 multi-frame transport (spec #115, sub-issue #116) replaced
     * BuiltEvent's single qr_bitmap with frame_count + qr_bitmaps[N].
     * Presenting frame 0 only, unconditionally, is a deliberate STOPGAP:
     * on-device cycling through all N frames on a fixed cadence (the pure
     * (frameCount, tick) -> frameIndex selector ADR-0006/spec #115 itself
     * calls for) is sibling sub-issue #118's scope, not this one's. This
     * keeps the ROM building and keeps today's N=1 behavior exactly
     * unchanged (a single static frame); an N>1 build displays only its
     * first fragment's QR until #118 lands the real cycling shell.
     */
    return qr_display_present(&sQrDisplay, event->qr_bitmaps[0]);
}

int qr_display_n64_is_active(void) {
    return qr_display_is_active(&sQrDisplay);
}

int qr_display_n64_step(void) {
    int aButtonHeld = (gPlayer1Controller->buttonDown & A_BUTTON) != 0;
    return qr_display_update(&sQrDisplay, aButtonHeld);
}

void qr_display_n64_render_if_active(uintptr_t framebuffer) {
    if (qr_display_is_active(&sQrDisplay)) {
        qr_render_blit_to_uncached_framebuffer(sQrDisplay.bitmap, framebuffer);
    }
}

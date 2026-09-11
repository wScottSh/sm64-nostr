/*
 * See qr_display_n64.h. Thin N64-only shell -- see that header's comment.
 * Not compiled by tools/pipeline_test (host build); ROM-only, via src/game
 * being one of the Makefile's SRC_DIRS.
 */

#include <ultra64.h>

#include "game_init.h"
#include "qr_cycle.h"
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

/*
 * The cycling shell's own copy of the WHOLE frame set (spec #115, sub-issue
 * #118), captured at present() time -- sQrDisplay.bitmap still holds frame
 * 0 too (the pure qr_display core's own contract, qr_display.h, is
 * unmodified by this sub-issue), but is no longer this shell's blit source
 * and, past this point, is dead storage kept only because the pure core
 * owns it; the remaining N-1 frames -- and, since this sub-issue, ALL N,
 * frame 0 included -- are read from here instead, where the shell that
 * actually cycles them can reach them. Sized to PIPELINE_BUILT_FRAME_COUNT/
 * PIPELINE_BUILT_QR_BITMAP_SIZE, the SAME compile-time constants
 * BuiltEvent::qr_bitmaps itself uses (build_event.h) -- this build only
 * ever has one frame count/bitmap size, so no separate bound is
 * introduced. sFrameCount and sTick are meaningless while sQrDisplay is
 * not active; qr_display_n64_present() (re-)arms both exactly when it
 * (re-)arms sQrDisplay, qr_display_n64_render_if_active() only ever reads
 * them while sQrDisplay IS active, and qr_display_n64_step() erases
 * sQrFrames (and resets both counters) on the exact tick it dismisses
 * sQrDisplay -- so the pure core's "genuinely unrecoverable after dismiss"
 * invariant (qr_display.h) covers every frame byte this shell ever held,
 * not just the one dead copy in sQrDisplay.bitmap.
 *
 * sTick is a plain pipeline_u32 render-tick counter with no explicit wrap
 * handling: at the ~30 Hz cadence QR_CYCLE_HOLD_TICKS assumes (qr_cycle.h),
 * it would take roughly 4.5 CONTINUOUS years of one overlay staying
 * presented and undismissed to wrap -- categorically unreachable for a
 * single star-grab overlay's lifetime, so no defensive floor is added
 * here (unlike sFrameCount's, which guards an input this module cannot
 * itself bound).
 */
static pipeline_u8 sQrFrames[PIPELINE_BUILT_FRAME_COUNT][PIPELINE_BUILT_QR_BITMAP_SIZE];
static pipeline_u32 sFrameCount;
static pipeline_u32 sTick;

/*
 * VI anti-aliasing workaround (issue #89). ADR-0008.
 *
 * The star-capture overlay is a direct CPU framebuffer blit (ADR-0004): it
 * writes only the 16-bit RGBA5551 COLOR of each pixel. It cannot write the
 * pixel's full 3-bit VI coverage -- the low two coverage bits live in the
 * RDP-only "hidden" plane of RDRAM (the CPU reaches only the color LSB) --
 * so every overlay pixel keeps whatever coverage the RDP left there when it
 * rendered the 3D scene into this buffer a frame ago.
 *
 * The game runs the VI in an anti-aliased/resample mode (OS_VI_*_LAN1,
 * main.c thread1_idle). That mode's display filter READS coverage: at
 * pixels the RDP marked partial-coverage -- 3D silhouette edges, e.g. the
 * top line of a door or the rim of Mario's hat -- the VI blends our overlay
 * color with its neighbours (and the divot filter takes a median, so only
 * the extreme, darkest/brightest edge texel survives). The result is thin
 * slivers of the scene behind bleeding IN FRONT of the QR and its text.
 *
 * This is exactly why the in-game HUD and dialog boxes never show it: the
 * RDP draws THEM, writing full coverage (hidden bits included) so the VI
 * treats them as opaque. A CPU blit structurally cannot reproduce that.
 *
 * So, for the lifetime of the overlay only, we drop the VI to the matching
 * point-sampled mode (OS_VI_*_LPN1), which ignores coverage and displays the
 * framebuffer 1:1 -- no neighbour blend, no divot, no resample. The QR and
 * text become pixel-exact (which also scans better); the only cost is the
 * paused background losing AA while the code is up. Restored on dismiss.
 *
 * The AA vs point-sampled table indices are picked per TV type exactly the
 * way main.c picks LAN1 (osTvType == TV_TYPE_NTSC ? NTSC : PAL); MPAL falls
 * through to PAL there, so it does here too. osViSetMode reinstates the mode
 * table's own feature bits, so we re-apply the two special features
 * thread1_idle sets globally, to avoid silently changing dither/gamma for
 * the rest of the game when we toggle back.
 */
static int qr_vi_mode_index(int antialiased) {
#if defined(VERSION_US) || defined(VERSION_SH) || defined(VERSION_CN)
    if (osTvType == TV_TYPE_NTSC) {
        return antialiased ? OS_VI_NTSC_LAN1 : OS_VI_NTSC_LPN1;
    }
    return antialiased ? OS_VI_PAL_LAN1 : OS_VI_PAL_LPN1;
#elif defined(VERSION_JP)
    return antialiased ? OS_VI_NTSC_LAN1 : OS_VI_NTSC_LPN1;
#else /* VERSION_EU */
    return antialiased ? OS_VI_PAL_LAN1 : OS_VI_PAL_LPN1;
#endif
}

static void qr_vi_set_antialiasing(int antialiased) {
    osViSetMode(&osViModeTable[qr_vi_mode_index(antialiased)]);
    osViSetSpecialFeatures(OS_VI_DITHER_FILTER_ON);
    osViSetSpecialFeatures(OS_VI_GAMMA_OFF);
}

int qr_display_n64_present(const BuiltEvent *event) {
    pipeline_u32 i, j;

    if (!qr_display_is_active(&sQrDisplay)) {
        qr_display_init(&sQrDisplay);
    }

    if (!qr_display_present(&sQrDisplay, event->qr_bitmaps[0])) {
        return 0;
    }

    /*
     * Copy the full frame set (ADR-0006 multi-frame transport, spec #115
     * sub-issue #116) into this shell's own storage so
     * qr_display_n64_render_if_active() can cycle through all of them
     * (sub-issue #118), not just the frame 0 the pure qr_display core
     * holds. Byte-by-byte, hand-rolled, mirroring qr_display.c's own
     * <string.h>-avoidance convention (this file already includes
     * <ultra64.h>, so a real memcpy would be available here; matching the
     * surrounding module's own idiom keeps the two copies easy to compare
     * even though the loop types differ, pipeline_u32 here vs int there).
     *
     * event->frame_count is contractually always PIPELINE_BUILT_FRAME_COUNT
     * on a successful build_event() (build_event.h), never 0 -- but this
     * copy clamps to that same [1, PIPELINE_BUILT_FRAME_COUNT] range
     * defensively rather than trusting that caller invariant blindly,
     * exactly like qr_cycle_frame_index()'s own frameCount==0 floor
     * (qr_cycle.h): an out-of-range value here would otherwise be either a
     * BSS buffer overrun (too high) or a stale previous grab's frames left
     * live in sQrFrames[0] (too low), neither of which qr_display_present()
     * above already caught.
     */
    sFrameCount = event->frame_count;
    if (sFrameCount == 0u) {
        sFrameCount = 1u;
    } else if (sFrameCount > (pipeline_u32) PIPELINE_BUILT_FRAME_COUNT) {
        sFrameCount = (pipeline_u32) PIPELINE_BUILT_FRAME_COUNT;
    }
    for (i = 0; i < sFrameCount; i++) {
        for (j = 0; j < (pipeline_u32) sizeof(sQrFrames[i]); j++) {
            sQrFrames[i][j] = event->qr_bitmaps[i][j];
        }
    }
    sTick = 0u;

    /* Overlay is now committed and about to be shown: drop the VI out of its
     * anti-aliased mode so its coverage-reading filter can't bleed the 3D
     * scene's edges through our CPU-blitted QR/text (issue #89, see
     * qr_vi_set_antialiasing's own comment). Paired with the restore in
     * qr_display_n64_step()'s dismiss branch. */
    qr_vi_set_antialiasing(0);
    return 1;
}

int qr_display_n64_is_active(void) {
    return qr_display_is_active(&sQrDisplay);
}

int qr_display_n64_step(void) {
    int aButtonHeld = (gPlayer1Controller->buttonDown & A_BUTTON) != 0;
    int dismissed = qr_display_update(&sQrDisplay, aButtonHeld);

    if (dismissed) {
        /*
         * qr_display_update() already memset-erased sQrDisplay.bitmap (its
         * own one-shot-erase contract, qr_display.h) -- but that copy is no
         * longer this shell's blit source (see sQrFrames's own header
         * comment above). Erase this shell's OWN copy of the full frame
         * set too, byte-by-byte for the same reason the pure core doesn't
         * use memset, so "the dismissed QR is genuinely unrecoverable" (the
         * pure core's own stated invariant) actually covers every byte
         * this shell ever held, not just the one dead copy.
         */
        pipeline_u32 i, j;
        for (i = 0; i < (pipeline_u32) PIPELINE_BUILT_FRAME_COUNT; i++) {
            for (j = 0; j < (pipeline_u32) sizeof(sQrFrames[i]); j++) {
                sQrFrames[i][j] = 0;
            }
        }
        sFrameCount = 0u;
        sTick = 0u;

        /* Overlay dismissed: restore the game's normal anti-aliased VI mode
         * (issue #89). Symmetric with the point-sampled switch in
         * qr_display_n64_present(). */
        qr_vi_set_antialiasing(1);
    }

    return dismissed;
}

void qr_display_n64_render_if_active(uintptr_t framebuffer) {
    pipeline_u32 frameIndex;

    if (!qr_display_is_active(&sQrDisplay)) {
        return;
    }

    /*
     * Cycling shell (spec #115, sub-issue #118): pick this tick's frame via
     * the pure qr_cycle_frame_index() selector (qr_cycle.h), then advance
     * the tick counter for the next render call. An N=1 event's selector
     * always returns 0, so this blits the same single frame every tick --
     * unchanged from before this sub-issue.
     */
    frameIndex = qr_cycle_frame_index(sFrameCount, sTick);
    sTick++;
    qr_render_blit_to_uncached_framebuffer(sQrFrames[frameIndex], framebuffer);
}

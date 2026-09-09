#ifndef QR_RENDER_N64_H
#define QR_RENDER_N64_H

#include <PR/ultratypes.h> /* uintptr_t, mirroring src/game/game_init.h's own convention */

#include "qr_render.h"

/*
 * The renderer glue's thin, non-host-testable N64 shell (spec #24,
 * sub-issue #32). Computes the UNCACHED (kseg1, |0xa0000000) framebuffer
 * pointer -- mirroring crash_screen_init()'s own non-EU addressing
 * (src/game/crash_screen.c: "gCrashScreen.framebuffer =
 * (u16 *)(osMemSize | 0xA0000000) - ..."), applied unconditionally on
 * every version -- then delegates every pixel-placement decision to the
 * pure qr_render_overlay_rgba16() (qr_render.h), passing it the dialog-font
 * seam built from the game's own gDialogCharWidths + main_font_lut
 * (ADR-0004). This shell itself contains no module/scale/quiet-zone/layout
 * math, only the address conversion, the font-glyph resolution
 * (segmented_to_virtual), and the SCREEN_WIDTH/SCREEN_HEIGHT (config.h)
 * framing.
 *
 * Deliberately NOT modeled on crash_screen_set_framebuffer()'s own
 * VERSION_EU-conditional branches: that function's `framebuffer` parameter
 * has a different, version-dependent contract (its caller sometimes
 * already hands it a converted/virtual address). `framebuffer` here has a
 * single, fixed contract instead: it is always a PHYSICAL framebuffer
 * address, e.g. one of gPhysicalFramebuffers[...] (src/game/game_init.h),
 * which VIRTUAL_TO_PHYSICAL() (include/macros.h) makes physical on every
 * version -- so the same unconditional |0xa0000000 conversion is correct
 * everywhere; see qr_render_n64.c's own comment for the full reasoning.
 *
 * This function does not decide WHICH of the ROM's three framebuffers to
 * target, or WHEN to blit; that sequencing is the qr_display state
 * machine's job (#33, out of scope for this sub-issue). This function only
 * builds the uncached pointer and blits once, synchronously, when called.
 *
 * Deliberately excluded from tools/pipeline_test's host build: this file
 * includes <ultra64.h>, which is unavailable off-target. Its own logic is
 * intentionally as thin as possible (one pointer conversion, the font-seam
 * glyph resolver, one call into the pure core) precisely so there is almost
 * nothing here that host coverage of qr_render_overlay_rgba16() doesn't
 * already exercise.
 */
void qr_render_blit_to_uncached_framebuffer(const pipeline_u8 *qrBitmap, uintptr_t framebuffer);

#endif /* QR_RENDER_N64_H */

/*
 * See qr_render_n64.h. Thin N64-only shell -- see that header's comment.
 * Not compiled by tools/pipeline_test (host build); ROM-only, via src/game
 * being one of the Makefile's SRC_DIRS.
 */

#include <ultra64.h>

#include "sm64.h"
#include "qr_render_n64.h"

void qr_render_blit_to_uncached_framebuffer(const pipeline_u8 *qrBitmap, uintptr_t framebuffer)
{
    /*
     * `framebuffer` is documented (qr_render_n64.h) as a PHYSICAL
     * framebuffer address -- e.g. one of gPhysicalFramebuffers[...]
     * (src/game/game_init.h/.c), which are always physical, on every
     * version, via VIRTUAL_TO_PHYSICAL() (game_init.c:623-625). A physical
     * address is converted to its uncached (kseg1) alias the same way on
     * every version: OR it into 0xa0000000. This is deliberately NOT the
     * same conditional crash_screen_set_framebuffer() uses
     * (src/game/crash_screen.c): that function's own `framebuffer`
     * parameter has a different, version-dependent contract (sometimes
     * already virtual/converted by its caller) that does not apply to a
     * known-physical input like gPhysicalFramebuffers -- branching on
     * VERSION_EU here would be copying that function's conditional without
     * its precondition, and would fault under EU (an unconverted physical
     * address is not a valid kuseg pointer). crash_screen_init()'s own
     * non-EU branch (osMemSize | 0xA0000000, also version-invariant for a
     * physical value) is the actually-applicable precedent.
     */
    u16 *uncached = (u16 *) (framebuffer | 0xa0000000);

    qr_render_blit_rgba16(qrBitmap, uncached, SCREEN_WIDTH, SCREEN_HEIGHT);
}

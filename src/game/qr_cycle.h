#ifndef QR_CYCLE_H
#define QR_CYCLE_H

#include "pipeline/build_event.h"

/*
 * The star-capture overlay's frame-cycling PURE core (spec #115, sub-issue
 * #118). ADR-0006's multi-frame transport (sub-issue #116) made BuiltEvent
 * carry frame_count + N qr_bitmaps instead of one; qr_display_n64.c's own
 * #118 stopgap comment documented that until this file existed, the
 * overlay just displayed qr_bitmaps[0] forever, even when frame_count > 1.
 * This header is the ONE pure function that decides WHICH of the N frames
 * is on screen on a given render tick; the N64 shell (qr_display_n64.c)
 * owns everything impure -- counting ticks, holding its own copy of the
 * BuiltEvent frame set, and calling qr_render_blit_to_uncached_framebuffer()
 * with whichever frame this function selects. Mirrors qr_render.h/
 * qr_display.h's own pure-core convention: no MarioState, no globals, no
 * N64 headers, no <string.h>; compiled unmodified a second time into
 * tools/pipeline_test so the cycling/wrap logic is a real, exercised seam,
 * not something only verifiable on real hardware.
 *
 * QR_CYCLE_HOLD_TICKS is the ONE tunable cadence knob spec #115/ADR-0006
 * calls for: how many consecutive render ticks each frame holds on screen
 * before the sequence advances to the next. Living here, as a single
 * #define in the shell-side game code (not the pipeline), means CRT
 * refresh-beat robustness (#107, a non-gating follow-up) can be retuned
 * later by changing this one constant -- no pipeline change, no format
 * change, no touching qr_display_n64.c's own logic.
 */
#define QR_CYCLE_HOLD_TICKS 20u

/*
 * qr_cycle_frame_index: pure (frameCount, tick) -> frameIndex.
 *
 * tick is a monotonically increasing counter of render ticks since the
 * overlay was presented (0, 1, 2, ...); the caller owns incrementing it
 * once per call to qr_display_n64_render_if_active(). frameCount is
 * BuiltEvent::frame_count.
 *
 * Returns the frame index (0 .. frameCount-1) that should be on screen on
 * this tick: each frame holds for QR_CYCLE_HOLD_TICKS consecutive ticks,
 * then the sequence advances by one and wraps back to 0 after frameCount-1
 * -- cycling 0..N-1 and wrapping, exactly as spec #115/#118's acceptance
 * criterion calls for.
 *
 * frameCount == 1 (the common, passively-snappable N=1 case) always
 * returns 0 -- no cycling, matching today's single-static-frame behavior
 * exactly, unchanged.
 *
 * frameCount == 0 is treated as 1 (defensive floor against a
 * divide-by-zero): build_event() never actually produces a BuiltEvent with
 * frame_count == 0 (PIPELINE_BUILT_FRAME_COUNT's own formula has a minimum
 * of 1, build_event.h), but this function stays total over its whole input
 * domain rather than relying on that caller invariant.
 */
pipeline_u32 qr_cycle_frame_index(pipeline_u32 frameCount, pipeline_u32 tick);

#endif /* QR_CYCLE_H */

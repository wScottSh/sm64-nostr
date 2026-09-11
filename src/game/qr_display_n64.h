#ifndef QR_DISPLAY_N64_H
#define QR_DISPLAY_N64_H

#include <PR/ultratypes.h>

#include "pipeline/build_event.h"

/*
 * The qr_display state machine's thin, non-host-testable N64 shell (spec
 * #24, sub-issue #33). Owns the ONE shared QrDisplayState instance both
 * save flows drive -- a module-static in qr_display_n64.c, never exposed
 * directly; callers only ever go through the functions declared here -- so
 * the never-re-summonable invariant lives in exactly one place. A plain C
 * global zero-initializes in BSS at boot, exactly matching
 * qr_display_init()'s own reset values; qr_display_n64_present() re-arms it
 * (re-calls qr_display_init()) each time a NEW star's QR is about to be
 * shown, but ONLY while no QR is currently active -- see qr_display_n64.c's
 * own header comment for why that guard matters. Reads the real
 * controller (gPlayer1Controller, game_init.h -- the same controller the
 * capture glue at interact_star_or_key already reads) and calls the real
 * renderer (qr_render_blit_to_uncached_framebuffer, #32). Every
 * debounce/erase/never-re-summonable decision is delegated to the pure
 * qr_display.h core; this file contains no such logic itself.
 *
 * Split into two entry points, called from two different places, because
 * they run at two different points in the frame (and, since sub-issue
 * #118, drive two different per-frame counters off that same assumed
 * once-per-frame cadence: qr_display_n64_step()'s dismiss debounce
 * (pressFrames, qr_display.h) and qr_display_n64_render_if_active()'s own
 * cycling tick (sTick, qr_display_n64.c) -- both implicitly assume exactly
 * one call per rendered frame, matching how thread5_game_loop() already
 * calls each of their call sites):
 *   - qr_display_n64_present()/qr_display_n64_step() are called from
 *     WITHIN the Mario action update (mario_actions_cutscene.c), which is
 *     where gPlayer1Controller's per-frame reading is already valid
 *     (read_controller_inputs() runs once per frame, before
 *     level_script_execute() reaches the action update -- see
 *     game_init.c's thread5_game_loop()) and where time-stop is already
 *     being managed by the calling save-flow site.
 *   - qr_display_n64_render_if_active() is called from game_init.c's
 *     display_and_vsync(), AFTER that frame's normal 3D scene has already
 *     been rendered by the RDP into the framebuffer about to be swapped to
 *     the VI (gPhysicalFramebuffers[sRenderedFramebuffer], one full frame
 *     after it was submitted -- by construction already complete by the
 *     time display_and_vsync reaches the swap). Writing our overlay
 *     earlier (e.g. from within the Mario action, before that frame's own
 *     display list has even been built) would risk the RDP's own render
 *     overwriting our pixels; writing here, right before the swap that
 *     displays this exact buffer, cannot be clobbered by anything else
 *     this frame. This mirrors crash_screen's own "write directly into an
 *     already-rendered/about-to-display framebuffer" precedent
 *     (src/game/crash_screen.c), adapted to run every frame from the
 *     normal game loop instead of a dedicated exception thread.
 */

/*
 * qr_display_n64_present: presents event->qr_bitmaps[0] on the shared
 * state and arms this shell's own frame-cycling copy of the WHOLE frame set
 * (spec #115, sub-issue #118: BuiltEvent is frame_count + N qr_bitmaps,
 * ADR-0006/sub-issue #116; qr_display_n64_render_if_active() below cycles
 * through all of them at a fixed cadence via the pure qr_cycle_frame_index()
 * selector, qr_cycle.h). Returns nonzero on success, 0 if rejected -- see
 * qr_display_present() (already shown once this session, or already
 * active). Callers (both save-flow sites) must check the return value: on
 * rejection there is nothing new to show, so they must fall through to
 * whatever they'd do if no event applies at all (this never actually
 * happens for a real star grab today, since each grab can only reach its
 * site once per dance, but is still the documented, checked contract --
 * mirroring build_event()'s own "callers must check the return value"
 * convention, src/pipeline/build_event.h).
 */
int qr_display_n64_present(const BuiltEvent *event);

/*
 * qr_display_n64_is_active: nonzero while a QR is currently being
 * displayed. Callers use this to decide whether to keep calling
 * qr_display_n64_step() every frame instead of advancing their own action
 * state machine, and to know when to resume normal play once it returns 0
 * after a dismiss.
 */
int qr_display_n64_is_active(void);

/*
 * qr_display_n64_step: call once per frame, from the Mario action update,
 * while qr_display_n64_is_active() is true. Reads gPlayer1Controller's A
 * button this frame and advances the debounce state machine (see
 * qr_display_update()). Returns nonzero on the exact frame the QR is
 * dismissed (bitmap erased, no longer active) -- callers own everything
 * that happens next (disabling time-stop, resuming their own action state
 * machine); this function does not touch gTimeStopState itself, since
 * time-stop is inherited from the dance, not this module's to manage.
 * Does NOT render anything -- see qr_display_n64_render_if_active().
 */
int qr_display_n64_step(void);

/*
 * qr_display_n64_render_if_active: call once per frame from
 * display_and_vsync() (game_init.c), unconditionally -- this function
 * itself checks qr_display_n64_is_active() and is a no-op otherwise.
 * framebuffer is a PHYSICAL framebuffer address (e.g.
 * gPhysicalFramebuffers[sRenderedFramebuffer], see this header's own
 * comment for why THAT specific buffer, at THAT specific call site, is
 * the correct one).
 *
 * Also owns the frame-cycling cadence (spec #115, sub-issue #118): each
 * call is one render tick, advancing this shell's own tick counter and
 * feeding it, plus the frame count captured at present() time, through the
 * pure qr_cycle_frame_index() selector (qr_cycle.h) to pick which of the N
 * captured frames to blit this tick -- QR_CYCLE_HOLD_TICKS consecutive
 * ticks per frame, then advance and wrap. An N=1 event's selector always
 * returns 0, so it renders as a single static frame, unchanged from
 * before this sub-issue. The selected frame is passed straight through to
 * qr_render_blit_to_uncached_framebuffer (#32), which performs the actual
 * uncached-address conversion and pixel writes.
 */
void qr_display_n64_render_if_active(uintptr_t framebuffer);

#endif /* QR_DISPLAY_N64_H */

#ifndef QR_DISPLAY_H
#define QR_DISPLAY_H

#include "pipeline/build_event.h"

/*
 * The shared qr_display state machine's PURE core (spec #24, sub-issue #33):
 * the "qr_present(bitmap)" / "qr_update(input) -> done" pair from the parent
 * spec's Implementation Decisions ("qr_display glue (shared state
 * machine)"). Owns exactly the three behaviors the parent spec assigns to
 * this ONE module so neither save flow re-implements them: the debounced-A
 * dismiss (release-then-press + minimum hold), the one-shot erase, and the
 * never-re-summonable-in-this-session latch. Time-stop itself is NOT owned
 * here -- it is "inherited from the dance" (parent spec): both call sites
 * already enable_time_stop() before reaching the point where they call
 * qr_display_present() (see mario_actions_cutscene.c's
 * act_exit_land_save_dialog() and general_star_dance_handler()), and this
 * module's caller (qr_display_n64.c) is responsible for calling
 * disable_time_stop() once qr_display_update() reports dismissal.
 *
 * Pure, like src/pipeline/* and qr_render.h: no MarioState, no globals, no
 * N64 headers, and deliberately no <string.h> either -- mirroring
 * qrcodegen.c's own hand-rolled qr_memset precedent (a byte-zeroing loop,
 * not the real libc call), so this file keeps compiling unmodified on the
 * ROM-side GCC toolchain (whose -nostdinc build doesn't guarantee a hosted
 * <string.h>) and, a second time, into tools/pipeline_test, exercising the
 * four acceptance-critical behaviors below on synthetic input sequences
 * without an emulator:
 *
 *   (a) holding A across qr_display_present() (i.e. the same press that
 *       triggered the star dance) does NOT dismiss -- a fresh press
 *       requires a RELEASE first;
 *   (b) release-then-press held for QR_DISPLAY_MIN_HOLD_FRAMES consecutive
 *       frames DOES dismiss;
 *   (c) after dismiss, the held bitmap buffer is erased (all-zero);
 *   (d) a qr_display_present() attempt after a dismiss is rejected.
 *
 * The thin, non-host-testable N64 shell (real controller input, the real
 * renderer, real time-stop coordination) lives in qr_display_n64.h/.c, NOT
 * here -- exactly mirroring qr_render.h/qr_render_n64.h's own split (#32).
 */

/*
 * Debounce: after qr_display_present(), A must be seen RELEASED at least
 * once before a fresh press begins counting -- so the same A press that
 * triggered the star dance (already held down the instant the QR appears)
 * can never itself dismiss it. Once a fresh press is seen, it must be held
 * for this many consecutive frames before it dismisses: a minimum hold, not
 * just an edge, so a single-frame flicker on real hardware can't dismiss it
 * either.
 */
#define QR_DISPLAY_MIN_HOLD_FRAMES 3

typedef struct QrDisplayState {
    /* The bitmap currently on screen, held here (not just referenced) so it
     * can be erased in place on dismiss (see qr_display_update()). */
    pipeline_u8 bitmap[PIPELINE_BUILT_QR_BITMAP_SIZE];
    int active;        /* nonzero while a QR is currently being displayed. */
    int everPresented;  /* nonzero once qr_display_present() has ever
                          * succeeded on this state -- the "never
                          * re-summonable in this session" latch. Never
                          * cleared once set. */
    int seenRelease;    /* nonzero once A has been observed NOT held at
                          * least once since the most recent
                          * qr_display_present(). */
    int pressFrames;    /* consecutive frames A has been held since the
                          * release-then-press edge that started counting;
                          * reset to 0 whenever A is not held. */
} QrDisplayState;

/*
 * qr_display_init: resets state to its startup values -- not active, never
 * yet presented. Call once per session (mirrors qr_render's lack of
 * persistent state: this struct's lifetime IS the persistent state).
 */
void qr_display_init(QrDisplayState *state);

/*
 * qr_display_present: copies bitmap into state and enters the display
 * state. Returns nonzero (true) on success. Returns 0 (false) -- copying
 * nothing, changing nothing -- if a QR has ALREADY been presented once on
 * this state (state->everPresented: the never-re-summonable invariant) or
 * if a QR is already active. Both save flows (the exit course-complete
 * menu site and the no-exit DIALOG_013/014 site) call this same function on
 * ONE shared state, so the invariant lives once instead of being
 * re-implemented per call site.
 */
int qr_display_present(QrDisplayState *state, const pipeline_u8 bitmap[PIPELINE_BUILT_QR_BITMAP_SIZE]);

/*
 * qr_display_is_active: nonzero while a QR is currently being displayed.
 * Callers use this to know whether to keep pumping qr_display_update() and
 * rendering state->bitmap every frame, and when to resume normal play once
 * it returns 0 after a dismiss.
 */
int qr_display_is_active(const QrDisplayState *state);

/*
 * qr_display_update: advances the debounce state machine by exactly one
 * frame. aButtonHeld is nonzero iff A is held THIS frame -- the raw,
 * un-debounced controller reading; all debouncing is this function's job,
 * not the caller's.
 *
 * Returns nonzero (true) on the exact frame the QR is dismissed: A must
 * have been observed released at least once since qr_display_present()
 * (so the press that triggered the star dance cannot itself dismiss it),
 * then held for QR_DISPLAY_MIN_HOLD_FRAMES consecutive frames. On that
 * frame, state->bitmap is erased byte-by-byte to all zero and
 * state->active is cleared; state->everPresented stays set, so
 * qr_display_present() can never succeed again on this state.
 *
 * Returns 0 on every other frame, including every frame the state is not
 * currently active (a harmless no-op call).
 */
int qr_display_update(QrDisplayState *state, int aButtonHeld);

#endif /* QR_DISPLAY_H */

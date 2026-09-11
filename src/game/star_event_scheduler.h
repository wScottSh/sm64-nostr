#ifndef STAR_EVENT_SCHEDULER_H
#define STAR_EVENT_SCHEDULER_H

/*
 * The capture@grab -> build@cover PURE scheduler core (spec #96, sub-issues
 * #145 and #146). Parent spec #96's Implementation Decisions call for
 * splitting capture from build so the heavy build_event() call (schnorr
 * sign + QR encode, ~112us on host, ~1-2 frames on real hardware -- see
 * #96's Root cause) never runs on the star-grab frame, only later, under
 * cover, once per grab -- for BOTH star flows (no-exit stars, #145; exit
 * stars, #146). This module is the ONE pure module that owns *when* the
 * glue (src/game/interaction.c's interact_star_or_key, src/game/
 * mario_actions_cutscene.c's general_star_dance_handler, src/game/
 * level_update.c's play_mode_change_level) is allowed to run that heavy call
 * -- mirroring qr_display.h/qr_cycle.h's own pure-core convention exactly:
 * no MarioState, no globals, no N64 headers, no <string.h>, compiled
 * unmodified a second time into tools/pipeline_test. One state instance
 * serves both flows: a real grab is always exactly one flow or the other
 * (INT_SUBTYPE_NO_EXIT is a property of the star object), so there is never
 * a second capture in flight to disambiguate -- the phase machine below has
 * no concept of "which flow" at all, only "captured" vs. "built".
 *
 * The core does NOT perform the build itself and does NOT hold a
 * StarCapture, a key, or a BuiltEvent -- it only tracks phase. The glue
 * still owns the capture data (interaction.c's file-scope
 * sPipelineCapturedStar, filled at grab) and the built-event hand-off
 * (interaction.c's existing sPipelinePendingEvent/sPipelinePendingValid,
 * qr_pending_star_event.h), and still makes the actual build_event() call;
 * this core only answers "should I build right now?" and "did that build
 * ever happen and succeed?".
 *
 * Each of the functions below corresponds to exactly one glue call site,
 * itself corresponding to exactly one kind of frame event -- so driving this
 * core with a sequence of calls IS driving it with "per-frame phase
 * signals" (parent spec #96's Testing Decisions wording): a star grab (exit
 * or no-exit) calls star_event_scheduler_capture() once; a key grab (or any
 * grab that must invalidate a previous, not-yet-built capture) calls
 * star_event_scheduler_reset() once; that flow's own cover frame (no-exit:
 * the enable_time_stop() frame in general_star_dance_handler, spec #145;
 * exit: play_mode_change_level's post-fade, static WARP_OP_STAR_EXIT
 * branch, spec #146 -- see that function's own comment for exactly what's
 * on screen at that point and why it, not the delayed-warp timer's own
 * zero frame one frame earlier, is the right frame) polls
 * star_event_scheduler_poll_build() once and, if it returns
 * true, calls build_event() and reports the outcome
 * via star_event_scheduler_report_build_result() before that frame ends;
 * every other frame calls nothing, leaving phase unchanged.
 *
 * Observable contract (spec #145/#146's acceptance criteria / parent #96's
 * Testing Decisions), all pinned by tools/pipeline_test/main.c, for BOTH
 * flows alike -- neither flow gets its own bespoke rule, because the core
 * itself can't tell them apart:
 *   (a) a build is never requested on the grab frame -- capture() alone
 *       never returns a build-now signal (it returns nothing at all);
 *   (b) a build is requested exactly once, on/before the cover frame --
 *       poll_build() returns true the FIRST time it is called while a
 *       capture is pending, and false on every call after that (including a
 *       second call the very same frame), until the next capture() call;
 *   (c) it reports ready before the display/take site -- is_ready() is
 *       queryable synchronously, immediately after
 *       report_build_result(state, 1), with no frame delay;
 *   (d) a build-failure leaves the same resume state as today --
 *       report_build_result(state, 0) leaves is_ready() false and a later
 *       poll_build() still false (no retry), matching build_event()'s own
 *       "astronomically unlikely, degrade with no QR" contract
 *       (build_event.h);
 *   (e) a Bowser-key grab requests no build and leaves no valid pending
 *       event -- reset() unconditionally returns phase to idle: is_ready()
 *       is false and a subsequent poll_build() returns false, with no
 *       lingering captured-but-unbuilt state to accidentally build later.
 */
typedef enum StarEventSchedulerPhase {
    STAR_EVENT_SCHEDULER_IDLE = 0,      /* nothing captured; nothing to build */
    STAR_EVENT_SCHEDULER_CAPTURED,      /* captured-not-yet-built (capture@grab happened,
                                          * build@cover has not been requested yet) */
    STAR_EVENT_SCHEDULER_BUILD_REQUESTED, /* poll_build() has told the glue to build;
                                            * waiting on report_build_result() */
    STAR_EVENT_SCHEDULER_READY,         /* build succeeded; event is valid and ready to take */
    STAR_EVENT_SCHEDULER_FAILED         /* build failed; degrade with no QR, exactly like today */
} StarEventSchedulerPhase;

typedef struct StarEventSchedulerState {
    StarEventSchedulerPhase phase;
} StarEventSchedulerState;

/*
 * star_event_scheduler_init: resets to the startup phase (idle, nothing
 * captured). Provided for callers that need an explicit, guaranteed-idle
 * starting state -- host tests construct one per test case this way. The
 * ROM glue (interaction.c) deliberately does NOT call this: its state lives
 * in a file-scope static, and STAR_EVENT_SCHEDULER_IDLE is that struct's
 * zero value, so BSS zero-init already leaves it correctly idle at boot,
 * exactly like sPipelinePendingEvent/sPipelinePendingValid rely on the same
 * zero-init rather than an explicit call -- see interaction.c's own comment
 * on sPipelineScheduler for why an explicit lazy-init call there would
 * actually be wrong (it could stomp an already-captured phase).
 */
void star_event_scheduler_init(StarEventSchedulerState *state);

/*
 * star_event_scheduler_capture: call exactly once, at the grab frame, for a
 * real star grab whose build is meant to be deferred -- EVERY real star
 * grab, as of spec #146 (a no-exit star, spec #145's original case, or an
 * exit star). Moves to the CAPTURED phase from ANY prior phase -- a fresh
 * grab always supersedes whatever was pending before, mirroring
 * interaction.c's existing "reset the hand-off unconditionally on every
 * grab" discipline. Never itself signals a build: the grab frame never sees
 * a build-now response from this module, by construction (it has no return
 * value).
 */
void star_event_scheduler_capture(StarEventSchedulerState *state);

/*
 * star_event_scheduler_reset: call at any grab that must invalidate a
 * previously captured-but-not-yet-built event without building it -- a
 * Bowser key grab (spec #145 acceptance criterion: keys build nothing and
 * leave no valid pending event). Moves to IDLE from any phase. Idempotent:
 * calling it when already idle is a harmless no-op.
 */
void star_event_scheduler_reset(StarEventSchedulerState *state);

/*
 * star_event_scheduler_poll_build: call once per frame at that grab's own
 * flow's cover frame (no-exit: general_star_dance_handler's
 * enable_time_stop() frame, spec #145; exit: play_mode_change_level's
 * post-fade, static WARP_OP_STAR_EXIT branch, spec #146). Returns
 * nonzero exactly the first time it is called while a capture is pending
 * (CAPTURED), moving to BUILD_REQUESTED so a second call -- same frame or a
 * later one -- returns 0 until the next capture(). The caller MUST call
 * build_event() and report the outcome via report_build_result() before
 * relying on is_ready() again. Returns 0 for every other phase (idle,
 * already requested, ready, failed) -- a harmless, repeatable no-op,
 * mirroring qr_display_update()'s own "no-op when inactive" convention --
 * which is exactly what lets BOTH flows' cover-frame call sites poll this
 * same shared state unconditionally: whichever flow's grab it wasn't finds
 * nothing pending and no-ops.
 */
int star_event_scheduler_poll_build(StarEventSchedulerState *state);

/*
 * star_event_scheduler_report_build_result: the glue's report of the
 * build_event() call it just made because poll_build() returned nonzero.
 * success nonzero moves BUILD_REQUESTED -> READY; success zero (a
 * build_event() failure -- astronomically unlikely, see build_event.h)
 * moves BUILD_REQUESTED -> FAILED, with no retry. Calling this when the
 * phase is not BUILD_REQUESTED (a caller bug: report without a preceding
 * poll_build() == true) is a defensive no-op, changing nothing.
 */
void star_event_scheduler_report_build_result(StarEventSchedulerState *state, int success);

/*
 * star_event_scheduler_is_ready: nonzero exactly when phase == READY -- the
 * build succeeded and the event is valid to hand to the take/display site.
 * False for every other phase, including FAILED (degrade with no QR,
 * exactly like today's grab-frame build_event() failure path).
 *
 * The ROM glue itself never calls this: report_build_result()'s caller
 * (interaction.c's pipeline_build_pending_star_event_if_captured()) already
 * knows the build's own success/failure right there and sets
 * sPipelinePendingValid directly from it -- that flag, not this function,
 * is what pipeline_take_pending_star_event() actually consults. This
 * function exists so the phase machine's "ready" contract (acceptance
 * criterion (c): ready is observable before the display/take site, with no
 * frame delay) is itself directly host-testable, independent of any glue
 * bookkeeping.
 */
int star_event_scheduler_is_ready(const StarEventSchedulerState *state);

#endif /* STAR_EVENT_SCHEDULER_H */

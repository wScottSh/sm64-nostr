#ifndef QR_PENDING_STAR_EVENT_H
#define QR_PENDING_STAR_EVENT_H

#include "pipeline/build_event.h"

/*
 * The capture@grab -> build@cover -> display@park bridge (spec #24,
 * sub-issue #33; capture/build split by spec #96, sub-issues #145/#146).
 * interact_star_or_key (interaction.c, sub-issue #31; #145/#146) only
 * CAPTURES a StarCapture at grab now and holds it in a file-static global
 * there -- it no longer builds a BuiltEvent synchronously at grab for
 * either star flow. The actual build_event() call happens later, at that
 * flow's own cover frame, via pipeline_build_pending_star_event_if_captured()
 * below; display happens later still, at park time, from the two save-flow
 * sites qr_display glue replaces (mario_actions_cutscene.c's
 * act_exit_land_save_dialog() and general_star_dance_handler()), once the
 * star dance/exit animation finishes parking Mario.
 *
 * Deliberately its OWN tiny header, not folded into interaction.h:
 * interaction.h is included by ~20 other src/game/*.c translation units
 * that have nothing to do with the pipeline, and pulling in
 * pipeline/build_event.h (which in turn pulls in the BUILD-GENERATED
 * format_descriptor.h) from there would make every one of those objects
 * depend on that generated header too -- the exact hazard the root
 * Makefile's per-object PIPELINE_FORMAT_DESCRIPTOR_H prerequisite comments
 * (interaction.o, qr_render.o, qr_render_n64.o) already call out explicitly.
 * Keeping this bridge in its own header confines that dependency to just
 * the objects that actually need it -- interaction.o (defines it),
 * mario_actions_cutscene.o and, as of #146, level_update.o (both consume
 * it). No per-object Makefile prerequisite is needed for any of the three:
 * the root Makefile's single order-only guard
 * ($(...O_FILES): | $(PIPELINE_GENERATED_HEADERS)) already covers every
 * consumer of every generated pipeline header, present or future -- see
 * its own comment ("New consumers need no edit here").
 */

/*
 * pipeline_take_pending_star_event: returns nonzero and copies the held
 * event into *out if a real star grab (never a Bowser key -- keys never
 * reach the build_event() call at all, see interact_star_or_key) built one
 * since the last call. Returns 0, leaving *out untouched, otherwise --
 * including for every key grab, and for a second call before the next star
 * grab (this is a one-shot take, not a peek: the pending flag is cleared
 * either way, so a stale event from an earlier grab can never be read
 * twice).
 */
int pipeline_take_pending_star_event(BuiltEvent *out);

/*
 * pipeline_build_pending_star_event_if_captured: the deferred-build glue
 * shared by BOTH star flows (spec #96, sub-issues #145 and #146). Call
 * exactly once, from that flow's own cover frame -- the no-exit flow's
 * enable_time_stop() frame (general_star_dance_handler,
 * mario_actions_cutscene.c) or the exit flow's post-fade, static cover
 * frame (play_mode_change_level's WARP_OP_STAR_EXIT branch, level_update.c
 * -- see its own comment for exactly what's on screen at that point and
 * why it, not the delayed-warp timer's own zero frame one frame earlier,
 * is the right frame) -- BEFORE calling pipeline_take_pending_star_event().
 *
 * If interact_star_or_key captured a star grab (exit or no-exit) that
 * hasn't been built yet, this runs the (heavy) build_event() call now --
 * exactly once, per the pure scheduler core's own contract
 * (star_event_scheduler.h) -- and fills the SAME sPipelinePendingEvent/
 * sPipelinePendingValid hand-off pipeline_take_pending_star_event() already
 * reads, so that function and its callers need no changes at all: on
 * success the event becomes valid and ready to take on this same frame; on
 * failure (build_event() failure -- astronomically unlikely, see
 * build_event.h) the hand-off is left/cleared invalid, degrading exactly
 * like the old grab-frame failure path used to, just discovered later, at
 * the cover frame.
 *
 * A harmless no-op on every call with nothing captured-and-unbuilt: no
 * grab yet, a key grab (which resets the capture), or a grab whose build
 * already ran. Both real call sites are naturally exclusive by construction
 * -- a no-exit grab's dance action never reaches WARP_OP_STAR_EXIT, and an
 * exit grab's dance action never reaches enable_time_stop() -- not because
 * this function or the scheduler enforces it. One documented exception: a
 * GRAND star grab also captures here (interact_star_or_key does not
 * special-case it) but its own action (ACT_JUMBO_STAR_CUTSCENE) reaches
 * NEITHER cover frame, ever, so that capture can be left sitting in the
 * scheduler's CAPTURED phase indefinitely -- harmlessly: it is always
 * superseded by the next real grab's own capture()/reset() call before
 * either cover frame's WARP_OP_STAR_EXIT/enable_time_stop() gate could ever
 * poll it (see play_mode_change_level's own comment on why its
 * WARP_OP_STAR_EXIT gate is load-bearing, not cosmetic, for exactly this
 * reason). Returns the resulting sPipelinePendingValid (nonzero iff an
 * event is now valid and pending) -- callers that don't need it (both of
 * today's call sites) can ignore it.
 */
int pipeline_build_pending_star_event_if_captured(void);

#endif /* QR_PENDING_STAR_EVENT_H */

#ifndef QR_PENDING_STAR_EVENT_H
#define QR_PENDING_STAR_EVENT_H

#include "pipeline/build_event.h"

/*
 * The capture@grab -> display@park bridge (spec #24, sub-issue #33).
 * interact_star_or_key (interaction.c, sub-issue #31) builds a BuiltEvent
 * synchronously at grab and holds it in a file-static global there; display
 * happens several frames LATER, at park time, from the two save-flow sites
 * qr_display glue replaces (mario_actions_cutscene.c's
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
 * mario_actions_cutscene.o (consumes it) -- which the Makefile lists
 * prerequisites for accordingly.
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
 * pipeline_build_pending_star_event_if_captured: the no-exit flow's
 * deferred-build glue (spec #96, sub-issue #145). Call exactly once, from
 * the no-exit flow's cover frame (general_star_dance_handler's
 * enable_time_stop() frame, mario_actions_cutscene.c), BEFORE calling
 * pipeline_take_pending_star_event().
 *
 * If interact_star_or_key captured a no-exit star grab that hasn't been
 * built yet, this runs the (heavy) build_event() call now -- exactly once,
 * per the pure scheduler core's own contract (star_event_scheduler.h) --
 * and fills the SAME sPipelinePendingEvent/sPipelinePendingValid hand-off
 * pipeline_take_pending_star_event() already reads, so that function and
 * its caller need no changes at all: on success the event becomes valid and
 * ready to take on this same frame; on failure (build_event() failure --
 * astronomically unlikely, see build_event.h) the hand-off is left/cleared
 * invalid, degrading exactly like today's grab-frame failure path, just
 * discovered a few frames later.
 *
 * A harmless no-op on every other call: nothing captured-and-unbuilt (no
 * grab yet, an exit-star grab which never defers, a key grab which resets
 * the capture, or a grab whose build already ran). Returns the resulting
 * sPipelinePendingValid (nonzero iff an event is now valid and pending) --
 * callers that don't need it (today's single call site) can ignore it.
 */
int pipeline_build_pending_star_event_if_captured(void);

#endif /* QR_PENDING_STAR_EVENT_H */

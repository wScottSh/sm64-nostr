/*
 * See star_event_scheduler.h. Pure C89 (matching src/pipeline/'s and
 * qr_display.c's own convention): no MarioState, no globals, no N64
 * headers, no <string.h>. Compiled unmodified into both the ROM build
 * (src/game is a SRC_DIRS entry) and, a second time, into
 * tools/pipeline_test, so the capture/build-once/ready ordering is a real,
 * exercised seam, not something only verifiable on real hardware.
 */

#include "star_event_scheduler.h"

void star_event_scheduler_init(StarEventSchedulerState *state) {
    state->phase = STAR_EVENT_SCHEDULER_IDLE;
}

void star_event_scheduler_capture(StarEventSchedulerState *state) {
    state->phase = STAR_EVENT_SCHEDULER_CAPTURED;
}

void star_event_scheduler_reset(StarEventSchedulerState *state) {
    state->phase = STAR_EVENT_SCHEDULER_IDLE;
}

int star_event_scheduler_poll_build(StarEventSchedulerState *state) {
    if (state->phase != STAR_EVENT_SCHEDULER_CAPTURED) {
        return 0;
    }
    state->phase = STAR_EVENT_SCHEDULER_BUILD_REQUESTED;
    return 1;
}

void star_event_scheduler_report_build_result(StarEventSchedulerState *state, int success) {
    if (state->phase != STAR_EVENT_SCHEDULER_BUILD_REQUESTED) {
        return;
    }
    state->phase = success ? STAR_EVENT_SCHEDULER_READY : STAR_EVENT_SCHEDULER_FAILED;
}

int star_event_scheduler_is_ready(const StarEventSchedulerState *state) {
    return state->phase == STAR_EVENT_SCHEDULER_READY;
}

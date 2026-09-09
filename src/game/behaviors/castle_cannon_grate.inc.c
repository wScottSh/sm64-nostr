// castle_cannon_grate.inc.c

void bhv_castle_cannon_grate_init(void) {
    // Sandbox seam B: the castle-grounds cannon grill (bhvHiddenAt120Stars) is a
    // star-count access gate -- vanilla only deactivates it, exposing the already-
    // open cannon beneath, once total stars reach 120. Route the >= 120 comparison
    // through save_file_star_gate_is_open() (always TRUE) so the grill is removed on
    // a fresh save and the outside-castle cannon is reachable at 0 stars, matching
    // the other star-count gates. Force-off, not delete: the vanilla threshold read
    // stays in the tree as the predicate's first argument but no longer decides.
    if (save_file_star_gate_is_open(
            save_file_get_total_star_count(gCurrSaveFileNum - 1, COURSE_MIN - 1, COURSE_MAX - 1), 120)) {
        o->activeFlags = ACTIVE_FLAG_DEACTIVATED;
    }
}

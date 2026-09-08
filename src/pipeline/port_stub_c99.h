#ifndef PIPELINE_PORT_STUB_C99_H
#define PIPELINE_PORT_STUB_C99_H

/*
 * Stand-in for the eventual C99 internal ports (SHA-256, secp256k1 Schnorr,
 * qrcodegen -- see spec #24). Declared here in plain C89-compatible form;
 * only port_stub_c99.c itself requires C99, never its callers.
 *
 * As of sub-issue #30, build_event() no longer calls port_stub_marker() --
 * its real body chains the actual ported seams (event_id.h/schnorr_adapter.h/
 * pack_adapter.h/qr_adapter.h) those C99 ports landed behind instead. This
 * function/TU stays compiled and linked into both the ROM's
 * pipeline-rom-objects and the host test tool (see the root Makefile's
 * PIPELINE_C99_PORT_SRC and tools/pipeline_test/Makefile's SRCS) purely as
 * the still-live proof that the C99 carve-out compilation arrangement
 * itself (sub-issue #25's walking-skeleton concern) keeps working -- not
 * because anything still calls it.
 */
unsigned char port_stub_marker(void);

#endif /* PIPELINE_PORT_STUB_C99_H */

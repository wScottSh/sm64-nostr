#ifndef QR_RENDER_H
#define QR_RENDER_H

/*
 * The renderer glue's PURE core (spec #24, sub-issue #32). Consumes a
 * finished qr_bitmap (build_event.h's BuiltEvent::qr_bitmap, produced by
 * the pipeline's qr_adapter.h -- see that header for the fixed version
 * 6 / ECC MEDIUM choice, 41x41 modules) and blits it into a caller-supplied
 * plain RGBA16 pixel array.
 *
 * This file is deliberately pure, mirroring src/pipeline/'s own pure-core
 * convention: no MarioState, no globals, no N64 headers (no ultra64.h, no
 * PR/*.h). It #includes only pipeline/qr_adapter.h, itself pure, for
 * pipeline_qr_get_size()/pipeline_qr_get_module() (the bitmap's own public
 * read accessors -- see qr_adapter.h's header comment) and
 * PIPELINE_QR_MODULE_SIZE. That keeps this file host-compilable, unmodified,
 * a second time into tools/pipeline_test -- exactly like src/pipeline/*.c --
 * so the pixel-placement math (module -> pixel-rect mapping, integer scale,
 * fixed quiet zone) can be exercised by a host test that renders into an
 * in-memory buffer, reconstructs the module grid by reading pixels back,
 * and feeds that grid to the existing host QR decoder (qr_host_decode.h) to
 * confirm it decodes to the exact packed payload -- all without a camera or
 * emulator (spec #24 acceptance criterion #16's spirit, and #32's own
 * "encoding never fused into the write" requirement: this function only
 * READS the bitmap via the same accessors any external reader would use;
 * it never calls pipeline_qr_encode() or touches qrcodegen.c).
 *
 * The thin, non-testable N64 shell around this pure function -- computing
 * the uncached (|0xa0000000) framebuffer pointer, mirroring
 * crash_screen_init()'s own non-EU addressing precedent
 * (src/game/crash_screen.c), applied unconditionally on every version
 * since this shell's input is always a physical address (see
 * qr_render_n64.h/.c for the full reasoning) -- lives in
 * qr_render_n64.h/.c, NOT here, so this header/TU never needs ultra64.h
 * and stays host-compilable.
 *
 * Render parameters (spec #24, sub-issue #32): fixed integer module scale
 * of 4 framebuffer pixels per QR module, and a fixed quiet-zone border of
 * 4 modules on every side (the minimum quiet zone the QR spec itself
 * recommends around a symbol, chosen here as the FIXED border acceptance
 * criterion #32 calls for). For the pipeline's fixed version-6 QR
 * (PIPELINE_QR_MODULE_SIZE == 41 modules, see qr_adapter.h):
 *   grid width/height  = 41 + 2*4  = 49 modules
 *   image width/height = 49 * 4    = 196 pixels
 * which fits comfortably inside the N64's 320x240 RGBA16 framebuffer
 * (config.h's SCREEN_WIDTH/SCREEN_HEIGHT) with room to spare (124 px of
 * horizontal margin, 44 px of vertical margin) -- centered by the origin
 * computed in qr_render_blit_rgba16() itself, so a caller only ever needs
 * to supply the framebuffer's own actual width/height.
 */

#include "pipeline/qr_adapter.h"

#define QR_RENDER_MODULE_SCALE_PX     4
#define QR_RENDER_QUIET_ZONE_MODULES  4

#define QR_RENDER_GRID_SIZE_MODULES \
    (PIPELINE_QR_MODULE_SIZE + 2 * QR_RENDER_QUIET_ZONE_MODULES)
#define QR_RENDER_IMAGE_SIZE_PX \
    (QR_RENDER_GRID_SIZE_MODULES * QR_RENDER_MODULE_SCALE_PX)

/*
 * RGBA16 (5R/5G/5B/1A) colors, matching crash_screen_draw_glyph's own
 * literal encoding exactly (src/game/crash_screen.c): 0xFFFF is opaque
 * white, 0x0001 is opaque black (RGB all zero, alpha bit set so the pixel
 * isn't treated as transparent by the VI).
 */
#define QR_RENDER_WHITE_RGBA16 ((unsigned short)0xFFFFu)
#define QR_RENDER_BLACK_RGBA16 ((unsigned short)0x0001u)

/*
 * qr_render_blit_rgba16: pure pixel-placement core. Blits qrBitmap (a
 * pipeline_qr_encode()-produced bitmap; only read via
 * pipeline_qr_get_size()/pipeline_qr_get_module(), never re-encoded) into
 * framebuffer, a plain row-major RGBA16 pixel array of fbWidth x fbHeight
 * pixels (stride == fbWidth, no padding -- matching crash_screen's own
 * framebuffer layout). The QR image (quiet zone + modules) is centered
 * within fbWidth x fbHeight; every module is written as an exact
 * QR_RENDER_MODULE_SCALE_PX x QR_RENDER_MODULE_SCALE_PX block, and the
 * quiet-zone border pixels are written as QR_RENDER_WHITE_RGBA16.
 *
 * Caller must ensure fbWidth/fbHeight are each >= QR_RENDER_IMAGE_SIZE_PX;
 * the fixed N64 320x240 framebuffer already satisfies this by construction
 * (see this header's comment above). This function does not clip a
 * partially-fitting image, but it does refuse to write anything at all
 * (returns immediately) if the RUNTIME grid size read from qrBitmap[0]
 * (pipeline_qr_get_size()) would make the image not fit fbWidth x
 * fbHeight, or is non-positive -- a defensive bound against a corrupt or
 * never-built bitmap, since that size is caller/runtime data, not a
 * compile-time constant.
 */
void qr_render_blit_rgba16(const pipeline_u8 *qrBitmap, unsigned short *framebuffer,
                            int fbWidth, int fbHeight);

#endif /* QR_RENDER_H */

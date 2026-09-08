/*
 * See qr_render.h. Pure C89 (matching src/pipeline/'s own convention): no
 * MarioState, no globals, no N64 headers. Compiled unmodified into both the
 * ROM build (src/game is a SRC_DIRS entry) and, a second time, the host
 * test tool (tools/pipeline_test), so its pixel-placement math is a real,
 * exercised seam.
 */

#include "qr_render.h"

void qr_render_blit_rgba16(const pipeline_u8 *qrBitmap, unsigned short *framebuffer,
                            int fbWidth, int fbHeight)
{
    int gridSizeModules = pipeline_qr_get_size(qrBitmap);
    int imageSizePx = (gridSizeModules + 2 * QR_RENDER_QUIET_ZONE_MODULES) * QR_RENDER_MODULE_SCALE_PX;
    int originX = (fbWidth - imageSizePx) / 2;
    int originY = (fbHeight - imageSizePx) / 2;
    int quietPx = QR_RENDER_QUIET_ZONE_MODULES * QR_RENDER_MODULE_SCALE_PX;
    int moduleAreaPx = gridSizeModules * QR_RENDER_MODULE_SCALE_PX;
    int px, py;
    int row, col;

    /*
     * Defensive bound: gridSizeModules comes from qrBitmap[0] (a runtime,
     * caller-supplied byte, not a compile-time constant -- see
     * pipeline_qr_get_size()/qr_adapter.h), so a corrupt or never-built
     * bitmap could in principle report a size large enough to push
     * imageSizePx past fbWidth/fbHeight, or non-positive. Writing in that
     * case would walk off the caller-supplied framebuffer array (in the
     * ROM's case, silently corrupting unrelated RDRAM through the uncached
     * window). Refuse to write anything rather than risk that -- this is
     * the only validation this pure function performs; it does not clip a
     * partially-fitting image.
     */
    if (gridSizeModules <= 0 || imageSizePx > fbWidth || imageSizePx > fbHeight) {
        return;
    }

    /*
     * Paint only the fixed quiet-zone RING (top/bottom full-width strips,
     * plus left/right strips alongside the module area) white first, so
     * the quiet-zone border ends up exactly QR_RENDER_WHITE_RGBA16
     * regardless of whatever was already in the framebuffer, without
     * separately re-writing the module area the loop below is about to
     * cover anyway (each module -- light or dark -- is written exactly
     * once, avoiding a redundant pass over ~2/3 of the image's pixels,
     * every one of them an uncached, write-buffer-bypassing store).
     */
    for (py = 0; py < quietPx; py++) {
        unsigned short *topRow = framebuffer + (originY + py) * fbWidth + originX;
        unsigned short *bottomRow = framebuffer + (originY + quietPx + moduleAreaPx + py) * fbWidth + originX;
        for (px = 0; px < imageSizePx; px++) {
            topRow[px] = QR_RENDER_WHITE_RGBA16;
            bottomRow[px] = QR_RENDER_WHITE_RGBA16;
        }
    }
    for (py = 0; py < moduleAreaPx; py++) {
        unsigned short *leftRow = framebuffer + (originY + quietPx + py) * fbWidth + originX;
        unsigned short *rightRow = leftRow + quietPx + moduleAreaPx;
        for (px = 0; px < quietPx; px++) {
            leftRow[px] = QR_RENDER_WHITE_RGBA16;
            rightRow[px] = QR_RENDER_WHITE_RGBA16;
        }
    }

    for (row = 0; row < gridSizeModules; row++) {
        int blockY = originY + (QR_RENDER_QUIET_ZONE_MODULES + row) * QR_RENDER_MODULE_SCALE_PX;
        for (col = 0; col < gridSizeModules; col++) {
            int blockX = originX + (QR_RENDER_QUIET_ZONE_MODULES + col) * QR_RENDER_MODULE_SCALE_PX;
            unsigned short color = pipeline_qr_get_module(qrBitmap, col, row)
                                        ? QR_RENDER_BLACK_RGBA16
                                        : QR_RENDER_WHITE_RGBA16;
            int dy, dx;

            for (dy = 0; dy < QR_RENDER_MODULE_SCALE_PX; dy++) {
                unsigned short *rowPtr = framebuffer + (blockY + dy) * fbWidth + blockX;
                for (dx = 0; dx < QR_RENDER_MODULE_SCALE_PX; dx++) {
                    rowPtr[dx] = color;
                }
            }
        }
    }
}

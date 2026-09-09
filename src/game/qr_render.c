/*
 * See qr_render.h. Pure C89 (matching src/pipeline/'s own convention): no
 * MarioState, no globals, no N64 headers. Compiled unmodified into both the
 * ROM build (src/game is a SRC_DIRS entry) and, a second time, the host
 * test tool (tools/pipeline_test), so its placement math is a real,
 * exercised seam. The dialog font is injected (QrRenderFont) so this core
 * never touches segmented ROM data -- see ADR-0004.
 */

#include "qr_render.h"

unsigned char qr_render_ascii_to_dialog(char c) {
    if (c >= '0' && c <= '9') {
        return (unsigned char) (0x00 + (c - '0'));
    }
    if (c >= 'A' && c <= 'Z') {
        return (unsigned char) (0x0A + (c - 'A'));
    }
    if (c >= 'a' && c <= 'z') {
        return (unsigned char) (0x24 + (c - 'a'));
    }
    switch (c) {
        case ' ':    return 0x9E;                              /* space       */
        case '!':    return 0xF2;                              /* exclamation */
        case '.':    return 0x3F;                              /* period      */
        case ',':    return 0x6F;                              /* comma       */
        case '\'':   return 0x3E;                              /* apostrophe  */
        case '\x01': return QR_RENDER_DIALOG_CODE_A_BUTTON;    /* [A] button  */
        default:     return QR_RENDER_DIALOG_CODE_SPACE;       /* safe blank  */
    }
}

/*
 * layout_segment: word-wrap one ASCII copy segment to QR_RENDER_DLG_USABLE_PX
 * starting at line `line`, and (when out != NULL) emit a glyph op per
 * non-space char at its wrapped position. Returns the next free line index.
 * Called first with out == NULL (pure line counting, to size the box) and
 * again with out != 0 (emit) -- both paths run identical wrap logic, so
 * the emitted glyph rows can never disagree with the counted box height.
 */
static int layout_segment(const char *s, const QrRenderFont *font,
                          int boxX, int contentTopY, int line, QrRenderLayout *out) {
    int usable = QR_RENDER_DLG_USABLE_PX;
    int inset = QR_RENDER_DLG_BOX_INSET;
    int spaceW = font->charWidths[QR_RENDER_DIALOG_CODE_SPACE];
    int i = 0;
    int penX = 0;
    int lineStarted = 0;

    while (s[i] != '\0') {
        int j = i;
        int wordW = 0;
        int k;

        while (s[j] != '\0' && s[j] != ' ') {
            wordW += font->charWidths[qr_render_ascii_to_dialog(s[j])];
            j++;
        }

        if (lineStarted) {
            if (penX + spaceW + wordW > usable) {
                line++;
                penX = 0;
                lineStarted = 0;
            } else {
                penX += spaceW;
            }
        }

        for (k = i; k < j; k++) {
            unsigned char code = qr_render_ascii_to_dialog(s[k]);
            if (out != 0 && out->glyphCount < QR_RENDER_MAX_GLYPHS) {
                QrRenderGlyphOp *op = &out->glyphs[out->glyphCount++];
                op->code = code;
                op->x = (short) (boxX + inset + penX);
                op->y = (short) (contentTopY + line * QR_RENDER_DLG_LINE_PITCH);
            }
            penX += font->charWidths[code];
        }
        lineStarted = 1;

        i = j;
        while (s[i] == ' ') {
            i++;
        }
    }

    return line + 1;
}

void qr_render_layout(int qrGridSizeModules, int fbWidth, int fbHeight,
                      const QrRenderFont *font,
                      const char *heading, const char *body, const char *prompt,
                      QrRenderLayout *out) {
    int qrImagePx = (qrGridSizeModules + 2 * QR_RENDER_QUIET_ZONE_MODULES)
                    * QR_RENDER_MODULE_SCALE_PX;
    int pairW = qrImagePx + QR_RENDER_PAIR_GAP_PX + QR_RENDER_DLG_BOX_W;
    int startX = (fbWidth - pairW) / 2;
    int lineCount;
    int boxH;
    int boxX;
    int boxY;
    int contentTopY;
    int line;
    int s;
    /* The three copy segments, stacked top-to-bottom, each starting a fresh
     * line -- walked identically in both passes so the counted line total
     * (which sizes the box) can't disagree with the emitted glyph rows. */
    const char *segments[3];
    segments[0] = heading;
    segments[1] = body;
    segments[2] = prompt;

    /* Pass 1: count wrapped lines to size the box (ROM formula 80*(lines/5 +
     * 0.1) == 16*lines + 8). */
    line = 0;
    for (s = 0; s < 3; s++) {
        line = layout_segment(segments[s], font, 0, 0, line, 0);
    }
    lineCount = line;
    boxH = QR_RENDER_DLG_LINE_PITCH * lineCount + 8;

    boxX = startX + qrImagePx + QR_RENDER_PAIR_GAP_PX;
    boxY = (fbHeight - boxH) / 2;
    contentTopY = boxY + QR_RENDER_DLG_BOX_TOP_PAD;

    out->qrImagePx = qrImagePx;
    out->qrX = startX;
    out->qrY = (fbHeight - qrImagePx) / 2;
    out->boxX = boxX;
    out->boxY = boxY;
    out->boxW = QR_RENDER_DLG_BOX_W;
    out->boxH = boxH;
    out->lineCount = lineCount;
    out->glyphCount = 0;

    out->fits = (qrGridSizeModules > 0)
             && (startX >= 0) && (pairW <= fbWidth)
             && (out->qrY >= QR_RENDER_OVERSCAN_PX)
             && (out->qrY + qrImagePx <= fbHeight - QR_RENDER_OVERSCAN_PX)
             && (boxY >= QR_RENDER_OVERSCAN_PX)
             && (boxY + boxH <= fbHeight - QR_RENDER_OVERSCAN_PX);

    if (!out->fits) {
        return;
    }

    /* Pass 2: emit glyph ops at their final positions. */
    line = 0;
    for (s = 0; s < 3; s++) {
        line = layout_segment(segments[s], font, boxX, contentTopY, line, out);
    }
}

void qr_render_blit_qr_at(const pipeline_u8 *qrBitmap, unsigned short *framebuffer,
                          int fbWidth, int fbHeight, int originX, int originY) {
    int gridSizeModules = pipeline_qr_get_size(qrBitmap);
    int imageSizePx = (gridSizeModules + 2 * QR_RENDER_QUIET_ZONE_MODULES)
                      * QR_RENDER_MODULE_SCALE_PX;
    int quietPx = QR_RENDER_QUIET_ZONE_MODULES * QR_RENDER_MODULE_SCALE_PX;
    int moduleAreaPx = gridSizeModules * QR_RENDER_MODULE_SCALE_PX;
    int px, py;
    int row, col;

    /*
     * Defensive bound: gridSizeModules is runtime, caller-supplied data
     * (qrBitmap[0]); refuse to write anything if a corrupt/never-built
     * bitmap would push the image outside the framebuffer, rather than walk
     * off the array (silently corrupting RDRAM through the uncached window
     * on device). Not a partial-fit clip -- all-or-nothing.
     */
    if (gridSizeModules <= 0 || originX < 0 || originY < 0
        || originX + imageSizePx > fbWidth || originY + imageSizePx > fbHeight) {
        return;
    }

    /* Quiet-zone ring, painted white first (top/bottom strips, then the
     * left/right strips beside the module area) so each module pixel below
     * is written exactly once. */
    for (py = 0; py < quietPx; py++) {
        unsigned short *topRow = framebuffer + (originY + py) * fbWidth + originX;
        unsigned short *bottomRow =
            framebuffer + (originY + quietPx + moduleAreaPx + py) * fbWidth + originX;
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

/* Darken one RGBA16 pixel toward black, keeping QR_RENDER_DLG_BOX_KEEP/255 of
 * each 5-bit channel -- the translucent-black dialog box over the frozen
 * frame (env alpha 150). Alpha bit set so the VI keeps the pixel opaque. */
static unsigned short qr_render_darken(unsigned short p) {
    int r = (p >> 11) & 0x1F;
    int g = (p >> 6) & 0x1F;
    int b = (p >> 1) & 0x1F;
    r = r * QR_RENDER_DLG_BOX_KEEP / 255;
    g = g * QR_RENDER_DLG_BOX_KEEP / 255;
    b = b * QR_RENDER_DLG_BOX_KEEP / 255;
    return (unsigned short) ((r << 11) | (g << 6) | (b << 1) | 1);
}

void qr_render_overlay_rgba16(const pipeline_u8 *qrBitmap, unsigned short *framebuffer,
                              int fbWidth, int fbHeight, const QrRenderFont *font) {
    QrRenderLayout layout;
    int gx, gy, y, x, i;

    qr_render_layout(pipeline_qr_get_size(qrBitmap), fbWidth, fbHeight, font,
                     QR_RENDER_COPY_HEADING, QR_RENDER_COPY_BODY, QR_RENDER_COPY_PROMPT,
                     &layout);
    if (!layout.fits) {
        return;
    }

    qr_render_blit_qr_at(qrBitmap, framebuffer, fbWidth, fbHeight, layout.qrX, layout.qrY);

    /* Translucent-black box. Clipped to the framebuffer defensively; the
     * layout already keeps it inside the overscan band. */
    for (y = layout.boxY; y < layout.boxY + layout.boxH; y++) {
        if (y < 0 || y >= fbHeight) {
            continue;
        }
        for (x = layout.boxX; x < layout.boxX + layout.boxW; x++) {
            if (x < 0 || x >= fbWidth) {
                continue;
            }
            framebuffer[y * fbWidth + x] = qr_render_darken(framebuffer[y * fbWidth + x]);
        }
    }

    /*
     * Authentic ia4 dialog glyphs. The game's US font glyph (main_font_lut
     * entry) is NOT a plain 8x16 image: it is stored as a 16-wide x 8-tall
     * ia4 texture (8 bytes/row, high nibble = leftmost/even texel) that the
     * in-game engine draws through gSPTextureRectangleFlip -- see segment2.c
     * dl_ia_text_tex_settings (SetTileSize S=16, T=8) and ingame_menu.c
     * render_generic_char(). The on-screen 8x16 glyph is that stored texture
     * transposed-and-flipped: on-screen pixel (gx,gy) samples stored texel
     * (storedX = 15 - gy, storedY = 7 - gx). Decoding the bytes as a plain
     * 8x16 image scrambles every glyph (the garbled-text bug). A non-zero
     * nibble is an "on" (white) pixel; blank codes (NULL glyph) draw nothing.
     */
    for (i = 0; i < layout.glyphCount; i++) {
        QrRenderGlyphOp *op = &layout.glyphs[i];
        const unsigned char *g = font->glyph(font->ctx, op->code);
        if (g == 0) {
            continue;
        }
        for (gy = 0; gy < QR_RENDER_GLYPH_H; gy++) {
            int storedX = (QR_RENDER_GLYPH_H - 1) - gy;  /* 0..15 along stored width */
            int py = op->y + gy;
            if (py < 0 || py >= fbHeight) {
                continue;
            }
            for (gx = 0; gx < QR_RENDER_GLYPH_W; gx++) {
                int storedY = (QR_RENDER_GLYPH_W - 1) - gx;  /* 0..7 stored row */
                unsigned char byte = g[storedY * (QR_RENDER_GLYPH_H / 2) + (storedX >> 1)];
                unsigned char nib = (storedX & 1) ? (byte & 0x0F)
                                                  : (unsigned char) (byte >> 4);
                int pxx = op->x + gx;
                if (nib != 0 && pxx >= 0 && pxx < fbWidth) {
                    framebuffer[py * fbWidth + pxx] = QR_RENDER_WHITE_RGBA16;
                }
            }
        }
    }
}

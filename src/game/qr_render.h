#ifndef QR_RENDER_H
#define QR_RENDER_H

/*
 * The renderer glue's PURE core (spec #24 sub-issue #32; redesigned for
 * issue #84). Consumes a finished qr_bitmap (build_event.h's
 * BuiltEvent::qr_bitmap, produced by the pipeline's qr_adapter.h -- see that
 * header for the fixed version 7 / ECC MEDIUM / fixed-mask choice, 45x45
 * modules, spec #52 sub-issue #53) and composites the on-star OVERLAY into a
 * caller-supplied plain RGBA16 pixel array: the QR flush-left, and an
 * authentic SM64 dialog box to its right (ADR-0004, "Variant A").
 *
 * This file is deliberately pure, mirroring src/pipeline/'s own pure-core
 * convention: no MarioState, no globals, no N64 headers (no ultra64.h, no
 * PR/ headers). It #includes only pipeline/qr_adapter.h, itself pure. That keeps
 * it host-compilable, unmodified, a second time into tools/pipeline_test --
 * so the placement math (2px QR + box rect + word-wrap + ia4 glyph
 * placement + overscan-safe centering) is exercised by a real host test.
 *
 * The one thing that genuinely varies across the ROM and host builds -- the
 * source of the dialog font -- is injected as a QrRenderFont seam (below),
 * so this pure core never touches segmented ROM data. On device the N64
 * shell (qr_render_n64.h/.c) supplies the game's own gDialogCharWidths +
 * main_font_lut (the SAME metrics/glyphs the in-game dialog engine uses,
 * ADR-0004); the host test supplies a fake.
 *
 * === Layout (all values from ROM source; see issue #84 / ADR-0004) ===
 * Screen 320x240; overscan-safe border 8px top & bottom (config.h). QR is
 * fixed at 2 framebuffer-px/module (a deliberate LED-monitor-first bet, to
 * be photo-tested before shipping -- docs/research/qr-onscreen-module-size.md;
 * fall back to 3px/4px via QR_RENDER_MODULE_SCALE_PX alone). For the fixed
 * v7 QR (45 modules) + a 4-module quiet zone per side (ISO min):
 *   grid  = 45 + 2*4 = 53 modules
 *   image = 53 * 2    = 106 px
 * The dialog box is the standard 143px-wide box (segment2.c/ingame_menu.c);
 * its pixel height is the ROM formula round(80 * (lines/5 + 0.1)) == a tidy
 * 16*lines + 8. QR + 6px gap + box = 106 + 6 + 143 = 255 of 320; the pair is
 * centered horizontally, the QR is centered vertically, and the box is
 * centered vertically, everything inside the 8px overscan band.
 */

#include "pipeline/qr_adapter.h"

#define QR_RENDER_MODULE_SCALE_PX     2
#define QR_RENDER_QUIET_ZONE_MODULES  4

#define QR_RENDER_GRID_SIZE_MODULES \
    (PIPELINE_QR_MODULE_SIZE + 2 * QR_RENDER_QUIET_ZONE_MODULES)
#define QR_RENDER_IMAGE_SIZE_PX \
    (QR_RENDER_GRID_SIZE_MODULES * QR_RENDER_MODULE_SCALE_PX)

/* Overscan-safe border, config.h BORDER_HEIGHT (top & bottom). */
#define QR_RENDER_OVERSCAN_PX   8

/* Dialog box + font geometry (ROM source, cited in issue #84). */
#define QR_RENDER_PAIR_GAP_PX     6     /* gap between QR and box            */
#define QR_RENDER_DLG_BOX_W       143   /* fixed box width (segment2.c)      */
#define QR_RENDER_DLG_LINE_PITCH  16    /* in-box line pitch, Y_VAL3         */
#define QR_RENDER_DLG_BOX_INSET   7     /* text inset per side -> usable 129 */
#define QR_RENDER_DLG_BOX_TOP_PAD 4     /* first line's top offset in box    */
#define QR_RENDER_GLYPH_W         8     /* dialog glyph cell width           */
#define QR_RENDER_GLYPH_H         16    /* dialog glyph cell height          */
#define QR_RENDER_DLG_USABLE_PX \
    (QR_RENDER_DLG_BOX_W - 2 * QR_RENDER_DLG_BOX_INSET)

/* Translucent-black box: env alpha 150/255 over the frozen frame, so each
 * RGB channel keeps (255-150)=105/255 of the source (ingame_menu.c:1150). */
#define QR_RENDER_DLG_BOX_KEEP  105

/* The dialog char codes this overlay's copy needs that ASCII can't spell.
 * space/'!'/'.'/',' /apostrophe are handled from ASCII; QR_RENDER_A_BUTTON
 * is the source-string sentinel that encodes to the [A] button glyph
 * (charmap.txt: '[A]' = 0x54). */
#define QR_RENDER_A_BUTTON  "\x01"
#define QR_RENDER_DIALOG_CODE_A_BUTTON  0x54
#define QR_RENDER_DIALOG_CODE_SPACE     0x9E

/* Placeholder copy (tune during impl -- issue #84). Authored ASCII; the
 * pure core encodes it to dialog char codes. */
#define QR_RENDER_COPY_HEADING  "STAR SAVED!"
#define QR_RENDER_COPY_BODY     "Scan this code to post your time to the leaderboard."
#define QR_RENDER_COPY_PROMPT   "Hold " QR_RENDER_A_BUTTON " to close"

/*
 * RGBA16 (5R/5G/5B/1A) colors, matching crash_screen_draw_glyph exactly
 * (src/game/crash_screen.c): 0xFFFF opaque white, 0x0001 opaque black
 * (RGB zero, alpha bit set so the VI treats the pixel as opaque).
 */
#define QR_RENDER_WHITE_RGBA16 ((unsigned short)0xFFFFu)
#define QR_RENDER_BLACK_RGBA16 ((unsigned short)0x0001u)

/*
 * QrRenderFont -- the injected dialog-font seam (ADR-0004). Both fields are
 * indexed by DIALOG char code (not ASCII): the game's charmap ordering,
 * where '0'..'9' == 0x00..0x09, 'A'..'Z' == 0x0A..0x23, 'a'..'z' ==
 * 0x24..0x3D, space == 0x9E, [A] == 0x54 (charmap.txt).
 *
 *   charWidths : 256-entry per-glyph advance table (gDialogCharWidths).
 *   glyph(ctx,code) : returns a pointer to that glyph's raw ia4 texture --
 *       8x16 px, 4 bits/px, row-major, 4 bytes/row, high nibble = left
 *       pixel, nibble != 0 == an "on" (white) pixel -- or NULL for a blank
 *       code. On device this resolves main_font_lut[code] via
 *       segmented_to_virtual; a NULL entry (unmapped code) draws nothing.
 */
typedef const unsigned char *(*QrRenderGlyphFn)(void *ctx, unsigned char code);

typedef struct {
    const unsigned char *charWidths; /* [256], dialog-code indexed */
    QrRenderGlyphFn glyph;
    void *ctx;
} QrRenderFont;

/* One glyph placement: dialog code + top-left of its 8x16 cell (fb px). */
typedef struct {
    unsigned char code;
    short x;
    short y;
} QrRenderGlyphOp;

#define QR_RENDER_MAX_GLYPHS  192

/*
 * QrRenderLayout -- the pure geometry plan (module-internal seam: the paint
 * path builds one, and the host tests assert against it directly, so the
 * riskiest logic -- word-wrap + overscan-safe centering -- is checked as
 * data, not reverse-engineered from pixels). All coordinates are
 * framebuffer pixels. `fits` is 0 when the pair or overscan constraints
 * fail, in which case the paint path is a no-op.
 */
typedef struct {
    int qrX, qrY, qrImagePx;
    int boxX, boxY, boxW, boxH;
    int lineCount;
    int glyphCount;
    QrRenderGlyphOp glyphs[QR_RENDER_MAX_GLYPHS];
    int fits;
} QrRenderLayout;

/*
 * qr_render_ascii_to_dialog: map one ASCII byte from the copy to its dialog
 * char code (charmap.txt). Handles A-Z, a-z, 0-9, space, '!', '.', ',',
 * apostrophe, and the QR_RENDER_A_BUTTON sentinel ('\x01' -> [A], 0x54).
 * Any other byte maps to space (a safe, visible advance). Pure; exposed so
 * the host test can pin the encoding.
 */
unsigned char qr_render_ascii_to_dialog(char c);

/*
 * qr_render_layout: pure geometry. Given the QR grid size in modules
 * (pipeline_qr_get_size()'s value, e.g. 45), the framebuffer dimensions,
 * the font (for per-char advances used by word-wrap), and the three ASCII
 * copy segments (heading / body / prompt, each starting a fresh line and
 * word-wrapped to QR_RENDER_DLG_USABLE_PX), fills *out with the full
 * placement plan. Sets out->fits = 0 (and writes no glyph ops) if the pair
 * would not fit horizontally or the QR/box would cross the overscan band.
 */
void qr_render_layout(int qrGridSizeModules, int fbWidth, int fbHeight,
                      const QrRenderFont *font,
                      const char *heading, const char *body, const char *prompt,
                      QrRenderLayout *out);

/*
 * qr_render_blit_qr_at: blit just the QR image (quiet zone + modules) with
 * its top-left at (originX, originY) into framebuffer (row-major RGBA16,
 * stride == fbWidth). Every module is an exact
 * QR_RENDER_MODULE_SCALE_PX-square block; the quiet-zone ring is
 * QR_RENDER_WHITE_RGBA16. Refuses to write anything (returns) if the
 * runtime grid size (qrBitmap[0]) is non-positive or the image would fall
 * outside the framebuffer -- a defensive bound against a corrupt/never-built
 * bitmap. Only READS qrBitmap via pipeline_qr_get_size/get_module (never
 * re-encodes).
 */
void qr_render_blit_qr_at(const pipeline_u8 *qrBitmap, unsigned short *framebuffer,
                          int fbWidth, int fbHeight, int originX, int originY);

/*
 * qr_render_overlay_rgba16: the top-level composite. Lays out the overlay
 * (using QR_RENDER_COPY_*), and if it fits: blits the QR flush-left, blends
 * the translucent-black dialog box, and blits the heading/body/prompt with
 * `font`'s real ia4 glyphs. A no-op if the layout does not fit. fbWidth/
 * fbHeight are the framebuffer dimensions (320x240 on device).
 */
void qr_render_overlay_rgba16(const pipeline_u8 *qrBitmap, unsigned short *framebuffer,
                              int fbWidth, int fbHeight, const QrRenderFont *font);

#endif /* QR_RENDER_H */

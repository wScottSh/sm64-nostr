# Star-capture QR screen: authentic dialog box via direct framebuffer blit

The bare 212×212 centered QR (scale 4, no message) is replaced by **Variant A**
(issue #84, settled by the `prototype/qr-display-layout` prototype): the QR at
**2 framebuffer-px/module** (106×106) flush-left, and an **authentic SM64 dialog
box** to its right — QR+box pair centered horizontally, box centered vertically,
all inside the 8px overscan-safe band. `QR_RENDER_MODULE_SCALE_PX` moves `4 → 2`.

"Authentic" is taken literally: the box text is drawn with the **same ia4 8×16
glyph textures** (`main_font_lut[code]`) and the **same per-char advances**
(`gDialogCharWidths`) the in-game dialog engine uses, the box height is the ROM
formula `80·(lines/5 + 0.1)`, and the box is translucent black ≈ env-alpha 150.
Nothing about the font metrics is re-invented.

## Decision: direct-blit the real font, do NOT route through the display list

The QR is composited by writing RGBA16 pixels **directly to the uncached
framebuffer** in `display_and_vsync` (`game_init.c`), *after* the display list
executes, onto the frame-behind buffer (`gPhysicalFramebuffers[sRenderedFramebuffer]`).
This blit-not-DL design already exists **on purpose**: the 3D scene re-renders
every frame and the game's triple buffering means a display-list overlay lands on
a *different* buffer, a frame out of sync with the QR. The dialog box must sit
pixel-locked beside the QR, so it is composited **the same way the QR is** — a
direct blit at the same call site — reusing the `crash_screen` direct-blit
precedent (`crash_screen.c`: framebuffer-darkening rect + glyph blit).

Rejected: rendering a real `create_dialog_box`/`print_generic_string` pass during
the capture cutscene. It is maximally authentic in mechanism but fights the
triple-buffer reason the QR blit exists, needs new per-frame DL plumbing inside a
time-stopped Mario action, and pushes the placement math out of the pure,
host-testable seam.

## Shape (see `/codebase-design`)

- **Deep module** — the pure `qr_render` core (C89, compiled a second time into
  `tools/pipeline_test`). Small interface (one paint call); large hidden
  behavior: 2px QR placement, box rect + height formula, translucent blend,
  ASCII→dialog-code encoding, word-wrap on real widths, ia4 glyph decode,
  overscan-safe centering.
- **Seam `QrRenderFont`** — the one thing that genuinely varies: `{ charWidths,
  glyph(ctx,code)→ia4 8×16, ctx }`. Two real adapters — the N64 shell
  (`gDialogCharWidths` + `main_font_lut` via `segmented_to_virtual`) and the host
  test fake — so it is a real seam, not a hypothetical one. All format knowledge
  (ia4 layout, wrap, blend, geometry) stays *pure*, behind the interface.
- **Internal seam `qr_render_layout()`** — pure geometry returning QR origin, box
  rect, and glyph draw-ops as data, so wrap + centering are asserted directly by
  the module's own tests rather than reverse-engineered from pixels.
- **Thin N64 adapter** (`qr_render_n64`) — builds the real font, resolves the
  uncached framebuffer, calls the pure paint. Small implementation.

## Consequences

- Dismiss (hold-A, 3 frames) and the present-once/re-arm-per-grab invariants in
  `qr_display*` are untouched — only what is *drawn* changes.
- The `[A]`-button prompt uses dialog code `0x54` (charmap `[A]`), space `0x9E`;
  the copy is authored ASCII and encoded to dialog codes in the pure core.
- **Not shippable from code review alone.** Issue #84's last acceptance criterion
  — an empirical off-a-real-screen photo scannability test at 2px/module — needs
  physical hardware (CRT-composite + LCD + phone decoders). 2px is a deliberate
  LED-monitor-first bet flagged *beyond the reliable CRT limit* by
  `docs/research/qr-onscreen-module-size.md`. If the photo test fails, fall back
  to 3px (LED-safe) or 4px (CRT-safe) by changing the single
  `QR_RENDER_MODULE_SCALE_PX` constant; the layout math re-centers automatically.

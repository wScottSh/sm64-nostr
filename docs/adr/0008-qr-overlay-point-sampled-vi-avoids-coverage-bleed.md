# Star-capture overlay: drop the VI to point-sampled while it is up

Issue #89: the QR and its dialog-box text show thin, intermittent slivers of
the 3D scene behind them — the top line of a door, the rim of Mario's hat,
"only the darkest or brightest color" — bleeding *in front of* the overlay.
Reported as apparent z-fighting; it is not (there is no Z here).

## Root cause: a CPU blit cannot write VI coverage

The star-capture overlay is a **direct CPU framebuffer blit** (ADR-0004):
`qr_render_overlay_rgba16()` writes only the 16-bit RGBA5551 **color** of each
pixel it touches, straight into the uncached framebuffer, after the RDP has
already rendered that frame's 3D scene into the same buffer.

The N64 VI runs a **3-bit coverage** value per pixel. For a 16-bit
framebuffer only the top coverage bit is the color pixel's LSB; the low two
bits live in RDRAM's **RDP-only "hidden" plane**, which the CPU cannot
address. So a CPU blit can set the color LSB (`| 1`, as the code does) but
**cannot force full coverage** — every overlay pixel inherits whatever
coverage the RDP left there when it drew the scene.

The game boots the VI in an **anti-aliased / resample** mode
(`OS_VI_NTSC_LAN1` / `OS_VI_PAL_LAN1`, `main.c:430`). That mode's display
filter *reads* coverage: at pixels the RDP marked partial-coverage — 3D
silhouette edges — the VI blends the pixel with its neighbours, and the divot
filter takes a median (hence "only the darkest/brightest" edge texel
survives). Where such an edge sits under our overlay, the VI reconstructs it
*through* our freshly-written QR/text pixels. It is intermittent because it
only appears where a scene silhouette happens to fall under the overlay.

This is exactly **why the in-game HUD and dialog boxes never show it**: the
RDP draws *them*, writing full coverage (hidden bits included), so the VI
treats them as opaque. A CPU blit structurally cannot reproduce that — the
one thing #89 asked us to mimic is unreachable from where this overlay lives.

## Decision: point-sample the VI for the overlay's lifetime

While the overlay is presented, switch the VI to the matching **point-sampled**
mode (`OS_VI_*_LPN1`), which ignores coverage and displays the framebuffer
1:1 — no neighbour blend, no divot, no resample — then restore the normal
anti-aliased mode on dismiss. The switch is owned by the overlay's existing
lifecycle in `qr_display_n64.c`: `qr_display_n64_present()` (on the committed
success path) drops to LPN1; `qr_display_n64_step()` restores LAN1 on the
dismiss tick. Mode/TV-type selection mirrors `main.c` exactly (NTSC vs PAL,
MPAL→PAL), and the two special features `thread1_idle` sets globally
(dither-filter on, gamma off) are re-applied after each `osViSetMode`.

Consequences:

- The QR and text become **pixel-exact** — strictly better for scanning.
- The (paused) background loses anti-aliasing for the seconds the code is up.
  Acceptable: it is a frozen info screen, not gameplay.
- No change to the pure `qr_render` core, the blit, or the frame-cycling.

## Rejected alternatives

- **Write full coverage from the CPU.** Impossible for a 16-bit AA
  framebuffer — the low coverage bits are in the RDP-only hidden plane.
- **Render the whole overlay through the RDP display list** (the literal
  "mimic the HUD/dialog" fix). This *would* write correct coverage and is the
  ideal end state, but it is a large change: an arbitrary runtime QR bitmap
  must be tiled into TMEM as a texture and drawn as textured rectangles, plus
  the box/text routed through the dialog engine, all inside a time-stopped
  Mario action. ADR-0004 rejected DL routing for triple-buffer sync reasons;
  those dissolve if the *entire* overlay is RDP-drawn (it is a static image,
  so a 1-frame display latency is imperceptible), so this remains the
  recommended follow-up if keeping AA on during the overlay ever matters.
- **Toggle only the divot filter** (`osViSetSpecialFeatures`). The neighbour
  blend is the AA/resample mode itself, not just divot; only a mode change
  reliably stops it. Point-sampling also removes any resample fringe at the
  overlay's rectangle borders, so it is robust to the exact sub-filter at
  fault.

## Verification status

The fix compiles and links a full US ROM via the Docker build. The visual
result is a hardware/VI-filter behaviour that neither the pure-core host test
(`tools/pipeline_test`, no VI) nor code review can confirm; final
confirmation is an on-emulator (ares) check of the star-capture screen with
3D geometry behind the overlay.

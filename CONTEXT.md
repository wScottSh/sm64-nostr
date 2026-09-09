# CONTEXT — domain glossary

Ubiquitous language for the **airgapped Nostr QR leaderboard** work (ticket [#4](https://github.com/wScottSh/sm64-nostr/issues/4)). Names the good seams so specs, code, and reviews all say the same thing. Architecture vocabulary (module, interface, depth, seam, adapter, leverage, locality) comes from the `/codebase-design` skill and is used here verbatim.

## Pipeline & code shape

- **The pipeline** — the one **deep module** of the feature: `(StarCapture, key) → bytes` (packed payload + QR bitmap). Pure — touches no `MarioState`, no globals, no N64 headers/timers — so it builds and runs off-device. Its **interface is the test surface**.

- **StarCapture** — the plain-old-data struct that *is* the pipeline's input seam: `{course, act, coins, frames, nonce16, keyId}`. The game **glue** fills it at the grab site (`interact_star_or_key`, `interaction.c:812`) from scattered N64 state (course/act globals, `m->numCoins`, `starIndex`) and hashes the content **nonce** in the glue. Nothing N64-specific crosses into the pipeline except this struct.

- **Glue** — the thin game-side code either side of the pipeline seam: the grab-site capture (fills `StarCapture`) and the renderer (consumes the QR bitmap). Deliberately shallow; carries no crypto or format logic.

- **Event profile** — the build-time constants that pin a build to one signing identity + event shape: baked serialization prefix (#13), kind `8064`, `t` tags, `created_at` (#12), pubkey. Emitted as generated `event_profile.h` (recipe mirrors `text_strings.h.in` → `$(BUILD_DIR)/include`).

- **Format descriptor** — the single machine-readable source of truth for the **packed payload** (~112–122 B in **format v2**; was 75 B in v1, #14), emitted by the same generator as the event profile. The ROM **pack adapter** and the host **unpack adapter** both derive from it, so the two sides can't drift. The packed payload is the system's narrowest, most permanent interface — the only artifact crossing ROM → companion → leaderboard.

- **Self-contained event** — the invariant that the QR carries a *complete, already-signed, broadcast-ready* Nostr event: every value in the signed serialization (`pubkey`, `created_at`, `kind`, `tags`, `content`) is fixed on-cartridge before the QR is drawn and is recoverable from the QR alone. No game↔companion out-of-band coordination exists. In **format v2** this forced `pubkey` + `created_at` + the per-game `t` tag onto the wire (v1 wrongly baked them out-of-band). See ADR-0001/0002.

- **Companion app** — the strictly **read-only airgap jumper**: it decodes the QR into the signed event and broadcasts it to a relay, injecting no value and performing no verification. Verification (if any) is the relay's / leaderboard's job.

- **Internal ports** — sha256 (#6), secp256k1 (#5/#23), qrcodegen (#15). They sit *behind* the pipeline interface as **internal seams** (swappable, each with its own known-answer test), never called by glue. Their C99 requirement stays contained here.

- **QR bitmap** — the pipeline's **output seam**: a 1-bpp bitmap, not framebuffer pixels. The renderer glue blits it via direct RGBA16 writes to the uncached framebuffer (`crash_screen_draw_glyph` precedent, `crash_screen.c:81-101`). Host tests decode the bitmap; encoding is never fused into the framebuffer write.

- **qr_display glue** *(deferred)* — the small shared state machine (`qr_present(bitmap)` / `qr_update(input)→done`) owning time-stop, debounced-A, and the one-shot `memset`, so the "never re-summonable" invariant lives in one place across both save flows.

## Timing & flow

- **Capture@grab / display@park** — values are frozen at the moment of the star grab (nonce included); the QR is shown later when Mario parks. See #17.

## Trust & provenance

- **Origin-provenance** — the guarantee the signature actually provides: "produced by the private per-event ROM the operator built for event X", *not* honest play. The unextractable-key problem is **dissolved by distribution control** (private binary, never distributed), per #9/#10.

## Sandbox seams

The fork deliberately opens progression gates so a fresh file plays as an open sandbox. Each such gate is a **sandbox seam**: a single, named, always-open decision point, kept together so the sandbox behavior is discoverable in one place.

- **Sandbox seam A** — fixed mask of "unlocked" progress flags (`SAVE_FLAG_SANDBOX_UNLOCK_MASK`) OR'd into `save_file_get_flags()` at read-time so a fresh save behaves as an open sandbox. Excludes star-collection flags, so HUD/course progress stays honest.

- **Sandbox seam B** — `save_file_star_gate_is_open()`, an always-open star-requirement predicate substituted at the live star-count comparison sites (doors, endless-staircase warp, MIPS, Toad checks) so every star gate is passable at 0 stars.

- **Star-select act gate (sandbox seam C)** — a menu-selection-only gate: all six of a course's act stars are always visible and selectable in the star-select menu, regardless of collection progress. Each slot's rendered model still follows the real per-course star flags (collected → solid, uncollected → translucent). Does not touch `sObtainedStars`, the star bitfield, level object spawning, or the 100-coin star path — selectability only.

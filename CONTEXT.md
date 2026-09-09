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

## Build & provisioning

- **Build wizard** — the single-command build pipeline. A thin host launcher (`build.ps1`/`build.sh`) `docker run -it`s an interactive `/wizard`-style bash orchestrator *inside* the container, which provisions the signing key, runs the one blessed `make` shape, and streams the build. Docker-only; the operator fires one command and a signed ROM comes out. See ADR-0003.

- **Ephemeral per-event key** — the paradigm that a ROM's signing key is the identity of *one game at one event*, minted fresh per build by default, freely overwritten, and never a long-lived identity. Its only recoverable surface is the end-of-run panel (`npub`/`nsec`). Distinct from **origin-provenance** (which the key still provides *within* an event): the key is disposable, the provenance guarantee is not.

- **Event name** *(implemented, spec #75 sub-issue #76)* — a REQUIRED human-readable identity for an event, distinct from `PIPELINE_KEY_LABEL` (registry label) and the per-game `t` tag: an event ROM cannot be built without one. Supplied via the Makefile's `PIPELINE_EVENT_NAME` (no default; `$(error)`s at parse time if unset/empty, mirroring the privkey fail-closed check) and the build wizard's `-EventName` (prompts interactively when omitted). Validated and normalized by `gen_event_profile.py` — uppercase-folded, restricted to `A-Z 0-9 space`, capped at 15 chars (rejected, never truncated, if over) — and baked into `include/event_profile.h.in` as `PIPELINE_EVENT_NAME`/`PIPELINE_EVENT_NAME_LEN`. Display-only: never sourced by `build_event()`'s pack stage, never on the QR wire or in the signed event.

## Timing & flow

- **Capture@grab / display@park** — values are frozen at the moment of the star grab (nonce included); the QR is shown later when Mario parks. See #17.

## Trust & provenance

- **Origin-provenance** — the guarantee the signature actually provides: "produced by the private per-event ROM the operator built for event X", *not* honest play. The unextractable-key problem is **dissolved by distribution control** (private binary, never distributed), per #9/#10.

## Sandbox seams

The fork deliberately opens progression gates so a fresh file plays as an open sandbox. Each such gate is a **sandbox seam**: a single, named, always-open decision point, kept together so the sandbox behavior is discoverable in one place.

- **Sandbox seam A** — fixed mask of "unlocked" progress flags (`SAVE_FLAG_SANDBOX_UNLOCK_MASK`) OR'd into `save_file_get_flags()` at read-time so a fresh save behaves as an open sandbox. Excludes star-collection flags, so HUD/course progress stays honest.

- **Sandbox seam B** — `save_file_star_gate_is_open()`, an always-open star-requirement predicate substituted at the live star-count comparison sites (doors, endless-staircase warp, MIPS, Toad checks) so every star gate is passable at 0 stars.

- **Star-select act gate (sandbox seam C)** — a menu-selection-only gate: all six of a course's act stars are always visible and selectable in the star-select menu, regardless of collection progress. Each slot's rendered model still follows the real per-course star flags (collected → solid, uncollected → translucent). Does not touch `sObtainedStars`, the star bitfield, level object spawning, or the 100-coin star path — selectability only.

- **Sandbox seam D — intro suppression** — `save_file_intro_is_suppressed()`, an always-TRUE predicate substituted at two decision points so it stays one gate, not two:
  - The spawn-time action-select decision point in `init_level` (`level_update.c`) so a pristine file selects `ACT_IDLE` instead of `ACT_INTRO_CUTSCENE`. Since the opening cutscene's `CAM_EVENT_START_INTRO` is never set, `CUTSCENE_INTRO_PEACH` never runs and DIALOG_033 (the pipe-exit text) is removed transitively, with no separate edit. The intro-only white fade-in transition is skipped along with it, so the normal star-warp transition plays.
  - The `gNeverEnteredCastle` assignment in `lvl_init_from_save_file` (`level_update.c`), which is forced `FALSE` ("already entered") whenever the predicate is suppressed. `bhvCameraLakitu` (the intro Lakitu that blocks the bridge for DIALOG_034) and `act_warp_door_spawn`'s Bowser taunt branch (DIALOG_021) both gate on this same flag, so both are removed at once. As a side effect, `set_background_music` (`sound_init.c`) no longer skips the castle-entry music cue, so normal castle music plays immediately instead of the vanilla quiet first-entry cue. A third vanilla reader, the `gNeverEnteredCastle` self-clear-and-start-music hook in `act_reading_automatic_dialog` (`mario_actions_cutscene.c`, fires after the first star dialog), is now dead code on a pristine file: the flag is already `FALSE` by the time it would run, so the hook's own `play_cutscene_music` call never fires. Harmless — the music it would start is already playing — but `lvl_init_from_save_file` becomes the sole effective writer while this seam is active.

  Force-off, not delete: vanilla `act_intro_cutscene`, `bhvCameraLakitu`'s intro branch, and the Bowser taunt branch all stay in the tree, unreached.

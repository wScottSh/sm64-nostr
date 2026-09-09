# The game build is one command: a Docker-wrapped, key-provisioning wizard

Building an event ROM is a **single command** the operator fires from any host
shell. A thin launcher (`build.ps1` / `build.sh`, whichever the operator
prefers) does nothing but `docker run -it` the real orchestrator — a
**build wizard** (`/wizard`-style interactive bash) that runs *inside* the
container, prompts for the few inputs it needs, provisions the signing key,
then runs the blessed `make` and streams a verbose CLI UI. The operator hits
Enter and a signed ROM comes out. No AI direction, no memorised multi-step
sequence.

The signing key is treated as **ephemeral, per-event identity**: each build
mints a fresh key by default. This is deliberate — a ROM's key is the identity
of *one game at one event*, it dies with that event, and it is never a
long-lived identity worth protecting. Everything is client-side and local, so
minting-and-overwriting freely is the intended paradigm, not a hazard.

## Consequences

- **Docker-only, no native path.** The wizard always runs in the container;
  the launcher auto-`docker build`s the `sm64` image when missing
  (`--rebuild-image` forces). "Runs on my machine" is the container's problem,
  not the operator's.
- **The wizard is the orchestrator, not a checklist.** Unlike a stock `/wizard`
  (which drives steps only a human can do), this one *does* the automatable work
  itself (mint key, run `make`); it prompts only for what genuinely needs human
  input — the key choice and the event name.
- **Key provisioning defaults to fresh-generate.** Press Enter to accept a
  newly-minted key; paste your own hex/`nsec` only to reuse a prior event's key.
  An existing `keys/event_privkey.hex` is overwritten without ceremony — the key
  is ephemeral, so muscle-memory Enter clobbering it is *intended*, not a
  footgun. (This reverses `gen_event_key.py`'s refuse-to-overwrite stance for the
  wizard path.)
- **Recoverability is one panel, no more.** The run ends with a summary panel:
  ROM path, ROM sha1, and the `npub` / `nsec`. Because the key is ephemeral and
  the only thing that ever prints from it is that panel, nothing more elaborate
  is warranted. The existing `registry.md` stamp (already inside `make`'s `$(ROM)`
  recipe) is left in place for free but nothing is built on top of it.
- **Baserom is step one.** Before Docker spins, the wizard checks for
  `baserom.us.z64` at its fixed repo-root path and verifies sha1
  `9bef1128717f958171a4afac3ed78ee2bb4e86ce`. Missing or wrong → fail with the
  exact absolute path to drop the ROM at, then rerun. No operator-configurable
  location.
- **One blessed build shape.** The wizard hardcodes `VERSION=us COMPARE=0
  COMPILER=gcc -j$(nproc)` — no config matrix prompt. `created_at` defaults to
  wall-clock silently, with a `--created-at` escape hatch for reproducible
  rebuilds. Interactive by default; every prompt has a pass-through flag
  (`--privkey`, `--event-name`, `--label`, `--yes`) so a repeat/CI build can run
  silently. Default build is incremental; `--clean` for scratch.
- **Event name is REQUIRED (spec #75, sub-issue #76).** A human-readable event
  identity, distinct from `PIPELINE_KEY_LABEL` and the `t` tag, shown locally
  in the castle HUD corner — an event ROM cannot be built without one. The
  wizard's `-EventName` prompts interactively when omitted (fails closed
  under `-Yes` with no value) and threads the value into `make` as
  `PIPELINE_EVENT_NAME`; `gen_event_profile.py` inside the container does the
  real charset/length validation (A-Z, 0-9, space; 15 chars max; reject, never
  truncate) and bakes it into `PIPELINE_EVENT_NAME` — display-only, never the
  signed wire.

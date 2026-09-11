# sm64-nostr

A fork of the [Super Mario 64 decompilation](https://github.com/n64decomp/sm64) that turns the game into an
**airgapped Nostr QR leaderboard cabinet**. It is built on the full US decomp and modifies two things:

- **Sandbox castle.** A brand-new save file is a full sandbox with nothing locked — every door, both Bowser-key
  doors, the endless staircase, all three caps, the drained moat, MIPS, and the message Toads are open from the
  first frame at 0 stars. You pick any of the 120 stars in any order from minute one. No stars are pre-collected:
  the HUD shows an honest count that starts at 0 and climbs as you actually collect. This fork *is* the sandbox —
  there is no toggle to play vanilla.

- **In-game Nostr QR pipeline.** Grabbing a star freezes that achievement, signs it on the N64 as a Nostr event
  (secp256k1 / Schnorr, BIP-340), and renders it as a single on-screen QR code in place of the save menu. The QR
  is ephemeral: it is erased from memory when it leaves the screen and can never be re-displayed. A phone scans it
  to submit a cryptographically verifiable score to a leaderboard. The console never touches a network.

The signature proves **origin-provenance** — "produced by the private, per-event ROM the operator built for event
X" — not honest play. There is no way to protect a self-signing key in a public ROM, so the security control is
operational, not cryptographic: the per-event signing key is injected at build time from an out-of-source secret,
and the binary is never distributed. See `CONTEXT.md` for the domain glossary and the design decisions behind all
of this.

Scope of this repo was originally the **ROM only** (ADR-0005), with the reader (a generic phone camera scans the
plaintext-URL QR → the website behind the URL re-publishes) and the leaderboard (aggregation, display) called out
as separate, out-of-scope efforts. **Superseded in part by spec #115, sub-issue #119** (flagged, not silently
overridden, per this repo's own ADR-conflict convention): the reader's source now lives in this repo too, under
`reader/` — a static site (no build step beyond generating its shared wire-format contract, see that directory's
own files) that a stock phone camera opens directly. The leaderboard remains a genuinely separate, out-of-scope
effort. See ADR-0005/ADR-0006.

## The pipeline

The Nostr work is one pure **deep module** — `(StarCapture, key) → bytes` — that touches no `MarioState`, no
globals, and no N64 headers, so it builds and unit-tests off-device. It lives under `src/pipeline/`:

- **`capture.*`** — `StarCapture`, the plain-old-data input seam: `{course, act, coins, frames, nonce16, keyId}`,
  filled by thin game glue at the star-grab site (`interact_star_or_key`, `interaction.c`).
- **`build_event.*` / `event_id.*` / `schnorr_adapter.*`** — canonical NIP-01 serialization, SHA-256 event id,
  BIP-340 signature. Custom regular kind `8064`; `created_at` is a fixed build-epoch constant (the N64 has no RTC).
- **`pack_adapter.*`** — packs the 75-byte wire payload (1-byte format tag + the run fields + the 64-byte
  signature) defined by `format_descriptor.json`, the single source of truth the host verifier also derives from.
- **`qr_adapter.*` / `qrcodegen.*`** — encodes the payload to a 1-bpp QR bitmap; game glue blits it via direct
  RGBA16 writes to the framebuffer.
- **`sha256.*` / `secp256k1.*`** — vendored C99 crypto ports, each behind the pipeline with a known-answer test.

The pipeline builds and runs on the host with no ROM. Run its end-to-end test (pack → decode → verify sig →
recompute id) with:

```
make pipeline-test
```

## Signing key (required to build)

The ROM build **fails closed** without a per-event secp256k1 private key at `keys/event_privkey.hex` (64 lowercase
hex chars, gitignored). For a local/dev build, mint a throwaway key:

```
python3 tools/gen_event_key.py
```

The build derives the x-only pubkey and bakes it — with the fixed event shape — into a generated header under the
build directory, never into `src/`. For a real cabinet build, replace the file's contents with the actual
per-event secret; keys are rotated per event and never committed. See `keys/README.md`.

## Building

### One command (Windows / PowerShell)

The build wizard chains preflight → key provisioning → Docker `make` → a summary
panel that prints the ROM's `npub`/`nsec`. From the repo root:

```powershell
.\build.ps1 -EventName "SUMMER JAM 2026"
```

Press Enter to mint a fresh ephemeral per-event key, or paste a 64-char hex
secret to reuse a prior event's. `-EventName <name>` is REQUIRED (A-Z, 0-9,
space only, 17 chars max) — an event ROM cannot be built without one; the
wizard prompts for it if omitted, unless `-Yes` is also given, in which case
a missing `-EventName` fails the build outright rather than prompting.
Other flags: `-PrivKey <hex>`, `-Clean`, `-RebuildImage`, `-Yes`
(non-interactive). See `docs/adr/0003-single-command-build-wizard.md`. The
manual steps below are the underlying pipeline the wizard runs for you.

### Manual

This fork's operative target is **US**, built with Docker (Ubuntu 18.04). Because the game is modified, the output
ROM does not match the original US sha1 — hash comparison is expected to differ, so build with `COMPARE=0` (it is
also auto-disabled by any non-default option). Asset extraction still requires an **unmodified** US ROM at
`./baserom.us.z64` (`sha1: 9bef1128717f958171a4afac3ed78ee2bb4e86ce`); assets are not distributed with the repo.

The build uses **gcc** (the `mips-linux-gnu-` cross-compiler, already in the Docker image) — this is the default
`COMPILER`, so no extra flag is needed. Because the ROM is intentionally non-matching, the IDO toolchain (whose only
purpose is byte-matching the original ROM) buys nothing here and is **not** required; the vendored `ido-static-recomp`
is additionally unreliable in this Docker environment. Pass `COMPILER=ido` only if you have a working IDO toolchain
and specifically want a matching build.

The underlying decomp still supports the other versions (`jp`, `eu`, `sh`, `cn`), but the sandbox and pipeline
work is validated on US and run in [ares](https://ares-emu.net/) (Video Output = Integer, Aspect Correction =
None, so the QR is not resampled).

Ensure the repo path length does not exceed 255 characters. Long path names result in build errors.

### Docker (recommended)

Build the image once:

```
docker build -t sm64 .
```

Then mount the repo and build the US ROM:

```
# macOS / Linux
docker run --rm --mount type=bind,source="$(pwd)",destination=/sm64 sm64 make VERSION=us COMPARE=0 -j4
```

On a Linux host, add `--user $UID:$GID` so the output files are owned by you. Resulting artifacts land in the
`build` directory.

### Native (Linux / WSL)

Install build dependencies and build directly.

#### Step 1: Install dependencies

The build system requires:

* binutils-mips
* pkgconf
* python3 >= 3.6

##### Debian / Ubuntu
```
sudo apt install -y binutils-mips-linux-gnu build-essential git pkgconf python3
```

##### Arch Linux
```
sudo pacman -S base-devel python
```
Install the [mips64-elf-binutils](https://aur.archlinux.org/packages/mips64-elf-binutils) AUR package.

##### Other Linux distributions
Most modern distros have equivalents. Fully compatible binutils prefixes with makefile support:

* `mips64-elf-` (Arch AUR)
* `mips-linux-gnu-` (Ubuntu and other Debian-based distros)
* `mips64-linux-gnu-` (RHEL/CentOS/Fedora)

On Windows, install [WSL](https://docs.microsoft.com/en-us/windows/wsl/install) with Debian or Ubuntu and follow
these same steps inside the Linux shell. (Docker Desktop is the smoother path on Windows.)

#### Step 2: Copy the baserom

Put an unmodified US ROM at `./baserom.us.z64` for asset extraction.

#### Step 3: Mint a key and build

```
python3 tools/gen_event_key.py
make VERSION=us COMPARE=0 -j4
```

Configurable variables (default first):

* ``VERSION``: ``us``, ``jp``, ``eu``, ``sh``, ``cn``
* ``COMPILER``: ``gcc`` (default for this fork, non-matching), ``ido`` (matching; needs a working IDO toolchain)
* ``COMPARE``: ``1`` (compare ROM hash), ``0`` (do not) — use ``0`` here, the ROM is modified
* ``GRUCODE``: ``f3d_old``, ``f3d_new``, ``f3dex``, ``f3dex2``, ``f3dzex``
* ``NON_MATCHING``: use functionally equivalent C for non-matchings; also avoids undefined behavior
* ``CROSS``: cross-compiler tool prefix (e.g. ``mips64-elf-``)

### macOS

Use Docker (above), or Homebrew's GNU make (the bundled `make` is too old):

```
brew install coreutils make pkg-config tehzz/n64-dev/mips64-elf-binutils
gmake VERSION=us COMPARE=0 -j4
```

## Project structure

	sm64-nostr
	├── actors: object behaviors, geo layout, and display lists
	├── asm: handwritten assembly code, rom header
	│   └── non_matchings: asm for non-matching sections
	├── assets: animation and demo data
	├── bin: C files for ordering display lists and textures
	├── build: output directory
	├── data: behavior scripts, misc. data
	├── doxygen: documentation infrastructure
	├── enhancements: example source modifications
	├── include: header files (incl. event_profile.h.in, the baked event shape, and secp256k1_baked.h.in, the baked signing public point and fixed-base comb table for k*G)
	├── keys: gitignored per-event signing key + registry (see keys/README.md)
	├── levels: level scripts, geo layout, and display lists
	├── lib: SDK library code
	├── rsp: audio and Fast3D RSP assembly code
	├── sound: sequences, sound samples, and sound banks
	├── src: C source code for game
	│   ├── audio: audio code
	│   ├── buffers: stacks, heaps, and task buffers
	│   ├── engine: script processing engines and utils
	│   ├── game: behaviors and rest of game source (sandbox seams in save_file.c)
	│   ├── goddard: Mario intro screen
	│   ├── menu: title screen and file, act, and debug level selection menus
	│   └── pipeline: the pure Nostr QR pipeline (capture → sign → pack → QR)
	├── text: dialog, level names, act names
	├── textures: skybox and generic texture data
	└── tools: build tools (incl. gen_event_key.py, gen_event_profile.py, pipeline_test)

## Contributing

Work is organized as GitHub issues (the "Wayfinder" issue tree) and mirrored in `research/*` and `spec/*`
branches. `CONTEXT.md` holds the ubiquitous language; use it so specs, code, and reviews stay in sync.

Run `clang-format` (`./format.sh`) before committing.

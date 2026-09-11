# Adaptive multi-frame airgap transport; the opened page reassembles when a payload exceeds one frame

The airgap transport is **adaptive multi-frame**. The cabinet emits the signed
event as one or more **URL-wrapped fragments** rendered as QR frames. A payload
that fits one frame is the **N=1** case — a single static QR a stock phone camera
passively snaps and opens, broadcasting on URL-open with no further interaction.
When the honest payload exceeds one frame, the cabinet cycles **N>1** frames and
the **opened website re-grabs the camera (`getUserMedia`) and reassembles** the
fragments in-page. Nothing is installed on either path. This extends ADR-0005's
reader model (a generic phone camera → plaintext-URL QR → website) from a fixed
single frame to an adaptive stream, and **amends ADR-0005 accordingly**.

This decision is forced by two facts the charting proved:

- **A stock camera is strictly single-frame.** Pointed at a cycling QR of
  *different* payloads it locks onto whichever frame it decodes first and never
  accumulates a stream — there is no append/accumulate API on any stock scanner
  (ML Kit per-frame decode; iOS Vision one-payload-per-decode). So a stock camera
  delivers exactly one frame's worth of bytes, full stop.
- **The honest floor overflows one frame.** The provably-minimal honest signed
  event is ~103 B under the zero-far-side-reconstruction invariant, which does not
  fit a single frozen v7-MEDIUM frame under any URL-safe encoding once a realistic
  domain prefix is added. So single-frame is a *boundary case*, not the ceiling.

The two facts collide: install-nothing + a payload past one frame provably requires
the opened page to re-scan (impossibility triangle, `airgap-qr-transport-design-space.md`
§5 — you cannot have install-nothing, domain-free, and passive single-snap all at
once, and past one frame passive single-snap is already impossible on a stock
camera regardless). The adaptive design concedes the passive snap **only** on the
overflow path, where it is already lost no matter what, and keeps it on the N=1
path where it is the best available UX.

## What crosses the airgap

- **Every frame is a complete, valid `https://` URL** — a constant resolver hook
  plus a fragment segment — so a stock camera opens *any single frame* it happens
  to grab, and the opened page bootstraps from there. No frame is an opaque blob
  or a custom scheme; there is no BBQr/`ur:`-style bare payload a stock camera
  cannot act on.
- **Per-frame geometry is unchanged from ADR-0002:** QR v7-MEDIUM (45×45, one
  fixed mask, ~2 px/module), kept for CRT legibility (glare, phosphor bloom,
  scanlines, rolling-shutter beat). The multi-frame pivot changes *total capacity*,
  not per-frame geometry.
- **Fragments carry a header identifying their index and the total frame count**
  so the page knows when it is done. **This bullet's original prose (fragments as
  "numeric-mode packed (path-based, all-uppercase URL)") is superseded, twice
  over:** first by spec #115 sub-issue #116's own build decision (base32, RFC
  4648 §6, `A-Z2-7`, which needs the QR **ALPHANUMERIC** segment mode, not
  numeric — base32's alphabet includes letters a numeric-mode segment cannot
  carry), and then by #101's own RATIFIED URL template, which this ADR always
  deferred the exact URL shape TO (see the next bullet) and which spec #122/
  sub-issue #123 realigned the build against: `<BASE>#<SEQ>/<TOTAL>/<PAYLOAD>` —
  a `#` hash-fragment join (never a `/` path join), the base URL emitted
  **verbatim** (never uppercased), and `/`-delimited SEQ/TOTAL/PAYLOAD fields.
  The "path-based, all-uppercase" language above was never itself ratified; it
  was loose prose that #115 mistakenly built against instead of deferring to
  #101 as this ADR's own next bullet says to. Noted here, corrected, not
  silently rewritten out of the historical record, per this repo's "flag ADR
  conflicts" convention.
- The exact URL template and base-URL provisioning are **out of this ADR** (#101);
  the full v3 wire layout — FRAMES semantics, fragment header bits, per-frame ECC
  under the actual segment mode chosen at build time — is **out of this ADR**
  (#102). This ADR fixes the *transport architecture and reader model*, not the
  byte-level layout.

## The invariant is unchanged

**Zero far-side reconstruction still holds, verbatim.** Reassembling N fragments
into the original packed bytes is a **lossless decode** of already-signed bytes —
the exact bytes the cabinet emitted, recovered in full — followed by the same
permitted `id` recompute (a SHA-256 checksum of the recovered bytes). No signed
value is computed, injected, defaulted, or rebuilt far-side; the reassembler
concatenates/solves fragments and hands the whole event to the broadcaster. A
heavier reader does not weaken the invariant: it decodes more frames, it
reconstructs no *values*.

## Sequential vs. fountain: the choice criterion (not yet the pick)

Two multi-frame schemes are viable and both preserve the invariant:

- **Sequential indexed cycling** (BBQr-style): N fixed, indexed frames; all N must
  be seen but in **any order**; the page cycles until it has collected the full
  set. Simple; no XOR solving; overhead is only re-seeing missed frames.
- **Fountain / rateless** (Luby transform, BC-UR MUR-style): rateless XOR-mixed
  parts; any sufficiently large set reconstructs the message; robust to lossy,
  never-complete capture at ~1.05–2× the raw fragment count.

**Criterion:** sequential cycling is the default; fountain coding only earns its
extra complexity **past ~8–10 frames**, where the odds of catching every distinct
indexed frame off a cycling animation degrade and rateless capture wins. Because
the honest floor (~103 B) reassembles in a **small** number of frames, sequential
is expected to suffice and **fountain is deferred**. The final pick is made at v3
synthesis (#102 / ADR follow-up) against the committed per-frame budget; this ADR
fixes only the criterion that decides it.

## Consequences

- **N=1 stays passively snappable — the best-UX common case is preserved.** A
  stock camera opens the one static frame and the event broadcasts with no camera
  re-acquisition, no permission grant, no active scan loop.
- **N>1 costs a camera-permission grant + an active hold** on the opened page.
  This second stage is **fragile in in-app browsers / webviews** (`getUserMedia`
  needs a secure context and is unreliable outside full Safari/Chrome — iOS
  WKWebView pre-14.3, raw Android WebView, any HTTP). The N=1 path has no such
  stage; this asymmetry is why single-frame stays the preferred case whenever the
  payload can be made to fit.
- **Make-or-break: PASSED on Android** (Pixel 7a: native camera → Chrome →
  `getUserMedia` → animated-QR reassembly, flawless; #104). **iOS is unverified**
  (n=0; docs favorable — Safari has `getUserMedia` since iOS 11, the camera opens
  Safari proper) and is tracked by #106. Prototype:
  https://wscottsh.github.io/sm64-nostr/prototype/getusermedia-airgap/
- **CRT robustness of a cycling animation is untested** (refresh/interlace beat
  against the phone's rolling shutter and the QR frame rate) — tuning, not gating;
  tracked by #107.
- **The retired premise is dead:** "footprint FROZEN at v7-M single frame is the
  ceiling." Per-frame v7-M geometry survives; total payload is no longer capped by
  one frame. Constraint C now means *per-frame geometry*, not *total capacity*.
- **ADR-0005 is amended, not superseded.** Its reader model (phone camera → URL →
  website, decode-and-broadcast only) and its invariant stand; this ADR extends the
  reader from a single frame to an adaptive stream and points ADR-0005 here.

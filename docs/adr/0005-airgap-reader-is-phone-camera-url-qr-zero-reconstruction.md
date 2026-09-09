# The airgap reader is a generic phone camera → URL QR → website; the far side reconstructs nothing

The airgap reader is a **generic phone camera**, not a dedicated app. The camera
reads a **plaintext-URL QR**, opens that URL, and the **website** behind it does
the decode-and-broadcast. The QR's content is a URL whose payload segment carries
the **complete, already-signed, broadcast-ready** Nostr event, encoded losslessly.
The event is signed on-cartridge before the QR is drawn and crosses the airgap
**whole and immutable**; the far side (the website) **decodes and broadcasts
only**. This retracts ADR-0001's *dedicated companion app* premise (an AI
assumption the owner never made) while re-affirming its self-contained-event
substance and making the reconstruction invariant explicit and quotable.

## The invariant

> **Zero far-side reconstruction.** No value in the signed event is ever computed,
> injected, defaulted, or rebuilt on the far side of the airgap. Every value that
> enters the NIP-01 serialization (`pubkey`, `created_at`, `kind`, `tags`,
> `content`) is fixed on-cartridge and recovered **verbatim** from the QR. The far
> side may **decode** the packed bytes into canonical JSON and **recompute the
> `id`** — a SHA-256 of the exact bytes it was handed, precisely as every Nostr
> client does: a checksum of given data, not the reconstruction of any value. If
> any signed value is rebuilt far-side, the event stops being a self-contained
> source of truth and the project collapses.

## Consequences

- **ADR-0001 is retracted as incorrect, not superseded.** Its *dedicated
  read-only companion app* premise is killed; its surviving substance (complete,
  already-signed, self-contained event; read-only decode-and-broadcast; **no
  out-of-band coordination** between game and reader) is carried by this ADR.
- **The reader is unprivileged and installs nothing.** Any phone camera plus a
  public website suffices — no app, no pairing, no side-channel. This strengthens,
  rather than weakens, the no-out-of-band-coordination guarantee of ADR-0001.
- **The QR is now a URL, not raw binary.** The event payload must therefore
  survive **URL-safe** encoding inside the **frozen v7-MEDIUM footprint** (the
  capacity/field work of #98 and #99; the v3 wire-layout synthesis of #102). This
  ADR fixes the *reader/airgap model*; it does **not** pick the encoding or the
  wire layout.
- **The `id` recompute is explicitly permitted and is not reconstruction.** It is
  the one derivation the far side performs, and it derives *no information* — it
  hashes bytes already present.
- **Verification stays downstream** (relay / leaderboard), unchanged from
  ADR-0001. The website is an airgap jumper, not a validator.
- **`origin-provenance` is untouched:** the private key never leaves the ROM;
  `pubkey` and `created_at` are public. Moving the reader to a phone+website
  exposes no secret.
- **Glossary follow-up:** `CONTEXT.md`'s **Companion app** term (defined as a
  "strictly read-only airgap jumper") should be re-pointed at the phone-camera +
  website reader named here. Left for a `/domain-modeling` touch, out of this
  ADR's scope.

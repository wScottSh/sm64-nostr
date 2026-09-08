# The companion app is read-only; the QR is a complete, self-contained event

The QR carries a **complete, already-signed, broadcast-ready Nostr event**, and the
companion app is **strictly read-only** — it decodes the QR and broadcasts to a
relay, injecting no value of its own. The whole point of the project is that the
truth of a run is self-contained on the cartridge at the moment the QR is drawn;
if any signed value originated off-cartridge, the event would no longer be a
source of truth. There is, and will be, **no out-of-band coordination** between
game and companion.

## Consequences

- Every value that enters the signed NIP-01 serialization (`pubkey`,
  `created_at`, `kind`, `tags`, `content`) must be fixed on-cartridge before the
  QR is rendered, and must be recoverable from the QR alone — not from companion
  config or a shared side-channel.
- `pubkey` (32 B) and `created_at` (4 B) vary per build and were previously baked
  out-of-band in `event_profile.h`; they **must now travel in the QR** (this is
  the defect ADR-0002 fixes).
- The per-game `t` tag varies per game and is signed on-cartridge, so it also
  travels in the QR. `kind` and the constant `ag-lb` tag are pinned by the format
  version (part of the published standard, not per-deployment coordination), so
  they need not be on the wire.
- The `id` (`sha256` of the serialization) is a pure function of the other
  fields, so the companion recomputes it. Deriving it injects no information, so
  it does not violate read-only — and it saves 32 B (see ADR-0002).
- The companion re-inflates packed binary fields into the canonical JSON per
  rules the spec pins exactly. That is decompression, not injection.
- No secret is exposed: `pubkey` and `created_at` are public; the private key
  never leaves the ROM, so **origin-provenance** (per `CONTEXT.md`) is untouched.
- The companion performs **no verification** — it is an airgap jumper. Any
  verification is the relay's / leaderboard's job downstream.

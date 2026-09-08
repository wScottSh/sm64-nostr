# Format v2 wire layout: self-contained payload at QR v7 / ECC MEDIUM

To satisfy ADR-0001 (self-contained, read-only companion), the packed payload
gains `pubkey` (32 B), `created_at` (4 B), and a length-prefixed per-game `t` tag
value, and `FORMAT_TAG` bumps `0x01 → 0x02`. The `id` is **not** packed (the
companion recomputes it — a 32 B saving; every Nostr client recomputes and relays
reject a mismatch). This grows the payload from 75 B to ~112–122 B, which exceeds
QR **v6-MEDIUM's** 106 B ceiling, so the symbol moves to **QR version 7
(45×45), ECC MEDIUM, BYTE mode**, with **one fixed mask** (not `AUTO`) to remove
the 8× masking/penalty cost on constrained hardware.

## Considered options

The floor is 96 B incompressible (64 B Schnorr sig + 32 B x-only pubkey, per
BIP-340/NIP-01), so a self-contained payload is ~112–120 B and **cannot** fit
v6-MEDIUM (106 B). The choice was forced (see `docs/research/qr-density-tradeoffs.md`):

- **A. v6 / LOW** (41×41, cap 134 B) — zero size increase, cheapest encoder, but
  only ~7% error correction. Rejected: this project targets N64/CRT/emulator
  displays where glare, moiré, phosphor bloom, and scanlines cause exactly the
  localized module loss that ~7% ECC does not cover. Robustness on archaic
  hardware is a stated requirement.
- **B. v7 / MEDIUM** (45×45, cap 122 B) — **chosen.** Keeps the inventor-default
  ~15% recovery; costs one QR version (~10% larger symbol) and ~40 B more encoder
  scratch. Fixing the mask reclaims most of the compute back.
- **C. v7 / LOW or v8 / MEDIUM** — more headroom for future fields, rejected as
  premature; revisit if fields are added.

## Consequences

- At v7-MEDIUM the usable BYTE-mode payload is **122 B**. Everything except the
  tag value is fixed at **112 B**, so the **per-game tag value is capped at 10 B**.
  A longer identifier forces v8-MEDIUM (cap 152 B, tag ≤ 40 B) — a version bump,
  not a silent truncation.
- `created_at` stays a full 4-byte `u32`. The 3-byte epoch-offset trick saves 1 B
  but caps validity at ~194 days from build — unacceptable for a cabinet, and it
  crosses no version boundary anyway.
- Bumping `FORMAT_TAG` to `0x02` means a companion MUST reject `0x01` (and any
  unknown tag) rather than guess — the layout and length differ per version.
- The QR version, ECC level, and mask are fixed constants known a priori by both
  sides; they are not carried in the payload.

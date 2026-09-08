#!/usr/bin/env python3
"""
Generate secp256k1_baked.h (spec #43, sub-issue #46) from
include/secp256k1_baked.h.in plus the same per-event 32-byte hex secp256k1
private key gen_event_profile.py reads.

Bakes the public point P = d*G as a build-time constant (P.x bytes plus
P's y-parity flag) so the runtime signing path never computes P via a
scalar multiplication -- see the template's own header comment for the
full rationale.

Fails closed (nonzero exit, no output file written) if the private key is
malformed, out of range, or if P fails any validation check below:
  (1) P lies on the curve (y^2 == x^3 + 7 mod p) -- the reference EC math.
      On its own this only proves P is SOME point on the curve, not that
      it's the RIGHT one (y^2 = x^3+7 holds for both a point and its
      negation) -- see (2).
  (2) P equals scalar_mult_msb_first(d, G) -- a SECOND, structurally
      different scalar-multiplication algorithm (binary double-and-add,
      most-significant-bit first) implemented independently below, cross-
      checked against nostr_secp256k1.scalar_mult (least-significant-bit
      first, right-to-left) above. Comparing the FULL point (x and y, not
      just x) also catches a wrong y/parity, which (1) alone cannot: y and
      -y both satisfy the curve equation, so only an independent
      re-derivation -- not the equation -- can tell them apart. (A naive
      first cut of this check called nostr_secp256k1.derive_xonly_pubkey,
      which is itself just scalar_mult(d, G) under another name -- the
      exact same function, same arguments -- so it could never disagree
      with the value under test; that was a tautology, not a check, and is
      why (2) is a genuinely separate algorithm instead.)
  (3) P.x matches nostr_secp256k1.derive_xonly_pubkey(privkey) exactly.
      Unlike (2), this ISN'T meant to independently prove P is correct
      (derive_xonly_pubkey is that same scalar_mult under another name,
      as (2)'s own note explains) -- its job is different: it is the
      cross-FILE guard that this generator's output and
      gen_event_profile.py's PIPELINE_EVENT_PUBKEY_BYTES (which IS
      derive_xonly_pubkey's return value, baked into the separately-
      generated event_profile.h) can never silently drift apart -- e.g.
      if a future edit read the private key from a different path, or
      passed the wrong bytes. event_id.c writes the event's `pubkey`
      field from event_profile.h while schnorr_adapter.c hashes THIS
      generator's baked X; without this check nothing ties those two
      generated constants to each other at all.

This is one of two independent proof layers spec #43's testing decisions
call for: this module's own validation runs at build time against the REAL
per-event key (never available to the host test tool), while
tools/pipeline_test/main.c's test_baked_public_point_matches_reference()
separately cross-checks a generated header against the C
pipeline_secp256k1_point_mul_base() at host-test time, for the FIXED
published KAT key (TEST_PRIVKEY_HEX, never the real one) -- the same split
gen_event_profile.py's own pubkey derivation already has (build-time-only
real-key derivation; host-test-time-only fixed-key KAT). Between the two,
every value this generator can produce is checked by construction (this
module) and every code path that consumes it is checked against the C
runtime (the host test), even though no single seam sees both at once.

Usage:
  gen_secp256k1_baked.py --privkey <path> --template <path> --out <path>
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nostr_secp256k1 as secp  # noqa: E402


def scalar_mult_msb_first(k, point):
    """
    k*point via binary double-and-add, most-significant-bit first
    (left-to-right) -- deliberately a DIFFERENT algorithm/loop direction
    than nostr_secp256k1.scalar_mult above (least-significant-bit first,
    right-to-left, doubling the addend instead of the accumulator), even
    though both call the same underlying _point_add point-addition formula
    (secp256k1's point-addition/doubling formula is itself part of "the
    reference EC math" this generator validates against -- re-deriving
    that formula a second, independent way in every generator that needs
    it would be its own source of bugs, not a genuine extra safeguard; the
    loop structure/bit order is where this generator's earlier, tautological
    check went wrong, and is what this function makes genuinely
    independent). Used only as gen_secp256k1_baked.py's cross-check oracle,
    exactly like this repo's C secp256k1 port keeps a naive reduce_wide_mod
    around solely as the fast reductions' differential-test oracle (spec
    #43 sub-issues #44/#45).
    """
    result = None
    for bit in bin(k)[2:]:  # MSB first; bin() has no leading zeros to worry about
        if result is not None:
            result = secp._point_add(result, result)
        if bit == "1":
            result = secp._point_add(result, point)
    return result


def read_privkey_hex(path):
    with open(path, "r") as f:
        raw = f.read().strip()
    if raw.lower().startswith("0x"):
        raw = raw[2:]
    if len(raw) != 64:
        raise ValueError(
            "%s: expected 64 hex chars (32 raw bytes), got %d" % (path, len(raw))
        )
    try:
        privkey_bytes = bytes.fromhex(raw)
    except ValueError as e:
        raise ValueError("%s: not valid hex (%s)" % (path, e))
    return privkey_bytes


def derive_and_validate(privkey_bytes):
    """
    Returns (x_bytes, y_is_even) for P = d*G, having validated P against
    the reference EC math -- see this module's own header comment for what
    the two checks below are and why the build must fail closed if either
    one fails.
    """
    d = int.from_bytes(privkey_bytes, "big")
    if not (0 < d < secp.N):
        raise ValueError("private key out of range [1, n-1]")

    point = secp.scalar_mult(d, secp.G)
    if point is None:
        raise ValueError(
            "d*G is the point at infinity (should be unreachable for 0 < d < n)"
        )
    x, y = point

    # (1) On-curve check against the reference EC equation y^2 = x^3 + 7.
    lhs = (y * y) % secp.P
    rhs = (x * x * x + 7) % secp.P
    if lhs != rhs:
        raise ValueError(
            "computed P = d*G is not on the curve (y^2 != x^3+7 mod p) -- "
            "refusing to bake a wrong point"
        )

    # (2) Cross-check against scalar_mult_msb_first -- a structurally
    # independent second algorithm (see its own docstring above for why
    # this, and not a call into derive_xonly_pubkey, is the real check).
    # Compares the FULL point, not just x, so it also catches a wrong
    # y/parity that (1) alone cannot.
    reference_point = scalar_mult_msb_first(d, secp.G)
    if reference_point != point:
        raise ValueError(
            "P = d*G from nostr_secp256k1.scalar_mult (LSB-first) disagrees "
            "with scalar_mult_msb_first (MSB-first) for the same private "
            "key -- got %r vs %r" % (point, reference_point)
        )

    x_bytes = x.to_bytes(32, "big")

    # (3) Cross-FILE consistency guard against gen_event_profile.py's own
    # pubkey derivation -- see this module's own header comment for why
    # this is a drift guard, not (2)'s independence proof.
    event_profile_x_bytes = secp.derive_xonly_pubkey(privkey_bytes)
    if x_bytes != event_profile_x_bytes:
        raise ValueError(
            "P.x disagrees with nostr_secp256k1.derive_xonly_pubkey (the "
            "same value event_profile.h's PIPELINE_EVENT_PUBKEY_BYTES is "
            "generated from) for the same private key -- %s != %s"
            % (x_bytes.hex(), event_profile_x_bytes.hex())
        )

    y_is_even = (y % 2 == 0)
    return x_bytes, y_is_even


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--privkey", required=True, help="path to raw 32-byte hex privkey file")
    ap.add_argument("--template", required=True, help="path to secp256k1_baked.h.in")
    ap.add_argument("--out", required=True, help="output secp256k1_baked.h path")
    args = ap.parse_args()

    try:
        privkey_bytes = read_privkey_hex(args.privkey)
        x_bytes, y_is_even = derive_and_validate(privkey_bytes)
        with open(args.template, "r") as f:
            template = f.read()
    except Exception as e:
        sys.stderr.write(
            "gen_secp256k1_baked.py: FATAL: could not generate %s (from privkey "
            "%s, template %s): %s\n" % (args.out, args.privkey, args.template, e)
        )
        return 1

    x_bytes_literal = "{ " + ", ".join("0x%02x" % b for b in x_bytes) + " }"
    rendered = (
        template.replace("@PUBKEY_X_BYTES@", x_bytes_literal)
        .replace("@Y_IS_EVEN@", "1" if y_is_even else "0")
    )

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w") as f:
        f.write(rendered)

    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
Generate secp256k1_baked.h (spec #43, sub-issues #46/#47) from
include/secp256k1_baked.h.in plus the same per-event 32-byte hex secp256k1
private key gen_event_profile.py reads.

Bakes TWO independent build-time constants into that one generated header:

  (A) the public point P = d*G (P.x bytes plus P's y-parity flag), so the
      runtime signing path never computes P via a scalar multiplication --
      see the template's own header comment for the full rationale
      (sub-issue #46). Depends on the per-event private key.

  (B) a fixed-base comb/window table for k*G (the FIXED generator G), so
      the runtime signing path's other scalar multiplication -- R = k'*G,
      k' derived fresh per signature from the nonce hash -- replaces ~256
      per-bit double-and-add iterations with a small table lookup per comb
      column instead (sub-issue #47; see build_comb_table()/
      validate_comb_table() below and secp256k1.c's point_mul_base_comb()
      for the matching C algorithm). Depends only on the fixed public
      generator G, never the private key -- but is computed and validated
      on every generator run anyway, right alongside (A), since #47's own
      acceptance criteria call for extending this SAME generator/template
      rather than adding a second, parallel one.

Fails closed (nonzero exit, no output file written) if the private key is
malformed, out of range, if P fails any validation check below, or if the
comb table fails ITS validation (see validate_comb_table()):
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
import random
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


# ---------------------------------------------------------------------------
# Fixed-base comb table for k*G (spec #43, sub-issue #47)
# ---------------------------------------------------------------------------
#
# Replaces the runtime k*G scalar multiplication schnorr_adapter.c performs
# for the nonce point R = k'*G (secp256k1.c's pipeline_secp256k1_point_mul_
# base) with a lookup into a small precomputed table for the FIXED
# generator G, instead of ~256 per-bit point doublings/additions. Standard
# "comb" construction (Handbook of Applied Cryptography, Algorithm 3.44):
# split a 256-bit scalar k into COMB_D "rows" of COMB_E-bit spans (k padded
# with high zero bits to COMB_D*COMB_E = 258 bits, since 258 > 256), so
# k = sum_{i=0..D-1} k_i * 2^(i*E), each k_i an E-bit row. Precompute basis
# points B_i = 2^(i*E) * G for each row, and a table T[s] (indexed by a
# D-bit digit s, bit i of s selecting whether B_i is included) =
# sum_{i: bit i of s set} B_i, for every s in [0, 2^D). Scalar multiplication
# then does COMB_E doublings, each followed by AT MOST one table lookup/add
# (using the D-bit digit gathered from column `col` across all D rows)
# instead of 256 doublings and up to 256 adds -- see secp256k1.c's
# point_mul_base_comb() for the exact same algorithm re-implemented in C
# (and tools/pipeline_test/main.c's differential sweep proving the two
# agree at RUNTIME, on the actual generated table, not just here at
# generation time against a second Python re-implementation).
#
# COMB_D = 6 is a deliberate, hand-picked tradeoff, not the large table
# upstream libsecp256k1 defaults to (which favors table size over cache
# footprint on a general-purpose CPU with megabytes of cache to spare).
# The table holds 2^COMB_D = 64 points (index 0 unused -- the "no bits set"
# digit is never looked up, see point_mul_base_comb()'s own comment), each
# stored as TWO pipeline_secp256k1_num (32 bytes each in secp256k1.c's
# internal representation) = 64 bytes/point, for 64 * 64 = 4096 bytes
# (4 KB) total: exactly HALF of the VR4300's 8 KB data cache, leaving
# headroom for the rest of the signing path's working set (the field
# prime/curve-order constants, the in-flight Jacobian accumulator, etc.) to
# stay resident too, rather than the table alone saturating the whole
# budget. COMB_D = 7 (128 points, 8192 bytes) would consume the ENTIRE
# cache on the table alone, leaving no room for anything else; COMB_D = 8
# (upstream's own common default) is 256 points * 64 bytes = 16384 bytes,
# over 2x the WHOLE cache -- exactly the "large upstream default...
# thrash the cache" case sub-issue #47's issue text calls out by name.
# COMB_D = 6 was chosen over smaller widths (COMB_D = 4 or 5) because a
# larger D means fewer columns (COMB_E = ceil(256/COMB_D)), i.e. fewer
# point doublings/adds per k*G: COMB_D = 6 gives COMB_E = 43 columns (at
# most 43 doublings + 43 adds = 86 Jacobian point operations, versus the
# naive path's 256 doublings + up to 256 adds = up to 512), a meaningfully
# bigger win than COMB_D = 5's 52 columns (up to 104 ops) while still using
# only half, not all, of the cache budget.
COMB_D = 6
COMB_E = (256 + COMB_D - 1) // COMB_D  # ceil(256 / COMB_D) == 43
COMB_TABLE_SIZE = 1 << COMB_D          # 64
COMB_TABLE_BYTES = COMB_TABLE_SIZE * 64  # 2 field elements * 32 bytes each
COMB_CACHE_BUDGET_BYTES = 8192          # the VR4300's data cache size


def _comb_basis_points():
    """B_i = 2^(i*COMB_E) * G for i in [0, COMB_D), via COMB_E successive
    doublings of the previous basis point (B_0 = G)."""
    basis = [secp.G]
    for _ in range(1, COMB_D):
        p = basis[-1]
        for _ in range(COMB_E):
            p = secp._point_add(p, p)
        basis.append(p)
    return basis


def build_comb_table():
    """
    T[s] for s in [0, COMB_TABLE_SIZE): T[0] is the point at infinity
    (represented as None here -- point_mul_base_comb() never looks index 0
    up at runtime, see its own comment for why); T[s] for s != 0 is the sum
    of basis[i] for every bit i set in s.
    """
    basis = _comb_basis_points()
    table = [None] * COMB_TABLE_SIZE
    for s in range(1, COMB_TABLE_SIZE):
        pt = None
        for i in range(COMB_D):
            if (s >> i) & 1:
                pt = secp._point_add(pt, basis[i])
        table[s] = pt
    return table


def _comb_digit_value(s):
    """The scalar value k_s such that scalar_mult(k_s, G) should equal
    T[s] -- sum of 2^(i*COMB_E) for every bit i set in s. Used only to
    independently re-derive each table entry for validation below."""
    value = 0
    for i in range(COMB_D):
        if (s >> i) & 1:
            value += 1 << (i * COMB_E)
    return value


def _comb_scalar_mult(k, table):
    """
    Re-implements secp256k1.c's point_mul_base_comb() bit for bit, in
    Python, as the "does the ALGORITHM (not just the table's individual
    entries) match the reference math" oracle -- see validate_comb_table()
    below for how this differs from (and complements) the per-entry checks.
    """
    acc = None
    for col in range(COMB_E - 1, -1, -1):
        acc = secp._point_add(acc, acc)  # double
        s = 0
        for i in range(COMB_D - 1, -1, -1):
            bitpos = i * COMB_E + col
            bit = (k >> bitpos) & 1 if bitpos < 256 else 0
            s = (s << 1) | bit
        if s != 0:
            acc = secp._point_add(acc, table[s])
    return acc


def validate_comb_table(table):
    """
    Fails closed (raises ValueError) unless ALL of:
      (0) the table's byte size fits the 8 KB VR4300 data-cache budget
          sub-issue #47 requires (see the COMB_D comment above for why
          COMB_D = 6/4096 bytes was chosen well under this ceiling).
      (1) every non-identity table entry lies on the curve
          (y^2 == x^3 + 7 mod p) -- the reference EC math, same equation
          derive_and_validate() checks P against above.
      (2) every table entry independently re-derives via
          scalar_mult_msb_first(_comb_digit_value(s), G) -- a second,
          structurally different algorithm than the one build_comb_table()
          itself used to build the entry (mirrors derive_and_validate()'s
          own check (2) for P above, and for the same reason: comparing
          against a DIFFERENT loop structure, not just re-running the same
          summation, is what makes this a genuine independence check).
      (3) _comb_scalar_mult() (the same algorithm point_mul_base_comb()
          implements in C) matches secp.scalar_mult() (the plain LSB-first
          double-and-add reference already used elsewhere in this file) for
          a large, deterministically-seeded sweep of random k in
          [1, N-1] plus fixed edge-case scalars -- proving the comb
          ALGORITHM itself (not just its table's individual entries) is
          correct, exactly as derive_and_validate()'s own header comment
          distinguishes "on-curve" from "the RIGHT point" for P.
    This table depends only on the fixed public generator G, never the
    per-event private key, but is validated every time this generator runs
    anyway -- cheap relative to the key-derivation work above, and this way
    there is no separate one-off validation step that could go stale.
    """
    if COMB_TABLE_BYTES > COMB_CACHE_BUDGET_BYTES:
        raise ValueError(
            "comb table is %d bytes, over the %d-byte (8 KB) VR4300 data "
            "cache budget sub-issue #47 requires -- refusing to bake a "
            "table that would thrash the cache and defeat the speedup "
            "(reduce COMB_D)" % (COMB_TABLE_BYTES, COMB_CACHE_BUDGET_BYTES)
        )

    for s in range(1, COMB_TABLE_SIZE):
        entry = table[s]
        if entry is None:
            raise ValueError("comb table entry s=%d is unexpectedly the point at infinity" % s)
        x, y = entry

        # (1) On-curve check against the reference EC equation.
        lhs = (y * y) % secp.P
        rhs = (x * x * x + 7) % secp.P
        if lhs != rhs:
            raise ValueError(
                "comb table entry s=%d is not on the curve (y^2 != x^3+7 mod p) -- "
                "refusing to bake a wrong table" % s
            )

        # (2) Independent MSB-first re-derivation of the same value.
        reference_point = scalar_mult_msb_first(_comb_digit_value(s), secp.G)
        if reference_point != entry:
            raise ValueError(
                "comb table entry s=%d disagrees with an independent MSB-first "
                "re-derivation of the same value -- got %r, want %r"
                % (s, entry, reference_point)
            )

    # (3) Differential sweep of the comb ALGORITHM against the plain
    # LSB-first reference, over fixed edge cases plus a deterministically
    # seeded random sample -- a failure reproduces exactly (fixed seed).
    edge_cases = [1, 2, 3, secp.N - 1, secp.N - 2, (1 << 255), (1 << 255) - 1, (1 << 43), (1 << 258) - 1]
    rng = random.Random(0x53656370)  # fixed seed ("Secp" in ASCII hex, arbitrary but fixed)
    for k in edge_cases:
        k_mod = k % secp.N
        if k_mod == 0:
            continue
        expected = secp.scalar_mult(k_mod, secp.G)
        got = _comb_scalar_mult(k_mod, table)
        if got != expected:
            raise ValueError(
                "comb scalar multiplication disagrees with the reference for "
                "edge-case k=0x%x -- got %r, want %r" % (k_mod, got, expected)
            )
    for _ in range(200):
        k = rng.randrange(1, secp.N)
        expected = secp.scalar_mult(k, secp.G)
        got = _comb_scalar_mult(k, table)
        if got != expected:
            raise ValueError(
                "comb scalar multiplication disagrees with the reference for "
                "k=0x%x -- got %r, want %r" % (k, got, expected)
            )


def _num_c_literal(value):
    """value (a Python int in [0, 2^256)) as a C initializer for
    pipeline_secp256k1_num -- little-endian 32-bit limbs (w[0] least
    significant), matching secp256k1.c's own internal representation (see
    that file's header comment) EXACTLY, since this literal is read
    directly as a pipeline_secp256k1_num initializer with no runtime
    conversion -- unlike PUBKEY_X_BYTES above (plain big-endian bytes,
    representation-agnostic, converted at runtime via
    pipeline_secp256k1_num_from_bytes)."""
    words = [(value >> (32 * i)) & 0xFFFFFFFF for i in range(8)]
    return "{{" + ", ".join("0x%08xu" % w for w in words) + "}}"


def _comb_point_c_literal(point):
    """point (an (x, y) tuple, or None for the never-read s=0 slot) as a C
    initializer for comb_point ({ pipeline_secp256k1_num x, y; },
    secp256k1.c-private)."""
    if point is None:
        x, y = 0, 0
    else:
        x, y = point
    return "{ %s, %s }" % (_num_c_literal(x), _num_c_literal(y))


def comb_table_c_initializer(table):
    """
    A SINGLE physical line (no embedded newlines): this string becomes the
    replacement text of a plain `#define PIPELINE_SECP256K1_COMB_TABLE_INIT
    ...` object-like macro in the rendered header, and the C preprocessor
    only allows a macro body to span multiple physical lines via explicit
    backslash-newline continuations -- an embedded bare newline here would
    silently truncate the macro after its first line (only the "{" alone),
    corrupting every table entry after it. Kept on one line deliberately
    rather than injecting "\\\n" continuations, which would be equivalent
    but harder to eyeball for correctness in the generated header.
    """
    entries = [_comb_point_c_literal(pt) for pt in table]
    return "{ " + ", ".join(entries) + " }"


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
        comb_table = build_comb_table()
        validate_comb_table(comb_table)
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
        .replace("@COMB_D@", str(COMB_D))
        .replace("@COMB_E@", str(COMB_E))
        .replace("@COMB_TABLE_SIZE@", str(COMB_TABLE_SIZE))
        .replace("@COMB_TABLE_BYTES@", str(COMB_TABLE_BYTES))
        .replace("@COMB_CACHE_BUDGET_BYTES@", str(COMB_CACHE_BUDGET_BYTES))
        .replace("@COMB_TABLE_INIT@", comb_table_c_initializer(comb_table))
    )

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w") as f:
        f.write(rendered)

    return 0


if __name__ == "__main__":
    sys.exit(main())

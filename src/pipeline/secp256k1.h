#ifndef PIPELINE_SECP256K1_H
#define PIPELINE_SECP256K1_H

/*
 * Internal C99 port (spec #24, sub-issue #29) of the secp256k1 elliptic
 * curve arithmetic needed for BIP-340 Schnorr signing: fixed-width 256-bit
 * integer arithmetic (32-bit limbs, chosen for the VR4300's native word
 * size -- see spec #24's "32-bit reps" implementation note) plus point
 * doubling/addition/scalar multiplication over secp256k1's short
 * Weierstrass curve y^2 = x^3 + 7 (a = 0, b = 7).
 *
 * This is a from-scratch, minimal port written for this project -- not a
 * vendor drop of bitcoin-core/secp256k1's own (heavily optimized,
 * constant-time) implementation. It is NOT constant-time: spec #24
 * explicitly locked "no cycle-budget gating" for this one-shot,
 * time-stopped-screen signing operation ("Performance / cycle-budget
 * gating: k*G is one-shot on the time-stopped screen; locked with no
 * measurement gate"), so this trades side-channel hardening for a
 * smaller, more directly auditable implementation -- that tradeoff is
 * unchanged by spec #43.
 *
 * Spec #43 (sub-issue #44) replaced the field path's reduction: field
 * multiplies (mod p) now use reduction specialized to secp256k1 p's
 * pseudo-Mersenne form (p = 2^256 - 2^32 - 977, folding 2^256 = 2^32 + 977
 * mod p -- see fe_reduce_wide in secp256k1.c) instead of the generic
 * schoolbook binary long division (reduce_wide_mod), which was the
 * dominant cost of a signature (a 512-iteration bit-serial divide inside
 * every field multiply).
 *
 * Spec #43 sub-issue #45 did the same for the scalar (mod n) path: scalar
 * reduction/multiplication (pipeline_secp256k1_scalar_reduce/_mul below,
 * used to reduce the BIP-340 nonce k and challenge e and to compute
 * s = (k + e*d) mod n) now use reduction specialized to the curve order n
 * via the same "fold 2^256 = c (mod n)" identity, just with n's own
 * (larger, ~129-bit, multi-word) complement c = 2^256 - n instead of p's
 * tiny single-word 977 -- see scalar_reduce_wide in secp256k1.c.
 *
 * reduce_wide_mod is RETAINED, used by neither runtime path any more, only
 * as the differential-tested naive reference both fast reductions are
 * checked against (see pipeline_secp256k1_fe_mul_reference/
 * pipeline_secp256k1_scalar_reduce_reference/_mul_reference below and
 * tools/pipeline_test/main.c's differential sweeps) -- it is no longer an
 * intentional correctness-first tradeoff on either path, just a generic
 * reduction kept solely as an oracle. Scalar multiplication (point scalar
 * mul, not the mod-n scalar multiply above) uses Jacobian coordinates (a
 * single field inversion per multiplication, at the very end) rather than
 * naive per-step affine inversion, and (as of sub-issue #48 below) that one
 * inversion itself is no longer slow either.
 *
 * Spec #43 sub-issue #46 removed one of the two pipeline_secp256k1_point_
 * mul_base calls a signature used to make: the per-event private key is
 * itself a build-time constant, so its public point P = d*G is one too --
 * it is now computed and validated once at build time (see
 * tools/gen_secp256k1_baked.py and the generated secp256k1_baked.h) and
 * baked into schnorr_adapter.c as a constant, instead of being
 * point_mul_base'd (and Jacobian-to-affine-inverted) on every signature.
 * pipeline_secp256k1_point_mul_base's OTHER call site, R = k'*G (k' is
 * nonce-derived per signature, never a build-time constant, so it can
 * never be baked away the way P was), remains -- sub-issue #47 (below)
 * speeds that one up instead of removing it.
 *
 * Spec #43 sub-issue #47 replaced pipeline_secp256k1_point_mul_base's OWN
 * algorithm: it no longer runs point_mul_core's generic per-bit double-
 * and-add (256 doublings, up to 256 additions) against the runtime base
 * point argument. Because this function's base point is always the FIXED
 * generator G, it now uses a small precomputed fixed-base comb/window
 * table for G instead (point_mul_base_comb in secp256k1.c) -- COMB_E
 * doublings (43) each followed by at most one table-lookup addition,
 * generated and validated at build time by the SAME tools/
 * gen_secp256k1_baked.py generator #46 added (see secp256k1_baked.h's own
 * header comment for the table's algorithm and its 8 KB VR4300 data-cache
 * budget). point_mul_core itself is unchanged and still used by
 * pipeline_secp256k1_point_mul (arbitrary base point, not fixed -- no comb
 * table applies) and, as the RETAINED naive reference, by
 * pipeline_secp256k1_point_mul_base_reference below (this sub-issue's own
 * differential-test oracle, exactly mirroring how #44/#45 kept
 * reduce_wide_mod around solely as their fast reductions' oracle).
 *
 * Spec #43 sub-issue #48 replaced the field inversion fe_inv performs
 * (mod-p inversion, used once per signature by jac_to_affine when R = k'*G
 * is converted from Jacobian back to affine coordinates -- the only field
 * inversion a signature still runs, now that sub-issue #46 baked P = d*G
 * at build time and removed the second one): it no longer computes a^-1 mod
 * p via full 256-bit square-and-multiply Fermat exponentiation
 * (fe_pow(a, p-2), one squaring AND, per set exponent bit, one multiply,
 * for all 256 bits). It now uses the published fixed secp256k1 addition
 * chain for that exact exponent instead (255 squarings + 15 multiplications
 * total -- see fe_inv in secp256k1.c) -- roughly half the field multiplies
 * of the generic path, for the identical result. fe_pow itself is RETAINED,
 * used only by lift_x's modular square root (a different, caller-supplied
 * exponent this hand-derived chain does not apply to), and as
 * pipeline_secp256k1_fe_inv_reference below's naive oracle.
 *
 * Point arithmetic takes/returns the same affine (x, y) representation as
 * tools/nostr_secp256k1.py's scalar_mult/point_add (used at BUILD TIME
 * only, for pubkey derivation) -- that file's own header comment calls out
 * this on-device signing port as separate, later work; this is that work.
 * The internal formulas differ, though: nostr_secp256k1.py multiplies
 * directly in affine coordinates (a field inversion per point operation,
 * fine for Python's arbitrary-precision arithmetic and a one-shot build
 * step), while this port's scalar multiplication (see point_mul_core in
 * secp256k1.c) works internally in Jacobian coordinates and only converts
 * back to affine once, at the very end -- see the performance note above.
 *
 * Like sha256.h/qrcodegen.h, this header/its .c never include <stdint.h>/
 * <string.h>/<stddef.h> (the ROM build's -nostdinc/-ffreestanding), use
 * this pipeline's own pipeline_u8/pipeline_u32 typedefs (from
 * build_event.h) in place of uint8_t/uint32_t/size_t, and go through the
 * root Makefile's per-object C99 carve-out (PIPELINE_C99_PORT_O), never
 * the whole-build COMPILER knob. It is compiled unmodified into both the
 * ROM build and the host test tool (tools/pipeline_test).
 *
 * Called only from within src/pipeline/ (schnorr_adapter.c, sub-issue
 * #29); game glue never calls this header directly, and never will --
 * schnorr_adapter.h is the only sanctioned caller of this port.
 */

#include "build_event.h"

#define PIPELINE_SECP256K1_BYTES 32

/*
 * A 256-bit unsigned integer. Callers must never rely on this struct's
 * in-memory layout (word order/endianness) -- always go through
 * pipeline_secp256k1_num_from_bytes/pipeline_secp256k1_num_to_bytes at the
 * byte boundary, mirroring the same discipline build_event.h documents for
 * StarCapture.
 */
typedef struct {
    pipeline_u32 w[8];
} pipeline_secp256k1_num;

/* An affine point on the curve. infinity is nonzero for the point at
 * infinity (the identity element), in which case x/y are unspecified. */
typedef struct {
    pipeline_secp256k1_num x;
    pipeline_secp256k1_num y;
    int infinity;
} pipeline_secp256k1_point;

/* Big-endian byte <-> num conversion -- BIP-340 encodes field elements and
 * scalars as big-endian 32-byte strings. */
void pipeline_secp256k1_num_from_bytes(const pipeline_u8 in[PIPELINE_SECP256K1_BYTES], pipeline_secp256k1_num *out);
void pipeline_secp256k1_num_to_bytes(const pipeline_secp256k1_num *in, pipeline_u8 out[PIPELINE_SECP256K1_BYTES]);

int pipeline_secp256k1_num_is_zero(const pipeline_secp256k1_num *a);

/*
 * Reduces an arbitrary value a (0 <= a < 2^256) modulo the curve order n,
 * yielding a value in [0, n). Used to turn raw 32-byte hash outputs (the
 * BIP-340 nonce/challenge scalars) into valid scalars.
 */
void pipeline_secp256k1_scalar_reduce(const pipeline_secp256k1_num *a, pipeline_secp256k1_num *out);

/* out = (a + b) mod n. */
void pipeline_secp256k1_scalar_add(const pipeline_secp256k1_num *a, const pipeline_secp256k1_num *b, pipeline_secp256k1_num *out);

/* out = (a * b) mod n. */
void pipeline_secp256k1_scalar_mul(const pipeline_secp256k1_num *a, const pipeline_secp256k1_num *b, pipeline_secp256k1_num *out);

/* out = (n - a) mod n; requires 0 < a < n (BIP-340's key/nonce negation,
 * applied when a point's y coordinate is odd). */
void pipeline_secp256k1_scalar_negate(const pipeline_secp256k1_num *a, pipeline_secp256k1_num *out);

/* True iff 0 < a < n -- the valid private-key/nonce scalar range. */
int pipeline_secp256k1_scalar_in_range(const pipeline_secp256k1_num *a);

/* out = k * G (the curve's base point/generator), via the fixed-base comb
 * table (spec #43, sub-issue #47 -- point_mul_base_comb in secp256k1.c).
 * Undefined (out->infinity set) only if k is 0 mod n, which
 * pipeline_secp256k1_scalar_in_range() rules out for valid callers. */
void pipeline_secp256k1_point_mul_base(const pipeline_secp256k1_num *k, pipeline_secp256k1_point *out);

/* out = k * base, for an arbitrary affine input point (base->infinity must
 * be 0). Used only by pipeline_schnorr_verify's internal self-consistency
 * check (verification needs k*pubkey, not just k*G) -- never called from
 * the signing path itself. */
void pipeline_secp256k1_point_mul(const pipeline_secp256k1_num *k, const pipeline_secp256k1_point *base, pipeline_secp256k1_point *out);

/* True iff p's y coordinate is even (BIP-340's has_even_y). p must not be
 * the point at infinity. */
int pipeline_secp256k1_point_y_is_even(const pipeline_secp256k1_point *p);

/*
 * pipeline_secp256k1_point_lift_x: BIP-340's lift_x(x) -- given a 32-byte
 * big-endian x coordinate, finds the unique point on the curve with that x
 * coordinate and an EVEN y (secp256k1's p is congruent to 3 mod 4, so the
 * square root of x^3+7 is computed directly via y = (x^3+7)^((p+1)/4) mod
 * p, then negated if that root came out odd). Returns nonzero (true) and
 * fills *out iff x < p and x^3+7 is a quadratic residue mod p (i.e. x is a
 * genuine on-curve x-only public key); returns 0 otherwise. Used only by
 * pipeline_schnorr_verify (to turn an x-only pubkey back into a full
 * point) -- never by the signing path.
 */
int pipeline_secp256k1_point_lift_x(const pipeline_u8 x[PIPELINE_SECP256K1_BYTES], pipeline_secp256k1_point *out);

/* out = (p - a) mod p, i.e. the field negation of a (0 stays 0). Used only
 * by pipeline_schnorr_verify to negate a point's y coordinate when forming
 * R = sG - eP = sG + (eP.x, -eP.y) -- never by the signing path. */
void pipeline_secp256k1_field_negate(const pipeline_secp256k1_num *a, pipeline_secp256k1_num *out);

/*
 * out = p1 + p2, for two arbitrary affine input points (either may be the
 * point at infinity). Used only by pipeline_schnorr_verify to form
 * R = sG + (-eP) -- never by the signing path, which only ever needs
 * scalar multiplication by G.
 */
void pipeline_secp256k1_point_add(const pipeline_secp256k1_point *p1, const pipeline_secp256k1_point *p2, pipeline_secp256k1_point *out);

/* True iff p (a field element that is a candidate signature/point x
 * coordinate) is strictly less than the field prime -- the range check
 * BIP-340 verification applies to sig[0:32] before treating it as an x
 * coordinate. */
int pipeline_secp256k1_num_is_valid_field_element(const pipeline_secp256k1_num *a);

/*
 * ---- Test-only diagnostic surface (spec #43 sub-issues #44/#45/#47/#48) ----
 *
 * Never called from signing/verification themselves (schnorr_adapter.c
 * only ever reaches field/scalar/point multiplication indirectly, through
 * the point-arithmetic/scalar entry points above) -- only from
 * tools/pipeline_test, so a rewrite of the internal field/scalar-multiply/
 * point-multiply representation can be proven behavior-preserving directly
 * at the arithmetic-op boundary, not just through whole-signature KATs.
 */

/* out = k * G, via the RETAINED naive generic double-and-add path
 * (point_mul_core, the same algorithm pipeline_secp256k1_point_mul_base
 * itself used before sub-issue #47) -- the differential-test/op-count-
 * proxy oracle for pipeline_secp256k1_point_mul_base's comb-table fast
 * path, exactly mirroring how the _reference functions below are kept
 * solely as sub-issues #44/#45's own oracles. */
void pipeline_secp256k1_point_mul_base_reference(const pipeline_secp256k1_num *k, pipeline_secp256k1_point *out);

/* out = a * b mod p, via the fast field-specialized reduction (identical
 * to what every fe_mul call inside this file uses). */
void pipeline_secp256k1_fe_mul_fast(const pipeline_secp256k1_num *a, const pipeline_secp256k1_num *b, pipeline_secp256k1_num *out);

/* out = a * b mod p, via the RETAINED naive generic-reduction path
 * (reduce_wide_mod) -- the differential-test oracle for
 * pipeline_secp256k1_fe_mul_fast above. */
void pipeline_secp256k1_fe_mul_reference(const pipeline_secp256k1_num *a, const pipeline_secp256k1_num *b, pipeline_secp256k1_num *out);

/*
 * out = a mod n / out = a * b mod n, via the fast curve-order-specialized
 * reduction (identical to what pipeline_secp256k1_scalar_reduce/_mul above
 * use -- sub-issue #45). */
void pipeline_secp256k1_scalar_reduce_fast(const pipeline_secp256k1_num *a, pipeline_secp256k1_num *out);
void pipeline_secp256k1_scalar_mul_fast(const pipeline_secp256k1_num *a, const pipeline_secp256k1_num *b, pipeline_secp256k1_num *out);

/* out = a mod n / out = a * b mod n, via the RETAINED naive generic-
 * reduction path (reduce_wide_mod) -- the differential-test oracle for
 * the two _fast functions above. */
void pipeline_secp256k1_scalar_reduce_reference(const pipeline_secp256k1_num *a, pipeline_secp256k1_num *out);
void pipeline_secp256k1_scalar_mul_reference(const pipeline_secp256k1_num *a, const pipeline_secp256k1_num *b, pipeline_secp256k1_num *out);

/*
 * out = a^-1 mod p, via the fast fixed addition-chain inversion (identical
 * to what jac_to_affine's single per-signature inversion uses -- sub-issue
 * #48) / via the RETAINED naive full-256-bit Fermat exponentiation path --
 * the differential-test oracle for the _fast function. a must be nonzero. */
void pipeline_secp256k1_fe_inv_fast(const pipeline_secp256k1_num *a, pipeline_secp256k1_num *out);
void pipeline_secp256k1_fe_inv_reference(const pipeline_secp256k1_num *a, pipeline_secp256k1_num *out);

/*
 * Host-side primitive-operation-count proxy (spec #43 sub-issue
 * #44, reused by later sub-issues in this spec's staged landing --
 * including sub-issue #45's scalar-path fast reduction, which is why the
 * backing counter is g_prim_op_count, not field-scoped). Counts primitive
 * 32-bit-limb operations performed by the width-parameterized
 * compare/add/subtract/multiply-by-scalar/multiply-by-array array
 * primitives (arr_cmp/arr_sub/arr_add/arr_mul_small/arr_mul_wide) and by
 * reduce_wide_mod's per-bit loop, since the last reset. reduce_wide_mod,
 * fe_reduce_wide (fast field reduction), and scalar_reduce_wide (fast
 * scalar reduction, sub-issue #45) are their main callers and dominate any
 * real count, but num_cmp/num_sub (used by a few non-reduction callers
 * too, e.g. addmod/submod/field negation) share the same width-
 * parameterized primitives and so are counted as well -- this is a general
 * primitive-operation counter, not one scoped narrowly to "reduction
 * calls" only.
 * Deliberately excluded: num_mul's own 32x32 schoolbook partial-product
 * loop, which is unchanged between the fast and naive field-multiply
 * paths and so would add nothing to a fast-vs-naive comparison. A deterministic,
 * architecture-agnostic stand-in for signing cost, since wall-clock time
 * on x86 does not reflect the VR4300 (see the header comment above).
 *
 * Only counts anything when secp256k1.c is compiled with
 * PIPELINE_SECP256K1_OP_COUNT defined (tools/pipeline_test/Makefile does
 * this for the host test tool only); otherwise
 * pipeline_secp256k1_get_op_count() always returns 0 and reset is a no-op
 * -- so the ROM build (which never defines that macro) pays nothing for
 * this, not even the counter increments. Not thread-safe when enabled;
 * this pipeline is single-threaded everywhere it runs.
 */
void pipeline_secp256k1_reset_op_count(void);
unsigned long long pipeline_secp256k1_get_op_count(void);

/*
 * Host-side field-INVERSION count (spec #43 sub-issue #48). Counts calls
 * to the one field-inversion primitive the signing path runs (fe_inv,
 * reached via jac_to_affine when R = k'*G is converted to affine
 * coordinates) since the last pipeline_secp256k1_reset_op_count() call --
 * lets tools/pipeline_test assert directly that a signature performs AT
 * MOST ONE modular inversion (this sub-issue's own acceptance criterion),
 * not just that inversion got cheaper. Same PIPELINE_SECP256K1_OP_COUNT
 * gating (always 0 unless that macro is defined) and reset pairing as
 * pipeline_secp256k1_get_op_count() above -- not a separate compile-time
 * knob.
 */
unsigned long long pipeline_secp256k1_get_inversion_count(void);

#endif /* PIPELINE_SECP256K1_H */

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
 * This is a from-scratch, minimal, correctness-first port written for this
 * project -- not a vendor drop of bitcoin-core/secp256k1's own (heavily
 * optimized, constant-time, field-specific-reduction) implementation.
 * Field/scalar reduction is done generically via schoolbook binary long
 * division (see reduce_wide_mod in secp256k1.c) rather than secp256k1 p's
 * special fast-reduction form (p = 2^256 - 2^32 - 977) or a constant-time
 * ladder: spec #24 explicitly locks "no cycle-budget gating" for this
 * one-shot, time-stopped-screen signing operation ("Performance /
 * cycle-budget gating: k*G is one-shot on the time-stopped screen; locked
 * with no measurement gate"), so this trades raw speed and side-channel
 * hardening for a smaller, more directly auditable implementation. Scalar
 * multiplication uses Jacobian coordinates (a single field inversion per
 * multiplication, at the very end) rather than naive per-step affine
 * inversion, which would otherwise be prohibitively slow under this
 * generic reduction -- that is a correctness-adjacent performance choice
 * (keeping a single build within a plausible run time), not a
 * cycle-budget commitment.
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

/* out = k * G (the curve's base point/generator). Undefined (out->infinity
 * set) only if k is 0 mod n, which pipeline_secp256k1_scalar_in_range()
 * rules out for valid callers. */
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

#endif /* PIPELINE_SECP256K1_H */

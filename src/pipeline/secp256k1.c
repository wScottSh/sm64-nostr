/*
 * See secp256k1.h. Internal representation: pipeline_secp256k1_num.w[0] is
 * the LEAST significant 32-bit word, w[7] the most significant (i.e.
 * little-endian limb order) -- the natural order for the schoolbook
 * add/sub/multiply loops below (ascending index = ascending significance).
 * This is the OPPOSITE of the big-endian byte order BIP-340 encodes values
 * in; pipeline_secp256k1_num_from_bytes/_to_bytes are the only two places
 * that ever reverse between the two, exactly like pack_adapter.c's
 * write_u32_be/read_u32_be are the only byte-order-aware functions in this
 * codebase. No other function in this file, nor any caller, may assume a
 * particular word order -- construct/read every pipeline_secp256k1_num via
 * those two functions or the arithmetic functions in secp256k1.h.
 *
 * `unsigned long long` (a built-in type needing no header, same
 * justification as sha256.h's bitlen field) is used as the carry/widening
 * type for 32x32->64-bit partial products and add/sub carries -- the VR4300
 * is 32-bit, so this becomes a compiler-synthesized double-word op, not a
 * native instruction, but it is still a plain arithmetic expression gcc
 * lowers inline, needing no library call.
 */

#include "secp256k1.h"

#define NUM_WORDS 8
#define WIDE_WORDS 16
#define REM_WORDS 9 /* one extra word of headroom for the reduce_wide_mod remainder */

/* A 512-bit unsigned integer: the output of a 256x256 multiply, before
 * reduction. Same little-endian limb order as pipeline_secp256k1_num. */
typedef struct {
    pipeline_u32 w[WIDE_WORDS];
} wide_num;

/* secp256k1 field prime p = 2^256 - 2^32 - 977. */
static const pipeline_secp256k1_num kFieldP = {{
    0xFFFFFC2Fu, 0xFFFFFFFEu, 0xFFFFFFFFu, 0xFFFFFFFFu,
    0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu,
}};

/* secp256k1 curve order n. */
static const pipeline_secp256k1_num kCurveN = {{
    0xD0364141u, 0xBFD25E8Cu, 0xAF48A03Bu, 0xBAAEDCE6u,
    0xFFFFFFFEu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu,
}};

/* Base point (generator) G's affine coordinates. */
static const pipeline_secp256k1_num kGx = {{
    0x16F81798u, 0x59F2815Bu, 0x2DCE28D9u, 0x029BFCDBu,
    0xCE870B07u, 0x55A06295u, 0xF9DCBBACu, 0x79BE667Eu,
}};
static const pipeline_secp256k1_num kGy = {{
    0xFB10D4B8u, 0x9C47D08Fu, 0xA6855419u, 0xFD17B448u,
    0x0E1108A8u, 0x5DA4FBFCu, 0x26A3C465u, 0x483ADA77u,
}};

/* ---- fixed-width big-integer primitives (mod 2^256, little-endian limbs) ---- */

static void num_zero(pipeline_secp256k1_num *out)
{
    int i;
    for (i = 0; i < NUM_WORDS; i++) {
        out->w[i] = 0;
    }
}

static void num_from_small(pipeline_u32 v, pipeline_secp256k1_num *out)
{
    num_zero(out);
    out->w[0] = v;
}

/* Width-parameterized little-endian-limb-array compare/subtract, shared by
 * num_cmp/num_sub (width NUM_WORDS) and reduce_wide_mod's 9-word remainder
 * arithmetic (width REM_WORDS) below, so the two widths don't duplicate the
 * same borrow/comparison logic twice. */
static int arr_cmp(const pipeline_u32 *a, const pipeline_u32 *b, int width)
{
    int i;
    for (i = width - 1; i >= 0; i--) {
        if (a[i] != b[i]) {
            return (a[i] < b[i]) ? -1 : 1;
        }
    }
    return 0;
}

/* out = (a - b) mod 2^(32*width); returns 1 if a < b (a borrow occurred). */
static pipeline_u32 arr_sub(const pipeline_u32 *a, const pipeline_u32 *b, int width, pipeline_u32 *out)
{
    unsigned long long borrow = 0;
    int i;
    for (i = 0; i < width; i++) {
        unsigned long long ai = a[i];
        unsigned long long bi = (unsigned long long)b[i] + borrow;
        if (ai >= bi) {
            out[i] = (pipeline_u32)(ai - bi);
            borrow = 0;
        } else {
            out[i] = (pipeline_u32)((ai + (1ULL << 32)) - bi);
            borrow = 1;
        }
    }
    return (pipeline_u32)borrow;
}

static int num_cmp(const pipeline_secp256k1_num *a, const pipeline_secp256k1_num *b)
{
    return arr_cmp(a->w, b->w, NUM_WORDS);
}

int pipeline_secp256k1_num_is_zero(const pipeline_secp256k1_num *a)
{
    int i;
    for (i = 0; i < NUM_WORDS; i++) {
        if (a->w[i] != 0) {
            return 0;
        }
    }
    return 1;
}

/* Only used within this file (point_y_is_even/lift_x's even-root choice);
 * not part of the public seam, unlike pipeline_secp256k1_num_is_zero. */
static int num_is_odd(const pipeline_secp256k1_num *a)
{
    return (int)(a->w[0] & 1u);
}

/* out = (a + b) mod 2^256; returns the carry bit that overflowed out of the
 * top word (i.e. the "true" 257th bit of the unmodded sum). */
static pipeline_u32 num_add(const pipeline_secp256k1_num *a, const pipeline_secp256k1_num *b, pipeline_secp256k1_num *out)
{
    unsigned long long carry = 0;
    int i;
    for (i = 0; i < NUM_WORDS; i++) {
        unsigned long long sum = (unsigned long long)a->w[i] + b->w[i] + carry;
        out->w[i] = (pipeline_u32)sum;
        carry = sum >> 32;
    }
    return (pipeline_u32)carry;
}

/* out = (a - b) mod 2^256; returns 1 if a < b (a borrow occurred), else 0. */
static pipeline_u32 num_sub(const pipeline_secp256k1_num *a, const pipeline_secp256k1_num *b, pipeline_secp256k1_num *out)
{
    return arr_sub(a->w, b->w, NUM_WORDS, out->w);
}

/* out = a * b, full 512-bit product (schoolbook long multiplication). */
static void num_mul(const pipeline_secp256k1_num *a, const pipeline_secp256k1_num *b, wide_num *out)
{
    int i, j;
    for (i = 0; i < WIDE_WORDS; i++) {
        out->w[i] = 0;
    }
    for (i = 0; i < NUM_WORDS; i++) {
        unsigned long long carry = 0;
        for (j = 0; j < NUM_WORDS; j++) {
            unsigned long long prod = (unsigned long long)a->w[i] * b->w[j] + out->w[i + j] + carry;
            out->w[i + j] = (pipeline_u32)prod;
            carry = prod >> 32;
        }
        {
            int k = i + NUM_WORDS;
            while (carry != 0) {
                unsigned long long sum = (unsigned long long)out->w[k] + carry;
                out->w[k] = (pipeline_u32)sum;
                carry = sum >> 32;
                k++;
            }
        }
    }
}

/*
 * reduce_wide_mod: out = x mod m, for a 512-bit x and 256-bit modulus m,
 * via schoolbook binary long division -- one bit of x consumed per
 * iteration, from the most significant bit down. The running remainder is
 * kept in REM_WORDS (9) limbs: since the loop invariant keeps
 * remainder < 2*m < 2^257, 9 words (288 bits) of headroom is always
 * sufficient and the final remainder's top word is always 0.
 *
 * This is deliberately the generic, unoptimized reduction (no use of
 * secp256k1 p's special 2^256-2^32-977 form) -- see secp256k1.h's header
 * comment on the performance/correctness-first tradeoff.
 */
static void reduce_wide_mod(const wide_num *x, const pipeline_secp256k1_num *m, pipeline_secp256k1_num *out)
{
    pipeline_u32 rem[REM_WORDS];
    pipeline_u32 mext[REM_WORDS];
    int i;
    int bitpos;

    for (i = 0; i < REM_WORDS; i++) {
        rem[i] = 0;
        mext[i] = (i < NUM_WORDS) ? m->w[i] : 0;
    }

    for (bitpos = WIDE_WORDS * 32 - 1; bitpos >= 0; bitpos--) {
        pipeline_u32 bit = (x->w[bitpos / 32] >> (bitpos % 32)) & 1u;

        /* Shift rem left by 1 (9-word), bringing bit into the new LSB. */
        pipeline_u32 carry = bit;
        for (i = 0; i < REM_WORDS; i++) {
            pipeline_u32 nextCarry = rem[i] >> 31;
            rem[i] = (rem[i] << 1) | carry;
            carry = nextCarry;
        }

        /* Conditional subtract: if rem >= mext, rem -= mext (in place --
         * arr_sub reads/writes the same array here, which is safe since it
         * only ever reads index i before writing index i). */
        if (arr_cmp(rem, mext, REM_WORDS) >= 0) {
            arr_sub(rem, mext, REM_WORDS, rem);
        }
    }

    for (i = 0; i < NUM_WORDS; i++) {
        out->w[i] = rem[i];
    }
}

static void addmod(const pipeline_secp256k1_num *a, const pipeline_secp256k1_num *b, const pipeline_secp256k1_num *m, pipeline_secp256k1_num *out)
{
    pipeline_secp256k1_num sum;
    pipeline_u32 carry = num_add(a, b, &sum);
    if (carry != 0 || num_cmp(&sum, m) >= 0) {
        num_sub(&sum, m, out);
    } else {
        *out = sum;
    }
}

static void submod(const pipeline_secp256k1_num *a, const pipeline_secp256k1_num *b, const pipeline_secp256k1_num *m, pipeline_secp256k1_num *out)
{
    if (num_cmp(a, b) >= 0) {
        num_sub(a, b, out);
    } else {
        pipeline_secp256k1_num diff;
        num_sub(b, a, &diff);
        num_sub(m, &diff, out);
    }
}

static void mulmod(const pipeline_secp256k1_num *a, const pipeline_secp256k1_num *b, const pipeline_secp256k1_num *m, pipeline_secp256k1_num *out)
{
    wide_num wide;
    num_mul(a, b, &wide);
    reduce_wide_mod(&wide, m, out);
}

/* ---- byte conversion ---- */

void pipeline_secp256k1_num_from_bytes(const pipeline_u8 in[PIPELINE_SECP256K1_BYTES], pipeline_secp256k1_num *out)
{
    int i;
    for (i = 0; i < NUM_WORDS; i++) {
        /* Word i (little-endian limb index) holds the byte range covering
         * big-endian bytes [28 - 4*i, 32 - 4*i). */
        pipeline_u32 base = (pipeline_u32)(NUM_WORDS - 1 - i) * 4u;
        out->w[i] = ((pipeline_u32)in[base] << 24) | ((pipeline_u32)in[base + 1] << 16) |
                    ((pipeline_u32)in[base + 2] << 8) | (pipeline_u32)in[base + 3];
    }
}

void pipeline_secp256k1_num_to_bytes(const pipeline_secp256k1_num *in, pipeline_u8 out[PIPELINE_SECP256K1_BYTES])
{
    int i;
    for (i = 0; i < NUM_WORDS; i++) {
        pipeline_u32 base = (pipeline_u32)(NUM_WORDS - 1 - i) * 4u;
        pipeline_u32 v = in->w[i];
        out[base]     = (pipeline_u8)((v >> 24) & 0xFFu);
        out[base + 1] = (pipeline_u8)((v >> 16) & 0xFFu);
        out[base + 2] = (pipeline_u8)((v >> 8) & 0xFFu);
        out[base + 3] = (pipeline_u8)(v & 0xFFu);
    }
}

/* ---- field arithmetic (mod p) -- file-internal only ---- */

static void fe_add(const pipeline_secp256k1_num *a, const pipeline_secp256k1_num *b, pipeline_secp256k1_num *out) { addmod(a, b, &kFieldP, out); }
static void fe_sub(const pipeline_secp256k1_num *a, const pipeline_secp256k1_num *b, pipeline_secp256k1_num *out) { submod(a, b, &kFieldP, out); }
static void fe_mul(const pipeline_secp256k1_num *a, const pipeline_secp256k1_num *b, pipeline_secp256k1_num *out) { mulmod(a, b, &kFieldP, out); }
static void fe_sqr(const pipeline_secp256k1_num *a, pipeline_secp256k1_num *out) { mulmod(a, a, &kFieldP, out); }

/* out = base^exponent mod p, via square-and-multiply. Shared by fe_inv
 * (exponent = p-2, Fermat's little theorem) and the modular square root
 * used by lift_x (exponent = (p+1)/4, valid since p = 3 mod 4). */
static void fe_pow(const pipeline_secp256k1_num *base, const pipeline_secp256k1_num *exponent, pipeline_secp256k1_num *out)
{
    pipeline_secp256k1_num result;
    int bitpos;

    num_from_small(1, &result);
    for (bitpos = NUM_WORDS * 32 - 1; bitpos >= 0; bitpos--) {
        pipeline_u32 bit = (exponent->w[bitpos / 32] >> (bitpos % 32)) & 1u;
        pipeline_secp256k1_num sq;
        fe_mul(&result, &result, &sq);
        result = sq;
        if (bit) {
            pipeline_secp256k1_num prod;
            fe_mul(&result, base, &prod);
            result = prod;
        }
    }
    *out = result;
}

/* out = a^-1 mod p (Fermat's little theorem: a^(p-2) mod p). a must be
 * nonzero. */
static void fe_inv(const pipeline_secp256k1_num *a, pipeline_secp256k1_num *out)
{
    pipeline_secp256k1_num exponent;
    pipeline_secp256k1_num two;

    num_from_small(2, &two);
    num_sub(&kFieldP, &two, &exponent); /* p - 2 */
    fe_pow(a, &exponent, out);
}

/* ---- scalar arithmetic (mod n) ---- */

void pipeline_secp256k1_scalar_reduce(const pipeline_secp256k1_num *a, pipeline_secp256k1_num *out)
{
    wide_num wide;
    int i;
    for (i = 0; i < NUM_WORDS; i++) {
        wide.w[i] = a->w[i];
    }
    for (i = NUM_WORDS; i < WIDE_WORDS; i++) {
        wide.w[i] = 0;
    }
    reduce_wide_mod(&wide, &kCurveN, out);
}

void pipeline_secp256k1_scalar_add(const pipeline_secp256k1_num *a, const pipeline_secp256k1_num *b, pipeline_secp256k1_num *out) { addmod(a, b, &kCurveN, out); }
void pipeline_secp256k1_scalar_mul(const pipeline_secp256k1_num *a, const pipeline_secp256k1_num *b, pipeline_secp256k1_num *out) { mulmod(a, b, &kCurveN, out); }

void pipeline_secp256k1_scalar_negate(const pipeline_secp256k1_num *a, pipeline_secp256k1_num *out)
{
    num_sub(&kCurveN, a, out);
}

int pipeline_secp256k1_scalar_in_range(const pipeline_secp256k1_num *a)
{
    return !pipeline_secp256k1_num_is_zero(a) && num_cmp(a, &kCurveN) < 0;
}

/* ---- Jacobian point arithmetic (a = 0 curve) -- file-internal only ---- */

typedef struct {
    pipeline_secp256k1_num X, Y, Z;
    int infinity;
} jacobian_point;

static void jac_double(const jacobian_point *p, jacobian_point *out)
{
    pipeline_secp256k1_num a, b, c, d, e, f, t1, t2, x3, y3, z3;

    if (p->infinity || pipeline_secp256k1_num_is_zero(&p->Y)) {
        /* Leave X/Y/Z at a well-defined (zero) value, not indeterminate,
         * even though infinity == 1 means callers must never read them. */
        num_zero(&out->X);
        num_zero(&out->Y);
        num_zero(&out->Z);
        out->infinity = 1;
        return;
    }

    fe_sqr(&p->X, &a);                 /* A = X1^2 */
    fe_sqr(&p->Y, &b);                 /* B = Y1^2 */
    fe_sqr(&b, &c);                    /* C = B^2 */

    fe_add(&p->X, &b, &t1);
    fe_sqr(&t1, &t1);                  /* (X1+B)^2 */
    fe_sub(&t1, &a, &t1);
    fe_sub(&t1, &c, &t1);
    fe_add(&t1, &t1, &d);              /* D = 2*((X1+B)^2 - A - C) */

    fe_add(&a, &a, &t2);
    fe_add(&t2, &a, &e);               /* E = 3*A */

    fe_sqr(&e, &f);                    /* F = E^2 */

    fe_add(&d, &d, &t1);
    fe_sub(&f, &t1, &x3);              /* X3 = F - 2*D */

    fe_sub(&d, &x3, &t1);
    fe_mul(&e, &t1, &t1);
    fe_add(&c, &c, &t2);
    fe_add(&t2, &t2, &t2);
    fe_add(&t2, &t2, &t2);             /* 8*C */
    fe_sub(&t1, &t2, &y3);             /* Y3 = E*(D-X3) - 8*C */

    fe_mul(&p->Y, &p->Z, &t1);
    fe_add(&t1, &t1, &z3);             /* Z3 = 2*Y1*Z1 */

    out->X = x3;
    out->Y = y3;
    out->Z = z3;
    out->infinity = 0;
}

/* Mixed addition: p2 is affine (Z2 = 1), p1 is (possibly infinity)
 * Jacobian. "madd-2007-bl". */
static void jac_add_mixed(const jacobian_point *p1, const pipeline_secp256k1_num *x2, const pipeline_secp256k1_num *y2, jacobian_point *out)
{
    pipeline_secp256k1_num z1z1, u2, s2, h, hh, i, j, r, v, t1, t2, x3, y3, z3;

    if (p1->infinity) {
        out->X = *x2;
        out->Y = *y2;
        num_from_small(1, &out->Z);
        out->infinity = 0;
        return;
    }

    fe_sqr(&p1->Z, &z1z1);
    fe_mul(x2, &z1z1, &u2);
    fe_mul(&p1->Z, &z1z1, &t1);
    fe_mul(y2, &t1, &s2);

    fe_sub(&u2, &p1->X, &h);
    fe_sub(&s2, &p1->Y, &r);

    if (pipeline_secp256k1_num_is_zero(&h)) {
        if (pipeline_secp256k1_num_is_zero(&r)) {
            jac_double(p1, out);
        } else {
            num_zero(&out->X);
            num_zero(&out->Y);
            num_zero(&out->Z);
            out->infinity = 1;
        }
        return;
    }

    fe_sqr(&h, &hh);
    fe_add(&hh, &hh, &i);
    fe_add(&i, &i, &i);                /* I = 4*HH */
    fe_mul(&h, &i, &j);
    fe_add(&r, &r, &r);                /* r = 2*(S2-Y1) */
    fe_mul(&p1->X, &i, &v);

    fe_sqr(&r, &t1);
    fe_sub(&t1, &j, &t1);
    fe_add(&v, &v, &t2);
    fe_sub(&t1, &t2, &x3);             /* X3 = r^2 - J - 2V */

    fe_sub(&v, &x3, &t1);
    fe_mul(&r, &t1, &t1);
    fe_mul(&p1->Y, &j, &t2);
    fe_add(&t2, &t2, &t2);
    fe_sub(&t1, &t2, &y3);             /* Y3 = r*(V-X3) - 2*Y1*J */

    fe_add(&p1->Z, &h, &t1);
    fe_sqr(&t1, &t1);
    fe_sub(&t1, &z1z1, &t1);
    fe_sub(&t1, &hh, &z3);             /* Z3 = (Z1+H)^2 - Z1Z1 - HH */

    out->X = x3;
    out->Y = y3;
    out->Z = z3;
    out->infinity = 0;
}

static void jac_to_affine(const jacobian_point *p, pipeline_secp256k1_point *out)
{
    pipeline_secp256k1_num zinv, zinv2, zinv3;

    if (p->infinity) {
        /* Leave x/y at a well-defined (zero) value, not indeterminate --
         * see the same defensive zeroing in jac_double's infinity branch. */
        num_zero(&out->x);
        num_zero(&out->y);
        out->infinity = 1;
        return;
    }

    fe_inv(&p->Z, &zinv);
    fe_sqr(&zinv, &zinv2);
    fe_mul(&zinv2, &zinv, &zinv3);
    fe_mul(&p->X, &zinv2, &out->x);
    fe_mul(&p->Y, &zinv3, &out->y);
    out->infinity = 0;
}

/* Shared double-and-add scalar multiplication core: out_affine = k * (bx,by). */
static void point_mul_core(const pipeline_secp256k1_num *k, const pipeline_secp256k1_num *bx, const pipeline_secp256k1_num *by, pipeline_secp256k1_point *out)
{
    jacobian_point r;
    int bitpos;

    r.infinity = 1;

    for (bitpos = NUM_WORDS * 32 - 1; bitpos >= 0; bitpos--) {
        pipeline_u32 bit = (k->w[bitpos / 32] >> (bitpos % 32)) & 1u;
        jacobian_point doubled;

        jac_double(&r, &doubled);
        r = doubled;

        if (bit) {
            jacobian_point added;
            jac_add_mixed(&r, bx, by, &added);
            r = added;
        }
    }

    jac_to_affine(&r, out);
}

void pipeline_secp256k1_point_mul_base(const pipeline_secp256k1_num *k, pipeline_secp256k1_point *out)
{
    point_mul_core(k, &kGx, &kGy, out);
}

void pipeline_secp256k1_point_mul(const pipeline_secp256k1_num *k, const pipeline_secp256k1_point *base, pipeline_secp256k1_point *out)
{
    point_mul_core(k, &base->x, &base->y, out);
}

int pipeline_secp256k1_point_y_is_even(const pipeline_secp256k1_point *p)
{
    return !num_is_odd(&p->y);
}

int pipeline_secp256k1_point_lift_x(const pipeline_u8 x[PIPELINE_SECP256K1_BYTES], pipeline_secp256k1_point *out)
{
    pipeline_secp256k1_num xnum, x2, x3, seven, c, sqrtExp, y, ysq, oneWord, pPlus1;

    pipeline_secp256k1_num_from_bytes(x, &xnum);
    if (num_cmp(&xnum, &kFieldP) >= 0) {
        return 0;
    }

    fe_sqr(&xnum, &x2);
    fe_mul(&x2, &xnum, &x3);
    num_from_small(7, &seven);
    fe_add(&x3, &seven, &c); /* c = x^3 + 7 mod p */

    /* sqrtExp = (p+1)/4, valid since secp256k1's p = 3 (mod 4). */
    num_from_small(1, &oneWord);
    num_add(&kFieldP, &oneWord, &pPlus1); /* p+1 (no overflow: p < 2^256-1) */
    {
        /* Divide pPlus1 by 4 via two single-bit right shifts. */
        int i;
        pipeline_secp256k1_num tmp = pPlus1;
        for (i = 0; i < 2; i++) {
            pipeline_u32 carry = 0;
            int w;
            for (w = NUM_WORDS - 1; w >= 0; w--) {
                pipeline_u32 nextCarry = tmp.w[w] & 1u;
                tmp.w[w] = (tmp.w[w] >> 1) | (carry << 31);
                carry = nextCarry;
            }
        }
        sqrtExp = tmp;
    }

    fe_pow(&c, &sqrtExp, &y);
    fe_sqr(&y, &ysq);
    if (num_cmp(&ysq, &c) != 0) {
        return 0; /* c is not a quadratic residue mod p: x isn't a valid x-only pubkey */
    }

    if (num_is_odd(&y)) {
        pipeline_secp256k1_num negY;
        num_sub(&kFieldP, &y, &negY);
        y = negY;
    }

    out->x = xnum;
    out->y = y;
    out->infinity = 0;
    return 1;
}

void pipeline_secp256k1_field_negate(const pipeline_secp256k1_num *a, pipeline_secp256k1_num *out)
{
    if (pipeline_secp256k1_num_is_zero(a)) {
        num_zero(out);
    } else {
        num_sub(&kFieldP, a, out);
    }
}

int pipeline_secp256k1_num_is_valid_field_element(const pipeline_secp256k1_num *a)
{
    return num_cmp(a, &kFieldP) < 0;
}

void pipeline_secp256k1_point_add(const pipeline_secp256k1_point *p1, const pipeline_secp256k1_point *p2, pipeline_secp256k1_point *out)
{
    jacobian_point j1;
    jacobian_point result;

    if (p2->infinity) {
        *out = *p1;
        return;
    }

    num_from_small(1, &j1.Z);
    j1.X = p1->x;
    j1.Y = p1->y;
    j1.infinity = p1->infinity;

    jac_add_mixed(&j1, &p2->x, &p2->y, &result);
    jac_to_affine(&result, out);
}

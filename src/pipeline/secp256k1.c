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
 * ONE scoped exception (spec #43, sub-issue #47): kCombTable below is
 * initialized directly from PIPELINE_SECP256K1_COMB_TABLE_INIT, a
 * generated-header macro (secp256k1_baked.h, rendered by tools/
 * gen_secp256k1_baked.py) that DOES hardcode this exact little-endian-limb
 * word order -- a generator-side literal, not a function, so the "no
 * function... may assume a particular word order" rule above still holds
 * for actual code; only that one generated constant knows the layout, and
 * only because it is consumed nowhere but this file (see
 * secp256k1_baked.h.in's own header comment for why this is safe: the
 * table is never read by any other translation unit, and a representation
 * mismatch between the generator and this file would fail the differential
 * sweep in tools/pipeline_test/main.c immediately, not silently).
 *
 * `unsigned long long` (a built-in type needing no header, same
 * justification as sha256.h's bitlen field) is used as the carry/widening
 * type for 32x32->64-bit partial products and add/sub carries -- the VR4300
 * is 32-bit, so this becomes a compiler-synthesized double-word op, not a
 * native instruction, but it is still a plain arithmetic expression gcc
 * lowers inline, needing no library call.
 */

#include "secp256k1.h"
#include "secp256k1_baked.h" /* PIPELINE_SECP256K1_COMB_* (spec #43, sub-issue #47) */

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

/*
 * n's complement c = 2^256 - n (spec #43 sub-issue #45's scalar-path
 * analogue of kFieldP's 977 -- the constant scalar_reduce_wide below folds
 * 2^256 = c (mod n) with). Unlike p = 2^256 - 2^32 - 977 (a single 32-bit
 * word), n has no comparably tiny pseudo-Mersenne complement: c is a
 * ~129-bit value, CN_C_WORDS (5) 32-bit words wide (index 4, the top word,
 * holds exactly 1; index 5 and up are zero and so are not stored). Value
 * cross-checked independently against Python:
 * hex(2**256 - 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)
 * == 0x14551231950b75fc4402da1732fc9bebf, and against libsecp256k1's own
 * published SECP256K1_N_C_0..4 constants for the same value. */
#define CN_C_WORDS 5
static const pipeline_u32 kCurveNComplement[CN_C_WORDS] = {
    0x2FC9BEBFu, 0x402DA173u, 0x50B75FC4u, 0x45512319u, 0x00000001u,
};

/* Base point (generator) G's affine coordinates. */
static const pipeline_secp256k1_num kGx = {{
    0x16F81798u, 0x59F2815Bu, 0x2DCE28D9u, 0x029BFCDBu,
    0xCE870B07u, 0x55A06295u, 0xF9DCBBACu, 0x79BE667Eu,
}};
static const pipeline_secp256k1_num kGy = {{
    0xFB10D4B8u, 0x9C47D08Fu, 0xA6855419u, 0xFD17B448u,
    0x0E1108A8u, 0x5DA4FBFCu, 0x26A3C465u, 0x483ADA77u,
}};

/*
 * Fixed-base comb table for k*G (spec #43, sub-issue #47) -- see
 * secp256k1_baked.h's own header comment and tools/gen_secp256k1_baked.py's
 * build_comb_table()/validate_comb_table() for the algorithm this table
 * implements, and point_mul_base_comb() below for how it is consumed. Each
 * entry is a plain affine (x, y) pair in this file's own internal little-
 * endian-limb pipeline_secp256k1_num representation (never bytes -- see
 * secp256k1_baked.h.in's own note on why this ONE generated header carries
 * values in two different representations for its two different
 * consumers), so kCombTable can be a `static const` array read directly at
 * its point_mul_base_comb() call sites with zero runtime byte<->num
 * conversion and zero extra RAM.
 *
 * kCombTable[0] is the unused "no bits set" slot (point_mul_base_comb()
 * never looks it up -- every table read below is guarded by `s != 0`); its
 * value is whatever the generator happened to emit for the point at
 * infinity (never a valid affine point) and must never be read as one.
 *
 * sizeof(kCombTable) is asserted at COMPILE time against the VR4300's
 * 8 KB data-cache budget (via PIPELINE_SECP256K1_COMB_CACHE_BUDGET_BYTES,
 * the SAME generator-owned budget constant gen_secp256k1_baked.py's
 * validate_comb_table() checks at generation time, not a second hardcoded
 * copy of "8192") by pipeline_secp256k1_comb_table_budget_check below (a
 * negative-array-size trick) -- so a future edit that widens
 * PIPELINE_SECP256K1_COMB_D without updating the generator's matching
 * budget check still fails the BUILD closed rather than silently shipping
 * an oversized table. A second check right below it separately confirms
 * kCombTable's REAL sizeof() matches PIPELINE_SECP256K1_COMB_TABLE_BYTES
 * (the generator's own byte-count arithmetic for that same table) exactly
 * -- catching a struct-layout/padding assumption drifting from the
 * generator's SIZE * 64-bytes-per-point arithmetic, which the budget
 * check alone (an inequality) would not.
 */
typedef struct {
    pipeline_secp256k1_num x, y;
} comb_point;

static const comb_point kCombTable[PIPELINE_SECP256K1_COMB_TABLE_SIZE] = PIPELINE_SECP256K1_COMB_TABLE_INIT;

typedef char pipeline_secp256k1_comb_table_budget_check[
    (sizeof(kCombTable) <= PIPELINE_SECP256K1_COMB_CACHE_BUDGET_BYTES) ? 1 : -1];
typedef char pipeline_secp256k1_comb_table_bytes_check[
    (sizeof(kCombTable) == PIPELINE_SECP256K1_COMB_TABLE_BYTES) ? 1 : -1];

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

/*
 * Host-side primitive-operation-count proxy (spec #43 sub-issue #44,
 * reused by later sub-issues in this spec). Named g_prim_op_count because it
 * is deliberately NOT scoped to the field-multiply path: #45 folded the
 * scalar (mod n) reduction, negation, and addmod into it too, so it counts
 * primitive-limb work across every fast-vs-naive path the differential seam
 * compares, not just reduction calls. Counts primitive 32-bit-limb
 * operations (compares, subtracts, adds, scalar-multiply-accumulate steps --
 * NOT num_mul's own 32x32 partial-product loop, which is identical on both
 * the fast and naive paths and so contributes nothing to a fast-vs-naive
 * comparison) performed by the width-parameterized array primitives below
 * and by reduce_wide_mod's per-bit loop -- i.e. the reduction-side
 * machine-level work each reduction does, not wall-clock time (which x86
 * doesn't share with the VR4300; see secp256k1.h's header comment). Read via
 * pipeline_secp256k1_get_op_count() after pipeline_secp256k1_reset_op_count().
 *
 * PIPELINE_SECP256K1_OP_COUNT-gated: every increment below compiles to
 * nothing unless that macro is defined. tools/pipeline_test/Makefile
 * defines it for the host test tool only -- the ROM build's
 * PIPELINE_C99_CFLAGS does NOT define it, so these counters cost the ROM
 * build exactly nothing (not even a global read-modify-write per limb
 * operation on the signing hot path this sub-issue exists to speed up).
 * Not thread-safe when enabled -- the pipeline is single-threaded
 * everywhere it runs. */
#ifdef PIPELINE_SECP256K1_OP_COUNT
static unsigned long long g_prim_op_count = 0;
#define PRIM_OP_COUNT_TICK() (g_prim_op_count++)
#else
#define PRIM_OP_COUNT_TICK() ((void)0)
#endif

/*
 * Host-side field-INVERSION count (spec #43 sub-issue #48's own proof
 * mechanism, alongside the pre-existing op-count proxy above). Counts calls
 * to fe_inv -- the ONE field-inversion primitive the signing path still
 * runs (jac_to_affine's Jacobian-to-affine conversion of R = k'*G; P = d*G
 * was baked at build time by sub-issue #46 and needs no runtime inversion
 * at all) -- so tools/pipeline_test can assert directly that a signature
 * performs AT MOST ONE modular inversion, not just that inversion got
 * cheaper. Same PIPELINE_SECP256K1_OP_COUNT gating and reset/read pairing
 * as g_prim_op_count above; not a separate compile-time knob. */
#ifdef PIPELINE_SECP256K1_OP_COUNT
static unsigned long long g_field_inv_count = 0;
#define FIELD_INV_COUNT_TICK() (g_field_inv_count++)
#else
#define FIELD_INV_COUNT_TICK() ((void)0)
#endif

void pipeline_secp256k1_reset_op_count(void)
{
#ifdef PIPELINE_SECP256K1_OP_COUNT
    g_prim_op_count = 0;
    g_field_inv_count = 0;
#endif
}

unsigned long long pipeline_secp256k1_get_op_count(void)
{
#ifdef PIPELINE_SECP256K1_OP_COUNT
    return g_prim_op_count;
#else
    return 0;
#endif
}

unsigned long long pipeline_secp256k1_get_inversion_count(void)
{
#ifdef PIPELINE_SECP256K1_OP_COUNT
    return g_field_inv_count;
#else
    return 0;
#endif
}

/* Width-parameterized little-endian-limb-array compare/subtract, shared by
 * num_cmp/num_sub (width NUM_WORDS) and reduce_wide_mod's 9-word remainder
 * arithmetic (width REM_WORDS) below, so the two widths don't duplicate the
 * same borrow/comparison logic twice. */
static int arr_cmp(const pipeline_u32 *a, const pipeline_u32 *b, int width)
{
    int i;
    for (i = width - 1; i >= 0; i--) {
        PRIM_OP_COUNT_TICK();
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
        PRIM_OP_COUNT_TICK();
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

/* out = (a + b) mod 2^(32*width); returns the carry-out bit. Width-
 * parameterized twin of arr_sub, used by fe_reduce_wide's folding steps
 * (num_add above is the fixed-NUM_WORDS twin used by the rest of the
 * file). */
static pipeline_u32 arr_add(const pipeline_u32 *a, const pipeline_u32 *b, int width, pipeline_u32 *out)
{
    unsigned long long carry = 0;
    int i;
    for (i = 0; i < width; i++) {
        unsigned long long sum = (unsigned long long)a[i] + b[i] + carry;
        PRIM_OP_COUNT_TICK();
        out[i] = (pipeline_u32)sum;
        carry = sum >> 32;
    }
    return (pipeline_u32)carry;
}

/* out[0..n] = a[0..n) * s (out sized n+1 words, the top word holding the
 * final carry) -- a width-parameterized multiply-by-small-scalar, used by
 * fe_reduce_wide to fold the high half of a wide product by secp256k1's
 * 977 constant. */
static void arr_mul_small(const pipeline_u32 *a, int n, pipeline_u32 s, pipeline_u32 *out)
{
    unsigned long long carry = 0;
    int i;
    for (i = 0; i < n; i++) {
        unsigned long long prod = (unsigned long long)a[i] * s + carry;
        PRIM_OP_COUNT_TICK();
        out[i] = (pipeline_u32)prod;
        carry = prod >> 32;
    }
    out[n] = (pipeline_u32)carry;
}

/* out[0 .. awidth+bwidth) = a[0..awidth) * b[0..bwidth), a general width-
 * parameterized schoolbook multiply -- the width-parameterized twin of
 * num_mul (fixed NUM_WORDS x NUM_WORDS) below, used by scalar_reduce_wide
 * (sub-issue #45) to fold the high half of a wide value against the curve
 * order's complement (kCurveNComplement), which -- unlike the field
 * prime's single-word 977 constant folded by arr_mul_small above -- needs
 * a multi-word multiplicand. Deliberately not implemented by delegating to
 * num_mul with zero-padded NUM_WORDS-width operands: that would inflate
 * the op-count proxy's tick count with padding-word no-op multiplies,
 * muddying the fast-vs-naive comparison the proxy exists to make. */
static void arr_mul_wide(const pipeline_u32 *a, int awidth, const pipeline_u32 *b, int bwidth, pipeline_u32 *out)
{
    int i, j;
    int outWidth = awidth + bwidth;
    for (i = 0; i < outWidth; i++) {
        out[i] = 0;
    }
    for (i = 0; i < awidth; i++) {
        unsigned long long carry = 0;
        for (j = 0; j < bwidth; j++) {
            unsigned long long prod = (unsigned long long)a[i] * b[j] + out[i + j] + carry;
            PRIM_OP_COUNT_TICK();
            out[i + j] = (pipeline_u32)prod;
            carry = prod >> 32;
        }
        {
            int k = i + bwidth;
            while (carry != 0) {
                unsigned long long sum = (unsigned long long)out[k] + carry;
                PRIM_OP_COUNT_TICK();
                out[k] = (pipeline_u32)sum;
                carry = sum >> 32;
                k++;
            }
        }
    }
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
 * As of spec #43 sub-issue #44, this generic reduction is no longer used
 * on the field (mod p) path -- fe_reduce_wide below replaces it there with
 * reduction specialized to p's pseudo-Mersenne form (2^256 - 2^32 - 977).
 * As of sub-issue #45, it is no longer used on the scalar (mod n) path
 * either -- scalar_reduce_wide (further below) replaces it there the same
 * way, specialized to the curve order n instead. It is RETAINED solely as
 * the differential-test oracle pipeline_secp256k1_fe_mul_reference() /
 * pipeline_secp256k1_scalar_reduce_reference() / _scalar_mul_reference()
 * (see secp256k1.h) check the two fast reductions against. See
 * secp256k1.h's header comment for the fuller picture.
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
            PRIM_OP_COUNT_TICK();
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

/*
 * Word-width of the fold accumulator used by fe_reduce_wide below.
 * NUM_WORDS (8) is not enough: the first fold's sum can reach just under
 * 2^289 (see the derivation below), one bit past what 9 words (288 bits)
 * can hold, so a 9th word is not sufficient headroom either -- hence
 * NUM_WORDS + 2 (10 words, 320 bits), comfortably clear of 2^289.
 */
#define FIELD_ACC_WORDS (NUM_WORDS + 2)
/* Fold 2 leaves acc under 2p (see fe_reduce_wide's header), so a single
 * conditional subtraction of p already suffices; this is a small, fixed
 * safety margin over that one required subtraction -- the field path's
 * counterpart to the scalar path's SCALAR_FINAL_SUB_ROUNDS below, named
 * (not a bare literal 2) so the two reduction paths spell the same
 * construct the same way. */
#define FIELD_FINAL_SUB_ROUNDS 2

/*
 * fe_reduce_wide: out = x mod p, specialized to secp256k1's field prime
 * p = 2^256 - 2^32 - 977 (fold 2^256 = 2^32 + 977 mod p), REPLACING
 * reduce_wide_mod's generic 512-iteration bit-serial long division on the
 * field path (spec #43 sub-issue #44 -- this is the dominant cost of a
 * signature; secp256k1.h's header comment documents the tradeoff this
 * supersedes).
 *
 * This shares the "fold the high half against 2^256 = c (mod m)" idea with
 * scalar_reduce_wide below, but deliberately does NOT share its code shape:
 * p's complement is the single 32-bit word 977 (folded by arr_mul_small, and
 * cheap enough to hand-unroll exactly two folds), whereas n has no tiny
 * pseudo-Mersenne form and its ~129-bit multi-word complement forces the
 * scalar path's general arr_mul_wide round-loop. The field path is the
 * dominant per-signature cost (sub-issue #44), so it keeps the tighter
 * single-word fast fold rather than being unified into the slower general
 * form -- the two paths intentionally diverge; see scalar_reduce_wide's
 * header for the matching note from the other side.
 *
 * Splitting the 512-bit product x into 256-bit halves x = hi*2^256 + lo,
 * 2^256 = 2^32 + 977 (mod p) gives x = lo + hi*(2^32+977) (mod p), i.e.
 * x = lo + (hi << 32) + hi*977 (mod p). Bounding each term with hi, lo both
 * < 2^256: (hi << 32) < 2^288, hi*977 < 977*2^256 < 2^266, lo < 2^256, so
 * fold 1's sum acc < 2^256 + 2^288 + 2^266 < 2^289 -- hence FIELD_ACC_WORDS
 * = 10 words (320 bits) above, not 9 (288 bits).
 *
 * acc can still be >= 2^256, so a second, much smaller fold repeats the
 * same trick on acc's own bits above 256 (hi2 = acc >> 256): since
 * acc < 2^289, hi2 < 2^33, so fold 2's sum tmp = lo2 + (hi2 << 32) + hi2*977
 * < 2^256 + 2^65 + 2^43 < 2^256 + 2^66 < 2p (p > 2^255, so 2p > 2^256 + a
 * term far bigger than 2^66 -- comfortably true). tmp being under 2p alone
 * means a SINGLE conditional subtraction of p already suffices to bring it
 * under p; the final loop below runs it twice anyway purely as a fixed,
 * cheap safety margin against a tighter bound derivation being wrong, not
 * because 2 is a tight requirement -- either way it is NOT a loop whose
 * length scales with the 512-bit input, unlike reduce_wide_mod's.
 */
static void fe_reduce_wide(const wide_num *x, pipeline_secp256k1_num *out)
{
    pipeline_u32 acc[FIELD_ACC_WORDS];
    pipeline_u32 hiShift[FIELD_ACC_WORDS];
    pipeline_u32 hiMul[FIELD_ACC_WORDS];
    pipeline_u32 mext[FIELD_ACC_WORDS];
    int i;

    /* ---- first fold: 512-bit x -> a <= FIELD_ACC_WORDS*32-bit acc ---- */
    for (i = 0; i < FIELD_ACC_WORDS; i++) {
        acc[i] = (i < NUM_WORDS) ? x->w[i] : 0; /* acc = lo, zero-extended */
        hiShift[i] = 0;
        hiMul[i] = 0;
    }
    for (i = 0; i < NUM_WORDS; i++) {
        hiShift[i + 1] = x->w[NUM_WORDS + i]; /* hiShift = hi << 32 (whole-word shift) */
    }
    arr_mul_small(&x->w[NUM_WORDS], NUM_WORDS, 977u, hiMul); /* hiMul[0..NUM_WORDS] = hi * 977 */

    arr_add(acc, hiShift, FIELD_ACC_WORDS, acc);
    arr_add(acc, hiMul, FIELD_ACC_WORDS, acc);

    /* ---- second fold: collapse acc's bits above 256 (word index
     * NUM_WORDS and up -- at most a couple of words after the first fold)
     * the same way, into acc's low 256 bits. ---- */
    {
        pipeline_u32 hi2[FIELD_ACC_WORDS];
        pipeline_u32 hi2Shift[FIELD_ACC_WORDS];
        pipeline_u32 hi2Mul[FIELD_ACC_WORDS];
        pipeline_u32 lo2[FIELD_ACC_WORDS];
        int hi2Words = FIELD_ACC_WORDS - NUM_WORDS;

        for (i = 0; i < FIELD_ACC_WORDS; i++) {
            hi2[i] = (i < hi2Words) ? acc[i + NUM_WORDS] : 0;
            hi2Shift[i] = 0;
            hi2Mul[i] = 0;
            lo2[i] = (i < NUM_WORDS) ? acc[i] : 0;
        }
        for (i = 0; i < hi2Words; i++) {
            hi2Shift[i + 1] = hi2[i];
        }
        arr_mul_small(hi2, hi2Words, 977u, hi2Mul);

        arr_add(lo2, hi2Shift, FIELD_ACC_WORDS, lo2);
        arr_add(lo2, hi2Mul, FIELD_ACC_WORDS, lo2);

        for (i = 0; i < FIELD_ACC_WORDS; i++) {
            acc[i] = lo2[i];
        }
    }

    /* acc < 2p (see the derivation above -- fold 2 leaves acc/tmp under
     * 2^256 + 2^66, comfortably under 2p), so a SINGLE conditional
     * subtraction of p already suffices to bring it under p. This loop
     * runs it up to FIELD_FINAL_SUB_ROUNDS times anyway as a fixed, cheap
     * safety margin, not because 2 is a tight requirement -- either way it
     * is a fixed, small
     * trip count enforced by the loop bound itself, not data-length-
     * dependent like reduce_wide_mod's 512-iteration loop. */
    for (i = 0; i < FIELD_ACC_WORDS; i++) {
        mext[i] = (i < NUM_WORDS) ? kFieldP.w[i] : 0;
    }
    for (i = 0; i < FIELD_FINAL_SUB_ROUNDS; i++) {
        if (arr_cmp(acc, mext, FIELD_ACC_WORDS) >= 0) {
            arr_sub(acc, mext, FIELD_ACC_WORDS, acc);
        }
    }

    for (i = 0; i < NUM_WORDS; i++) {
        out->w[i] = acc[i];
    }
}

/*
 * Word-width of the fold accumulator used by scalar_reduce_wide below.
 * WIDE_WORDS (16, 512 bits) is both the minimum needed (the very first
 * fold round must hold the full 512-bit input x without truncation) and
 * comfortably sufficient for every later round too -- see
 * scalar_reduce_wide's header comment for the round-by-round magnitude
 * trace, which never exceeds ~386 bits (13 words) after any round. Unlike
 * fe_reduce_wide's single-word complement (977, folded by arr_mul_small),
 * n's complement (kCurveNComplement, CN_C_WORDS words, ~129 bits) needs a
 * multi-word fold multiply (arr_mul_wide) whose growth per round is more
 * awkward to bound exactly by hand than the field path's; the correctness
 * that this width (and SCALAR_FINAL_SUB_ROUNDS below) is meant to protect
 * is proven empirically by the differential sweep
 * (test_scalar_differential_sweep in tools/pipeline_test/main.c) against
 * the retained naive reduce_wide_mod oracle, not asserted from the
 * derivation alone.
 */
#define SCALAR_ACC_WORDS WIDE_WORDS
#define SCALAR_FOLD_ROUNDS 3
/* The round-3 trace below bounds acc at that point to comfortably under
 * 2n, so a single conditional subtraction of n already suffices; 4 rounds
 * is a small, cheap, fixed safety margin over that, not a tight
 * requirement -- see the differential sweep for the actual proof. */
#define SCALAR_FINAL_SUB_ROUNDS 4

/*
 * scalar_reduce_wide: out = x mod n, specialized to secp256k1's curve
 * order n via the same "fold the high half against 2^256 mod n" identity
 * fe_reduce_wide above uses for the field prime p (sub-issue #44) --
 * REPLACING reduce_wide_mod's generic 512-iteration bit-serial long
 * division on the SCALAR path (sub-issue #45: reducing the BIP-340 nonce k
 * and challenge e, and computing s = (k + e*d) mod n, all go through
 * pipeline_secp256k1_scalar_reduce/_mul below, which now call this
 * instead).
 *
 * Unlike p = 2^256 - 2^32 - 977 (a single 32-bit-word complement, 977), n's
 * complement c = 2^256 - n (kCurveNComplement above) is a ~129-bit,
 * multi-word (CN_C_WORDS = 5) value -- n has no comparably tiny
 * pseudo-Mersenne form. Folding therefore uses a general multi-word
 * multiply (arr_mul_wide) rather than a multiply-by-one-word
 * (arr_mul_small), and needs more fold rounds for hi*c to shrink down near
 * n's own size. Tracking the actual (unpadded) magnitude of x's part above
 * 2^256 round by round, for a 512-bit input x < 2^512:
 *   round 1: hi < 2^256, hi*c < 2^256 * 2^129 = 2^385, acc < 2^385 + 2^256
 *            (lo) < ~2^386.
 *   round 2: hi < 2^386/2^256 = 2^130, hi*c < 2^130*2^129 = 2^259,
 *            acc < 2^259 + 2^256 (lo) < ~2^260.
 *   round 3: hi < 2^260/2^256 = 2^4, hi*c < 2^4*2^129 = 2^133,
 *            acc < 2^133 + 2^256 (lo) -- just barely over 2^256, comfortably
 *            under 2n (n is itself just under 2^256).
 * SCALAR_FOLD_ROUNDS (3) leaves acc within a small fixed multiple of n; the
 * final SCALAR_FINAL_SUB_ROUNDS (4, a small safety margin over the single
 * subtraction the trace above implies is actually needed) conditional-
 * subtract loop brings it under n -- a fixed, small trip count, NOT one
 * that scales with the 512-bit input the way reduce_wide_mod's does. This
 * derivation is the
 * design rationale, not the proof of correctness: see
 * test_scalar_differential_sweep (tools/pipeline_test/main.c) for the
 * actual proof, against the retained naive reduce_wide_mod oracle over a
 * wide seeded random sweep plus pinned edge vectors.
 */
static void scalar_reduce_wide(const wide_num *x, pipeline_secp256k1_num *out)
{
    pipeline_u32 acc[SCALAR_ACC_WORDS];
    pipeline_u32 mext[SCALAR_ACC_WORDS];
    int i, round;

    /* SCALAR_ACC_WORDS is defined as WIDE_WORDS above specifically so this
     * copy can never truncate x -- the "i < WIDE_WORDS" guard is a no-op
     * today (SCALAR_ACC_WORDS == WIDE_WORDS) kept only as a defensive
     * reminder: SCALAR_ACC_WORDS must never be redefined smaller than
     * WIDE_WORDS, or this copy would silently drop x's high words. */
    for (i = 0; i < SCALAR_ACC_WORDS; i++) {
        acc[i] = (i < WIDE_WORDS) ? x->w[i] : 0;
    }

    for (round = 0; round < SCALAR_FOLD_ROUNDS; round++) {
        pipeline_u32 hi[SCALAR_ACC_WORDS - NUM_WORDS];
        pipeline_u32 lo[SCALAR_ACC_WORDS];
        pipeline_u32 hiC[SCALAR_ACC_WORDS];

        for (i = 0; i < SCALAR_ACC_WORDS - NUM_WORDS; i++) {
            hi[i] = acc[i + NUM_WORDS];
        }
        for (i = 0; i < SCALAR_ACC_WORDS; i++) {
            lo[i] = (i < NUM_WORDS) ? acc[i] : 0;
            hiC[i] = 0;
        }

        arr_mul_wide(hi, SCALAR_ACC_WORDS - NUM_WORDS, kCurveNComplement, CN_C_WORDS, hiC);
        arr_add(lo, hiC, SCALAR_ACC_WORDS, acc);
    }

    for (i = 0; i < SCALAR_ACC_WORDS; i++) {
        mext[i] = (i < NUM_WORDS) ? kCurveN.w[i] : 0;
    }
    for (i = 0; i < SCALAR_FINAL_SUB_ROUNDS; i++) {
        if (arr_cmp(acc, mext, SCALAR_ACC_WORDS) >= 0) {
            arr_sub(acc, mext, SCALAR_ACC_WORDS, acc);
        }
    }

    for (i = 0; i < NUM_WORDS; i++) {
        out->w[i] = acc[i];
    }
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

/* out = a * b mod p, via the fast field-specialized reduction
 * (fe_reduce_wide) -- every field multiply on the signing/verification
 * path goes through here (sub-issue #44). */
static void fe_mul(const pipeline_secp256k1_num *a, const pipeline_secp256k1_num *b, pipeline_secp256k1_num *out)
{
    wide_num wide;
    num_mul(a, b, &wide);
    fe_reduce_wide(&wide, out);
}
static void fe_sqr(const pipeline_secp256k1_num *a, pipeline_secp256k1_num *out) { fe_mul(a, a, out); }

/*
 * Test-only diagnostic surface (spec #43 sub-issue #44). Exposes the fast
 * field multiply (identical to fe_mul above) and the RETAINED naive
 * generic-reduction field multiply (identical to what fe_mul used to be,
 * before this sub-issue) directly, so the host test tool's differential
 * sweep can compare fast-vs-naive field multiplication over arbitrary
 * field elements without going through a full point operation. Never
 * called by signing/verification themselves -- only by tools/pipeline_test.
 */
void pipeline_secp256k1_fe_mul_fast(const pipeline_secp256k1_num *a, const pipeline_secp256k1_num *b, pipeline_secp256k1_num *out)
{
    fe_mul(a, b, out);
}

void pipeline_secp256k1_fe_mul_reference(const pipeline_secp256k1_num *a, const pipeline_secp256k1_num *b, pipeline_secp256k1_num *out)
{
    mulmod(a, b, &kFieldP, out);
}

/*
 * out = base^exponent mod p, via generic full-width square-and-multiply
 * (one squaring AND, per set bit, one multiply, for every one of the
 * exponent's 256 bits). As of spec #43 sub-issue #48, the ONLY remaining
 * caller is lift_x's modular square root (exponent = (p+1)/4, valid since
 * p = 3 mod 4) -- fe_inv below no longer calls this; it now uses the fixed
 * addition chain instead, which is cheaper specifically because it is
 * hand-derived for the one fixed exponent p-2, a shortcut this generic
 * routine (built for an arbitrary caller-supplied exponent, here (p+1)/4)
 * has no equivalent for.
 */
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

/* out = a squared n times (out = a^(2^n)). Shared helper for the fixed
 * addition chain in fe_inv below, where every step is either "square k
 * times" or "square k times then multiply by a previously-computed power" --
 * see fe_inv's own header comment. fe_sqr (like fe_mul) is safe to call with
 * its input and output aliased to the same object, so this squares directly
 * into *out across all n iterations rather than round-tripping through a
 * separate temporary each time. */
static void fe_sqrn(const pipeline_secp256k1_num *a, int n, pipeline_secp256k1_num *out)
{
    int i;
    *out = *a;
    for (i = 0; i < n; i++) {
        fe_sqr(out, out);
    }
}

/*
 * out = a^-1 mod p, via the published fixed secp256k1 addition chain for
 * the exponent p-2 (spec #43, sub-issue #48) -- REPLACING the full 256-bit
 * square-and-multiply Fermat exponentiation (fe_pow(a, p-2)) this function
 * used to call. Fermat's little theorem (a^(p-2) = a^-1 mod p, a != 0) is
 * still the underlying identity; what changes is HOW a^(p-2) is computed.
 * fe_pow's generic square-and-multiply touches one squaring per exponent
 * bit unconditionally, PLUS one field multiply for every bit that is set --
 * for p-2's essentially-all-ones 256-bit exponent that is ~256 squarings
 * *and* ~256 multiplies (~512 field multiplies total). The chain below is
 * the published fixed addition chain for exactly this exponent
 * (originally published for libsecp256k1's field_5x52_impl.h/
 * field_10x26_impl.h secp256k1_fe_inv, and widely re-derived/cited since):
 * it builds up x^(2^k-1) values (x2=a^3, x3=a^7, x6, x9, x11, x22, x44, x88,
 * x176, x220, x223) via double-and-add-style repeated squaring, each step
 * reusing a previously-computed power instead of restarting from a, then
 * finishes with a short explicit tail -- 255 squarings + 15 multiplications
 * total, exactly matching p-2's bit pattern with none of fe_pow's per-bit
 * branching or wasted squarings on a's lower bits. a must be nonzero.
 *
 * a's own value is only ever read (never written), so this chain is safe
 * even when a and out alias the same object at the call site.
 */
static void fe_inv(const pipeline_secp256k1_num *a, pipeline_secp256k1_num *out)
{
    pipeline_secp256k1_num x2, x3, x6, x9, x11, x22, x44, x88, x176, x220, x223, t1;

    FIELD_INV_COUNT_TICK();

    fe_sqr(a, &x2);
    fe_mul(&x2, a, &x2);           /* x2 = a^(2^2-1) = a^3 */

    fe_sqr(&x2, &x3);
    fe_mul(&x3, a, &x3);           /* x3 = a^(2^3-1) = a^7 */

    fe_sqrn(&x3, 3, &x6);
    fe_mul(&x6, &x3, &x6);         /* x6 = a^(2^6-1) */

    fe_sqrn(&x6, 3, &x9);
    fe_mul(&x9, &x3, &x9);         /* x9 = a^(2^9-1) */

    fe_sqrn(&x9, 2, &x11);
    fe_mul(&x11, &x2, &x11);       /* x11 = a^(2^11-1) */

    fe_sqrn(&x11, 11, &x22);
    fe_mul(&x22, &x11, &x22);      /* x22 = a^(2^22-1) */

    fe_sqrn(&x22, 22, &x44);
    fe_mul(&x44, &x22, &x44);      /* x44 = a^(2^44-1) */

    fe_sqrn(&x44, 44, &x88);
    fe_mul(&x88, &x44, &x88);      /* x88 = a^(2^88-1) */

    fe_sqrn(&x88, 88, &x176);
    fe_mul(&x176, &x88, &x176);    /* x176 = a^(2^176-1) */

    fe_sqrn(&x176, 44, &x220);
    fe_mul(&x220, &x44, &x220);    /* x220 = a^(2^220-1) */

    fe_sqrn(&x220, 3, &x223);
    fe_mul(&x223, &x3, &x223);     /* x223 = a^(2^223-1) */

    /* Tail: p-2's low-order bit pattern below the run of 223 leading ones,
     * assembled explicitly rather than via another named power. */
    fe_sqrn(&x223, 23, &t1);
    fe_mul(&t1, &x22, &t1);
    fe_sqrn(&t1, 5, &t1);
    fe_mul(&t1, a, &t1);
    fe_sqrn(&t1, 3, &t1);
    fe_mul(&t1, &x2, &t1);
    fe_sqrn(&t1, 2, &t1);
    fe_mul(a, &t1, out);
}

/*
 * Test-only diagnostic surface (spec #43 sub-issue #48), mirroring the
 * fast/reference pairing sub-issues #44/#45 established for field/scalar
 * multiplication (pipeline_secp256k1_fe_mul_fast/_reference,
 * pipeline_secp256k1_scalar_reduce_fast/_reference, etc. above/below).
 * Exposes the fast addition-chain inversion (identical to fe_inv above) and
 * a RETAINED naive Fermat full-exponentiation inversion (identical to what
 * fe_inv used to be, before this sub-issue) directly, so the host test
 * tool's differential sweep can compare fast-vs-naive field inversion over
 * arbitrary nonzero field elements -- including that both agree the result
 * is the TRUE modular inverse (a * inv(a) = 1 mod p) -- without going
 * through a full point operation. Never called by signing/verification
 * themselves -- only by tools/pipeline_test.
 */
void pipeline_secp256k1_fe_inv_fast(const pipeline_secp256k1_num *a, pipeline_secp256k1_num *out)
{
    fe_inv(a, out);
}

void pipeline_secp256k1_fe_inv_reference(const pipeline_secp256k1_num *a, pipeline_secp256k1_num *out)
{
    pipeline_secp256k1_num exponent;
    pipeline_secp256k1_num two;

    num_from_small(2, &two);
    num_sub(&kFieldP, &two, &exponent); /* p - 2 */
    fe_pow(a, &exponent, out);
}

/* ---- scalar arithmetic (mod n) ---- */

/* out = a * b mod n, via the fast curve-order-specialized reduction
 * (scalar_reduce_wide) -- the signing path's one scalar multiply (e*d
 * inside s = (k + e*d) mod n) goes through here (sub-issue #45). */
static void scalar_mulmod(const pipeline_secp256k1_num *a, const pipeline_secp256k1_num *b, pipeline_secp256k1_num *out)
{
    wide_num wide;
    num_mul(a, b, &wide);
    scalar_reduce_wide(&wide, out);
}

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
    scalar_reduce_wide(&wide, out);
}

void pipeline_secp256k1_scalar_add(const pipeline_secp256k1_num *a, const pipeline_secp256k1_num *b, pipeline_secp256k1_num *out) { addmod(a, b, &kCurveN, out); }
void pipeline_secp256k1_scalar_mul(const pipeline_secp256k1_num *a, const pipeline_secp256k1_num *b, pipeline_secp256k1_num *out) { scalar_mulmod(a, b, out); }

/*
 * Test-only diagnostic surface (spec #43 sub-issue #45). Exposes the fast
 * scalar reduce/multiply (identical to pipeline_secp256k1_scalar_reduce/
 * _mul above) and the RETAINED naive generic-reduction equivalents
 * (identical to what those two functions used to be, before this
 * sub-issue) directly, so the host test tool's differential sweep can
 * compare fast-vs-naive scalar reduction/multiplication over arbitrary
 * scalars without going through a full signature. Never called by
 * signing/verification themselves -- only by tools/pipeline_test, mirroring
 * pipeline_secp256k1_fe_mul_fast/_reference above (sub-issue #44).
 */
void pipeline_secp256k1_scalar_reduce_fast(const pipeline_secp256k1_num *a, pipeline_secp256k1_num *out)
{
    pipeline_secp256k1_scalar_reduce(a, out);
}

void pipeline_secp256k1_scalar_reduce_reference(const pipeline_secp256k1_num *a, pipeline_secp256k1_num *out)
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

void pipeline_secp256k1_scalar_mul_fast(const pipeline_secp256k1_num *a, const pipeline_secp256k1_num *b, pipeline_secp256k1_num *out)
{
    scalar_mulmod(a, b, out);
}

void pipeline_secp256k1_scalar_mul_reference(const pipeline_secp256k1_num *a, const pipeline_secp256k1_num *b, pipeline_secp256k1_num *out)
{
    mulmod(a, b, &kCurveN, out);
}

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

/*
 * Fixed-base comb scalar multiplication for k*G (spec #43, sub-issue #47):
 * out_affine = k * G, via kCombTable instead of point_mul_core's generic
 * per-bit double-and-add against a runtime base point. Standard "comb"
 * method (Handbook of Applied Cryptography, Algorithm 3.44) -- see
 * secp256k1_baked.h's own header comment and tools/gen_secp256k1_baked.py's
 * build_comb_table()/_comb_scalar_mult() for the matching Python
 * construction/oracle this function must stay bit-for-bit consistent with
 * (tools/pipeline_test/main.c's differential sweep proves that at runtime).
 *
 * k is treated as an unsigned PIPELINE_SECP256K1_COMB_D * PIPELINE_
 * SECP256K1_COMB_E-bit value (258 bits for D=6/E=43), zero-padded above
 * bit 255 -- k itself is only ever 256 bits wide (pipeline_secp256k1_num),
 * so every bit position >= 256 this function would otherwise read is
 * always exactly 0, matching the Python oracle's own
 * `bit = (k >> bitpos) & 1 if bitpos < 256 else 0` padding rule.
 *
 * For each of the E columns (most significant first), doubles the running
 * accumulator once, then gathers one bit from each of the D rows at that
 * column into a D-bit digit s and -- unless s is all-zero (no bits set,
 * kCombTable[0] is never a valid point and is never read) -- adds
 * kCombTable[s]. At most E doublings + E additions (86 Jacobian point
 * operations for D=6/E=43), versus point_mul_core's up to 256 doublings +
 * 256 additions (512) for the same k -- the whole point of sub-issue #47.
 */
static void point_mul_base_comb(const pipeline_secp256k1_num *k, pipeline_secp256k1_point *out)
{
    jacobian_point acc;
    int col;

    acc.infinity = 1;

    for (col = PIPELINE_SECP256K1_COMB_E - 1; col >= 0; col--) {
        jacobian_point doubled;
        unsigned s;
        int i;

        jac_double(&acc, &doubled);
        acc = doubled;

        s = 0;
        for (i = PIPELINE_SECP256K1_COMB_D - 1; i >= 0; i--) {
            int bitpos = i * PIPELINE_SECP256K1_COMB_E + col;
            pipeline_u32 bit = 0;
            if (bitpos < NUM_WORDS * 32) {
                bit = (k->w[bitpos / 32] >> (bitpos % 32)) & 1u;
            }
            s = (s << 1) | bit;
        }

        if (s != 0) {
            jacobian_point added;
            jac_add_mixed(&acc, &kCombTable[s].x, &kCombTable[s].y, &added);
            acc = added;
        }
    }

    jac_to_affine(&acc, out);
}

void pipeline_secp256k1_point_mul_base(const pipeline_secp256k1_num *k, pipeline_secp256k1_point *out)
{
    point_mul_base_comb(k, out);
}

void pipeline_secp256k1_point_mul_base_reference(const pipeline_secp256k1_num *k, pipeline_secp256k1_point *out)
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

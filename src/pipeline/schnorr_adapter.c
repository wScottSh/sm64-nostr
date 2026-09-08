/*
 * See schnorr_adapter.h. Fields/buffers are built up one explicit byte
 * range at a time (never via memcpy/struct-layout), the same
 * explicit-serialization discipline event_id.c/pack_adapter.c document --
 * this file avoids <string.h> (unavailable under the ROM build's
 * -nostdinc) for the same reason those files do.
 */

#include "schnorr_adapter.h"
#include "secp256k1.h"
#include "sha256.h"

/* BIP-340 tagged hash tags, as explicit byte arrays with explicit lengths
 * (no strlen -- see the file header comment). */
static const pipeline_u8 kTagAux[11]       = {'B','I','P','0','3','4','0','/','a','u','x'};
static const pipeline_u8 kTagNonce[13]     = {'B','I','P','0','3','4','0','/','n','o','n','c','e'};
static const pipeline_u8 kTagChallenge[17] = {'B','I','P','0','3','4','0','/','c','h','a','l','l','e','n','g','e'};

/* A single (pointer, length) message fragment -- see tagged_hash() below. */
typedef struct {
    const pipeline_u8 *data;
    pipeline_u32 len;
} hash_part;

/*
 * tagged_hash(tag, parts, partCount) =
 *   SHA256(SHA256(tag) || SHA256(tag) || parts[0] || parts[1] || ... ),
 * per BIP-340's hash_tag(x) definition. Every call site in this file needs
 * at most 3 concatenated fragments (t/R || P || m).
 * Built via explicit byte copies into a fixed local buffer and a single
 * one-shot pipeline_sha256() call (never the streaming init/update/final
 * API) so this file -- like event_id.c -- only ever needs sha256.h's
 * one-shot wrapper, not pipeline_sha256_ctx's internal layout; that keeps
 * this adapter, like pack_adapter.c/event_id.c, out of the C99-port
 * carve-out (see this file's own header comment). Max buffer use: 32
 * (tagHash) + 32 (tagHash again) + up to 3*32 (parts) = 160 bytes.
 */
static void tagged_hash(const pipeline_u8 *tag, pipeline_u32 tagLen,
                         const hash_part *parts, int partCount,
                         pipeline_u8 out[32])
{
    pipeline_u8 tagHash[32];
    pipeline_u8 buf[160];
    pipeline_u32 offset = 0;
    pipeline_u32 i;
    int p;

    pipeline_sha256(tag, tagLen, tagHash);

    for (i = 0; i < 32; i++) {
        buf[offset++] = tagHash[i];
    }
    for (i = 0; i < 32; i++) {
        buf[offset++] = tagHash[i];
    }
    for (p = 0; p < partCount; p++) {
        for (i = 0; i < parts[p].len; i++) {
            buf[offset++] = parts[p].data[i];
        }
    }

    pipeline_sha256(buf, offset, out);
}

int pipeline_schnorr_sign(const pipeline_u8 msg32[PIPELINE_SCHNORR_MSG_SIZE],
                           const pipeline_u8 privkey32[PIPELINE_SCHNORR_PRIVKEY_SIZE],
                           pipeline_u8 sig64[PIPELINE_SCHNORR_SIG_SIZE])
{
    /* aux_rand is always the fixed all-zero 32 bytes here (spec #24's
     * signing decision: aux_rand = 0, live-deterministic k = f(d, m)). */
    static const pipeline_u8 kAuxRand[32] = {0};

    pipeline_secp256k1_num dPrime;
    pipeline_secp256k1_point capP;
    pipeline_secp256k1_num d;
    pipeline_u8 pBytes[32];
    pipeline_u8 t0[32];
    pipeline_u8 dBytes[32];
    pipeline_u8 t[32];
    pipeline_u8 randBuf[32];
    pipeline_secp256k1_num kPrimeRaw;
    pipeline_secp256k1_num kPrime;
    pipeline_secp256k1_point capR;
    pipeline_secp256k1_num k;
    pipeline_u8 rBytes[32];
    pipeline_u8 eHash[32];
    pipeline_secp256k1_num e;
    pipeline_secp256k1_num ed;
    pipeline_secp256k1_num s;
    int i;

    /* Step 1: d' = int(seckey); fail if out of [1, n-1]. */
    pipeline_secp256k1_num_from_bytes(privkey32, &dPrime);
    if (!pipeline_secp256k1_scalar_in_range(&dPrime)) {
        return 0;
    }

    /* Step 2: P = d'*G; d = has_even_y(P) ? d' : n - d'. */
    pipeline_secp256k1_point_mul_base(&dPrime, &capP);
    if (pipeline_secp256k1_point_y_is_even(&capP)) {
        d = dPrime;
    } else {
        pipeline_secp256k1_scalar_negate(&dPrime, &d);
    }
    pipeline_secp256k1_num_to_bytes(&capP.x, pBytes);

    /* Step 3: t = bytes(d) XOR tagged_hash("BIP0340/aux", aux_rand). */
    {
        hash_part parts[1];
        parts[0].data = kAuxRand;
        parts[0].len = 32;
        tagged_hash(kTagAux, sizeof(kTagAux), parts, 1, t0);
    }
    pipeline_secp256k1_num_to_bytes(&d, dBytes);
    for (i = 0; i < 32; i++) {
        t[i] = (pipeline_u8)(dBytes[i] ^ t0[i]);
    }

    /* Step 4: rand = tagged_hash("BIP0340/nonce", t || bytes(P) || m). */
    {
        hash_part parts[3];
        parts[0].data = t;         parts[0].len = 32;
        parts[1].data = pBytes;    parts[1].len = 32;
        parts[2].data = msg32;     parts[2].len = PIPELINE_SCHNORR_MSG_SIZE;
        tagged_hash(kTagNonce, sizeof(kTagNonce), parts, 3, randBuf);
    }

    /* Step 5: k' = int(rand) mod n; fail if k' = 0. */
    pipeline_secp256k1_num_from_bytes(randBuf, &kPrimeRaw);
    pipeline_secp256k1_scalar_reduce(&kPrimeRaw, &kPrime);
    if (pipeline_secp256k1_num_is_zero(&kPrime)) {
        return 0;
    }

    /* Step 6: R = k'*G; k = has_even_y(R) ? k' : n - k'. */
    pipeline_secp256k1_point_mul_base(&kPrime, &capR);
    if (pipeline_secp256k1_point_y_is_even(&capR)) {
        k = kPrime;
    } else {
        pipeline_secp256k1_scalar_negate(&kPrime, &k);
    }
    pipeline_secp256k1_num_to_bytes(&capR.x, rBytes);

    /* Step 7: e = int(tagged_hash("BIP0340/challenge", bytes(R) || bytes(P) || m)) mod n. */
    {
        hash_part parts[3];
        pipeline_secp256k1_num eRaw;
        parts[0].data = rBytes;    parts[0].len = 32;
        parts[1].data = pBytes;    parts[1].len = 32;
        parts[2].data = msg32;     parts[2].len = PIPELINE_SCHNORR_MSG_SIZE;
        tagged_hash(kTagChallenge, sizeof(kTagChallenge), parts, 3, eHash);
        pipeline_secp256k1_num_from_bytes(eHash, &eRaw);
        pipeline_secp256k1_scalar_reduce(&eRaw, &e);
    }

    /* Step 8: sig = bytes(R) || bytes((k + e*d) mod n). */
    pipeline_secp256k1_scalar_mul(&e, &d, &ed);
    pipeline_secp256k1_scalar_add(&k, &ed, &s);

    for (i = 0; i < 32; i++) {
        sig64[i] = rBytes[i];
    }
    pipeline_secp256k1_num_to_bytes(&s, sig64 + 32);

    return 1;
}

int pipeline_schnorr_verify(const pipeline_u8 msg32[PIPELINE_SCHNORR_MSG_SIZE],
                             const pipeline_u8 pubkey32[PIPELINE_SCHNORR_PRIVKEY_SIZE],
                             const pipeline_u8 sig64[PIPELINE_SCHNORR_SIG_SIZE])
{
    pipeline_secp256k1_num rNum, sNum, e;
    pipeline_secp256k1_point capP, sG, eP, negEp, rPoint;
    pipeline_u8 eHash[32];
    pipeline_u8 rComputedBytes[32];
    int i;
    int equal;

    /* sig[0:32] must be a valid field element (BIP-340 verify step 2). */
    pipeline_secp256k1_num_from_bytes(sig64, &rNum);
    if (!pipeline_secp256k1_num_is_valid_field_element(&rNum)) {
        return 0;
    }

    /* sig[32:64] must be a valid scalar in [0, n-1] (verify step 3). s = 0
     * is a mathematically well-formed (if practically never-produced)
     * value, so it is explicitly allowed alongside scalar_in_range's
     * (0, n-1). */
    pipeline_secp256k1_num_from_bytes(sig64 + 32, &sNum);
    if (!pipeline_secp256k1_num_is_zero(&sNum) && !pipeline_secp256k1_scalar_in_range(&sNum)) {
        return 0;
    }

    /* lift_x(pubkey) -- fails if pubkey32 isn't a genuine on-curve x-only
     * public key (verify step 1). */
    if (!pipeline_secp256k1_point_lift_x(pubkey32, &capP)) {
        return 0;
    }

    /* e = int(tagged_hash("BIP0340/challenge", r || pubkey || m)) mod n. */
    {
        hash_part parts[3];
        pipeline_secp256k1_num eRaw;
        parts[0].data = sig64;     parts[0].len = 32;
        parts[1].data = pubkey32;  parts[1].len = 32;
        parts[2].data = msg32;     parts[2].len = PIPELINE_SCHNORR_MSG_SIZE;
        tagged_hash(kTagChallenge, sizeof(kTagChallenge), parts, 3, eHash);
        pipeline_secp256k1_num_from_bytes(eHash, &eRaw);
        pipeline_secp256k1_scalar_reduce(&eRaw, &e);
    }

    /* R = sG - eP = sG + (eP.x, -eP.y). */
    pipeline_secp256k1_point_mul_base(&sNum, &sG);
    pipeline_secp256k1_point_mul(&e, &capP, &eP);

    if (eP.infinity) {
        rPoint = sG;
    } else {
        negEp.x = eP.x;
        pipeline_secp256k1_field_negate(&eP.y, &negEp.y);
        negEp.infinity = 0;
        pipeline_secp256k1_point_add(&sG, &negEp, &rPoint);
    }

    if (rPoint.infinity) {
        return 0;
    }
    if (!pipeline_secp256k1_point_y_is_even(&rPoint)) {
        return 0;
    }

    pipeline_secp256k1_num_to_bytes(&rPoint.x, rComputedBytes);
    equal = 1;
    for (i = 0; i < 32; i++) {
        if (rComputedBytes[i] != sig64[i]) {
            equal = 0;
            break;
        }
    }
    return equal;
}

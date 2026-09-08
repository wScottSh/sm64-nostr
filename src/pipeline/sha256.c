/*
 * See sha256.h for provenance (Brad Conte's public-domain SHA-256, ported
 * the same way qrcodegen.c ports Project Nayuki's library -- no standard
 * headers, this pipeline's own fixed-width typedefs, block-scoped C99 `for`
 * declarations throughout).
 *
 * Algorithm structure (message schedule, compression rounds, padding,
 * length suffix, big-endian output) matches FIPS 180-4 / the upstream
 * reference exactly; only the two mechanical changes above have been made.
 * Correctness is pinned by published known-answer vectors in
 * tools/pipeline_test/main.c (test_sha256_known_answer_vectors), not
 * asserted here.
 */

#include "sha256.h"

static const pipeline_u32 kSha256K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

#define PIPELINE_SHA256_ROTRIGHT(a, b) (((a) >> (b)) | ((a) << (32 - (b))))

#define PIPELINE_SHA256_CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define PIPELINE_SHA256_MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define PIPELINE_SHA256_EP0(x) (PIPELINE_SHA256_ROTRIGHT(x, 2) ^ PIPELINE_SHA256_ROTRIGHT(x, 13) ^ PIPELINE_SHA256_ROTRIGHT(x, 22))
#define PIPELINE_SHA256_EP1(x) (PIPELINE_SHA256_ROTRIGHT(x, 6) ^ PIPELINE_SHA256_ROTRIGHT(x, 11) ^ PIPELINE_SHA256_ROTRIGHT(x, 25))
#define PIPELINE_SHA256_SIG0(x) (PIPELINE_SHA256_ROTRIGHT(x, 7) ^ PIPELINE_SHA256_ROTRIGHT(x, 18) ^ ((x) >> 3))
#define PIPELINE_SHA256_SIG1(x) (PIPELINE_SHA256_ROTRIGHT(x, 17) ^ PIPELINE_SHA256_ROTRIGHT(x, 19) ^ ((x) >> 10))

static void pipeline_sha256_transform(pipeline_sha256_ctx *ctx, const pipeline_u8 data[PIPELINE_SHA256_BLOCK_SIZE])
{
    pipeline_u32 m[64];
    pipeline_u32 a, b, c, d, e, f, g, h, t1, t2;

    for (int i = 0, j = 0; i < 16; i++, j += 4) {
        m[i] = ((pipeline_u32)data[j] << 24) | ((pipeline_u32)data[j + 1] << 16) |
               ((pipeline_u32)data[j + 2] << 8) | (pipeline_u32)data[j + 3];
    }
    for (int i = 16; i < 64; i++) {
        m[i] = PIPELINE_SHA256_SIG1(m[i - 2]) + m[i - 7] + PIPELINE_SHA256_SIG0(m[i - 15]) + m[i - 16];
    }

    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

    for (int i = 0; i < 64; i++) {
        t1 = h + PIPELINE_SHA256_EP1(e) + PIPELINE_SHA256_CH(e, f, g) + kSha256K[i] + m[i];
        t2 = PIPELINE_SHA256_EP0(a) + PIPELINE_SHA256_MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

void pipeline_sha256_init(pipeline_sha256_ctx *ctx)
{
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
}

void pipeline_sha256_update(pipeline_sha256_ctx *ctx, const pipeline_u8 *data, pipeline_u32 len)
{
    for (pipeline_u32 i = 0; i < len; i++) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == PIPELINE_SHA256_BLOCK_SIZE) {
            pipeline_sha256_transform(ctx, ctx->data);
            ctx->bitlen += (unsigned long long)PIPELINE_SHA256_BLOCK_SIZE * 8ULL;
            ctx->datalen = 0;
        }
    }
}

void pipeline_sha256_final(pipeline_sha256_ctx *ctx, pipeline_u8 hash[PIPELINE_SHA256_DIGEST_SIZE])
{
    pipeline_u32 i = ctx->datalen;

    /* Pad the final block: 0x80, zeros, then the 64-bit big-endian bit
     * length in the last 8 bytes, per FIPS 180-4 -- an extra block is
     * transformed first if there isn't room for the length in this one. */
    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) {
            ctx->data[i++] = 0x00;
        }
    } else {
        ctx->data[i++] = 0x80;
        while (i < PIPELINE_SHA256_BLOCK_SIZE) {
            ctx->data[i++] = 0x00;
        }
        pipeline_sha256_transform(ctx, ctx->data);
        for (i = 0; i < 56; i++) {
            ctx->data[i] = 0x00;
        }
    }

    ctx->bitlen += (unsigned long long)ctx->datalen * 8ULL;
    ctx->data[63] = (pipeline_u8)(ctx->bitlen);
    ctx->data[62] = (pipeline_u8)(ctx->bitlen >> 8);
    ctx->data[61] = (pipeline_u8)(ctx->bitlen >> 16);
    ctx->data[60] = (pipeline_u8)(ctx->bitlen >> 24);
    ctx->data[59] = (pipeline_u8)(ctx->bitlen >> 32);
    ctx->data[58] = (pipeline_u8)(ctx->bitlen >> 40);
    ctx->data[57] = (pipeline_u8)(ctx->bitlen >> 48);
    ctx->data[56] = (pipeline_u8)(ctx->bitlen >> 56);
    pipeline_sha256_transform(ctx, ctx->data);

    for (i = 0; i < 4; i++) {
        hash[i]      = (pipeline_u8)((ctx->state[0] >> (24 - i * 8)) & 0xff);
        hash[i + 4]  = (pipeline_u8)((ctx->state[1] >> (24 - i * 8)) & 0xff);
        hash[i + 8]  = (pipeline_u8)((ctx->state[2] >> (24 - i * 8)) & 0xff);
        hash[i + 12] = (pipeline_u8)((ctx->state[3] >> (24 - i * 8)) & 0xff);
        hash[i + 16] = (pipeline_u8)((ctx->state[4] >> (24 - i * 8)) & 0xff);
        hash[i + 20] = (pipeline_u8)((ctx->state[5] >> (24 - i * 8)) & 0xff);
        hash[i + 24] = (pipeline_u8)((ctx->state[6] >> (24 - i * 8)) & 0xff);
        hash[i + 28] = (pipeline_u8)((ctx->state[7] >> (24 - i * 8)) & 0xff);
    }
}

void pipeline_sha256(const pipeline_u8 *data, pipeline_u32 len, pipeline_u8 hash[PIPELINE_SHA256_DIGEST_SIZE])
{
    pipeline_sha256_ctx ctx;

    pipeline_sha256_init(&ctx);
    pipeline_sha256_update(&ctx, data, len);
    pipeline_sha256_final(&ctx, hash);
}

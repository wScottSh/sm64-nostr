#ifndef PIPELINE_SHA256_H
#define PIPELINE_SHA256_H

/*
 * Internal C99 port (spec #24, sub-issue #28) of Brad Conte's public-domain
 * SHA-256 implementation:
 *   https://github.com/B-Con/crypto-algorithms (sha256.h/sha256.c)
 *
 * This is free and unencumbered software released into the public domain
 * (the Unlicense), per the original repository's LICENSE file:
 *
 *   This is free and unencumbered software released into the public domain.
 *   Anyone is free to copy, modify, publish, use, compile, sell, or
 *   distribute this software, either in source code form or as a compiled
 *   binary, for any purpose, commercial or non-commercial, and by any means.
 *   For more information, please refer to <https://unlicense.org>.
 *
 * This is a genuine C99 port, not a verbatim vendor drop -- same discipline
 * as qrcodegen.h/.c (spec #24, sub-issue #27): the ROM build compiles under
 * -nostdinc/-ffreestanding, so this header/its .c never include <stdint.h>/
 * <string.h>/<stddef.h>. It uses this pipeline's own pipeline_u8/pipeline_u32
 * typedefs (from build_event.h) in place of uint8_t/uint32_t/size_t, and its
 * .c hand-rolls the couple of byte-copy loops upstream gets from <string.h>.
 * Loop-variable declarations are block-scoped throughout (genuinely C99),
 * so -- like port_stub_c99.c and qrcodegen.c -- this goes through the root
 * Makefile's per-object C99 carve-out (PIPELINE_C99_PORT_O), never the
 * whole-build COMPILER knob. It is compiled unmodified into both the ROM
 * build and the host test tool (tools/pipeline_test).
 *
 * Only the digest algorithm itself is ported here (init/update/final plus a
 * one-shot convenience wrapper). It is called only from within
 * src/pipeline/ (event_id.c, sub-issue #28) -- game glue never calls this
 * header directly.
 */

#include "build_event.h"

#define PIPELINE_SHA256_DIGEST_SIZE 32
#define PIPELINE_SHA256_BLOCK_SIZE  64

typedef struct {
    pipeline_u8  data[PIPELINE_SHA256_BLOCK_SIZE];
    pipeline_u32 datalen;
    /* Total input length in bits, tracked the same way upstream's
     * `unsigned long long bitlen` does. Plain `unsigned long long` is a
     * built-in type (no header needed); only additions and constant-amount
     * shifts are performed on it, both of which gcc emits inline on this
     * target without any libgcc/library call. */
    unsigned long long bitlen;
    pipeline_u32 state[8];
} pipeline_sha256_ctx;

void pipeline_sha256_init(pipeline_sha256_ctx *ctx);
void pipeline_sha256_update(pipeline_sha256_ctx *ctx, const pipeline_u8 *data, pipeline_u32 len);
void pipeline_sha256_final(pipeline_sha256_ctx *ctx, pipeline_u8 hash[PIPELINE_SHA256_DIGEST_SIZE]);

/* One-shot convenience wrapper: hash = SHA256(data[0:len]). */
void pipeline_sha256(const pipeline_u8 *data, pipeline_u32 len, pipeline_u8 hash[PIPELINE_SHA256_DIGEST_SIZE]);

#endif /* PIPELINE_SHA256_H */

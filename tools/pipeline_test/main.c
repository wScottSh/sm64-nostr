/*
 * Host test tool for the pipeline walking skeleton (spec #24, sub-issue
 * #25). Feeds a fixed StarCapture + key into build_event() and asserts the
 * stub output is byte-exact -- proving the pure pipeline sources compile
 * and run here identically to how they will in the ROM build.
 */
#include <stdio.h>
#include <string.h>

#include "build_event.h"

int main(void)
{
    StarCapture capture;
    pipeline_u8 key[PIPELINE_KEY_SIZE];
    BuiltEvent event;
    pipeline_u8 expected[PIPELINE_STUB_PAYLOAD_SIZE];
    int i;

    capture.course  = 9;
    capture.act     = 1;
    capture.coins   = 42;
    capture.frames  = 1234;
    capture.nonce16 = 0xBEEF;
    capture.keyId   = 0;

    for (i = 0; i < PIPELINE_KEY_SIZE; i++) {
        key[i] = (pipeline_u8)i;
    }

    build_event(&capture, key, &event);

    expected[0] = capture.course;
    expected[1] = capture.act;
    expected[2] = capture.coins;
    expected[3] = (pipeline_u8)(0xA5 ^ key[0]); /* port_stub_marker() ^ key[0] */

    if (memcmp(event.payload, expected, PIPELINE_STUB_PAYLOAD_SIZE) != 0) {
        printf("FAIL: pipeline stub output mismatch\n");
        return 1;
    }

    printf("PASS: pipeline stub build_event byte-exact\n");
    return 0;
}

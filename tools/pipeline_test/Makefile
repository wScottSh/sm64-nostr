# Host test tool for the Nostr pipeline (spec #24, sub-issue #25).
#
# Links the SAME pure pipeline sources compiled into the ROM
# (../../src/pipeline/*.c) a second time, unmodified, into a native host
# binary. This is the second "adapter" that proves the pipeline's
# interface -- build_event() -- is a real, exercised seam, mirroring the
# tools/asm-processor/tests prior art for a host tool with its own runner.
#
# port_stub_c99.c requires C99 (see its own header comment, and the root
# Makefile's per-object carve-out for the ROM side); on the host side there
# is no COMPILER=ido concern, so the whole tool is just built with -std=gnu99.

CC           := gcc
PIPELINE_DIR := ../../src/pipeline
CFLAGS       := -std=gnu99 -Wall -Wextra -I $(PIPELINE_DIR)

SRCS := main.c $(PIPELINE_DIR)/build_event.c $(PIPELINE_DIR)/port_stub_c99.c
BIN  := pipeline_test

.PHONY: all test clean

all: test

$(BIN): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $(SRCS)

test: $(BIN)
	./$(BIN)

clean:
	$(RM) $(BIN)

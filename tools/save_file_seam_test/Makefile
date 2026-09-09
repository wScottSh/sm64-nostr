# Host test tool for sandbox seam E -- cannon suppression (spec #80,
# sub-issue #81).
#
# Links the SAME src/game/save_file.c the ROM build compiles, unmodified, a
# second time into a native host binary -- mirroring ../pipeline_test's own
# convention (see its Makefile header comment). save_file_host_stubs.c (this
# directory) satisfies save_file.c's non-seam externs so it can link without
# the rest of the game; it never enters the ROM's object graph, exactly like
# ../pipeline_test/qr_host_decode.c.
#
# NON_MATCHING=1 AVOID_UB=1 VERSION_US=1 mirror the root Makefile's own
# NON_MATCHING build defines (see its DEFINES += NON_MATCHING=1 AVOID_UB=1
# and CC_CHECK_CFLAGS) -- required because include/macros.h #errors out
# without them on a non-IDO compiler. -I paths mirror the root Makefile's
# own INCLUDE_DIRS (include, src, .).

CC      := gcc
ROOT    := ../..
SRC_DIR := $(ROOT)/src

CFLAGS := -std=gnu99 -Wall -Wextra -Wno-unused-parameter \
          -DNON_MATCHING=1 -DAVOID_UB=1 -DVERSION_US=1 \
          -I $(ROOT)/include -I $(SRC_DIR) -I $(SRC_DIR)/game -I $(ROOT)

SRCS := main.c save_file_host_stubs.c $(SRC_DIR)/game/save_file.c
BIN  := save_file_seam_test

.PHONY: all test clean

all: test

$(BIN): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $(SRCS)

test: $(BIN)
	./$(BIN)

clean:
	$(RM) $(BIN)

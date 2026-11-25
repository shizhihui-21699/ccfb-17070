# io_uring audit / intercept component
#
# Target: portable C99, no liburing, no kernel headers.  The same sources build
#   - as an out-of-tree kernel module (src/kmod) against 5.4 .. 6.x
#   - as a userspace tool (bin/iou) on the Linux host
#   - as a userspace test binary on any POSIX host (this Mac, CI)
#
# Usage:
#   make            # build the portable lib + userspace tools
#   make test       # build and run the portable unit tests
#   make kmod KDIR=...   # build the kernel module (Linux only)
#   make docs       # regenerate the opcode/version reference docs

CC      ?= cc
AR      ?= ar
CFLAGS  ?= -O2 -g
WARN     = -Wall -Wextra -Werror -Wshadow -Wpointer-arith -Wcast-align \
           -Wstrict-prototypes -Wmissing-prototypes -Wformat=2 \
           -Wnull-dereference -Wdouble-promotion -Wvla -Wundef
STD      = -std=c99 -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE
INCLUDES = -Iinclude

BUILD    = build
LIB_OBJS = $(BUILD)/iou_op.o $(BUILD)/iou_version.o $(BUILD)/iou_decode.o
ALL_OBJS = $(LIB_OBJS) $(BUILD)/iou_rules.o $(BUILD)/iou_audit.o \
           $(BUILD)/iou_keeper.o $(BUILD)/iou_ring.o

.PHONY: all lib tools test clean kmod docs check

all: lib tools

$(BUILD):
	@mkdir -p $(BUILD)

$(BUILD)/%.o: src/core/%.c | $(BUILD)
	$(CC) $(STD) $(WARN) $(CFLAGS) $(INCLUDES) -c -o $@ $<

lib: $(BUILD)/libiouaudit.a

$(BUILD)/libiouaudit.a: $(ALL_OBJS)
	$(AR) rcs $@ $(ALL_OBJS)

tools: $(BUILD)/iou

$(BUILD)/iou: $(BUILD)/iou_main.o $(BUILD)/libiouaudit.a
	$(CC) $(CFLAGS) -o $@ $^ -lm

$(BUILD)/iou_main.o: src/iou_main.c | $(BUILD)
	$(CC) $(STD) $(WARN) $(CFLAGS) $(INCLUDES) -c -o $@ $<

# ---------------------------------------------------------------- tests
TEST_BINS = $(BUILD)/test_decode $(BUILD)/test_version $(BUILD)/test_rules \
            $(BUILD)/test_ring $(BUILD)/test_keeper \
            $(BUILD)/test_audit

$(BUILD)/test_%: tests/test_%.c $(BUILD)/libiouaudit.a | $(BUILD)
	$(CC) $(STD) $(WARN) $(CFLAGS) $(INCLUDES) -o $@ $< $(BUILD)/libiouaudit.a

test: $(TEST_BINS) $(BUILD)/iou
	@set -e; for t in $(TEST_BINS); do echo "== $$t"; $$t; done; \
	echo "== CLI integration"; \
	sh tests/test_cli.sh; \
	echo "all portable tests passed"

# ---------------------------------------------------------------- kernel module
kmod:
	@test -n "$(KDIR)" || { echo "usage: make kmod KDIR=/lib/modules/\$$(uname -r)/build"; exit 1; }
	$(MAKE) -C $(KDIR) M=$(CURDIR)/src/kmod modules

# ---------------------------------------------------------------- docs
docs: $(BUILD)/gen_catalog
	$(BUILD)/gen_catalog > docs/opcode-catalog.md

$(BUILD)/gen_catalog: tools/gen_catalog.c $(BUILD)/libiouaudit.a | $(BUILD)
	$(CC) $(STD) $(CFLAGS) $(INCLUDES) -o $@ $< $(BUILD)/libiouaudit.a

clean:
	rm -rf $(BUILD)

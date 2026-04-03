# Test suite Makefile for famine

CC32 = gcc -m32
CC64 = gcc -m64
CFLAGS = -Wall -Wextra
LDFLAGS = -lm
SRCDIR = src
BINDIR = bin

# Test program sources
SRCS = $(wildcard $(SRCDIR)/*.c)
ASMS = $(wildcard $(SRCDIR)/*.S)

# Generate all binary variants
BINS_64_PIE     = $(patsubst $(SRCDIR)/%.c,$(BINDIR)/%_64_pie,$(SRCS))
BINS_64_NOPIE   = $(patsubst $(SRCDIR)/%.c,$(BINDIR)/%_64_nopie,$(SRCS))
BINS_64_STATIC  = $(patsubst $(SRCDIR)/%.c,$(BINDIR)/%_64_static,$(SRCS))
BINS_64_STATIC_PIE = $(patsubst $(SRCDIR)/%.c,$(BINDIR)/%_64_static_pie,$(SRCS))
BINS_32_PIE     = $(patsubst $(SRCDIR)/%.c,$(BINDIR)/%_32_pie,$(SRCS))
BINS_32_NOPIE   = $(patsubst $(SRCDIR)/%.c,$(BINDIR)/%_32_nopie,$(SRCS))
BINS_32_STATIC  = $(patsubst $(SRCDIR)/%.c,$(BINDIR)/%_32_static,$(SRCS))
BINS_32_STATIC_PIE = $(patsubst $(SRCDIR)/%.c,$(BINDIR)/%_32_static_pie,$(SRCS))

# Assembly programs (64-bit only for now)
BINS_ASM_64 = $(patsubst $(SRCDIR)/%.S,$(BINDIR)/%_asm64,$(ASMS))

ALL_BINS = $(BINS_64_PIE) $(BINS_64_NOPIE) $(BINS_64_STATIC) $(BINS_64_STATIC_PIE) \
           $(BINS_32_PIE) $(BINS_32_NOPIE) $(BINS_32_STATIC) $(BINS_32_STATIC_PIE) \
           $(BINS_ASM_64)

.PHONY: all clean test

all: $(ALL_BINS)

# 64-bit PIE (default)
$(BINDIR)/%_64_pie: $(SRCDIR)/%.c | $(BINDIR)
	$(CC64) $(CFLAGS) -pie -fPIE -o $@ $< $(LDFLAGS)

# 64-bit no-PIE
$(BINDIR)/%_64_nopie: $(SRCDIR)/%.c | $(BINDIR)
	$(CC64) $(CFLAGS) -no-pie -fno-PIE -o $@ $< $(LDFLAGS)

# 64-bit static
$(BINDIR)/%_64_static: $(SRCDIR)/%.c | $(BINDIR)
	$(CC64) $(CFLAGS) -static -o $@ $< $(LDFLAGS) 2>/dev/null || touch $@

# 64-bit static-PIE
$(BINDIR)/%_64_static_pie: $(SRCDIR)/%.c | $(BINDIR)
	$(CC64) $(CFLAGS) -static-pie -o $@ $< $(LDFLAGS) 2>/dev/null || touch $@

# 32-bit PIE
$(BINDIR)/%_32_pie: $(SRCDIR)/%.c | $(BINDIR)
	$(CC32) $(CFLAGS) -pie -fPIE -o $@ $< $(LDFLAGS) 2>/dev/null || touch $@

# 32-bit no-PIE
$(BINDIR)/%_32_nopie: $(SRCDIR)/%.c | $(BINDIR)
	$(CC32) $(CFLAGS) -no-pie -fno-PIE -o $@ $< $(LDFLAGS) 2>/dev/null || touch $@

# 32-bit static
$(BINDIR)/%_32_static: $(SRCDIR)/%.c | $(BINDIR)
	$(CC32) $(CFLAGS) -static -o $@ $< $(LDFLAGS) 2>/dev/null || touch $@

# 32-bit static-PIE
$(BINDIR)/%_32_static_pie: $(SRCDIR)/%.c | $(BINDIR)
	$(CC32) $(CFLAGS) -static-pie -o $@ $< $(LDFLAGS) 2>/dev/null || touch $@

# 64-bit assembly
$(BINDIR)/%_asm64: $(SRCDIR)/%.S | $(BINDIR)
	$(CC64) -nostdlib -static -o $@ $<

$(BINDIR):
	mkdir -p $(BINDIR)

clean:
	rm -rf $(BINDIR) results/*.log results/*.out crashed/*

test: all
	./run_tests.sh

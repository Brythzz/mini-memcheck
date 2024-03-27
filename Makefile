CC = clang
WARNINGS = -Wall -Wextra -Wno-unused-parameter -Wmissing-declarations -Wmissing-variable-declarations
CFLAGS_COMMON = $(WARNINGS) -std=c99 -O3
CFLAGS_SHARED = -dynamiclib -fPIC

EXE_SHARED = mini-memcheck.dylib
EXE_BINARY = mini-memcheck

.PHONY: all lib clean

all: $(EXE_SHARED) $(EXE_BINARY)
lib: $(EXE_SHARED)

$(EXE_SHARED): mini-memcheck.c mini-utils.c
	$(CC) $(CFLAGS_COMMON) $(CFLAGS_SHARED) $^ -o $@

$(EXE_BINARY): mini-main.c
	$(CC) $(CFLAGS_COMMON) $< -o $@

clean:
	rm -rf $(EXE_SHARED) $(EXE_BINARY)

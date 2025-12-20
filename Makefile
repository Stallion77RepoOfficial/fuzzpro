CC = clang
CFLAGS = -Wall -Wextra -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function -Wno-unused-but-set-variable -Wno-shift-count-overflow -Wno-tautological-bitwise-compare -Wno-sign-compare -Wno-format -g -O3 -Iinclude -arch arm64
LDFLAGS = -framework CoreFoundation

SRC = src/main.c \
      src/fuzzer.c \
      src/macho.c \
      src/arm64dis.c \
      src/executor.c \
      src/coverage_engine.c \
      src/forkserver.c \
      src/instrument.c \
      src/persistent.c \
      src/calibrate.c \
      src/trace.c \
      src/minimize.c \
      src/redqueen.c \
      src/analysis.c \
      src/simd.c \
      src/atomic.c \
      src/autodict.c \
      src/decompile.c \
      src/symbolic.c \
      src/symexec.c \
      src/lafintel.c \
      src/parallel.c \
      src/pathexplorer.c \
      src/crypto.c \
      src/taint.c \
      src/syscall.c \
      src/constraint.c \
      src/solver.c \
      src/ssa.c \
      src/codegen.c \
      src/exploit.c

TARGET = fuzzpro

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo ""
	@echo "Build complete: $(TARGET)"
	@echo "Run './fuzzpro --help' for usage"

debug: CFLAGS += -fsanitize=address -fsanitize=undefined
debug: LDFLAGS += -fsanitize=address -fsanitize=undefined
debug: $(TARGET)

release: CFLAGS = -Wall -O3 -Iinclude -arch arm64 -DNDEBUG
release: $(TARGET)
	strip $(TARGET)

test: $(TARGET)
	@echo "Testing Mach-O parser..."
	./$(TARGET) --parse /bin/ls
	@echo ""
	@echo "Testing disassembler..."
	./$(TARGET) --disasm /bin/ls | head -20

clean:
	rm -f $(TARGET)
	rm -rf crashes/

install: release
	install -m 755 $(TARGET) /usr/local/bin/

.PHONY: all debug release test clean install

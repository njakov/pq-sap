# Paths
LIB_DIR = ./libs
INC_DIR = ./libs
TEST_DIR = ./tests
SRC_DIR = ./src
BENCH_DIR = ./bench

# Targets
TARGET = kyber_demo
TEST_NAMES = kem_test protocol_test
TEST_TARGETS = $(addprefix $(TEST_DIR)/, $(TEST_NAMES))
BENCH_NAMES = benchmark benchmark_shuffle
BENCH_TARGET = $(addprefix $(BENCH_DIR)/, $(BENCH_NAMES))

# Sources
MAIN_SOURCES = main.c 
SHARED_SOURCES = $(LIB_DIR)/randombytes.c #$(LIB_DIR)/indcpa.c
BENCH_SOURCES = $(SRC_DIR)/protocol.c $(SHARED_SOURCES)

# Libraries 
KYBER_LIBS =  -lpqcrystals_kyber512_avx2 -lpqcrystals_kyber768_avx2 -lpqcrystals_kyber1024_avx2
FIPS202_LIBS = -lpqcrystals_fips202_ref -lpqcrystals_fips202x4_avx2

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -I$(INC_DIR) -I$(SRC_DIR)
LDFLAGS = -L$(LIB_DIR) -Wl,-rpath=$(LIB_DIR) $(KYBER_LIBS) $(FIPS202_LIBS)

# Default target
all: $(TARGET) tests benchmarks

# Main demo target
$(TARGET): $(MAIN_SOURCES) $(SHARED_SOURCES)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Rule for compiling tests
$(TEST_DIR)/kem_test: $(TEST_DIR)/kem_test.c $(SHARED_SOURCES)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(TEST_DIR)/protocol_test: $(TEST_DIR)/protocol_test.c $(SRC_DIR)/protocol.c $(SHARED_SOURCES)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Benchmark target
$(BENCH_DIR)/benchmark: $(BENCH_DIR)/bench.c $(BENCH_SOURCES)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(BENCH_DIR)/benchmark_shuffle: $(BENCH_DIR)/bench_shuffle.c $(BENCH_SOURCES)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)


# Build all test targets
tests: $(TEST_TARGETS)
benchmarks: $(BENCH_TARGET)

# Run tests
test: tests
	LD_LIBRARY_PATH=$(LIB_DIR) $(TEST_DIR)/kem_test
	LD_LIBRARY_PATH=$(LIB_DIR) $(TEST_DIR)/protocol_test

# Run main demo
run: $(TARGET)
	LD_LIBRARY_PATH=$(LIB_DIR) ./$(TARGET)

# Run benchmarks
bench: benchmarks
	LD_LIBRARY_PATH=$(LIB_DIR) ./$(BENCH_TARGET)

# Clean build artifacts
clean:
	rm -f $(TARGET) $(TEST_TARGETS) $(BENCH_TARGET)

.PHONY: all tests test run clean

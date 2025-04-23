# Paths
LIB_DIR = ./libs
INC_DIR = ./libs
TEST_DIR = ./tests

# Targets
TARGET = kyber_demo
TEST_NAMES = kem_test protocol_test
TEST_TARGETS = $(addprefix $(TEST_DIR)/, $(TEST_NAMES))

# Sources
MAIN_SOURCES = main.c 
SHARED_SOURCES = $(LIB_DIR)/randombytes.c


# Libraries
KYBER_LIBS = -lpqcrystals_kyber512_avx2 -lpqcrystals_kyber768_avx2 -lpqcrystals_kyber1024_avx2
FIPS202_LIBS = -lpqcrystals_fips202_ref -lpqcrystals_fips202x4_avx2

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -I$(INC_DIR)
LDFLAGS = -L$(LIB_DIR) -Wl,-rpath=$(LIB_DIR) $(KYBER_LIBS) $(FIPS202_LIBS)

# Default target
all: $(TARGET) tests

# Main demo target
$(TARGET): $(MAIN_SOURCES) $(SHARED_SOURCES)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Rule for compiling tests
$(TEST_DIR)/%: $(TEST_DIR)/%.c
	$(CC) $(CFLAGS) $< $(SHARED_SOURCES) -o $@ $(LDFLAGS)

# Build all test targets
tests: $(TEST_TARGETS)

# Run tests
test: tests
	LD_LIBRARY_PATH=$(LIB_DIR) $(TEST_DIR)/kem_test
	LD_LIBRARY_PATH=$(LIB_DIR) $(TEST_DIR)/protocol_test

# Run main demo
run: $(TARGET)
	LD_LIBRARY_PATH=$(LIB_DIR) ./$(TARGET)

# Clean build artifacts
clean:
	rm -f $(TARGET) $(TEST_TARGETS)

.PHONY: all tests test run clean

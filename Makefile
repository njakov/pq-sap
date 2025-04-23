# Paths
LIB_DIR = ./libs
INC_DIR = ./libs
TARGET = kyber_demo

SOURCES = main.c libs/randombytes.c

# Link ALL Kyber libraries (no KYBER_LEVEL selection)
KYBER_LIBS = -lpqcrystals_kyber512_avx2 -lpqcrystals_kyber768_avx2 -lpqcrystals_kyber1024_avx2
FIPS202_LIBS = -lpqcrystals_fips202_ref -lpqcrystals_fips202x4_avx2

# Compiler/linker flags
CC = gcc
CFLAGS = -Wall -Wextra -I$(INC_DIR)
LDFLAGS = -L$(LIB_DIR) -Wl,-rpath=$(LIB_DIR) $(KYBER_LIBS) $(FIPS202_LIBS)

# Build rules
all: $(TARGET)
$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) $(SOURCES) -o $@ $(LDFLAGS)

run: $(TARGET)
	LD_LIBRARY_PATH=$(LIB_DIR) ./$(TARGET)

clean:
	rm -f $(TARGET)
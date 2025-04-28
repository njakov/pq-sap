/**
 * @file fips202.h
 * @brief Header file for SHA-3 and SHAKE cryptographic hash functions (FIPS 202 standard).
 *
 * This file provides the interface for SHA-3 based functions including SHAKE128, SHAKE256, SHA3-256, and SHA3-512,
 * along with necessary constants, types, and function prototypes.
 *
 * It defines the keccak_state structure used for internal state management,
 * and the FIPS202_NAMESPACE macro for namespace management of function names.
 *
 * The implementation follows the FIPS 202 standard for cryptographic hash functions and extendable-output functions (XOFs).
 *
 * The actual function implementations are located in shared libraries (.so files),
 * primarily in:
 * - `libpqcrystals_fips202_ref.so` (reference implementation)
 * - `libpqcrystals_fips202x4_avx2.so` (AVX2-optimized implementation)
 *
 * @note All functions operate on byte arrays, and sizes are specified in bytes.
 *
 * @see https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf for the FIPS 202 standard.
 */

#ifndef FIPS202_H
#define FIPS202_H

#include <stddef.h>
#include <stdint.h>

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_512_RATE 72

#define FIPS202_NAMESPACE(s) pqcrystals_kyber_fips202_avx2_##s

typedef struct {
    uint64_t s[25];
    unsigned int pos;
} keccak_state;

#define shake128_init FIPS202_NAMESPACE(shake128_init)
void shake128_init(keccak_state *state);
#define shake128_absorb FIPS202_NAMESPACE(shake128_absorb)
void shake128_absorb(keccak_state *state, const uint8_t *in, size_t inlen);
#define shake128_finalize FIPS202_NAMESPACE(shake128_finalize)
void shake128_finalize(keccak_state *state);
#define shake128_squeeze FIPS202_NAMESPACE(shake128_squeeze)
void shake128_squeeze(uint8_t *out, size_t outlen, keccak_state *state);
#define shake128_absorb_once FIPS202_NAMESPACE(shake128_absorb_once)
void shake128_absorb_once(keccak_state *state, const uint8_t *in, size_t inlen);
#define shake128_squeezeblocks FIPS202_NAMESPACE(shake128_squeezeblocks)
void shake128_squeezeblocks(uint8_t *out, size_t nblocks, keccak_state *state);

#define shake256_init FIPS202_NAMESPACE(shake256_init)
void shake256_init(keccak_state *state);
#define shake256_absorb FIPS202_NAMESPACE(shake256_absorb)
void shake256_absorb(keccak_state *state, const uint8_t *in, size_t inlen);
#define shake256_finalize FIPS202_NAMESPACE(shake256_finalize)
void shake256_finalize(keccak_state *state);
#define shake256_squeeze FIPS202_NAMESPACE(shake256_squeeze)
void shake256_squeeze(uint8_t *out, size_t outlen, keccak_state *state);
#define shake256_absorb_once FIPS202_NAMESPACE(shake256_absorb_once)
void shake256_absorb_once(keccak_state *state, const uint8_t *in, size_t inlen);
#define shake256_squeezeblocks FIPS202_NAMESPACE(shake256_squeezeblocks)
void shake256_squeezeblocks(uint8_t *out, size_t nblocks,  keccak_state *state);


/**
 * @brief Computes the SHAKE128 extendable-output function (XOF) on input data.
 *
 * This function takes an input message `in` of length `inlen` bytes
 * and produces an output of `outlen` bytes into the buffer `out`.
 *
 * SHAKE128 is a member of the SHA-3 family of hash functions standardized by NIST,
 * providing cryptographic hashing with arbitrary output length.
 *
 * @param[out] out Pointer to the output buffer where the result will be stored (must have at least `outlen` bytes allocated).
 * @param[in] outlen Desired number of output bytes to produce.
 * @param[in] in Pointer to the input message.
 * @param[in] inlen Length of the input message in bytes.
 *
 * @note This function implements the SHAKE128 function as specified in FIPS 202.
 *
 * @see https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf for the SHA-3 standard.
 */
#define shake128 FIPS202_NAMESPACE(shake128)
void shake128(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);



#define shake256 FIPS202_NAMESPACE(shake256)
void shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);
#define sha3_256 FIPS202_NAMESPACE(sha3_256)
void sha3_256(uint8_t h[32], const uint8_t *in, size_t inlen);
#define sha3_512 FIPS202_NAMESPACE(sha3_512)
void sha3_512(uint8_t h[64], const uint8_t *in, size_t inlen);

#endif

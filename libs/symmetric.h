#ifndef SYMMETRIC_H
#define SYMMETRIC_H

#include <stddef.h>
#include <stdint.h>
#include "params.h"

#include "fips202.h"
#include "fips202x4.h"

typedef keccak_state xof_state;

#define kyber_shake128_absorb KYBER_NAMESPACE(kyber_shake128_absorb)
void kyber_shake128_absorb(keccak_state *s,
                           const uint8_t seed[KYBER_SYMBYTES],
                           uint8_t x,
                           uint8_t y);

#define kyber_shake256_prf KYBER_NAMESPACE(kyber_shake256_prf)
void kyber_shake256_prf(uint8_t *out, size_t outlen, const uint8_t key[KYBER_SYMBYTES], uint8_t nonce);

#define kyber_shake256_rkprf KYBER_NAMESPACE(kyber_shake256_rkprf)
void kyber_shake256_rkprf(uint8_t out[KYBER_SSBYTES], const uint8_t key[KYBER_SYMBYTES], const uint8_t input[KYBER_CIPHERTEXTBYTES]);

#define XOF_BLOCKBYTES SHAKE128_RATE

#define hash_h(OUT, IN, INBYTES) sha3_256(OUT, IN, INBYTES)
#define hash_g(OUT, IN, INBYTES) sha3_512(OUT, IN, INBYTES)
/**
 * @brief Absorbs a seed and matrix indices into the state of the SHAKE128 XOF (Extensible Output Function).
 *
 * This function absorbs the provided seed and the matrix indices (`x` and `y`) into the given XOF state. The absorbed data
 * is used as the basis for generating deterministic random values, which are then squeezed out by the `xof_squeezeblocks` function.
 * This operation initializes the internal state of the XOF for subsequent squeezes.
 *
 * The function uses the `SHAKE128` cryptographic hash function and is commonly used in lattice-based cryptography to ensure
 * deterministically generated random values for matrix generation or other cryptographic operations.
 *
 * @param[out] s The XOF state to absorb data into.
 * @param[in] seed The seed used to initialize the XOF state (KYBER_SYMBYTES length).
 * @param[in] x The x-index of the matrix (or other context-specific value).
 * @param[in] y The y-index of the matrix (or other context-specific value).
 */
#define xof_absorb(STATE, SEED, X, Y) kyber_shake128_absorb(STATE, SEED, X, Y)
 /**
  * @brief Squeezes random blocks of data from the SHAKE128 XOF state into the output buffer.
  *
  * This function squeezes `OUTBLOCKS` blocks of data from the given XOF state into the output buffer. The data is generated
  * deterministically based on the absorbed seed and matrix indices. The number of bytes squeezed is determined by the
  * `OUTBLOCKS` parameter, which specifies how many blocks of `SHAKE128_RATE` bytes are output.
  *
  * This operation is typically used after absorbing the seed and matrix indices via `xof_absorb`, and it generates the random
  * values needed for various cryptographic operations (such as matrix generation, key derivation, etc.).
  *
  * @param[out] OUT The output buffer where the squeezed data will be stored.
  * @param[in] OUTBLOCKS The number of blocks of data to squeeze from the XOF state.
  * @param[in] STATE The XOF state from which data will be squeezed (initialized by `xof_absorb`).
  */
#define xof_squeezeblocks(OUT, OUTBLOCKS, STATE) shake128_squeezeblocks(OUT, OUTBLOCKS, STATE)


#define prf(OUT, OUTBYTES, KEY, NONCE) kyber_shake256_prf(OUT, OUTBYTES, KEY, NONCE)
#define rkprf(OUT, KEY, INPUT) kyber_shake256_rkprf(OUT, KEY, INPUT)

#endif /* SYMMETRIC_H */

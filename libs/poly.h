/**
 * @file poly.h
 * @brief This file defines the `poly` data structure and provides function declarations for operations
 * on polynomials used in cryptographic algorithms, particularly in the context of Kyber, a lattice-based
 * encryption scheme. The operations include compression, decomposition, NTT (Number Theoretic Transform),
 * base multiplication, and polynomial reductions.
 *
 * The `poly` structure represents a polynomial used in the Kyber cryptosystem, and the functions in this file
 * perform various polynomial operations, such as converting to/from byte arrays, applying noise, performing
 * modular reductions, and executing arithmetic operations (addition, subtraction, multiplication).
 *
 * The function implementations are likely found in the corresponding Kyber implementation files.
 */

#ifndef POLY_H
#define POLY_H

#include <stdint.h>
#include "align.h"
#include "params.h"

typedef ALIGNED_INT16(KYBER_N) poly;

/**
 * @brief Compresses a polynomial into a compact byte representation.
 *
 * This function compresses the given polynomial `a` into a byte array `r`. The implementation is optimized for
 * the Kyber encryption scheme and is used for efficient polynomial storage and transmission.
 *
 * @param r The compressed byte representation of the polynomial.
 * @param a The polynomial to be compressed.
 */#define poly_compress KYBER_NAMESPACE(poly_compress)
void poly_compress(uint8_t r[KYBER_POLYCOMPRESSEDBYTES], const poly *a);


/**
 * @brief Decompresses a byte array back into a polynomial.
 *
 * This function decompresses the byte array `a` into the polynomial `r`. The byte array `a` represents the
 * compressed form of the polynomial.
 *
 * @param r The resulting polynomial.
 * @param a The byte array containing the compressed polynomial.
 */
#define poly_decompress KYBER_NAMESPACE(poly_decompress)
void poly_decompress(poly *r, const uint8_t a[KYBER_POLYCOMPRESSEDBYTES]);

#define poly_tobytes KYBER_NAMESPACE(poly_tobytes)
void poly_tobytes(uint8_t r[KYBER_POLYBYTES], const poly *a);
#define poly_frombytes KYBER_NAMESPACE(poly_frombytes)
void poly_frombytes(poly *r, const uint8_t a[KYBER_POLYBYTES]);

#define poly_frommsg KYBER_NAMESPACE(poly_frommsg)
void poly_frommsg(poly *r, const uint8_t msg[KYBER_INDCPA_MSGBYTES]);
#define poly_tomsg KYBER_NAMESPACE(poly_tomsg)
void poly_tomsg(uint8_t msg[KYBER_INDCPA_MSGBYTES], const poly *r);


/**
 * @brief Generates noise (eta1) for a polynomial using a seed and nonce.
 *
 * This function generates noise with a specific distribution (eta1) and stores it in the polynomial `r`.
 * The noise is generated deterministically using the provided `seed` and `nonce`.
 *
 * @param r The resulting polynomial containing the generated noise.
 * @param seed The seed for noise generation.
 * @param nonce The nonce used to differentiate different noise generations.
 */
#define poly_getnoise_eta1 KYBER_NAMESPACE(poly_getnoise_eta1)
void poly_getnoise_eta1(poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce);

#define poly_getnoise_eta2 KYBER_NAMESPACE(poly_getnoise_eta2)
void poly_getnoise_eta2(poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce);

#ifndef KYBER_90S
#define poly_getnoise_eta1_4x KYBER_NAMESPACE(poly_getnoise_eta2_4x)
void poly_getnoise_eta1_4x(poly *r0,
                           poly *r1,
                           poly *r2,
                           poly *r3,
                           const uint8_t seed[32],
                           uint8_t nonce0,
                           uint8_t nonce1,
                           uint8_t nonce2,
                           uint8_t nonce3);

#if KYBER_K == 2
#define poly_getnoise_eta1122_4x KYBER_NAMESPACE(poly_getnoise_eta1122_4x)
void poly_getnoise_eta1122_4x(poly *r0,
                              poly *r1,
                              poly *r2,
                              poly *r3,
                              const uint8_t seed[32],
                              uint8_t nonce0,
                              uint8_t nonce1,
                              uint8_t nonce2,
                              uint8_t nonce3);
#endif
#endif


#define poly_ntt KYBER_NAMESPACE(poly_ntt)
void poly_ntt(poly *r);
#define poly_invntt_tomont KYBER_NAMESPACE(poly_invntt_tomont)
void poly_invntt_tomont(poly *r);
#define poly_nttunpack KYBER_NAMESPACE(poly_nttunpack)
void poly_nttunpack(poly *r);
#define poly_basemul_montgomery KYBER_NAMESPACE(poly_basemul_montgomery)
void poly_basemul_montgomery(poly *r, const poly *a, const poly *b);


/**
 * @brief Converts a polynomial to Montgomery form.
 *
 * This function converts the polynomial `r` into Montgomery form, which is necessary for efficient modular
 * arithmetic in the Kyber scheme.
 *
 * @param r The polynomial to be converted.
 */
#define poly_tomont KYBER_NAMESPACE(poly_tomont)
void poly_tomont(poly *r);

#define poly_reduce KYBER_NAMESPACE(poly_reduce)
void poly_reduce(poly *r);

#define poly_add KYBER_NAMESPACE(poly_add)
void poly_add(poly *r, const poly *a, const poly *b);
#define poly_sub KYBER_NAMESPACE(poly_sub)
void poly_sub(poly *r, const poly *a, const poly *b);

#endif

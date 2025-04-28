/**
 * @file polyvec.h
 * @brief This file defines the `polyvec` data structure and provides function declarations for operations
 * on polynomial vectors used in cryptographic algorithms, particularly in the context of Kyber, a lattice-based
 * encryption scheme. The operations include compression, decomposition, NTT (Number Theoretic Transform), and base multiplication.
 *
 * The `polyvec` structure is an array of polynomials and various functions operate on these vectors to perform
 * polynomial transformations, reductions, additions, and byte conversions. These operations are integral to the
 * encryption and decryption procedures of the Kyber scheme.
 *
 * The function implementations are likely located in the corresponding Kyber implementation files.
 */
#ifndef POLYVEC_H
#define POLYVEC_H

#include <stdint.h>
#include "params.h"
#include "poly.h"

 /**
  * @struct polyvec
  * @brief A structure that holds a vector of polynomials.
  *
  * The `polyvec` structure contains an array of `KYBER_K` polynomials, where `KYBER_K` is a predefined constant
  * indicating the number of polynomials in the vector.
  */
typedef struct{
  poly vec[KYBER_K]; /**< Array of polynomials */
} polyvec;

/**
 * @brief Compresses a polynomial vector into a compact byte representation.
 *
 * This function compresses the given polynomial vector `a` into the byte array `r`, which is of fixed size.
 * The implementation is likely found in one of the Kyber library files, specifically designed for efficient compression.
 *
 * @param r The compressed byte representation of the polynomial vector.
 * @param a The polynomial vector to be compressed.
 */
#define polyvec_compress KYBER_NAMESPACE(polyvec_compress)
void polyvec_compress(uint8_t r[KYBER_POLYVECCOMPRESSEDBYTES+2], const polyvec *a);


/**
 * @brief Decompresses a byte representation back into a polynomial vector.
 *
 * This function decompresses the byte array `a` into the polynomial vector `r`. The byte array `a` contains a
 * compressed version of the polynomial vector, and the function reconstructs the original polynomial vector.
 *
 * @param r The resulting polynomial vector.
 * @param a The byte array containing the compressed polynomial vector.
 */
#define polyvec_decompress KYBER_NAMESPACE(polyvec_decompress)
void polyvec_decompress(polyvec *r, const uint8_t a[KYBER_POLYVECCOMPRESSEDBYTES+12]);


/**
 * @brief Converts a polynomial vector into a byte array.
 *
 * This function converts the given polynomial vector `a` into a byte array `r` for transmission or storage.
 * The byte array is of fixed size, determined by the parameters of the Kyber scheme.
 *
 * @param r The resulting byte array representation of the polynomial vector.
 * @param a The polynomial vector to be converted to bytes.
 */
#define polyvec_tobytes KYBER_NAMESPACE(polyvec_tobytes)
void polyvec_tobytes(uint8_t r[KYBER_POLYVECBYTES], const polyvec *a);


/**
 * @brief Converts a byte array back into a polynomial vector.
 *
 * This function converts the byte array `a` back into the corresponding polynomial vector `r`.
 * The byte array `a` represents a serialized form of the polynomial vector.
 *
 * @param r The resulting polynomial vector.
 * @param a The byte array containing the serialized polynomial vector.
 */
#define polyvec_frombytes KYBER_NAMESPACE(polyvec_frombytes)
void polyvec_frombytes(polyvec *r, const uint8_t a[KYBER_POLYVECBYTES]);


#define polyvec_ntt KYBER_NAMESPACE(polyvec_ntt)
void polyvec_ntt(polyvec *r);



#define polyvec_invntt_tomont KYBER_NAMESPACE(polyvec_invntt_tomont)
void polyvec_invntt_tomont(polyvec *r);



/**
 * @brief Performs base multiplication and accumulation in Montgomery form on two polynomial vectors.
 *
 * This function performs base multiplication on two polynomial vectors `a` and `b`, accumulating the result
 * into the polynomial `r` in Montgomery form. This operation is essential for lattice-based cryptographic schemes
 * like Kyber.
 *
 * @param r The result of the base multiplication and accumulation.
 * @param a The first polynomial vector.
 * @param b The second polynomial vector.
 */
#define polyvec_basemul_acc_montgomery KYBER_NAMESPACE(polyvec_basemul_acc_montgomery)
void polyvec_basemul_acc_montgomery(poly *r, const polyvec *a, const polyvec *b);


/**
 * @brief Reduces the coefficients of a polynomial vector.
 *
 * This function reduces the coefficients of the polynomial vector `r` by applying a modular reduction. It is
 * commonly used to ensure the coefficients are within a certain range, typically required by the Kyber scheme.
 *
 * @param r The polynomial vector whose coefficients will be reduced.
 */
#define polyvec_reduce KYBER_NAMESPACE(polyvec_reduce)
void polyvec_reduce(polyvec *r);



/**
 * @brief Adds two polynomial vectors.
 *
 * This function adds the polynomial vectors `a` and `b`, storing the result in the polynomial vector `r`.
 *
 * @param r The resulting polynomial vector after addition.
 * @param a The first polynomial vector.
 * @param b The second polynomial vector.
 */
#define polyvec_add KYBER_NAMESPACE(polyvec_add)
void polyvec_add(polyvec *r, const polyvec *a, const polyvec *b);

#endif

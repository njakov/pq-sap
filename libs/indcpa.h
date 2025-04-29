#ifndef INDCPA_H
#define INDCPA_H

#include <stdint.h>
#include "params.h"
#include "polyvec.h"


/**
 * @brief Generate the matrix A or A^T - USED.
 *
 * @param a Output matrix A (or A^T).
 * @param seed The seed to generate the matrix.
 * @param transposed Boolean flag to decide whether A or A^T is generated.
 */
#define gen_matrix KYBER_NAMESPACE(gen_matrix)
void gen_matrix(polyvec *a, const uint8_t seed[KYBER_SYMBYTES], int transposed);

#define indcpa_keypair_derand KYBER_NAMESPACE(indcpa_keypair_derand)
void indcpa_keypair_derand(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                           uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES],
                           const uint8_t coins[KYBER_SYMBYTES]);

#define indcpa_enc KYBER_NAMESPACE(indcpa_enc)
void indcpa_enc(uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                const uint8_t coins[KYBER_SYMBYTES]);

#define indcpa_dec KYBER_NAMESPACE(indcpa_dec)
void indcpa_dec(uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES]);


/**
 * @brief De-serialize public key from a byte array; approximate inverse of pack_pk. - USED
* @param pk Pointer to output public-key polynomial vector.
 * @param seed Pointer to output seed to generate matrix A.
 * @param packedpk Pointer to the input serialized public key.
 */
#define unpack_pk KYBER_NAMESPACE(unpack_pk)
void unpack_pk(polyvec *pk,
                      uint8_t seed[KYBER_SYMBYTES],
                      const uint8_t packedpk[KYBER_INDCPA_PUBLICKEYBYTES]);

#endif

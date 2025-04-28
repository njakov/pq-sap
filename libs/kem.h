/**
 * @file kem.h
 * @brief Declarations of functions for the Key Encapsulation Mechanism (KEM).
 *
 * The implementation of all functions is located in .so files (shared object dynamic libraries).
 */
#ifndef KEM_H
#define KEM_H

#include <stdint.h>
#include "params.h"

// Definitions for key sizes and other parameters
#define CRYPTO_SECRETKEYBYTES  KYBER_SECRETKEYBYTES   /**< Size of secret key */
#define CRYPTO_PUBLICKEYBYTES  KYBER_PUBLICKEYBYTES   /**< Size of public key */
#define CRYPTO_CIPHERTEXTBYTES KYBER_CIPHERTEXTBYTES  /**< Size of ciphertext */
#define CRYPTO_BYTES           KYBER_SSBYTES          /**< Size of shared secret */

/**
 * @brief Defines the algorithm name based on the KYBER_K parameter.
 *
 * Sets the algorithm name depending on the value of `KYBER_K`.
 * `KYBER_K` can be 2, 3, or 4, representing different variants of the Kyber algorithm:
 * Kyber512, Kyber768, or Kyber1024.
 */
#if   (KYBER_K == 2)
#define CRYPTO_ALGNAME "Kyber512"
#elif (KYBER_K == 3)
#define CRYPTO_ALGNAME "Kyber768"
#elif (KYBER_K == 4)
#define CRYPTO_ALGNAME "Kyber1024"
#endif

 // Function declarations for KEM (Key Encapsulation Mechanism)

 /**
  * @brief Generates a public and secret key with additional random data.
  *
  * This function generates a public and secret key for the Kyber KEM (Key Encapsulation Mechanism)
  * using additional random data.
  *
  * @param pk Pointer to an array where the public key will be stored.
  * @param sk Pointer to an array where the secret key will be stored.
  * @param coins Pointer to an array of random data used for key generation.
  *
  * @return 0 if the function is executed successfully, or a non-zero value if an error occurs.
  */
#define crypto_kem_keypair_derand KYBER_NAMESPACE(keypair_derand)
int crypto_kem_keypair_derand(uint8_t* pk, uint8_t* sk, const uint8_t* coins); // Function definition to follow

/**
 * @brief Generates a public and secret key for Kyber KEM.
 *
 * This function generates a public and secret key for the Kyber KEM without additional random data.
 *
 * @param pk Pointer to an array where the public key will be stored.
 * @param sk Pointer to an array where the secret key will be stored.
 *
 * @return 0 if the function is executed successfully, or a non-zero value if an error occurs.
 */
#define crypto_kem_keypair KYBER_NAMESPACE(keypair)
int crypto_kem_keypair(uint8_t* pk, uint8_t* sk); // Function definition to follow

/**
 * @brief Encrypts data using the public key and generates a shared secret.
 *
 * This function uses the public key to encrypt the message and generates the ciphertext
 * along with the shared secret.
 *
 * @param ct Pointer to an array where the ciphertext will be stored.
 * @param ss Pointer to the shared secret that will be generated during encryption.
 * @param pk Pointer to the public key used for encryption.
 *
 * @return 0 if the function is executed successfully, or a non-zero value if an error occurs.
 */
#define crypto_kem_enc_derand KYBER_NAMESPACE(enc_derand)
int crypto_kem_enc_derand(uint8_t* ct, uint8_t* ss, const uint8_t* pk, const uint8_t* coins); // Function definition to follow

/**
 * @brief Encrypts data using the public key.
 *
 * This function uses the public key to encrypt the data and generates the ciphertext
 * along with the shared secret.
 *
 * @param ct Pointer to an array where the ciphertext will be stored.
 * @param ss Pointer to the shared secret that will be generated during encryption.
 * @param pk Pointer to the public key used for encryption.
 *
 * @return 0 if the function is executed successfully, or a non-zero value if an error occurs.
 */
#define crypto_kem_enc KYBER_NAMESPACE(enc)
int crypto_kem_enc(uint8_t* ct, uint8_t* ss, const uint8_t* pk); // Function definition to follow

/**
 * @brief Decrypts the ciphertext using the secret key and generates the shared secret.
 *
 * This function decrypts the ciphertext using the secret key and generates the shared secret.
 *
 * @param ss Pointer to the shared secret that will be generated during decryption.
 * @param ct Pointer to the ciphertext that will be decrypted.
 * @param sk Pointer to the secret key used for decryption.
 *
 * @return 0 if the function is executed successfully, or a non-zero value if an error occurs.
 */
#define crypto_kem_dec KYBER_NAMESPACE(dec)
int crypto_kem_dec(uint8_t* ss, const uint8_t* ct, const uint8_t* sk); // Function definition to follow

#endif  // KEM_H


/**
 * @file kem.h
 * @brief Header file for Kyber Key Encapsulation Mechanism (KEM) implementation.
 *
 * This file provides the interface for the Kyber KEM (Key Encapsulation Mechanism),
 * which is a post-quantum cryptographic algorithm used for key exchange. It includes
 * definitions for key sizes, encryption and decryption functions, and shared secret
 * generation based on the Kyber algorithm variant selected (Kyber512, Kyber768, or Kyber1024).
 *
 * The functions in this file include:
 * - Key pair generation (both random and deterministic)
 * - Encryption and decryption of data using the Kyber public and secret keys
 * - Generation of shared secrets during encryption and decryption processes
 *
 * The algorithm used is based on the Kyber post-quantum cryptosystem, which relies
 * on lattice-based cryptography. This header file is designed to work with a specific
 * implementation of the Kyber algorithm with different parameter sets, as defined
 * by the KYBER_K constant.
 *
 * @note This file requires the inclusion of "params.h" for the configuration of Kyber parameters.
 */

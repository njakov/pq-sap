#ifndef PARAMS_H
#define PARAMS_H

#ifndef KYBER_K
#define KYBER_K 3	/* Change this for different security strengths */
#endif

//#define KYBER_90S	/* Uncomment this if you want the 90S variant */

/* Don't change parameters below this line */

/**
 * @brief Namespace definition based on the value of KYBER_K and KYBER_90S.
 *
 * Depending on the value of KYBER_K (2, 3, or 4) and whether KYBER_90S is defined,
 * this macro creates a namespace prefix used for naming functions and variables.
 * This ensures that the correct version of the Kyber algorithm (with different security levels)
 * is used during compilation.
 */
#if   (KYBER_K == 2)
#ifdef KYBER_90S
#define KYBER_NAMESPACE(s) pqcrystals_kyber512_90s_avx2_##s
#else
#define KYBER_NAMESPACE(s) pqcrystals_kyber512_avx2_##s
#endif
#elif (KYBER_K == 3)
#ifdef KYBER_90S
#define KYBER_NAMESPACE(s) pqcrystals_kyber768_90s_avx2_##s
#else
#define KYBER_NAMESPACE(s) pqcrystals_kyber768_avx2_##s
#endif
#elif (KYBER_K == 4)
#ifdef KYBER_90S
#define KYBER_NAMESPACE(s) pqcrystals_kyber1024_90s_avx2_##s
#else
#define KYBER_NAMESPACE(s) pqcrystals_kyber1024_avx2_##s
#endif
#else
#error "KYBER_K must be in {2,3,4}"
#endif

 /**
  * @brief The value of N for Kyber algorithm.
  *
  * Defines the size of the underlying ring in the Kyber cryptographic scheme.
  * This value is used for the number of elements in the polynomials.
  * Typically, it is fixed at 256 for all Kyber variants.
  */
#define KYBER_N 256

  /**
   * @brief The modulus Q for Kyber algorithm.
   *
   * This constant defines the modulus used in the Kyber cryptographic scheme.
   * Kyber uses a polynomial ring over the finite field Z/QZ, where Q is 3329.
   */
#define KYBER_Q 3329

   /**
	* @brief The size in bytes for hashes and seeds used in the Kyber algorithm.
	*
	* Defines the length of hash values and seeds in the Kyber algorithm.
	* It is typically set to 32 bytes for security reasons.
	*/
#define KYBER_SYMBYTES 32   /* size in bytes of hashes, and seeds */

	/**
	 * @brief The size in bytes of the shared key in the Kyber algorithm.
	 *
	 * This is the size in bytes of the shared secret key generated during the encryption and decryption process.
	 */
#define KYBER_SSBYTES  32   /* size in bytes of shared key */

	 /**
	  * @brief The size in bytes of a single polynomial in the Kyber algorithm.
	  *
	  * Defines the size in bytes for a polynomial used in Kyber encryption and decryption.
	  * It is based on the N value, which is typically 256.
	  */
#define KYBER_POLYBYTES		384

	  /**
	   * @brief The size in bytes of a vector of polynomials.
	   *
	   * This defines the size of a vector containing `KYBER_K` polynomials.
	   * This value changes depending on the Kyber variant (KYBER_K).
	   */
#define KYBER_POLYVECBYTES	(KYBER_K * KYBER_POLYBYTES)

	   /**
		* @brief The value of eta1 based on the security level (KYBER_K).
		*
		* This constant controls the noise parameter in Kyber. It varies based on the security strength,
		* with different values for KYBER_K = 2, 3, or 4.
		*/
#if KYBER_K == 2
#define KYBER_ETA1 3
#define KYBER_POLYCOMPRESSEDBYTES    128
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 320)
#elif KYBER_K == 3
#define KYBER_ETA1 2
#define KYBER_POLYCOMPRESSEDBYTES    128
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 320)
#elif KYBER_K == 4
#define KYBER_ETA1 2
#define KYBER_POLYCOMPRESSEDBYTES    160
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 352)
#endif

		/**
		 * @brief The value of eta2 for the Kyber algorithm.
		 *
		 * Defines the noise parameter `eta2`, which is constant across all Kyber versions.
		 */
#define KYBER_ETA2 2

		 /**
		  * @brief The number of bytes used for the message in the Kyber IND-CPA (Indistinguishability under Chosen-Plaintext Attack) scheme.
		  *
		  * This defines the number of bytes used for the message during the encryption process.
		  */
#define KYBER_INDCPA_MSGBYTES       (KYBER_SYMBYTES)

		  /**
		   * @brief The number of bytes used for the public key in the Kyber IND-CPA scheme.
		   *
		   * This defines the size of the public key in the Kyber IND-CPA scheme.
		   * It includes the vector of polynomials and the hash of the public key.
		   */
#define KYBER_INDCPA_PUBLICKEYBYTES (KYBER_POLYVECBYTES + KYBER_SYMBYTES)

		   /**
			* @brief The number of bytes used for the secret key in the Kyber IND-CPA scheme.
			*
			* This defines the size of the secret key in the Kyber IND-CPA scheme.
			* It includes the vector of polynomials used for decryption.
			*/
#define KYBER_INDCPA_SECRETKEYBYTES (KYBER_POLYVECBYTES)

			/**
			 * @brief The number of bytes used for the ciphertext in the Kyber IND-CPA scheme.
			 *
			 * This defines the size of the ciphertext in the Kyber IND-CPA scheme.
			 * It is a compressed representation of the polynomial vectors.
			 */
#define KYBER_INDCPA_BYTES          (KYBER_POLYVECCOMPRESSEDBYTES + KYBER_POLYCOMPRESSEDBYTES)

			 /**
			  * @brief The number of bytes used for the public key in the Kyber scheme.
			  *
			  * This defines the size of the public key in the Kyber cryptosystem,
			  * including both the IND-CPA public key and the hash of the public key.
			  */
#define KYBER_PUBLICKEYBYTES  (KYBER_INDCPA_PUBLICKEYBYTES)

			  /**
			   * @brief The number of bytes used for the secret key in the Kyber scheme.
			   *
			   * This defines the size of the secret key in the Kyber cryptosystem.
			   * It includes the IND-CPA secret key, the public key, and additional data.
			   */
#define KYBER_SECRETKEYBYTES  (KYBER_INDCPA_SECRETKEYBYTES + KYBER_INDCPA_PUBLICKEYBYTES + 2*KYBER_SYMBYTES)

			   /**
				* @brief The number of bytes used for the ciphertext in the Kyber scheme.
				*
				* This defines the size of the ciphertext in the Kyber cryptosystem.
				* It is composed of the IND-CPA ciphertext along with the necessary metadata.
				*/
#define KYBER_CIPHERTEXTBYTES (KYBER_INDCPA_BYTES)

#endif  // PARAMS_H

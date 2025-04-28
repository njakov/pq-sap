#include "kem.h"
#include <stdint.h>
#include <stdio.h>



/**
 * @brief Main function that runs the Kyber Key Encapsulation Mechanism (KEM)
 * and demonstrates key generation, encapsulation, and decapsulation.
 *
 * This function orchestrates the entire process of Kyber's Key Encapsulation Mechanism (KEM),
 * starting from the generation of key pairs, followed by the encapsulation and decapsulation
 * of shared secrets. The main purpose of this test is to verify the correctness of the Kyber
 * encryption and decryption cycle.
 *
 * The following variables are used in this function:
 * - pk[#KYBER_PUBLICKEYBYTES]: Public key used for encryption and encapsulation.
 * - sk[#KYBER_SECRETKEYBYTES]: Secret key used for decryption and decapsulation.
 * - ct[#KYBER_CIPHERTEXTBYTES]: Ciphertext, the encrypted version of the shared secret.
 * - ss1[#KYBER_SSBYTES]: Shared secret from encapsulation.
 * - ss2[#KYBER_SSBYTES]: Shared secret from decapsulation.
 *
 * The main function performs the following steps:
 * 1. It generates a public and secret key pair using the Kyber KEM key generation function ( crypto_kem_keypair(pk, sk) )
 * 2. It encapsulates a shared secret using the public key to create a ciphertext and a shared secret ( crypto_kem_enc(ct, ss1, pk) ).
 * 3. It decapsulates the ciphertext using the secret key to recover the shared secret ( crypto_kem_dec(ss2, ct, sk) ).
 * 4. It compares the encapsulated and decapsulated shared secrets to ensure they match.
 * 5. It prints the number of bytes required for the ciphertext in the Kyber scheme.
 * 6. It prints the result of the test, whether it passed or failed based on the shared secret comparison.
 * This function outputs:
 * - The public and secret keys in hexadecimal format.
 * - The ciphertext and the two shared secrets (one from encapsulation and one from decapsulation).
 * - A message indicating whether the test passed or failed.
 *
 * @return 0 if the test passes, indicating successful execution; otherwise, it returns early on failure.
 */




int main() {
    uint8_t pk[KYBER_PUBLICKEYBYTES];  // Public key
    uint8_t sk[KYBER_SECRETKEYBYTES];  // Secret key
    uint8_t ct[KYBER_CIPHERTEXTBYTES]; // Ciphertext
    uint8_t ss1[KYBER_SSBYTES];          // Shared secret from encapsulation
    uint8_t ss2[KYBER_SSBYTES];          // Shared secret from decapsulation

    printf("Kem Enc-Dec: ");

    // 1. Generate key pair
    crypto_kem_keypair(pk, sk);

    // 2. Encapsulate (create ciphertext and shared secret)
    crypto_kem_enc(ct, ss1, pk);

    // 3. Decapsulate (recover shared secret)
    crypto_kem_dec(ss2, ct, sk);

    // 4. Verify both shared secrets match
    for (size_t i = 0; i < KYBER_SSBYTES; i++) {
        if(ss1[i] != ss2[i]){
            printf("Test FAILED!\n");
            return 0;
        }
    }
    printf("Test PASSED!\n");
    return 0;
}
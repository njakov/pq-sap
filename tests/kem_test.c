#include "kem.h"
#include <stdint.h>
#include <stdio.h>

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
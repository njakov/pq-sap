#include "kem.h"
#include <stdint.h>
#include <stdio.h>

// Helper function to print bytes in hex
void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}



int main() {
    uint8_t pk[KYBER_PUBLICKEYBYTES];  // Public key
    uint8_t sk[KYBER_SECRETKEYBYTES];  // Secret key
    uint8_t ct[KYBER_CIPHERTEXTBYTES]; // Ciphertext
    uint8_t ss1[KYBER_SSBYTES];          // Shared secret from encapsulation
    uint8_t ss2[KYBER_SSBYTES];          // Shared secret from decapsulation

    printf("Hello Kyber!\n");

    // 1. Generate key pair
    crypto_kem_keypair(pk, sk);

    print_hex("Public Key", pk, KYBER_PUBLICKEYBYTES);
    print_hex("Secret Key", sk, KYBER_SECRETKEYBYTES);

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

    printf("\nNUMBER OF BYTES: %d\n", KYBER_CIPHERTEXTBYTES);
    printf("Test PASSED!\n");
    return 0;
}
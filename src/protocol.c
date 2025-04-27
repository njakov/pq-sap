#include "protocol_api.h"

#define STEALTH_ADDRESS_BYTES (KYBER_K * KYBER_POLYBYTES)

 // For SHA-256 hash function



// Recipient computes stealth public key
void recipient_computes_stealth_pub_key(uint8_t stealth_pub_key[STEALTH_ADDRESS_BYTES],
                                      const uint8_t k_pub[PUBLIC_KEY_BYTES],
                                      const uint8_t ephemeral_pub_key[CIPHERTEXT_BYTES],
                                      const uint8_t v[SECRET_KEY_BYTES]) {
    // Calculate shared secret
    uint8_t ss[SS_BYTES];
    crypto_kem_dec(ss, ephemeral_pub_key, v);

    printf("Recipient k_pub:\n");
    for (int i = 0; i < PUBLIC_KEY_BYTES; i++) printf("%02x", k_pub[i]);
    printf("\n");

    printf("Recipient shared secret:\n");
    for (int i = 0; i < SS_BYTES; i++) printf("%02x", ss[i]);
    printf("\n");

    // Calculate stealth public key
    calculate_stealth_pub_key(stealth_pub_key, ss, k_pub);
}

// Sender computes stealth public key and view tag
void sender_computes_stealth_pub_key_and_viewtag(uint8_t stealth_pub_key[STEALTH_ADDRESS_BYTES],
                                               uint8_t ephemeral_pub_key[CIPHERTEXT_BYTES],
                                               uint8_t *view_tag,
                                               const uint8_t v_pub[PUBLIC_KEY_BYTES],
                                               const uint8_t k_pub[PUBLIC_KEY_BYTES]) {
    // Validate input lengths
    if (v_pub == NULL || k_pub == NULL) {
        // Handle error
        return;
    }

    // Calculate shared secret and ciphertext
    uint8_t ss[SS_BYTES];
    crypto_kem_enc(ephemeral_pub_key, ss, v_pub);

    printf("Sender k_pub:\n");
    for (int i = 0; i < PUBLIC_KEY_BYTES; i++) printf("%02x", k_pub[i]);
    printf("\n");

    printf("Sender shared secret:\n");
    for (int i = 0; i < SS_BYTES; i++) printf("%02x", ss[i]);
    printf("\n");

    // Calculate stealth public key
    calculate_stealth_pub_key(stealth_pub_key, ss, k_pub);

    // Calculate view tag
    *view_tag = calculate_view_tag(ss);
}

// View tag calculation
uint8_t calculate_view_tag(const uint8_t ss[SS_BYTES]) {
    if (ss == NULL) {
        return 0;  // Or handle error appropriately
    }

    uint8_t hash[32]; // Example buffer
    shake128(hash, 32, ss, KYBER_SSBYTES);
    uint8_t view_tag = hash[0];

    return view_tag;  // First byte of hash
}


void calculate_stealth_pub_key(uint8_t stealth_pub_key[STEALTH_ADDRESS_BYTES], 
                             const uint8_t ss[KYBER_SYMBYTES], 
                             const uint8_t k_pub[KYBER_INDCPA_PUBLICKEYBYTES]) {
    polyvec pkpv, skpv;
    uint8_t public_seed[KYBER_SYMBYTES] = {0};
    
    // Initialize polyvecs
    polyvec pkpv_zero = {0};
    polyvec skpv_zero = {0};
    pkpv = pkpv_zero;
    skpv = skpv_zero;

    // Unpack public key
    unpack_pk(&pkpv, public_seed, k_pub);

    // Derive matrix A
    polyvec a[KYBER_K];
    for (int i = 0; i < KYBER_K; i++) {
        polyvec zero = {0};     //????
        a[i] = zero; // Initialize
    }
    gen_matrix(a, public_seed, 0); // 0 is for deterministic generation

    // Convert shared secret to polynomial (noise sampling)
    uint8_t nonce = 0;
    for (int i = 0; i < KYBER_K; i++) {
        poly_getnoise_eta1(&skpv.vec[i], ss, nonce);
        nonce++;
    }

    // Compute A*S + K
    polyvec p_poly = {0};
    for (int i = 0; i < KYBER_K; i++) {
        polyvec_basemul_acc_montgomery(&p_poly.vec[i], &a[i], &skpv);    //?????
        poly_tomont(&p_poly.vec[i]);
    }
    polyvec_add(&p_poly, &p_poly, &pkpv);
    polyvec_reduce(&p_poly);

    // Convert stealth public key from polynomial to bytes
    polyvec_tobytes(stealth_pub_key, &p_poly);
}
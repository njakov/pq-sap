#include "protocol_api.h"

#define STEALTH_ADDRESS_BYTES (KYBER_K * KYBER_POLYBYTES)

/**
 * Workflow:
 *  1. Calls crypto_kem_dec(ss, ephemeral_pub_key, v)  to derive shared secret `ss` from ephemeral public key and private key `v`.
 *  2. Prints recipient's public key and derived shared secret.
 *  3. Calls calculate_stealth_pub_key() to compute stealth public key using public key `k_pub` and shared secret `ss`. The resulting stealth public key is written into the output parameter `stealth_pub_key`.
 *
 * @param[out] stealth_pub_key Output array for the computed stealth public key.
 * @param[in] k_pub Recipient's public spending key.
 * @param[in] ephemeral_pub_key Ephemeral public key received from the sender.
 * @param[in] v Recipient's private "view" key.
 */
void recipient_computes_stealth_pub_key(uint8_t stealth_pub_key[STEALTH_ADDRESS_BYTES],
    const uint8_t k_pub[PUBLIC_KEY_BYTES],
    const uint8_t ephemeral_pub_key[CIPHERTEXT_BYTES],
    const uint8_t v[SECRET_KEY_BYTES])
{
    uint8_t ss[SS_BYTES];
    crypto_kem_dec(ss, ephemeral_pub_key, v);

    printf("Recipient k_pub:\n");
    for (int i = 0; i < PUBLIC_KEY_BYTES; i++) printf("%02x", k_pub[i]);
    printf("\n");

    printf("Recipient shared secret:\n");
    for (int i = 0; i < SS_BYTES; i++) printf("%02x", ss[i]);
    printf("\n");

    calculate_stealth_pub_key(stealth_pub_key, ss, k_pub);
}

/**
 * Workflow:
 *  1. Validates input.
 *  2. Calls crypto_kem_enc(ephemeral_pub_key, ss, v_pub) to generate shared secret `ss` and ephemeral public key.
 *  3. Prints sender's public key and derived shared secret.
 *  4. Calls calculate_stealth_pub_key() to compute stealth public key using public key `k_pub` and shared secret `ss`. The resulting stealth public key is written into the output parameter `stealth_pub_key`.
 *  5. Calls calculate_view_tag() to compute view tag from shared secret `ss`.
 *
 * @param[out] stealth_pub_key Output array for computed stealth public key.
 * @param[out] ephemeral_pub_key Output ephemeral public key (to be sent to recipient).
 * @param[out] view_tag Output computed view tag (single byte).
 * @param[in] v_pub Recipient's public "view" key.
 * @param[in] k_pub Recipient's public "spending" key.
 */
void sender_computes_stealth_pub_key_and_viewtag(uint8_t stealth_pub_key[STEALTH_ADDRESS_BYTES],
    uint8_t ephemeral_pub_key[CIPHERTEXT_BYTES],
    uint8_t* view_tag,
    const uint8_t v_pub[PUBLIC_KEY_BYTES],
    const uint8_t k_pub[PUBLIC_KEY_BYTES])
{
    if (v_pub == NULL || k_pub == NULL) {
        return;
    }

    uint8_t ss[SS_BYTES];
    crypto_kem_enc(ephemeral_pub_key, ss, v_pub);

    printf("Sender k_pub:\n");
    for (int i = 0; i < PUBLIC_KEY_BYTES; i++) printf("%02x", k_pub[i]);
    printf("\n");

    printf("Sender shared secret:\n");
    for (int i = 0; i < SS_BYTES; i++) printf("%02x", ss[i]);
    printf("\n");

    calculate_stealth_pub_key(stealth_pub_key, ss, k_pub);

    *view_tag = calculate_view_tag(ss);
}

/**
 * Workflow:
 *  1. Calls shake128(hash, 32, ss, KYBER_SSBYTES) to hash the shared secret into 32 bytes.
 *  2. Takes the first byte of the hash as the view tag.
 *
 * @param[in] ss Shared secret.
 * @return uint8_t View tag (single byte).
 */
uint8_t calculate_view_tag(const uint8_t ss[SS_BYTES])
{
    if (ss == NULL) {
        return 0;
    }

    uint8_t hash[32];
    shake128(hash, 32, ss, KYBER_SSBYTES);

    uint8_t view_tag = hash[0];
    return view_tag;
}

/**
 * Workflow:
 *  1. Initializes polyvec structures.
 *      - This step initializes the polyvec structures pkpv and skpv. These structures hold polynomial vectors, and each polynomial is essentially a vector of coefficients used in lattice-based cryptography.The public_seed is initialized to zero here, which will later be used to derive the public key.
 *  2. Unpacks recipient's public key using unpack_pk(&pkpv, public_seed, k_pub) .The unpacked public key is stored in `pkpv`.
 *  3. Derives matrix A deterministically using gen_matrix(a, public_seed, 0) .
 *      - The gen_matrix() function fills in the matrix a with polynomials where the coefficients are derived from a cryptographic randomness function xof_squeezeblocks()
 *  4. Converts shared secret into a noise sampled secret key vector `skpv` using  poly_getnoise_eta1() .
 *  5. Computes A * S + K polynomial vector:
 *      - Calls polyvec_basemul_acc_montgomery() and poly_tomont() for each element.
 *  6. Adds original public key polynomial and reduces ( polyvec_add(&p_poly, &p_poly, &pkpv)  polyvec_reduce(&p_poly) ).
 *  7. Converts resulting polynomial vector into byte array using polyvec_tobytes(stealth_pub_key, &p_poly).
 *
 * @param[out] stealth_pub_key Output array for stealth public key.
 * @param[in] ss Shared secret.
 * @param[in] k_pub Recipient's public spending key.
 */
void calculate_stealth_pub_key(uint8_t stealth_pub_key[STEALTH_ADDRESS_BYTES],
    const uint8_t ss[KYBER_SYMBYTES],
    const uint8_t k_pub[KYBER_INDCPA_PUBLICKEYBYTES])
{
    polyvec pkpv, skpv;
    uint8_t public_seed[KYBER_SYMBYTES] = { 0 };

    polyvec pkpv_zero = { 0 };
    polyvec skpv_zero = { 0 };
    pkpv = pkpv_zero;
    skpv = skpv_zero;

    unpack_pk(&pkpv, public_seed, k_pub);

    polyvec a[KYBER_K];
    for (int i = 0; i < KYBER_K; i++) {
        polyvec zero = { 0 };
        a[i] = zero;
    }
    gen_matrix(a, public_seed, 0);

    uint8_t nonce = 0;
    for (int i = 0; i < KYBER_K; i++) {
        poly_getnoise_eta1(&skpv.vec[i], ss, nonce);
        nonce++;
    }

    polyvec p_poly = { 0 };
    for (int i = 0; i < KYBER_K; i++) {
        polyvec_basemul_acc_montgomery(&p_poly.vec[i], &a[i], &skpv);
        poly_tomont(&p_poly.vec[i]);
    }

    polyvec_add(&p_poly, &p_poly, &pkpv);
    polyvec_reduce(&p_poly);

    polyvec_tobytes(stealth_pub_key, &p_poly);
}


uint8_t* calculate_ss_hash(const uint8_t ss[SS_BYTES])
{
    if (ss == NULL) {
        return 0;
    }

    uint8_t* hash = malloc(32*sizeof(uint8_t));
    shake128(hash, 32, ss, KYBER_SSBYTES);

    return hash;
}
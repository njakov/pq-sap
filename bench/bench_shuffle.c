#include "protocol_api.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#define M_TRIALS 10

__uint128_t calculate_elapsed_time(struct timespec start, struct timespec end) {
    // Convert to nanoseconds
    __uint128_t start_ns = (__uint128_t)start.tv_sec * 1000000000 + start.tv_nsec;
    __uint128_t end_ns = (__uint128_t)end.tv_sec * 1000000000 + end.tv_nsec;
    return end_ns - start_ns;
}

void print_time(__uint128_t time_ns) {
    double time_ms = (double)time_ns / 1e6;
    printf("Elapsed time: %.3f milliseconds\n", time_ms);
}


void shuffle_registers(uint8_t** epkr, uint8_t** view_tags, int n) {

    for (int i = 0; i < n - 1; i++) {

        int j = i + rand() % (n - i);
        
        uint8_t* temp = epkr[j];
        epkr[j] = epkr[i];
        epkr[i] = temp;

        temp = view_tags[j];
        view_tags[j] = view_tags[i];
        view_tags[i] = temp;
    }

}


void run(int n, int m) {
    struct timespec start, end;
    __uint128_t total_ns = 0;

    for (int trial = 0; trial < m; ++trial) {
        // Receiver keypair
        uint8_t k_pub[CRYPTO_PUBLICKEYBYTES];
        uint8_t k_priv[CRYPTO_SECRETKEYBYTES];
        crypto_kem_keypair(k_pub, k_priv);

        uint8_t v_pub[CRYPTO_PUBLICKEYBYTES];
        uint8_t v_priv[CRYPTO_SECRETKEYBYTES];
        crypto_kem_keypair(v_pub, v_priv);

        uint8_t** ephemeral_pub_key_reg = malloc(n * sizeof(uint8_t*));
        // uint8_t* view_tags = malloc(n * sizeof(uint8_t));
        // uint8_t* view_tags = malloc(n * 32 * sizeof(uint8_t));
        uint8_t** view_tags = malloc(n * sizeof(uint8_t*));
        for (int i = 0; i < n; ++i) {
            ephemeral_pub_key_reg[i] = malloc(CRYPTO_CIPHERTEXTBYTES);
        }

        for (int i = 0; i < n-1; ++i) {
            uint8_t temp_pub[CRYPTO_PUBLICKEYBYTES];
            uint8_t temp_priv[CRYPTO_SECRETKEYBYTES];
            crypto_kem_keypair(temp_pub, temp_priv);

            uint8_t ss[CRYPTO_BYTES];
            crypto_kem_enc(ephemeral_pub_key_reg[i], ss, temp_pub);

            // view_tags[i] = calculate_view_tag(ss);
            // shake128(view_tags+32*i, 32, ss, KYBER_SSBYTES);
            view_tags[i] = calculate_ss_hash(ss);
        }

        uint8_t ss_sender[CRYPTO_BYTES];
        crypto_kem_enc(ephemeral_pub_key_reg[n-1], ss_sender, v_pub);
        // view_tags[n-1] = calculate_view_tag(ss_sender);
        // shake128(view_tags+32*(n-1), 32, ss_sender, KYBER_SSBYTES);
        view_tags[n-1] = calculate_ss_hash(ss_sender);

        shuffle_registers(ephemeral_pub_key_reg, view_tags, n);

        clock_gettime(CLOCK_REALTIME, &start);

        for (int i = 0; i < n; ++i) {
            uint8_t ss[CRYPTO_BYTES];
            uint8_t stealth_pub_key[STEALTH_ADDRESS_BYTES];

            crypto_kem_dec(ss, ephemeral_pub_key_reg[i], v_priv);
            // uint8_t tag = calculate_view_tag(ss);
            uint8_t* tag = calculate_ss_hash(ss);

            // if (tag == view_tags[i]) {
            //     calculate_stealth_pub_key(stealth_pub_key, ss, k_pub);
            // }
            int equal=1;
            for(int j=0; j<32; j++){
                if(tag[j] != view_tags[i][j])equal=0;
            }
            if(equal){
                calculate_stealth_pub_key(stealth_pub_key, ss, k_pub);
                break;
            }

        }

        clock_gettime(CLOCK_REALTIME, &end);
        __uint128_t elapsed_ns = calculate_elapsed_time(start, end);
        total_ns += elapsed_ns;

        for (int i = 0; i < n; ++i) {
            free(ephemeral_pub_key_reg[i]);
            free(view_tags[i]);
        }
        free(ephemeral_pub_key_reg);
        free(view_tags);
    }

    double avg_ms = (double)total_ns / m / 1e6;
    printf(" N = %d, Avg time = %.3f ms\n", n, avg_ms);
}

int main() {
    int ns[] = {5000, 10000, 20000, 40000, 80000};
    int len = sizeof(ns) / sizeof(ns[0]);

    for (int i = 0; i < len; ++i) {
        run(ns[i], M_TRIALS);
    }
    
    /*  N = 5000, Avg time = 72.737 ms
        N = 10000, Avg time = 134.340 ms
        N = 20000, Avg time = 246.183 ms
        N = 40000, Avg time = 530.417 ms
        N = 80000, Avg time = 1391.601 ms
    */

    return 0;
}

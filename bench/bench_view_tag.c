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


void run(int n, int m, int shuffle) {
    struct timespec start, end;
    __uint128_t total_ns_1 = 0,
                total_ns_2 = 0,
                total_ns_3 = 0;

    for (int trial = 0; trial < m; ++trial) {
        // Receiver keypair
        uint8_t k_pub[CRYPTO_PUBLICKEYBYTES];
        uint8_t k_priv[CRYPTO_SECRETKEYBYTES];
        crypto_kem_keypair(k_pub, k_priv);

        uint8_t v_pub[CRYPTO_PUBLICKEYBYTES];
        uint8_t v_priv[CRYPTO_SECRETKEYBYTES];
        crypto_kem_keypair(v_pub, v_priv);

        uint8_t** ephemeral_pub_key_reg = malloc(n * sizeof(uint8_t*));
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

            view_tags[i] = calculate_ss_hash(ss);
        }

        uint8_t ss_sender[CRYPTO_BYTES];
        crypto_kem_enc(ephemeral_pub_key_reg[n-1], ss_sender, v_pub);
        view_tags[n-1] = calculate_ss_hash(ss_sender);

        if(shuffle) shuffle_registers(ephemeral_pub_key_reg, view_tags, n);

        __uint128_t elapsed_ns;

        //using no view tag
        clock_gettime(CLOCK_REALTIME, &start);
        for (int i = 0; i < n; ++i) {
            uint8_t ss[CRYPTO_BYTES];
            uint8_t stealth_pub_key[STEALTH_ADDRESS_BYTES];

            crypto_kem_dec(ss, ephemeral_pub_key_reg[i], v_priv);
            calculate_stealth_pub_key(stealth_pub_key, ss, k_pub);
        }
        clock_gettime(CLOCK_REALTIME, &end);
        elapsed_ns = calculate_elapsed_time(start, end);
        total_ns_1 += elapsed_ns;

        //using 1B of hash view tag
        clock_gettime(CLOCK_REALTIME, &start);
        for (int i = 0; i < n; ++i) {
            uint8_t ss[CRYPTO_BYTES];
            uint8_t stealth_pub_key[STEALTH_ADDRESS_BYTES];

            crypto_kem_dec(ss, ephemeral_pub_key_reg[i], v_priv);
            uint8_t tag = calculate_view_tag(ss);

            if(view_tags[i][0] == tag)
                calculate_stealth_pub_key(stealth_pub_key, ss, k_pub);
        }
        clock_gettime(CLOCK_REALTIME, &end);
        elapsed_ns = calculate_elapsed_time(start, end);
        total_ns_2 += elapsed_ns;

        //using whole hash view tag
        clock_gettime(CLOCK_REALTIME, &start);
        for (int i = 0; i < n; ++i) {
            uint8_t ss[CRYPTO_BYTES];
            uint8_t stealth_pub_key[STEALTH_ADDRESS_BYTES];

            crypto_kem_dec(ss, ephemeral_pub_key_reg[i], v_priv);
            uint8_t* tag = calculate_ss_hash(ss);

            int equal=1;
            for(int j=0; j<32; j++){ if(tag[j] != view_tags[i][j]) equal=0; }
            if(equal){ calculate_stealth_pub_key(stealth_pub_key, ss, k_pub); break; }
        }
        clock_gettime(CLOCK_REALTIME, &end);
        elapsed_ns = calculate_elapsed_time(start, end);
        total_ns_3 += elapsed_ns;

        for (int i = 0; i < n; ++i) {
            free(ephemeral_pub_key_reg[i]);
            free(view_tags[i]);
        }
        free(ephemeral_pub_key_reg);
        free(view_tags);
    }

    double avg_ms_1 = (double)total_ns_1 / m / 1e6;
    double avg_ms_2 = (double)total_ns_2 / m / 1e6;
    double avg_ms_3 = (double)total_ns_3 / m / 1e6;
    printf("N = %5d, Avg time (No WT|1B WT|Full WT) = %8.3fms | %8.3fms | %8.3fms\n",
                                                     n, avg_ms_1,avg_ms_2,avg_ms_3);
}

int main() {
    int ns[] = {5000, 10000, 20000, 40000, 80000};
    int len = sizeof(ns) / sizeof(ns[0]);
    int shuffle = 0;

    for (int i = 0; i < len; ++i) {
        run(ns[i], M_TRIALS, shuffle);
    }
    
    /*  N =  5000, Avg time (No WT|1B WT|Full WT) =   67.174ms |   43.454ms |   44.289ms
        N = 10000, Avg time (No WT|1B WT|Full WT) =  135.695ms |   88.034ms |   88.525ms
        N = 20000, Avg time (No WT|1B WT|Full WT) =  274.977ms |  179.547ms |  178.979ms
        N = 40000, Avg time (No WT|1B WT|Full WT) =  545.585ms |  352.256ms |  355.304ms
        N = 80000, Avg time (No WT|1B WT|Full WT) = 1104.643ms |  707.253ms |  719.648ms
    */

    return 0;
}

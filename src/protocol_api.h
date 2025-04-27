#pragma once

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include "indcpa.h"
#include "kem.h"
#include "fips202.h"
#include "fips202x4.h"


#define PUBLIC_KEY_BYTES KYBER_PUBLICKEYBYTES
#define CIPHERTEXT_BYTES KYBER_CIPHERTEXTBYTES
#define SECRET_KEY_BYTES KYBER_SECRETKEYBYTES
#define STEALTH_ADDRESS_BYTES (KYBER_K * KYBER_POLYBYTES)
#define SS_BYTES KYBER_SSBYTES

//This header contains functions called both by recipient and sender to complete neccesary operations in MLWE PQ SAP 



// int recipient_calculates_keys()



//Description: Calculates the public key of the stealth address
//Arguments: 
//      ss    -> Shared secret
//      k_pub -> Recipient's public spending key

void calculate_stealth_pub_key(uint8_t stealth_pub_key[STEALTH_ADDRESS_BYTES], 
                             const uint8_t ss[KYBER_SYMBYTES], 
                             const uint8_t k_pub[KYBER_INDCPA_PUBLICKEYBYTES]);


                             
void recipient_computes_stealth_pub_key(uint8_t stealth_pub_key[STEALTH_ADDRESS_BYTES],
                                      const uint8_t k_pub[PUBLIC_KEY_BYTES],
                                      const uint8_t ephemeral_pub_key[CIPHERTEXT_BYTES],
                                      const uint8_t v[SECRET_KEY_BYTES]);


void sender_computes_stealth_pub_key_and_viewtag(uint8_t stealth_pub_key[STEALTH_ADDRESS_BYTES],
                                               uint8_t ephemeral_pub_key[CIPHERTEXT_BYTES],
                                               uint8_t *view_tag,
                                               const uint8_t v_pub[PUBLIC_KEY_BYTES],
                                               const uint8_t k_pub[PUBLIC_KEY_BYTES]);


uint8_t calculate_view_tag(const uint8_t ss[SS_BYTES]);



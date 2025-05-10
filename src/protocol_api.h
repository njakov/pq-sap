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

/// @file protocol_api.h
/// @brief Header file containing functions and constants for SAP protocol operations (MLWE PQ SAP).
///
/// This file provides the function declarations and macro definitions needed
/// for both sender and recipient to complete stealth address generation and key exchanges
/// according to the SAP protocol based on Kyber primitives.

/// @def PUBLIC_KEY_BYTES
/// @brief Number of bytes in a public key.
#define PUBLIC_KEY_BYTES KYBER_PUBLICKEYBYTES

/// @def CIPHERTEXT_BYTES
/// @brief Number of bytes in a ciphertext.
#define CIPHERTEXT_BYTES KYBER_CIPHERTEXTBYTES

/// @def SECRET_KEY_BYTES
/// @brief Number of bytes in a secret key.
#define SECRET_KEY_BYTES KYBER_SECRETKEYBYTES

/// @def STEALTH_ADDRESS_BYTES
/// @brief Number of bytes in a stealth address.
#define STEALTH_ADDRESS_BYTES (KYBER_K * KYBER_POLYBYTES)

/// @def SS_BYTES
/// @brief Number of bytes in a shared secret.
#define SS_BYTES KYBER_SSBYTES

/// @brief Calculates the public key of the stealth address.
///
/// @param[out] stealth_pub_key Array where the computed stealth public key will be stored (STEALTH_ADDRESS_BYTES).
/// @param[in] ss Shared secret derived from key exchange.
/// @param[in] k_pub Recipient's public spending key (KYBER_INDCPA_PUBLICKEYBYTES).
void calculate_stealth_pub_key(uint8_t stealth_pub_key[STEALTH_ADDRESS_BYTES],
    const uint8_t ss[KYBER_SYMBYTES],
    const uint8_t k_pub[KYBER_INDCPA_PUBLICKEYBYTES]);

/// @brief Computes the stealth public key by the recipient.
///
/// The recipient uses their secret view key and the sender's ephemeral public key to compute the stealth address.
///
/// @param[out] stealth_pub_key Array where the computed stealth public key will be stored.
/// @param[in] k_pub Sender's public key.
/// @param[in] ephemeral_pub_key Sender's ephemeral public key.
/// @param[in] v Recipient's secret view key.
void recipient_computes_stealth_pub_key(uint8_t stealth_pub_key[STEALTH_ADDRESS_BYTES],
    const uint8_t k_pub[PUBLIC_KEY_BYTES],
    const uint8_t ephemeral_pub_key[CIPHERTEXT_BYTES],
    const uint8_t v[SECRET_KEY_BYTES]);

/// @brief Computes the stealth public key and view tag by the sender.
///
/// The sender generates an ephemeral key pair, derives a shared secret, 
/// computes the stealth address, and extracts a view tag.
///
/// @param[out] stealth_pub_key Array where the computed stealth public key will be stored.
/// @param[out] ephemeral_pub_key Array where the ephemeral public key will be stored.
/// @param[out] view_tag Computed view tag.
/// @param[in] v_pub Recipient's public view key.
/// @param[in] k_pub Sender's public key.
void sender_computes_stealth_pub_key_and_viewtag(uint8_t stealth_pub_key[STEALTH_ADDRESS_BYTES],
    uint8_t ephemeral_pub_key[CIPHERTEXT_BYTES],
    uint8_t* view_tag,
    const uint8_t v_pub[PUBLIC_KEY_BYTES],
    const uint8_t k_pub[PUBLIC_KEY_BYTES]);

/// @brief Calculates a view tag from a shared secret.
///
/// The view tag is used to quickly identify transactions meant for the recipient.
///
/// @param[in] ss Shared secret.
/// @return View tag as a single byte.
uint8_t calculate_view_tag(const uint8_t ss[SS_BYTES]);



uint8_t* calculate_ss_hash(const uint8_t ss[SS_BYTES]);
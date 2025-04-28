#include "protocol_api.h"
#include "stdio.h"

int main(){


    uint8_t k_pub[KYBER_PUBLICKEYBYTES];  // Public key
    uint8_t v_pub[KYBER_PUBLICKEYBYTES];  // Public key
    uint8_t k_priv[KYBER_SECRETKEYBYTES];  // Secret key
    uint8_t v_priv[KYBER_SECRETKEYBYTES];  // Secret key

    uint8_t ephemeral_pub_key[CIPHERTEXT_BYTES];
    uint8_t view_tag;
    uint8_t stealth_pub_key_sender[STEALTH_ADDRESS_BYTES];
    uint8_t stealth_pub_key_reciever[STEALTH_ADDRESS_BYTES];
    uint8_t ss[KYBER_SSBYTES];
    uint8_t ss2[KYBER_SSBYTES];


    printf("SAP Protocol: ");

    // 1. Generate key pair
    crypto_kem_keypair(k_pub, k_priv);
    crypto_kem_keypair(v_pub, v_priv);

    printf("KYBER_K: %d\n", KYBER_K);

    // crypto_kem_enc(ephemeral_pub_key, ss, v_pub);
    // crypto_kem_dec(ss2, ephemeral_pub_key, v_priv);

    // for(int i=0; i< KYBER_SSBYTES; i++){
    //     printf("%d", ss[i]);
    // }printf("\n\n");

    // for(int i=0; i< KYBER_SSBYTES; i++){
    //     printf("%d", ss2[i]);
    // }
    //2. Sender computes shared secret and view tag
    sender_computes_stealth_pub_key_and_viewtag(stealth_pub_key_sender, ephemeral_pub_key, 
                                                    &view_tag, v_pub, k_pub);

    //3. Recipient calculates stealth address public key
    recipient_computes_stealth_pub_key(stealth_pub_key_reciever,
                                      k_pub,
                                      ephemeral_pub_key,
                                      v_priv);

    for(int i=0; i<STEALTH_ADDRESS_BYTES; i++){
        if(stealth_pub_key_reciever[i]!=stealth_pub_key_sender[i]){

            // printf("R: %d\tS: %d\n", stealth_pub_key_reciever[i], stealth_pub_key_sender[i]);
            printf("Test FAILED!\n");
            return 0;
        }
    }
    printf("Test PASSED!\n");
}


        // let (k_pub, _) = key_pair(); 
        // let (v_pub, v_priv) = key_pair(); 
        

        // let (stealth_pub_key_sender, ephemeral_pub_key, _) = sender_computes_stealth_pub_key_and_viewtag(&v_pub, &k_pub);

        // let stealh_pub_key_recipient = recipient_computes_stealth_pub_key(&k_pub, &ephemeral_pub_key, &v_priv);  

        // assert_eq!(stealh_pub_key_recipient, stealth_pub_key_sender);
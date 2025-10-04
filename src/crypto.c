#include "crypto.h"
#include "common.h"
#include <sodium.h>
#include <string.h>
#include <stdio.h>

int crypto_init(void) {
    if (sodium_init() < 0) {
        log_message(LOG_ERROR, "Failed to initialize libsodium");
        return -1;
    }
    log_message(LOG_INFO, "Cryptography library initialized");
    return 0;
}

int encrypt_message(const uint8_t *plaintext, size_t plaintext_len,
                   const uint8_t *recipient_pubkey,
                   const uint8_t *sender_privkey,
                   uint8_t *ciphertext, size_t *ciphertext_len) {

    if (!plaintext || !recipient_pubkey || !sender_privkey || !ciphertext || !ciphertext_len) {
        return -1;
    }

    /* crypto_box を使用した公開鍵暗号化 */
    unsigned char nonce[crypto_box_NONCEBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    /* ナンスをciphertextの先頭に格納 */
    memcpy(ciphertext, nonce, crypto_box_NONCEBYTES);

    if (crypto_box_easy(ciphertext + crypto_box_NONCEBYTES,
                       plaintext, plaintext_len,
                       nonce, recipient_pubkey, sender_privkey) != 0) {
        log_message(LOG_ERROR, "Encryption failed");
        return -1;
    }

    *ciphertext_len = crypto_box_NONCEBYTES + crypto_box_MACBYTES + plaintext_len;
    return 0;
}

int decrypt_message(const uint8_t *ciphertext, size_t ciphertext_len,
                   const uint8_t *sender_pubkey,
                   const uint8_t *recipient_privkey,
                   uint8_t *plaintext, size_t *plaintext_len) {

    if (!ciphertext || !sender_pubkey || !recipient_privkey || !plaintext || !plaintext_len) {
        return -1;
    }

    if (ciphertext_len < crypto_box_NONCEBYTES + crypto_box_MACBYTES) {
        log_message(LOG_ERROR, "Ciphertext too short");
        return -1;
    }

    /* ナンスを取得 */
    const unsigned char *nonce = ciphertext;
    const unsigned char *encrypted_msg = ciphertext + crypto_box_NONCEBYTES;
    size_t encrypted_len = ciphertext_len - crypto_box_NONCEBYTES;

    if (crypto_box_open_easy(plaintext, encrypted_msg, encrypted_len,
                            nonce, sender_pubkey, recipient_privkey) != 0) {
        log_message(LOG_ERROR, "Decryption failed");
        return -1;
    }

    *plaintext_len = encrypted_len - crypto_box_MACBYTES;
    return 0;
}

int generate_keypair(uint8_t *pubkey, uint8_t *privkey) {
    if (!pubkey || !privkey) {
        return -1;
    }

    if (crypto_box_keypair(pubkey, privkey) != 0) {
        log_message(LOG_ERROR, "Key pair generation failed");
        return -1;
    }

    log_message(LOG_INFO, "Generated new key pair");
    return 0;
}

int load_public_key(const char *key_str, uint8_t *pubkey) {
    if (!key_str || !pubkey) {
        return -1;
    }

    size_t bin_len;
    if (sodium_base642bin(pubkey, WG_KEY_LEN,
                         key_str, strlen(key_str),
                         NULL, &bin_len, NULL,
                         sodium_base64_VARIANT_ORIGINAL) != 0) {
        log_message(LOG_ERROR, "Failed to decode public key");
        return -1;
    }

    if (bin_len != WG_KEY_LEN) {
        log_message(LOG_ERROR, "Invalid public key length");
        return -1;
    }

    return 0;
}

int load_private_key(const char *key_str, uint8_t *privkey) {
    if (!key_str || !privkey) {
        return -1;
    }

    size_t bin_len;
    if (sodium_base642bin(privkey, WG_KEY_LEN,
                         key_str, strlen(key_str),
                         NULL, &bin_len, NULL,
                         sodium_base64_VARIANT_ORIGINAL) != 0) {
        log_message(LOG_ERROR, "Failed to decode private key");
        return -1;
    }

    if (bin_len != WG_KEY_LEN) {
        log_message(LOG_ERROR, "Invalid private key length");
        return -1;
    }

    return 0;
}

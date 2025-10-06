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

    size_t key_str_len = strlen(key_str);
    log_message(LOG_DEBUG, "Decoding private key: length=%zu", key_str_len);

    size_t bin_len;
    if (sodium_base642bin(privkey, WG_KEY_LEN,
                         key_str, key_str_len,
                         NULL, &bin_len, NULL,
                         sodium_base64_VARIANT_ORIGINAL) != 0) {
        log_message(LOG_ERROR, "Failed to decode private key (input length: %zu)", key_str_len);
        return -1;
    }

    if (bin_len != WG_KEY_LEN) {
        log_message(LOG_ERROR, "Invalid private key length: got %zu, expected %d", bin_len, WG_KEY_LEN);
        return -1;
    }

    return 0;
}

int pubkey_to_base64(const uint8_t *pubkey, char *output, size_t output_len) {
    if (!pubkey || !output || output_len < 45) {
        return -1;
    }

    sodium_bin2base64(output, output_len, pubkey, WG_KEY_LEN,
                     sodium_base64_VARIANT_ORIGINAL);
    return 0;
}

int privkey_to_base64(const uint8_t *privkey, char *output, size_t output_len) {
    if (!privkey || !output || output_len < 45) {
        return -1;
    }

    sodium_bin2base64(output, output_len, privkey, WG_KEY_LEN,
                     sodium_base64_VARIANT_ORIGINAL);
    return 0;
}

int save_keypair_to_file(const char *filepath, const uint8_t *pubkey, const uint8_t *privkey) {
    if (!filepath || !pubkey || !privkey) {
        return -1;
    }

    FILE *fp = fopen(filepath, "w");
    if (!fp) {
        log_message(LOG_ERROR, "Failed to open file for writing: %s", filepath);
        return -1;
    }

    char pubkey_b64[64];
    char privkey_b64[64];

    pubkey_to_base64(pubkey, pubkey_b64, sizeof(pubkey_b64));
    privkey_to_base64(privkey, privkey_b64, sizeof(privkey_b64));

    fprintf(fp, "PUBLIC_KEY=%s\n", pubkey_b64);
    fprintf(fp, "PRIVATE_KEY=%s\n", privkey_b64);

    fclose(fp);
    log_message(LOG_INFO, "Keypair saved to %s", filepath);
    return 0;
}

int load_keypair_from_file(const char *filepath, uint8_t *pubkey, uint8_t *privkey) {
    if (!filepath || !pubkey || !privkey) {
        return -1;
    }

    FILE *fp = fopen(filepath, "r");
    if (!fp) {
        log_message(LOG_WARN, "Keypair file not found: %s", filepath);
        return -1;
    }

    char line[256];
    char pubkey_b64[64] = {0};
    char privkey_b64[64] = {0};

    while (fgets(line, sizeof(line), fp)) {
        /* 改行を削除 */
        line[strcspn(line, "\r\n")] = 0;

        if (strncmp(line, "PUBLIC_KEY=", 11) == 0) {
            strncpy(pubkey_b64, line + 11, sizeof(pubkey_b64) - 1);
        } else if (strncmp(line, "PRIVATE_KEY=", 12) == 0) {
            strncpy(privkey_b64, line + 12, sizeof(privkey_b64) - 1);
        }
    }

    fclose(fp);

    if (strlen(pubkey_b64) == 0 || strlen(privkey_b64) == 0) {
        log_message(LOG_ERROR, "Invalid keypair file format");
        return -1;
    }

    if (load_public_key(pubkey_b64, pubkey) != 0) {
        return -1;
    }

    if (load_private_key(privkey_b64, privkey) != 0) {
        return -1;
    }

    log_message(LOG_INFO, "Keypair loaded from %s", filepath);
    return 0;
}

int encrypt_sealed(const uint8_t *plaintext, size_t plaintext_len,
                  const uint8_t *recipient_pubkey,
                  uint8_t *ciphertext, size_t *ciphertext_len) {
    if (!plaintext || !recipient_pubkey || !ciphertext || !ciphertext_len) {
        return -1;
    }

    if (crypto_box_seal(ciphertext, plaintext, plaintext_len, recipient_pubkey) != 0) {
        log_message(LOG_ERROR, "Sealed box encryption failed");
        return -1;
    }

    *ciphertext_len = crypto_box_SEALBYTES + plaintext_len;
    return 0;
}

int decrypt_sealed(const uint8_t *ciphertext, size_t ciphertext_len,
                  const uint8_t *recipient_pubkey,
                  const uint8_t *recipient_privkey,
                  uint8_t *plaintext, size_t *plaintext_len) {
    if (!ciphertext || !recipient_pubkey || !recipient_privkey || !plaintext || !plaintext_len) {
        return -1;
    }

    if (ciphertext_len < crypto_box_SEALBYTES) {
        log_message(LOG_ERROR, "Sealed ciphertext too short");
        return -1;
    }

    if (crypto_box_seal_open(plaintext, ciphertext, ciphertext_len,
                            recipient_pubkey, recipient_privkey) != 0) {
        log_message(LOG_ERROR, "Sealed box decryption failed");
        return -1;
    }

    *plaintext_len = ciphertext_len - crypto_box_SEALBYTES;
    return 0;
}

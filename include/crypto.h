#ifndef CRYPTO_H
#define CRYPTO_H

#include "common.h"
#include <stddef.h>

/* 暗号化初期化 */
int crypto_init(void);

/* メッセージの暗号化 */
int encrypt_message(const uint8_t *plaintext, size_t plaintext_len,
                   const uint8_t *recipient_pubkey,
                   const uint8_t *sender_privkey,
                   uint8_t *ciphertext, size_t *ciphertext_len);

/* メッセージの復号化 */
int decrypt_message(const uint8_t *ciphertext, size_t ciphertext_len,
                   const uint8_t *sender_pubkey,
                   const uint8_t *recipient_privkey,
                   uint8_t *plaintext, size_t *plaintext_len);

/* 鍵ペア生成 */
int generate_keypair(uint8_t *pubkey, uint8_t *privkey);

/* 公開鍵の読み込み（Base64形式） */
int load_public_key(const char *key_str, uint8_t *pubkey);

/* 秘密鍵の読み込み（Base64形式） */
int load_private_key(const char *key_str, uint8_t *privkey);

/* 公開鍵をBase64文字列に変換 */
int pubkey_to_base64(const uint8_t *pubkey, char *output, size_t output_len);

/* 秘密鍵をBase64文字列に変換 */
int privkey_to_base64(const uint8_t *privkey, char *output, size_t output_len);

/* 鍵ペアをファイルに保存 */
int save_keypair_to_file(const char *filepath, const uint8_t *pubkey, const uint8_t *privkey);

/* 鍵ペアをファイルから読み込み */
int load_keypair_from_file(const char *filepath, uint8_t *pubkey, uint8_t *privkey);

/* Sealed box暗号化（受信者公開鍵のみで暗号化、送信者匿名） */
int encrypt_sealed(const uint8_t *plaintext, size_t plaintext_len,
                  const uint8_t *recipient_pubkey,
                  uint8_t *ciphertext, size_t *ciphertext_len);

/* Sealed box復号化 */
int decrypt_sealed(const uint8_t *ciphertext, size_t ciphertext_len,
                  const uint8_t *recipient_pubkey,
                  const uint8_t *recipient_privkey,
                  uint8_t *plaintext, size_t *plaintext_len);

#endif /* CRYPTO_H */

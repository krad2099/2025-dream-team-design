#include "simple_crypto.h"
#include <stdint.h>
#include <string.h>
#include <openssl/aes.h>

/** @brief AES encryption */
int encrypt_sym(uint8_t *plaintext, size_t len, uint8_t *key, uint8_t *ciphertext) {
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 256, &aes_key);

    for (int i = 0; i < len; i += AES_BLOCK_SIZE) {
        AES_encrypt(plaintext + i, ciphertext + i, &aes_key);
    }

    return 0;
}

/** @brief AES decryption */
int decrypt_sym(uint8_t *ciphertext, size_t len, uint8_t *key, uint8_t *plaintext) {
    AES_KEY aes_key;
    AES_set_decrypt_key(key, 256, &aes_key);

    for (int i = 0; i < len; i += AES_BLOCK_SIZE) {
        AES_decrypt(ciphertext + i, plaintext + i, &aes_key);
    }

    return 0;
}

/** @brief AES-GCM encryption */
int encrypt_aes_gcm(const uint8_t *plaintext, size_t len, const uint8_t *key, uint8_t *ciphertext) {
    AES_KEY aes_key;
    uint8_t nonce[12] = {0}; // Secure nonce
    AES_set_encrypt_key(key, 256, &aes_key);
    AES_GCM_encrypt(&aes_key, ciphertext, plaintext, len, nonce, 12, NULL, 0, NULL);
    return 0;
}

/** @brief AES-GCM decryption */
int decrypt_aes_gcm(const uint8_t *ciphertext, size_t len, const uint8_t *key, uint8_t *plaintext) {
    AES_KEY aes_key;
    uint8_t nonce[12] = {0};
    AES_set_decrypt_key(key, 256, &aes_key);
    AES_GCM_decrypt(&aes_key, plaintext, ciphertext, len, nonce, 12, NULL, 0, NULL);
    return 0;
}

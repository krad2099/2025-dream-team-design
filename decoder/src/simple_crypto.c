#include "simple_crypto.h"
#include <stdint.h>
#include <string.h>

/** @brief AES-GCM encryption */
int encrypt_aes_gcm(const uint8_t *plaintext, size_t len, const uint8_t *key, uint8_t *ciphertext) {
    Aes aes;
    uint8_t nonce[12] = {0}; // Secure nonce
    wc_AesSetKey(&aes, key, 32, nonce, AES_ENCRYPTION);
    wc_AesGcmEncrypt(&aes, ciphertext, plaintext, len, nonce, 12, NULL, 0, NULL);
    return 0;
}

/** @brief AES-GCM decryption */
int decrypt_aes_gcm(const uint8_t *ciphertext, size_t len, const uint8_t *key, uint8_t *plaintext) {
    Aes aes;
    uint8_t nonce[12]; // Extract nonce

    if (len < 28) return -1; // Prevent buffer overflow (12-byte nonce + 16-byte tag)

    memcpy(nonce, ciphertext, 12);
    ciphertext += 12;
    len -= 12;

    wc_AesSetKey(&aes, key, 32, nonce, AES_DECRYPTION);
    wc_AesGcmDecrypt(&aes, plaintext, ciphertext, len, nonce, 12, NULL, 0, NULL);

    return 0;
}

/** @brief Compute HMAC-SHA256 */
int compute_hmac_sha256(const uint8_t *data, size_t len, const uint8_t *key, size_t key_len, uint8_t *hmac_output) {
    wc_Hmac hmac;
    wc_HmacSetKey(&hmac, WC_SHA256, key, key_len);
    wc_HmacUpdate(&hmac, data, len);
    wc_HmacFinal(&hmac, hmac_output);
    return 0;
}
/**
 * @file "simple_crypto.c"
 * @author Dream Team
 * @brief Simplified Crypto API Implementation using XOR encryption.
 * @date 2025
 *
 * This implementation uses a simple XOR cipher for encryption and decryption.
 * The output format for encryption is simply the XOR‐encrypted plaintext.
 * The caller must provide an output buffer that is at least the length of the plaintext.
 *
 */

#if CRYPTO_EXAMPLE

#include "simple_crypto.h"
#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include <wolfssl/wolfcrypt/sha256.h>

#define GCM_IV_SIZE    0    /* Not used in XOR */
#define GCM_TAG_SIZE   0    /* Not used in XOR */
#define KEY_SIZE 16

/**
 * @brief "Encrypts" plaintext using a simple XOR cipher.
 *
 * @param plaintext Pointer to the plaintext to encrypt.
 * @param len Length of the plaintext.
 * @param key Pointer to the 16-byte key.
 * @param out Pointer to the output buffer. Must be at least len bytes.
 *
 * @return 0 on success.
 */
int encrypt_sym(uint8_t *plaintext, size_t len, uint8_t *key, uint8_t *out) {
    for (size_t i = 0; i < len; i++) {
        out[i] = plaintext[i] ^ key[i % KEY_SIZE];
    }
    return 0;
}

/**
 * @brief Decrypts ciphertext that was "encrypted" with encrypt_sym.
 *
 * Since XOR is symmetric, decryption is identical to encryption.
 *
 * @param ciphertext Pointer to the input data.
 * @param cipher_len Total length of the input data.
 * @param key Pointer to the 16-byte key.
 * @param plaintext Pointer to the output buffer for the decrypted plaintext.
 *                  Must be at least cipher_len bytes.
 *
 * @return 0 on success.
 */
int decrypt_sym(const uint8_t *ciphertext, uint16_t cipher_len, const uint8_t *key, uint8_t *plaintext) {
    for (uint16_t i = 0; i < cipher_len; i++) {
        plaintext[i] = ciphertext[i] ^ key[i % KEY_SIZE];
    }
    return 0;
}

/**
 * @brief Hashes arbitrary-length data using SHA-256.
 *
 * @param data Pointer to the data to hash.
 * @param len Length of the data.
 * @param hash_out Pointer to the output buffer. Must be at least 32 bytes.
 *
 * @return 0 on success, non-zero error code on failure.
 */
int hash(void *data, size_t len, uint8_t *hash_out) {
    return wc_Sha256Hash((uint8_t *)data, (word32)len, hash_out);
}

#endif  // CRYPTO_EXAMPLE

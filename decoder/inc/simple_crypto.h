/**
 * @file "simple_crypto.h"
 * @author Dream Team
 * @brief Simplified Crypto API Header (Updated for AES-GCM & SHA-256)
 * @date 2025
 *
 */

#ifndef SIMPLE_CRYPTO_H
#define SIMPLE_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#if CRYPTO_EXAMPLE

#define GCM_IV_SIZE    12
#define GCM_TAG_SIZE   16
#define KEY_SIZE       16
#define HASH_SIZE      32

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Encrypts plaintext using a simple XOR-based cipher.
 *
 * The output format is: [IV (12 bytes)] || [ciphertext (plaintext length bytes)] || [tag (16 bytes)]
 *
 * The caller must provide an output buffer that is at least:
 *         plaintext length + 12 (IV) + 16 (tag) bytes.
 *
 * @param plaintext Pointer to the plaintext to encrypt.
 * @param len Length of the plaintext.
 * @param key Pointer to the 16-byte key.
 * @param out Pointer to the output buffer.
 *
 * @return 0 on success, non-zero error code on failure.
 */
int encrypt_sym(uint8_t *plaintext, size_t len, uint8_t *key, uint8_t *out);

/**
 * @brief Decrypts ciphertext that was encrypted with encrypt_sym.
 *
 * Expects input format: [IV (12 bytes)] || [ciphertext (plaintext length bytes)] || [tag (16 bytes)]
 *
 * @param ciphertext Pointer to the input data.
 * @param cipher_len Total length of the input data.
 * @param key Pointer to the 16-byte key.
 * @param plaintext Pointer to the output buffer for decrypted plaintext.
 *
 * @return 0 on success, non-zero error code on failure.
 */
int decrypt_sym(const uint8_t *ciphertext, uint16_t cipher_len, const uint8_t *key, uint8_t *plaintext);

/**
 * @brief Hashes arbitrary-length data using a simple hash.
 *
 * Produces a 32-byte hash.
 *
 * @param data Pointer to the data to hash.
 * @param len Length of the data.
 * @param hash_out Pointer to the output buffer (at least 32 bytes).
 *
 * @return 0 on success, non-zero error code on failure.
 */
int hash(void *data, size_t len, uint8_t *hash_out);

#ifdef __cplusplus
}
#endif

#endif  // CRYPTO_EXAMPLE

#endif  // SIMPLE_CRYPTO_H


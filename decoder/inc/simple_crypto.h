/**
 * @file "simple_crypto.h"
 * @author Dream Team
 * @brief Simplified Crypto API Header (Updated for AES-GCM & SHA-256)
 * @date 2025
 *
 */

#if CRYPTO_EXAMPLE
#ifndef ECTF_CRYPTO_H
#define ECTF_CRYPTO_H

#include "./wolfssl/options.h"
#include ".wolfssl/wolfcrypt/settings.h"
#include ".wolfssl/wolfcrypt/aes.h"
#include ".wolfssl/wolfcrypt/hash.h"
#include ".wolfssl/wolfcrypt/types.h"

/******************************** MACRO DEFINITIONS ********************************/
// For AES-GCM, plaintext can be any length.
// The output format for encryption is:
//   [IV (12 bytes)] || [ciphertext (plaintext length bytes)] || [auth tag (16 bytes)]
#define GCM_IV_SIZE    12
#define GCM_TAG_SIZE   16

#define KEY_SIZE 16
// Use 32 bytes for SHA-256 digest output.
#define HASH_SIZE 32

/******************************** FUNCTION PROTOTYPES ********************************/
/**
 * @brief Encrypts plaintext using AES-GCM authenticated encryption.
 *
 * The output is formatted as:
 *   [IV (12 bytes)] || [ciphertext (plaintext length bytes)] || [auth tag (16 bytes)]
 * The caller must allocate a ciphertext buffer of size (plaintext length + 12 + 16) bytes.
 *
 * @param plaintext  Pointer to the plaintext to encrypt.
 * @param len        Length of the plaintext (in bytes).
 * @param key        Pointer to a 16-byte key.
 * @param ciphertext Pointer to the output buffer where the resulting ciphertext is written.
 *
 * @return 0 on success, or a non-zero error code on failure.
 */
int encrypt_sym(uint8_t *plaintext, size_t len, uint8_t *key, uint8_t *ciphertext);

/**
 * @brief Decrypts ciphertext that was produced by encrypt_sym.
 *
 * Expects input format:
 *   [IV (12 bytes)] || [ciphertext (plaintext length bytes)] || [auth tag (16 bytes)]
 *
 * @param ciphertext Pointer to the input ciphertext buffer.
 * @param inLen      Total length of the input buffer (must be at least 12+16 bytes).
 * @param key        Pointer to a 16-byte key.
 * @param plaintext  Pointer to the output buffer for the decrypted plaintext.
 *                   This buffer must be at least (inLen - 12 - 16) bytes in size.
 *
 * @return 0 on success, or a non-zero error code on failure.
 */
int decrypt_sym(uint8_t *ciphertext, size_t inLen, uint8_t *key, uint8_t *plaintext);

/**
 * @brief Hashes arbitrary-length data using SHA-256.
 *
 * @param data     Pointer to the data to hash.
 * @param len      Length of the data (in bytes).
 * @param hash_out Pointer to a buffer (32 bytes) where the resulting hash will be written.
 *
 * @return 0 on success, or a non-zero error code on failure.
 */
int hash(void *data, size_t len, uint8_t *hash_out);

#endif // ECTF_CRYPTO_H
#endif // CRYPTO_EXAMPLE

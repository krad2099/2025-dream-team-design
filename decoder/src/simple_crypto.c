/**
 * @file    simple_crypto.c
 * @author  Dream Team
 * @brief   Simplified Crypto API Implementation (Updated for AES-GCM & SHA-256)
 * @date    2025
 *
 * This source file is part of an example system for MITRE's 2025 Embedded System CTF (eCTF).
 * This version uses AES-GCM for authenticated encryption and SHA-256 for hashing.
 *
 * The output format for encryption is:
 *    [IV (12 bytes)] || [ciphertext (plaintext length bytes)] || [auth tag (16 bytes)]
 *
 * The caller must provide an output buffer that is at least:
 *    plaintext length + 12 (IV) + 16 (auth tag) bytes.
 *
 * @copyright 
 */

#if CRYPTO_EXAMPLE

#include "simple_crypto.h"
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/* Remove wolfSSL includes */
#include "aes_gcm.h"    // Minimal AES-GCM implementation (e.g. tiny-AES-GCM)
#include "sha256.h"     // Minimal SHA-256 implementation providing simple_sha256()

/* Use our own simple RNG function.
   (For production, use a proper cryptographically secure RNG.) */
static void generate_random_bytes(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        buf[i] = rand() & 0xFF;
    }
}

/**
 * @brief Encrypts plaintext using AES-GCM authenticated encryption.
 *
 * The output format is: [IV (12 bytes)] || [ciphertext (plaintext length bytes)] || [auth tag (16 bytes)]
 *
 * @param plaintext Pointer to the plaintext to encrypt.
 * @param len Length of the plaintext.
 * @param key Pointer to the 16-byte key.
 * @param out Pointer to the output buffer. Must be at least (len + 12 + 16) bytes.
 *
 * @return 0 on success, non-zero error code on failure.
 */
int encrypt_sym(uint8_t *plaintext, size_t len, uint8_t *key, uint8_t *out) {
    int ret;
    uint8_t iv[GCM_IV_SIZE];
    uint8_t tag[GCM_TAG_SIZE];

    /* Generate a random IV */
    generate_random_bytes(iv, GCM_IV_SIZE);

    /* Perform AES-GCM encryption.
       This function is assumed to perform AES-GCM encryption with no AAD.
       It should write the ciphertext into (out + GCM_IV_SIZE) and output a 16-byte auth tag in tag. */
    ret = AESGCM_encrypt(key, iv, plaintext, (uint32_t)len, out + GCM_IV_SIZE, tag);
    if (ret != 0) {
        return ret;
    }

    /* Prepend IV to output */
    memcpy(out, iv, GCM_IV_SIZE);
    /* Append auth tag after the ciphertext */
    memcpy(out + GCM_IV_SIZE + len, tag, GCM_TAG_SIZE);

    return 0;
}

/**
 * @brief Decrypts ciphertext that was produced with encrypt_sym.
 *
 * Expects input format: [IV (12 bytes)] || [ciphertext (N bytes)] || [auth tag (16 bytes)]
 *
 * @param in Pointer to the input data.
 * @param inLen Total length of the input data. Must be at least (12 + 16) bytes.
 * @param key Pointer to the 16-byte key.
 * @param plaintext Pointer to the output buffer for the decrypted plaintext.
 *                  Must be at least (inLen - 12 - 16) bytes.
 *
 * @return 0 on success, non-zero error code on failure.
 */
int decrypt_sym(uint8_t *in, size_t inLen, uint8_t *key, uint8_t *plaintext) {
    int ret;
    if (inLen < (GCM_IV_SIZE + GCM_TAG_SIZE))
        return -1;  /* Not enough data */

    size_t cipherLen = inLen - GCM_IV_SIZE - GCM_TAG_SIZE;
    uint8_t iv[GCM_IV_SIZE];
    uint8_t tag[GCM_TAG_SIZE];

    /* Extract the IV and auth tag */
    memcpy(iv, in, GCM_IV_SIZE);
    memcpy(tag, in + GCM_IV_SIZE + cipherLen, GCM_TAG_SIZE);

    /* Perform AES-GCM decryption.
       It should verify the auth tag and write the decrypted plaintext into 'plaintext'. */
    ret = AESGCM_decrypt(key, iv, in + GCM_IV_SIZE, (uint32_t)cipherLen, tag, plaintext);
    return ret;
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
    return simple_sha256(data, len, hash_out);
}

#endif  // CRYPTO_EXAMPLE

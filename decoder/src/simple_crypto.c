/**
 * @file "simple_crypto.c"
 * @author Dream Team
 * @brief Simplified Crypto API Implementation (Modified for Security)
 * @date 2025
 *
 * This source file is part of an example system for MITRE's 2025 Embedded System CTF (eCTF).
 * This version uses AES-GCM for authenticated encryption and SHA-256 for hashing.
 *
 * Note: The output format for encryption is:
 *         [IV (12 bytes)] || [ciphertext (plaintext length bytes)] || [auth tag (16 bytes)]
 *
 * The caller must provide an output buffer that is at least:
 *         plaintext length + 12 (IV) + 16 (auth tag) bytes.
 *
 * @copyright 
 */

#if CRYPTO_EXAMPLE

#include "simple_crypto.h"
#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha256.h>

#define GCM_IV_SIZE    12
#define GCM_TAG_SIZE   16

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
    Aes aes;
    byte iv[GCM_IV_SIZE];
    byte authTag[GCM_TAG_SIZE];
    wc_RNG rng;

    /* Initialize RNG */
    ret = wc_InitRng(&rng);
    if (ret != 0)
        return ret;

    /* Generate a random IV */
    ret = wc_RNG_GenerateBlock(&rng, iv, GCM_IV_SIZE);
    if (ret != 0) {
        wc_FreeRng(&rng);
        return ret;
    }

    /* Set AES key for GCM mode */
    ret = wc_AesGcmSetKey(&aes, key, 16);
    if (ret != 0) {
        wc_FreeRng(&rng);
        return ret;
    }

    /* Perform AES-GCM encryption.
       No additional authenticated data (AAD) is used here (NULL, 0). */
    ret = wc_AesGcmEncrypt(&aes, 
                           out + GCM_IV_SIZE,    /* ciphertext output location */
                           plaintext,            /* plaintext input */
                           (word32)len,          /* plaintext length */
                           iv, GCM_IV_SIZE,      /* IV and its size */
                           authTag, GCM_TAG_SIZE,/* authentication tag output */
                           NULL, 0);             /* no AAD */
    if (ret != 0) {
        wc_FreeRng(&rng);
        return ret;
    }

    /* Prepend IV to output */
    memcpy(out, iv, GCM_IV_SIZE);
    /* Append auth tag after the ciphertext */
    memcpy(out + GCM_IV_SIZE + len, authTag, GCM_TAG_SIZE);

    wc_FreeRng(&rng);
    return 0;
}

/**
 * @brief Decrypts ciphertext that was encrypted with encrypt_sym.
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
    Aes aes;
    if (inLen < (GCM_IV_SIZE + GCM_TAG_SIZE))
        return -1;  /* Not enough data */

    size_t cipherLen = inLen - GCM_IV_SIZE - GCM_TAG_SIZE;
    byte iv[GCM_IV_SIZE];
    byte authTag[GCM_TAG_SIZE];

    /* Extract the IV and authentication tag from the input */
    memcpy(iv, in, GCM_IV_SIZE);
    memcpy(authTag, in + GCM_IV_SIZE + cipherLen, GCM_TAG_SIZE);

    /* Set AES key for GCM mode */
    ret = wc_AesGcmSetKey(&aes, key, 16);
    if (ret != 0)
        return ret;

    /* Perform AES-GCM decryption.
       No additional authenticated data (AAD) is used (NULL, 0). */
    ret = wc_AesGcmDecrypt(&aes, 
                           plaintext,         /* plaintext output */
                           in + GCM_IV_SIZE,  /* ciphertext input */
                           (word32)cipherLen, /* ciphertext length */
                           iv, GCM_IV_SIZE,   /* IV and its size */
                           authTag, GCM_TAG_SIZE, /* authentication tag */
                           NULL, 0);          /* no AAD */

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
    /* Use SHA-256 instead of MD5 for better security.
       SHA-256 produces a 32-byte hash output. */
    return wc_Sha256Hash((uint8_t *)data, (word32)len, hash_out);
}

#endif

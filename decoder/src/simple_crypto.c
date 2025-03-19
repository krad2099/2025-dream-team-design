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
#include <wolfssl/wolfcrypt/gcm.h>
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
                           out + GCM_IV_SIZE,    /* Ciphertext output offset by IV */
                           plaintext,            /* Plaintext input */
                           (word32)len,          /* Length of plaintext */
                           iv, GCM_IV_SIZE,      /* IV and IV length */
                           authTag, GCM_TAG_SIZE,/* Authentication tag and tag length */
                           NULL, 0);             /* No AAD */
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
 * @param ciphertext Pointer to the input data.
 * @param inLen Total length of the input data. Must be at least (12 + 16) bytes.
 * @param key Pointer to the 16-byte key.
 * @param plaintext Pointer to the output buffer for the decrypted plaintext.
 *                  Must be at least (inLen - 12 - 16) bytes.
 *
 * @return 0 on success, non-zero error code on failure.
 */
int decrypt_sym(uint8_t *ciphertext, size_t inLen, uint8_t *key, uint8_t *plaintext) {
    /* Ensure the input is long enough to contain IV and tag */
    if (inLen < (GCM_IV_SIZE + GCM_TAG_SIZE)) {
        return -1;  // Input too short.
    }

    /* Calculate the length of the ciphertext (which is also the plaintext length) */
    size_t cipher_text_len = inLen - (GCM_IV_SIZE + GCM_TAG_SIZE);

    /* Extract the IV (nonce), ciphertext, and tag */
    uint8_t *iv = ciphertext;  // First 12 bytes.
    uint8_t *enc_data = ciphertext + GCM_IV_SIZE;  // Next cipher_text_len bytes.
    uint8_t *tag = ciphertext + GCM_IV_SIZE + cipher_text_len;  // Final 16 bytes.

    Aes aes;
    int ret = wc_AesGcmSetKey(&aes, key, 16);
    if (ret != 0) {
        return ret;
    }

    /* Decrypt the ciphertext.
       - plaintext: Output buffer for decrypted data.
       - enc_data: The ciphertext to decrypt.
       - cipher_text_len: Length of the ciphertext (should equal the original plaintext length).
       - iv: The 12-byte nonce.
       - tag: The 16-byte authentication tag.
       - No additional authenticated data (AAD) is used.
    */
    ret = wc_AesGcmDecrypt(&aes,
                           plaintext,             /* Output buffer */
                           enc_data,              /* Ciphertext */
                           (word32)cipher_text_len, /* Ciphertext length */
                           iv, GCM_IV_SIZE,       /* IV and IV length */
                           tag, GCM_TAG_SIZE,     /* Tag and tag length */
                           NULL, 0);              /* No AAD */

    return ret;  // Return 0 on success, non-zero on error.
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

#endif // CRYPTO_EXAMPLE

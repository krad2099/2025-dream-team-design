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
 * @param len Length of the plaintext (in bytes).
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

    /* Encrypt plaintext using AES-GCM.
       No additional authenticated data (AAD) is used (NULL, 0). */
    ret = wc_AesGcmEncrypt(&aes, 
                           out + GCM_IV_SIZE,
                           plaintext,
                           (word32)len,
                           iv, GCM_IV_SIZE,
                           authTag, GCM_TAG_SIZE,
                           NULL, 0);
    if (ret != 0) {
        wc_FreeRng(&rng);
        return ret;
    }

    /* Prepend the IV */
    memcpy(out, iv, GCM_IV_SIZE);
    /* Append the auth tag right after the ciphertext */
    memcpy(out + GCM_IV_SIZE + len, authTag, GCM_TAG_SIZE);

    wc_FreeRng(&rng);
    return 0;
}

/**
 * @brief Decrypts ciphertext that was produced by encrypt_sym.
 *
 * Expects input format: [IV (12 bytes)] || [ciphertext (N bytes)] || [auth tag (16 bytes)]
 *
 * @param in Pointer to the input ciphertext buffer.
 * @param inLen Total length of the input buffer (must be at least 12 + 16 bytes).
 * @param key Pointer to a 16-byte key.
 * @param plaintext Pointer to the output buffer for the decrypted plaintext.
 *                  Must be at least (inLen - 12 - 16) bytes in size.
 *
 * @return 0 on success, non-zero error code on failure.
 */
int decrypt_sym(uint8_t *in, size_t inLen, uint8_t *key, uint8_t *plaintext) {
    int ret;
    Aes aes;
    byte iv[GCM_IV_SIZE];
    byte authTag[GCM_TAG_SIZE];
    word32 ciphertextLen;

    /* Check input length */
    if (inLen < (GCM_IV_SIZE + GCM_TAG_SIZE))
        return -1;  // Input too short

    ciphertextLen = (word32)(inLen - (GCM_IV_SIZE + GCM_TAG_SIZE));

    /* Extract IV from the beginning */
    memcpy(iv, in, GCM_IV_SIZE);
    /* Extract auth tag from the end */
    memcpy(authTag, in + GCM_IV_SIZE + ciphertextLen, GCM_TAG_SIZE);

    /* Set AES key for GCM mode */
    ret = wc_AesGcmSetKey(&aes, key, 16);
    if (ret != 0)
        return ret;

    /* Decrypt ciphertext */
    ret = wc_AesGcmDecrypt(&aes,
                           plaintext,
                           in + GCM_IV_SIZE, ciphertextLen,
                           iv, GCM_IV_SIZE,
                           authTag, GCM_TAG_SIZE,
                           NULL, 0);
    return ret;
}

/**
 * @brief Hashes arbitrary-length data using SHA-256.
 *
 * @param data Pointer to the data to hash.
 * @param len Length of the data (in bytes).
 * @param hash_out Pointer to a buffer (32 bytes) where the resulting hash will be written.
 *
 * @return 0 on success, non-zero error code on failure.
 */
int hash(void *data, size_t len, uint8_t *hash_out) {
    return wc_Sha256Hash((uint8_t *)data, (word32)len, hash_out);
}

#endif // CRYPTO_EXAMPLE

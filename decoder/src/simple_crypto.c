/**
 * @file "simple_crypto.c"
 * @author Ben Janis
 * @brief Simplified Crypto API Implementation
 * @date 2025
 *
 * This source file is part of an example system for MITRE's 2025 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2025 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2025 The MITRE Corporation
 */

#if CRYPTO_EXAMPLE

#include "simple_crypto.h"
#include <stdint.h>
#include <string.h>
#include <wolfssl/wolfcrypt/sha256.h>

/* Helper function to compute SHA-256 hash in one shot */
static int compute_sha256(const uint8_t *data, size_t len, uint8_t *hash) {
    wc_Sha256 sha;
    int ret;

    ret = wc_InitSha256(&sha);
    if(ret != 0)
        return ret;

    ret = wc_Sha256Update(&sha, data, len);
    if(ret != 0) {
        wc_Sha256Free(&sha);
        return ret;
    }

    ret = wc_Sha256Final(&sha, hash);
    wc_Sha256Free(&sha);
    return ret;
}

int encrypt_sym(uint8_t *plaintext, size_t len, uint8_t *key, uint8_t *ciphertext) {
    Aes ctx; /* Context for encryption */
    int result; /* Library result */
    uint8_t iv[BLOCK_SIZE];

    /* Ensure valid length: must be non-zero and a multiple of BLOCK_SIZE */
    if (len == 0 || (len % BLOCK_SIZE) != 0)
        return -1;

    /* Derive a static IV from the key: iv = first BLOCK_SIZE bytes of SHA-256(key) */
    result = compute_sha256(key, KEY_SIZE, iv);
    if (result != 0)
        return result;

    /* Set the key for encryption in CBC mode using the derived IV */
    result = wc_AesSetKey(&ctx, key, KEY_SIZE, iv, AES_ENCRYPTION);
    if (result != 0)
        return result;

    /* Encrypt in CBC mode */
    result = wc_AesCbcEncrypt(&ctx, ciphertext, plaintext, len);
    if (result != 0)
        return result;

    return 0;
}

int decrypt_sym(uint8_t *ciphertext, size_t len, uint8_t *key, uint8_t *plaintext) {
    Aes ctx; /* Context for decryption */
    int result; /* Library result */
    uint8_t iv[BLOCK_SIZE];

    /* Ensure valid length: must be non-zero and a multiple of BLOCK_SIZE */
    if (len == 0 || (len % BLOCK_SIZE) != 0)
        return -1;

    /* Derive the static IV from the key */
    result = compute_sha256(key, KEY_SIZE, iv);
    if (result != 0)
        return result;

    /* Set the key for decryption in CBC mode using the derived IV */
    result = wc_AesSetKey(&ctx, key, KEY_SIZE, iv, AES_DECRYPTION);
    if (result != 0)
        return result;

    /* Decrypt in CBC mode */
    result = wc_AesCbcDecrypt(&ctx, plaintext, ciphertext, len);
    if (result != 0)
        return result;

    return 0;
}

int hash(void *data, size_t len, uint8_t *hash_out) {
    /* Compute SHA-256 hash on the data */
    return compute_sha256((const uint8_t *)data, len, hash_out);
}

#endif

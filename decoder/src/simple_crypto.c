#include "simple_crypto.h"
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/types.h>

/** @brief AES encryption using WolfSSL in CBC mode */
int encrypt_sym(uint8_t *plaintext, size_t len, uint8_t *key, uint8_t *ciphertext) {
    WC_Aes aes;
    byte iv[16] = {0}; // Initialization vector (set to zero here; in practice, use a proper IV)
    
    if(wc_AesInit(&aes, NULL, INVALID_DEVID) != 0)
        return -1;
    if(wc_AesSetKey(&aes, key, KEY_SIZE, iv, AES_ENCRYPTION) != 0) {
        wc_AesFree(&aes);
        return -1;
    }
    for (size_t i = 0; i < len; i += AES_BLOCK_SIZE) {
        if(wc_AesCbcEncrypt(&aes, ciphertext + i, plaintext + i, AES_BLOCK_SIZE) != 0) {
            wc_AesFree(&aes);
            return -1;
        }
    }
    wc_AesFree(&aes);
    return 0;
}

/** @brief AES decryption using WolfSSL in CBC mode */
int decrypt_sym(uint8_t *ciphertext, size_t len, uint8_t *key, uint8_t *plaintext) {
    WC_Aes aes;
    byte iv[16] = {0}; // Initialization vector (must be the same as used for encryption)
    
    if(wc_AesInit(&aes, NULL, INVALID_DEVID) != 0)
        return -1;
    if(wc_AesSetKey(&aes, key, KEY_SIZE, iv, AES_DECRYPTION) != 0) {
        wc_AesFree(&aes);
        return -1;
    }
    for (size_t i = 0; i < len; i += AES_BLOCK_SIZE) {
        if(wc_AesCbcDecrypt(&aes, plaintext + i, ciphertext + i, AES_BLOCK_SIZE) != 0) {
            wc_AesFree(&aes);
            return -1;
        }
    }
    wc_AesFree(&aes);
    return 0;
}

/** @brief Simple hash function using WolfSSL's MD5 (or use SHA-256 if desired) */
int hash(void *data, size_t len, uint8_t *hash_out) {
    // Using MD5 here; you may change to SHA256 if required.
    return wc_Md5Hash(data, len, hash_out);
}

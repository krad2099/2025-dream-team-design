#ifndef ECTF_CRYPTO_H
#define ECTF_CRYPTO_H

#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/hash.h"

/******************************** MACRO DEFINITIONS ********************************/
#define BLOCK_SIZE AES_BLOCK_SIZE
#define KEY_SIZE 32            // Updated to AES-256 key size
#define IV_SIZE AES_BLOCK_SIZE  // Added for CBC mode
#define HASH_SIZE MD5_DIGEST_SIZE

/******************************** FUNCTION PROTOTYPES ********************************/
int encrypt_sym(uint8_t *plaintext, size_t len, uint8_t *key, uint8_t *iv, uint8_t *ciphertext);
int decrypt_sym(uint8_t *ciphertext, size_t len, uint8_t *key, uint8_t *iv, uint8_t *plaintext);
int hash(void *data, size_t len, uint8_t *hash_out);

#endif // ECTF_CRYPTO_H

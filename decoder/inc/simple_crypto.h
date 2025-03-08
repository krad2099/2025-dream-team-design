#ifndef ECTF_CRYPTO_H
#define ECTF_CRYPTO_H

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/types.h>

#define BLOCK_SIZE AES_BLOCK_SIZE
#define KEY_SIZE 32  // AES-256 key size (32 bytes)
#define HASH_SIZE 32 // Using SHA-256 (32 bytes output)

int encrypt_sym(uint8_t *plaintext, size_t len, uint8_t *key, uint8_t *ciphertext);
int decrypt_sym(uint8_t *ciphertext, size_t len, uint8_t *key, uint8_t *plaintext);
int hash(void *data, size_t len, uint8_t *hash_out);

#endif // ECTF_CRYPTO_H

#ifndef ECTF_CRYPTO_H
#define ECTF_CRYPTO_H

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define BLOCK_SIZE AES_BLOCK_SIZE
#define KEY_SIZE 32  // AES-256 key size
#define HASH_SIZE 32  // SHA-256 hash size

int encrypt_sym(uint8_t *plaintext, size_t len, uint8_t *key, uint8_t *ciphertext);
int decrypt_sym(uint8_t *ciphertext, size_t len, uint8_t *key, uint8_t *plaintext);
int hash(void *data, size_t len, uint8_t *hash_out);

#endif // ECTF_CRYPTO_H

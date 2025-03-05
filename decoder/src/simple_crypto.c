#include "simple_crypto.h"
#include "wolfssl/ssl.h"  // Include wolfSSL for AES

// Encrypt data using AES from wolfSSL
int encrypt_sym(uint8_t *plaintext, size_t len, uint8_t *key, uint8_t *ciphertext) {
    WOLFSSL_AES_KEY aes_key;
    
    // Set AES encryption key
    wolfSSL_AES_set_encrypt_key(&aes_key, key, 32);  // AES-256 key (32 bytes)
    
    // Encrypt the data
    for (int i = 0; i < len; i += 16) {
        wolfSSL_AES_encrypt(&aes_key, plaintext + i, ciphertext + i);
    }

    return 0;
}

// Decrypt data using AES from wolfSSL
int decrypt_sym(uint8_t *ciphertext, size_t len, uint8_t *key, uint8_t *plaintext) {
    WOLFSSL_AES_KEY aes_key;
    
    // Set AES decryption key
    wolfSSL_AES_set_decrypt_key(&aes_key, key, 32);  // AES-256 key (32 bytes)
    
    // Decrypt the data
    for (int i = 0; i < len; i += 16) {
        wolfSSL_AES_decrypt(&aes_key, ciphertext + i, plaintext + i);
    }

    return 0;
}

// Hash using SHA256 (example)
int hash(void *data, size_t len, uint8_t *hash_out) {
    // We can use wolfSSL's internal hash function or use external libraries for hashing.
    return wc_Sha256Hash(data, len, hash_out);  // SHA256 example
}

#include "simple_crypto.h"
#include <openssl/evp.h>  // OpenSSL for AES

// Encrypt data using AES from OpenSSL
int encrypt_sym(uint8_t *plaintext, size_t len, uint8_t *key, uint8_t *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    
    // Initialize OpenSSL AES context
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return -1;  // Error initializing context
    }

    // Initialize encryption operation
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len_out;
    if (EVP_EncryptUpdate(ctx, ciphertext, &len_out, plaintext, len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int encrypted_len = len_out;

    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len_out, &len_out) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    encrypted_len += len_out;
    EVP_CIPHER_CTX_free(ctx);

    return 0;
}

// Decrypt data using AES from OpenSSL
int decrypt_sym(uint8_t *ciphertext, size_t len, uint8_t *key, uint8_t *plaintext) {
    EVP_CIPHER_CTX *ctx;
    
    // Initialize OpenSSL AES context
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return -1;  // Error initializing context
    }

    // Initialize decryption operation
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len_out;
    if (EVP_DecryptUpdate(ctx, plaintext, &len_out, ciphertext, len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int decrypted_len = len_out;

    // Finalize decryption
    if (EVP_DecryptFinal_ex(ctx, plaintext + len_out, &len_out) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    decrypted_len += len_out;
    EVP_CIPHER_CTX_free(ctx);

    return 0;
}

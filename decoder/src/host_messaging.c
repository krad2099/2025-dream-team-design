#include <stdio.h>
#include "host_messaging.h"
#include <openssl/evp.h>  // OpenSSL for AES

int read_bytes(void *buf, uint16_t len, uint8_t *key) {
    int result;
    int i;

    for (i = 0; i < len; i++) {
        if (i % 256 == 0 && i != 0) {
            write_ack();
        }
        result = uart_readbyte();
        if (result < 0) {
            return result;
        }
        ((uint8_t *)buf)[i] = result;
    }

    // Decrypt data after receiving with AES from OpenSSL
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return -1;  // Error initializing context
    }

    // Initialize the decryption operation
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len;
    if (EVP_DecryptUpdate(ctx, (uint8_t *)buf, &len, (uint8_t *)buf, len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int decrypted_len = len;

    // Finalize the decryption
    if (EVP_DecryptFinal_ex(ctx, (uint8_t *)buf + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    decrypted_len += len;
    EVP_CIPHER_CTX_free(ctx);

    return 0;
}

int write_bytes(const void *buf, uint16_t len, bool should_ack, uint8_t *key) {
    uint8_t encrypted_data[len];

    // Encrypt data using AES with OpenSSL
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return -1;  // Error initializing context
    }

    // Initialize the encryption operation
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len_out;
    if (EVP_EncryptUpdate(ctx, encrypted_data, &len_out, (uint8_t *)buf, len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int encrypted_len = len_out;

    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx, encrypted_data + len_out, &len_out) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    encrypted_len += len_out;
    EVP_CIPHER_CTX_free(ctx);

    // Send encrypted data
    for (int i = 0; i < encrypted_len; i++) {
        if (i % 256 == 0 && i != 0) {
            if (should_ack && read_ack() < 0) {
                return -1;
            }
        }
        uart_writebyte(encrypted_data[i]);
    }

    fflush(stdout);

    return 0;
}

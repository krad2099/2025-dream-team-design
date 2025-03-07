#include "simple_flash.h"
#include <openssl/evp.h>  // OpenSSL for AES encryption

int flash_simple_erase_page(uint32_t address) {
    return MXC_FLC_PageErase(address);
}

void flash_simple_read(uint32_t address, void* buffer, uint32_t size, uint8_t *key) {
    uint8_t encrypted_data[size];

    // Perform the flash read operation
    MXC_FLC_Read(address, (uint32_t *)encrypted_data, size);

    // Decrypt the data after reading using AES from OpenSSL
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return;  // Error initializing context
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    int len;
    EVP_DecryptUpdate(ctx, (uint8_t *)buffer, &len, encrypted_data, size);
    EVP_CIPHER_CTX_free(ctx);
}

int flash_simple_write(uint32_t address, void* buffer, uint32_t size, uint8_t *key) {
    uint8_t encrypted_data[size];

    // Encrypt the data before writing using AES from OpenSSL
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return -1;  // Error initializing context
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len_out;
    if (EVP_EncryptUpdate(ctx, encrypted_data, &len_out, (uint8_t *)buffer, size) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int encrypted_len = len_out;

    if (EVP_EncryptFinal_ex(ctx, encrypted_data + len_out, &len_out) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    encrypted_len += len_out;
    EVP_CIPHER_CTX_free(ctx);

    // Perform the flash write operation
    return MXC_FLC_Write(address, size, (uint32_t *)encrypted_data);
}

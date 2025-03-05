#include "simple_flash.h"
#include "wolfssl/ssl.h"  // Include wolfSSL for AES encryption

int flash_simple_erase_page(uint32_t address) {
    return MXC_FLC_PageErase(address);
}

void flash_simple_read(uint32_t address, void* buffer, uint32_t size, uint8_t *key) {
    uint8_t encrypted_data[size];

    // Perform the flash read operation
    MXC_FLC_Read(address, (uint32_t *)encrypted_data, size);

    // Decrypt the data after reading using AES from wolfSSL
    WOLFSSL_AES_KEY aes_key;
    wolfSSL_AES_set_decrypt_key(&aes_key, key, 32);  // AES-256
    wolfSSL_AES_decrypt(&aes_key, encrypted_data, (uint8_t *)buffer);
}

int flash_simple_write(uint32_t address, void* buffer, uint32_t size, uint8_t *key) {
    uint8_t encrypted_data[size];

    // Encrypt the data before writing using AES from wolfSSL
    WOLFSSL_AES_KEY aes_key;
    wolfSSL_AES_set_encrypt_key(&aes_key, key, 32);  // AES-256
    wolfSSL_AES_encrypt(&aes_key, (uint8_t *)buffer, encrypted_data);

    // Perform the flash write operation
    return MXC_FLC_Write(address, size, (uint32_t *)encrypted_data);
}

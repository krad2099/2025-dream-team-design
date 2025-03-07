#include <stdio.h>
#include "host_messaging.h"
#include <wolfssl/wolfcrypt/aes.h>

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

    // Decrypt data after receiving with AES from WolfSSL
    WC_Aes aes;
    byte iv[16] = {0};

    // Initialize WolfSSL AES context
    if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0) {
        return -1;
    }

    // Set the decryption key
    if (wc_AesSetKey(&aes, key, 32, iv, AES_DECRYPTION) != 0) {  // AES-256
        wc_AesFree(&aes);
        return -1;
    }

    // Decrypt the data using AES CBC mode
    if (wc_AesCbcDecrypt(&aes, (uint8_t *)buf, (uint8_t *)buf, len) != 0) {
        wc_AesFree(&aes);
        return -1;
    }

    // Finalize AES operation
    wc_AesFree(&aes);

    return 0;
}

int write_bytes(const void *buf, uint16_t len, bool should_ack, uint8_t *key) {
    uint8_t encrypted_data[len];

    // Encrypt data using AES with WolfSSL
    WC_Aes aes;
    byte iv[16] = {0};

    // Initialize WolfSSL AES context
    if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0) {
        return -1;
    }

    // Set the encryption key
    if (wc_AesSetKey(&aes, key, 32, iv, AES_ENCRYPTION) != 0) {
        wc_AesFree(&aes);
        return -1;
    }

    // Encrypt the data using AES CBC mode
    if (wc_AesCbcEncrypt(&aes, encrypted_data, (uint8_t *)buf, len) != 0) {
        wc_AesFree(&aes);
        return -1;
    }

    // Finalize AES operation
    wc_AesFree(&aes);

    // Send encrypted data
    for (int i = 0; i < len; i++) {
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

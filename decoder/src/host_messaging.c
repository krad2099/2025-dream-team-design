#include <stdio.h>
#include "host_messaging.h"
#include "wolfssl/ssl.h"  // Include wolfSSL for AES

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

    // Decrypt data after receiving with AES from wolfSSL
    WOLFSSL_AES_KEY aes_key;
    wolfSSL_AES_set_decrypt_key(&aes_key, key, 32);  // Use a 32-byte AES key for AES-256
    wolfSSL_AES_decrypt(&aes_key, (uint8_t *)buf, (uint8_t *)buf);  // In-place decryption

    return 0;
}

int write_bytes(const void *buf, uint16_t len, bool should_ack, uint8_t *key) {
    uint8_t encrypted_data[len];

    // Encrypt data using AES with wolfSSL
    WOLFSSL_AES_KEY aes_key;
    wolfSSL_AES_set_encrypt_key(&aes_key, key, 32);  // AES-256 encryption
    wolfSSL_AES_encrypt(&aes_key, (uint8_t *)buf, encrypted_data);

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

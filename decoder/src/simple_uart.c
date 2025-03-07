#include "simple_uart.h"
#include <openssl/evp.h>  // OpenSSL for AES encryption

void uart_writebyte(uint8_t data, uint8_t *key) {
    uint8_t encrypted_data[1];
    uint8_t data_buf[1] = {data};

    // Encrypt data before sending using AES from OpenSSL
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return;  // Error initializing context
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    int len_out;
    if (EVP_EncryptUpdate(ctx, encrypted_data, &len_out, data_buf, 1) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    int encrypted_len = len_out;

    if (EVP_EncryptFinal_ex(ctx, encrypted_data + len_out, &len_out) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    encrypted_len += len_out;
    EVP_CIPHER_CTX_free(ctx);

    // Send encrypted data
    while (MXC_UART_GET_UART(CONSOLE_UART)->status & MXC_F_UART_STATUS_TX_FULL) {
    }
    MXC_UART_GET_UART(CONSOLE_UART)->fifo = encrypted_data[0];
}

int uart_readbyte(uint8_t *key) {
    uint8_t encrypted_data[1];
    uint8_t decrypted_data[1];

    int data = MXC_UART_ReadCharacter(MXC_UART_GET_UART(CONSOLE_UART));

    encrypted_data[0] = data;

    // Decrypt data after receiving using AES from OpenSSL
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return -1;  // Error initializing context
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len;
    EVP_DecryptUpdate(ctx, decrypted_data, &len, encrypted_data, 1);
    EVP_CIPHER_CTX_free(ctx);

    return decrypted_data[0];
}

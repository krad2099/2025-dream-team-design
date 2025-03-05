#include "simple_uart.h"
#include "wolfssl/ssl.h"  // Include wolfSSL for AES encryption

void uart_writebyte(uint8_t data, uint8_t *key) {
    uint8_t encrypted_data[1];
    uint8_t data_buf[1] = {data};

    // Encrypt data before sending using AES from wolfSSL
    WOLFSSL_AES_KEY aes_key;
    wolfSSL_AES_set_encrypt_key(&aes_key, key, 32);  // AES-256
    wolfSSL_AES_encrypt(&aes_key, data_buf, encrypted_data);

    while (MXC_UART_GET_UART(CONSOLE_UART)->status & MXC_F_UART_STATUS_TX_FULL) {
    }
    MXC_UART_GET_UART(CONSOLE_UART)->fifo = encrypted_data[0];
}

int uart_readbyte(uint8_t *key) {
    uint8_t encrypted_data[1];
    uint8_t decrypted_data[1];

    int data = MXC_UART_ReadCharacter(MXC_UART_GET_UART(CONSOLE_UART));

    encrypted_data[0] = data;

    // Decrypt data after receiving using AES from wolfSSL
    WOLFSSL_AES_KEY aes_key;
    wolfSSL_AES_set_decrypt_key(&aes_key, key, 32);  // AES-256
    wolfSSL_AES_decrypt(&aes_key, encrypted_data, decrypted_data);

    return decrypted_data[0];
}

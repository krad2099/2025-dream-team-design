#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "host_messaging.h"
#include "simple_uart.h"

/** @brief Read len bytes from UART securely */
int read_bytes(void *buf, uint16_t len) {
    int result;
    int i;

    for (i = 0; i < len; i++) {
        if (i % 256 == 0 && i != 0) { // Secure ACK handling
            write_ack();
        }
        result = uart_readbyte();
        if (result < 0) {
            return result;
        }
        ((uint8_t *)buf)[i] = result;
    }

    return 0;
}

/** @brief Read a message header securely */
void read_header(msg_header_t *hdr) {
    hdr->magic = uart_readbyte();
    while (hdr->magic != MSG_MAGIC) {
        hdr->magic = uart_readbyte();
    }
    hdr->cmd = uart_readbyte();
    read_bytes(&hdr->len, sizeof(hdr->len));
}

/** @brief Securely send an ACK */
uint8_t read_ack() {
    msg_header_t ack_buf = {0};
    read_header(&ack_buf);
    return (ack_buf.cmd == ACK_MSG) ? 0 : -1;
}

/** @brief Securely write bytes to UART */
int write_bytes(const void *buf, uint16_t len, bool should_ack) {
    for (int i = 0; i < len; i++) {
        uart_writebyte(((uint8_t *)buf)[i]);
        if (i % 256 == 0 && should_ack && read_ack() < 0) {
            return -1;
        }
    }
    return 0;
}
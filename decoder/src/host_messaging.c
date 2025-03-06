#include <stdio.h>
#include "host_messaging.h"
#include <openssl/aes.h>

int read_bytes(void *buf, uint16_t len);
uint8_t read_ack(void);


/** @brief Read a msg header securely */
void read_header(msg_header_t *hdr) {
    hdr->magic = uart_readbyte();
    while (hdr->magic != MSG_MAGIC) {
        hdr->magic = uart_readbyte();
    }
    hdr->cmd = uart_readbyte();
    read_bytes(&hdr->len, sizeof(hdr->len));
}

/** @brief Securely write bytes to UART */
int write_bytes(const void *buf, uint16_t len, bool should_ack) {
    for (int i = 0; i < len; i++) {
        uart_writebyte(((uint8_t *)buf)[i]);
        if (i % 256 == 0 && should_ack && read_ack() < 0) return -1;
    }
    return 0;
}

int read_bytes(void *buf, uint16_t len) {
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

    return 0;
}

/** @brief Receive an ACK from UART */
uint8_t read_ack() {
    msg_header_t ack_buf = {0};

    read_header(&ack_buf);
    if (ack_buf.cmd == ACK_MSG) {
        return 0;
    } else {
        return -1;
    }
}

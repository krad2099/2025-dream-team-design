#include <stdio.h>
#include "host_messaging.h"

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
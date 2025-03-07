#ifndef __HOST_MESSAGING__
#define __HOST_MESSAGING__

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include "simple_uart.h"

#define CMD_TYPE_LEN sizeof(char)
#define CMD_LEN_LEN sizeof(uint16_t)
#define MSG_MAGIC '%'     // '%' - 0x25

typedef enum {
    DECODE_MSG = 'D',     // 'D' - 0x44
    SUBSCRIBE_MSG = 'S',  // 'S' - 0x53
    LIST_MSG = 'L',       // 'L' - 0x4c
    ACK_MSG = 'A',        // 'A' - 0x41
    DEBUG_MSG = 'G',      // 'G' - 0x47
    ERROR_MSG = 'E',      // 'E' - 0x45
} msg_type_t;

#pragma pack(push, 1)
typedef struct {
    char magic;    // Should be MSG_MAGIC
    char cmd;      // msg_type_t
    uint16_t len;
} msg_header_t;

#pragma pack(pop)

#define MSG_HEADER_SIZE sizeof(msg_header_t)

int write_hex(msg_type_t type, const void *buf, size_t len);
int write_packet(msg_type_t type, const void *buf, uint16_t len);
int read_packet(msg_type_t* cmd, void *buf, uint16_t *len);

#define print_error(msg) write_packet(ERROR_MSG, msg, strlen(msg))
#define print_debug(msg) write_packet(DEBUG_MSG, msg, strlen(msg))
#define print_hex_debug(msg, len) write_hex(DEBUG_MSG, msg, len)
#define write_ack() write_packet(ACK_MSG, NULL, 0)

#endif

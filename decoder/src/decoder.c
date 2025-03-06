#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "mxc_device.h"
#include "status_led.h"
#include "board.h"
#include "mxc_delay.h"
#include "simple_flash.h"
#include "host_messaging.h"
#include "simple_uart.h"
#include "simple_crypto.h"

#define FRAME_SIZE 64
#define DEFAULT_CHANNEL_TIMESTAMP 0xFFFFFFFFFFFFFFFF
#define FLASH_FIRST_BOOT 0xDEADBEEF

typedef uint64_t timestamp_t;
typedef uint32_t channel_id_t;
typedef uint32_t decoder_id_t;
typedef uint16_t pkt_len_t;

typedef struct {
    channel_id_t channel;
    timestamp_t timestamp;
    uint8_t data[FRAME_SIZE];
} frame_packet_t;

typedef struct {
    decoder_id_t decoder_id;
    timestamp_t start_timestamp;
    timestamp_t end_timestamp;
    channel_id_t channel;
} subscription_update_packet_t;

typedef struct {
    channel_id_t channel;
    timestamp_t start;
    timestamp_t end;
} channel_info_t;

typedef struct {
    uint32_t n_channels;
    channel_info_t channel_info[MAX_CHANNEL_COUNT];
} list_response_t;

typedef struct {
    bool active;
    channel_id_t id;
    timestamp_t start_timestamp;
    timestamp_t end_timestamp;
} channel_status_t;

typedef struct {
    uint32_t first_boot;
    channel_status_t subscribed_channels[MAX_CHANNEL_COUNT];
} flash_entry_t;

flash_entry_t decoder_status;

int decode(pkt_len_t pkt_len, frame_packet_t *new_frame, uint8_t *key) {
    uint8_t decrypted_data[FRAME_SIZE];
    
    // Decrypt using AES (assuming simple_crypto provides the necessary functions)
    decrypt_sym(new_frame->data, FRAME_SIZE, key, decrypted_data);

    // Process decrypted data (you can now use this data)
    printf("Decoded frame for channel %u: ", new_frame->channel);
    for (int i = 0; i < FRAME_SIZE; i++) {
        printf("%02X ", decrypted_data[i]);
    }
    printf("\n");

    return 0;
}

int main(void) {
    uint8_t uart_buf[100];
    msg_type_t cmd;
    uint16_t pkt_len;

    flash_simple_read(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));

    while (1) {
        if (read_packet(&cmd, uart_buf, &pkt_len) < 0) continue;

        switch (cmd) {
            case DECODE_MSG:
                decode(pkt_len, (frame_packet_t *)uart_buf, decoder_status.subscribed_channels[0].key);
                break;
            case SUBSCRIBE_MSG:
                update_subscription(pkt_len, (subscription_update_packet_t *)uart_buf);
                break;
            default:
                break;
        }
    }
}

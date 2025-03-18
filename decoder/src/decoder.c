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

/**********************************************************
 ******************* PRIMITIVE TYPES **********************
 **********************************************************/
#define timestamp_t uint64_t
#define channel_id_t uint32_t
#define decoder_id_t uint32_t
#define pkt_len_t uint16_t

/**********************************************************
 *********************** CONSTANTS ************************
 **********************************************************/
#define MAX_CHANNEL_COUNT 8
#define EMERGENCY_CHANNEL 0
#define FRAME_SIZE 64
#define DEFAULT_CHANNEL_TIMESTAMP 0xFFFFFFFFFFFFFFFF
#define FLASH_FIRST_BOOT 0xDEADBEEF
#define FLASH_STATUS_ADDR 0x100000

#define AES_KEY_SIZE 32
#define AES_BLOCK_SIZE 16

/**********************************************************
 ******************* STRUCT DEFINITIONS *******************
 **********************************************************/
#pragma pack(push, 1)
typedef struct {
    channel_id_t channel;
    timestamp_t timestamp;
    uint8_t iv[AES_BLOCK_SIZE];
    uint8_t encrypted_data[FRAME_SIZE];
} frame_packet_t;

typedef struct {
    uint32_t first_boot;
    struct {
        bool active;
        channel_id_t id;
        timestamp_t start_timestamp;
        timestamp_t end_timestamp;
    } subscribed_channels[MAX_CHANNEL_COUNT];
} flash_entry_t;

#pragma pack(pop)

/**********************************************************
 ******************** GLOBAL VARIABLES ********************
 **********************************************************/
static uint8_t encryption_key[AES_KEY_SIZE];
flash_entry_t decoder_status;

/**********************************************************
 ******************* UTILITY FUNCTIONS ********************
 **********************************************************/
void decrypt_frame(uint8_t *ciphertext, uint8_t *plaintext, uint8_t *iv) {
    decrypt_sym(ciphertext, FRAME_SIZE, encryption_key, iv, plaintext);
}

/** @brief Checks if the decoder is subscribed to a given channel.
 * 
 *  @param channel The channel number to check.
 *  @return 1 if subscribed, 0 if not.
 */
int is_subscribed(channel_id_t channel) {
    if (channel == EMERGENCY_CHANNEL) {
        return 1;  // Emergency broadcasts are always allowed
    }
    for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].id == channel && decoder_status.subscribed_channels[i].active) {
            return 1;  // Subscribed to this channel
        }
    }
    return 0;  // Not subscribed
}

/**********************************************************
 ********************* CORE FUNCTIONS *********************
 **********************************************************/
int decode(pkt_len_t pkt_len, frame_packet_t *new_frame) {
    char output_buf[128] = {0};
    uint8_t decrypted_frame[FRAME_SIZE];
    channel_id_t channel = new_frame->channel;

    if (is_subscribed(channel)) {
        decrypt_frame(new_frame->encrypted_data, decrypted_frame, new_frame->iv);
        write_packet(DECODE_MSG, decrypted_frame, FRAME_SIZE);
        return 0;
    } else {
        STATUS_LED_RED();
        sprintf(output_buf, "Receiving unsubscribed channel data. %u\n", channel);
        print_error(output_buf);
        return -1;
    }
}

void init() {
    flash_simple_init();
    flash_simple_read(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    if (decoder_status.first_boot != FLASH_FIRST_BOOT) {
        decoder_status.first_boot = FLASH_FIRST_BOOT;
        memset(decoder_status.subscribed_channels, 0, sizeof(decoder_status.subscribed_channels));
        flash_simple_erase_page(FLASH_STATUS_ADDR);
        flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    }
    uart_init();
    flash_simple_read(FLASH_STATUS_ADDR, encryption_key, AES_KEY_SIZE);
}

int main(void) {
    init();
    while (1) {
        uint8_t uart_buf[100];
        msg_type_t cmd;
        uint16_t pkt_len;
        if (read_packet(&cmd, uart_buf, &pkt_len) < 0) continue;

        switch (cmd) {
            case DECODE_MSG:
                decode(pkt_len, (frame_packet_t *)uart_buf);
                break;
            case SUBSCRIBE_MSG:
                update_subscription(pkt_len, (subscription_update_packet_t *)uart_buf);
                break;
            case LIST_MSG:
                list_channels();
                break;
            case ACK_MSG:
            case DEBUG_MSG:
            case ERROR_MSG:
            case ENCRYPTED_MSG:
                print_debug("Unhandled message type\n");
                break;
            default:
                print_error("Unknown command received\n");
        }
    }
}

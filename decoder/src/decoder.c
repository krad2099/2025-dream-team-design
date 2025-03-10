#define _POSIX_C_SOURCE 200809L

/**
 * @file    decoder.c
 * @author  Dream Team
 * @brief   eCTF Dream Team Decoder Design Implementation with Clock Synchronization
 *          and simplified cryptography.
 * @date    2025
 *
 */

/*********************** INCLUDES *************************/
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>   // For snprintf
#include "mxc_device.h"
#include "status_led.h"
#include "board.h"
#include "mxc_delay.h"
#include "simple_flash.h"
#include "host_messaging.h"
#include "simple_uart.h"
#include "simple_crypto.h"   // Use our simple crypto implementation

#ifdef CRYPTO_EXAMPLE
/* If wolfSSL is not available, define wc_Sha256Hash in terms of our simple_sha256 */
#ifndef wc_Sha256Hash
#define wc_Sha256Hash(data, datalen, out) simple_sha256(data, datalen, out)
#endif
#endif  // CRYPTO_EXAMPLE

/**********************************************************
 ******************* PRIMITIVE TYPES **********************
 **********************************************************/
#define timestamp_t uint64_t
#define channel_id_t uint32_t
#define decoder_id_t uint32_t
#define pkt_len_t uint16_t

/**********************************************************
 ************************ CONSTANTS ***********************
 **********************************************************/
// For a 64-byte plaintext, AES-GCM produces a 12-byte nonce, 64-byte ciphertext, and a 16-byte tag.
// That gives a total encrypted data length of 12+16+64 = 92 bytes.
#define FRAME_SIZE 92

#define MAX_CHANNEL_COUNT 8
#define EMERGENCY_CHANNEL 0
#define DEFAULT_CHANNEL_TIMESTAMP 0xFFFFFFFFFFFFFFFFULL
#define FLASH_FIRST_BOOT 0xDEADBEEF
#define FLASH_STATUS_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))
#define SYNC_FRAME_CHANNEL 0xFFFFFFFF

/**********************************************************
 ***** COMMUNICATION PACKET DEFINITIONS (packed) *******
 **********************************************************/
#pragma pack(push, 1)
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
#pragma pack(pop)

/**********************************************************
 ********************* TYPE DEFINITIONS *******************
 **********************************************************/
typedef struct {
    bool active;
    channel_id_t id;
    timestamp_t start_timestamp;
    timestamp_t end_timestamp;
} channel_status_t;

typedef struct {
    uint32_t first_boot; // Set to FLASH_FIRST_BOOT if device has booted before.
    channel_status_t subscribed_channels[MAX_CHANNEL_COUNT];
} flash_entry_t;

/**********************************************************
 ************************ GLOBALS *************************
 **********************************************************/
static uint8_t global_secret[KEY_SIZE];  // Global secret for crypto

flash_entry_t decoder_status;

/* Global variables for timestamp synchronization */
static int64_t timestamp_offset = 0;
static int sync_received = 0;
static uint64_t last_adjusted_timestamp = 0;

/**********************************************************
 ********** FORWARD FUNCTION PROTOTYPES *******************
 **********************************************************/
timestamp_t get_monotonic_timestamp(void);
void process_sync_frame(frame_packet_t *sync_frame);
void init_global_secret(void);

/**********************************************************
 ******************** UTILITY FUNCTIONS *******************
 **********************************************************/
timestamp_t get_monotonic_timestamp(void) {
    /* For production, replace this with a hardware timer.
       Here we use a simple counter that increments by 1ms (1,000,000 ns) per call. */
    static timestamp_t counter = 0;
    counter += 1000000;
    return counter;
}

void process_sync_frame(frame_packet_t *sync_frame) {
    uint64_t local_time = get_monotonic_timestamp();
    timestamp_offset = (int64_t)sync_frame->timestamp - (int64_t)local_time;
    sync_received = 1;
    {
        char dbg_buf[128];
        snprintf(dbg_buf, sizeof(dbg_buf),
                 "Sync frame received. Offset set to %lld\n", timestamp_offset);
        print_debug(dbg_buf);
    }
}

void init_global_secret(void) {
    /* Load the global secret from persistent storage */
    load_global_secret(global_secret, sizeof(global_secret));
}

int is_subscribed(channel_id_t channel) {
    if (channel == EMERGENCY_CHANNEL) {
        return 1;
    }
    for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].id == channel &&
            decoder_status.subscribed_channels[i].active) {
            return 1;
        }
    }
    return 0;
}

int list_channels() {
    list_response_t resp;
    pkt_len_t len;
    resp.n_channels = 0;
    for (uint32_t i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].active) {
            resp.channel_info[resp.n_channels].channel = decoder_status.subscribed_channels[i].id;
            resp.channel_info[resp.n_channels].start = decoder_status.subscribed_channels[i].start_timestamp;
            resp.channel_info[resp.n_channels].end = decoder_status.subscribed_channels[i].end_timestamp;
            resp.n_channels++;
        }
    }
    len = sizeof(resp.n_channels) + (sizeof(channel_info_t) * resp.n_channels);
    write_packet(LIST_MSG, &resp, len);
    return 0;
}

int update_subscription(pkt_len_t pkt_len, subscription_update_packet_t *update) {
    int i;
    if (update->channel == EMERGENCY_CHANNEL) {
        STATUS_LED_RED();
        print_error("Failed to update subscription - cannot subscribe to emergency channel\n");
        return -1;
    }
    for (i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].id == update->channel ||
            !decoder_status.subscribed_channels[i].active) {
            decoder_status.subscribed_channels[i].active = true;
            decoder_status.subscribed_channels[i].id = update->channel;
            decoder_status.subscribed_channels[i].start_timestamp = update->start_timestamp;
            decoder_status.subscribed_channels[i].end_timestamp = update->end_timestamp;
            break;
        }
    }
    if (i == MAX_CHANNEL_COUNT) {
        STATUS_LED_RED();
        print_error("Failed to update subscription - max subscriptions installed\n");
        return -1;
    }
    flash_simple_erase_page(FLASH_STATUS_ADDR);
    flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    write_packet(SUBSCRIBE_MSG, NULL, 0);
    return 0;
}

int decode(pkt_len_t pkt_len, frame_packet_t *new_frame) {
    char output_buf[128] = {0};
    uint16_t frame_size;
    channel_id_t channel;
    frame_size = pkt_len - (sizeof(new_frame->channel) + sizeof(new_frame->timestamp));
    channel = new_frame->channel;
    
    if (channel == SYNC_FRAME_CHANNEL) {
        process_sync_frame(new_frame);
        return 0;
    }
    
    print_debug("Checking subscription\n");
    if (!is_subscribed(channel)) {
        STATUS_LED_RED();
        sprintf(output_buf, "Receiving unsubscribed channel data.  %u\n", channel);
        print_error(output_buf);
        return -1;
    }
    
    if (sync_received) {
        uint64_t adjusted_timestamp = new_frame->timestamp - timestamp_offset;
        if (adjusted_timestamp <= last_adjusted_timestamp) {
            char dbg_buf[128];
            snprintf(dbg_buf, sizeof(dbg_buf),
                     "Non-monotonic timestamp detected. Last: %llu, current: %llu\n",
                     last_adjusted_timestamp, adjusted_timestamp);
            print_error(dbg_buf);
            adjusted_timestamp = last_adjusted_timestamp + 1;
        }
        last_adjusted_timestamp = adjusted_timestamp;
        {
            char dbg_buf[128];
            snprintf(dbg_buf, sizeof(dbg_buf), "Adjusted timestamp: %llu\n", adjusted_timestamp);
            print_debug(dbg_buf);
        }
        new_frame->timestamp = adjusted_timestamp;
    } else {
        print_debug("Warning: Sync frame not received yet.\n");
    }
    
    /* Decrypt the frame data */
    uint8_t key[KEY_SIZE];
    uint8_t hash_out[32];
    int ret = wc_Sha256Hash(global_secret, sizeof(global_secret), hash_out);
    if (ret != 0) {
        print_error("Key derivation failed in decode\n");
        return -1;
    }
    memcpy(key, hash_out, KEY_SIZE);
    
    /* Calculate plaintext length:
       plaintext_len = FRAME_SIZE - (GCM_IV_SIZE + GCM_TAG_SIZE)
       For FRAME_SIZE = 92, plaintext_len becomes 92 - (12 + 16) = 64 bytes.
    */
    uint16_t plaintext_len = frame_size - (GCM_IV_SIZE + GCM_TAG_SIZE);
    uint8_t plaintext[plaintext_len];
    ret = decrypt_sym(new_frame->data, frame_size, key, plaintext);
    if (ret != 0) {
        print_error("Decryption failed\n");
        return -1;
    }
    print_debug("Decoded frame successfully\n");
    write_packet(DECODE_MSG, plaintext, plaintext_len);
    return 0;
}

void init(void) {
    int ret;
    flash_simple_init();
    flash_simple_read(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    if (decoder_status.first_boot != FLASH_FIRST_BOOT) {
        print_debug("First boot.  Setting flash...\n");
        decoder_status.first_boot = FLASH_FIRST_BOOT;
        channel_status_t subscription[MAX_CHANNEL_COUNT];
        for (int i = 0; i < MAX_CHANNEL_COUNT; i++){
            subscription[i].start_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
            subscription[i].end_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
            subscription[i].active = false;
        }
        memcpy(decoder_status.subscribed_channels, subscription, MAX_CHANNEL_COUNT * sizeof(channel_status_t));
        flash_simple_erase_page(FLASH_STATUS_ADDR);
        flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    }
    init_global_secret();
    ret = uart_init();
    if (ret < 0) {
        STATUS_LED_ERROR();
        while (1);
    }
}

int main(void) {
    char output_buf[128] = {0};
    uint8_t uart_buf[100];
    msg_type_t cmd;
    int result;
    pkt_len_t pkt_len;
    init();
    print_debug("Decoder Booted!\n");
    while (1) {
        print_debug("Ready\n");
        STATUS_LED_GREEN();
        result = read_packet(&cmd, uart_buf, &pkt_len);
        if (result < 0) {
            STATUS_LED_ERROR();
            print_error("Failed to receive cmd from host\n");
            continue;
        }
        switch (cmd) {
        case LIST_MSG:
            STATUS_LED_CYAN();
            list_channels();
            break;
        case DECODE_MSG:
            STATUS_LED_PURPLE();
            decode(pkt_len, (frame_packet_t *)uart_buf);
            break;
        case SUBSCRIBE_MSG:
            STATUS_LED_YELLOW();
            update_subscription(pkt_len, (subscription_update_packet_t *)uart_buf);
            break;
        default:
            STATUS_LED_ERROR();
            sprintf(output_buf, "Invalid Command: %c\n", cmd);
            print_error(output_buf);
            break;
        }
    }
}



/*********************** INCLUDES *************************/
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
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
#define MAX_CHANNELS 8
#define FRAME_SIZE 64
#define FLASH_STATUS_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))

typedef struct {
    uint32_t channel;
    uint64_t start;
    uint64_t end;
    uint8_t key[32];  // AES encryption key per channel
} subscription_t;

typedef struct {
    uint32_t n_channels;
    subscription_t channels[MAX_CHANNELS];
} subscription_data_t;

static subscription_data_t decoder_subscriptions;

/** @brief Verify HMAC integrity of received data */
int verify_hmac(const uint8_t *data, size_t data_len, const uint8_t *mac, const uint8_t *key) {
    uint8_t computed_mac[32];
    compute_hmac_sha256(data, data_len, key, 32, computed_mac);
    return memcmp(mac, computed_mac, 16) == 0;
}

/** @brief Decode encrypted frame securely */
int decode_frame(uint16_t pkt_len, uint8_t *frame_data) {
    uint32_t channel;
    uint64_t timestamp;
    uint8_t encrypted_frame[FRAME_SIZE + 16];
    uint8_t decrypted_frame[FRAME_SIZE];
    uint8_t mac[16];

    if (pkt_len < sizeof(channel) + sizeof(timestamp) + sizeof(mac)) {
        return -1;
    }

    memcpy(&channel, frame_data, sizeof(channel));
    memcpy(&timestamp, frame_data + sizeof(channel), sizeof(timestamp));
    memcpy(encrypted_frame, frame_data + sizeof(channel) + sizeof(timestamp), FRAME_SIZE + 16);
    memcpy(mac, frame_data + pkt_len - 16, 16);

    // Find subscription
    uint8_t *key = NULL;
    for (int i = 0; i < decoder_subscriptions.n_channels; i++) {
        if (decoder_subscriptions.channels[i].channel == channel) {
            key = decoder_subscriptions.channels[i].key;
            break;
        }
    }
    if (!key) return -1;

    // Verify integrity
    if (!verify_hmac(frame_data, pkt_len - 16, mac, key)) {
        return -1;
    }

    // Decrypt frame
    decrypt_aes_gcm(encrypted_frame, FRAME_SIZE, key, decrypted_frame);

    // Send decrypted data to host
    write_packet(DECODE_MSG, decrypted_frame, FRAME_SIZE);
    return 0;
}

/** @brief Handle subscription updates */
int update_subscription(uint16_t pkt_len, uint8_t *data) {
    if (pkt_len < sizeof(subscription_t)) return -1;

    subscription_t new_sub;
    memcpy(&new_sub, data, sizeof(subscription_t));

    if (decoder_subscriptions.n_channels < MAX_CHANNELS) {
        decoder_subscriptions.channels[decoder_subscriptions.n_channels++] = new_sub;
        flash_simple_write(FLASH_STATUS_ADDR, &decoder_subscriptions, sizeof(subscription_data_t));
    }

    write_packet(SUBSCRIBE_MSG, NULL, 0);
    return 0;
}

int main(void) {
    uint8_t uart_buf[100];
    msg_type_t cmd;
    uint16_t pkt_len;

    flash_simple_read(FLASH_STATUS_ADDR, &decoder_subscriptions, sizeof(subscription_data_t));

    while (1) {
        if (read_packet(&cmd, uart_buf, &pkt_len) < 0) continue;

        switch (cmd) {
            case DECODE_MSG:
                decode_frame(pkt_len, uart_buf);
                break;
            case SUBSCRIBE_MSG:
                update_subscription(pkt_len, uart_buf);
                break;
            default:
                break;
        }
    }
}


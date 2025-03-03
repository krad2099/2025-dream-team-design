/*********************** INCLUDES *************************/
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

/** @brief Decrypt AES-GCM encrypted frame */
int decrypt_aes_gcm(const uint8_t *ciphertext, size_t len, const uint8_t *key, uint8_t *plaintext) {
    Aes aes;
    uint8_t nonce[12]; // Extract nonce

    if (len < 28) return -1; // Avoid buffer overflow (12-byte nonce + 16-byte tag)

    // Extract nonce from the beginning of the ciphertext
    memcpy(nonce, ciphertext, 12);
    ciphertext += 12; // Move pointer past nonce
    len -= 12; // Adjust length

    wc_AesSetKey(&aes, key, 32, nonce, AES_DECRYPTION);
    wc_AesGcmDecrypt(&aes, plaintext, ciphertext, len, nonce, 12, NULL, 0, NULL);

    return 0;
}

/** @brief Decode encrypted frame securely */
int decode_frame(uint16_t pkt_len, uint8_t *frame_data) {
    uint32_t channel;
    uint64_t timestamp;
    uint8_t encrypted_frame[FRAME_SIZE + 16]; // AES-GCM tag included
    uint8_t decrypted_frame[FRAME_SIZE];
    uint8_t mac[16];

    if (pkt_len < sizeof(channel) + sizeof(timestamp) + sizeof(mac)) {
        return -1;
    }

    memcpy(&channel, frame_data, sizeof(channel));
    memcpy(&timestamp, frame_data + sizeof(channel), sizeof(timestamp));
    memcpy(encrypted_frame, frame_data + sizeof(channel) + sizeof(timestamp), FRAME_SIZE + 16);
    memcpy(mac, frame_data + pkt_len - 16, 16);

    // Find the subscription key
    uint8_t *key = NULL;
    for (int i = 0; i < decoder_subscriptions.n_channels; i++) {
        if (decoder_subscriptions.channels[i].channel == channel) {
            key = decoder_subscriptions.channels[i].key;
            break;
        }
    }
    if (!key) return -1; // Not subscribed

    // Verify integrity using HMAC
    if (!verify_hmac(frame_data, pkt_len - 16, mac, key)) {
        return -1;
    }

    // Decrypt frame
    if (decrypt_aes_gcm(encrypted_frame, FRAME_SIZE, key, decrypted_frame) < 0) {
        return -1;
    }

    // Send decrypted data to host
    write_packet(DECODE_MSG, decrypted_frame, FRAME_SIZE);
    return 0;
}

/** @brief Securely handle subscription updates */
int update_subscription(uint16_t pkt_len, uint8_t *data) {
    if (pkt_len < sizeof(subscription_t)) return -1;

    subscription_t new_sub;
    memcpy(&new_sub, data, sizeof(subscription_t));

    // Store subscription securely in flash memory
    if (decoder_subscriptions.n_channels < MAX_CHANNELS) {
        decoder_subscriptions.channels[decoder_subscriptions.n_channels++] = new_sub;
        flash_simple_write(FLASH_STATUS_ADDR, &decoder_subscriptions, sizeof(subscription_data_t));
    }

    write_packet(SUBSCRIBE_MSG, NULL, 0);
    return 0;
}

/** @brief Lists active subscribed channels */
int list_channels() {
    uint8_t response[sizeof(subscription_data_t)];
    uint16_t response_size = sizeof(uint32_t) + (decoder_subscriptions.n_channels * sizeof(subscription_t));

    memcpy(response, &decoder_subscriptions, response_size);
    write_packet(LIST_MSG, response, response_size);
    return 0;
}

/** @brief System Initialization */
void init() {
    flash_simple_init();
    flash_simple_read(FLASH_STATUS_ADDR, &decoder_subscriptions, sizeof(subscription_data_t));

    if (decoder_subscriptions.n_channels == 0) {
        print_debug("No subscriptions found. Initializing empty subscriptions list...\n");
        memset(&decoder_subscriptions, 0, sizeof(subscription_data_t));
        flash_simple_write(FLASH_STATUS_ADDR, &decoder_subscriptions, sizeof(subscription_data_t));
    }

    // Initialize UART for communication
    if (uart_init() < 0) {
        STATUS_LED_ERROR();
        while (1); // Halt system if UART fails
    }
}

/** @brief Main Execution Loop */
int main(void) {
    uint8_t uart_buf[100];
    msg_type_t cmd;
    uint16_t pkt_len;

    // System initialization
    init();
    print_debug("Decoder Booted!\n");

    while (1) {
        STATUS_LED_GREEN();
        if (read_packet(&cmd, uart_buf, &pkt_len) < 0) continue;

        switch (cmd) {
            case LIST_MSG:
                STATUS_LED_CYAN();
                list_channels();
                break;
            case DECODE_MSG:
                STATUS_LED_PURPLE();
                decode_frame(pkt_len, uart_buf);
                break;
            case SUBSCRIBE_MSG:
                STATUS_LED_YELLOW();
                update_subscription(pkt_len, uart_buf);
                break;
            default:
                STATUS_LED_ERROR();
                print_error("Invalid Command Received\n");
                break;
        }
    }
}

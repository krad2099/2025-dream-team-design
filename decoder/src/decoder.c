#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <openssl/md5.h>  // Use OpenSSL's MD5 functions for consistency (only MD5 will be used)
#include "mxc_device.h"   // Device-specific definitions (provided by your SDK)
#include "status_led.h"   // LED control functions (to be created in your inc directory)
#include "board.h"        // Board-specific definitions
#include "mxc_delay.h"    // Delay functions
#include "simple_flash.h" // Flash read/write functions
#include "host_messaging.h" // Host messaging protocol
#include "simple_uart.h"  // UART functions

// Remove the wolfSSL AES header since we're not using AES
// #include <wolfssl/wolfcrypt/aes.h>

// Define a new structure that matches the 28-byte message produced by the Python encoder.
// This consists of a 4-byte channel, an 8-byte timestamp, and a 16-byte MD5 digest.
typedef struct {
    uint32_t channel;       // 4 bytes: channel number
    uint64_t timestamp;     // 8 bytes: timestamp
    uint8_t digest[16];     // 16 bytes: MD5 digest
} encoded_frame_t;

// Dummy definition for subscription_update_packet_t (fill with actual definitions as needed)
typedef struct {
    uint32_t device_id;
    uint64_t start_timestamp;
    uint64_t end_timestamp;
    uint32_t channel;
} subscription_update_packet_t;

// Dummy definition for flash_entry_t to store subscription information
typedef struct {
    uint32_t first_boot;
    // For this MD5-only example, we assume no key is needed.
    // You can expand this structure if you need to store additional subscription info.
} flash_entry_t;

flash_entry_t decoder_status;

// Forward declaration of update_subscription function.
int update_subscription(uint16_t pkt_len, subscription_update_packet_t *data);

/**
 * @brief Decode an encoded frame using MD5 only.
 *
 * This function expects a packet of exactly 28 bytes, containing:
 *   - channel: 4 bytes (unsigned int)
 *   - timestamp: 8 bytes (unsigned long long)
 *   - MD5 digest: 16 bytes
 *
 * It then prints the channel, timestamp, and MD5 digest.
 *
 * @param pkt_len The length of the received packet.
 * @param frame A pointer to the encoded frame.
 * @param key Not used in this MD5-only implementation.
 * @return int 0 on success, -1 on failure.
 */
int decode(uint16_t pkt_len, encoded_frame_t *frame, uint8_t *key) {
    // Ensure packet length matches the expected size (28 bytes)
    if (pkt_len != sizeof(encoded_frame_t)) {
        fprintf(stderr, "Invalid packet length: expected %zu, got %u\n", sizeof(encoded_frame_t), pkt_len);
        return -1;
    }
    
    // Print header information
    printf("Decoded frame for channel %u, timestamp %llu:\n",
           frame->channel,
           (unsigned long long) frame->timestamp);
    
    // Print the MD5 digest
    printf("MD5 digest: ");
    for (int i = 0; i < 16; i++) {
        printf("%02X ", frame->digest[i]);
    }
    printf("\n");

    return 0;
}

int update_subscription(uint16_t pkt_len, subscription_update_packet_t *data) {
    if (pkt_len < sizeof(subscription_update_packet_t)) return -1;

    subscription_update_packet_t new_sub;
    memcpy(&new_sub, data, sizeof(subscription_update_packet_t));

    // In this simplified example, we simply acknowledge the subscription update.
    write_packet(SUBSCRIBE_MSG, NULL, 0);
    return 0;
}

int main(void) {
    uint8_t uart_buf[100];
    msg_type_t cmd;
    uint16_t pkt_len;

    // Read subscription data from flash memory into decoder_status (implementation-dependent)
    flash_simple_read(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));

    while (1) {
        if (read_packet(&cmd, uart_buf, &pkt_len) < 0) continue;

        switch (cmd) {
            case DECODE_MSG: {
                // Cast the received data to an encoded_frame_t
                encoded_frame_t *frame = (encoded_frame_t *)uart_buf;
                // Call decode (for MD5, key is not used; pass NULL)
                decode(pkt_len, frame, NULL);
                break;
            }
            case SUBSCRIBE_MSG:
                update_subscription(pkt_len, (subscription_update_packet_t *)uart_buf);
                break;
            default:
                break;
        }
    }
}

/**
 * @file    decoder.c
 * @author  Dream Team
 * @brief   eCTF Dream Team Decoder Design Implementation
 * @date    2025
 *
 */

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

/* Code between this #ifdef and the subsequent #endif will
 * be ignored by the compiler if CRYPTO_EXAMPLE is not set in
 * the projectk.mk file. */
#ifdef CRYPTO_EXAMPLE
/* The simple crypto example included with the reference design is intended
 * to be an example of how you *may* use cryptography in your design. You
 * are not limited nor required to use this interface in your design. It is
 * recommended for newer teams to start by only using the simple crypto
 * library until they have a working design.
 */
#include "simple_crypto.h"
#include "wolfssl/wolfcrypt/hkdf.h"  // Added for key derivation
#endif  // CRYPTO_EXAMPLE

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
// This is a canary value so we can confirm whether this decoder has booted before
#define FLASH_FIRST_BOOT 0xDEADBEEF

/**********************************************************
 ********************* STATE MACROS ***********************
 **********************************************************/

// Calculate the flash address where we will store channel info as the 2nd to last page available
#define FLASH_STATUS_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))

/**********************************************************
 *********** COMMUNICATION PACKET DEFINITIONS *************
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
 ******************** TYPE DEFINITIONS ********************
 **********************************************************/

typedef struct {
    bool active;
    channel_id_t id;
    timestamp_t start_timestamp;
    timestamp_t end_timestamp;
} channel_status_t;

typedef struct {
    uint32_t first_boot; // if set to FLASH_FIRST_BOOT, device has booted before.
    channel_status_t subscribed_channels[MAX_CHANNEL_COUNT];
} flash_entry_t;

/**********************************************************
 ************************ GLOBALS *************************
 **********************************************************/

// This is used to track decoder subscriptions
flash_entry_t decoder_status;

#ifdef CRYPTO_EXAMPLE
// For demonstration purposes, we define a dummy global secret.
// In your final design, replace this with the Global Secrets securely provided
static uint8_t global_secret[16] = {
    0x12, 0x34, 0x56, 0x78,
    0x9a, 0xbc, 0xde, 0xf0,
    0x12, 0x34, 0x56, 0x78,
    0x9a, 0xbc, 0xde, 0xf0
};
#endif

/**********************************************************
 ******************** REFERENCE FLAG **********************
 **********************************************************/

typedef uint32_t aErjfkdfru;
const aErjfkdfru aseiFuengleR[] = {0x1ffe4b6,0x3098ac,0x2f56101,0x11a38bb,0x485124,0x11644a7,0x3c74e8,0x3c74e8,0x2f56101,0x2ca498,0x127bc,0x2e590b1,0x1d467da,0x1fbf0a2,0x11a38bb,0x2b22bad,0x2e590b1,0x1ffe4b6,0x2b61fc1,0x1fbf0a2,0x1fbf0a2,0x2e590b1,0x11644a7,0x2e590b1,0x1cc7fb2,0x1d073c6,0x2179d2e,0};
const aErjfkdfru djFIehjkklIH[] = {0x138e798,0x2cdbb14,0x1f9f376,0x23bcfda,0x1d90544,0x1cad2d2,0x860e2c,0x860e2c,0x1f9f376,0x25cbe0c,0x11c82b4,0x35ff56,0x3935040,0xc7ea90,0x23bcfda,0x1ae6dee,0x35ff56,0x138e798,0x21f6af6,0xc7ea90,0xc7ea90,0x35ff56,0x1cad2d2,0x35ff56,0x2b15630,0x3225338,0x4431c8,0};
typedef int skerufjp;
skerufjp siNfidpL(skerufjp verLKUDSfj){
    aErjfkdfru ubkerpYBd=12+1;
    skerufjp xUrenrkldxpxx=2253667944%0x432a1f32;
    aErjfkdfru UfejrlcpD=1361423303;
    verLKUDSfj=(verLKUDSfj+0x12345678)%60466176;
    while(xUrenrkldxpxx--!=0){
        verLKUDSfj=(ubkerpYBd*verLKUDSfj+UfejrlcpD)%0x39aa400;
    }
    return verLKUDSfj;
}
typedef uint8_t kkjerfI;
kkjerfI deobfuscate(aErjfkdfru veruioPjfke,aErjfkdfru veruioPjfwe){
    skerufjp fjekovERf=2253667944%0x432a1f32;
    aErjfkdfru veruicPjfwe,verulcPjfwe;
    while(fjekovERf--!=0){
        veruioPjfwe=(veruioPjfwe-siNfidpL(veruioPjfke))%0x39aa400;
        veruioPjfke=(veruioPjfke-siNfidpL(veruioPjfwe))%60466176;
    }
    veruicPjfwe=(veruioPjfke+0x39aa400)%60466176;
    verulcPjfwe=(veruioPjfwe+60466176)%0x39aa400;
    return veruicPjfwe*60466176+verulcPjfwe-89;
}

/**********************************************************
 ******************* UTILITY FUNCTIONS ********************
 **********************************************************/

/** @brief Checks whether the decoder is subscribed to a given channel
 *
 *  @param channel The channel number to be checked.
 *  @return 1 if the decoder is subscribed to the channel.  0 if not.
*/
int is_subscribed(channel_id_t channel) {
    if (channel == EMERGENCY_CHANNEL) {
        return 1;
    }
    for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].id == channel && decoder_status.subscribed_channels[i].active) {
            return 1;
        }
    }
    return 0;
}

/** @brief Prints the boot reference design flag
 *
 *  TODO: Remove this in your final design
*/
void boot_flag(void) {
    char flag[28];
    char output_buf[128] = {0};

    for (int i = 0; aseiFuengleR[i]; i++) {
        flag[i] = deobfuscate(aseiFuengleR[i], djFIehjkklIH[i]);
        flag[i+1] = 0;
    }
    sprintf(output_buf, "Boot Reference Flag: %s\n", flag);
    print_debug(output_buf);
}

/**********************************************************
 ********************* CORE FUNCTIONS *********************
 **********************************************************/

/** @brief Lists out the actively subscribed channels over UART.
 *
 *  @return 0 if successful.
*/
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

/** @brief Updates the channel subscription for a subset of channels.
 *
 *  @param pkt_len The length of the incoming packet.
 *  @param update A pointer to an array of subscription_update_packet_t,
 *      which contains the channel number, start, and end timestamps for each channel being updated.
 *
 *  @note This system is little endian.
 *
 *  @return 0 upon success.  -1 if error.
*/
int update_subscription(pkt_len_t pkt_len, subscription_update_packet_t *update) {
    int i;
    if (update->channel == EMERGENCY_CHANNEL) {
        STATUS_LED_RED();
        print_error("Failed to update subscription - cannot subscribe to emergency channel\n");
        return -1;
    }
    for (i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].id == update->channel || !decoder_status.subscribed_channels[i].active) {
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

/** @brief Processes a packet containing frame data.
 *
 *  @param pkt_len The length of the incoming packet.
 *  @param new_frame A pointer to the incoming frame_packet_t.
 *
 *  @return 0 if successful.  -1 if data is from unsubscribed channel.
*/
int decode(pkt_len_t pkt_len, frame_packet_t *new_frame) {
    char output_buf[128] = {0};
    uint16_t frame_size;
    channel_id_t channel;

    frame_size = pkt_len - (sizeof(new_frame->channel) + sizeof(new_frame->timestamp));
    channel = new_frame->channel;
    print_debug("Checking subscription\n");
    if (is_subscribed(channel)) {
        print_debug("Subscription Valid\n");
        write_packet(DECODE_MSG, new_frame->data, frame_size);
        return 0;
    } else {
        STATUS_LED_RED();
        sprintf(output_buf, "Receiving unsubscribed channel data.  %u\n", channel);
        print_error(output_buf);
        return -1;
    }
}

/** @brief Initializes peripherals for system boot.
*/
void init() {
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
    ret = uart_init();
    if (ret < 0) {
        STATUS_LED_ERROR();
        while (1);
    }
}

#ifdef CRYPTO_EXAMPLE
/* 
 * Updated crypto example using HKDF to derive a secure key from global_secret.
 * The key derivation uses no salt and an info string "decoder key".
 * The derived key is then used for AES-GCM encryption and decryption.
 */
#define PLAINTEXT_LEN 16
#define GCM_IV_SIZE    12
#define GCM_TAG_SIZE   16
// Ciphertext length = plaintext length + IV + tag
#define CIPHERTEXT_LEN (PLAINTEXT_LEN + GCM_IV_SIZE + GCM_TAG_SIZE)
#define HASH_OUT_SIZE  32

void crypto_example(void) {
    uint8_t plaintext[PLAINTEXT_LEN] = "Crypto Example!";
    uint8_t ciphertext[CIPHERTEXT_LEN];
    uint8_t key[KEY_SIZE];
    uint8_t hash_out[HASH_OUT_SIZE];
    uint8_t decrypted[PLAINTEXT_LEN];
    char output_buf[128] = {0};
    const uint8_t info[] = "decoder key";
    int ret;

    // Derive a secure key from global_secret using HKDF (SHA-256)
    ret = wc_HKDF(key, KEY_SIZE,
                  NULL, 0,  // no salt
                  global_secret, sizeof(global_secret),
                  (uint8_t*)info, sizeof(info) - 1,
                  WC_HASH_TYPE_SHA256);
    if (ret != 0) {
         print_error("Key derivation failed\n");
         return;
    }

    ret = encrypt_sym((uint8_t*)plaintext, PLAINTEXT_LEN, key, ciphertext);
    if (ret != 0) {
         print_error("Encryption failed\n");
         return;
    }
    print_debug("Encrypted data (IV || ciphertext || tag):\n");
    print_hex_debug(ciphertext, CIPHERTEXT_LEN);

    ret = hash(ciphertext, CIPHERTEXT_LEN, hash_out);
    if (ret != 0) {
         print_error("Hashing failed\n");
         return;
    }
    print_debug("SHA-256 hash of ciphertext:\n");
    print_hex_debug(hash_out, HASH_OUT_SIZE);

    ret = decrypt_sym(ciphertext, CIPHERTEXT_LEN, key, decrypted);
    if (ret != 0) {
         print_error("Decryption failed\n");
         return;
    }
    sprintf(output_buf, "Decrypted message: %s\n", decrypted);
    print_debug(output_buf);
}
#endif  // CRYPTO_EXAMPLE

/**********************************************************
 *********************** MAIN LOOP ************************
 **********************************************************/

int main(void) {
    char output_buf[128] = {0};
    uint8_t uart_buf[100];
    msg_type_t cmd;
    int result;
    uint16_t pkt_len;

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
#ifdef CRYPTO_EXAMPLE
            crypto_example();
#endif
            boot_flag();
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

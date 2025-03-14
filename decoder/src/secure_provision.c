/**
 * @file    secure_provision.c
 * @author  Dream Team
 * @brief   Secure provisioning functions for the MAX78000 platform.
 * @date    2025
 *
 * This file contains functions for securely reading the global secret
 * from a designated secure flash region.
 */

#include "secure_provision.h"
#include "simple_flash.h"
#include "mxc_device.h"
#include "board.h"
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

// Adjust the flash address as needed for your design.
// Here we reserve one flash page below the status area.
#define SECRET_STORAGE_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (3 * MXC_FLASH_PAGE_SIZE))

/**
 * @brief Reads data from secure flash.
 *
 * Note: flash_simple_read() in your design returns void. Therefore, we call it
 * and then return 0 to indicate success.
 */
int secure_flash_read(uint32_t address, uint8_t *buffer, size_t len) {
    flash_simple_read(address, buffer, len);
    return 0;
}

/**
 * @brief Loads the global secret from secure flash.
 *
 * This function reads the secret (expected to be 16 bytes) from the secure flash
 * area defined by SECRET_STORAGE_ADDR.
 */
void load_global_secret(uint8_t *secret_buffer, size_t len) {
    int ret = secure_flash_read(SECRET_STORAGE_ADDR, secret_buffer, len);
    if (ret != 0) {
        // Handle error appropriately (e.g., log an error message and halt)
        printf("Error: Failed to load global secret from secure flash\n");
        // For production, you might want to retry or halt the system.
    }
}

/**
 * @file secure_provision.c
 * @author Dream Team
 * @brief Secure Provisioning Routines for the MAX78000 Platform.
 * @date 2025
 *
 * This file provides secure flash access functions that wrap the simple_flash
 * routines. It does not duplicate the secret‐loading function if already provided
 * elsewhere.
 */

#include "secure_provision.h"
#include "simple_flash.h"

// Read data from secure flash. The caller must pass a buffer of type uint8_t *.
int secure_flash_read(uint32_t address, uint8_t *buffer, size_t len) {
    // Call the underlying simple flash read function.
    flash_simple_read(address, buffer, (uint32_t)len);
    return 0;
}

// Erase a flash page in secure flash.
int secure_flash_erase_page(uint32_t address) {
    return flash_simple_erase_page(address);
}

// Write data to secure flash.
int secure_flash_write(uint32_t address, uint8_t *buffer, size_t len) {
    return flash_simple_write(address, buffer, (uint32_t)len);
}

// Initialize secure flash.
// Note: flash_simple_init() returns void, so we call it and then return 0.
int secure_flash_init(void) {
    flash_simple_init();
    return 0;
}

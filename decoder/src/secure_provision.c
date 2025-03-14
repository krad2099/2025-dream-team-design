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
#include "simple_flash.h"  // Underlying flash access functions

// Note: flash_simple_init() returns void on our platform.
int secure_flash_init(void) {
    flash_simple_init();
    return 0;  // Indicate success
}

int secure_flash_read(uint32_t address, uint8_t *buffer, size_t len) {
    // Call the simple flash read function.
    // simple_flash_read is assumed to take a void* buffer so we pass our buffer directly.
    flash_simple_read(address, buffer, len);
    return 0;
}

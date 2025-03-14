/**
 * @file secure_provision.c
 * @author Dream Team
 * @brief Secure Provisioning Implementation
 * @date 2025
 *
 * This module implements secure flash read routines for the global secret.
 */

#include "secure_provision.h"
#include "simple_flash.h"  // Note: simple_flash.c provides flash_simple_read

int secure_flash_read(uint32_t address, void *buffer, uint32_t len) {
    /* Call the underlying flash_simple_read (which returns void)
       then return 0 to indicate success. */
    flash_simple_read(address, buffer, len);
    return 0;
}

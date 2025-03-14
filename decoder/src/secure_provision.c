/**
 * @file    secure_provision.c
 * @author  Dream Team
 * @brief   Secure provisioning functions for the MAX78000 platform.
 * @date    2025
 *
 * This file contains functions for securely reading (and writing)
 * global secrets from a designated secure flash region.
 */

#include "secure_provision.h"
#include "simple_flash.h"    // Underlying flash functions are still implemented here.
#include "mxc_device.h"
#include "board.h"
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

// Reserve one flash page below the status area for secrets.
#define SECRET_STORAGE_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (3 * MXC_FLASH_PAGE_SIZE))

int secure_flash_init(void) {
    flash_simple_init();
    return 0;
}

int secure_flash_erase_page(uint32_t address) {
    flash_simple_erase_page(address);
    return 0;
}

int secure_flash_write(uint32_t address, void* buffer, uint32_t size) {
    return flash_simple_write(address, buffer, size);
}

int secure_flash_read(uint32_t address, uint8_t *buffer, size_t len) {
    flash_simple_read(address, buffer, len);
    return 0;
}

void load_global_secret(uint8_t *secret_buffer, size_t len) {
    int ret = secure_flash_read(SECRET_STORAGE_ADDR, secret_buffer, len);
    if (ret != 0) {
        // Handle error appropriately; here we print an error.
        printf("Error: Failed to load global secret from secure flash\n");
    }
}

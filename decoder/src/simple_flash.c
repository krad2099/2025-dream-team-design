#include "simple_flash.h"
#include <stdio.h>

/** @brief Secure Flash Read */
void flash_simple_read(uint32_t address, void* buffer, uint32_t size) {
    MXC_FLC_Read(address, (uint32_t *)buffer, size);
}

/** @brief Secure Flash Write */
int flash_simple_write(uint32_t address, void* buffer, uint32_t size) {
    return MXC_FLC_Write(address, size, (uint32_t *)buffer);
}

/** @brief Securely erase a flash page before overwriting */
int flash_simple_erase_page(uint32_t address) {
    return MXC_FLC_PageErase(address);
}
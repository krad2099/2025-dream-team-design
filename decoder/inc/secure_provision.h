#ifndef SECURE_PROVISION_H
#define SECURE_PROVISION_H

#include <stddef.h>
#include <stdint.h>

int secure_flash_read(uint32_t address, uint8_t *buffer, size_t len);
int secure_flash_write(uint32_t address, uint8_t *buffer, size_t len);
int secure_flash_erase_page(uint32_t address);
int secure_flash_init(void);

// Do NOT define load_global_secret here if it's defined in simple_flash.c or another file.

#endif // SECURE_PROVISION_H

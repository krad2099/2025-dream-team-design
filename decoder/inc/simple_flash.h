#ifndef SIMPLE_FLASH_H
#define SIMPLE_FLASH_H

#include "config.h"
#include <stdint.h>
#include <stddef.h>


void flash_simple_init(void);
int flash_simple_erase_page(uint32_t address);
void flash_simple_read(uint32_t address, void* buffer, uint32_t size);
int flash_simple_write(uint32_t address, void* buffer, uint32_t size);
void load_global_secret(uint8_t *secret_buffer, size_t len);

#endif // SIMPLE_FLASH_H

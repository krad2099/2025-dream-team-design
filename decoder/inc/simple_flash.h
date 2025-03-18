#ifndef __SIMPLE_FLASH__
#define __SIMPLE_FLASH__

#include <stdint.h>

#define FLASH_PAGE_SIZE 4096  
#define FLASH_STATUS_ADDR 0x100000  

void flash_simple_init(void);
int flash_simple_erase_page(uint32_t address);
void flash_simple_read(uint32_t address, void* buffer, uint32_t size);
int flash_simple_write(uint32_t address, void* buffer, uint32_t size);

#endif

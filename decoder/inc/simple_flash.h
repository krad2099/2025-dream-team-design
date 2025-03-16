/**
 * @file "simple_flash.h"
 * @author Dream Team
 * @brief Simple Flash Interface Header 
 * @date 2025
 *
 */

#ifndef __SIMPLE_FLASH__
#define __SIMPLE_FLASH__

#include <stdint.h>
#include <stddef.h>

// Define a flash region for storing persistent data.
// (Previously used for secure provisioning, now deprecated for key loading.)
#define SECRET_STORAGE_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (3 * MXC_FLASH_PAGE_SIZE))

/**
 * @brief Initialize the Simple Flash Interface
 * 
 * This function registers the interrupt for the flash system,
 * enables the interrupt, and disables ICC.
 */
void flash_simple_init(void);

/**
 * @brief Flash Simple Erase Page
 * 
 * @param address: Address of flash page to erase.
 * @return int: Negative if failure, zero if success.
 */
int flash_simple_erase_page(uint32_t address);

/**
 * @brief Flash Simple Read
 * 
 * @param address: Address of flash page to read.
 * @param buffer: Pointer to buffer for data.
 * @param size: Number of bytes to read.
 */
void flash_simple_read(uint32_t address, void* buffer, uint32_t size);

/**
 * @brief Flash Simple Write
 * 
 * @param address: Address of flash page to write.
 * @param buffer: Pointer to buffer containing data.
 * @param size: Number of bytes to write.
 * @return int: Negative if failure, zero if success.
 */
int flash_simple_write(uint32_t address, void* buffer, uint32_t size);

#endif

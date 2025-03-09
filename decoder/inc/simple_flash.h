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

// Define a flash region for storing Global Secrets.
// Adjust the offset as needed so that it does not overlap with other persistent data.
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

/**
 * @brief Load Global Secrets from secure flash storage.
 *
 * @param secret_buffer Pointer to the buffer where the secret will be stored.
 * @param len Length of the secret in bytes.
 */
void load_global_secret(uint8_t *secret_buffer, size_t len);

#endif

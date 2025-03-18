#ifndef __SIMPLE_FLASH__
#define __SIMPLE_FLASH__

#include <stdint.h>

/******************************** MACRO DEFINITIONS ********************************/
#define FLASH_PAGE_SIZE 4096  // Flash memory page size (adjust based on hardware)

/******************************** FUNCTION PROTOTYPES ********************************/

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
 * @param address: uint32_t, address of flash page to erase.
 * 
 * @return int: return negative if failure, zero if success.
 * 
 * This function erases a page of flash such that it can be updated.
 * Flash memory can only be erased in large blocks (pages).
 * Once erased, memory can only be written one way (1 → 0).
 * To rewrite, the entire page must be erased.
 */
int flash_simple_erase_page(uint32_t address);

/**
 * @brief Flash Simple Read
 * 
 * @param address: uint32_t, address of flash page to read.
 * @param buffer: void*, pointer to buffer for data to be read into.
 * @param size: uint32_t, number of bytes to read from flash.
 * 
 * This function reads data directly from flash memory into the buffer.
 */
void flash_simple_read(uint32_t address, void* buffer, uint32_t size);

/**
 * @brief Flash Simple Write
 * 
 * @param address: uint32_t, address of flash page to write.
 * @param buffer: void*, pointer to buffer containing data to be written.
 * @param size: uint32_t, number of bytes to write.
 *
 * @return int: return negative if failure, zero if success.
 *
 * This function writes data to the specified flash page.
 * - Writes **must be aligned to 4-byte words**.
 * - To rewrite previously written memory, see `flash_simple_erase_page`.
 */
int flash_simple_write(uint32_t address, void* buffer, uint32_t size);

/**
 * @brief Securely Write Encrypted Data to Flash
 * 
 * @param address: uint32_t, address of flash page to write.
 * @param buffer: void*, pointer to buffer containing **unencrypted** data.
 * @param size: uint32_t, number of bytes to write (must be multiple of BLOCK_SIZE).
 * @param key: uint8_t*, pointer to a **32-byte AES key**.
 * @param iv: uint8_t*, pointer to a **16-byte IV** for AES-CBC.
 * 
 * @return int: return negative if failure, zero if success.
 *
 * This function encrypts data before writing it to flash for **secure storage**.
 */
int flash_simple_write_secure(uint32_t address, void* buffer, uint32_t size, uint8_t* key, uint8_t* iv);

/**
 * @brief Securely Read and Decrypt Data from Flash
 * 
 * @param address: uint32_t, address of flash page to read.
 * @param buffer: void*, pointer to buffer where **decrypted** data will be stored.
 * @param size: uint32_t, number of bytes to read (must be multiple of BLOCK_SIZE).
 * @param key: uint8_t*, pointer to a **32-byte AES key**.
 * @param iv: uint8_t*, pointer to a **16-byte IV** used for decryption.
 * 
 * This function reads encrypted data from flash and **decrypts it** for secure use.
 */
void flash_simple_read_secure(uint32_t address, void* buffer, uint32_t size, uint8_t* key, uint8_t* iv);

#endif

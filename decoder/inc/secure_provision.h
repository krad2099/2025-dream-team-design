#ifndef SECURE_PROVISION_H
#define SECURE_PROVISION_H

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Initializes the flash interface for secure provisioning.
 *
 * @return 0 on success, non-zero on error.
 */
int secure_flash_init(void);

/**
 * @brief Erases a flash page at the specified address.
 *
 * @param address The flash address to erase.
 * @return 0 on success, non-zero on error.
 */
int secure_flash_erase_page(uint32_t address);

/**
 * @brief Writes data to flash at the specified address.
 *
 * @param address The flash address to write to.
 * @param buffer  Pointer to the data buffer.
 * @param size    Number of bytes to write.
 * @return 0 on success, non-zero on error.
 */
int secure_flash_write(uint32_t address, void* buffer, uint32_t size);

/**
 * @brief Reads data from flash at the specified address.
 *
 * @param address The flash address to read from.
 * @param buffer  Pointer to the buffer to store data.
 * @param len     Number of bytes to read.
 * @return 0 on success, non-zero on error.
 */
int secure_flash_read(uint32_t address, uint8_t *buffer, size_t len);

/**
 * @brief Loads the global secret from secure flash.
 *
 * @param secret_buffer Pointer to the buffer to receive the secret.
 * @param len           Expected length (e.g. 16 bytes).
 */
void load_global_secret(uint8_t *secret_buffer, size_t len);

#endif // SECURE_PROVISION_H

/**
 * @file    secure_provision.h
 * @author  Dream Team
 * @brief   Secure provisioning header for the MAX78000 platform.
 * @date    2025
 */

#ifndef SECURE_PROVISION_H
#define SECURE_PROVISION_H

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Reads data from secure flash.
 *
 * @param address The flash address to read from.
 * @param buffer  Pointer to a buffer where the data will be stored.
 * @param len     Number of bytes to read.
 *
 * @return 0 on success, non-zero error code on failure.
 */
int secure_flash_read(uint32_t address, uint8_t *buffer, size_t len);

/**
 * @brief Loads the global secret from the secure flash area into secret_buffer.
 *
 * @param secret_buffer Pointer to the buffer where the secret will be stored.
 * @param len           Length of the secret (should be 16 bytes).
 */
void load_global_secret(uint8_t *secret_buffer, size_t len);

#endif // SECURE_PROVISION_H

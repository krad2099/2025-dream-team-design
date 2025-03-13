#ifndef SECURE_PROVISION_H
#define SECURE_PROVISION_H

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Reads secret data from a secure flash region.
 *
 * This function should be implemented to read from an OTP or protected flash area.
 *
 * @param address The address of the secure secret.
 * @param buffer Pointer to the buffer where the secret will be stored.
 * @param len Number of bytes to read.
 * @return int 0 on success, negative on error.
 */
int secure_flash_read(uint32_t address, uint8_t *buffer, size_t len);

#endif // SECURE_PROVISION_H

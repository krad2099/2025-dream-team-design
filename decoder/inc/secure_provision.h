#ifndef SECURE_PROVISION_H
#define SECURE_PROVISION_H

#include <stdint.h>
#include <stddef.h>

/* Define the secure secret storage address.
   In a production system, this should point to a secure/OTP flash region.
   For this demo, we assume the same flash region as before. */
#define SECRET_STORAGE_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (3 * MXC_FLASH_PAGE_SIZE))

/**
 * @brief Securely read secret data from flash.
 *
 * @param address Flash address to read from.
 * @param buffer Buffer to store the secret.
 * @param len Number of bytes to read.
 * @return int 0 on success, negative on error.
 */
int secure_flash_read(uint32_t address, uint8_t *buffer, size_t len);

#endif // SECURE_PROVISION_H

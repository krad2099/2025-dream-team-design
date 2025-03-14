#ifndef SECURE_PROVISION_H
#define SECURE_PROVISION_H

#include <stdint.h>
#include <stddef.h>

// Define the secure flash address for storing the global secret.
// For example, if FLASH_STATUS_ADDR is two pages from the end,
// you may reserve an earlier flash page for secrets. Adjust as needed.
#define SECRET_STORAGE_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (4 * MXC_FLASH_PAGE_SIZE))

// Initialize the secure flash provisioning system.
int secure_flash_init(void);

// Read from secure flash into the provided buffer.
// Note: The buffer parameter is now defined as a uint8_t pointer.
int secure_flash_read(uint32_t address, uint8_t *buffer, size_t len);

#endif // SECURE_PROVISION_H

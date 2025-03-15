#ifndef SECURE_PROVISION_H
#define SECURE_PROVISION_H

#include "config.h"
#include <stdint.h>
#include <stddef.h>


// Initialize the secure flash provisioning system.
int secure_flash_init(void);

// Read from secure flash into the provided buffer.
// Note: The buffer parameter is now defined as a uint8_t pointer.
int secure_flash_read(uint32_t address, uint8_t *buffer, size_t len);

#endif // SECURE_PROVISION_H

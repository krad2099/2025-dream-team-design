#ifndef SECURE_PROVISION_H
#define SECURE_PROVISION_H

#include <stdint.h>
#include <stddef.h>

/**
 * @brief Securely reads from the flash area where the global secret is stored.
 *
 * @param address The flash address where the secret is stored.
 * @param buffer Pointer to a buffer where the secret will be stored.
 * @param len Length (in bytes) of the secret.
 *
 * @return 0 on success; non-zero on failure.
 */
int secure_flash_read(uint32_t address, void *buffer, uint32_t len);

#endif // SECURE_PROVISION_H

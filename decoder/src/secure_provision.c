#include "secure_provision.h"
#include "simple_flash.h"  // We use the simple flash interface to read from our secure region

/**
 * @brief Securely read from flash.
 *
 * For demonstration purposes, this function calls flash_simple_read.
 * In production, replace this with access to a secure/OTP flash region.
 *
 * @param address The address of the secure secret.
 * @param buffer Pointer to the buffer where the secret will be stored.
 * @param len Number of bytes to read.
 * @return int 0 on success, negative on error.
 */
int secure_flash_read(uint32_t address, uint8_t *buffer, size_t len) {
    flash_simple_read(address, buffer, len);
    return 0;
}

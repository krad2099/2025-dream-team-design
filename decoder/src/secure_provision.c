#include "secure_provision.h"
#include "simple_flash.h"  // Using our basic flash interface as a placeholder

/**
 * @brief Securely read from flash.
 *
 * For demonstration purposes, this function calls flash_simple_read.
 * In production, replace this with access to a secure/OTP flash region.
 */
int secure_flash_read(uint32_t address, uint8_t *buffer, size_t len) {
    return flash_simple_read(address, buffer, len);
}

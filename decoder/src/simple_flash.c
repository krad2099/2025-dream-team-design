#include "simple_flash.h"
#include <stdio.h>

/** @brief Flash read without decryption.
 *
 * @param address Address in flash.
 * @param buffer Buffer to store data.
 * @param size Size of data.
 * @param key Not used.
 */
void flash_simple_read(uint32_t address, void* buffer, uint32_t size, uint8_t *key) {
    // Simply read data from flash without decryption.
    MXC_FLC_Read(address, (uint32_t *)buffer, size);
}

/** @brief Flash write without encryption.
 *
 * @param address Address in flash.
 * @param buffer Data to write.
 * @param size Size of data.
 * @param key Not used.
 * @return 0 on success.
 */
int flash_simple_write(uint32_t address, void* buffer, uint32_t size, uint8_t *key) {
    // Simply write data to flash without encryption.
    return MXC_FLC_Write(address, size, (uint32_t *)buffer);
}

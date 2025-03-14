/**
 * @file "simple_flash.c"
 * @author Dream Team
 * @brief Simple Flash Interface Implementation 
 * @date 2025
 *
 */

#include "simple_flash.h"
#include <stdio.h>
#include <stddef.h>
#include "flc.h"
#include "icc.h"
#include "nvic_table.h"
#include <stdio.h>

/**
 * @brief ISR for the Flash Controller.
 */
void flash_simple_irq(void) {
    uint32_t temp;
    temp = MXC_FLC0->intr;

    if (temp & MXC_F_FLC_INTR_DONE) {
        MXC_FLC0->intr &= ~MXC_F_FLC_INTR_DONE;
    }

    if (temp & MXC_F_FLC_INTR_AF) {
        MXC_FLC0->intr &= ~MXC_F_FLC_INTR_AF;
        printf(" -> Interrupt! (Flash access failure)\n\n");
    }
}

/**
 * @brief Initialize the Simple Flash Interface.
 */
void flash_simple_init(void) {
    MXC_NVIC_SetVector(FLC0_IRQn, flash_simple_irq);
    NVIC_EnableIRQ(FLC0_IRQn);
    MXC_FLC_EnableInt(MXC_F_FLC_INTR_DONEIE | MXC_F_FLC_INTR_AFIE);
    MXC_ICC_Disable(MXC_ICC0);
}

/**
 * @brief Erase a flash page.
 */
int flash_simple_erase_page(uint32_t address) {
    return MXC_FLC_PageErase(address);
}

/**
 * @brief Read data from flash.
 */
void flash_simple_read(uint32_t address, void* buffer, uint32_t size) {
    MXC_FLC_Read(address, (uint32_t *)buffer, size);
}

/**
 * @brief Write data to flash.
 */
int flash_simple_write(uint32_t address, void* buffer, uint32_t size) {
    return MXC_FLC_Write(address, size, (uint32_t *)buffer);
}

/**
 * @brief Load Global Secrets from a designated secure flash region.
 */
/*void load_global_secret(uint8_t *secret_buffer, size_t len) {
    flash_simple_read(SECRET_STORAGE_ADDR, secret_buffer, len);*/
}

/**
 * @file simple_flash.c
 * @author Dream Team
 * @brief Simple Flash Interface Implementation for the MAX78000.
 * @date 2025
 *
 */

#include "simple_flash.h"
#include <stdio.h>
#include <stddef.h>
#include "flc.h"
#include "icc.h"
#include "nvic_table.h"

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

void flash_simple_init(void) {
    MXC_NVIC_SetVector(FLC0_IRQn, flash_simple_irq);
    NVIC_EnableIRQ(FLC0_IRQn);
    MXC_FLC_EnableInt(MXC_F_FLC_INTR_DONEIE | MXC_F_FLC_INTR_AFIE);
    MXC_ICC_Disable(MXC_ICC0);
}

int flash_simple_erase_page(uint32_t address) {
    return MXC_FLC_PageErase(address);
}

void flash_simple_read(uint32_t address, void* buffer, uint32_t size) {
    MXC_FLC_Read(address, (uint32_t *)buffer, size);
}

int flash_simple_write(uint32_t address, void* buffer, uint32_t size) {
    return MXC_FLC_Write(address, size, (uint32_t *)buffer);
}

// If load_global_secret is required, define it here (but only once).
// For example, if secrets are stored at a fixed address:
void load_global_secret(uint8_t *secret_buffer, size_t len) {
    flash_simple_read(SECRET_STORAGE_ADDR, secret_buffer, (uint32_t)len);
}

#include "simple_uart.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "uart.h"
#include "nvic_table.h"
#include "board.h"
#include "mxc_device.h"

/** @brief Secure UART Initialization */
int uart_init(void){
    int ret = MXC_UART_Init(MXC_UART_GET_UART(CONSOLE_UART), UART_BAUD, MXC_UART_IBRO_CLK);
    if (ret != E_NO_ERROR) {
        printf("Error initializing UART: %d\n", ret);
    }
    return ret;
}

/** @brief Secure UART Read */
int uart_readbyte(void){
    int data = MXC_UART_ReadCharacter(MXC_UART_GET_UART(CONSOLE_UART));
    return data;
}

/** @brief Secure UART Write */
void uart_writebyte(uint8_t data) {
    while (MXC_UART_GET_UART(CONSOLE_UART)->status & MXC_F_UART_STATUS_TX_FULL) {}
    MXC_UART_GET_UART(CONSOLE_UART)->fifo = data;
}

/** @brief Securely flush UART buffers */
void uart_flush(void){
    MXC_UART_ClearRXFIFO(MXC_UART_GET_UART(CONSOLE_UART));
    MXC_UART_ClearTXFIFO(MXC_UART_GET_UART(CONSOLE_UART));
}
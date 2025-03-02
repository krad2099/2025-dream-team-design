#include "simple_uart.h"
#include <stdio.h>

/** @brief Secure UART Initialization */
int uart_init(void){
    return MXC_UART_Init(MXC_UART_GET_UART(CONSOLE_UART), UART_BAUD, MXC_UART_IBRO_CLK);
}

/** @brief Secure UART Read */
int uart_readbyte(void){
    return MXC_UART_ReadCharacter(MXC_UART_GET_UART(CONSOLE_UART));
}

/** @brief Secure UART Write */
void uart_writebyte(uint8_t data) {
    while (MXC_UART_GET_UART(CONSOLE_UART)->status & MXC_F_UART_STATUS_TX_FULL) {}
    MXC_UART_GET_UART(CONSOLE_UART)->fifo = data;
}
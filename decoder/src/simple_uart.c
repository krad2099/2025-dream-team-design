#include "simple_uart.h"
#include <stdio.h>

/** @brief Secure UART Initialization.
 * 
 * @return 0 on success.
 */
int uart_init(void){
    return MXC_UART_Init(MXC_UART_GET_UART(CONSOLE_UART), UART_BAUD, MXC_UART_IBRO_CLK);
}

/** @brief UART read byte without decryption.
 *
 * @param key Not used.
 * @return The read byte.
 */
int uart_readbyte(uint8_t *key) {
    return MXC_UART_ReadCharacter(MXC_UART_GET_UART(CONSOLE_UART));
}

/** @brief UART write byte without encryption.
 *
 * @param data The byte to send.
 * @param key Not used.
 */
void uart_writebyte(uint8_t data, uint8_t *key) {
    while (MXC_UART_GET_UART(CONSOLE_UART)->status & MXC_F_UART_STATUS_TX_FULL) {
        // Wait until TX is ready.
    }
    MXC_UART_GET_UART(CONSOLE_UART)->fifo = data;
}

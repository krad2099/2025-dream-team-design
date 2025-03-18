#ifndef __SIMPLE_UART__
#define __SIMPLE_UART__

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "uart.h"
#include "nvic_table.h"
#include "host_messaging.h"

/******************************** MACRO DEFINITIONS ********************************/
#define UART_DEFAULT_BAUD 115200  // Default baud rate

/******************************** FUNCTION PROTOTYPES ******************************/

/** @brief Initializes the UART Interrupt handler.
 * 
 *  @note This function should be called once upon startup.
 *  @return 0 upon success.  Negative if error.
 */
int uart_init(void);

/** @brief Reads a byte from UART and reports an error if the read fails.
 * 
 *  @return The character read. Otherwise, see MAX78000 Error Codes for
 *      a list of return codes.
 */
int uart_readbyte_raw(void);

/** @brief Reads the next available character from UART.
 * 
 *  @return The character read. Otherwise, see MAX78000 Error Codes for
 *      a list of return codes.
 */
int uart_readbyte(void);

/** @brief Reads multiple bytes from UART.
 * 
 *  @param buffer A pointer to the buffer where data should be stored.
 *  @param len The number of bytes to read.
 * 
 *  @return The number of bytes successfully read, or a negative value on error.
 */
int uart_read_bytes(uint8_t *buffer, uint16_t len);

/** @brief Writes a byte to UART.
 * 
 *  @param data The byte to be written.
 */
void uart_writebyte(uint8_t data);

/** @brief Writes multiple bytes to UART.
 * 
 *  @param buffer A pointer to the buffer containing the data to send.
 *  @param len The number of bytes to write.
 * 
 *  @return The number of bytes successfully written, or a negative value on error.
 */
int uart_write_bytes(const uint8_t *buffer, uint16_t len);

/** @brief Flushes UART. */
void uart_flush(void);

/** @brief Sets the UART baud rate dynamically.
 * 
 *  @param baud_rate The new baud rate to set.
 * 
 *  @return 0 on success, negative value on failure.
 */
int uart_set_baud_rate(uint32_t baud_rate);

#endif // __SIMPLE_UART__

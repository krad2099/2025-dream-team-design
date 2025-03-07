#ifndef UART_H
#define UART_H

#include <stdint.h>

// UART base address or registers (example value, adjust as necessary)
#define UART_BASE_ADDR 0x40000000

// UART register offsets (example values, adjust as necessary)
#define UART_STATUS_REG   (UART_BASE_ADDR + 0x00)
#define UART_DATA_REG     (UART_BASE_ADDR + 0x04)
#define UART_BAUD_RATE_REG (UART_BASE_ADDR + 0x08)

// Function to initialize UART (set baud rate, etc.)
int uart_init(void);

// Function to read a byte from UART
int uart_readbyte(void);

// Function to write a byte to UART
void uart_writebyte(uint8_t data);

#endif // UART_H

#ifndef MXC_DEVICE_H
#define MXC_DEVICE_H

#include <stdint.h>

// Device configuration, UART in this case (example base address and settings)
#define UART_BASE_ADDR   0x40000000  // Example base address
#define UART_BAUD_RATE   9600        // Default baud rate for UART
#define UART_STATUS_REG  (UART_BASE_ADDR + 0x00)
#define UART_DATA_REG    (UART_BASE_ADDR + 0x04)
#define UART_CTRL_REG    (UART_BASE_ADDR + 0x08)

// Function to initialize the device (example UART or other peripherals)
void mxc_device_init(void);

// Function to configure the UART
void mxc_uart_configure(uint32_t baud_rate);

// Function to read a byte from the UART register
uint8_t mxc_uart_read(void);

// Function to write a byte to the UART register
void mxc_uart_write(uint8_t data);

#endif // MXC_DEVICE_H

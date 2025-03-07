#ifndef __SIMPLE_UART__
#define __SIMPLE_UART__

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "uart.h"
#include "nvic_table.h"
#include "host_messaging.h"

#define UART_BAUD 115200

int uart_init(void);
int uart_readbyte_raw(void);
int uart_readbyte(void);
void uart_writebyte(uint8_t data);
void uart_flush(void);

#endif // __SIMPLE_UART__

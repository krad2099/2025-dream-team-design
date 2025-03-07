#ifndef NVIC_TABLE_H
#define NVIC_TABLE_H

// Function declarations for interrupt handling
void nvic_init(void);
void nvic_enable_irq(int irq);
void nvic_disable_irq(int irq);
void nvic_clear_pending_irq(int irq);

// Define interrupt vector table if necessary (depending on your microcontroller's architecture)
// extern uint32_t _vector_table[];

#endif // NVIC_TABLE_H

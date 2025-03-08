#ifndef __STATUS_LED__
#define __STATUS_LED__

#include "led.h"

// Reset LED state
#define STATUS_LED_OFF(void) LED_Off(LED1); LED_Off(LED2); LED_Off(LED3);
// Error state
#define STATUS_LED_RED(void) STATUS_LED_OFF(); LED_On(LED1);
// Waiting state
#define STATUS_LED_GREEN(void) STATUS_LED_OFF(); LED_On(LED2);
#define STATUS_LED_BLUE(void) STATUS_LED_OFF(); LED_On(LED3);
// Combined states
#define STATUS_LED_PURPLE(void) STATUS_LED_OFF(); LED_On(LED1); LED_On(LED3);
#define STATUS_LED_CYAN(void) STATUS_LED_OFF(); LED_On(LED2); LED_On(LED3);
#define STATUS_LED_YELLOW(void) STATUS_LED_OFF(); LED_On(LED1); LED_On(LED2);
#define STATUS_LED_WHITE(void) STATUS_LED_OFF(); LED_On(LED1); LED_On(LED2); LED_On(LED3);

#define STATUS_LED_ERROR STATUS_LED_RED

#endif // __STATUS_LED__

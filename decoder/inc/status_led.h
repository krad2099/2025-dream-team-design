#ifndef __STATUS_LED__
#define __STATUS_LED__

#include "led.h"
#include "mxc_delay.h"  // Required for delay in STATUS_LED_BLINK

/* These macros control the RGB LED on the MAX78000 FTHR board */

// Reset LED state
#define STATUS_LED_OFF()  do { LED_Off(LED1); LED_Off(LED2); LED_Off(LED3); } while(0)

// Error state
#define STATUS_LED_RED()  do { STATUS_LED_OFF(); LED_On(LED1); } while(0)

// Waiting for message
#define STATUS_LED_GREEN() do { STATUS_LED_OFF(); LED_On(LED2); } while(0)
#define STATUS_LED_BLUE()  do { STATUS_LED_OFF(); LED_On(LED3); } while(0)

// Decode command
#define STATUS_LED_PURPLE() do { STATUS_LED_OFF(); LED_On(LED1); LED_On(LED3); } while(0)

// List command
#define STATUS_LED_CYAN()  do { STATUS_LED_OFF(); LED_On(LED2); LED_On(LED3); } while(0)

// Update command
#define STATUS_LED_YELLOW() do { STATUS_LED_OFF(); LED_On(LED1); LED_On(LED2); } while(0)

// White (all LEDs on)
#define STATUS_LED_WHITE() do { STATUS_LED_OFF(); LED_On(LED1); LED_On(LED2); LED_On(LED3); } while(0)

// Toggle all LEDs (useful for blinking effects)
#define STATUS_LED_TOGGLE() do { LED_Toggle(LED1); LED_Toggle(LED2); LED_Toggle(LED3); } while(0)

// Blink effect for errors (useful for debugging)
#define STATUS_LED_BLINK() \
    do { \
        for (int i = 0; i < 5; i++) { \
            STATUS_LED_TOGGLE(); \
            MXC_Delay(500000); /* 500ms delay */ \
        } \
        STATUS_LED_OFF(); \
    } while(0)

// Error alias
#define STATUS_LED_ERROR STATUS_LED_RED

#endif // __STATUS_LED__

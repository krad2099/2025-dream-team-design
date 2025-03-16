// config.h
#ifndef CONFIG_H
#define CONFIG_H

// Define flash parameters
/* #define MXC_FLASH_MEM_BASE 0x00000000
#define MXC_FLASH_MEM_SIZE 0x00080000
#define MXC_FLASH_PAGE_SIZE  0x1000 */

// Use a single definition for SECRET_STORAGE_ADDR
#ifndef SECRET_STORAGE_ADDR
#define SECRET_STORAGE_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (4 * MXC_FLASH_PAGE_SIZE))  // 0x0007C000
#endif

#endif /* CONFIG_H */



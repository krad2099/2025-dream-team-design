#ifndef _STUB_STDIO_H_
#define _STUB_STDIO_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdarg.h>
#include <stddef.h>

#ifndef NULL
#define NULL ((void*)0)
#endif

/* Minimal definition for FILE. */
typedef struct {
    int dummy;
} FILE;

#define EOF (-1)

/* Minimal stubs for I/O functions.
   You may customize these if you need actual functionality.
   For now, these dummy implementations simply return 0 or equivalent. */
static inline int fputc(int c, FILE* stream) { (void)stream; return c; }
static inline int fputs(const char* s, FILE* stream) { (void)s; (void)stream; return 0; }
static inline int fprintf(FILE* stream, const char* format, ...) { (void)stream; (void)format; return 0; }
static inline int printf(const char* format, ...) { (void)format; return 0; }
static inline int sprintf(char* str, const char* format, ...) { (void)str; (void)format; return 0; }
static inline int vsnprintf(char* str, size_t size, const char* format, va_list ap) { (void)str; (void)size; (void)format; (void)ap; return 0; }
static inline int snprintf(char* str, size_t size, const char* format, ...) { (void)str; (void)size; (void)format; return 0; }
static inline FILE* fopen(const char* filename, const char* mode) { (void)filename; (void)mode; return NULL; }
static inline int fclose(FILE* stream) { (void)stream; return 0; }

#ifdef __cplusplus
}
#endif

#endif /* _STUB_STDIO_H_ */

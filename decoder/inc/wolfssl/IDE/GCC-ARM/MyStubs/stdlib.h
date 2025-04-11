#ifndef _STUB_STDLIB_H_
#define _STUB_STDLIB_H_

#ifdef __cplusplus
extern "C" {
#endif

/* Define NULL if not defined. */
#ifndef NULL
#define NULL ((void*)0)
#endif

/* Define size_t if not defined. */
#ifndef _SIZE_T
typedef unsigned int size_t;
#define _SIZE_T
#endif

/* Minimal prototypes for memory allocation functions.
   You can provide stub implementations or link against your own implementations.
   If your build does not actually need dynamic allocation, you might simply
   return NULL or handle it as appropriate for your system. */
void* malloc(size_t size);
void free(void* ptr);
void exit(int status);

/* Optionally, you may add other standard functions that your build needs. */

#ifdef __cplusplus
}
#endif

#endif /* _STUB_STDLIB_H_ */

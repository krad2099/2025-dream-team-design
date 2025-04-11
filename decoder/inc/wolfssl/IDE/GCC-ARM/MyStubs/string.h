#ifndef _STUB_STRING_H_
#define _STUB_STRING_H_

#ifdef __cplusplus
extern "C" {
#endif

/* Provide a minimal definition for size_t if not already defined. */
#ifndef _SIZE_T
typedef unsigned int size_t;
#define _SIZE_T
#endif

/* Minimal implementation of memcpy */
static inline void* memcpy(void* dest, const void* src, size_t n) {
    char* d = (char*) dest;
    const char* s = (const char*) src;
    while (n--) {
        *d++ = *s++;
    }
    return dest;
}

/* Minimal implementation of memmove */
static inline void* memmove(void* dest, const void* src, size_t n) {
    char* d = (char*) dest;
    const char* s = (const char*) src;
    if (d < s) {
        while(n--) {
            *d++ = *s++;
        }
    } else if (d > s) {
        d += n;
        s += n;
        while(n--) {
            *(--d) = *(--s);
        }
    }
    return dest;
}

/* Minimal implementation of memcmp */
static inline int memcmp(const void* s1, const void* s2, size_t n) {
    const unsigned char* a = s1;
    const unsigned char* b = s2;
    while(n--) {
        if (*a != *b)
            return (*a - *b);
        a++;
        b++;
    }
    return 0;
}

/* Minimal implementation of strlen */
static inline size_t strlen(const char* s) {
    size_t len = 0;
    while (s[len] != '\0') {
        len++;
    }
    return len;
}

#ifdef __cplusplus
}
#endif

#endif /* _STUB_STRING_H_ */

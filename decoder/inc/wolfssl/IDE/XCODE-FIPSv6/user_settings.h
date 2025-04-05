/* user_settings.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* Custom wolfSSL user settings for GCC ARM */

#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H
#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------- */
/* Platform */
/* ------------------------------------------------------------------------- */
#undef  WOLFSSL_GENERAL_ALIGNMENT
#define WOLFSSL_GENERAL_ALIGNMENT   4

#undef  SINGLE_THREADED
//#define SINGLE_THREADED

#undef  WOLFSSL_SMALL_STACK
//#define WOLFSSL_SMALL_STACK

#undef  WOLFSSL_USER_IO
//#define WOLFSSL_USER_IO

#undef ANDROID_V454
/* #define ANDROID_V454 */ /* application specific stuff in benchmark and harness from 140-2 days, carry
                      * over to 140-3 work also */

#undef NO_WRITE_TEMP_FILES
#define NO_WRITE_TEMP_FILES

#ifdef ANDROID_V454
    #define MAX_FIPS_DATA_SZ 50000000
    #define MAX_FIPS_CODE_SZ 50000000
    #if 0
       /* To have all printouts go to the app view on the device use: */
       extern int appendToTextView(const char* fmt, ...);
       #undef printf
       #define printf(format, ...) appendToTextView(format, ## __VA_ARGS__)
    #else
       #include <stdio.h>
       #include <android/log.h>
       #include <unistd.h>
       /* Inline function for WOLFLOGV */
       static inline int wolf_logv(const char* fmt, ...) {
           usleep(500); /* Sleep for 0.5 millisecond */
           va_list args;
           va_start(args, fmt);
           int n = __android_log_vprint(ANDROID_LOG_VERBOSE,
                                        "wolfCrypt_android", fmt, args);
           va_end(args);
           usleep(500); /* Sleep for 0.5 millisecond */
           return n;
       }

       #define WOLFLOGV(...) wolf_logv(__VA_ARGS__)
       #undef printf
       #define printf WOLFLOGV
    #endif
#endif

/* Uncomment for iOS devices with PAA */
#undef IPHONE
#define IPHONE

/* ------------------------------------------------------------------------- */
/* Math Configuration */
/* ------------------------------------------------------------------------- */
#undef  SIZEOF_LONG_LONG
#define SIZEOF_LONG_LONG 8

/* Maximum math bits (Max RSA key bits * 2) */
#undef  FP_MAX_BITS
#define FP_MAX_BITS 16384

/* Maximum math bits (largest supported key bits) */
#undef SP_INT_BITS
#define SP_INT_BITS 8192

#undef USE_FAST_MATH
#if 0 /* Flip to 1 for PAA with single precision */
    #define WOLFSSL_SP_MATH_ALL
    #define WOLFSSL_SP_INT_NEGATIVE
#else
    #define USE_FAST_MATH

    #undef  TFM_TIMING_RESISTANT
    #define TFM_TIMING_RESISTANT

    #define WOLFCRYPT_HAVE_SAKKE /* Note: Sakke can be enabled with 1024-bit support */

    #undef TFM_NO_ASM
    //#define TFM_NO_ASM

    #if 0 /* Flip to 1 for PAA with tfm */
        /* Optimizations */
        #define TFM_ARM
    #endif
#endif

/* Wolf Single Precision Math */
#undef WOLFSSL_SP
#if 0 /* SP Assembly Speedups (wPAA) */  /* Flip to 1 for PAA with tfm or single precision */
    #define WOLFSSL_SP
    //#define WOLFSSL_SP_SMALL      /* use smaller version of code */
    #define WOLFSSL_SP_1024
    #undef WOLFCRYPT_HAVE_SAKKE
    #define WOLFCRYPT_HAVE_SAKKE /* Note: Sakke can be enabled with 1024-bit support */
    #define WOLFSSL_SP_4096 /* Explicitly enable 4096-bit support (2048/3072 on by default) */
    #define WOLFSSL_SP_384 /* Explicitly enable 384-bit support (others on by default) */
    #define WOLFSSL_SP_521 /* Explicitly enable 521-bit support (others on by default) */
    #define WOLFSSL_HAVE_SP_RSA
    #define WOLFSSL_HAVE_SP_DH
    #define WOLFSSL_HAVE_SP_ECC
    /* Customer indicated no desire for PAA, leave out */
    #if 0 /* Flip to 1 for PAA with single precision */
        #define WOLFSSL_ARMASM
        #define WOLFSSL_SP_ARM64
        #define WOLFSSL_SP_ARM64_ASM
        #define WOLFSSL_ARMASM_INLINE
    #endif
#endif

/* ------------------------------------------------------------------------- */
/* FIPS - Requires eval or license from wolfSSL */
/* ------------------------------------------------------------------------- */
#undef  HAVE_FIPS
#if 1

    #define WOLFCRYPT_FIPS_CORE_HASH_VALUE \
1EF567FF471CFF983D21DA74623BDD14CCBCD0B14DADA8E4A9A79A47DEE82F3C
    #define HAVE_FIPS

    #undef  HAVE_FIPS_VERSION
    #define HAVE_FIPS_VERSION 6

    #undef HAVE_FIPS_VERSION_MAJOR
    #define HAVE_FIPS_VERSION_MAJOR HAVE_FIPS_VERSION

    #undef HAVE_FIPS_VERSION_MINOR
    #define HAVE_FIPS_VERSION_MINOR 0

    #undef HAVE_FIPS_VERSION_PATCH
    #define HAVE_FIPS_VERSION_PATCH 0

    #undef WOLFSSL_WOLFSSH
    #define WOLFSSL_WOLFSSH

    #undef WOLFSSL_ECDSA_SET_K
    #define WOLFSSL_ECDSA_SET_K

    #undef WC_RNG_SEED_CB
    #define WC_RNG_SEED_CB

    #ifdef SINGLE_THREADED
        #undef  NO_THREAD_LS
        #define NO_THREAD_LS
    #endif

    #if 0
        #undef NO_ATTRIBUTE_CONSTRUCTOR
        #define NO_ATTRIBUTE_CONSTRUCTOR
    #endif

#endif


/* ------------------------------------------------------------------------- */
/* Crypto */
/* ------------------------------------------------------------------------- */
/* RSA */
#undef NO_RSA
#if 1

    /* half as much memory but twice as slow */
    #undef  RSA_LOW_MEM
    //#define RSA_LOW_MEM

    /* Enables blinding mode, to prevent timing attacks */
    #if 1
        #undef  WC_RSA_BLINDING
        #define WC_RSA_BLINDING
    #else
        #undef  WC_NO_HARDEN
        #define WC_NO_HARDEN
    #endif

    /* RSA PSS Support */
    #if 1
        #undef WC_RSA_PSS
        #define WC_RSA_PSS

        #undef WOLFSSL_PSS_LONG_SALT
        #define WOLFSSL_PSS_LONG_SALT

        #undef WOLFSSL_PSS_SALT_LEN_DISCOVER /* ? */
        #define WOLFSSL_PSS_SALT_LEN_DISCOVER /* ? */
    #endif

    #if 1
        #define WC_RSA_NO_PADDING
    #endif
#else
    #define NO_RSA
#endif

/* ECC */
#undef HAVE_ECC
#if 1
    #define HAVE_ECC

    /* Manually define enabled curves */
    #undef  ECC_USER_CURVES
    #define ECC_USER_CURVES

    #ifdef ECC_USER_CURVES
        /* Manual Curve Selection */
        #define HAVE_ECC192
        #define HAVE_ECC224
        #undef NO_ECC256
        #define HAVE_ECC256
        #define HAVE_ECC384
        #define HAVE_ECC521
    #endif

    /* Fixed point cache (speeds repeated operations against same private key) */
    #undef  FP_ECC
    //#define FP_ECC
    #ifdef FP_ECC
        /* Bits / Entries */
        #undef  FP_ENTRIES
        #define FP_ENTRIES  2
        #undef  FP_LUT
        #define FP_LUT      4
    #endif

    /* Optional ECC calculation method */
    /* Note: doubles heap usage, but slightly faster */
    #undef  ECC_SHAMIR
    #define ECC_SHAMIR

    /* Reduces heap usage, but slower */
    #undef  ECC_TIMING_RESISTANT
    #define ECC_TIMING_RESISTANT

    #ifdef HAVE_FIPS
        #undef  HAVE_ECC_CDH
        #define HAVE_ECC_CDH /* Enable cofactor support */

        #undef NO_STRICT_ECDSA_LEN
        #define NO_STRICT_ECDSA_LEN /* Do not force fixed len w/ FIPS */

        #undef  WOLFSSL_VALIDATE_ECC_IMPORT
        #define WOLFSSL_VALIDATE_ECC_IMPORT /* Validate import */

        #undef WOLFSSL_VALIDATE_ECC_KEYGEN
        #define WOLFSSL_VALIDATE_ECC_KEYGEN /* Validate generated keys */

    #endif

    /* Compressed Key Support */
    #undef  HAVE_COMP_KEY
    //#define HAVE_COMP_KEY

    /* Use alternate ECC size for ECC math */
    #ifdef USE_FAST_MATH
        /* MAX ECC BITS = ROUND8(MAX ECC) * 2 */
        #ifdef NO_RSA
            /* Custom fastmath size if not using RSA */
            #undef  FP_MAX_BITS
            #define FP_MAX_BITS     (256 * 2)
        #else
            #undef  ALT_ECC_SIZE
            #define ALT_ECC_SIZE
            /* wolfSSL will compute the FP_MAX_BITS_ECC, but it can be overridden */
            //#undef  FP_MAX_BITS_ECC
            //#define FP_MAX_BITS_ECC (256 * 2)
        #endif

        /* Speedups specific to curve */
        #ifndef NO_ECC256
            #undef  TFM_ECC256
            #define TFM_ECC256
        #endif
    #endif
#endif

/* DH */
#undef  NO_DH
#if 1
    /* Use table for DH instead of -lm (math) lib dependency */
    #if 1
        #define HAVE_DH_DEFAULT_PARAMS
        #define WOLFSSL_DH_CONST
        #define HAVE_FFDHE_2048
        #define HAVE_FFDHE_3072
        #define HAVE_FFDHE_4096
        #define HAVE_FFDHE_6144
        #define HAVE_FFDHE_8192
    #endif

    #ifdef HAVE_FIPS
        #define WOLFSSL_VALIDATE_FFC_IMPORT
        #define HAVE_FFDHE_Q
    #endif
#else
    #define NO_DH
#endif


/* AES */
#undef NO_AES
#if 1
    #undef  HAVE_AES_CBC
    #define HAVE_AES_CBC

    #undef  HAVE_AESGCM
    #define HAVE_AESGCM

    /* GCM Method (slowest to fastest): GCM_SMALL, GCM_WORD32, GCM_TABLE or
     *                                  GCM_TABLE_4BIT */
    #define GCM_TABLE_4BIT

    #undef  WOLFSSL_AES_DIRECT
    #define WOLFSSL_AES_DIRECT

    #undef  HAVE_AES_ECB
    #define HAVE_AES_ECB

    #undef  WOLFSSL_AES_COUNTER
    #define WOLFSSL_AES_COUNTER

    #undef  HAVE_AESCCM
    #define HAVE_AESCCM

    #undef WOLFSSL_AES_OFB
    #define WOLFSSL_AES_OFB

    /* Required for module v6.0.0 */
    #undef WOLFSSL_AES_CFB
    #define WOLFSSL_AES_CFB

    #undef WOLFSSL_AES_XTS
    #define WOLFSSL_AES_XTS

    #undef WOLFSSL_AESXTS_STREAM
    #define WOLFSSL_AESXTS_STREAM

    #undef WOLFSSL_AES_128
    #define WOLFSSL_AES_128

    #undef WOLFSSL_AES_256
    #define WOLFSSL_AES_256

    #undef WOLFSSL_AESGCM_STREAM
    #define WOLFSSL_AESGCM_STREAM

    #undef HAVE_AES_KEYWRAP
    #define HAVE_AES_KEYWRAP
#else
    #define NO_AES
#endif


/* DES3 */
#undef NO_DES3
#if 0
    #if 1
        #undef WOLFSSL_DES_ECB
        #define WOLFSSL_DES_ECB
    #endif
#else
    #define NO_DES3
#endif

/* ChaCha20 / Poly1305 */
#undef HAVE_CHACHA
#undef HAVE_POLY1305
#if 0
    #define HAVE_CHACHA
    #define HAVE_POLY1305

    /* Needed for Poly1305 */
    #undef  HAVE_ONE_TIME_AUTH
    #define HAVE_ONE_TIME_AUTH
#endif

/* Ed25519 / Curve25519 */
#undef HAVE_CURVE25519
#undef HAVE_ED25519
/* Required for module v6.0.0 */
#if 1
    #define HAVE_CURVE25519
    #define HAVE_ED25519 /* ED25519 Requires SHA512 */
    #define WOLFSSL_ED25519_STREAMING_VERIFY
    #define HAVE_ED25519_KEY_IMPORT

    /* Optionally use small math (less flash usage, but much slower) */
    #if 0
        #define CURVED25519_SMALL
    #endif
#endif

/* Ed448 / Curve448 */
/* Required for module v6.0.0 */
#if 1
    #define HAVE_CURVE448
    #define HAVE_ED448
    #define WOLFSSL_ED448_STREAMING_VERIFY
    #define HAVE_ED448_KEY_IMPORT
#endif

/* ------------------------------------------------------------------------- */
/* Hashing */
/* ------------------------------------------------------------------------- */
/* Sha */
#undef NO_SHA
#if 1
    /* 1k smaller, but 25% slower */
    //#define USE_SLOW_SHA
#else
    #define NO_SHA
#endif

/* Sha256 */
#undef NO_SHA256
#if 1
    /* not unrolled - ~2k smaller and ~25% slower */
    //#define USE_SLOW_SHA256

    /* Sha224 */
    #if 1
        #define WOLFSSL_SHA224
    #endif
#else
    #define NO_SHA256
#endif

/* Sha512 */
#undef WOLFSSL_SHA512
#if 1
    #define WOLFSSL_SHA512

    #define  WOLFSSL_NOSHA512_224 /* Not in FIPS mode */
    #define  WOLFSSL_NOSHA512_256 /* Not in FIPS mode */


    /* Sha384 */
    #undef  WOLFSSL_SHA384
    #if 1
        #define WOLFSSL_SHA384
    #endif

    /* over twice as small, but 50% slower */
    //#define USE_SLOW_SHA512
#endif

/* Sha3 */
#undef WOLFSSL_SHA3
#if 1
    #define WOLFSSL_SHA3
    /* Required to not be disabled for module v6.0.0 */
    #if 0
        #undef WOLFSSL_NO_SHAKE128
        #define WOLFSSL_NO_SHAKE128

        #undef WOLFSSL_NO_SHAKE256
        #define WOLFSSL_NO_SHAKE256
    #else
        #define WOLFSSL_SHAKE256
        #define WOLFSSL_SHAKE128
    #endif
#endif

/* MD5 */
#undef  NO_MD5
#if 0

#else
    #define NO_MD5
#endif

/* HKDF / PRF */
#undef HAVE_HKDF
#if 1
    #define HAVE_HKDF
    #define WOLFSSL_HAVE_PRF

    /* Required for module v6.0.0 */
    #define WC_SRTP_KDF
    #define HAVE_PBKDF2
#endif

/* CMAC */
#undef WOLFSSL_CMAC
#if 1
    #define WOLFSSL_CMAC
#endif


/* ------------------------------------------------------------------------- */
/* Benchmark / Test */
/* ------------------------------------------------------------------------- */
/* Use reduced benchmark / test sizes */
#undef  BENCH_EMBEDDED
#define BENCH_EMBEDDED

#undef  USE_CERT_BUFFERS_2048
#define USE_CERT_BUFFERS_2048

#undef  USE_CERT_BUFFERS_1024
//#define USE_CERT_BUFFERS_1024

#undef  USE_CERT_BUFFERS_256
#define USE_CERT_BUFFERS_256


/* ------------------------------------------------------------------------- */
/* Debugging */
/* ------------------------------------------------------------------------- */

#undef DEBUG_WOLFSSL
#undef NO_ERROR_STRINGS
#if 1
    //#define DEBUG_WOLFSSL
#else
    #if 0
        #define NO_ERROR_STRINGS
    #endif
#endif


/* ------------------------------------------------------------------------- */
/* Memory */
/* ------------------------------------------------------------------------- */

/* Override Memory API's */
#if 0
    #undef  XMALLOC_OVERRIDE
    #define XMALLOC_OVERRIDE

    /* prototypes for user heap override functions */
    /* Note: Realloc only required for normal math */
    #include <stddef.h>  /* for size_t */
    extern void *myMalloc(size_t n, void* heap, int type);
    extern void myFree(void *p, void* heap, int type);
    extern void *myRealloc(void *p, size_t n, void* heap, int type);

    #define XMALLOC(n, h, t)     myMalloc(n, h, t)
    #define XFREE(p, h, t)       myFree(p, h, t)
    #define XREALLOC(p, n, h, t) myRealloc(p, n, h, t)
#endif

#if 0
    /* Static memory requires fast math */
    #define WOLFSSL_STATIC_MEMORY

    /* Disable fallback malloc/free */
    #define WOLFSSL_NO_MALLOC
    #if 1
        #define WOLFSSL_MALLOC_CHECK /* trap malloc failure */
    #endif
#endif

/* Memory callbacks */
#if 1
    #undef  USE_WOLFSSL_MEMORY
    #define USE_WOLFSSL_MEMORY

    /* Use this to measure / print heap usage */
    #if 0
        #undef  WOLFSSL_TRACK_MEMORY
//        #define WOLFSSL_TRACK_MEMORY

        #undef  WOLFSSL_DEBUG_MEMORY
        //#define WOLFSSL_DEBUG_MEMORY

        #undef WOLFSSL_DEBUG_MEMORY_PRINT
        //#define WOLFSSL_DEBUG_MEMORY_PRINT
    #endif
#else
    #ifndef WOLFSSL_STATIC_MEMORY
        #define NO_WOLFSSL_MEMORY
        /* Otherwise we will use stdlib malloc, free and realloc */
    #endif
#endif


/* ------------------------------------------------------------------------- */
/* Port */
/* ------------------------------------------------------------------------- */

/* Override Current Time */
/* Allows custom "custom_time()" function to be used for benchmark */
//#define WOLFSSL_USER_CURRTIME
//#define WOLFSSL_GMTIME
//#define USER_TICKS
//extern unsigned long my_time(unsigned long* timer);
//#define XTIME my_time


/* ------------------------------------------------------------------------- */
/* RNG */
/* ------------------------------------------------------------------------- */

/* Seed Source */
 /* Seed Source */
// extern int my_rng_generate_seed(unsigned char* output, int sz);
// #undef  CUSTOM_RAND_GENERATE_SEED
// #define CUSTOM_RAND_GENERATE_SEED  my_rng_generate_seed

/* Choose RNG method */
#if 1
    /* Use built-in P-RNG (SHA256 based) with HW RNG */
    /* P-RNG + HW RNG (P-RNG is ~8K) */
    //#define WOLFSSL_GENSEED_FORTEST
    #undef  HAVE_HASHDRBG
    #define HAVE_HASHDRBG
#else
    #undef  WC_NO_HASHDRBG
    #define WC_NO_HASHDRBG

    /* Bypass P-RNG and use only HW RNG */
    extern int my_rng_gen_block(unsigned char* output, unsigned int sz);
    #undef  CUSTOM_RAND_GENERATE_BLOCK
    #define CUSTOM_RAND_GENERATE_BLOCK  my_rng_gen_block
#endif


/* ------------------------------------------------------------------------- */
/* Custom Standard Lib */
/* ------------------------------------------------------------------------- */
/* Allows override of all standard library functions */
#undef STRING_USER
#if 0
    #define STRING_USER

    #include <string.h>

    #undef  USE_WOLF_STRSEP
    #define USE_WOLF_STRSEP
    #define XSTRSEP(s1,d)     wc_strsep((s1),(d))

    #undef  USE_WOLF_STRTOK
    #define USE_WOLF_STRTOK
    #define XSTRTOK(s1,d,ptr) wc_strtok((s1),(d),(ptr))

    #define XSTRNSTR(s1,s2,n) mystrnstr((s1),(s2),(n))

    #define XMEMCPY(d,s,l)    memcpy((d),(s),(l))
    #define XMEMSET(b,c,l)    memset((b),(c),(l))
    #define XMEMCMP(s1,s2,n)  memcmp((s1),(s2),(n))
    #define XMEMMOVE(d,s,l)   memmove((d),(s),(l))

    #define XSTRLEN(s1)       strlen((s1))
    #define XSTRNCPY(s1,s2,n) strncpy((s1),(s2),(n))
    #define XSTRSTR(s1,s2)    strstr((s1),(s2))

    #define XSTRNCMP(s1,s2,n)     strncmp((s1),(s2),(n))
    #define XSTRNCAT(s1,s2,n)     strncat((s1),(s2),(n))
    #define XSTRNCASECMP(s1,s2,n) strncasecmp((s1),(s2),(n))

    #define XSNPRINTF snprintf
#endif



/* ------------------------------------------------------------------------- */
/* Enable Features */
/* ------------------------------------------------------------------------- */
#undef WOLFSSL_ASN_TEMPLATE
#define WOLFSSL_ASN_TEMPLATE

#undef WOLFSSL_ASN_PRINT
#define WOLFSSL_ASN_PRINT

#undef WOLFSSL_TLS13
#if 1
    #define WOLFSSL_TLS13
#endif

#undef WOLFSSL_KEY_GEN
#if 1
    #define WOLFSSL_KEY_GEN
#endif

#if defined(HAVE_FIPS) && !defined(WOLFSSL_KEY_GEN)
    #define WOLFSSL_OLD_PRIME_CHECK
#endif

#undef  KEEP_PEER_CERT
//#define KEEP_PEER_CERT

#undef  HAVE_COMP_KEY
//#define HAVE_COMP_KEY

#undef  HAVE_TLS_EXTENSIONS
#define HAVE_TLS_EXTENSIONS

#undef HAVE_EXTENDED_MASTER
#define HAVE_EXTENDED_MASTER

#undef  HAVE_SUPPORTED_CURVES
#define HAVE_SUPPORTED_CURVES

#undef  WOLFSSL_BASE64_ENCODE
#define WOLFSSL_BASE64_ENCODE

/* TLS Session Cache */
#if 0
    #define SMALL_SESSION_CACHE
#else
    #define NO_SESSION_CACHE
#endif

#undef OPENSSL_EXTRA
#define OPENSSL_EXTRA

#undef WOLFSSL_DER_LOAD
#define WOLFSSL_DER_LOAD

#undef HAVE_SESSION_TICKET
#define HAVE_SESSION_TICKET

#undef HAVE_EX_DATA
#define HAVE_EX_DATA

#undef HAVE_ENCRYPT_THEN_MAC
#define HAVE_ENCRYPT_THEN_MAC

#undef WOLFSSL_CERT_GEN
#define WOLFSSL_CERT_GEN

#undef ATOMIC_USER
#define ATOMIC_USER

#undef HAVE_SECRET_CALLBACK
#define HAVE_SECRET_CALLBACK

/* wolfEngine */
#if 0
    #define OPENSSL_COEXIST

    /* HKDF for engine */
    #undef HAVE_HKDF
    #if 1
        #define HAVE_HKDF
        #define HAVE_X963_KDF
    #endif

    #undef WOLFSSL_PUBLIC_MP
    #define WOLFSSL_PUBLIC_MP

    #undef NO_OLD_RNGNAME
    #define NO_OLD_RNGNAME

    #undef NO_OLD_WC_NAMES
    #define NO_OLD_WC_NAMES

    #undef NO_OLD_SSL_NAMES
    #define NO_OLD_SSL_NAMES

    #undef NO_OLD_SHA_NAMES
    #define NO_OLD_SHA_NAMES

    #undef NO_OLD_MD5_NAME
    #define NO_OLD_MD5_NAME

    #undef NO_OLD_SHA256_NAMES
    #define NO_OLD_SHA256_NAMES
#endif

#undef WOLFSSL_SYS_CA_CERTS
//#define WOLFSSL_SYS_CA_CERTS

#undef LIBWOLFSSL_GLOBAL_EXTRA_CFLAGS
#define LIBWOLFSSL_GLOBAL_EXTRA_CFLAGS

#undef HAVE_SERVER_RENEGOTIATION_INFO
#define HAVE_SERVER_RENEGOTIATION_INFO

#undef WOLFSSL_PEM_TO_DER
#define WOLFSSL_PEM_TO_DER

#undef WOLFSSL_PUB_PEM_TO_DER
#define WOLFSSL_PUB_PEM_TO_DER

/* ------------------------------------------------------------------------- */
/* Disable Features */
/* ------------------------------------------------------------------------- */
#undef  NO_WOLFSSL_SERVER
//#define NO_WOLFSSL_SERVER

#undef  NO_WOLFSSL_CLIENT
//#define NO_WOLFSSL_CLIENT

#undef  NO_CRYPT_TEST
//#define NO_CRYPT_TEST

#undef  NO_CRYPT_BENCHMARK
//#define NO_CRYPT_BENCHMARK

#undef  WOLFCRYPT_ONLY
#define WOLFCRYPT_ONLY

/* In-lining of misc.c functions */
/* If defined, must include wolfcrypt/src/misc.c in build */
/* Slower, but about 1k smaller */
#undef  NO_INLINE
//#define NO_INLINE

#undef  NO_FILESYSTEM
//#define NO_FILESYSTEM

#undef  NO_WRITEV
//#define NO_WRITEV

#undef  NO_MAIN_DRIVER
#define NO_MAIN_DRIVER

#undef  NO_DEV_RANDOM
//#define NO_DEV_RANDOM

#undef  NO_DSA
#define NO_DSA

#undef  NO_RC4
#define NO_RC4

#undef  NO_OLD_TLS
#define NO_OLD_TLS

#undef  NO_PSK
#define NO_PSK

#undef  NO_MD4
#define NO_MD4

#undef  NO_PWDBASED
//#define NO_PWDBASED

#undef  NO_CODING
//#define NO_CODING

#undef  NO_ASN_TIME
//#define NO_ASN_TIME

#undef  NO_CERTS
//#define NO_CERTS

#undef  NO_SIG_WRAPPER
//#define NO_SIG_WRAPPER

#undef NO_DO178
#define NO_DO178

/* wolfSSL engineering ACVP algo and operational testing only (Default: Off) */
#if 1
    #ifndef WOLFSSL_PUBLIC_MP
        #define WOLFSSL_PUBLIC_MP
    #endif
    #define OPTEST_LOGGING_ENABLED
    #define DEBUG_FIPS_VERBOSE
    #ifndef DEBUG_WOLFSSL
        //#define DEBUG_WOLFSSL
    #endif
    #define OPTEST_RUNNING_ORGANIC
    #define OPTEST_INVALID_LOGGING_ENABLED
    #define HAVE_FORCE_FIPS_FAILURE
    #define DEEPLY_EMBEDDED
    #define OPTEST_LOG_TE_MAPPING
    #define NO_MAIN_OPTEST_DRIVER
    #define NO_MAIN_DRIVER
    #define NO_MAIN_HARNESS_DRIVER

    #ifdef BENCH_EMBEDDED
    /* NOTE: Can not be on for operational testing */
        #undef BENCH_EMBEDDED
    #endif

    #define NO_WRITE_TEMP_FILES
#endif

/* Customer Specific Section */
/* #define CUSTOMER_1_IOS */
#ifdef CUSTOMER_1_IOS

    /* not certified, disable for full FIPS compliance, will attempt to include
     * in UPDT submission and/or next FS submission */
    #undef HAVE_PKCS7
    #define HAVE_PKCS7

    #undef HAVE_SNI
    #define HAVE_SNI

    #undef HAVE_THREAD_LS
    #define HAVE_THREAD_LS

    /* Not certifiable but external to module boundary and out of scope */
    #undef WOLFCRYPT_HAVE_ECCSI
    #define WOLFCRYPT_HAVE_ECCSI

    #undef WOLFSSL_DTLS
    #define WOLFSSL_DTLS

    #undef WOLFSSL_DTLS_MTU
    #define WOLFSSL_DTLS_MTU

    /* OpenSSL Compatibility (NOTE: Incompatible with wolfEngine and
       OPENSSL_COEXIST) */
    #ifndef OPENSSL_COEXIST
        #undef OPENSSL_EXTRA
        #if 1
            #define OPENSSL_EXTRA
            /* Larger footprint but enable ALL compatibility not just a subset */
            #if 1
                #define OPENSSL_ALL
            #endif
        #endif
    #endif
#endif /* CUSTOMER_1_IOS */

#ifdef __cplusplus
}
#endif


#endif /* WOLFSSL_USER_SETTINGS_H */


/* fips.c
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

/* in case user set HAVE_FIPS there */
#include <wolfssl/wolfcrypt/settings.h>

#ifdef HAVE_FIPS

#ifdef USE_WINDOWS_API
    #pragma code_seg(".fipsA$o")
    #pragma const_seg(".fipsB$o")
#endif

/* detect new macro for disabling RNG */
#if defined(WC_NO_RNG) && !defined(NO_RNG)
    #define NO_RNG
#endif


/* set FIPS_NO_WRAPPERS before headers, use direct internal f()s not wrappers */
#define FIPS_NO_WRAPPERS

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/des3.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/cmac.h>
#include <wolfssl/wolfcrypt/kdf.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/dh.h>
#include <wolfssl/wolfcrypt/fips_test.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/ed448.h>
#include <wolfssl/wolfcrypt/pwdbased.h>
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#if FIPS_VERSION3_GE(6,0,0)
    const unsigned int wolfCrypt_FIPS_f_ro_sanity[2] =
                                                     { 0x1a2b3c4d, 0x00000018 };
#endif

/* global variable version string, cast to const char on return */
static char version_string[WC_VERSION_LEN];

/* global init flag */
static int versionInitialized = 0;

/* NOTE: When preparing a new full submission and updating the service API table
 * in the FIPS User Guide [UG], because all the API's get mapped to various
 * services (and are not in order as they appear in fips.c) having an ID per API
 * makes it 10 times easier to sanity check your work. Simply define
 * FIPS_LOG_API_ID then re-build, update the fips hash, run the operational test
 * once with #define RUN_INVALID on and #define RUN_VALID off.
 * This will produce a log of all ID's actively used while running invalid.c
 * file.
 * Echo the output to a log file, sort it and then see which ID's were missed
 * and now you know which APIs need to be added to invalid.c to satisfy
 * TE03.15.06 from ISO.IEC.24759-2017; "The tester shall attempt to input data
 * and/or control information which is not compliant with the format, and
 * verify that such service inputs are rejected by the cryptographic module"
 * Now (without rebuilding the module) re-compile the optest app after
 * defining RUN_VALID and un-defining RUN_INVALID. Again echo the output to a
 * log file, sort the contents and see which API ID's are not present. Update
 * test.c to exercise those API's in a valid manner. Now all services should
 * be covered satisfying all test requirements, define both RUN_INVALID and
 * RUN_VALID in optest.h and run the operational test app for the lab.
 */
/* In optesting print function line numbers and function ID's */
#undef FIPS_LOG_API_ID
/* #define FIPS_LOG_API_ID */
#undef FIPS_LOG_LINE_NUMBERS
/* #define FIPS_LOG_LINE_NUMBERS */
/* Only define FIPS_LOG_LINE_NUMBERS during code review (disable for optesting)
 * echo the output of wolfcrypt/test/test.c or optest to a log.txt file then
 * filter with `sort -u log.txt` to get only unique lines. Use output to fill in
 * the line numbers in the services table for the FS  paperwork */
#if defined(FIPS_LOG_API_ID) && defined(FIPS_LOG_LINE_NUMBERS)
    #define WC_LOG_FUNC_ID(a) printf("API ID: %s :[%s at %d]\n", a, __func__, __LINE__);
#elif defined(FIPS_LOG_API_ID) && !defined(FIPS_LOG_LINE_NUMBERS)
    #define WC_LOG_FUNC_ID(a) printf("API ID %s: ----------------------- [%s()]\n", a, __func__);
#else
    #define WC_LOG_FUNC_ID(a) (void) (a)
#endif

#if defined(HAVE_FORCE_FIPS_FAILURE) || defined(DEBUG_WOLFSSL)
    #include <stdio.h>
    static void FIPS_MSG(const char* msg)
    {
        printf("%s\n", msg);
    }
#else
    #define FIPS_MSG(m)
#endif

#ifdef WOLFSSL_STM32L4
    extern HAL_StatusTypeDef HAL_Init(void);
    extern void wolfSSL_POS_SystemClock_Config(void);
#endif /* WOLFSSL_STM32L4 */


#ifdef USE_WINDOWS_API

    #define CCALL __cdecl
    #pragma section(".CRT$XCU",read)
    #define INITIALIZER(f) \
       static void __cdecl f(void); \
       __declspec(allocate(".CRT$XCU")) void (__cdecl*f##_)(void) = f; \
       static void __cdecl f(void)

#elif defined(NO_ATTRIBUTE_CONSTRUCTOR)

    #define INITIALIZER(f) void f(void)

#else

    #define INITIALIZER(f) static void __attribute__((constructor)) f(void)

#endif


/* power on self (pos) test status */
enum POS_STATUS {
    POS_NOT_DONE,    /* in progress, not complete yet */
    POS_FAILURE,     /* done, but failed  */
    POS_SUCCESS      /* done, and SUCCESS */
};

static enum POS_STATUS posStatus = POS_FAILURE;   /* our pos status */
static int             posReturn =
    WC_NO_ERR_TRACE(FIPS_NOT_ALLOWED_E); /* pos return value */
static char base16_hash[FIPS_IN_CORE_DIGEST_SIZE*2+1]; /* calculated hash */


fipsCastStateId_t fipsCastStatus[FIPS_CAST_COUNT];
enum FipsModeId fipsMode;


#ifdef WOLFSSL_FIPS_DEBUG_OUTPUT

    static const char* CastIdToStr(enum FipsCastId id)
    {
        switch (id) {
            case FIPS_CAST_AES_CBC:
                return "AES-CBC";
            case FIPS_CAST_AES_GCM:
                return "AES-GCM";
            case FIPS_CAST_HMAC_SHA1:
                return "HMAC-SHA1";
            case FIPS_CAST_HMAC_SHA2_256:
                return "HMAC-SHA2-256";
            case FIPS_CAST_HMAC_SHA2_512:
                return "HMAC-SHA2-512";
            case FIPS_CAST_HMAC_SHA3_256:
                return "HMAC-SHA3-256";
            case FIPS_CAST_DRBG:
                return "DRBG";
            case FIPS_CAST_RSA_SIGN_PKCS1v15:
                return "RSA Sign PKCS1 v1.5";
            case FIPS_CAST_ECC_CDH:
                return "ECC Cofactor";
            case FIPS_CAST_ECC_PRIMITIVE_Z:
                return "ECC Primitive Z";
            case FIPS_CAST_DH_PRIMITIVE_Z:
                return "DH Primitive Z";
            case FIPS_CAST_ECDSA:
                return "ECDSA";
            case FIPS_CAST_KDF_TLS12:
                return "KDF-TLS12";
            case FIPS_CAST_KDF_TLS13:
                return "KDF-TLS13";
            case FIPS_CAST_KDF_SSH:
                return "KDF-SSH";
            case FIPS_CAST_COUNT:
                return "count";
            case FIPS_CAST_KDF_SRTP:
                return "KDF-SRTP";
            case FIPS_CAST_ED25519:
                return "ED25519";
            case FIPS_CAST_ED448:
                return "ED448";
            case FIPS_CAST_PBKDF2:
                return "PBKDF";
            default:
                return "unknown";
        }
    }


    static const char* CastStateIdToStr(fipsCastStateId_t id)
    {
        switch (fipsCastStatus_get(id)) {
            case FIPS_CAST_STATE_INIT:
                return "initialized";
            case FIPS_CAST_STATE_PROCESSING:
                return "processing";
            case FIPS_CAST_STATE_SUCCESS:
                return "success";
            case FIPS_CAST_STATE_FAILURE:
                return "failure";
            default:
                return "unknown";
        }
    }


    static void OutputCastStatus(void)
    {
        int i;

        for (i = 0; i < FIPS_CAST_COUNT; i++) {
            printf("%20s test: %s\n",
                    CastIdToStr((enum FipsCastId)i),
                    CastStateIdToStr(fipsCastStatus[i]));
        }
    }
    #define OUTPUT_CAST_STATUS() do { OutputCastStatus(); } while(0)

#else
    #define OUTPUT_CAST_STATUS() do {} while(0)
#endif


/*
 * HAVE_THREAD_LS: means compiler provides a primitive local storage type.
 *
 * NO_THREAD_LS: works in SINGLE_THREADED mode OR where the compiler doesn't
 * provide local storage. It MUST be guaranteed that this is run in a single
 * task/thread and we are absolutely certain no other task/thread can access
 * the wolfcrypt module before execution of the power on self test has finished.
 * Note GetTLS(&thisThreadInPOS) MUST return correct value therefore no ops
 * would not work.
 */
#ifdef WOLFSSL_LINUXKM
    typedef atomic_t TLS_Key;

    static INLINE int InitTLS(TLS_Key* key)
    {
        atomic_set(key, 0);
        return 0;
    }

    static INLINE int GetTLS(TLS_Key* key)
    {
        return atomic_read(key);
    }

    /* for the linuxkm, there is no true TLS (indeed some contexts aren't
     * associated with a thread), so use the variable as a mutex.
     */
    static WARN_UNUSED_RESULT INLINE int SetTLS(TLS_Key* key, int cur_flag, int next_flag)
    {
        int cmpxchg_ret = atomic_cmpxchg(key, cur_flag, next_flag);
        if (cmpxchg_ret == cur_flag)
            return 0;
        else
            return WC_FAILURE;
    }

#elif defined(HAVE_THREAD_LS) || defined(NO_THREAD_LS)
    /* Note: this thread local stuff doesn't work in pre-Vista DLLs.
     * Need to use TlsAlloc, etc, in that case. */

    typedef int TLS_Key;

    static INLINE int InitTLS(TLS_Key* key)
    {
        *key = 0;
        return 0;
    }

    static INLINE int GetTLS(TLS_Key* key)
    {
        return *key;
    }

    static INLINE void SetTLS(TLS_Key* key, int flag)
    {
        *key = flag;
    }

#elif defined(USE_WINDOWS_API)
    /* Uses the WINAPI calls that TlsAlloc() the thread local
     * storage rather than using the _declspec(thread) tags.
     * pre-Vista DLLs, and DLLs loaded at runtime cannot use
     * the declspec tag. */

    typedef DWORD TLS_Key;

    static INLINE int NewTLS(TLS_Key* key)
    {
        *key = TlsAlloc();
        if (*key == TLS_OUT_OF_INDEXES)
            return THREAD_STORE_KEY_E;

        return 0;
    }

    static INLINE int InitTLS(TLS_Key* key)
    {
        int* value;

        value = (int*)malloc(sizeof(int));
        if (value == NULL)
            return MEMORY_E;

        *value = 0;

        if (TlsSetValue(*key, (LPVOID)value) == 0) {
            free(value);
            return THREAD_STORE_SET_E;
        }

        return 0;
    }

    static INLINE int GetTLS(TLS_Key* key)
    {
        int* value = TlsGetValue(*key);

        if (value != NULL)
            return *value;
        else 
            return InitTLS(key);

        return 0;
    }

    static INLINE void SetTLS(TLS_Key* key, int flag)
    {
        int* value = TlsGetValue(*key);

        if (value != NULL)
            *value = flag;
        else {
            if (InitTLS(key) == 0) {
                SetTLS(key, flag);
            }
        }
    }

    static INLINE void FreeTLS(TLS_Key* key)
    {
        int* value = TlsGetValue(*key);

        if (value != NULL)
            free(value);
        TlsFree(*key);
    }

#else

    typedef pthread_key_t TLS_Key;

    static INLINE int NewTLS(TLS_Key* key)
    {
        if (pthread_key_create(key, NULL) != 0)
            return THREAD_STORE_KEY_E;

        return 0;
    }

    static INLINE int InitTLS(TLS_Key* key)
    {
        int* value;

        value = (int*)malloc(sizeof(int));
        if (value == NULL)
            return MEMORY_E;

        *value = 0;

        if (pthread_setspecific(*key, value) != 0) {
            free(value);
            return THREAD_STORE_SET_E;
        }

        return 0;
    }

    static INLINE int GetTLS(TLS_Key* key)
    {
        int* value = pthread_getspecific(*key);

        if (value != NULL)
            return *value;
        else 
            return InitTLS(key);

        return 0;
    }

    static INLINE void SetTLS(TLS_Key* key, int flag)
    {
        int* value = pthread_getspecific(*key);

        if (value != NULL)
            *value = flag;
        else {
             if (InitTLS(key) == 0) {
                SetTLS(key, flag);
            }
        }
    }

#endif

#ifdef WOLFSSL_LINUXKM
static THREAD_LS_T TLS_Key thisThreadInPOS = ATOMIC_INIT(0);          /* one per kernel module */
static THREAD_LS_T TLS_Key privateKeyReadEnable = ATOMIC_INIT(0);     /* one per kernel module, default to false */
#else
static THREAD_LS_T TLS_Key thisThreadInPOS = 0;          /* per thread in pos */
static THREAD_LS_T TLS_Key privateKeyReadEnable = 0;     /* default to false */
#endif


#ifndef NO_RNG
static wolfSSL_Mutex conTestMutex;       /* continuous test mutex */
static int           conTestFailure = 0; /* in failure mode */
#endif

wolfCrypt_fips_cb errCb = NULL;                    /* error callback */

/* user callback setter for err result */
int wolfCrypt_SetCb_fips(wolfCrypt_fips_cb cbf)
{
    WC_LOG_FUNC_ID("1.00");
    errCb = cbf;

    return 0;
}


/* check continuous test status, return 0 if status ok, else < 0 */
#ifndef NO_RNG
static int CheckConTestStatus(void)
{
    int localFailure = 0;

    if (LockMutex(&conTestMutex) != 0) {
        conTestFailure = 1;
        localFailure   = 1;
    } else {
        if (conTestFailure)
            localFailure = 1;
        UnLockMutex(&conTestMutex);
    }

    if (localFailure) {
        return WC_FAILURE;
    }

    return 0;
}
#endif

/* set continuous test failure status, return 0 on success */
#ifndef NO_RNG
static int SetConTestFailure(void)
{
    if (LockMutex(&conTestMutex) != 0) {
        conTestFailure = 1;
    } else {
        conTestFailure = 1;
        UnLockMutex(&conTestMutex);
    }

    return 0;
}
#endif

/* // NOLINTBEGIN(misc-no-recursion) */

static void EnterDegradedMode(int castErr)
{
    int i, ret;

    if (fipsMode == FIPS_MODE_DEGRADED) {
#ifdef DEBUG_FIPS_VERBOSE
        FIPS_MSG("Module already in degraded mode, do nothing");
#endif
        (void) i;
        (void) ret;
    } else {

        FIPS_MSG("Enter EnterDegradedMode()");
        if (errCb) {
            errCb(0, castErr, base16_hash);
        }
        fipsMode = FIPS_MODE_DEGRADED;
        for (i = 0; i < FIPS_CAST_COUNT; i++) {
            if (fipsCastStatus_get(i) == FIPS_CAST_STATE_SUCCESS) {
                fipsCastStatus_put(i, FIPS_CAST_STATE_INIT);
            }
        }
        if (errCb) {
            errCb(1, FIPS_DEGRADED_E, base16_hash);
        }

        ret = wc_RunAllCast_fips();
        if (ret == 0) {
            FIPS_MSG("ERROR: All casts passed in degraded mode\n");
            FIPS_MSG("ERROR: Reload the module or power cycle the device\n");
            posStatus = POS_FAILURE;
            posReturn = FIPS_NOT_ALLOWED_E;
        }


        FIPS_MSG("Leave EnterDegradedMode()");
    }
}

int wolfCrypt_GetMode_fips(void)
{
    WC_LOG_FUNC_ID("1.01");
    return (int)fipsMode;
}


#ifdef HAVE_FORCE_FIPS_FAILURE

#define DEGRADE_STATE(a) { fipsCastStatus[a] = FIPS_CAST_STATE_PROCESSING; \
                           fipsCastStatus_put(a, FIPS_CAST_STATE_FAILURE); }

int wolfCrypt_SetStatus_fips(int status)
{
    if (status == WC_NO_ERR_TRACE(DRBG_CONT_FIPS_E)) {
#ifndef NO_RNG
        SetConTestFailure();
        return 0;
#else
        return NOT_COMPILED_IN;
#endif
    } else if (status < 0) {
        printf("Setting status: %s\n", wc_GetErrorString(status));
        switch(status) {
            /* -127 */
            case WC_NO_ERR_TRACE(FIPS_DEGRADED_E):
                posStatus = POS_SUCCESS;
                fipsMode = FIPS_MODE_DEGRADED;
                posReturn = status;
                break;
            /* -128 */
            case WC_NO_ERR_TRACE(FIPS_CODE_SZ_E):
                posStatus = POS_FAILURE;
                fipsMode = FIPS_MODE_FAILED;
                posReturn = status;
                break;
            /* -159 */
            case WC_NO_ERR_TRACE(KDF_SRTP_KAT_FIPS_E):
                DEGRADE_STATE(FIPS_CAST_KDF_SRTP);
                break;
            /* -163 */
            case WC_NO_ERR_TRACE(ED25519_KAT_FIPS_E):
                DEGRADE_STATE(FIPS_CAST_ED25519);
                break;
            /* -164 */
            case WC_NO_ERR_TRACE(ED448_KAT_FIPS_E):
                DEGRADE_STATE(FIPS_CAST_ED448);
                break;
            /* -165 */
            case WC_NO_ERR_TRACE(PBKDF2_KAT_FIPS_E):
                DEGRADE_STATE(FIPS_CAST_PBKDF2);
                break;
            /* -197 */
            case WC_NO_ERR_TRACE(FIPS_NOT_ALLOWED_E):
                posStatus = POS_FAILURE;
                fipsMode = FIPS_MODE_FAILED;
                posReturn = status;
                break;
            /* -200 */
            case WC_NO_ERR_TRACE(HMAC_MIN_KEYLEN_E):
                FIPS_MSG("HMAC key is below minimum threshold, reject "
                         "but no module status change");
                return 0;
            /* -203 */
            case WC_NO_ERR_TRACE(IN_CORE_FIPS_E):
                posStatus = POS_FAILURE;
                fipsMode = FIPS_MODE_FAILED;
                posReturn = status;
                break;
            /* -204 */
            case WC_NO_ERR_TRACE(AES_KAT_FIPS_E):
                DEGRADE_STATE(FIPS_CAST_AES_GCM);
                DEGRADE_STATE(FIPS_CAST_AES_CBC);
                break;
            /* -205 - Des3 not supported in 140-3 or degraded mode*/
            case WC_NO_ERR_TRACE(DES3_KAT_FIPS_E):
                FIPS_MSG("Des3 not supported in this module, no change");
                return 0;
            /* -206 */
            case WC_NO_ERR_TRACE(HMAC_KAT_FIPS_E):
                DEGRADE_STATE(FIPS_CAST_HMAC_SHA1);
                DEGRADE_STATE(FIPS_CAST_HMAC_SHA2_256);
                DEGRADE_STATE(FIPS_CAST_HMAC_SHA2_512);
                DEGRADE_STATE(FIPS_CAST_HMAC_SHA3_256);
                break;
            /* -207 */
            case WC_NO_ERR_TRACE(RSA_KAT_FIPS_E):
                DEGRADE_STATE(FIPS_CAST_RSA_SIGN_PKCS1v15);
                break;
            /* -208 */
            case WC_NO_ERR_TRACE(DRBG_KAT_FIPS_E):
                /* fall-through to -209 */
            /* -209 */
            case WC_NO_ERR_TRACE(DRBG_CONT_FIPS_E):
                DEGRADE_STATE(FIPS_CAST_DRBG);
                break;
            /* -210 */
            case WC_NO_ERR_TRACE(AESGCM_KAT_FIPS_E):
                DEGRADE_STATE(FIPS_CAST_AES_GCM);
                break;
            /* -231 */
            case WC_NO_ERR_TRACE(SIG_TYPE_E):
                FIPS_MSG("Attempted sign with unsupported key length "
                         "(1024/192), reject but no module status change");
                return 0;
            /* -233 */
            case WC_NO_ERR_TRACE(FIPS_INVALID_VER_E):
                posStatus = POS_FAILURE;
                fipsMode = FIPS_MODE_FAILED;
                posReturn = status;
                break;
            /* -242 */
            case WC_NO_ERR_TRACE(ECC_CDH_KAT_FIPS_E):
                DEGRADE_STATE(FIPS_CAST_ECC_CDH);
                break;
            /* -254 - There is no RSA-PSS PAT test, defer to -207 */
            case WC_NO_ERR_TRACE(RSAPSS_PAT_FIPS_E):
                DEGRADE_STATE(FIPS_CAST_RSA_SIGN_PKCS1v15);
                break;
            /* -255 - There is no ECDSA PAT test, defer to -280 */
            case WC_NO_ERR_TRACE(ECDSA_PAT_FIPS_E):
                DEGRADE_STATE(FIPS_CAST_ECDSA);
                break;
            /* -256 */
            case WC_NO_ERR_TRACE(DH_KAT_FIPS_E):
                DEGRADE_STATE(FIPS_CAST_DH_PRIMITIVE_Z);
                break;
            /* -257 There is no CCM KAT, defer to AES -204 */
            case WC_NO_ERR_TRACE(AESCCM_KAT_FIPS_E):
                DEGRADE_STATE(FIPS_CAST_AES_GCM);
                DEGRADE_STATE(FIPS_CAST_AES_CBC);
                break;
            /* -258 - SHA3 is tested as part of a higher level protocol under
             *        HMAC, there is no specific SHA3 KAT to fail, defer to
             *        HMAC-SHA3 KAT */
            case WC_NO_ERR_TRACE(SHA3_KAT_FIPS_E):
                DEGRADE_STATE(FIPS_CAST_HMAC_SHA3_256);
                break;
            /* -259 */
            case WC_NO_ERR_TRACE(ECDHE_KAT_FIPS_E):
                DEGRADE_STATE(FIPS_CAST_ECC_PRIMITIVE_Z);
                break;
            /* -280 */
            case WC_NO_ERR_TRACE(ECDSA_KAT_FIPS_E):
                DEGRADE_STATE(FIPS_CAST_ECDSA);
                break;
            /* -281 */
            case WC_NO_ERR_TRACE(RSA_PAT_FIPS_E):
                DEGRADE_STATE(FIPS_CAST_RSA_SIGN_PKCS1v15);
                break;
            /* -282 */
            case WC_NO_ERR_TRACE(KDF_TLS12_KAT_FIPS_E):
                DEGRADE_STATE(FIPS_CAST_KDF_TLS12);
                break;
            /* -283 */
            case WC_NO_ERR_TRACE(KDF_TLS13_KAT_FIPS_E):
                DEGRADE_STATE(FIPS_CAST_KDF_TLS13);
                break;
            /* -284 */
            case WC_NO_ERR_TRACE(KDF_SSH_KAT_FIPS_E):
                DEGRADE_STATE(FIPS_CAST_KDF_SSH);
                break;
            /* -285 */
            case WC_NO_ERR_TRACE(DHE_PCT_E):
                DEGRADE_STATE(FIPS_CAST_DH_PRIMITIVE_Z);
                break;
            /* -286 */
            case WC_NO_ERR_TRACE(ECC_PCT_E):
                DEGRADE_STATE(FIPS_CAST_ECC_PRIMITIVE_Z);
                break;
            /* -287 - Degrade all private key services */
            case WC_NO_ERR_TRACE(FIPS_PRIVATE_KEY_LOCKED_E):
                DEGRADE_STATE(FIPS_CAST_RSA_SIGN_PKCS1v15);
                DEGRADE_STATE(FIPS_CAST_ECDSA);
                DEGRADE_STATE(FIPS_CAST_DH_PRIMITIVE_Z);
                break;
            default:
                FIPS_MSG("That code has no impact on the module, do nothing");
                return 0;
        }
        if (posReturn == 0) {
            EnterDegradedMode(status);
            posStatus = POS_SUCCESS;
        }
        return 0;
    }

    return BAD_FUNC_ARG;
}

#endif /* HAVE_FORCE_FIPS_FAILURE */


/* return 0 on allowed (success), < 0 on error */
static int FipsAllowed(void)
{
    if (posStatus == POS_NOT_DONE && GetTLS(&thisThreadInPOS) == 1)
        return 0;  /* allow POS on this thread only */
    else if (posStatus == POS_FAILURE) {
        if (errCb)
            errCb(0, posReturn, base16_hash);
        return WC_FAILURE;
    }

#ifndef NO_RNG
    if (CheckConTestStatus() != 0) {
        if (errCb)
            errCb(0, DRBG_CONT_FIPS_E, base16_hash);
        return WC_FAILURE;
    }
#endif

    return 0;
}


/* return 0 on allowed (success), < 0 on error */
static int AlgoAllowed(int type)
{
    int castErr = 0;

    if ((type < 0) || (type >= FIPS_CAST_COUNT)) {
        return WC_FAILURE;
    }

    if (fipsCastStatus_get(type) == FIPS_CAST_STATE_SUCCESS) {
        return 0;
    }

#ifdef WOLFSSL_LINUXKM
    /* for CAST in _LINUXKM, atomic ops are used for safe contended access to
     * fipsCastStatus[type], and thisThreadInPOS isn't used at all.
     */
    castErr = DoCAST(type);
    if (castErr == 0)
        return 0;
    else {
        EnterDegradedMode(castErr);
        return WC_FAILURE;
    }
#else /* !WOLFSSL_LINUXKM */
    if (GetTLS(&thisThreadInPOS) > 0) {
        if (fipsCastStatus_get(type) == FIPS_CAST_STATE_PROCESSING) {
            return 0;
        }
        else if (fipsCastStatus_get(type) == FIPS_CAST_STATE_INIT) {
            /* This is happening because another CAST is in process,
             * and this algo is a dependency. */
            castErr = DoCAST(type);
        }
    }

    if (fipsCastStatus_get(type) == FIPS_CAST_STATE_INIT) {
        SetTLS(&thisThreadInPOS, 1);
        castErr = DoCAST(type);
        SetTLS(&thisThreadInPOS, 0);
    }

    /* Return test status */
    if (fipsCastStatus_get(type) == FIPS_CAST_STATE_SUCCESS) {
        return 0;
    }
    else if (fipsCastStatus_get(type) == FIPS_CAST_STATE_PROCESSING) {
        return FIPS_CAST_STATE_PROCESSING;
    }
    else {
        EnterDegradedMode(castErr);
        return WC_FAILURE;
    }
#endif /* !WOLFSSL_LINUXKM */
}


/* power on self test proper, only function to change POS status, only called
 * by entry point */
static void DoSelfTest(void)
{
#ifdef WOLFSSL_LINUXKM
    if (SetTLS(&thisThreadInPOS, 0, 1) < 0) {
        pr_err("FIPS error: POS initiated, but thisThreadInPOS already has value %d.\n",GetTLS(&thisThreadInPOS));
    }
#else
    SetTLS(&thisThreadInPOS, 1);
#endif

    FIPS_MSG("Starting Power On Self Test");

    /* switch to not done, mark this thread as in pos */
    posStatus = POS_NOT_DONE;
    fipsMode = FIPS_MODE_INIT;

    /* do tests proper */
    if ( (posReturn = DoPOST(base16_hash, sizeof(base16_hash))) != 0) {
        OUTPUT_CAST_STATUS();
        posStatus = POS_FAILURE;
        fipsMode = FIPS_MODE_FAILED;
#ifdef WOLFSSL_LINUXKM
        if (SetTLS(&thisThreadInPOS, 1, 0) < 0)
            pr_err("FIPS error: thisThreadInPOS should be 1, but is %d.\n",GetTLS(&thisThreadInPOS));
#else
        SetTLS(&thisThreadInPOS, 0);
#endif
        FIPS_MSG("Pre-Operational Self Test FAILURE");
        return;
    }
    ForceZero(base16_hash, sizeof(base16_hash));
    OUTPUT_CAST_STATUS();

    /* completed success */
    posStatus = POS_SUCCESS;
    fipsMode = FIPS_MODE_NORMAL;
#ifdef WOLFSSL_LINUXKM
        if (SetTLS(&thisThreadInPOS, 1, 0) < 0) {
            pr_err("FIPS error: thisThreadInPOS should be 1, but is %d.\n",GetTLS(&thisThreadInPOS));
        }
#else
        SetTLS(&thisThreadInPOS, 0);
#endif

    FIPS_MSG("Pre-Operational Self Test SUCCESS");
}


/* fips entry point, auto */
INITIALIZER(fipsEntry)
{
    char* versionSanity = NULL;
#ifdef WOLFSSL_STM32L4
    /* Configure clock peripheral at 120MHz otherwise the tests take
     * more than 12 minutes to complete. With peripheral configured
     * takes 32 seconds */
    HAL_Init();
    wolfSSL_POS_SystemClock_Config();
#endif
#ifndef NO_RNG
    if (InitMutex(&conTestMutex) != 0) {
        conTestFailure = 1;
    }
#endif

#if !defined(HAVE_THREAD_LS) && !defined(NO_THREAD_LS)
    /* In the case of TlsAlloc() or pthread_key_create use case,
    *  (no __thread or __declspec(thread))
    *  it needs allocating a TLS index or pthread key.
    *  then any threads init TLS index for itself by calling InitTLS().
    *  GetTLS()/SetTLS() call initTLS if the index is not initialized for
    *  the thread.
    */
    if (NewTLS(&thisThreadInPOS) != 0) {
        posStatus = POS_FAILURE;
        FIPS_MSG("Power On Self Test FAILURE");
        return;
    }

    if (NewTLS(&privateKeyReadEnable) != 0) {
        posStatus = POS_FAILURE;
        FIPS_MSG("Power On Self Test FAILURE");
        return;
    }
#endif
    if ( (posReturn = InitTLS(&thisThreadInPOS)) != 0) {
        posStatus = POS_FAILURE;
        FIPS_MSG("Power On Self Test FAILURE");
        return;
    }

    if ( (posReturn = InitTLS(&privateKeyReadEnable)) != 0) {
        posStatus = POS_FAILURE;
        FIPS_MSG("Power On Self Test FAILURE");
        return;
    }

    /* Initialize the version on startup */
    versionSanity = (char*) wolfCrypt_GetVersion_fips();
    if (versionSanity == NULL) {
        posStatus = POS_FAILURE;
        FIPS_MSG("version init failed");
        FIPS_MSG("Check HAVE_FIPS_VERSION_PORT not > 3 bytes");
        return;
    }
    DoSelfTest();
}


#if defined(USE_WINDOWS_API) && defined(WOLFSSL_DLL)

BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved )
{
    (void)hinstDLL;
    (void)lpReserved;

    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            fipsEntry();
            break;
        case DLL_PROCESS_DETACH:
            #if !defined(HAVE_THREAD_LS) && !defined(NO_THREAD_LS)
                FreeTLS(&thisThreadInPOS);
                FreeTLS(&privateKeyReadEnable);
            #endif
            break;
#if !defined(HAVE_THREAD_LS) && !defined(NO_THREAD_LS)
        case DLL_THREAD_ATTACH:
            if ((posReturn = InitTLS(&thisThreadInPOS)) != 0) {
                posStatus = POS_FAILURE;
                FIPS_MSG("Init TLS index for thread failure");
            }
            if ((posReturn = InitTLS(&privateKeyReadEnable)) != 0) {
                posStatus = POS_FAILURE;
                FIPS_MSG("Init TLS index for thread failure");
            }
            break;
        case DLL_THREAD_DETACH:
            FreeTLS(&thisThreadInPOS);
            FreeTLS(&privateKeyReadEnable);
            break;
#endif
    }

    return TRUE;
}

#endif


#ifdef WOLFSSL_LINUXKM
/* Allows an external read of a private key from in boundary */
int wolfCrypt_SetPrivateKeyReadEnable_fips(int enable, enum wc_KeyType keyType)
{
    WC_LOG_FUNC_ID("1.02");

    if (keyType == WC_KEYTYPE_ALL) {
        if (enable == 0) {
            if (atomic_dec_return(&privateKeyReadEnable) < 0) {
                atomic_inc(&privateKeyReadEnable);
                return BAD_STATE_E;
            }
            return 0;
        }
        else {
            int cur_privateKeyReadEnable = atomic_read(&privateKeyReadEnable);
            for (;;) {
                int cmpxchg_ret;
                if (cur_privateKeyReadEnable >= INT_MAX)
                    return BAD_STATE_E;
                cmpxchg_ret = atomic_cmpxchg(&privateKeyReadEnable,
                                             cur_privateKeyReadEnable,
                                             cur_privateKeyReadEnable + 1);
                if (cmpxchg_ret == cur_privateKeyReadEnable)
                    return 0;
                cur_privateKeyReadEnable = cmpxchg_ret;
            }
        }
    }
    return BAD_FUNC_ARG;
}

#else /* !WOLFSSL_LINUXKM */

/* Allows an external read of a private key from in boundary */
int wolfCrypt_SetPrivateKeyReadEnable_fips(int enable, enum wc_KeyType keyType)
{
    WC_LOG_FUNC_ID("1.03");

    if (keyType == WC_KEYTYPE_ALL) {
        int value = GetTLS(&privateKeyReadEnable);
        if (enable == 0) {
            if (value > 0)
                value--;
        }
        else {
            if (value < INT_MAX)
                value++;
        }
        SetTLS(&privateKeyReadEnable, value);
        return 0;
    }
    return BAD_FUNC_ARG;
}

#endif /* !WOLFSSL_LINUXKM */

int wolfCrypt_GetPrivateKeyReadEnable_fips(enum wc_KeyType keyType)
{
    WC_LOG_FUNC_ID("1.04");
    if (keyType == WC_KEYTYPE_ALL) {
        return GetTLS(&privateKeyReadEnable);
    }
    return BAD_FUNC_ARG;
}


/* Trigger an integrity test. */
int wolfCrypt_IntegrityTest_fips(void)
{
    WC_LOG_FUNC_ID("1.05");
    DoSelfTest();
    return 0;
}


/* get current error status, 0 on ok */
int wolfCrypt_GetStatus_fips(void)
{
    WC_LOG_FUNC_ID("1.06");
    if (posStatus != POS_SUCCESS)
        return posReturn;

#ifndef NO_RNG
    if (CheckConTestStatus() != 0)
        return DRBG_CONT_FIPS_E;
#endif

    return 0;
}

#ifdef WOLFCRYPT_FIPS_CORE_DYNAMIC_HASH_VALUE
extern char verifyCore[];
#else
extern const char verifyCore[];
#endif

/* get current inCore hash */
/* TE05.08.02 requires the CSP base16_hash to be zero'd however a customer
 * (ZD17183) was dependent upon this returning a non-empty hash for
 * some application logic. DP modified this function to return the non-zero
 * verifyCore instead when the POS has passed to satisfy customer requirement.
 * A new API was added to check the CSP is properly zeroised, please use
 * wolfCrypt_GetRawComputedHash_fips() for op-test and any other cases that
 * expect the hash to be a valid string when failing or empty string when
 * module has passed the pre-operational self test */
const char* wolfCrypt_GetCoreHash_fips(void)
{
    WC_LOG_FUNC_ID("1.07");
    if (posStatus == POS_SUCCESS)
        return verifyCore;
    else
        return base16_hash;
}

/* Restores behavior previously expected from wolfCrypt_GetCoreHash_fips() */
const char* wolfCrypt_GetRawComputedHash_fips(void)
{
    WC_LOG_FUNC_ID("1.08");
    return base16_hash;
}

/* If porting is done define HAVE_FIPS_VERSION_PORT in this file, should be
 * hard-coded into that module version not left up to user_settings.h or other
 * to set. Current version scheme supports up to 3 chars for porting IE:
 * "a" or "ab" or "abc" are valid. "abcd" is invalid. Compiler should throw an
 * warning or error but in case build with warnings is allowed a run time check
 * for valid length is also implemented
 */
/* Example to disallow external setting of the PORT version:
 * #ifdef HAVE_FIPS_VERSION_PORT
 *     #undef HAVE_FIPS_VERSION_PORT
 *     #define HAVE_FIPS_VERSION_PORT "a"
 * #endif
 *
 * End result should be something like "wolfCrypt v6.0.0a" when porting changes
 * present where base module version was "wolfCrypt v6.0.0" for non-porting
 * changes increment HAVE_FIPS_VERSION_MINOR or HAVE_FIPS_VERSION_PATCH as
 * appropriate and add a new configure option to configure.ac respectively
 */
const char* wolfCrypt_GetVersion_fips(void)
{
    int versionLen;
    WC_LOG_FUNC_ID("1.09");
    if (versionInitialized == 0) {
        XMEMSET(version_string, 0, WC_VERSION_LEN);
#ifdef HAVE_FIPS_VERSION_PORT
        versionLen = XSNPRINTF(version_string, WC_VERSION_LEN,
                               "wolfCrypt v%d.%d.%d%s",
                               HAVE_FIPS_VERSION_MAJOR,
                               HAVE_FIPS_VERSION_MINOR,
                               HAVE_FIPS_VERSION_PATCH,
                               HAVE_FIPS_VERSION_PORT);
#else
        versionLen = XSNPRINTF(version_string, WC_VERSION_LEN,
                               "wolfCrypt v%d.%d.%d",
                               HAVE_FIPS_VERSION_MAJOR,
                               HAVE_FIPS_VERSION_MINOR,
                               HAVE_FIPS_VERSION_PATCH);
#endif

        if (versionLen <= 0 || versionLen >= WC_VERSION_LEN) {
#ifdef DEBUG_FIPS_VERBOSE
            printf("Invalid version length detected %d\n", versionLen);
#endif
            if (errCb) {
                errCb(0, FIPS_INVALID_VER_E, base16_hash);
            }
            return NULL;
        }

        versionInitialized = 1;
    }
    return (const char*) version_string;
}


int wc_GetCastStatus_fips(int type)
{
    WC_LOG_FUNC_ID("1.10");
    if (type >= FIPS_CAST_COUNT || type < 0)
        return WC_FAILURE;
    else
        return fipsCastStatus_get(type);
}


int wc_RunCast_fips(int type)
{
    int castErr = 0;

    WC_LOG_FUNC_ID("1.11");
#ifdef WOLFSSL_LINUXKM
    castErr =  DoCAST(type);
#else /* !WOLFSSL_LINUXKM */
    SetTLS(&thisThreadInPOS, 1);
    castErr = DoCAST(type);
    SetTLS(&thisThreadInPOS, 0);
#endif /* !WOLFSSL_LINUXKM */
    if ((castErr != 0) && (fipsMode != FIPS_MODE_DEGRADED)) {
        EnterDegradedMode(castErr);
    }
    return castErr;
}

int wc_RunAllCast_fips(void)
{
    int failCount = 0;

    WC_LOG_FUNC_ID("1.12");
#ifndef WOLFSSL_LINUXKM
    SetTLS(&thisThreadInPOS, 1);
#endif
#if !defined(NO_AES) && !defined(NO_AES_CBC)
#if defined(DEBUG_FIPS_VERBOSE)
    printf("FIPS_CAST_STATE_FAILURE = %d\n", FIPS_CAST_STATE_FAILURE);
    printf("wc_GetCastStatus_fips(FIPS_CAST_AES_CBC) = %d\n",
            wc_GetCastStatus_fips(FIPS_CAST_AES_CBC));
#endif
    if (wc_GetCastStatus_fips(FIPS_CAST_AES_CBC) != FIPS_CAST_STATE_FAILURE) {
        if (wc_RunCast_fips(FIPS_CAST_AES_CBC) != 0) {
            FIPS_MSG("AES-CBC CAST failed");
            failCount++;
        }
    } else {
        failCount++;
    }
#endif
#ifdef HAVE_AESGCM
#if defined(DEBUG_FIPS_VERBOSE)
    printf("wc_GetCastStatus_fips(FIPS_CAST_AES_GCM) = %d\n",
            wc_GetCastStatus_fips(FIPS_CAST_AES_GCM));
#endif
    if (wc_GetCastStatus_fips(FIPS_CAST_AES_GCM) != FIPS_CAST_STATE_FAILURE) {
        if (wc_RunCast_fips(FIPS_CAST_AES_GCM) != 0) {
            FIPS_MSG("AES-GCM CAST failed");
            failCount++;
        }
    } else {
        failCount++;
    }
#endif
#ifndef NO_SHA
#if defined(DEBUG_FIPS_VERBOSE)
    printf("wc_GetCastStatus_fips(FIPS_CAST_HMAC_SHA1) = %d\n",
            wc_GetCastStatus_fips(FIPS_CAST_HMAC_SHA1));
#endif
    if (wc_GetCastStatus_fips(FIPS_CAST_HMAC_SHA1) != FIPS_CAST_STATE_FAILURE) {
        if (wc_RunCast_fips(FIPS_CAST_HMAC_SHA1) != 0) {
            FIPS_MSG("HMAC-SHA1 CAST failed");
            failCount++;
        }
    } else {
        failCount++;
    }
#endif
    /* the only non-optional CAST */
#if defined(DEBUG_FIPS_VERBOSE)
    printf("wc_GetCastStatus_fips(FIPS_CAST_HMAC_SHA2_256) = %d\n",
            wc_GetCastStatus_fips(FIPS_CAST_HMAC_SHA2_256));
#endif
    if (wc_GetCastStatus_fips(FIPS_CAST_HMAC_SHA2_256)
                              != FIPS_CAST_STATE_FAILURE) {
        if (wc_RunCast_fips(FIPS_CAST_HMAC_SHA2_256) != 0) {
            FIPS_MSG("HMAC-SHA2-256 CAST failed");
            failCount++;
        }
    } else {
        failCount++;
    }
#ifdef WOLFSSL_SHA512
#if defined(DEBUG_FIPS_VERBOSE)
    printf("wc_GetCastStatus_fips(FIPS_CAST_HMAC_SHA2_512) = %d\n",
            wc_GetCastStatus_fips(FIPS_CAST_HMAC_SHA2_512));
#endif
    if (wc_GetCastStatus_fips(FIPS_CAST_HMAC_SHA2_512)
                              != FIPS_CAST_STATE_FAILURE) {
        if (wc_RunCast_fips(FIPS_CAST_HMAC_SHA2_512) != 0) {
            FIPS_MSG("HMAC-SHA2-512 CAST failed");
        }
    } else {
        failCount++;
    }
#endif
#ifdef WOLFSSL_SHA3
#if defined(DEBUG_FIPS_VERBOSE)
    printf("wc_GetCastStatus_fips(FIPS_CAST_HMAC_SHA3_256) = %d\n",
            wc_GetCastStatus_fips(FIPS_CAST_HMAC_SHA3_256));
#endif
    if (wc_GetCastStatus_fips(FIPS_CAST_HMAC_SHA3_256)
                              != FIPS_CAST_STATE_FAILURE) {
        if (wc_RunCast_fips(FIPS_CAST_HMAC_SHA3_256) != 0) {
            FIPS_MSG("HMAC-SHA3-256 CAST failed");
            failCount++;
        }
    } else {
        failCount++;
    }
#endif
#ifdef HAVE_HASHDRBG
#if defined(DEBUG_FIPS_VERBOSE)
    printf("wc_GetCastStatus_fips(FIPS_CAST_DRBG) = %d\n",
            wc_GetCastStatus_fips(FIPS_CAST_DRBG));
#endif
    if (wc_GetCastStatus_fips(FIPS_CAST_DRBG) != FIPS_CAST_STATE_FAILURE) {
        if (wc_RunCast_fips(FIPS_CAST_DRBG) != 0) {
            FIPS_MSG("Hash_DRBG CAST failed");
            failCount++;
        }
    } else {
        failCount++;
    }
#endif
#ifndef NO_RSA
#if defined(DEBUG_FIPS_VERBOSE)
    printf("wc_GetCastStatus_fips(FIPS_CAST_RSA_SIGN_PKCS1v15) = %d\n",
            wc_GetCastStatus_fips(FIPS_CAST_RSA_SIGN_PKCS1v15));
#endif
    if (wc_GetCastStatus_fips(FIPS_CAST_RSA_SIGN_PKCS1v15)
                              != FIPS_CAST_STATE_FAILURE) {
        if (wc_RunCast_fips(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0) {
            FIPS_MSG("RSA sign CAST failed");
            failCount++;
        }
    } else {
        failCount++;
    }
#endif
#if defined(HAVE_ECC_CDH) && defined(HAVE_ECC_CDH_CAST)
#if defined(DEBUG_FIPS_VERBOSE)
    printf("wc_GetCastStatus_fips(FIPS_CAST_ECC_CDH) = %d\n",
            wc_GetCastStatus_fips(FIPS_CAST_ECC_CDH));
#endif
    if (wc_GetCastStatus_fips(FIPS_CAST_ECC_CDH) != FIPS_CAST_STATE_FAILURE) {
        if (wc_RunCast_fips(FIPS_CAST_ECC_CDH) != 0) {
            FIPS_MSG("ECC CDH CAST failed");
            failCount++;
        }
    } else {
        failCount++;
    }
#endif
#ifdef HAVE_ECC_DHE
#if defined(DEBUG_FIPS_VERBOSE)
    printf("wc_GetCastStatus_fips(FIPS_CAST_ECC_PRIMITIVE_Z) = %d\n",
            wc_GetCastStatus_fips(FIPS_CAST_ECC_PRIMITIVE_Z));
#endif
    /* ECC_PRIMITIVE_Z depends on AES so don't re-run if AES failed */
    if (wc_GetCastStatus_fips(FIPS_CAST_ECC_PRIMITIVE_Z)
                              != FIPS_CAST_STATE_FAILURE) {
        if (wc_RunCast_fips(FIPS_CAST_ECC_PRIMITIVE_Z) != 0) {
            FIPS_MSG("ECC Primitive Z CAST failed");
            failCount++;
        }
    } else {
        failCount++;
    }
#endif
#ifdef HAVE_ECC
#if defined(DEBUG_FIPS_VERBOSE)
    printf("wc_GetCastStatus_fips(FIPS_CAST_ECDSA) = %d\n",
            wc_GetCastStatus_fips(FIPS_CAST_ECDSA));
#endif
    if (wc_GetCastStatus_fips(FIPS_CAST_ECDSA) != FIPS_CAST_STATE_FAILURE) {
        if (wc_RunCast_fips(FIPS_CAST_ECDSA) != 0) {
            FIPS_MSG("ECDSA CAST failed");
            failCount++;
        }
    } else {
        failCount++;
    }
#endif
#ifndef NO_DH
#if defined(DEBUG_FIPS_VERBOSE)
    printf("wc_GetCastStatus_fips(FIPS_CAST_DH_PRIMITIVE_Z) = %d\n",
            wc_GetCastStatus_fips(FIPS_CAST_DH_PRIMITIVE_Z));
#endif
    if (wc_GetCastStatus_fips(FIPS_CAST_DH_PRIMITIVE_Z)
                              != FIPS_CAST_STATE_FAILURE) {
        if (wc_RunCast_fips(FIPS_CAST_DH_PRIMITIVE_Z) != 0) {
            FIPS_MSG("DH Primitive Z CAST failed");
        }
    } else {
        failCount++;
    }
#endif
#ifdef WOLFSSL_HAVE_PRF
#if defined(DEBUG_FIPS_VERBOSE)
    printf("wc_GetCastStatus_fips(FIPS_CAST_KDF_TLS12) = %d\n",
            wc_GetCastStatus_fips(FIPS_CAST_KDF_TLS12));
#endif
    if (wc_GetCastStatus_fips(FIPS_CAST_KDF_TLS12) != FIPS_CAST_STATE_FAILURE) {
        if (wc_RunCast_fips(FIPS_CAST_KDF_TLS12) != 0) {
            FIPS_MSG("KDF TLSv1.2 CAST failed");
            failCount++;
        }
    } else {
        failCount++;
    }
#endif
#if defined(HAVE_HKDF) && !defined(NO_HMAC)
#if defined(DEBUG_FIPS_VERBOSE)
    printf("wc_GetCastStatus_fips(FIPS_CAST_KDF_TLS13) = %d\n",
            wc_GetCastStatus_fips(FIPS_CAST_KDF_TLS13));
#endif
    if (wc_GetCastStatus_fips(FIPS_CAST_KDF_TLS13) != FIPS_CAST_STATE_FAILURE) {
        if (wc_RunCast_fips(FIPS_CAST_KDF_TLS13) != 0) {
            FIPS_MSG("KDF TLSv1.3 CAST failed");
            failCount++;
        }
    } else {
        failCount++;
    }
#endif
#ifdef WOLFSSL_WOLFSSH
#if defined(DEBUG_FIPS_VERBOSE)
    printf("wc_GetCastStatus_fips(FIPS_CAST_KDF_SSH) = %d\n",
            wc_GetCastStatus_fips(FIPS_CAST_KDF_SSH));
#endif
    if (wc_GetCastStatus_fips(FIPS_CAST_KDF_SSH) != FIPS_CAST_STATE_FAILURE) {
        if (wc_RunCast_fips(FIPS_CAST_KDF_SSH) != 0) {
            FIPS_MSG("KDF SSHv2.0 CAST failed");
            failCount++;
        }
    } else {
        failCount++;
    }
#endif

#ifdef WC_SRTP_KDF
#if defined(DEBUG_FIPS_VERBOSE)
    printf("wc_GetCastStatus_fips(FIPS_CAST_KDF_SRTP) = %d\n",
            wc_GetCastStatus_fips(FIPS_CAST_KDF_SRTP));
#endif
    if (wc_GetCastStatus_fips(FIPS_CAST_KDF_SRTP) != FIPS_CAST_STATE_FAILURE) {
        if (wc_RunCast_fips(FIPS_CAST_KDF_SRTP) != 0) {
            FIPS_MSG("KDF SRTP CAST failed");
            failCount++;
        }
    } else {
        failCount++;
    }
#endif

#ifdef HAVE_ED25519
#if defined(DEBUG_FIPS_VERBOSE)
    printf("wc_GetCastStatus_fips(FIPS_CAST_ED25519) = %d\n",
            wc_GetCastStatus_fips(FIPS_CAST_ED25519));
#endif
    if (wc_GetCastStatus_fips(FIPS_CAST_ED25519) != FIPS_CAST_STATE_FAILURE) {
        if (wc_RunCast_fips(FIPS_CAST_ED25519) != 0) {
            FIPS_MSG("ED25519 CAST failed");
            failCount++;
        }
    } else {
        failCount++;
    }
#endif

#ifdef HAVE_ED448
#if defined(DEBUG_FIPS_VERBOSE)
    printf("wc_GetCastStatus_fips(FIPS_CAST_ED448) = %d\n",
            wc_GetCastStatus_fips(FIPS_CAST_ED448));
#endif
    if (wc_GetCastStatus_fips(FIPS_CAST_ED448) != FIPS_CAST_STATE_FAILURE) {
        if (wc_RunCast_fips(FIPS_CAST_ED448) != 0) {
            FIPS_MSG("ED448 CAST failed");
            failCount++;
        }
    } else {
        failCount++;
    }
#endif

#ifdef HAVE_PBKDF2
#if defined(DEBUG_FIPS_VERBOSE)
    printf("wc_GetCastStatus_fips(FIPS_CAST_PBKDF2) = %d\n",
            wc_GetCastStatus_fips(FIPS_CAST_PBKDF2));
#endif
    if (wc_GetCastStatus_fips(FIPS_CAST_PBKDF2) != FIPS_CAST_STATE_FAILURE) {
        if (wc_RunCast_fips(FIPS_CAST_PBKDF2) != 0) {
            FIPS_MSG("PBKDF2 CAST failed");
            failCount++;
        }
    } else {
        failCount++;
    }
#endif

#ifndef WOLFSSL_LINUXKM
    SetTLS(&thisThreadInPOS, 0);
#endif

    if (failCount > 0 && fipsMode != FIPS_MODE_DEGRADED) {
        fipsMode = FIPS_MODE_DEGRADED;
        FIPS_MSG("Module status set to: FIPS_MODE_DEGRADED");
    } else if (fipsMode == FIPS_MODE_DEGRADED) {
        FIPS_MSG("Module status - FIPS_MODE_DEGRADED");
    } else {
        FIPS_MSG("Module status - FIPS_MODE_NORMAL");
    }

    return failCount;
}

/* // NOLINTEND(misc-no-recursion) */

/* AES TIERED TEST COMMENT:
 * It keeps coming up, why are we checking CBC when running CCM service or
 * GCM when running a CCM service??
 * The reason is that the AES tests are tiered.
 *
 * Reference 140-3 IG 10.3.A -> Resolution for "symmetric key algorithms such as
 * SKIPJACK, Triple-DES, or AES:" -> section 'd.' items (i), (ii), (iii)
 *
 * Tier 1 (Most complex): GCM, CCM, CMAC, GMAC
 * A CAST is required for one (1) mode if implemented. (We test GCM, that
 * test now governs use of the others in this tier IE check GCM
 * self-test/CAST status before using CCM, CMAC, or GMAC)
 *
 * Tier 2 (Mid-complexity): KW or KWP
 * No test is required if GCM, CCM, CMAC or GMAC are self-tested from tier 1,
 * If a tier 1 self test is used that test 'governs' use of KW otherwise if
 * no tier 1 self test and KW is implemented a KW self test shall be used
 * instead of a tier 1 test.
 *
 * Tier 3 (Least complex): ECB, CBC, OFB, CFB, CTR, AESFF1 or XTS
 * A cast is required if no other modes of the corresponding encryption
 * algorithm are implemented and self-tested. We test CBC mode and CBC
 * governs use an "encryption and decryption" so when doing CCM Encrypt we
 * check if CBC and GCM have passed self-test but if doing CMAC (which is not
 * an encrypt operation) we will only check GCM from tier 1.
 */

/* Aes wrappers */
/* setkey wrapper */
#ifndef NO_AES
int wc_AesSetKey_fips(Aes* aes, const byte* userKey, word32 keylen,
                   const byte* iv, int dir)
{
    WC_LOG_FUNC_ID("1.13");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesSetKey(aes, userKey, keylen, iv, dir);
}


/* set iv wrapper */
int wc_AesSetIV_fips(Aes* aes, const byte* iv)
{
    WC_LOG_FUNC_ID("1.14");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesSetIV(aes, iv);
}

#ifdef HAVE_AES_ECB
/* ecb encrypt wrapper */
int wc_AesEcbEncrypt_fips(Aes* aes, byte* out, const byte* in, word32 sz)
{
    WC_LOG_FUNC_ID("1.15");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesEcbEncrypt(aes, out, in, sz);
}


/* ecb decrypt wrapper */
int wc_AesEcbDecrypt_fips(Aes* aes, byte* out, const byte* in, word32 sz)
{
    WC_LOG_FUNC_ID("1.16");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesEcbDecrypt(aes, out, in, sz);
}

int wc_AesSetKeyDirect_fips(Aes* aes, const byte* key, word32 len,
                            const byte* iv, int dir)
{
    WC_LOG_FUNC_ID("1.17");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesSetKeyDirect(aes, key, len, iv, dir);
}


#endif

#ifdef HAVE_AES_CBC
/* cbc encrypt wrapper */
int wc_AesCbcEncrypt_fips(Aes* aes, byte* out, const byte* in, word32 sz)
{
    WC_LOG_FUNC_ID("1.18");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesCbcEncrypt(aes, out, in, sz);
}


/* cbc decrypt wrapper */
int wc_AesCbcDecrypt_fips(Aes* aes, byte* out, const byte* in, word32 sz)
{
    WC_LOG_FUNC_ID("1.19");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesCbcDecrypt(aes, out, in, sz);
}
#endif

#ifdef WOLFSSL_AES_COUNTER
/* ctr encrypt wrapper */
int wc_AesCtrEncrypt_fips(Aes* aes, byte* out, const byte* in, word32 sz)
{
    WC_LOG_FUNC_ID("1.20");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesCtrEncrypt(aes, out, in, sz);
}

int wc_AesCtrSetKey_fips(Aes* aes, const byte* key, word32 len,
                                         const byte* iv, int dir)
{
    WC_LOG_FUNC_ID("1.21");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesCtrSetKey(aes, key, len, iv, dir);
}
#endif

#ifdef WOLFSSL_AES_OFB
/* ofb encrypt wrapper */
int wc_AesOfbEncrypt_fips(Aes* aes, byte* out, const byte* in, word32 sz)
{
    WC_LOG_FUNC_ID("1.22");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesOfbEncrypt(aes, out, in, sz);
}


/* ofb decrypt wrapper */
int wc_AesOfbDecrypt_fips(Aes* aes, byte* out, const byte* in, word32 sz)
{
    WC_LOG_FUNC_ID("1.23");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesOfbDecrypt(aes, out, in, sz);
}
#endif

#ifdef WOLFSSL_AES_CFB
/* CFB governed by CBC per IG 10.3.A */
int wc_AesCfbEncrypt_fips(Aes* aes, byte* out, const byte* in, word32 sz)
{
    WC_LOG_FUNC_ID("1.24");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesCfbEncrypt(aes, out, in, sz);
}

int wc_AesCfb1Encrypt_fips(Aes* aes, byte* out, const byte* in, word32 sz)
{
    WC_LOG_FUNC_ID("1.25");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesCfb1Encrypt(aes, out, in, sz);
}

int wc_AesCfb8Encrypt_fips(Aes* aes, byte* out, const byte* in, word32 sz)
{
    WC_LOG_FUNC_ID("1.26");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesCfb8Encrypt(aes, out, in, sz);
}

#ifdef HAVE_AES_DECRYPT
int wc_AesCfbDecrypt_fips(Aes* aes, byte* out, const byte* in, word32 sz)
{
    WC_LOG_FUNC_ID("1.27");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesCfbDecrypt(aes, out, in, sz);
}

int wc_AesCfb1Decrypt_fips(Aes* aes, byte* out, const byte* in, word32 sz)
{
    WC_LOG_FUNC_ID("1.28");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesCfb1Decrypt(aes, out, in, sz);
}

int wc_AesCfb8Decrypt_fips(Aes* aes, byte* out, const byte* in, word32 sz)
{
    WC_LOG_FUNC_ID("1.29");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesCfb8Decrypt(aes, out, in, sz);
}

#endif /* HAVE_AES_DECRYPT */
#endif /* WOLFSSL_AES_CFB */

int wc_AesGetKeySize_fips(Aes* aes, word32* keySize)
{
    WC_LOG_FUNC_ID("1.30");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesGetKeySize(aes, keySize);
}

/* Init like a free function, no cryptography just initializing a structure
 * for use so make it pass-through without the "Allowed" checks */
int  wc_AesInit_fips(Aes* aes, void* heap, int devId)
{
    WC_LOG_FUNC_ID("1.31");
    (void) devId; /* Disabled in FIPS mode */

    return wc_AesInit(aes, heap, FIPS_INVALID_DEVID);
}

void wc_AesFree_fips(Aes* aes)
{
    WC_LOG_FUNC_ID("1.32");
    wc_AesFree(aes);
}
#endif /* NO_AES */


/* gcm set key wrapper */
#ifdef HAVE_AESGCM
int wc_AesGcmSetKey_fips(Aes* aes, const byte* key, word32 len)
{
    WC_LOG_FUNC_ID("1.33");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_AES_GCM) != 0)
        return AESGCM_KAT_FIPS_E;

    return wc_AesGcmSetKey(aes, key, len);
}

/* gcm set external iv wrapper */
int wc_AesGcmSetExtIV_fips(Aes* aes, const byte* iv, word32 ivSz)
{
    WC_LOG_FUNC_ID("1.34");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_AES_GCM) != 0)
        return AESGCM_KAT_FIPS_E;

    return wc_AesGcmSetExtIV(aes, iv, ivSz);
}

/* gcm set internal iv wrapper */
int wc_AesGcmSetIV_fips(Aes* aes, word32 ivSz, const byte* ivFixed,
                     word32 ivFixedSz, WC_RNG* rng)
{
    WC_LOG_FUNC_ID("1.35");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_AES_GCM) != 0)
        return AESGCM_KAT_FIPS_E;

    return wc_AesGcmSetIV(aes, ivSz, ivFixed, ivFixedSz, rng);
}

/* gcm encrypt wrapper */
int wc_AesGcmEncrypt_fips(Aes* aes, byte* out, const byte* in, word32 sz,
                       byte* ivOut, word32 ivOutSz,
                       byte* authTag, word32 authTagSz,
                       const byte* authIn, word32 authInSz)
{
    WC_LOG_FUNC_ID("1.36");

    /* re-direct to the _ex API below which will execute the allowed checks */
    return wc_AesGcmEncrypt_ex_fips(aes, out, in, sz, ivOut, ivOutSz, authTag,
                            authTagSz, authIn, authInSz);
}

int  wc_AesGcmEncrypt_ex_fips(Aes* aes, byte* out, const byte* in, word32 sz,
                          byte* ivOut, word32 ivOutSz, byte* authTag,
                          word32 authTagSz, const byte* authIn, word32 authInSz)
{
    WC_LOG_FUNC_ID("1.37");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_AES_GCM) != 0)
        return AESGCM_KAT_FIPS_E;

    return wc_AesGcmEncrypt_ex(aes, out, in, sz, ivOut, ivOutSz, authTag,
                               authTagSz, authIn, authInSz);
}


/* gcm decrypt wrapper */
int wc_AesGcmDecrypt_fips(Aes* aes, byte* out, const byte* in,
                       word32 sz, const byte* iv, word32 ivSz,
                       const byte* authTag, word32 authTagSz,
                       const byte* authIn, word32 authInSz)
{
    WC_LOG_FUNC_ID("1.38");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_AES_GCM) != 0)
        return AESGCM_KAT_FIPS_E;

    return wc_AesGcmDecrypt(aes, out, in, sz, iv, ivSz, authTag, authTagSz,
                         authIn, authInSz);
}

/* GMAC convenience wrapper */
int wc_Gmac_fips(const byte* key, word32 keySz, byte* iv, word32 ivSz,
              const byte* authIn, word32 authInSz,
              byte* authTag, word32 authTagSz, WC_RNG* rng)
{
    WC_LOG_FUNC_ID("1.39");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Since GMAC is just doing data integrity, AES-CBC failing it's cast would
     * only indicate the encryption and decryption are unavailable for use.
     * do not check CBC CAST status for Gmac operations */

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_GCM) != 0)
        return AESGCM_KAT_FIPS_E;

    return wc_Gmac(key, keySz, iv, ivSz, authIn, authInSz,
                   authTag, authTagSz, rng);
}

/* GMAC verify convenience wrapper */
int wc_GmacVerify_fips(const byte* key, word32 keySz,
                    const byte* iv, word32 ivSz,
                    const byte* authIn, word32 authInSz,
                    const byte* authTag, word32 authTagSz)
{
    WC_LOG_FUNC_ID("1.40");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Since GMAC is just doing data integrity, AES-CBC failing it's cast would
     * only indicate the encryption and decryption are unavailable for use.
     * do not check CBC CAST status for Gmac operations */

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_GCM) != 0)
        return AESGCM_KAT_FIPS_E;

    return wc_GmacVerify(key, keySz, iv, ivSz,
                         authIn, authInSz, authTag, authTagSz);
}

int wc_GmacSetKey_fips(Gmac* gmac, const byte* key, word32 len)
{
    WC_LOG_FUNC_ID("1.41");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Since GMAC is just doing data integrity, AES-CBC failing it's cast would
     * only indicate the encryption and decryption are unavailable for use.
     * do not check CBC CAST status for Gmac operations */

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_GCM) != 0)
        return AESGCM_KAT_FIPS_E;

    return wc_GmacSetKey(gmac, key, len);
}

int wc_GmacUpdate_fips(Gmac* gmac, const byte* iv, word32 ivSz,
                  const byte* authIn, word32 authInSz,
                  byte* authTag, word32 authTagSz)
{
    WC_LOG_FUNC_ID("1.42");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Since GMAC is just doing data integrity, AES-CBC failing it's cast would
     * only indicate the encryption and decryption are unavailable for use.
     * do not check CBC CAST status for Gmac operations */

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_GCM) != 0)
        return AESGCM_KAT_FIPS_E;

    return wc_GmacUpdate(gmac, iv, ivSz, authIn, authInSz, authTag,
                            authTagSz);
}

#ifdef WOLFSSL_AESGCM_STREAM
int wc_AesGcmInit_fips(Aes* aes, const byte* key, word32 len, const byte* iv,
                       word32 ivSz)
{
    WC_LOG_FUNC_ID("1.43");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_AES_GCM) != 0)
        return AESGCM_KAT_FIPS_E;

    return wc_AesGcmInit(aes, key, len, iv, ivSz);
}

int wc_AesGcmEncryptInit_fips(Aes* aes, const byte* key, word32 len, const byte* iv,
                              word32 ivSz)
{
    WC_LOG_FUNC_ID("1.44");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_AES_GCM) != 0)
        return AESGCM_KAT_FIPS_E;

    return wc_AesGcmEncryptInit(aes, key, len, iv, ivSz);
}

int wc_AesGcmEncryptInit_ex_fips(Aes* aes, const byte* key, word32 len, byte* ivOut,
                                 word32 ivOutSz)
{
    WC_LOG_FUNC_ID("1.45");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_AES_GCM) != 0)
        return AESGCM_KAT_FIPS_E;

    return wc_AesGcmEncryptInit_ex(aes, key, len, ivOut, ivOutSz);
}

int wc_AesGcmEncryptUpdate_fips(Aes* aes, byte* out, const byte* in, word32 sz,
                                const byte* authIn, word32 authInSz)
{
    WC_LOG_FUNC_ID("1.46");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_AES_GCM) != 0)
        return AESGCM_KAT_FIPS_E;

    return wc_AesGcmEncryptUpdate(aes, out, in, sz, authIn, authInSz);
}

int wc_AesGcmEncryptFinal_fips(Aes* aes, byte* authTag, word32 authTagSz)
{
    WC_LOG_FUNC_ID("1.47");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_AES_GCM) != 0)
        return AESGCM_KAT_FIPS_E;

    return wc_AesGcmEncryptFinal(aes, authTag, authTagSz);
}

int wc_AesGcmDecryptInit_fips(Aes* aes, const byte* key, word32 len, const byte* iv,
                         word32 ivSz)
{
    WC_LOG_FUNC_ID("1.48");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_AES_GCM) != 0)
        return AESGCM_KAT_FIPS_E;

    return wc_AesGcmDecryptInit(aes, key, len, iv, ivSz);
}

int wc_AesGcmDecryptUpdate_fips(Aes* aes, byte* out, const byte* in, word32 sz,
                           const byte* authIn, word32 authInSz)
{
    WC_LOG_FUNC_ID("1.49");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_AES_GCM) != 0)
        return AESGCM_KAT_FIPS_E;

    return wc_AesGcmDecryptUpdate(aes, out, in, sz, authIn, authInSz);
}

int wc_AesGcmDecryptFinal_fips(Aes* aes, const byte* authTag, word32 authTagSz)
{
    WC_LOG_FUNC_ID("1.50");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_AES_GCM) != 0)
        return AESGCM_KAT_FIPS_E;

    return wc_AesGcmDecryptFinal(aes, authTag, authTagSz);
}

#endif
#endif /* HAVE_AESGCM */


#if defined(HAVE_AESCCM)
/* ccm set key wrapper */
int wc_AesCcmSetKey_fips(Aes* aes, const byte* key, word32 len)
{
    WC_LOG_FUNC_ID("1.51");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_AES_GCM) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesCcmSetKey(aes, key, len);
}


/* ccm set nonce wrapper */
int wc_AesCcmSetNonce_fips(Aes* aes, const byte* nonce, word32 nonceSz)
{
    WC_LOG_FUNC_ID("1.52");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_AES_GCM) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesCcmSetNonce(aes, nonce, nonceSz);
}


/* ccm encrypt wrapper */
int  wc_AesCcmEncrypt_ex_fips(Aes* aes, byte* out, const byte* in, word32 sz,
                              byte* ivOut, word32 ivOutSz, byte* authTag,
                              word32 authTagSz, const byte* authIn,
                              word32 authInSz)
{
    WC_LOG_FUNC_ID("1.53");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_AES_GCM) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesCcmEncrypt_ex(aes, out, in, sz, ivOut, ivOutSz,
                               authTag, authTagSz, authIn, authInSz);
}

int wc_AesCcmEncrypt_fips(Aes* aes, byte* out, const byte* in,
                       word32 sz, byte* ivOut, word32 ivOutSz,
                       byte* authTag, word32 authTagSz,
                       const byte* authIn, word32 authInSz)
{
    WC_LOG_FUNC_ID("1.54");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_AES_GCM) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesCcmEncrypt(aes, out, in, sz, ivOut, ivOutSz,
                            authTag, authTagSz, authIn, authInSz);
}


/* ccm decrypt wrapper */
int wc_AesCcmDecrypt_fips(Aes* aes, byte* out, const byte* in,
                       word32 sz, const byte* iv, word32 ivSz,
                       const byte* authTag, word32 authTagSz,
                       const byte* authIn, word32 authInSz)
{
    WC_LOG_FUNC_ID("1.55");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_AES_GCM) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesCcmDecrypt(aes, out, in, sz, iv, ivSz, authTag, authTagSz,
                         authIn, authInSz);
}
#endif /* HAVE_AESCCM */

#ifdef HAVE_AES_KEYWRAP
int wc_AesKeyWrap_fips(const byte* key, word32 keySz, const byte* in, word32 inSz,
                       byte* out, word32 outSz, const byte* iv)
{
    WC_LOG_FUNC_ID("1.56");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_AES_GCM) != 0)
        return AESGCM_KAT_FIPS_E;

    return wc_AesKeyWrap(key, keySz, in, inSz, out, outSz, iv);
}

int wc_AesKeyWrap_ex_fips(Aes *aes, const byte* in, word32 inSz, byte* out,
                          word32 outSz, const byte* iv)
{
    WC_LOG_FUNC_ID("1.57");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_AES_GCM) != 0)
        return AESGCM_KAT_FIPS_E;

    return wc_AesKeyWrap_ex(aes, in, inSz, out, outSz, iv);
}

int wc_AesKeyUnWrap_fips(const byte* key, word32 keySz, const byte* in, word32 inSz,
                         byte* out, word32 outSz, const byte* iv)
{
    WC_LOG_FUNC_ID("1.58");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_AES_GCM) != 0)
        return AESGCM_KAT_FIPS_E;

    return wc_AesKeyUnWrap(key, keySz, in, inSz, out, outSz, iv);
}

int wc_AesKeyUnWrap_ex_fips(Aes *aes, const byte* in, word32 inSz, byte* out,
                            word32 outSz, const byte* iv)
{
    WC_LOG_FUNC_ID("1.59");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_AES_GCM) != 0)
        return AESGCM_KAT_FIPS_E;

    return wc_AesKeyUnWrap_ex(aes, in, inSz, out, outSz, iv);
}

#endif /* HAVE_AES_KEYWRAP */

#ifdef WOLFSSL_AES_XTS
int wc_AesXtsInit_fips(XtsAes* aes, void* heap, int devId)
{
    WC_LOG_FUNC_ID("1.60");

    (void) devId; /* Disabled in FIPS mode */
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesXtsInit(aes, heap, FIPS_INVALID_DEVID);
}

int wc_AesXtsSetKeyNoInit_fips(XtsAes* aes, const byte* key, word32 len,
                               int dir)
{
    WC_LOG_FUNC_ID("1.61");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesXtsSetKeyNoInit(aes, key, len, dir);
}

int wc_AesXtsSetKey_fips(XtsAes* aes, const byte* key, word32 len, int dir,
                         void* heap, int devId)
{
    WC_LOG_FUNC_ID("1.62");

    (void) devId; /* Disabled in FIPS mode */
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesXtsSetKey(aes, key, len, dir, heap, FIPS_INVALID_DEVID);
}

int wc_AesXtsEncryptSector_fips(XtsAes* aes, byte* out, const byte* in,
                                word32 sz, word64 sector)
{
    WC_LOG_FUNC_ID("1.63");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesXtsEncryptSector(aes, out, in, sz, sector);
}

int wc_AesXtsDecryptSector_fips(XtsAes* aes, byte* out, const byte* in,
                                word32 sz, word64 sector)
{
    WC_LOG_FUNC_ID("1.64");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesXtsDecryptSector(aes, out, in, sz, sector);
}

int wc_AesXtsEncrypt_fips(XtsAes* aes, byte* out, const byte* in, word32 sz,
                          const byte* i, word32 iSz)
{
    WC_LOG_FUNC_ID("1.65");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesXtsEncrypt(aes, out, in, sz, i, iSz);
}

int wc_AesXtsDecrypt_fips(XtsAes* aes, byte* out, const byte* in, word32 sz,
                          const byte* i, word32 iSz)
{
    WC_LOG_FUNC_ID("1.66");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesXtsDecrypt(aes, out, in, sz, i, iSz);
}

int wc_AesXtsEncryptConsecutiveSectors_fips(XtsAes* aes, byte* out,
                                            const byte* in, word32 sz,
                                            word64 sector, word32 sectorSz)
{
    WC_LOG_FUNC_ID("1.67");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesXtsEncryptConsecutiveSectors(aes, out, in, sz, sector,
                                              sectorSz);
}

int wc_AesXtsDecryptConsecutiveSectors_fips(XtsAes* aes, byte* out,
                                            const byte* in, word32 sz,
                                            word64 sector, word32 sectorsz)
{
    WC_LOG_FUNC_ID("1.68");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesXtsDecryptConsecutiveSectors(aes, out, in, sz, sector,
                                              sectorsz);
}

#ifdef WOLFSSL_AESXTS_STREAM
int wc_AesXtsEncryptInit_fips(XtsAes* aes, const byte* i,
                              word32 iSz, struct XtsAesStreamData *stream)
{
    WC_LOG_FUNC_ID("1.69");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesXtsEncryptInit(aes, i, iSz, stream);
}

int wc_AesXtsDecryptInit_fips(XtsAes* aes, const byte* i,
                              word32 iSz, struct XtsAesStreamData *stream)
{
    WC_LOG_FUNC_ID("1.70");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesXtsDecryptInit(aes, i, iSz, stream);
}

int wc_AesXtsEncryptUpdate_fips(XtsAes* aes, byte* out, const byte* in,
                                word32 sz, struct XtsAesStreamData *stream)
{
    WC_LOG_FUNC_ID("1.71");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesXtsEncryptUpdate(aes, out, in, sz, stream);
}

int wc_AesXtsDecryptUpdate_fips(XtsAes* aes, byte* out, const byte* in,
                                word32 sz, struct XtsAesStreamData *stream)
{
    WC_LOG_FUNC_ID("1.72");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesXtsDecryptUpdate(aes, out, in, sz, stream);
}

int wc_AesXtsEncryptFinal_fips(XtsAes* aes, byte* out, const byte* in,
                               word32 sz, struct XtsAesStreamData *stream)
{
    WC_LOG_FUNC_ID("1.73");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesXtsEncryptFinal(aes, out, in, sz, stream);
}

int wc_AesXtsDecryptFinal_fips(XtsAes* aes, byte* out, const byte* in,
                               word32 sz, struct XtsAesStreamData *stream)
{
    WC_LOG_FUNC_ID("1.74");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesXtsDecryptFinal(aes, out, in, sz, stream);
}
#endif /* WOLFSSL_AESXTS_STREAM */

int wc_AesXtsFree_fips(XtsAes* aes)
{
    WC_LOG_FUNC_ID("1.75");

    return wc_AesXtsFree(aes);
}

#endif


/* Hash wrappers */
#ifndef NO_SHA
/* Init SHA wrapper */
/* Init like a free function, no cryptography just initializing a structure
 * for use so make it pass-through without the "Allowed" checks */
int wc_InitSha_fips(wc_Sha* sha)
{
    WC_LOG_FUNC_ID("1.76");

    return wc_InitSha(sha);
}

int wc_InitSha_ex_fips(wc_Sha* sha, void* heap, int devId)
{
    WC_LOG_FUNC_ID("1.77");
    (void) devId; /* Disabled in FIPS mode */

    return wc_InitSha_ex(sha, heap, FIPS_INVALID_DEVID);
}

/* SHA Update wrapper */
int wc_ShaUpdate_fips(wc_Sha* sha, const byte* data, word32 len)
{
    WC_LOG_FUNC_ID("1.78");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA1) != 0)
        return HMAC_KAT_FIPS_E;

    return wc_ShaUpdate(sha, data, len);
}


/* SHA Final wrapper */
int wc_ShaFinal_fips(wc_Sha* sha, byte* hash)
{
    WC_LOG_FUNC_ID("1.79");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA1) != 0)
        return HMAC_KAT_FIPS_E;

    return wc_ShaFinal(sha, hash);
}

int wc_ShaFinalRaw_fips(wc_Sha* sha, byte* hash)
{
    WC_LOG_FUNC_ID("1.80");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA1) != 0)
        return HMAC_KAT_FIPS_E;

    return wc_ShaFinalRaw(sha, hash);
}

/* SHA-1 Free wrapper */
void wc_ShaFree_fips(wc_Sha* sha)
{
    WC_LOG_FUNC_ID("1.81");
    wc_ShaFree(sha);
}

#endif /* NO_SHA */


#ifndef NO_SHA256
/* Init SHA256 wrapper */
/* Init like a free function, no cryptography just initializing a structure
 * for use so make it pass-through without the "Allowed" checks */
int wc_InitSha256_fips(wc_Sha256* sha)
{
    WC_LOG_FUNC_ID("1.82");

    return wc_InitSha256(sha);
}

int wc_InitSha256_ex_fips(wc_Sha256* sha, void* heap, int devId)
{
    WC_LOG_FUNC_ID("1.83");
    (void) devId; /* Disabled in FIPS mode */

    return wc_InitSha256_ex(sha, heap, FIPS_INVALID_DEVID);
}

/* SHA256 Update wrapper */
int wc_Sha256Update_fips(wc_Sha256* sha, const byte* data, word32 len)
{
    WC_LOG_FUNC_ID("1.84");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_256) != 0)
        return HMAC_KAT_FIPS_E;

    return wc_Sha256Update(sha, data, len);
}


/* SHA256 Final wrapper */
int wc_Sha256Final_fips(wc_Sha256* sha, byte* hash)
{
    WC_LOG_FUNC_ID("1.85");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_256) != 0)
        return HMAC_KAT_FIPS_E;

    return wc_Sha256Final(sha, hash);
}

int wc_Sha256FinalRaw_fips(wc_Sha256* sha256, byte* hash)
{
    WC_LOG_FUNC_ID("1.86");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_256) != 0)
        return HMAC_KAT_FIPS_E;

    return wc_Sha256FinalRaw(sha256, hash);
}

/* SHA256 Free wrapper */
void wc_Sha256Free_fips(wc_Sha256* sha)
{
    WC_LOG_FUNC_ID("1.87");
    wc_Sha256Free(sha);
}

#ifdef WOLFSSL_SHA224

/* Init SHA224 wrapper */
/* Init like a free function, no cryptography just initializing a structure
 * for use so make it pass-through without the "Allowed" checks */
int wc_InitSha224_fips(wc_Sha224* sha224)
{
    WC_LOG_FUNC_ID("1.88");

    return wc_InitSha224(sha224);
}

int wc_InitSha224_ex_fips(wc_Sha224* sha224, void* heap, int devId)
{
    WC_LOG_FUNC_ID("1.89");
    (void) devId; /* Disabled in FIPS mode */

    return wc_InitSha224_ex(sha224, heap, FIPS_INVALID_DEVID);
}


/* SHA224 Update wrapper */
int wc_Sha224Update_fips(wc_Sha224* sha224, const byte* data, word32 len)
{
    WC_LOG_FUNC_ID("1.90");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_256) != 0)
        return HMAC_KAT_FIPS_E;

    return wc_Sha224Update(sha224, data, len);
}


/* SHA224 Final wrapper */
int wc_Sha224Final_fips(wc_Sha224* sha224, byte* hash)
{
    WC_LOG_FUNC_ID("1.91");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_256) != 0)
        return HMAC_KAT_FIPS_E;

    return wc_Sha224Final(sha224, hash);
}

/* SHA224 Free wrapper */
void wc_Sha224Free_fips(wc_Sha224* sha)
{
    WC_LOG_FUNC_ID("1.92");
    wc_Sha224Free(sha);
}
#endif /* WOLFSSL_SHA224 */
#endif /* NO_SHA256 */


#ifdef WOLFSSL_SHA512
/* Init SHA512 wrapper */
/* Init like a free function, no cryptography just initializing a structure
 * for use so make it pass-through without the "Allowed" checks */
int wc_InitSha512_fips(wc_Sha512* sha)
{
    WC_LOG_FUNC_ID("1.93");

    return wc_InitSha512(sha);
}

int wc_InitSha512_ex_fips(wc_Sha512* sha, void* heap, int devId)
{
    WC_LOG_FUNC_ID("1.94");
    (void) devId; /* Disabled in FIPS mode */

    return wc_InitSha512_ex(sha, heap, FIPS_INVALID_DEVID);
}

/* SHA512 Update wrapper */
int wc_Sha512Update_fips(wc_Sha512* sha, const byte* data, word32 len)
{
    WC_LOG_FUNC_ID("1.95");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_512) != 0)
        return HMAC_KAT_FIPS_E;

    return wc_Sha512Update(sha, data, len);
}


/* SHA512 Final wrapper */
int wc_Sha512Final_fips(wc_Sha512* sha, byte* hash)
{
    WC_LOG_FUNC_ID("1.96");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_512) != 0)
        return HMAC_KAT_FIPS_E;

    return wc_Sha512Final(sha, hash);
}

int wc_Sha512FinalRaw_fips(wc_Sha512* sha512, byte* hash)
{
    WC_LOG_FUNC_ID("1.97");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_512) != 0)
        return HMAC_KAT_FIPS_E;

    return wc_Sha512FinalRaw(sha512, hash);
}

/* SHA512 Free wrapper */
void wc_Sha512Free_fips(wc_Sha512* sha)
{
    WC_LOG_FUNC_ID("1.98");
    wc_Sha512Free(sha);
}
#endif /* WOLFSSL_SHA512 */


/* Init SHA384 wrapper */
#ifdef WOLFSSL_SHA384
/* Init like a free function, no cryptography just initializing a structure
 * for use so make it pass-through without the "Allowed" checks */
int wc_InitSha384_fips(wc_Sha384* sha)
{
    WC_LOG_FUNC_ID("1.99");

    return wc_InitSha384(sha);
}

int wc_InitSha384_ex_fips(wc_Sha384* sha, void* heap, int devId)
{
    WC_LOG_FUNC_ID("2.00");
    (void) devId; /* Disabled in FIPS mode */

    return wc_InitSha384_ex(sha, heap, FIPS_INVALID_DEVID);
}

/* SHA384 Update wrapper */
int wc_Sha384Update_fips(wc_Sha384* sha, const byte* data, word32 len)
{
    WC_LOG_FUNC_ID("2.01");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_512) != 0)
        return HMAC_KAT_FIPS_E;

    return wc_Sha384Update(sha, data, len);
}


/* SHA384 Final wrapper */
int wc_Sha384Final_fips(wc_Sha384* sha, byte* hash)
{
    WC_LOG_FUNC_ID("2.02");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_512) != 0)
        return HMAC_KAT_FIPS_E;

    return wc_Sha384Final(sha, hash);
}

int wc_Sha384FinalRaw_fips(wc_Sha384* sha384, byte* hash)
{
    WC_LOG_FUNC_ID("2.03");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_512) != 0)
        return HMAC_KAT_FIPS_E;

    return wc_Sha384FinalRaw(sha384, hash);
}

/* SHA384 Free wrapper */
void wc_Sha384Free_fips(wc_Sha384* sha)
{
    WC_LOG_FUNC_ID("2.04");
    wc_Sha384Free(sha);
}
#endif /* WOLFSSL_SHA384 */


#ifdef WOLFSSL_SHA3
/* Base SHA-3 Functions */
/* Init like a free function, no cryptography just initializing a structure
 * for use so make it pass-through without the "Allowed" checks */
int wc_InitSha3_224_fips(wc_Sha3* sha3, void* heap, int devId)
{
    WC_LOG_FUNC_ID("2.05");

    (void) devId; /* Disabled in FIPS mode */
    return wc_InitSha3_224(sha3, heap, FIPS_INVALID_DEVID);
}


int wc_Sha3_224_Update_fips(wc_Sha3* sha3, const byte* data, word32 len)
{
    WC_LOG_FUNC_ID("2.06");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    return wc_Sha3_224_Update(sha3, data, len);
}


int wc_Sha3_224_Final_fips(wc_Sha3* sha3, byte* hash)
{
    WC_LOG_FUNC_ID("2.07");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    return wc_Sha3_224_Final(sha3, hash);
}

void wc_Sha3_224_Free_fips(wc_Sha3* sha3)
{
    WC_LOG_FUNC_ID("2.08");
    wc_Sha3_224_Free(sha3);
}


/* Init like a free function, no cryptography just initializing a structure
 * for use so make it pass-through without the "Allowed" checks */
int wc_InitSha3_256_fips(wc_Sha3* sha3, void* heap, int devId)
{
    WC_LOG_FUNC_ID("2.09");

    (void) devId; /* Disabled in FIPS mode */
    return wc_InitSha3_256(sha3, heap, FIPS_INVALID_DEVID);
}


int wc_Sha3_256_Update_fips(wc_Sha3* sha3, const byte* data, word32 len)
{
    WC_LOG_FUNC_ID("2.10");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    return wc_Sha3_256_Update(sha3, data, len);
}


int wc_Sha3_256_Final_fips(wc_Sha3* sha3, byte* hash)
{
    WC_LOG_FUNC_ID("2.11");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    return wc_Sha3_256_Final(sha3, hash);
}


void wc_Sha3_256_Free_fips(wc_Sha3* sha3)
{
    WC_LOG_FUNC_ID("2.12");
    wc_Sha3_256_Free(sha3);
}


/* Init like a free function, no cryptography just initializing a structure
 * for use so make it pass-through without the "Allowed" checks */
int wc_InitSha3_384_fips(wc_Sha3* sha3, void* heap, int devId)
{
    WC_LOG_FUNC_ID("2.13");

    (void) devId; /* Disabled in FIPS mode */
    return wc_InitSha3_384(sha3, heap, FIPS_INVALID_DEVID);
}


int wc_Sha3_384_Update_fips(wc_Sha3* sha3, const byte* data, word32 len)
{
    WC_LOG_FUNC_ID("2.14");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    return wc_Sha3_384_Update(sha3, data, len);
}


int wc_Sha3_384_Final_fips(wc_Sha3* sha3, byte* hash)
{
    WC_LOG_FUNC_ID("2.15");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    return wc_Sha3_384_Final(sha3, hash);
}


void wc_Sha3_384_Free_fips(wc_Sha3* sha3)
{
    WC_LOG_FUNC_ID("2.16");
    wc_Sha3_384_Free(sha3);
}

/* Init like a free function, no cryptography just initializing a structure
 * for use so make it pass-through without the "Allowed" checks */
int wc_InitSha3_512_fips(wc_Sha3* sha3, void* heap, int devId)
{
    WC_LOG_FUNC_ID("2.17");

    (void) devId; /* Disabled in FIPS mode */
    return wc_InitSha3_512(sha3, heap, FIPS_INVALID_DEVID);
}


int wc_Sha3_512_Update_fips(wc_Sha3* sha3, const byte* data, word32 len)
{
    WC_LOG_FUNC_ID("2.18");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    return wc_Sha3_512_Update(sha3, data, len);
}


int wc_Sha3_512_Final_fips(wc_Sha3* sha3, byte* hash)
{
    WC_LOG_FUNC_ID("2.19");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    return wc_Sha3_512_Final(sha3, hash);
}

void wc_Sha3_512_Free_fips(wc_Sha3* sha3)
{
    WC_LOG_FUNC_ID("2.20");
    wc_Sha3_512_Free(sha3);
}
#endif /* WOLFSSL_SHA3 */


/* HMAC wrappers */

static WC_INLINE int HmacTypeToTest(int hmacType)
{
    WC_LOG_FUNC_ID("2.21");
    switch (hmacType) {
        case WC_SHA:
            return FIPS_CAST_HMAC_SHA1;
        case WC_SHA224:
        case WC_SHA256:
            return FIPS_CAST_HMAC_SHA2_256;
        case WC_SHA384:
        case WC_SHA512:
            return FIPS_CAST_HMAC_SHA2_512;
        case WC_SHA3_224:
        case WC_SHA3_256:
        case WC_SHA3_384:
        case WC_SHA3_512:
            return FIPS_CAST_HMAC_SHA3_256;
        default:
            return FIPS_CAST_COUNT;
    }
}


/* HMAC SetKey wrapper */
int wc_HmacSetKey_fips(Hmac* hmac, int type, const byte* key, word32 keySz)
{
    WC_LOG_FUNC_ID("2.22");
    int testType = FIPS_CAST_COUNT;

    if (FipsAllowed() != 0) {
        return FIPS_NOT_ALLOWED_E;
    }

    if (hmac != NULL)
        testType = HmacTypeToTest(type);
    if (testType == FIPS_CAST_COUNT)
        return BAD_FUNC_ARG;

    if (AlgoAllowed(testType) != 0)
        return HMAC_KAT_FIPS_E;

    return wc_HmacSetKey(hmac, type, key, keySz);
}

int wc_HmacSetKey_ex_fips(Hmac* hmac, int type, const byte* key,
                            word32 length, int allowFlag)
{
    WC_LOG_FUNC_ID("2.23");
    int testType = FIPS_CAST_COUNT;

    if (FipsAllowed() != 0) {
        return FIPS_NOT_ALLOWED_E;
    }

    if (hmac != NULL)
        testType = HmacTypeToTest(type);
    if (testType == FIPS_CAST_COUNT)
        return BAD_FUNC_ARG;

    if (AlgoAllowed(testType) != 0)
        return HMAC_KAT_FIPS_E;

    return wc_HmacSetKey_ex(hmac, type, key, length, allowFlag);
}



/* HMAC Update wrapper */
int wc_HmacUpdate_fips(Hmac* hmac, const byte* data, word32 len)
{
    WC_LOG_FUNC_ID("2.24");
    int testType = FIPS_CAST_COUNT;

    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (hmac != NULL)
        testType = HmacTypeToTest(hmac->macType);
    if (testType == FIPS_CAST_COUNT)
        return BAD_FUNC_ARG;

    if (AlgoAllowed(testType) != 0)
        return HMAC_KAT_FIPS_E;

    return wc_HmacUpdate(hmac, data, len);
}


/* HMAC Final wrapper */
int wc_HmacFinal_fips(Hmac* hmac, byte* hash)
{
    WC_LOG_FUNC_ID("2.25");
    int testType = FIPS_CAST_COUNT;

    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (hmac != NULL)
        testType = HmacTypeToTest(hmac->macType);
    if (testType == FIPS_CAST_COUNT)
        return BAD_FUNC_ARG;

    if (AlgoAllowed(testType) != 0)
        return HMAC_KAT_FIPS_E;

    return wc_HmacFinal(hmac, hash);
}

/* HMAC Free wrapper */
void wc_HmacFree_fips(Hmac* hmac)
{
    WC_LOG_FUNC_ID("2.26");
    wc_HmacFree(hmac);
}

int wc_HmacSizeByType_fips(int type)
{
    WC_LOG_FUNC_ID("2.27");
    int testType =  HmacTypeToTest(type);

    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(testType) != 0)
        return HMAC_KAT_FIPS_E;

    return wc_HmacSizeByType(type);
}

/* Init like a free function, no cryptography just initializing a structure
 * for use so make it pass-through without the "Allowed" checks */
int wc_HmacInit_fips(Hmac* hmac, void* heap, int devId)
{
    WC_LOG_FUNC_ID("2.28");

    (void) devId; /* Disabled in FIPS mode */
    return wc_HmacInit(hmac, heap, FIPS_INVALID_DEVID);
}

#ifdef WOLFSSL_HAVE_PRF

/* PRF */
int wc_PRF_fips(byte* result, word32 resLen,
        const byte* secret, word32 secLen,
        const byte* seed, word32 seedLen,
        int hash_type, void* heap, int devId)
{
    WC_LOG_FUNC_ID("2.29");

    (void) devId; /* Disabled in FIPS mode */
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_KDF_TLS12) != 0)
        return KDF_TLS12_KAT_FIPS_E;

    if (GetTLS(&privateKeyReadEnable) > 0)
        return wc_PRF(result, resLen, secret, secLen, seed, seedLen,
                hash_type, heap, FIPS_INVALID_DEVID);
    else
        return FIPS_PRIVATE_KEY_LOCKED_E;
}


/* TLS v1.2 PRF */
int wc_PRF_TLSv12_fips(byte* result, word32 resLen,
        const byte* secret, word32 secLen,
        const byte* label, word32 labLen,
        const byte* seed, word32 seedLen,
        int useAtLeastSha256, int hash_type,
        void* heap, int devId)
{
    WC_LOG_FUNC_ID("2.30");

    (void) devId; /* Disabled in FIPS mode */
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_KDF_TLS12) != 0)
        return KDF_TLS12_KAT_FIPS_E;

    if (GetTLS(&privateKeyReadEnable) > 0)
        return wc_PRF_TLS(result, resLen, secret, secLen, label, labLen,
                seed, seedLen, useAtLeastSha256, hash_type, heap,
                FIPS_INVALID_DEVID);
    else
        return FIPS_PRIVATE_KEY_LOCKED_E;
}

#endif /* WOLFSSL_HAVE_PRF */


#ifdef HAVE_HKDF

/* HKDF Extract */
int wc_HKDF_Extract_fips(int type,
        const byte* salt, word32 saltSz,
        const byte* inKey, word32 inKeySz, byte* out)
{
    WC_LOG_FUNC_ID("2.31");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_256) != 0)
        return HMAC_KAT_FIPS_E;

    if (GetTLS(&privateKeyReadEnable) > 0)
        return wc_HKDF_Extract(type, salt, saltSz, inKey, inKeySz, out);
    else
        return FIPS_PRIVATE_KEY_LOCKED_E;
}

int wc_HKDF_Extract_ex_fips(int type, const byte* salt,
                            word32 saltSz, const byte* inKey, word32 inKeySz,
                            byte* out, void* heap, int devId)
{
    WC_LOG_FUNC_ID("2.32");
    (void) devId; /* Disabled in FIPS mode */
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_256) != 0)
        return HMAC_KAT_FIPS_E;

    if (GetTLS(&privateKeyReadEnable) > 0)
        return wc_HKDF_Extract_ex(type, salt, saltSz, inKey, inKeySz, out,
                            heap, FIPS_INVALID_DEVID);
    else
        return FIPS_PRIVATE_KEY_LOCKED_E;
}


/* HKDF Expand */
int wc_HKDF_Expand_fips(int type,
        const byte* inKey, word32 inKeySz,
        const byte* info, word32 infoSz,
        byte* out, word32 outSz)
{
    WC_LOG_FUNC_ID("2.33");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_256) != 0)
        return HMAC_KAT_FIPS_E;

    if (GetTLS(&privateKeyReadEnable) > 0)
        return wc_HKDF_Expand(type, inKey, inKeySz, info, infoSz, out, outSz);
    else
        return FIPS_PRIVATE_KEY_LOCKED_E;
}

int wc_HKDF_Expand_ex_fips(int type, const byte* inKey,
                            word32 inKeySz, const byte* info, word32 infoSz,
                            byte* out, word32 outSz, void* heap, int devId)
{
    WC_LOG_FUNC_ID("2.34");
    (void) devId; /* Disabled in FIPS mode */
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_256) != 0)
        return HMAC_KAT_FIPS_E;

    if (GetTLS(&privateKeyReadEnable) > 0)
        return wc_HKDF_Expand_ex(type, inKey, inKeySz, info, infoSz, out,
                            outSz, heap, FIPS_INVALID_DEVID);
    else
        return FIPS_PRIVATE_KEY_LOCKED_E;
}



/* HKDF */
int wc_HKDF_fips(int type, const byte* inKey, word32 inKeySz,
              const byte* salt, word32 saltSz,
              const byte* info, word32 infoSz,
              byte* out, word32 outSz)
{
    WC_LOG_FUNC_ID("2.35");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_256) != 0)
        return HMAC_KAT_FIPS_E;

    if (GetTLS(&privateKeyReadEnable) > 0)
        return wc_HKDF(type, inKey, inKeySz, salt, saltSz,
                info, infoSz, out, outSz);
    else
        return FIPS_PRIVATE_KEY_LOCKED_E;
}

int wc_Tls13_HKDF_Extract_fips(byte* prk,
                const byte* salt, int saltLen,
                byte* ikm, int ikmLen, int digest)
{
    WC_LOG_FUNC_ID("2.36");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_KDF_TLS13) != 0)
        return KDF_TLS13_KAT_FIPS_E;

    if (GetTLS(&privateKeyReadEnable) > 0)
        return wc_Tls13_HKDF_Extract(prk, salt, (word32)saltLen, ikm, (word32)ikmLen, digest);
    else
        return FIPS_PRIVATE_KEY_LOCKED_E;
}

WOLFSSL_API int wc_Tls13_HKDF_Extract_ex_fips(byte* prk,
        const byte* salt, word32 saltLen, byte* ikm, word32 ikmLen,
        int digest, void* heap, int devId)
{
    WC_LOG_FUNC_ID("2.37");

    (void) devId; /* Disabled in FIPS mode */
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_256) != 0)
        return HMAC_KAT_FIPS_E;

    if (GetTLS(&privateKeyReadEnable) > 0)
        return wc_Tls13_HKDF_Extract_ex(prk, salt, (word32)saltLen, ikm,
                    (word32)ikmLen, digest, heap, FIPS_INVALID_DEVID);
    else
        return FIPS_PRIVATE_KEY_LOCKED_E;
}
int wc_Tls13_HKDF_Expand_Label_fips(
                byte* okm, word32 okmLen,
                const byte* prk, word32 prkLen,
                const byte* protocol, word32 protocolLen,
                const byte* label, word32 labelLen,
                const byte* info, word32 infoLen,
                int digest)
{
    WC_LOG_FUNC_ID("2.38");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_KDF_TLS13) != 0)
        return KDF_TLS13_KAT_FIPS_E;

    if (GetTLS(&privateKeyReadEnable) >0)
        return wc_Tls13_HKDF_Expand_Label(okm, okmLen, prk, prkLen,
                protocol, protocolLen, label, labelLen, info, infoLen, digest);
    else
        return FIPS_PRIVATE_KEY_LOCKED_E;
}

WOLFSSL_API int wc_Tls13_HKDF_Expand_Label_ex_fips(byte* okm,
        word32 okmLen, const byte* prk, word32 prkLen,
        const byte* protocol, word32 protocolLen,
        const byte* label, word32 labelLen,
        const byte* info, word32 infoLen,
        int digest, void* heap, int devId)
{
    WC_LOG_FUNC_ID("2.39");

    (void) devId; /* Disabled in FIPS mode */
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_KDF_TLS13) != 0)
        return KDF_TLS13_KAT_FIPS_E;

    if (GetTLS(&privateKeyReadEnable) >0)
        return wc_Tls13_HKDF_Expand_Label_ex(okm, okmLen, prk, prkLen,
                protocol, protocolLen, label, labelLen, info, infoLen, digest,
                heap, FIPS_INVALID_DEVID);
    else
        return FIPS_PRIVATE_KEY_LOCKED_E;
}

#endif /* HAVE_HKDF */


#ifdef WOLFSSL_WOLFSSH

int wc_SSH_KDF_fips(byte hashId, byte keyId,
        byte* key, word32 keySz,
        const byte* k, word32 kSz,
        const byte* h, word32 hSz,
        const byte* sessionId, word32 sessionIdSz)
{
    WC_LOG_FUNC_ID("2.40");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_KDF_SSH) != 0)
        return KDF_SSH_KAT_FIPS_E;

    if (GetTLS(&privateKeyReadEnable) > 0)
        return wc_SSH_KDF(hashId, keyId, key, keySz,
                k, kSz, h, hSz, sessionId, sessionIdSz);
    else
        return FIPS_PRIVATE_KEY_LOCKED_E;
}

#endif /* WOLFSSL_WOLFSSH */


/* RSA wrappers */
#ifndef NO_RSA
/* Init RsaKey */
int wc_InitRsaKey_fips(RsaKey* key, void* p)
{
    WC_LOG_FUNC_ID("2.41");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_InitRsaKey(key, p);
}


int wc_InitRsaKeyEx_fips(RsaKey* key, void* p, int devId)
{
    WC_LOG_FUNC_ID("2.42");

    (void) devId; /* Disabled in FIPS mode */
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_InitRsaKey_ex(key, p, FIPS_INVALID_DEVID);
}


/* Free RsaKey */
int wc_FreeRsaKey_fips(RsaKey* key)
{
    WC_LOG_FUNC_ID("2.43");
    if (key == NULL)
        return BAD_FUNC_ARG;

    return wc_FreeRsaKey(key);
}


/* Check RsaKey */
int wc_CheckRsaKey_fips(RsaKey* key)
{
    WC_LOG_FUNC_ID("2.44");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (key == NULL)
        return BAD_FUNC_ARG;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_CheckRsaKey(key);
}


/* Rsa Public Encrypt */
int wc_RsaPublicEncrypt_fips(const byte* in,word32 inLen,byte* out,
                          word32 outLen, RsaKey* key, WC_RNG* rng)
{
    WC_LOG_FUNC_ID("2.45");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (key == NULL)
        return BAD_FUNC_ARG;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_RsaPublicEncrypt(in, inLen, out, outLen, key, rng);
}


/* Rsa Public Encrypt Extended */
int wc_RsaPublicEncryptEx_fips(const byte* in, word32 inLen, byte* out,
                            word32 outLen, RsaKey* key, WC_RNG* rng, int type,
                            enum wc_HashType hash, int mgf, byte* label,
                            word32 labelSz)
{
    WC_LOG_FUNC_ID("2.46");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (key == NULL)
        return BAD_FUNC_ARG;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_RsaPublicEncrypt_ex(in, inLen, out, outLen, key, rng, type,
                                  hash, mgf, label, labelSz);
}


/* Rsa Private Decrypt Inline */
int wc_RsaPrivateDecryptInline_fips(byte* in, word32 inLen,
                                 byte** out, RsaKey* key)
{
    WC_LOG_FUNC_ID("2.47");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (key == NULL)
        return BAD_FUNC_ARG;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_RsaPrivateDecryptInline(in, inLen, out, key);
}


/* Rsa Private Decrypt Inline Extended */
int wc_RsaPrivateDecryptInlineEx_fips(byte* in, word32 inLen,
                                   byte** out, RsaKey* key, int type,
                                   enum wc_HashType hash, int mgf, byte* label,
                                   word32 labelSz)
{
    WC_LOG_FUNC_ID("2.48");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (key == NULL)
        return BAD_FUNC_ARG;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_RsaPrivateDecryptInline_ex(in, inLen, out, key, type,
                                         hash, mgf, label, labelSz);
}


/* Rsa Private Decrypt */
int wc_RsaPrivateDecrypt_fips(const byte* in, word32 inLen,
                           byte* out,word32 outLen,RsaKey* key)
{
    WC_LOG_FUNC_ID("2.49");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (key == NULL)
        return BAD_FUNC_ARG;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_RsaPrivateDecrypt(in, inLen, out, outLen, key);
}


/* Rsa Private Decrypt Extended */
int wc_RsaPrivateDecryptEx_fips(const byte* in, word32 inLen,
                             byte* out, word32 outLen, RsaKey* key, int type,
                             enum wc_HashType hash, int mgf, byte* label,
                             word32 labelSz)
{
    WC_LOG_FUNC_ID("2.50");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (key == NULL)
        return BAD_FUNC_ARG;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_RsaPrivateDecrypt_ex(in, inLen, out, outLen, key, type,
                                   hash, mgf, label, labelSz);
}


/* Rsa SSL Sign */
int wc_RsaSSL_Sign_fips(const byte* in, word32 inLen, byte* out,
                     word32 outLen, RsaKey* key, WC_RNG* rng)
{
    int ret;

    WC_LOG_FUNC_ID("2.51");

    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (key == NULL)
        return BAD_FUNC_ARG;


    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    ret = wc_RsaSSL_Sign(in, inLen, out, outLen, key, rng);

    if (ret > 0 && ret < WC_RSA_FIPS_SIG_MIN) {
        WC_LOG_FUNC_ID("2.52");
        ForceZero(key->data, key->dataLen);
        return SIG_TYPE_E;
    }

    return ret;
}


/* Rsa SSL Verify Inline */
int wc_RsaSSL_VerifyInline_fips(byte* in, word32 inLen, byte** out, RsaKey* key)
{
    WC_LOG_FUNC_ID("2.53");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (key == NULL)
        return BAD_FUNC_ARG;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_RsaSSL_VerifyInline(in, inLen, out, key);
}


/* Rsa SSL Verify */
int wc_RsaSSL_Verify_fips(const byte* in, word32 inLen, byte* out,
                       word32 outLen, RsaKey* key)
{
    WC_LOG_FUNC_ID("2.54");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (key == NULL)
        return BAD_FUNC_ARG;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_RsaSSL_Verify(in, inLen, out, outLen, key);
}


#ifdef WC_RSA_PSS
/* Rsa PSS Sign */
int wc_RsaPSS_Sign_fips(const byte* in, word32 inLen, byte* out, word32 outLen,
                     enum wc_HashType hash, int mgf, RsaKey* key, WC_RNG* rng)
{
    int ret;

    WC_LOG_FUNC_ID("2.55");

    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (key == NULL)
        return BAD_FUNC_ARG;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    ret = wc_RsaPSS_Sign(in, inLen, out, outLen, hash, mgf, key, rng);

    if (ret > 0 && ret < WC_RSA_FIPS_SIG_MIN) {
        ForceZero(key->data, key->dataLen);
        return SIG_TYPE_E;
    }

    return ret;
}


/* Rsa PSS Sign Extended */
int wc_RsaPSS_SignEx_fips(const byte* in, word32 inLen,
                       byte* out, word32 outLen,
                       enum wc_HashType hash, int mgf, int saltLen,
                       RsaKey* key, WC_RNG* rng)
{
    int ret;

    WC_LOG_FUNC_ID("2.56");

    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (key == NULL)
        return BAD_FUNC_ARG;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    ret = wc_RsaPSS_Sign_ex(in, inLen, out, outLen,
                             hash, mgf, saltLen, key, rng);

    if (ret > 0 && ret < WC_RSA_FIPS_SIG_MIN) {
        ForceZero(key->data, key->dataLen);
        return SIG_TYPE_E;
    }

    return ret;
}


/* Rsa PSS Verify Inline */
int wc_RsaPSS_VerifyInline_fips(byte* in, word32 inLen, byte** out,
                             enum wc_HashType hash, int mgf, RsaKey* key)
{
    WC_LOG_FUNC_ID("2.57");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (key == NULL)
        return BAD_FUNC_ARG;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_RsaPSS_VerifyInline(in, inLen, out, hash, mgf, key);
}


/* Rsa PSS Verify Inline Extended */
int wc_RsaPSS_VerifyInlineEx_fips(byte* in, word32 inLen, byte** out,
                               enum wc_HashType hash, int mgf,
                               int saltLen, RsaKey* key)
{
    WC_LOG_FUNC_ID("2.58");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (key == NULL)
        return BAD_FUNC_ARG;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_RsaPSS_VerifyInline_ex(in, inLen, out, hash, mgf, saltLen, key);
}


/* Rsa PSS Verify */
int wc_RsaPSS_Verify_fips(byte* in, word32 inLen, byte* out, word32 outLen,
                       enum wc_HashType hash, int mgf, RsaKey* key)
{
    WC_LOG_FUNC_ID("2.59");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (key == NULL)
        return BAD_FUNC_ARG;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_RsaPSS_Verify(in, inLen, out, outLen, hash, mgf, key);
}


/* Rsa PSS Verify Extended */
int wc_RsaPSS_VerifyEx_fips(byte* in, word32 inLen, byte* out, word32 outLen,
                               enum wc_HashType hash, int mgf,
                               int saltLen, RsaKey* key)
{
    WC_LOG_FUNC_ID("2.60");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (key == NULL)
        return BAD_FUNC_ARG;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_RsaPSS_Verify_ex(in, inLen, out, outLen, hash,
                               mgf, saltLen, key);
}


/* Rsa PSS Check Padding */
int wc_RsaPSS_CheckPadding_fips(const byte* in, word32 inSz,
                             byte* sig, word32 sigSz,
                             enum wc_HashType hashType)
{
    WC_LOG_FUNC_ID("2.61");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_RsaPSS_CheckPadding(in, inSz, sig, sigSz, hashType);
}


/* Rsa PSS Check Padding Extended */
int wc_RsaPSS_CheckPaddingEx_fips(const byte* in, word32 inSz,
                               byte* sig, word32 sigSz,
                               enum wc_HashType hashType,
                               int saltLen, int bits)
{
    WC_LOG_FUNC_ID("2.62");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_RsaPSS_CheckPadding_ex(in, inSz, sig, sigSz, hashType,
                                     saltLen, bits);
}
#endif

/* Rsa Encrypt Size */
int wc_RsaEncryptSize_fips(RsaKey* key)
{
    WC_LOG_FUNC_ID("2.63");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_RsaEncryptSize(key);
}

#if 0
/* Rsa PrivateKey Decode */
int wc_RsaPrivateKeyDecode_fips(const byte* input, word32* inOutIdx,
                             RsaKey* key, word32 inSz)
{
    WC_LOG_FUNC_ID(previously unused function enabled,
                   add a func ID (intentional compile error));
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_RsaPrivateKeyDecode(input, inOutIdx, key, inSz);
}


/* Rsa PublicKey Decode */
int wc_RsaPublicKeyDecode_fips(const byte* input, word32* inOutIdx, RsaKey* key,
                            word32 inSz)
{
    WC_LOG_FUNC_ID(previously unused function enabled,
                   add a func ID (intentional compile error));
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_RsaPublicKeyDecode(input, inOutIdx, key, inSz);
}
#endif


/* Rsa Export Key */
int wc_RsaExportKey_fips(RsaKey* key,
                      byte* e, word32* eSz, byte* n, word32* nSz,
                      byte* d, word32* dSz, byte* p, word32* pSz,
                      byte* q, word32* qSz)
{
    WC_LOG_FUNC_ID("2.64");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    if (GetTLS(&privateKeyReadEnable) > 0)
        return wc_RsaExportKey(key, e, eSz, n, nSz, d, dSz, p, pSz, q, qSz);
    else
        return FIPS_PRIVATE_KEY_LOCKED_E;
}


#ifdef WOLFSSL_KEY_GEN
#if 0
/* Not meant as a public API, was used for internal testing of some edge cases
 * where libraries could be convinced a non-prime candidate was prime without
 * proper primality testing (M-R)
 */
/* Rsa Check Probable Prime */
int wc_CheckProbablePrime_fips(const byte* p, word32 pSz,
                            const byte* q, word32 qSz,
                            const byte* e, word32 eSz,
                            int nlen, int* isPrime)
{
    WC_LOG_FUNC_ID(previously unused function enabled,
                   add a func ID (intentional compile error));
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_CheckProbablePrime(p, pSz, q, qSz, e, eSz, nlen, isPrime);
}
#endif

/* Rsa Key Gen */
int wc_MakeRsaKey_fips(RsaKey* key, int size, long e, WC_RNG* rng)
{
    WC_LOG_FUNC_ID("2.65");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (size < WC_RSA_FIPS_GEN_MIN)
        return BAD_FUNC_ARG;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_MakeRsaKey(key, size, e, rng);
}
#endif
#if defined(WC_RSA_DIRECT) || defined(WC_RSA_NO_PADDING)
int wc_RsaDirect_fips(byte* in, word32 inLen, byte* out,
                        word32* outSz, RsaKey* key, int type, WC_RNG* rng)
{
    WC_LOG_FUNC_ID("2.66");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_RsaDirect(in, inLen, out, outSz, key, type, rng);
}
#endif

int wc_RsaFlattenPublicKey_fips(RsaKey* key, byte* e,
                            word32* eSz, byte* n, word32* nSz)
{
    WC_LOG_FUNC_ID("2.67");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_RsaFlattenPublicKey(key, e, eSz, n, nSz);
}

int wc_RsaPSS_VerifyCheckInline_fips(byte* in, word32 inLen,
                            byte** out, const byte* digest, word32 digentLen,
                            enum wc_HashType hash, int mgf, RsaKey* key)
{
    WC_LOG_FUNC_ID("2.68");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_RsaPSS_VerifyCheckInline(in, inLen, out, digest, digentLen, hash,
                            mgf, key);
}

int wc_RsaPSS_VerifyCheck_fips(byte* in, word32 inLen,
                            byte* out, word32 outLen, const byte* digest,
                            word32 digestLen, enum wc_HashType hash, int mgf,
                            RsaKey* key)
{
    WC_LOG_FUNC_ID("2.69");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_RsaPSS_VerifyCheck(in, inLen, out, outLen, digest, digestLen,
                            hash, mgf, key);
}

int wc_RsaSSL_Verify_ex_fips(const byte* in, word32 inLen,
                            byte* out, word32 outLen, RsaKey* key,
                            int pad_type)
{
    WC_LOG_FUNC_ID("2.70");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_RsaSSL_Verify_ex(in, inLen, out, outLen, key, pad_type);
}

int wc_RsaSSL_Verify_ex2_fips(const byte* in, word32 inLen,
                            byte* out, word32 outLen, RsaKey* key, int pad_type,
                            enum wc_HashType hash)
{
    WC_LOG_FUNC_ID("2.71");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_RsaSSL_Verify_ex2(in, inLen, out, outLen, key, pad_type, hash);
}


#endif /* NO_RSA */


/* Base ECC Functions */
#ifdef HAVE_ECC

/* init ECC key */
/* Init like a free function, no cryptography just initializing a structure
 * for use so make it pass-through without the "Allowed" checks */
int wc_ecc_init_fips(ecc_key* key)
{
    WC_LOG_FUNC_ID("2.72");

    return wc_ecc_init(key);
}


/* free ECC key */
int wc_ecc_free_fips(ecc_key* key)
{
    WC_LOG_FUNC_ID("2.73");
    if (key == NULL)
        return BAD_FUNC_ARG;

    return wc_ecc_free(key);
}


#ifdef ECC_TIMING_RESISTANT
/* set ECC key's RNG */
int wc_ecc_set_rng_fips(ecc_key* key, WC_RNG* rng)
{
    WC_LOG_FUNC_ID("2.74");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    return wc_ecc_set_rng(key, rng);
}
#endif


/* check ECC key */
int wc_ecc_check_key_fips(ecc_key* key)
{
    WC_LOG_FUNC_ID("2.75");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_ECDSA) != 0)
        return ECDSA_KAT_FIPS_E;

    return wc_ecc_check_key(key);
}


/* make ECC key */
int wc_ecc_make_key_fips(WC_RNG* rng, int keysize, ecc_key* key)
{
    WC_LOG_FUNC_ID("2.76");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (keysize < WC_ECC_FIPS_GEN_MIN)
        return BAD_FUNC_ARG;

    if (AlgoAllowed(FIPS_CAST_ECDSA) != 0)
        return ECDSA_KAT_FIPS_E;

    return wc_ecc_make_key(rng, keysize, key);
}


/* make ECC key extended */
int wc_ecc_make_key_ex_fips(WC_RNG* rng, int keysize, ecc_key* key,
                                     int curve_id)
{
    WC_LOG_FUNC_ID("2.77");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (keysize < WC_ECC_FIPS_GEN_MIN) {
        if (keysize == 0 && (curve_id == ECC_SECP256R1 ||
                             curve_id == ECC_SECP224R1 ||
                             curve_id == ECC_SECP384R1 ||
                             curve_id == ECC_SECP521R1)) {
            FIPS_MSG("Allow keysize 0, approved curve_id will be used");
        } else if (keysize == 0 && curve_id == 0) {
            FIPS_MSG("Allow keysize 0, curve_id 0, defaults to 256-bit");
        } else {
            return BAD_FUNC_ARG;
        }
    }

    if (AlgoAllowed(FIPS_CAST_ECDSA) != 0)
        return ECDSA_KAT_FIPS_E;

    return wc_ecc_make_key_ex(rng, keysize, key, curve_id);
}

/* Explicit force zero function, no cryptography just zeroing
 * make it pass-through without the "Allowed" checks to protect from CSP not
 * getting zeroised in the event the CAST has failed */
void wc_ecc_forcezero_point_fips(ecc_point* p)
{
    WC_LOG_FUNC_ID("2.78");

    wc_ecc_forcezero_point(p);
}

/*
 * Allocates and returns a new ECC point
 * returns an allocated point on success or NULL on failure
 * Init functions like a free function, no cryptography just initializing a
 * structure for use so make it pass-through without the "Allowed" checks
 */
ecc_point* wc_ecc_new_point_fips(void)
{
    WC_LOG_FUNC_ID("2.79");

    return wc_ecc_new_point();
}

/*
 * Allocates and returns a new ECC point, takes in a heap hint to track memory
 * allocations.
 * Returns an allocated point on success or NULL on failure
 * Init functions like a free function, no cryptography just initializing a
 * structure for use so make it pass-through without the "Allowed" checks
 */
ecc_point* wc_ecc_new_point_h_fips(void* h)
{
    WC_LOG_FUNC_ID("2.80");

    return wc_ecc_new_point_h(h);
}

/* zeros and frees a point */
/* Free function, no cryptography just releasing resources back to the OS
 * so make it pass-through without the "Allowed" checks to prevent leaks and/or
 * CSPs from being zeroised */
void wc_ecc_del_point_fips(ecc_point* p)
{
    WC_LOG_FUNC_ID("2.81");

    wc_ecc_del_point(p);
}

/* zeros and frees a point, takes in a heap hint to track memory frees */
/* Free function, no cryptography just releasing resources back to the OS
 * so make it pass-through without the "Allowed" checks to prevent leaks and/or
 * CSPs from being zeroised */
void wc_ecc_del_point_h_fips(ecc_point* p, void* h)
{
    WC_LOG_FUNC_ID("2.82");

    wc_ecc_del_point_h(p, h);
}

/* Init like a free function, no cryptography just initializing a structure
 * for use so make it pass-through without the "Allowed" checks, this is the
 * extended version of the init function that takes in a heap hint for tracking
 * memory allocations */
int wc_ecc_init_ex_fips(ecc_key* key, void* heap, int devId)
{
    WC_LOG_FUNC_ID("2.83");

    (void) devId; /* Disabled in FIPS mode */
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_ECDSA) != 0)
        return ECDSA_KAT_FIPS_E;

    return wc_ecc_init_ex(key, heap, FIPS_INVALID_DEVID);
}

/* Init like a free function, no cryptography just initializing a structure
 * for use so make it pass-through without the "Allowed" checks */
/* Allocates a new ecc_key structure, takes in a heap hint for tracking
 * memory allocations, returns allocated structure on success or NULL on fail */
ecc_key* wc_ecc_key_new_fips(void* heap)
{
    WC_LOG_FUNC_ID("2.84");

    return wc_ecc_key_new(heap);
}

/* Free function, no cryptography just freeing a structure
 * releasing resources back to the OS and zeros the structure. Make it
 * pass-through without the "Allowed" checks to prevent memory leaks and to
 * ensure all CSPs are zeroised in the event the CAST has failed */
void wc_ecc_key_free_fips(ecc_key* key)
{
    WC_LOG_FUNC_ID("2.85");

    wc_ecc_key_free(key);
}

/* make ECC key extended+, like the first ecc_make_key and ecc_make_key_ex
 * checks that the keySize requested is within the ALLOWED sizes (not less than
 * WC_ECC_FIPS_GEN_MIN */
int wc_ecc_make_key_ex2_fips(WC_RNG* rng, int keysize, ecc_key* key,
                            int curve_id, int flags)
{
    WC_LOG_FUNC_ID("2.86");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (keysize < WC_ECC_FIPS_GEN_MIN)
        return BAD_FUNC_ARG;

    if (AlgoAllowed(FIPS_CAST_ECDSA) != 0)
        return ECDSA_KAT_FIPS_E;

    return wc_ecc_make_key_ex2(rng, keysize, key, curve_id, flags);
}

/* creates the public ECC key from the allowed private key */
int wc_ecc_make_pub_fips(ecc_key* key, ecc_point* pubOut)
{
    WC_LOG_FUNC_ID("2.87");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_ECDSA) != 0)
        return ECDSA_KAT_FIPS_E;

    return wc_ecc_make_pub(key, pubOut);
}

/* creates the public ECC key from the allowed private key, extended API takes
 * in an optional RNG */
int wc_ecc_make_pub_ex_fips(ecc_key* key, ecc_point* pubOut, WC_RNG* rng)
{
    WC_LOG_FUNC_ID("2.88");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_ECDSA) != 0)
        return ECDSA_KAT_FIPS_E;

    return wc_ecc_make_pub_ex(key, pubOut, rng);
}

#endif /* HAVE_ECC */


#if defined(HAVE_ECC) && defined(HAVE_ECC_KEY_EXPORT)

/* ECC Key Export Function */
int wc_ecc_export_x963_fips(ecc_key* key, byte* out, word32* outLen)
{
    WC_LOG_FUNC_ID("2.89");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_ECDSA) != 0)
        return ECDSA_KAT_FIPS_E;

    /* When out is NULL, export x963 returns the expected outLen. Allow. */
    if ((key != NULL && out == NULL && outLen != NULL)
            || (GetTLS(&privateKeyReadEnable) > 0))
        return wc_ecc_export_x963(key, out, outLen);
    else
        return FIPS_PRIVATE_KEY_LOCKED_E;
}

int wc_ecc_export_ex_fips(ecc_key* key, byte* qx, word32* qxLen,
            byte* qy, word32* qyLen, byte* d, word32* dLen,
            int encType)
{
    WC_LOG_FUNC_ID("2.90");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_ECDSA) != 0)
        return ECDSA_KAT_FIPS_E;

    /* Supports exporting public only, don't check private read enable if d is
     * NULL */
    if (d == NULL || GetTLS(&privateKeyReadEnable) > 0)
        return wc_ecc_export_ex(key, qx, qxLen, qy, qyLen, d, dLen, encType);
    else
        return FIPS_PRIVATE_KEY_LOCKED_E;
}

int wc_ecc_export_private_only_fips(ecc_key* key, byte* out, word32* outLen)
{
    WC_LOG_FUNC_ID("2.91");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_ECDSA) != 0)
        return ECDSA_KAT_FIPS_E;

    if (GetTLS(&privateKeyReadEnable) > 0)
        return wc_ecc_export_private_only(key, out, outLen);
    else
        return FIPS_PRIVATE_KEY_LOCKED_E;
}

int wc_ecc_export_public_raw_fips(ecc_key* key, byte* qx,
            word32* qxLen, byte* qy, word32* qyLen)
{
    WC_LOG_FUNC_ID("2.92");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_ECDSA) != 0)
        return ECDSA_KAT_FIPS_E;

    /* don't check private key read enable when only exporting the public */
    return wc_ecc_export_public_raw(key, qx, qxLen, qy, qyLen);
}

int wc_ecc_export_private_raw_fips(ecc_key* key, byte* qx,
            word32* qxLen, byte* qy, word32* qyLen, byte* d,
            word32* dLen)
{
    WC_LOG_FUNC_ID("2.93");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_ECDSA) != 0)
        return ECDSA_KAT_FIPS_E;

    /* Supports exporting public only, don't check private read enable if d is
     * NULL */
    if (d == NULL || GetTLS(&privateKeyReadEnable) > 0)
        return wc_ecc_export_private_raw(key, qx, qxLen, qy, qyLen, d, dLen);
    else
        return FIPS_PRIVATE_KEY_LOCKED_E;
}

int wc_ecc_export_point_der_ex_fips(const int curve_idx,
            ecc_point* point, byte* out, word32* outLen,
            int compressed)
{
    WC_LOG_FUNC_ID("2.94");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_ECDSA) != 0)
        return ECDSA_KAT_FIPS_E;

    return wc_ecc_export_point_der_ex(curve_idx, point, out, outLen,
                            compressed);
}

int wc_ecc_export_point_der_fips(const int curve_idx,
            ecc_point* point, byte* out, word32* outLen)
{
    WC_LOG_FUNC_ID("2.95");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_ECDSA) != 0)
        return ECDSA_KAT_FIPS_E;

    return wc_ecc_export_point_der(curve_idx, point, out, outLen);
}

int wc_ecc_export_x963_ex_fips(ecc_key* key, byte* out,
            word32* outLen, int compressed)
{
    WC_LOG_FUNC_ID("2.96");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_ECDSA) != 0)
        return ECDSA_KAT_FIPS_E;

    /* When out is NULL, export x963 returns the expected outLen. Allow. */
    if ((key != NULL && out == NULL && outLen != NULL)
            || (GetTLS(&privateKeyReadEnable) > 0))
        return wc_ecc_export_x963_ex(key, out, outLen, compressed);
    else
        return FIPS_PRIVATE_KEY_LOCKED_E;
}

#endif /* HAVE_ECC && HAVE_ECC_KEY_EXPORT */


#if defined(HAVE_ECC) && defined(HAVE_ECC_KEY_IMPORT)

/* ECC Key Import Function */
int wc_ecc_import_x963_fips(const byte* in, word32 inLen, ecc_key* key)
{
    WC_LOG_FUNC_ID("2.97");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Do not check if ECDSA is allowed yet, no crypto happening at this time
     * check algo allowed post import when user attempts to perform crypto */

    return wc_ecc_import_x963(in, inLen, key);
}

int wc_ecc_import_x963_ex_fips(const byte* in, word32 inLen,
            ecc_key* key, int curve_id)
{
    WC_LOG_FUNC_ID("2.98");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Do not check if ECDSA is allowed yet, no crypto happening at this time
     * check algo allowed post import when user attempts to perform crypto */

    return wc_ecc_import_x963_ex(in, inLen, key, curve_id);
}

int wc_ecc_import_private_key_fips(const byte* priv, word32 privSz,
            const byte* pub, word32 pubSz, ecc_key* key)
{
    WC_LOG_FUNC_ID("2.99");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Do not check if ECDSA is allowed yet, no crypto happening at this time
     * check algo allowed post import when user attempts to perform crypto */

    return wc_ecc_import_private_key(priv, privSz, pub, pubSz, key);
}

int wc_ecc_import_private_key_ex_fips(const byte* priv, word32 privSz,
                            const byte* pub, word32 pubSz, ecc_key* key,
                            int curve_id)
{
    WC_LOG_FUNC_ID("3.00");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Do not check if ECDSA is allowed yet, no crypto happening at this time
     * check algo allowed post import when user attempts to perform crypto */

    return wc_ecc_import_private_key_ex(priv, privSz, pub, pubSz, key,
                            curve_id);
}

int wc_ecc_import_raw_fips(ecc_key* key, const char* qx, const char* qy,
                            const char* d, const char* curveName)
{
    WC_LOG_FUNC_ID("3.01");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Do not check if ECDSA is allowed yet, no crypto happening at this time
     * check algo allowed post import when user attempts to perform crypto */

    return wc_ecc_import_raw(key, qx, qy, d, curveName);
}

int wc_ecc_import_raw_ex_fips(ecc_key* key, const char* qx,
            const char* qy, const char* d, int curve_id)
{
    WC_LOG_FUNC_ID("3.02");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Do not check if ECDSA is allowed yet, no crypto happening at this time
     * check algo allowed post import when user attempts to perform crypto */

    return wc_ecc_import_raw_ex(key, qx, qy, d, curve_id);
}

int wc_ecc_import_unsigned_fips(ecc_key* key, const byte* qx,
                            const byte* qy, const byte* d, int curve_id)
{
    WC_LOG_FUNC_ID("3.03");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Do not check if ECDSA is allowed yet, no crypto happening at this time
     * check algo allowed post import when user attempts to perform crypto */

    return wc_ecc_import_unsigned(key, qx, qy, d, curve_id);
}

int wc_ecc_import_point_der_ex_fips(const byte* in, word32 inLen,
                            const int curve_idx, ecc_point* point,
                            int shortKeySize)
{
    WC_LOG_FUNC_ID("3.04");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Do not check if ECDSA is allowed yet, no crypto happening at this time
     * check algo allowed post import when user attempts to perform crypto */

    return wc_ecc_import_point_der_ex(in, inLen, curve_idx, point,
                            shortKeySize);
}

int wc_ecc_import_point_der_fips(const byte* in, word32 inLen,
            const int curve_idx, ecc_point* point)
{
    WC_LOG_FUNC_ID("3.05");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Do not check if ECDSA is allowed yet, no crypto happening at this time
     * check algo allowed post import when user attempts to perform crypto */

    return wc_ecc_import_point_der(in, inLen, curve_idx, point);
}


int wc_ecc_rs_to_sig_fips(const char* r, const char* s,
                        byte* out, word32* outlen)
{
    WC_LOG_FUNC_ID("3.06");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_ECDSA) != 0)
        return ECDSA_KAT_FIPS_E;

    return wc_ecc_rs_to_sig(r, s, out, outlen);
}

int wc_ecc_rs_raw_to_sig_fips(const byte* r, word32 rSz, const byte* s,
                            word32 sSz, byte* out, word32* outlen)
{
    WC_LOG_FUNC_ID("3.07");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_ECDSA) != 0)
        return ECDSA_KAT_FIPS_E;

    return wc_ecc_rs_raw_to_sig(r, rSz, s, sSz, out, outlen);
}

int wc_ecc_sig_to_rs_fips(const byte* sig, word32 sigLen, byte* r, word32* rLen,
                            byte* s, word32* sLen)
{
    WC_LOG_FUNC_ID("3.08");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_ECDSA) != 0)
        return ECDSA_KAT_FIPS_E;

    return wc_ecc_sig_to_rs(sig, sigLen, r, rLen, s, sLen);
}

#endif /* HAVE_ECC && HAVE_ECC_KEY_IMPORT */


#if defined(HAVE_ECC) && defined(HAVE_ECC_DHE)

/* ECC DHE Function */
int wc_ecc_shared_secret_fips(ecc_key* private_key, ecc_key* public_key,
                                       byte* out, word32* outlen)
{
    WC_LOG_FUNC_ID("3.09");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_ECC_PRIMITIVE_Z) != 0)
        return ECDHE_KAT_FIPS_E;

    if (GetTLS(&privateKeyReadEnable) > 0)
        return wc_ecc_shared_secret(private_key, public_key, out, outlen);
    else
        return FIPS_PRIVATE_KEY_LOCKED_E;
}

int wc_ecc_shared_secret_ex_fips(ecc_key* private_key,
            ecc_point* point, byte* out, word32 *outlen)
{
    WC_LOG_FUNC_ID("3.10");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_ECC_PRIMITIVE_Z) != 0)
        return ECDHE_KAT_FIPS_E;

    if (GetTLS(&privateKeyReadEnable) > 0)
        return wc_ecc_shared_secret_ex(private_key, point, out, outlen);
    else
        return FIPS_PRIVATE_KEY_LOCKED_E;
}

#endif /* HAVE_ECC && HAVE_ECC_DHE */


#if defined(HAVE_ECC) && defined(HAVE_ECC_SIGN)

/* ECDSA Signing Function */
int wc_ecc_sign_hash_fips(const byte* in, word32 inlen,
                                   byte* out, word32 *outlen,
                                   WC_RNG* rng, ecc_key* key)
{
    WC_LOG_FUNC_ID("3.11");

    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_ECDSA) != 0) {
        return ECDSA_KAT_FIPS_E;
    }

    if (key == NULL)
        return ECC_BAD_ARG_E;

    if (ecc_sets[key->idx].id == ECC_SECP192R1) {
        WC_LOG_FUNC_ID("3.12");
#ifdef DEBUG_FIPS_VERBOSE
        FIPS_MSG("Invalid curve for sign operations");
#endif
        return SIG_TYPE_E;
    }

    return wc_ecc_sign_hash(in, inlen, out, outlen, rng, key);
}

#ifndef WOLFSSL_KCAPI_ECC
int wc_ecc_sign_hash_ex_fips(const byte* in, word32 inlen,
                                   WC_RNG* rng, ecc_key* key,
                                   MP_INT_T* r, MP_INT_T* s)
{
    WC_LOG_FUNC_ID("3.13");

    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_ECDSA) != 0) {
        return ECDSA_KAT_FIPS_E;
    }

    if (key == NULL)
        return ECC_BAD_ARG_E;

    if (ecc_sets[key->idx].id == ECC_SECP192R1) {
#ifdef DEBUG_FIPS_VERBOSE
        FIPS_MSG("Invalid curve for sign operations");
#endif
        return SIG_TYPE_E;
    }

    return wc_ecc_sign_hash_ex(in, inlen, rng, key, (mp_int*)r, (mp_int*)s);
}
#endif
#if defined(WOLFSSL_ECDSA_SET_K) || defined(WOLFSSL_ECDSA_SET_K_ONE_LOOP)
int wc_ecc_sign_set_k_fips(const byte* k, word32 klen,
                            ecc_key* key)
{
    WC_LOG_FUNC_ID("3.14");

    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_ECDSA) != 0) {
        return ECDSA_KAT_FIPS_E;
    }

    /* Just setting the k for sign operation to come, sign key size not checked
     * here, will get checked when sign operation performed, application to
     * handle cleanup on error due to invalid key size in sign with FIPS
     * approved mode */

    return wc_ecc_sign_set_k(k, klen, key);
}
#endif /* WOLFSSL_ECDSA_SET_K || WOLFSSL_ECDSA_SET_K_ONE_LOOP */
#endif /* HAVE_ECC && HAVE_ECC_SIGN */


/* ECDSA Signature Verify Function */
#if defined(HAVE_ECC) && defined(HAVE_ECC_VERIFY)

int wc_ecc_verify_hash_fips(const byte* sig, word32 siglen,
                                     const byte* hash, word32 hashlen,
                                     int* res, ecc_key* key)
{
    WC_LOG_FUNC_ID("3.15");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_ECDSA) != 0)
        return ECDSA_KAT_FIPS_E;

    return wc_ecc_verify_hash(sig, siglen, hash, hashlen, res, key);
}

int wc_ecc_verify_hash_ex_fips(MP_INT_T* r, MP_INT_T* s,
                               const byte* hash, word32 hashlen,
                               int* stat, ecc_key* key)
{
    WC_LOG_FUNC_ID("3.16");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_ECDSA) != 0)
        return ECDSA_KAT_FIPS_E;

    return wc_ecc_verify_hash_ex((mp_int*)r, (mp_int*)s, hash, hashlen, stat,
                                 key);
}

#endif /* HAVE_ECC && HAVE_ECC_VERIFY */


/* Base DH Functions */
#ifndef NO_DH

/* Init DH key */
/* Init like a free function, no cryptography just initializing a structure
 * for use so make it pass-through without the "Allowed" checks */
int wc_InitDhKey_fips(DhKey* key)
{
    WC_LOG_FUNC_ID("3.17");

    return wc_InitDhKey(key);
}

/* Init like a free function, no cryptography just initializing a structure
 * for use so make it pass-through without the "Allowed" checks */
int wc_InitDhKey_ex_fips(DhKey* key, void* heap, int devId)
{
    WC_LOG_FUNC_ID("3.18");
    (void) devId; /* Disabled in FIPS mode */

    return wc_InitDhKey_ex(key, heap, FIPS_INVALID_DEVID);
}


/* Free DH Key */
int wc_FreeDhKey_fips(DhKey* key)
{
    WC_LOG_FUNC_ID("3.19");
    if (key == NULL)
        return BAD_FUNC_ARG;

    return wc_FreeDhKey(key);
}


/* Set DH Key */
int wc_DhSetKeyEx_fips(DhKey* key, const byte* p, word32 pSz,
                    const byte* g, word32 gSz, const byte* q, word32 qSz)
{
    WC_LOG_FUNC_ID("3.20");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_DH_PRIMITIVE_Z) != 0)
        return DH_KAT_FIPS_E;

    return wc_DhSetKey_ex(key, p, pSz, g, gSz, q, qSz);
}

int wc_DhSetKey_fips(DhKey* key, const byte* p, word32 pSz,
                const byte* g, word32 gSz)
{
    WC_LOG_FUNC_ID("3.21");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_DH_PRIMITIVE_Z) != 0)
        return DH_KAT_FIPS_E;

    return wc_DhSetKey(key, p, pSz, g, gSz);
}

int wc_DhGenerateParams_fips(WC_RNG *rng, int modSz, DhKey *dh)
{
    WC_LOG_FUNC_ID("3.22");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_DH_PRIMITIVE_Z) != 0)
        return DH_KAT_FIPS_E;

    return wc_DhGenerateParams(rng, modSz, dh);
}

int wc_DhExportParamsRaw_fips(DhKey* dh, byte* p, word32* pSz,
                byte* q, word32* qSz, byte* g, word32* gSz)
{
    WC_LOG_FUNC_ID("3.23");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_DH_PRIMITIVE_Z) != 0)
        return DH_KAT_FIPS_E;

    return wc_DhExportParamsRaw(dh, p, pSz, q, qSz, g, gSz);
}

int wc_DhCmpNamedKey_fips(int name, int noQ, const byte* p,
                word32 pSz, const byte* g, word32 gSz,
                const byte* q, word32 qSz)
{
    WC_LOG_FUNC_ID("3.24");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_DH_PRIMITIVE_Z) != 0)
        return DH_KAT_FIPS_E;

    return wc_DhCmpNamedKey(name, noQ, p, pSz, g, gSz, q, qSz);
}

int wc_DhGetNamedKeyParamSize_fips(int name,
                word32* p, word32* g, word32* q)
{
    WC_LOG_FUNC_ID("3.25");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_DH_PRIMITIVE_Z) != 0)
        return DH_KAT_FIPS_E;

    return wc_DhGetNamedKeyParamSize(name, p, g, q);
}

word32 wc_DhGetNamedKeyMinSize_fips(int name)
{
    WC_LOG_FUNC_ID("3.26");

    /* Note, wc_DhGetNamedKeyMinSize() is a public API that returns an unsigned
     * word32, and calling code throughout the library (including FIPS test
     * code) expects an unsigned retval and expects 0 on error.  Therefore we
     * can't return error codes here, because they will be interpreted by the
     * callers as enormous positive numbers.
     */

    if (FipsAllowed() != 0)
        return 0; /* FIPS_NOT_ALLOWED_E */

    if (AlgoAllowed(FIPS_CAST_DH_PRIMITIVE_Z) != 0)
        return 0; /* DH_KAT_FIPS_E */

    return wc_DhGetNamedKeyMinSize(name);
}

int wc_DhSetCheckKey_fips(DhKey* key, const byte* p, word32 pSz,
                                const byte* g, word32 gSz, const byte* q,
                                word32 qSz, int trusted, WC_RNG* rng)
{
    WC_LOG_FUNC_ID("3.27");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_DH_PRIMITIVE_Z) != 0)
        return DH_KAT_FIPS_E;

    return wc_DhSetCheckKey(key, p, pSz, g, gSz, q, qSz, trusted, rng);
}

/* Set trusted domain parameters */
int wc_DhSetNamedKey_fips(DhKey* key, int name)
{
    WC_LOG_FUNC_ID("3.28");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_DH_PRIMITIVE_Z) != 0)
        return DH_KAT_FIPS_E;

    return wc_DhSetNamedKey(key, name);
}

/* Generate a DH key pair */
int wc_DhGenerateKeyPair_fips(DhKey* key, WC_RNG* rng,
                           byte* priv, word32* privSz,
                           byte* pub, word32* pubSz)
{
    WC_LOG_FUNC_ID("3.29");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_DH_PRIMITIVE_Z) != 0)
        return DH_KAT_FIPS_E;

    if (GetTLS(&privateKeyReadEnable) > 0)
        return wc_DhGenerateKeyPair(key, rng, priv, privSz, pub, pubSz);
    else
        return FIPS_PRIVATE_KEY_LOCKED_E;
}

int wc_DhCheckPubKey_fips(DhKey* key, const byte* pub,
                           word32 pubSz)
{
    WC_LOG_FUNC_ID("3.30");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_DH_PRIMITIVE_Z) != 0)
        return DH_KAT_FIPS_E;

    return wc_DhCheckPubKey(key, pub, pubSz);
}

/* Check a DH public key for mathematical correctness */
int wc_DhCheckPubKeyEx_fips(DhKey* key, const byte* pub, word32 pubSz,
                             const byte* prime, word32 primeSz)
{
    WC_LOG_FUNC_ID("3.31");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_DH_PRIMITIVE_Z) != 0)
        return DH_KAT_FIPS_E;

    return wc_DhCheckPubKey_ex(key, pub, pubSz, prime, primeSz);
}

int wc_DhCheckPubValue_fips(const byte* prime, word32 primeSz, const byte* pub,
                            word32 pubSz)
{
    WC_LOG_FUNC_ID("3.32");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_DH_PRIMITIVE_Z) != 0)
        return DH_KAT_FIPS_E;

    return wc_DhCheckPubValue(prime, primeSz, pub, pubSz);
}

/* Check a DH private key for mathematical correctness */
int wc_DhCheckPrivKey_fips(DhKey* key, const byte* priv, word32 pubSz)
{
    WC_LOG_FUNC_ID("3.33");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_DH_PRIMITIVE_Z) != 0)
        return DH_KAT_FIPS_E;

    return wc_DhCheckPrivKey(key, priv, pubSz);
}

int wc_DhCheckPrivKeyEx_fips(DhKey* key, const byte* priv, word32 pubSz,
                              const byte* prime, word32 primeSz)
{
    WC_LOG_FUNC_ID("3.34");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_DH_PRIMITIVE_Z) != 0)
        return DH_KAT_FIPS_E;

    return wc_DhCheckPrivKey_ex(key, priv, pubSz, prime, primeSz);
}


/* Check a DH public and private key for pair-wise consistency */
int wc_DhCheckKeyPair_fips(DhKey* key, const byte* pub, word32 pubSz,
                        const byte* priv, word32 privSz)
{
    WC_LOG_FUNC_ID("3.35");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_DH_PRIMITIVE_Z) != 0)
        return DH_KAT_FIPS_E;

    return wc_DhCheckKeyPair(key, pub, pubSz, priv, privSz);
}


/* Generate shared secret with DH */
int wc_DhAgree_fips(DhKey* key, byte* agree, word32* agreeSz,
                 const byte* priv, word32 privSz, const byte* otherPub,
                 word32 pubSz)
{
    WC_LOG_FUNC_ID("3.36");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_DH_PRIMITIVE_Z) != 0)
        return DH_KAT_FIPS_E;

    if (GetTLS(&privateKeyReadEnable) > 0)
        return wc_DhAgree(key, agree, agreeSz, priv, privSz, otherPub, pubSz);
    else
        return FIPS_PRIVATE_KEY_LOCKED_E;
}

#endif /* NO_DH */


/* Init RNG */
#ifndef NO_RNG
/* DRBG Init not like a free function, needs instantiated for the first time
 * do not make pass-through like other init functions that do nothing but
 * initialize a structure for use */
int wc_InitRng_fips(WC_RNG* rng)
{
    int ret;

    WC_LOG_FUNC_ID("3.37");

    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_DRBG) != 0)
        return DRBG_KAT_FIPS_E;

    ret = wc_InitRng(rng);

    if (ret == WC_NO_ERR_TRACE(DRBG_CONT_FIPS_E)) {
        SetConTestFailure();
    }

    return ret;
}

int  wc_InitRng_ex_fips(WC_RNG* rng, void* heap, int devId)
{
    int ret;

    WC_LOG_FUNC_ID("3.38");

    (void) devId; /* Disabled in FIPS mode */
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_DRBG) != 0)
        return DRBG_KAT_FIPS_E;

    ret = wc_InitRng_ex(rng, heap, FIPS_INVALID_DEVID);

    if (ret == WC_NO_ERR_TRACE(DRBG_CONT_FIPS_E)) {
        SetConTestFailure();
    }

    return ret;
}

/* Init RNG with Nonce */
int wc_InitRngNonce_fips(WC_RNG* rng, byte* nonce, word32 nonceSz)
{
    int ret;

    WC_LOG_FUNC_ID("3.39");

    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_DRBG) != 0)
        return DRBG_KAT_FIPS_E;

    ret = wc_InitRngNonce(rng, nonce, nonceSz);
    if (ret == WC_NO_ERR_TRACE(DRBG_CONT_FIPS_E)) {
        SetConTestFailure();
    }

    return ret;
}

int  wc_InitRngNonce_ex_fips(WC_RNG* rng, byte* nonce,
    word32 nonceSz, void* heap, int devId)
{
    int ret;

    WC_LOG_FUNC_ID("3.40");

    (void) devId; /* Disabled in FIPS mode */
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_DRBG) != 0)
        return DRBG_KAT_FIPS_E;

    ret = wc_InitRngNonce_ex(rng, nonce, nonceSz, heap, FIPS_INVALID_DEVID);
    if (ret == WC_NO_ERR_TRACE(DRBG_CONT_FIPS_E)) {
        SetConTestFailure();
    }

    return ret;
}

/* Free RNG */
int wc_FreeRng_fips(WC_RNG* rng)
{
    WC_LOG_FUNC_ID("3.41");

    return wc_FreeRng(rng);
}


#ifdef WC_RNG_SEED_CB
/* Set the seeding callback. */
int wc_SetSeed_Cb_fips(wc_RngSeed_Cb cb)
{
    WC_LOG_FUNC_ID("3.42");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_DRBG) != 0)
        return DRBG_KAT_FIPS_E;

    return wc_SetSeed_Cb(cb);
}
#endif


/* Generate block of pseudo random numbers */
int wc_RNG_GenerateBlock_fips(WC_RNG* rng, byte* buf, word32 bufSz)
{
    int ret;

    WC_LOG_FUNC_ID("3.43");

    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_DRBG) != 0)
        return DRBG_KAT_FIPS_E;

    ret = wc_RNG_GenerateBlock(rng, buf, bufSz);
    if (ret == WC_NO_ERR_TRACE(DRBG_CONT_FIPS_E)) {
        SetConTestFailure();
        return DRBG_CONT_FIPS_E;
    }

    return ret;
}

int  wc_RNG_GenerateByte_fips(WC_RNG* rng, byte* b)
{
    int ret;

    WC_LOG_FUNC_ID("3.44");

    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_DRBG) != 0)
        return DRBG_KAT_FIPS_E;

    ret = wc_RNG_GenerateByte(rng, b);
    if (ret == WC_NO_ERR_TRACE(DRBG_CONT_FIPS_E)) {
        SetConTestFailure();
        return DRBG_CONT_FIPS_E;
    }

    return ret;
}

/* Optionally trigger a reseed of the DRBG ahead of automated reseed if a
 * more frequent reseed is desired for security considerations */
int wc_RNG_DRBG_Reseed_fips(WC_RNG* rng, const byte* entropy,
                                       word32 entropySz)
{
    WC_LOG_FUNC_ID("3.45");

    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_DRBG) != 0)
        return DRBG_KAT_FIPS_E;

    return wc_RNG_DRBG_Reseed(rng, entropy, entropySz);
}

/* Manually check a seed is OK */
WOLFSSL_API int wc_RNG_TestSeed_fips(const byte* seed, word32 seedSz)
{
    WC_LOG_FUNC_ID("3.46");

    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_DRBG) != 0)
        return DRBG_KAT_FIPS_E;

    return wc_RNG_TestSeed(seed, seedSz);
}

/* RNG Health Test */
int wc_RNG_HealthTest_fips(int reseed,
                                    const byte* entropyA, word32 entropyASz,
                                    const byte* entropyB, word32 entropyBSz,
                                    byte* output, word32 outputSz)
{
    int ret;

    WC_LOG_FUNC_ID("3.47");

    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_DRBG) != 0)
        return DRBG_KAT_FIPS_E;

#ifdef CUSTOM_RAND_GENERATE_BLOCK
    /* using custom RNG */
    /* One uses their own FIPS validated entropy source by:
     * Step 1) in user_settings.h or CFLAGS define CUSTOM_RAND_GENERATE_BLOCK
     *         to your custom function for example:
     *         #define CUSTOM_RAND_GENERATE_BLOCK my_rng_gen_block
     * Step 2) declare an "extern int my_rng_gen_block(unsigned char* output,
     *                                                  unsigned int sz);"
     *          function globally in user_settings.h or in
     *          wolfssl/wolfcrypt/settings.h.
     * Step 3) Implement that function at your application level having it load
     *         entropy from the desired FIPS validated entropy source
     * Anytime a DRBG or RNG  service is used it will now load entropy from that
     * source. */
    ret = 0;
    (void)reseed;
    (void)entropyA;
    (void)entropyASz;
    (void)entropyB;
    (void)entropyBSz;
    (void)output;
    (void)outputSz;
#else
    ret = wc_RNG_HealthTest(reseed, entropyA, entropyASz, entropyB, entropyBSz,
                                                              output, outputSz);
#endif
    if (ret == WC_NO_ERR_TRACE(DRBG_CONT_FIPS_E)) {
        SetConTestFailure();
        return DRBG_CONT_FIPS_E;
    }

    return ret;
}

int wc_RNG_HealthTest_ex_fips(int reseed, const byte* nonce,
    word32 nonceSz, const byte* entropyA, word32 entropyASz,
    const byte* entropyB, word32 entropyBSz, byte* output, word32 outputSz,
    void* heap, int devId)
{
    int ret;

    WC_LOG_FUNC_ID("3.48");

    (void) devId; /* Disabled in FIPS mode */
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_DRBG) != 0)
        return DRBG_KAT_FIPS_E;

#ifdef CUSTOM_RAND_GENERATE_BLOCK
    /* using custom RNG */
    /* consider adding RNG test similar to health test to ensure good entropy */
    ret = 0;
    (void)reseed;
    (void)entropyA;
    (void)entropyASz;
    (void)entropyB;
    (void)entropyBSz;
    (void)output;
    (void)outputSz;
#else
    ret = wc_RNG_HealthTest_ex(reseed, nonce, nonceSz, entropyA, entropyASz,
                entropyB, entropyBSz, output, outputSz, heap,
                FIPS_INVALID_DEVID);
#endif
    if (ret == WC_NO_ERR_TRACE(DRBG_CONT_FIPS_E)) {
        SetConTestFailure();
        return DRBG_CONT_FIPS_E;
    }

    return ret;
}

WC_RNG* wc_rng_new_fips(byte* nonce, word32 nonceSz, void* heap)
{
    WC_LOG_FUNC_ID("3.49");

    if (FipsAllowed() != 0)
        return NULL;

    if (AlgoAllowed(FIPS_CAST_DRBG) != 0)
        return NULL;

    return wc_rng_new(nonce, nonceSz, heap);
}

int wc_rng_new_ex_fips(WC_RNG **rng, byte* nonce, word32 nonceSz, void* heap,
                            int devId)
{
    WC_LOG_FUNC_ID("3.50");
    (void) devId; /* Disabled in FIPS mode */

    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_DRBG) != 0)
        return DRBG_KAT_FIPS_E;

    return wc_rng_new_ex(rng, nonce, nonceSz, heap, FIPS_INVALID_DEVID);
}

/* Free function, no cryptography just freeing resources
 * make it pass-through without the "Allowed" checks to protect against memory
 * leaks and CSPs not getting zeroised in the event the CAST has failed */
void wc_rng_free_fips(WC_RNG* rng)
{
    WC_LOG_FUNC_ID("3.51");

    wc_rng_free(rng);
}


#endif /* NO_RNG */


/* CMAC API */
#ifdef WOLFSSL_CMAC

/* Init CMAC */
/* Init like a free function, no cryptography just initializing a structure
 * for use so make it pass-through without the "Allowed" checks */
int wc_InitCmac_fips(Cmac* cmac, const byte* key, word32 keySz,
                                    int type, void* unused)
{
    WC_LOG_FUNC_ID("3.52");

    return wc_InitCmac(cmac, key, keySz, type, unused);
}


/*  CMAC Update */
int wc_CmacUpdate_fips(Cmac* cmac, const byte* in, word32 inSz)
{
    WC_LOG_FUNC_ID("3.53");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Since CMAC is just doing data integrity, AES-CBC failing it's cast would
     * only indicate the encryption and decryption are unavailable for use.
     * do not check CBC CAST status for Cmac operations */

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_GCM) != 0)
        return AES_KAT_FIPS_E;

    return wc_CmacUpdate(cmac, in, inSz);
}


/*  CMAC Final */
int wc_CmacFinal_fips(Cmac* cmac, byte* out, word32* outSz)
{
    WC_LOG_FUNC_ID("3.54");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Since CMAC is just doing data integrity, AES-CBC failing it's cast would
     * only indicate the encryption and decryption are unavailable for use.
     * do not check CBC CAST status for Cmac operations */

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_GCM) != 0)
        return AES_KAT_FIPS_E;

    return wc_CmacFinal(cmac, out, outSz);
}

/* Init like a free function, no cryptography just initializing a structure
 * for use so make it pass-through without the "Allowed" checks */
int wc_InitCmac_ex_fips(Cmac* cmac, const byte* key, word32 keySz, int type,
                        void* unused, void* heap, int devId)
{
    WC_LOG_FUNC_ID("3.55");

    (void) devId; /* Disabled in FIPS mode */

    return wc_InitCmac_ex(cmac, key, keySz, type, unused, heap,
                          FIPS_INVALID_DEVID);
}

int wc_CmacFinalNoFree_fips(Cmac* cmac, byte* out, word32* outSz)
{
    WC_LOG_FUNC_ID("3.56");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Since CMAC is just doing data integrity, AES-CBC failing it's cast would
     * only indicate the encryption and decryption are unavailable for use.
     * do not check CBC CAST status for Cmac operations */

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_GCM) != 0)
        return AES_KAT_FIPS_E;

    return wc_CmacFinalNoFree(cmac, out, outSz);
}

/* Free function, no cryptography just freeing resources
 * make it pass-through without the "Allowed" checks to protect against memory
 * leaks in the event the CAST has failed */
int wc_CmacFree_fips(Cmac* cmac)
{
    WC_LOG_FUNC_ID("3.57");

    return wc_CmacFree(cmac);
}

int wc_AesCmacGenerate_fips(byte* out, word32* outSz, const byte* in,
                            word32 inSz, const byte* key, word32 keySz)
{
    WC_LOG_FUNC_ID("3.58");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Since CMAC is just doing data integrity, AES-CBC failing it's cast would
     * only indicate the encryption and decryption are unavailable for use.
     * do not check CBC CAST status for Cmac operations */

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_GCM) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesCmacGenerate(out, outSz, in, inSz, key, keySz);
}

int wc_AesCmacGenerate_ex_fips(Cmac *cmac, byte* out, word32* outSz,
                               const byte* in, word32 inSz, const byte* key,
                               word32 keySz, void* heap, int devId)
{
    WC_LOG_FUNC_ID("3.59");

    (void) devId; /* Disabled in FIPS mode */
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Since CMAC is just doing data integrity, AES-CBC failing it's cast would
     * only indicate the encryption and decryption are unavailable for use.
     * do not check CBC CAST status for Cmac operations */

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_GCM) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesCmacGenerate_ex(cmac, out, outSz, in, inSz, key, keySz, heap,
                                 FIPS_INVALID_DEVID);
}

int wc_AesCmacVerify_fips(const byte* check, word32 checkSz, const byte* in,
                          word32 inSz, const byte* key, word32 keySz)
{
    WC_LOG_FUNC_ID("3.60");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Since CMAC is just doing data integrity, AES-CBC failing it's cast would
     * only indicate the encryption and decryption are unavailable for use.
     * do not check CBC CAST status for Cmac operations */

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_GCM) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesCmacVerify(check, checkSz, in, inSz, key, keySz);
}

int wc_AesCmacVerify_ex_fips(Cmac* cmac, const byte* check, word32 checkSz,
                             const byte* in, word32 inSz, const byte* key,
                             word32 keySz, void* heap, int devId)
{
    WC_LOG_FUNC_ID("3.61");

    (void) devId; /* Disabled in FIPS mode */
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Since CMAC is just doing data integrity, AES-CBC failing it's cast would
     * only indicate the encryption and decryption are unavailable for use.
     * do not check CBC CAST status for Cmac operations */

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_GCM) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesCmacVerify_ex(cmac, check, checkSz, in, inSz, key, keySz, heap,
                               FIPS_INVALID_DEVID);
}

#ifdef WOLFSSL_HASH_KEEP
int wc_CMAC_Grow_fips(Cmac* cmac, const byte* in, int inSz)
{
    WC_LOG_FUNC_ID("3.62");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    /* Since CMAC is just doing data integrity, AES-CBC failing it's cast would
     * only indicate the encryption and decryption are unavailable for use.
     * do not check CBC CAST status for Cmac operations */

    /* Reference AES TIERED TEST COMMENT why checking CBC and/or GCM here */
    if (AlgoAllowed(FIPS_CAST_AES_GCM) != 0)
        return AES_KAT_FIPS_E;

    return wc_CMAC_Grow(cmac, in, inSz);
}
#endif

#endif /* WOLFSSL_CMAC */

#ifdef WC_SRTP_KDF
int wc_SRTP_KDF_fips(const byte* key, word32 keySz, const byte* salt,
                     word32 saltSz, int kdrIdx, const byte* index, byte* key1,
                     word32 key1Sz, byte* key2, word32 key2Sz, byte* key3,
                     word32 key3Sz)
{
    WC_LOG_FUNC_ID("3.63");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_KDF_SRTP) != 0)
        return KDF_SRTP_KAT_FIPS_E;

    if (GetTLS(&privateKeyReadEnable) > 0)
        return wc_SRTP_KDF(key, keySz, salt, saltSz, kdrIdx, index, key1,
                           key1Sz, key2, key2Sz, key3, key3Sz);
    else
        return FIPS_PRIVATE_KEY_LOCKED_E;
}

int wc_SRTCP_KDF_fips(const byte* key, word32 keySz, const byte* salt, word32 saltSz,
                 int kdrIdx, const byte* index, byte* key1, word32 key1Sz,
                 byte* key2, word32 key2Sz, byte* key3, word32 key3Sz)
{
    WC_LOG_FUNC_ID("3.64");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_KDF_SRTP) != 0)
        return KDF_SRTP_KAT_FIPS_E;

    if (GetTLS(&privateKeyReadEnable) > 0)
        return wc_SRTCP_KDF(key, keySz, salt, saltSz, kdrIdx, index, key1,
                            key1Sz, key2, key2Sz, key3, key3Sz);
    else
        return FIPS_PRIVATE_KEY_LOCKED_E;
}

int wc_SRTCP_KDF_ex_fips(const byte* key, word32 keySz,
                            const byte* salt, word32 saltSz, int kdrIdx,
                            const byte* index, byte* key1, word32 key1Sz,
                            byte* key2, word32 key2Sz, byte* key3,
                            word32 key3Sz, int idxLenIndicator)
{
    WC_LOG_FUNC_ID("3.65");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_KDF_SRTP) != 0)
        return KDF_SRTP_KAT_FIPS_E;

    if (GetTLS(&privateKeyReadEnable) > 0)
        return wc_SRTCP_KDF_ex(key, keySz, salt, saltSz, kdrIdx, index, key1,
                            key1Sz, key2, key2Sz, key3, key3Sz,
                            idxLenIndicator);
    else
        return FIPS_PRIVATE_KEY_LOCKED_E;
}

int wc_SRTP_KDF_label_fips(const byte* key, word32 keySz, const byte* salt,
                      word32 saltSz, int kdrIdx, const byte* index, byte label,
                      byte* outKey, word32 outKeySz)
{
    WC_LOG_FUNC_ID("3.66");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_KDF_SRTP) != 0)
        return KDF_SRTP_KAT_FIPS_E;

    if (GetTLS(&privateKeyReadEnable) > 0)
        return wc_SRTP_KDF_label(key, keySz, salt, saltSz, kdrIdx, index, label,
                                 outKey, outKeySz);
    else
        return FIPS_PRIVATE_KEY_LOCKED_E;
}

int wc_SRTCP_KDF_label_fips(const byte* key, word32 keySz, const byte* salt,
                       word32 saltSz, int kdrIdx, const byte* index, byte label,
                       byte* outKey, word32 outKeySz)
{
    WC_LOG_FUNC_ID("3.67");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_KDF_SRTP) != 0)
        return KDF_SRTP_KAT_FIPS_E;

    if (GetTLS(&privateKeyReadEnable) > 0)
        return wc_SRTCP_KDF_label(key, keySz, salt, saltSz, kdrIdx, index,
                                  label, outKey, outKeySz);
    else
        return FIPS_PRIVATE_KEY_LOCKED_E;
}

int wc_SRTP_KDF_kdr_to_idx_fips(word32 kdr)
{
    WC_LOG_FUNC_ID("3.68");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_KDF_SRTP) != 0)
        return KDF_SRTP_KAT_FIPS_E;

    return wc_SRTP_KDF_kdr_to_idx(kdr);
}
#endif

#ifdef HAVE_ED25519
/* NOTE: Ed25519 SHALL use SHA2-512 (Per NIST.FIPS.186-5)
 */
int wc_ed25519_make_public_fips(ed25519_key* key, unsigned char* pubKey,
                           word32 pubKeySz)
{
    WC_LOG_FUNC_ID("3.69");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_512) != 0)
        return HMAC_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED25519) != 0)
        return ED25519_KAT_FIPS_E;

    return wc_ed25519_make_public(key, pubKey, pubKeySz);
}

int wc_ed25519_make_key_fips(WC_RNG* rng, int keysize, ed25519_key* key)
{
    WC_LOG_FUNC_ID("3.70");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_512) != 0)
        return HMAC_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED25519) != 0)
        return ED25519_KAT_FIPS_E;

    return wc_ed25519_make_key(rng, keysize, key);
}

#ifdef HAVE_ED25519_SIGN
int wc_ed25519_sign_msg_fips(const byte* in, word32 inLen, byte* out,
                        word32 *outLen, ed25519_key* key)
{
    WC_LOG_FUNC_ID("3.71");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_512) != 0)
        return HMAC_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED25519) != 0)
        return ED25519_KAT_FIPS_E;

    return wc_ed25519_sign_msg(in, inLen, out, outLen, key);
}

int wc_ed25519ctx_sign_msg_fips(const byte* in, word32 inLen, byte* out,
                           word32 *outLen, ed25519_key* key,
                           const byte* context, byte contextLen)
{
    WC_LOG_FUNC_ID("3.72");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_512) != 0)
        return HMAC_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED25519) != 0)
        return ED25519_KAT_FIPS_E;

    return wc_ed25519ctx_sign_msg(in, inLen, out, outLen, key, context,
                                  contextLen);
}

int wc_ed25519ph_sign_hash_fips(const byte* hash, word32 hashLen, byte* out,
                           word32 *outLen, ed25519_key* key,
                           const byte* context, byte contextLen)
{
    WC_LOG_FUNC_ID("3.73");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_512) != 0)
        return HMAC_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED25519) != 0)
        return ED25519_KAT_FIPS_E;

    return wc_ed25519ph_sign_hash(hash, hashLen, out, outLen, key, context,
                                  contextLen);
}

int wc_ed25519ph_sign_msg_fips(const byte* in, word32 inLen, byte* out,
                          word32 *outLen, ed25519_key* key, const byte* context,
                          byte contextLen)
{
    WC_LOG_FUNC_ID("3.74");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_512) != 0)
        return HMAC_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED25519) != 0)
        return ED25519_KAT_FIPS_E;

    return wc_ed25519ph_sign_msg(in, inLen, out, outLen, key, context,
                                 contextLen);
}

int wc_ed25519_sign_msg_ex_fips(const byte* in, word32 inLen, byte* out,
                            word32 *outLen, ed25519_key* key, byte type,
                            const byte* context, byte contextLen)
{
    WC_LOG_FUNC_ID("3.75");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_512) != 0)
        return HMAC_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED25519) != 0)
        return ED25519_KAT_FIPS_E;

    return wc_ed25519_sign_msg_ex(in, inLen, out, outLen, key, type, context,
                                  contextLen);
}
#endif /* HAVE_ED25519_SIGN */

#ifdef HAVE_ED25519_VERIFY
int wc_ed25519_verify_msg_fips(const byte* sig, word32 sigLen, const byte* msg,
                          word32 msgLen, int* res, ed25519_key* key)
{
    WC_LOG_FUNC_ID("3.76");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_512) != 0)
        return HMAC_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED25519) != 0)
        return ED25519_KAT_FIPS_E;

    return wc_ed25519_verify_msg(sig, sigLen, msg, msgLen, res, key);
}

int wc_ed25519ctx_verify_msg_fips(const byte* sig, word32 sigLen,
                             const byte* msg, word32 msgLen, int* res,
                             ed25519_key* key, const byte* context,
                             byte contextLen)
{
    WC_LOG_FUNC_ID("3.77");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_512) != 0)
        return HMAC_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED25519) != 0)
        return ED25519_KAT_FIPS_E;

    return wc_ed25519ctx_verify_msg(sig, sigLen, msg, msgLen, res, key, context,
                                    contextLen);
}

int wc_ed25519ph_verify_hash_fips(const byte* sig, word32 sigLen,
                             const byte* hash, word32 hashLen, int* res,
                             ed25519_key* key, const byte* context,
                             byte contextLen)
{
    WC_LOG_FUNC_ID("3.78");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_512) != 0)
        return HMAC_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED25519) != 0)
        return ED25519_KAT_FIPS_E;

    return wc_ed25519ph_verify_hash(sig, sigLen, hash, hashLen, res, key,
                                    context, contextLen);
}

int wc_ed25519ph_verify_msg_fips(const byte* sig, word32 sigLen, const byte* msg,
                            word32 msgLen, int* res, ed25519_key* key,
                            const byte* context, byte contextLen)
{
    WC_LOG_FUNC_ID("3.79");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_512) != 0)
        return HMAC_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED25519) != 0)
        return ED25519_KAT_FIPS_E;

    return wc_ed25519ph_verify_msg(sig, sigLen, msg, msgLen, res, key, context,
                                   contextLen);
}

int wc_ed25519_verify_msg_ex_fips(const byte* sig, word32 sigLen,
                              const byte* msg, word32 msgLen, int* res,
                              ed25519_key* key, byte type, const byte* context,
                              byte contextLen)
{
    WC_LOG_FUNC_ID("3.80");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_512) != 0)
        return HMAC_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED25519) != 0)
        return ED25519_KAT_FIPS_E;

    return wc_ed25519_verify_msg_ex(sig, sigLen, msg, msgLen, res, key, type,
                                    context, contextLen);
}

#ifdef WOLFSSL_ED25519_STREAMING_VERIFY
int wc_ed25519_verify_msg_init_fips(const byte* sig, word32 sigLen,
                               ed25519_key* key, byte type, const byte* context,
                               byte contextLen)
{
    WC_LOG_FUNC_ID("3.81");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_512) != 0)
        return HMAC_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED25519) != 0)
        return ED25519_KAT_FIPS_E;

    return wc_ed25519_verify_msg_init(sig, sigLen, key, type, context,
                                      contextLen);
}

int wc_ed25519_verify_msg_update_fips(const byte* msgSegment,
                               word32 msgSegmentLen, ed25519_key* key)
{
    WC_LOG_FUNC_ID("3.82");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_512) != 0)
        return HMAC_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED25519) != 0)
        return ED25519_KAT_FIPS_E;

    return wc_ed25519_verify_msg_update(msgSegment, msgSegmentLen, key);
}

int wc_ed25519_verify_msg_final_fips(const byte* sig, word32 sigLen, int* res,
                                ed25519_key* key)
{
    WC_LOG_FUNC_ID("3.83");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_512) != 0)
        return HMAC_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED25519) != 0)
        return ED25519_KAT_FIPS_E;

    return wc_ed25519_verify_msg_final(sig, sigLen, res, key);
}
#endif /* WOLFSSL_ED25519_STREAMING_VERIFY */
#endif /* HAVE_ED25519_VERIFY */

/* Init like a free function, no cryptography just initializing a structure
 * for use so make it pass-through without the "Allowed" checks */
int wc_ed25519_init_fips(ed25519_key* key)
{
    WC_LOG_FUNC_ID("3.84");

    return wc_ed25519_init(key);
}

int wc_ed25519_init_ex_fips(ed25519_key* key, void* heap, int devId)
{
    WC_LOG_FUNC_ID("3.85");

    (void) devId; /* Disabled in FIPS mode */
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_512) != 0)
        return HMAC_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED25519) != 0)
        return ED25519_KAT_FIPS_E;

    return wc_ed25519_init_ex(key, heap, FIPS_INVALID_DEVID);
}

void wc_ed25519_free_fips(ed25519_key* key)
{
    WC_LOG_FUNC_ID("3.86");

    wc_ed25519_free(key);
}

#ifdef HAVE_ED25519_KEY_IMPORT

int wc_ed25519_import_public_fips(const byte* in, word32 inLen,
                                  ed25519_key* key)
{
    WC_LOG_FUNC_ID("3.87");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_512) != 0)
        return HMAC_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED25519) != 0)
        return ED25519_KAT_FIPS_E;

    return wc_ed25519_import_public(in, inLen, key);
}

int wc_ed25519_import_public_ex_fips(const byte* in, word32 inLen,
                                ed25519_key* key, int trusted)
{
    WC_LOG_FUNC_ID("3.88");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_512) != 0)
        return HMAC_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED25519) != 0)
        return ED25519_KAT_FIPS_E;

    return wc_ed25519_import_public_ex(in, inLen, key, trusted);
}

int wc_ed25519_import_private_only_fips(const byte* priv, word32 privSz,
                                                              ed25519_key* key)
{
    WC_LOG_FUNC_ID("3.89");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_512) != 0)
        return HMAC_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED25519) != 0)
        return ED25519_KAT_FIPS_E;

    return wc_ed25519_import_private_only(priv, privSz, key);
}

int wc_ed25519_import_private_key_fips(const byte* priv, word32 privSz,
                               const byte* pub, word32 pubSz, ed25519_key* key)
{
    WC_LOG_FUNC_ID("3.90");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_512) != 0)
        return HMAC_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED25519) != 0)
        return ED25519_KAT_FIPS_E;

    return wc_ed25519_import_private_key(priv, privSz, pub, pubSz, key);
}

int wc_ed25519_import_private_key_ex_fips(const byte* priv, word32 privSz,
    const byte* pub, word32 pubSz, ed25519_key* key, int trusted)
{
    WC_LOG_FUNC_ID("3.91");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_512) != 0)
        return HMAC_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED25519) != 0)
        return ED25519_KAT_FIPS_E;

    return wc_ed25519_import_private_key_ex(priv, privSz, pub, pubSz, key,
                                            trusted);
}
#endif /* HAVE_ED25519_KEY_IMPORT */

#ifdef HAVE_ED25519_KEY_EXPORT

int wc_ed25519_export_public_fips(ed25519_key* key, byte* out, word32* outLen)
{
    WC_LOG_FUNC_ID("3.92");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_512) != 0)
        return HMAC_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED25519) != 0)
        return ED25519_KAT_FIPS_E;

    return wc_ed25519_export_public(key, out, outLen);
}

int wc_ed25519_export_private_only_fips(ed25519_key* key, byte* out,
                                        word32* outLen)
{
    WC_LOG_FUNC_ID("3.93");

    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_512) != 0)
        return HMAC_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED25519) != 0)
        return ED25519_KAT_FIPS_E;

    if (GetTLS(&privateKeyReadEnable) > 0)
        return wc_ed25519_export_private_only(key, out, outLen);
    else
        return FIPS_PRIVATE_KEY_LOCKED_E;

}

int wc_ed25519_export_private_fips(ed25519_key* key, byte* out, word32* outLen)
{
    WC_LOG_FUNC_ID("3.94");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_512) != 0)
        return HMAC_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED25519) != 0)
        return ED25519_KAT_FIPS_E;

    if (GetTLS(&privateKeyReadEnable) > 0)
        return wc_ed25519_export_private(key, out, outLen);
    else
        return FIPS_PRIVATE_KEY_LOCKED_E;
}

int wc_ed25519_export_key_fips(ed25519_key* key, byte* priv, word32 *privSz,
                               byte* pub, word32 *pubSz)
{
    WC_LOG_FUNC_ID("3.95");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_512) != 0)
        return HMAC_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED25519) != 0)
        return ED25519_KAT_FIPS_E;

    if (GetTLS(&privateKeyReadEnable) > 0)
        return wc_ed25519_export_key(key, priv, privSz, pub, pubSz);
    else
        return FIPS_PRIVATE_KEY_LOCKED_E;

}
#endif /* HAVE_ED25519_KEY_EXPORT */

int wc_ed25519_check_key_fips(ed25519_key* key)
{
    WC_LOG_FUNC_ID("3.96");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_512) != 0)
        return HMAC_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED25519) != 0)
        return ED25519_KAT_FIPS_E;

    return wc_ed25519_check_key(key);
}

/* size helper */
int wc_ed25519_size_fips(ed25519_key* key)
{
    WC_LOG_FUNC_ID("3.97");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_512) != 0)
        return HMAC_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED25519) != 0)
        return ED25519_KAT_FIPS_E;

    return wc_ed25519_size(key);
}

int wc_ed25519_priv_size_fips(ed25519_key* key)
{
    WC_LOG_FUNC_ID("3.98");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_512) != 0)
        return HMAC_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED25519) != 0)
        return ED25519_KAT_FIPS_E;

    return wc_ed25519_priv_size(key);
}

int wc_ed25519_pub_size_fips(ed25519_key* key)
{
    WC_LOG_FUNC_ID("3.99");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_512) != 0)
        return HMAC_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED25519) != 0)
        return ED25519_KAT_FIPS_E;

    return wc_ed25519_pub_size(key);
}

int wc_ed25519_sig_size_fips(ed25519_key* key)
{
    WC_LOG_FUNC_ID("4.00");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_512) != 0)
        return HMAC_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED25519) != 0)
        return ED25519_KAT_FIPS_E;

    return wc_ed25519_sig_size(key);
}
#endif

#ifdef HAVE_ED448
/* NOTE: Ed448 SHALL use SHAKE256 (FIPS 202) (Per NIST.FIPS.186-5),
 * SHA3 CAST governs cShake256 per IG 10.3.A
 *      SP800-185 cSHAK256 will not be tested separately from SHA3 since
 *      wolfCrypt implementation SHA3 and SHAKE256 share the same underlying
 *      implementation IG10.3.A sub 4 item 2
 *      “FIPS 202 shared SHAKE implementation"
 */
int wc_ed448_make_public_fips(ed448_key* key, unsigned char* pubKey,
                           word32 pubKeySz)
{
    WC_LOG_FUNC_ID("4.01");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED448) != 0)
        return ED448_KAT_FIPS_E;

    return wc_ed448_make_public(key, pubKey, pubKeySz);
}

int wc_ed448_make_key_fips(WC_RNG* rng, int keysize, ed448_key* key)
{
    WC_LOG_FUNC_ID("4.02");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED448) != 0)
        return ED448_KAT_FIPS_E;

    return wc_ed448_make_key(rng, keysize, key);
}
#ifdef HAVE_ED448_SIGN
int wc_ed448_sign_msg_fips(const byte* in, word32 inLen, byte* out,
                        word32 *outLen, ed448_key* key,
                        const byte* context, byte contextLen)
{
    WC_LOG_FUNC_ID("4.03");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED448) != 0)
        return ED448_KAT_FIPS_E;

    return wc_ed448_sign_msg(in, inLen, out, outLen, key, context, contextLen);
}

int wc_ed448ph_sign_hash_fips(const byte* hash, word32 hashLen, byte* out,
                           word32 *outLen, ed448_key* key,
                           const byte* context, byte contextLen)
{
    WC_LOG_FUNC_ID("4.04");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED448) != 0)
        return ED448_KAT_FIPS_E;

    return wc_ed448ph_sign_hash(hash, hashLen, out, outLen, key, context,
                                  contextLen);
}

int wc_ed448ph_sign_msg_fips(const byte* in, word32 inLen, byte* out,
                          word32 *outLen, ed448_key* key, const byte* context,
                          byte contextLen)
{
    WC_LOG_FUNC_ID("4.05");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED448) != 0)
        return ED448_KAT_FIPS_E;

    return wc_ed448ph_sign_msg(in, inLen, out, outLen, key, context,
                                 contextLen);
}

int wc_ed448_sign_msg_ex_fips(const byte* in, word32 inLen, byte* out,
                            word32 *outLen, ed448_key* key, byte type,
                            const byte* context, byte contextLen)
{
    WC_LOG_FUNC_ID("4.06");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED448) != 0)
        return ED448_KAT_FIPS_E;

    return wc_ed448_sign_msg_ex(in, inLen, out, outLen, key, type, context,
                                  contextLen);
}
#endif /* HAVE_ED448_SIGN */

#ifdef HAVE_ED448_VERIFY
int wc_ed448_verify_msg_fips(const byte* sig, word32 sigLen, const byte* msg,
                          word32 msgLen, int* res, ed448_key* key,
                          const byte* context, byte contextLen)
{
    WC_LOG_FUNC_ID("4.07");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED448) != 0)
        return ED448_KAT_FIPS_E;

    return wc_ed448_verify_msg(sig, sigLen, msg, msgLen, res, key, context,
                               contextLen);
}

int wc_ed448ph_verify_hash_fips(const byte* sig, word32 sigLen,
                             const byte* hash, word32 hashLen, int* res,
                             ed448_key* key, const byte* context,
                             byte contextLen)
{
    WC_LOG_FUNC_ID("4.08");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED448) != 0)
        return ED448_KAT_FIPS_E;

    return wc_ed448ph_verify_hash(sig, sigLen, hash, hashLen, res, key,
                                    context, contextLen);
}

int wc_ed448ph_verify_msg_fips(const byte* sig, word32 sigLen, const byte* msg,
                            word32 msgLen, int* res, ed448_key* key,
                            const byte* context, byte contextLen)
{
    WC_LOG_FUNC_ID("4.09");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED448) != 0)
        return ED448_KAT_FIPS_E;

    return wc_ed448ph_verify_msg(sig, sigLen, msg, msgLen, res, key, context,
                                   contextLen);
}

int wc_ed448_verify_msg_ex_fips(const byte* sig, word32 sigLen,
                              const byte* msg, word32 msgLen, int* res,
                              ed448_key* key, byte type, const byte* context,
                              byte contextLen)
{
    WC_LOG_FUNC_ID("4.10");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED448) != 0)
        return ED448_KAT_FIPS_E;

    return wc_ed448_verify_msg_ex(sig, sigLen, msg, msgLen, res, key, type,
                                    context, contextLen);
}

#ifdef WOLFSSL_ED448_STREAMING_VERIFY
int wc_ed448_verify_msg_init_fips(const byte* sig, word32 sigLen,
                               ed448_key* key, byte type, const byte* context,
                               byte contextLen)
{
    WC_LOG_FUNC_ID("4.11");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED448) != 0)
        return ED448_KAT_FIPS_E;

    return wc_ed448_verify_msg_init(sig, sigLen, key, type, context,
                                      contextLen);
}

int wc_ed448_verify_msg_update_fips(const byte* msgSegment,
                               word32 msgSegmentLen, ed448_key* key)
{
    WC_LOG_FUNC_ID("4.12");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED448) != 0)
        return ED448_KAT_FIPS_E;

    return wc_ed448_verify_msg_update(msgSegment, msgSegmentLen, key);
}

int wc_ed448_verify_msg_final_fips(const byte* sig, word32 sigLen, int* res,
                                ed448_key* key)
{
    WC_LOG_FUNC_ID("4.13");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED448) != 0)
        return ED448_KAT_FIPS_E;

    return wc_ed448_verify_msg_final(sig, sigLen, res, key);
}
#endif /* WOLFSSL_ED448_STREAMING_VERIFY */
#endif /* HAVE_ED448_VERIFY */

/* Init like a free function, no cryptography just initializing a structure
 * for use so make it pass-through without the "Allowed" checks */
int wc_ed448_init_fips(ed448_key* key)
{
    WC_LOG_FUNC_ID("4.14");

    return wc_ed448_init(key);
}

int wc_ed448_init_ex_fips(ed448_key* key, void* heap, int devId)
{
    WC_LOG_FUNC_ID("4.15");

    (void) devId; /* Disabled in FIPS mode */
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED448) != 0)
        return ED448_KAT_FIPS_E;

    return wc_ed448_init_ex(key, heap, FIPS_INVALID_DEVID);
}

void wc_ed448_free_fips(ed448_key* key)
{
    WC_LOG_FUNC_ID("4.16");

    wc_ed448_free(key);
}

#ifdef HAVE_ED448_KEY_IMPORT

int wc_ed448_import_public_fips(const byte* in, word32 inLen,
                                  ed448_key* key)
{
    WC_LOG_FUNC_ID("4.17");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED448) != 0)
        return ED448_KAT_FIPS_E;

    return wc_ed448_import_public(in, inLen, key);
}

int wc_ed448_import_public_ex_fips(const byte* in, word32 inLen,
                                ed448_key* key, int trusted)
{
    WC_LOG_FUNC_ID("4.18");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED448) != 0)
        return ED448_KAT_FIPS_E;

    return wc_ed448_import_public_ex(in, inLen, key, trusted);
}

int wc_ed448_import_private_only_fips(const byte* priv, word32 privSz,
                                                              ed448_key* key)
{
    WC_LOG_FUNC_ID("4.19");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED448) != 0)
        return ED448_KAT_FIPS_E;

    return wc_ed448_import_private_only(priv, privSz, key);
}

int wc_ed448_import_private_key_fips(const byte* priv, word32 privSz,
                               const byte* pub, word32 pubSz, ed448_key* key)
{
    WC_LOG_FUNC_ID("4.20");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED448) != 0)
        return ED448_KAT_FIPS_E;

    return wc_ed448_import_private_key(priv, privSz, pub, pubSz, key);
}

int wc_ed448_import_private_key_ex_fips(const byte* priv, word32 privSz,
    const byte* pub, word32 pubSz, ed448_key* key, int trusted)
{
    WC_LOG_FUNC_ID("4.21");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED448) != 0)
        return ED448_KAT_FIPS_E;

    return wc_ed448_import_private_key_ex(priv, privSz, pub, pubSz, key,
                                            trusted);
}
#endif /* HAVE_ED448_KEY_IMPORT */

#ifdef HAVE_ED448_KEY_EXPORT

int wc_ed448_export_public_fips(ed448_key* key, byte* out, word32* outLen)
{
    WC_LOG_FUNC_ID("4.22");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED448) != 0)
        return ED448_KAT_FIPS_E;

    return wc_ed448_export_public(key, out, outLen);
}

int wc_ed448_export_private_only_fips(ed448_key* key, byte* out,
                                        word32* outLen)
{
    WC_LOG_FUNC_ID("4.23");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED448) != 0)
        return ED448_KAT_FIPS_E;

    if (GetTLS(&privateKeyReadEnable) > 0)
        return wc_ed448_export_private_only(key, out, outLen);
    else
        return FIPS_PRIVATE_KEY_LOCKED_E;
}

int wc_ed448_export_private_fips(ed448_key* key, byte* out, word32* outLen)
{
    WC_LOG_FUNC_ID("4.24");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED448) != 0)
        return ED448_KAT_FIPS_E;

    if (GetTLS(&privateKeyReadEnable) > 0)
        return wc_ed448_export_private(key, out, outLen);
    else
        return FIPS_PRIVATE_KEY_LOCKED_E;
}

int wc_ed448_export_key_fips(ed448_key* key, byte* priv, word32 *privSz,
                               byte* pub, word32 *pubSz)
{
    WC_LOG_FUNC_ID("4.25");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED448) != 0)
        return ED448_KAT_FIPS_E;

    if (GetTLS(&privateKeyReadEnable) > 0)
        return wc_ed448_export_key(key, priv, privSz, pub, pubSz);
    else
        return FIPS_PRIVATE_KEY_LOCKED_E;
}
#endif /* HAVE_ED448_KEY_EXPORT */

int wc_ed448_check_key_fips(ed448_key* key)
{
    WC_LOG_FUNC_ID("4.26");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED448) != 0)
        return ED448_KAT_FIPS_E;

    return wc_ed448_check_key(key);
}

/* size helper */
int wc_ed448_size_fips(ed448_key* key)
{
    WC_LOG_FUNC_ID("4.27");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED448) != 0)
        return ED448_KAT_FIPS_E;

    return wc_ed448_size(key);
}

int wc_ed448_priv_size_fips(ed448_key* key)
{
    WC_LOG_FUNC_ID("4.28");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED448) != 0)
        return ED448_KAT_FIPS_E;

    return wc_ed448_priv_size(key);
}

int wc_ed448_pub_size_fips(ed448_key* key)
{
    WC_LOG_FUNC_ID("4.29");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED448) != 0)
        return ED448_KAT_FIPS_E;

    return wc_ed448_pub_size(key);
}

int wc_ed448_sig_size_fips(ed448_key* key)
{
    WC_LOG_FUNC_ID("4.30");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_ED448) != 0)
        return ED448_KAT_FIPS_E;

    return wc_ed448_sig_size(key);
}
#endif

#ifdef WOLFSSL_SHAKE128
/* Init like a free function, no cryptography just initializing a structure
 * for use so make it pass-through without the "Allowed" checks */
int wc_InitShake128_fips(wc_Shake* shake, void* heap, int devId)
{
    WC_LOG_FUNC_ID("4.31");
    (void) devId; /* Disabled in FIPS mode */

    return wc_InitShake128(shake, heap, FIPS_INVALID_DEVID);
}

int wc_Shake128_Update_fips(wc_Shake* shake, const byte* data, word32 len)
{
    WC_LOG_FUNC_ID("4.32");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    return wc_Shake128_Update(shake, data, len);
}

int wc_Shake128_Final_fips(wc_Shake* shake, byte* hash, word32 hashLen)
{
    WC_LOG_FUNC_ID("4.33");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    return wc_Shake128_Final(shake, hash, hashLen);
}

int wc_Shake128_Absorb_fips(wc_Shake* shake, const byte* data, word32 len)
{
    WC_LOG_FUNC_ID("4.34");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    return wc_Shake128_Absorb(shake, data, len);
}

int wc_Shake128_SqueezeBlocks_fips(wc_Shake* shake, byte* out, word32 blockCnt)
{
    WC_LOG_FUNC_ID("4.35");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    return wc_Shake128_SqueezeBlocks(shake, out, blockCnt);
}

void wc_Shake128_Free_fips(wc_Shake* shake)
{
    WC_LOG_FUNC_ID("4.36");
    wc_Shake128_Free(shake);
}
#endif

#ifdef WOLFSSL_SHAKE256
/* Init like a free function, no cryptography just initializing a structure
 * for use so make it pass-through without the "Allowed" checks */
int wc_InitShake256_fips(wc_Shake* shake, void* heap, int devId)
{
    WC_LOG_FUNC_ID("4.37");
    (void) devId; /* Disabled in FIPS mode */

    return wc_InitShake256(shake, heap, FIPS_INVALID_DEVID);
}

int wc_Shake256_Update_fips(wc_Shake* shake, const byte* data, word32 len)
{
    WC_LOG_FUNC_ID("4.38");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    return wc_Shake256_Update(shake, data, len);
}

int wc_Shake256_Final_fips(wc_Shake* shake, byte* hash, word32 hashLen)
{
    WC_LOG_FUNC_ID("4.39");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    return wc_Shake256_Final(shake, hash, hashLen);
}

int wc_Shake256_Absorb_fips(wc_Shake* shake, const byte* data, word32 len)
{
    WC_LOG_FUNC_ID("4.40");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    return wc_Shake256_Absorb(shake, data, len);
}

int wc_Shake256_SqueezeBlocks_fips(wc_Shake* shake, byte* out, word32 blockCnt)
{
    WC_LOG_FUNC_ID("4.41");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    return wc_Shake256_SqueezeBlocks(shake, out, blockCnt);
}

void wc_Shake256_Free_fips(wc_Shake* shake)
{
    WC_LOG_FUNC_ID("4.42");

    wc_Shake256_Free(shake);
}
#endif

#ifdef HAVE_PBKDF2
int wc_PBKDF2_ex_fips(byte* output, const byte* passwd, int pLen,
                 const byte* salt, int sLen, int iterations, int kLen,
                 int typeH, void* heap, int devId)
{
    WC_LOG_FUNC_ID("4.43");

    (void) devId; /* Disabled in FIPS mode */
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_PBKDF2) != 0)
        return PBKDF2_KAT_FIPS_E;

    if (GetTLS(&privateKeyReadEnable) > 0)
        return wc_PBKDF2_ex(output, passwd, pLen, salt, sLen, iterations, kLen,
                            typeH, heap, FIPS_INVALID_DEVID);
    else
        return FIPS_PRIVATE_KEY_LOCKED_E;
}
int wc_PBKDF2_fips(byte* output, const byte* passwd, int pLen,
              const byte* salt, int sLen, int iterations, int kLen,
              int typeH)
{
    WC_LOG_FUNC_ID("4.44");
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_PBKDF2) != 0)
        return PBKDF2_KAT_FIPS_E;

    if (GetTLS(&privateKeyReadEnable) > 0)
        return wc_PBKDF2(output, passwd, pLen, salt, sLen, iterations, kLen,
                         typeH);
    else
        return FIPS_PRIVATE_KEY_LOCKED_E;
}
/* The PKCS12 PBKDF is not yet approved, but may one day be available, for
 * now leave as potential future service */
#if 0
int wc_PKCS12_PBKDF_fips(byte* output, const byte* passwd, int pLen,
                    const byte* salt, int sLen, int iterations,
                    int kLen, int typeH, int purpose)
{
    WC_LOG_FUNC_ID(previously unused function enabled,
                   add a func ID (intentional compile error));
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_PBKDF2) != 0)
        return PBKDF2_KAT_FIPS_E;

    if (GetTLS(&privateKeyReadEnable) > 0)
        return wc_PKCS12_PBKDF(output, passwd, pLen, salt, sLen, iterations,
                               kLen, typeH, purpose);
    else
        return FIPS_PRIVATE_KEY_LOCKED_E;
}

int wc_PKCS12_PBKDF_ex_fips(byte* output, const byte* passwd,int passLen,
                       const byte* salt, int saltLen, int iterations, int kLen,
                       int hashType, int id, void* heap)
{
    WC_LOG_FUNC_ID(previously unused function enabled,
                   add a func ID (intentional compile error));
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_PBKDF2) != 0)
        return PBKDF2_KAT_FIPS_E;

    if (GetTLS(&privateKeyReadEnable) > 0)
        return wc_PKCS12_PBKDF_ex(output, passwd, passLen, salt, saltLen,
                                  iterations, kLen, hashType, id, heap);
    else
        return FIPS_PRIVATE_KEY_LOCKED_E;
}
#endif /* if 0 */
#endif


#endif /* HAVE_FIPS */

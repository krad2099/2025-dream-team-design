/* fips.h
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



#ifndef WOLF_CRYPT_FIPS_H
#define WOLF_CRYPT_FIPS_H


#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/fips_test.h>

#ifdef __cplusplus
    extern "C" {
#endif

/* FIPS_INVALID_DEVID value */
#ifdef FIPS_INVALID_DEVID
    #undef FIPS_INVALID_DEVID
#endif
#define FIPS_INVALID_DEVID INVALID_DEVID
#if (FIPS_INVALID_DEVID != -2)
    #error "INVALID_DEVID value has been modified from its' original value -2"
#endif

/* Module version string max length */
#define WC_VERSION_LEN 20

#if FIPS_VERSION3_GE(6,0,0)
    extern const unsigned int wolfCrypt_FIPS_f_ro_sanity[2];
#endif

/* mp_int */
/* provide opaque definition for math int type */
#if defined(WOLFSSL_SP_MATH) || defined(WOLFSSL_SP_MATH_ALL)
    struct sp_int;
    #define MP_INT_T struct sp_int
#elif defined(USE_FAST_MATH)
    struct fp_int;
    #define MP_INT_T struct fp_int
#else
    struct mp_int;
    #define MP_INT_T struct mp_int
#endif

WOLFSSL_API const char* wolfCrypt_GetVersion_fips(void);
WOLFSSL_API int wolfCrypt_IntegrityTest_fips(void);

#ifdef WOLFSSL_LINUXKM
typedef atomic_t fipsCastStateId_t;
#define fipsCastStateId_read(x) atomic_read(&(x))
#define fipsCastStateId_set(x, y) atomic_set(&(x), y)
#else
typedef enum FipsCastStateId fipsCastStateId_t;
#define fipsCastStateId_read(x) (x)
#define fipsCastStateId_set(x,y) ((x) = (y))
#endif
WOLFSSL_LOCAL extern fipsCastStateId_t fipsCastStatus[FIPS_CAST_COUNT];
#define fipsCastStatus_get(x) fipsCastStateId_read(fipsCastStatus[x])
#define fipsCastStatus_put(x, y) fipsCastStateId_set(fipsCastStatus[x], y)


enum wc_KeyType {
    WC_KEYTYPE_ALL = 0
};
WOLFSSL_API int wolfCrypt_SetPrivateKeyReadEnable_fips(int enable,
                                                       enum wc_KeyType keyType);
WOLFSSL_API int wolfCrypt_GetPrivateKeyReadEnable_fips(enum wc_KeyType keyType);


/* Hash_DRBG API */
#if defined(HAVE_HASHDRBG) || defined(CUSTOM_RAND_GENERATE_BLOCK)

#ifdef FIPS_NO_WRAPPERS
    #ifndef WC_RNG_TYPE_DEFINED
        typedef struct OS_Seed OS_Seed;
        typedef struct WC_RNG WC_RNG;
        #ifdef WC_RNG_SEED_CB
        typedef int (*wc_RngSeed_Cb)(OS_Seed* os, byte* seed, word32 sz);
        #endif
        #define WC_RNG_TYPE_DEFINED
    #endif

    WOLFSSL_API int wc_InitRng_fips(WC_RNG* rng);
    WOLFSSL_API int wc_InitRng_ex_fips(WC_RNG* rng, void* heap, int devId);
    WOLFSSL_API int wc_InitRngNonce_fips(WC_RNG* rng, byte* nonce,
                                         word32 nonceSz);
    WOLFSSL_API int  wc_InitRngNonce_ex_fips(WC_RNG* rng, byte* nonce,
        word32 nonceSz, void* heap, int devId);
    WOLFSSL_API int wc_FreeRng_fips(WC_RNG* rng);
    #ifdef WC_RNG_SEED_CB
    WOLFSSL_API int wc_SetSeed_Cb_fips(wc_RngSeed_Cb cb);
    #endif
    WOLFSSL_API int wc_RNG_GenerateBlock_fips(WC_RNG* rng, byte* buf,
                                              word32 bufSz);
    WOLFSSL_API int  wc_RNG_GenerateByte_fips(WC_RNG* rng, byte* b);
    WOLFSSL_API int wc_RNG_DRBG_Reseed_fips(WC_RNG* rng, const byte* entropy,
                                       word32 entropySz);
    WOLFSSL_API int wc_RNG_TestSeed_fips(const byte* seed, word32 seedSz);
    WOLFSSL_API int wc_RNG_HealthTest_fips( int reseed, const byte* entropyA,
                            word32 entropyASz, const byte* entropyB,
                            word32 entropyBSz, byte* output, word32 outputSz);
    WOLFSSL_API int wc_RNG_HealthTest_ex_fips(int reseed, const byte* nonce,
                            word32 nonceSz, const byte* entropyA,
                            word32 entropyASz, const byte* entropyB,
                            word32 entropyBSz, byte* output, word32 outputSz,
                            void* heap, int devId);
    WOLFSSL_API WC_RNG* wc_rng_new_fips(byte* nonce, word32 nonceSz,
                            void* heap);
    WOLFSSL_API int wc_rng_new_ex_fips(WC_RNG **rng, byte* nonce,
                            word32 nonceSz, void* heap, int devId);
    WOLFSSL_API void wc_rng_free_fips(WC_RNG* rng);

#else /* FIPS_NO_WRAPPERS */
    /* if not impl or fips.c impl wrapper force fips calls if fips build */
    #define wc_InitRng                  wc_InitRng_fips
    #define wc_InitRng_ex               wc_InitRng_ex_fips
    #define wc_InitRngNonce             wc_InitRngNonce_fips
    #define wc_InitRngNonce_ex          wc_InitRngNonce_ex_fips
    #define wc_FreeRng                  wc_FreeRng_fips
    #define wc_SetSeed_Cb               wc_SetSeed_Cb_fips
    #define wc_RNG_GenerateBlock        wc_RNG_GenerateBlock_fips
    #define wc_RNG_GenerateByte         wc_RNG_GenerateByte_fips
    #define wc_RNG_DRBG_Reseed          wc_RNG_DRBG_Reseed_fips
    #define wc_RNG_TestSeed             wc_RNG_TestSeed_fips
    #define wc_RNG_HealthTest           wc_RNG_HealthTest_fips
    #define wc_RNG_HealthTest_ex        wc_RNG_HealthTest_ex_fips
    #define wc_rng_new                  wc_rng_new_fips
    #define wc_rng_new_ex               wc_rng_new_ex_fips
    #define wc_rng_free                 wc_rng_free_fips
#endif /* FIPS_NO_WRAPPERS */

#endif /* HAVE_HASHDRBG */


/* AES API */
#ifndef NO_AES

#ifdef FIPS_NO_WRAPPERS
    #ifndef WC_AES_TYPE_DEFINED
        typedef struct Aes Aes;
        #define WC_AES_TYPE_DEFINED
    #endif
    #ifdef WOLFSSL_AES_XTS
        #ifndef WC_AESXTS_TYPE_DEFINED
            typedef struct XtsAes XtsAes;
            typedef struct XtsAesStreamData XtsAesStreamData;
            #define WC_AESXTS_TYPE_DEFINED
        #endif
    #endif
    #ifdef HAVE_AESGCM
        #ifndef WC_AESGCM_TYPE_DEFINED
            typedef struct Gmac Gmac;
            #define WC_AESGCM_TYPE_DEFINED
        #endif
    #endif

    WOLFSSL_API int wc_AesSetKey_fips(Aes* aes, const byte* userKey,
                                      word32 keylen, const byte* iv, int dir);
    WOLFSSL_API int wc_AesSetIV_fips(Aes* aes, const byte* iv);
    WOLFSSL_API int wc_AesEcbEncrypt_fips(Aes* aes, byte* out, const byte* in,
                                          word32 sz);
    WOLFSSL_API int wc_AesEcbDecrypt_fips(Aes* aes, byte* out, const byte* in,
                                          word32 sz);
    WOLFSSL_API int wc_AesSetKeyDirect_fips(Aes* aes, const byte* key,
                                            word32 len, const byte* iv,
                                            int dir);
    WOLFSSL_API int wc_AesCbcEncrypt_fips(Aes* aes, byte* out, const byte* in,
                                          word32 sz);
    WOLFSSL_API int wc_AesCbcDecrypt_fips(Aes* aes, byte* out, const byte* in,
                                          word32 sz);
    WOLFSSL_API int wc_AesCtrEncrypt_fips(Aes* aes, byte* out, const byte* in,
                                          word32 sz);
    WOLFSSL_API int wc_AesCtrSetKey_fips(Aes* aes, const byte* key, word32 len,
                                         const byte* iv, int dir);
    WOLFSSL_API int wc_AesOfbEncrypt_fips(Aes* aes, byte* out, const byte* in,
                                          word32 sz);
    WOLFSSL_API int wc_AesOfbDecrypt_fips(Aes* aes, byte* out, const byte* in,
                                          word32 sz);
    #ifdef WOLFSSL_AES_CFB
        WOLFSSL_API int wc_AesCfbEncrypt_fips(Aes* aes, byte* out,
                                              const byte* in, word32 sz);
        WOLFSSL_API int wc_AesCfb1Encrypt_fips(Aes* aes, byte* out,
                                               const byte* in, word32 sz);
        WOLFSSL_API int wc_AesCfb8Encrypt_fips(Aes* aes, byte* out,
                                               const byte* in, word32 sz);
      #ifdef HAVE_AES_DECRYPT
        WOLFSSL_API int wc_AesCfbDecrypt_fips(Aes* aes, byte* out,
                                              const byte* in, word32 sz);
        WOLFSSL_API int wc_AesCfb1Decrypt_fips(Aes* aes, byte* out,
                                               const byte* in, word32 sz);
        WOLFSSL_API int wc_AesCfb8Decrypt_fips(Aes* aes, byte* out,
                                               const byte* in, word32 sz);
      #endif /* HAVE_AES_DECRYPT */
    #endif /* WOLFSSL_AES_CFB */

    WOLFSSL_API int wc_AesGcmSetKey_fips(Aes* aes, const byte* key, word32 len);
    WOLFSSL_API int wc_AesGcmSetExtIV_fips(Aes* aes, const byte* iv,
                                           word32 ivSz);
    WOLFSSL_API int wc_AesGcmSetIV_fips(Aes* aes, word32 ivSz,
                                        const byte* ivFixed, word32 ivFixedSz,
                                        WC_RNG* rng);
    WOLFSSL_API int wc_AesGcmEncrypt_fips(Aes* aes, byte* out, const byte* in,
                                          word32 sz,
                                          byte* ivOut, word32 ivOutSz,
                                          byte* authTag, word32 authTagSz,
                                          const byte* authIn, word32 authInSz);
    WOLFSSL_API int  wc_AesGcmEncrypt_ex_fips(Aes* aes, byte* out,
                                          const byte* in, word32 sz,
                                          byte* ivOut, word32 ivOutSz,
                                          byte* authTag, word32 authTagSz,
                                          const byte* authIn, word32 authInSz);

    WOLFSSL_API int wc_AesGcmDecrypt_fips(Aes* aes, byte* out, const byte* in,
                                          word32 sz,
                                          const byte* iv, word32 ivSz,
                                          const byte* authTag, word32 authTagSz,
                                          const byte* authIn, word32 authInSz);
    WOLFSSL_API int wc_Gmac_fips(const byte* key, word32 keySz, byte* iv,
                                 word32 ivSz,
                                 const byte* authIn, word32 authInSz,
                                 byte* authTag, word32 authTagSz, WC_RNG* rng);
    WOLFSSL_API int wc_GmacVerify_fips(const byte* key, word32 keySz,
                                       const byte* iv, word32 ivSz,
                                       const byte* authIn, word32 authInSz,
                                       const byte* authTag, word32 authTagSz);
    WOLFSSL_API int wc_GmacSetKey_fips(Gmac* gmac, const byte* key, word32 len);
    WOLFSSL_API int wc_GmacUpdate_fips(Gmac* gmac, const byte* iv, word32 ivSz,
                                  const byte* authIn, word32 authInSz,
                                  byte* authTag, word32 authTagSz);
    WOLFSSL_API int wc_AesCcmSetKey_fips(Aes* aes, const byte* key, word32 len);
    WOLFSSL_API int wc_AesCcmSetNonce_fips(Aes* aes, const byte* nonce,
                                           word32 nonceSz);
    WOLFSSL_API int wc_AesCcmEncrypt_fips(Aes* aes, byte* out, const byte* in,
                                          word32 sz,
                                          byte* ivOut, word32 ivOutSz,
                                          byte* authTag, word32 authTagSz,
                                          const byte* authIn, word32 authInSz);
    WOLFSSL_API int  wc_AesCcmEncrypt_ex_fips(Aes* aes, byte* out,
                                          const byte* in, word32 sz,
                                          byte* ivOut, word32 ivOutSz,
                                          byte* authTag, word32 authTagSz,
                                          const byte* authIn, word32 authInSz);
    WOLFSSL_API int wc_AesCcmDecrypt_fips(Aes* aes, byte* out, const byte* in,
                                          word32 sz,
                                          const byte* iv, word32 ivSz,
                                          const byte* authTag, word32 authTagSz,
                                          const byte* authIn, word32 authInSz);

#ifdef HAVE_AES_KEYWRAP
    WOLFSSL_API int  wc_AesKeyWrap_fips(const byte* key, word32 keySz,
                                        const byte* in, word32 inSz,
                                        byte* out, word32 outSz,
                                        const byte* iv);
    WOLFSSL_API int  wc_AesKeyWrap_ex_fips(Aes *aes,
                                        const byte* in, word32 inSz,
                                        byte* out, word32 outSz,
                                        const byte* iv);
    WOLFSSL_API int  wc_AesKeyUnWrap_fips(const byte* key, word32 keySz,
                                        const byte* in, word32 inSz,
                                        byte* out, word32 outSz,
                                        const byte* iv);
    WOLFSSL_API int  wc_AesKeyUnWrap_ex_fips(Aes *aes,
                                        const byte* in, word32 inSz,
                                        byte* out, word32 outSz,
                                        const byte* iv);
#endif /* HAVE_AES_KEYWRAP */

#ifdef WOLFSSL_AES_XTS
    WOLFSSL_API int wc_AesXtsInit_fips(XtsAes* aes, void* heap, int devId);
    WOLFSSL_API int wc_AesXtsSetKeyNoInit_fips(XtsAes* aes, const byte* key,
                                         word32 len, int dir);
    WOLFSSL_API int wc_AesXtsSetKey_fips(XtsAes* aes, const byte* key,
                                         word32 len, int dir, void* heap,
                                         int devId);
    WOLFSSL_API int wc_AesXtsEncryptSector_fips(XtsAes* aes, byte* out,
                                         const byte* in, word32 sz,
                                         word64 sector);
    WOLFSSL_API int wc_AesXtsDecryptSector_fips(XtsAes* aes, byte* out,
                                         const byte* in, word32 sz,
                                         word64 sector);
    WOLFSSL_API int wc_AesXtsEncrypt_fips(XtsAes* aes, byte* out,
                                          const byte* in, word32 sz,
                                          const byte* i, word32 iSz);
    WOLFSSL_API int wc_AesXtsDecrypt_fips(XtsAes* aes, byte* out,
                                          const byte* in, word32 sz,
                                          const byte* i, word32 iSz);
    WOLFSSL_API int wc_AesXtsEncryptConsecutiveSectors_fips(XtsAes* aes,
                                          byte* out, const byte* in, word32 sz,
                                          word64 sector, word32 sectorSz);
    WOLFSSL_API int wc_AesXtsDecryptConsecutiveSectors_fips(XtsAes* aes,
                                          byte* out, const byte* in, word32 sz,
                                          word64 sector, word32 sectorSz);
#ifdef WOLFSSL_AESXTS_STREAM
    WOLFSSL_API int wc_AesXtsEncryptInit_fips(XtsAes* aes, const byte* i,
                            word32 iSz, struct XtsAesStreamData *stream);
    WOLFSSL_API int wc_AesXtsDecryptInit_fips(XtsAes* aes, const byte* i,
                            word32 iSz, struct XtsAesStreamData *stream);
    WOLFSSL_API int wc_AesXtsEncryptUpdate_fips(XtsAes* aes, byte* out,
                            const byte* in, word32 sz,
                            struct XtsAesStreamData *stream);
    WOLFSSL_API int wc_AesXtsDecryptUpdate_fips(XtsAes* aes, byte* out,
                            const byte* in, word32 sz,
                            struct XtsAesStreamData *stream);
    WOLFSSL_API int wc_AesXtsEncryptFinal_fips(XtsAes* aes, byte* out,
                            const byte* in, word32 sz,
                            struct XtsAesStreamData *stream);
    WOLFSSL_API int wc_AesXtsDecryptFinal_fips(XtsAes* aes, byte* out,
                            const byte* in, word32 sz,
                            struct XtsAesStreamData *stream);
#endif /* WOLFSSL_AESXTS_STREAM */

    WOLFSSL_API int wc_AesXtsFree_fips(XtsAes* aes);
#endif

#ifdef WOLFSSL_AESGCM_STREAM
    WOLFSSL_API int wc_AesGcmInit_fips(Aes* aes, const byte* key, word32 len,
                                       const byte* iv, word32 ivSz);
    WOLFSSL_API int wc_AesGcmEncryptInit_fips(Aes* aes, const byte* key,
                                              word32 len, const byte* iv,
                                              word32 ivSz);
    WOLFSSL_API int wc_AesGcmEncryptInit_ex_fips(Aes* aes, const byte* key,
                                                 word32 len, byte* ivOut,
                                                 word32 ivOutSz);
    WOLFSSL_API int wc_AesGcmEncryptUpdate_fips(Aes* aes, byte* out,
                                                const byte* in, word32 sz,
                                                const byte* authIn,
                                                word32 authInSz);
    WOLFSSL_API int wc_AesGcmEncryptFinal_fips(Aes* aes, byte* authTag,
                                               word32 authTagSz);
    WOLFSSL_API int wc_AesGcmDecryptInit_fips(Aes* aes, const byte* key,
                                              word32 len, const byte* iv,
                                              word32 ivSz);
    WOLFSSL_API int wc_AesGcmDecryptUpdate_fips(Aes* aes, byte* out,
                                                const byte* in, word32 sz,
                                                const byte* authIn,
                                                word32 authInSz);
    WOLFSSL_API int wc_AesGcmDecryptFinal_fips(Aes* aes, const byte* authTag,
                                               word32 authTagSz);
#endif

WOLFSSL_API int wc_AesGetKeySize_fips(Aes* aes, word32* keySize);
WOLFSSL_API int  wc_AesInit_fips(Aes* aes, void* heap, int devId);
WOLFSSL_API void wc_AesFree_fips(Aes* aes);

#else /* NO_FIPS_WRAPPERS */
    /* if not impl or fips.c impl wrapper force fips calls if fips build */
    #define wc_AesSetKey                wc_AesSetKey_fips
    #define wc_AesSetIV                 wc_AesSetIV_fips
    #define wc_AesEcbEncrypt            wc_AesEcbEncrypt_fips
    #define wc_AesEcbDecrypt            wc_AesEcbDecrypt_fips
    #define wc_AesSetKeyDirect          wc_AesSetKeyDirect_fips
    #define wc_AesCbcEncrypt            wc_AesCbcEncrypt_fips
    #define wc_AesCbcDecrypt            wc_AesCbcDecrypt_fips
    #define wc_AesCtrEncrypt            wc_AesCtrEncrypt_fips
    #define wc_AesCtrSetKey             wc_AesCtrSetKey_fips
    #define wc_AesOfbEncrypt            wc_AesOfbEncrypt_fips
    #define wc_AesOfbDecrypt            wc_AesOfbDecrypt_fips
    #ifdef WOLFSSL_AES_CFB
        #define wc_AesCfbEncrypt        wc_AesCfbEncrypt_fips
        #define wc_AesCfb1Encrypt       wc_AesCfb1Encrypt_fips
        #define wc_AesCfb8Encrypt       wc_AesCfb8Encrypt_fips
      #ifdef HAVE_AES_DECRYPT
        #define wc_AesCfbDecrypt        wc_AesCfbDecrypt_fips
        #define wc_AesCfb1Decrypt       wc_AesCfb1Decrypt_fips
        #define wc_AesCfb8Decrypt       wc_AesCfb8Decrypt_fips
      #endif /* HAVE_AES_DECRYPT */
    #endif /* WOLFSSL_AES_CFB */
    #define wc_AesGcmSetKey             wc_AesGcmSetKey_fips
    #define wc_AesGcmSetExtIV           wc_AesGcmSetExtIV_fips
    #define wc_AesGcmSetIV              wc_AesGcmSetIV_fips
    #define wc_AesGcmEncrypt_ex         wc_AesGcmEncrypt_fips
    #define wc_AesGcmDecrypt            wc_AesGcmDecrypt_fips
    #define wc_AesCcmSetKey             wc_AesCcmSetKey_fips
    #define wc_AesCcmSetNonce           wc_AesCcmSetNonce_fips
    #define wc_AesCcmEncrypt            wc_AesCcmEncrypt_fips
    #define wc_AesCcmEncrypt_ex         wc_AesCcmEncrypt_ex_fips
    #define wc_AesCcmDecrypt            wc_AesCcmDecrypt_fips
    #define wc_Gmac                     wc_Gmac_fips
    #define wc_GmacVerify               wc_GmacVerify_fips
    #define wc_GmacSetKey               wc_GmacSetKey_fips
    #define wc_GmacUpdate               wc_GmacUpdate_fips

    #ifdef HAVE_AES_KEYWRAP
        #define wc_AesKeyWrap           wc_AesKeyWrap_fips
        #define wc_AesKeyWrap_ex        wc_AesKeyWrap_ex_fips
        #define wc_AesKeyUnWrap         wc_AesKeyUnWrap_fips
        #define wc_AesKeyUnWrap_ex      wc_AesKeyUnWrap_ex_fips
    #endif /* HAVE_AES_KEYWRAP */

    #ifdef WOLFSSL_AES_XTS
        #define wc_AesXtsInit           wc_AesXtsInit_fips
        #define wc_AesXtsSetKeyNoInit   wc_AesXtsSetKeyNoInit_fips
        #define wc_AesXtsSetKey         wc_AesXtsSetKey_fips
        #define wc_AesXtsEncryptSector  wc_AesXtsEncryptSector_fips
        #define wc_AesXtsDecryptSector  wc_AesXtsDecryptSector_fips
        #define wc_AesXtsEncrypt        wc_AesXtsEncrypt_fips
        #define wc_AesXtsDecrypt        wc_AesXtsDecrypt_fips
        #define wc_AesXtsEncryptConsecutiveSectors \
                                        wc_AesXtsEncryptConsecutiveSectors_fips
        #define wc_AesXtsDecryptConsecutiveSectors \
                                        wc_AesXtsDecryptConsecutiveSectors_fips
        #ifdef WOLFSSL_AESXTS_STREAM
            #define wc_AesXtsEncryptInit    wc_AesXtsEncryptInit_fips
            #define wc_AesXtsDecryptInit    wc_AesXtsDecryptInit_fips
            #define wc_AesXtsEncryptUpdate  wc_AesXtsEncryptUpdate_fips
            #define wc_AesXtsDecryptUpdate  wc_AesXtsDecryptUpdate_fips
            #define wc_AesXtsEncryptFinal   wc_AesXtsEncryptFinal_fips
            #define wc_AesXtsDecryptFinal   wc_AesXtsDecryptFinal_fips
        #endif /* WOLFSSL_AESXTS_STREAM */

        #define wc_AesXtsFree           wc_AesXtsFree_fips
    #endif

    #ifdef WOLFSSL_AESGCM_STREAM
        #define wc_AesGcmInit           wc_AesGcmInit_fips
        #define wc_AesGcmEncryptInit    wc_AesGcmEncryptInit_fips
        #define wc_AesGcmEncryptInit_ex wc_AesGcmEncryptInit_ex_fips
        #define wc_AesGcmEncryptUpdate  wc_AesGcmEncryptUpdate_fips
        #define wc_AesGcmEncryptFinal   wc_AesGcmEncryptFinal_fips
        #define wc_AesGcmDecryptInit    wc_AesGcmDecryptInit_fips
        #define wc_AesGcmDecryptUpdate  wc_AesGcmDecryptUpdate_fips
        #define wc_AesGcmDecryptFinal   wc_AesGcmDecryptFinal_fips
    #endif

    #define wc_AesGetKeySize            wc_AesGetKeySize_fips
    #define wc_AesInit                  wc_AesInit_fips
    #define wc_AesFree                  wc_AesFree_fips

    #ifdef WOLF_PRIVATE_KEY_ID
        #define wc_AesInit_Id               wc_AesInit_Id_fips
        #define wc_AesInit_Label            wc_AesInit_Label_fips
    #endif

#endif /* NO_FIPS_WRAPPERS */
#endif /* NO_AES */


/* RSA API */
#ifndef NO_RSA

#ifdef FIPS_NO_WRAPPERS
    #ifndef WC_RSAKEY_TYPE_DEFINED
        typedef struct RsaKey RsaKey;
        #define WC_RSAKEY_TYPE_DEFINED
    #endif

    WOLFSSL_API int wc_InitRsaKey_fips(RsaKey* key, void* p);
    WOLFSSL_API int wc_InitRsaKeyEx_fips(RsaKey* key, void* p, int devId);
    WOLFSSL_API int wc_FreeRsaKey_fips(RsaKey* key);
    WOLFSSL_API int wc_CheckRsaKey_fips(RsaKey* key);
    WOLFSSL_API int wc_RsaPublicEncrypt_fips(const byte* in, word32 inLen,
                                             byte* out, word32 outLen,
                                             RsaKey* key, WC_RNG* rng);
    WOLFSSL_API int wc_RsaPublicEncryptEx_fips(const byte* in, word32 inLen,
                                               byte* out, word32 outLen,
                                               RsaKey* key, WC_RNG* rng,
                                               int type, enum wc_HashType hash,
                            int mgf, byte* label, word32 labelSz);
    WOLFSSL_API int wc_RsaPrivateDecryptInline_fips(byte* in, word32 inLen,
                                                    byte** out, RsaKey* key);
    WOLFSSL_API int wc_RsaPrivateDecryptInlineEx_fips(
        byte* in, word32 inLen, byte** out, RsaKey* key, int type,
        enum wc_HashType hash, int mgf, byte* label, word32 labelSz);
    WOLFSSL_API int wc_RsaPrivateDecrypt_fips(
        const byte* in, word32 inLen, byte* out, word32 outLen, RsaKey* key);
    WOLFSSL_API int wc_RsaPrivateDecryptEx_fips(
        const byte* in, word32 inLen, byte* out, word32 outLen, RsaKey* key,
        int type, enum wc_HashType hash, int mgf, byte* label, word32 labelSz);
    WOLFSSL_API int wc_RsaSSL_Sign_fips(
        const byte* in, word32 inLen, byte* out, word32 outLen, RsaKey* key,
        WC_RNG* rng);
    WOLFSSL_API int wc_RsaSSL_VerifyInline_fips(
        byte* in, word32 inLen, byte** out, RsaKey* key);
    WOLFSSL_API int wc_RsaSSL_Verify_fips(
        const byte* in, word32 inLen, byte* out, word32 outLen, RsaKey* key);
    WOLFSSL_API int wc_RsaPSS_Sign_fips(
        const byte* in, word32 inLen, byte* out, word32 outLen,
        enum wc_HashType hash, int mgf, RsaKey* key, WC_RNG* rng);
    WOLFSSL_API int wc_RsaPSS_SignEx_fips(
        const byte* in, word32 inLen, byte* out, word32 outLen,
        enum wc_HashType hash, int mgf, int saltLen, RsaKey* key, WC_RNG* rng);
    WOLFSSL_API int wc_RsaPSS_VerifyInline_fips(
        byte* in, word32 inLen, byte** out, enum wc_HashType hash, int mgf,
        RsaKey* key);
    WOLFSSL_API int wc_RsaPSS_VerifyInlineEx_fips(
        byte* in, word32 inLen, byte** out, enum wc_HashType hash, int mgf,
        int saltLen, RsaKey* key);
    WOLFSSL_API int wc_RsaPSS_Verify_fips(
        byte* in, word32 inLen, byte* out, word32 outLen, enum wc_HashType hash,
        int mgf, RsaKey* key);
    WOLFSSL_API int wc_RsaPSS_VerifyEx_fips(
        byte* in, word32 inLen, byte* out, word32 outLen, enum wc_HashType hash,
        int mgf, int saltLen, RsaKey* key);
    WOLFSSL_API int wc_RsaPSS_CheckPadding_fips(
        const byte* in, word32 inSz, byte* sig, word32 sigSz,
        enum wc_HashType hashType);
    WOLFSSL_API int wc_RsaPSS_CheckPaddingEx_fips(
        const byte* in, word32 inSz, byte* sig, word32 sigSz,
        enum wc_HashType hashType, int saltLen, int bits);
    WOLFSSL_API int wc_RsaEncryptSize_fips(RsaKey* key);
    WOLFSSL_API int wc_RsaExportKey_fips(
        RsaKey* key, byte* e, word32* eSz, byte* n, word32* nSz, byte* d,
        word32* dSz, byte* p, word32* pSz, byte* q, word32* qSz);
    #if defined(WC_RSA_DIRECT) || defined(WC_RSA_NO_PADDING)
        WOLFSSL_API int wc_RsaDirect_fips(byte* in, word32 inLen, byte* out,
                            word32* outSz, RsaKey* key, int type, WC_RNG* rng);
    #endif
#if 0
    WOLFSSL_API int wc_CheckProbablePrime_fips(
        const byte* p, word32 pSz, const byte* q, word32 qSz, const byte* e,
        word32 eSz, int nlen, int* isPrime);
#endif
    WOLFSSL_API int wc_MakeRsaKey_fips(RsaKey* key, int size, long e,
                            WC_RNG* rng);
    WOLFSSL_API int  wc_RsaFlattenPublicKey_fips(RsaKey* key, byte* e,
                            word32* eSz, byte* n, word32* nSz);
    WOLFSSL_API int  wc_RsaPSS_VerifyCheckInline_fips(byte* in, word32 inLen,
                            byte** out, const byte* digest, word32 digentLen,
                            enum wc_HashType hash, int mgf, RsaKey* key);
    WOLFSSL_API int  wc_RsaPSS_VerifyCheck_fips(byte* in, word32 inLen,
                            byte* out, word32 outLen, const byte* digest,
                            word32 digestLen, enum wc_HashType hash, int mgf,
                            RsaKey* key);
    WOLFSSL_API int  wc_RsaSSL_Verify_ex_fips(const byte* in, word32 inLen,
                            byte* out, word32 outLen, RsaKey* key,
                            int pad_type);
    WOLFSSL_API int  wc_RsaSSL_Verify_ex2_fips(const byte* in, word32 inLen,
                            byte* out, word32 outLen, RsaKey* key, int pad_type,
                            enum wc_HashType hash);

#else /* FIPS_NO_WRAPPERS */
    /* if not impl or fips.c impl wrapper force fips calls if fips build */
    #define wc_InitRsaKey               wc_InitRsaKey_fips
    #define wc_InitRsaKey_ex            wc_InitRsaKeyEx_fips
    #define wc_FreeRsaKey               wc_FreeRsaKey_fips
    #define wc_CheckRsaKey              wc_CheckRsaKey_fips
    #define wc_RsaPublicEncrypt         wc_RsaPublicEncrypt_fips
    #define wc_RsaPublicEncrypt_ex      wc_RsaPublicEncryptEx_fips
    #define wc_RsaPrivateDecryptInline  wc_RsaPrivateDecryptInline_fips
    #define wc_RsaPrivateDecryptInline_ex wc_RsaPrivateDecryptInlineEx_fips
    #define wc_RsaPrivateDecrypt        wc_RsaPrivateDecrypt_fips
    #define wc_RsaPrivateDecrypt_ex     wc_RsaPrivateDecryptEx_fips
    #define wc_RsaSSL_Sign              wc_RsaSSL_Sign_fips
    #define wc_RsaSSL_VerifyInline      wc_RsaSSL_VerifyInline_fips
    #define wc_RsaSSL_Verify            wc_RsaSSL_Verify_fips
    #define wc_RsaPSS_Sign              wc_RsaPSS_Sign_fips
    #define wc_RsaPSS_Sign_ex           wc_RsaPSS_SignEx_fips
    #define wc_RsaPSS_VerifyInline      wc_RsaPSS_VerifyInline_fips
    #define wc_RsaPSS_VerifyInline_ex   wc_RsaPSS_VerifyInlineEx_fips
    #define wc_RsaPSS_Verify            wc_RsaPSS_Verify_fips
    #define wc_RsaPSS_Verify_ex         wc_RsaPSS_VerifyEx_fips
    #define wc_RsaPSS_CheckPadding      wc_RsaPSS_CheckPadding_fips
    #define wc_RsaPSS_CheckPadding_ex   wc_RsaPSS_CheckPaddingEx_fips
    #define wc_RsaEncryptSize           wc_RsaEncryptSize_fips
    #define wc_RsaExportKey             wc_RsaExportKey_fips
    #if defined(WC_RSA_DIRECT) || defined(WC_RSA_NO_PADDING)
        #define wc_RsaDirect            wc_RsaDirect_fips
    #endif
    #define wc_MakeRsaKey               wc_MakeRsaKey_fips
    #define wc_RsaFlattenPublicKey      wc_RsaFlattenPublicKey_fips
    #define wc_RsaPSS_VerifyCheckInline wc_RsaPSS_VerifyCheckInline_fips
    #define wc_RsaPSS_VerifyCheck       wc_RsaPSS_VerifyCheck_fips
    #define wc_RsaSSL_Verify_ex         wc_RsaSSL_Verify_ex_fips
    #define wc_RsaSSL_Verify_ex2        wc_RsaSSL_Verify_ex2_fips
#endif /* FIPS_NO_WRAPPERS */

#endif /* NO_RSA */


/* ECC API */
#ifdef HAVE_ECC

#ifdef FIPS_NO_WRAPPERS
    #ifndef WC_ECCKEY_TYPE_DEFINED
        typedef struct ecc_key ecc_key;
        #define WC_ECCKEY_TYPE_DEFINED
    #endif
    #ifndef WC_ECCPOINT_TYPE_DEFINED
        typedef struct ecc_point ecc_point;
        #define WC_ECCPOINT_TYPE_DEFINED
    #endif
    #ifndef WC_ECCSET_TYPE_DEFINED
        typedef struct ecc_set_type ecc_set_type;
        #define WC_ECCSET_TYPE_DEFINED
    #endif

    WOLFSSL_API int wc_ecc_init_fips(ecc_key* key);
    WOLFSSL_API int wc_ecc_free_fips(ecc_key* key);
    WOLFSSL_API int wc_ecc_set_rng_fips(ecc_key* key, WC_RNG* rng);
    WOLFSSL_API int wc_ecc_check_key_fips(ecc_key* key);
    WOLFSSL_API int wc_ecc_make_key_fips(WC_RNG* rng, int keysize,
                            ecc_key* key);
    WOLFSSL_API int wc_ecc_make_key_ex_fips(WC_RNG* rng, int keysize,
                            ecc_key* key, int curve_id);
    WOLFSSL_API int wc_ecc_export_x963_fips(ecc_key* key, byte* out,
                            word32* outLen);
    WOLFSSL_API int wc_ecc_import_x963_fips(const byte* in, word32 inLen,
                            ecc_key* key);
    WOLFSSL_API int wc_ecc_shared_secret_fips( ecc_key* private_key,
                            ecc_key* public_key, byte* out, word32* outlen);
    WOLFSSL_API int wc_ecc_sign_hash_fips(const byte* in, word32 inlen,
                            byte* out, word32* outlen, WC_RNG* rng,
                            ecc_key* key);
    WOLFSSL_API int wc_ecc_sign_hash_ex_fips(const byte* in, word32 inlen,
                            WC_RNG* rng, ecc_key* key, MP_INT_T* r,
                            MP_INT_T* s);
    WOLFSSL_API int wc_ecc_verify_hash_fips(const byte* sig, word32 siglen,
        const byte* hash, word32 hashlen, int* res, ecc_key* key);
    WOLFSSL_API int wc_ecc_verify_hash_ex_fips(MP_INT_T* r, MP_INT_T* s,
                            const byte* hash, word32 hashlen, int* res,
                            ecc_key* key);
    WOLFSSL_API int wc_ecc_export_ex_fips(ecc_key* key, byte* qx, word32* qxLen,
                            byte* qy, word32* qyLen, byte* d, word32* dLen,
                            int encType);
    WOLFSSL_API int wc_ecc_export_private_only_fips(ecc_key* key, byte* out,
                            word32* outLen);
    WOLFSSL_API int wc_ecc_export_public_raw_fips(ecc_key* key, byte* qx,
                            word32* qxLen, byte* qy, word32* qyLen);
    WOLFSSL_API int wc_ecc_export_private_raw_fips(ecc_key* key, byte* qx,
                            word32* qxLen, byte* qy, word32* qyLen, byte* d,
                            word32* dLen);
    WOLFSSL_API int wc_ecc_export_point_der_ex_fips(const int curve_idx,
                            ecc_point* point, byte* out, word32* outLen,
                            int compressed);
    WOLFSSL_API int wc_ecc_export_point_der_fips(const int curve_idx,
                            ecc_point* point, byte* out, word32* outLen);
    WOLFSSL_API int wc_ecc_export_x963_ex_fips(ecc_key* key, byte* out,
                            word32* outLen, int compressed);
    WOLFSSL_API void wc_ecc_forcezero_point_fips(ecc_point* p);
    WOLFSSL_API ecc_point* wc_ecc_new_point_fips(void);
    WOLFSSL_API ecc_point* wc_ecc_new_point_h_fips(void* h);
    WOLFSSL_API void wc_ecc_del_point_fips(ecc_point* p);
    WOLFSSL_API void wc_ecc_del_point_h_fips(ecc_point* p, void* h);

    WOLFSSL_API int wc_ecc_import_x963_ex_fips(const byte* in, word32 inLen,
                            ecc_key* key, int curve_id);
    WOLFSSL_API int wc_ecc_import_private_key_fips(const byte* priv,
                            word32 privSz, const byte* pub, word32 pubSz,
                            ecc_key* key);
    WOLFSSL_API int wc_ecc_import_private_key_ex_fips(const byte* priv,
                            word32 privSz, const byte* pub, word32 pubSz,
                            ecc_key* key, int curve_id);
    WOLFSSL_API int wc_ecc_import_raw_fips(ecc_key* key, const char* qx,
                            const char* qy, const char* d,
                            const char* curveName);
    WOLFSSL_API int wc_ecc_import_raw_ex_fips(ecc_key* key, const char* qx,
                            const char* qy, const char* d, int curve_id);
    WOLFSSL_API int wc_ecc_import_unsigned_fips(ecc_key* key, const byte* qx,
                            const byte* qy, const byte* d, int curve_id);
    WOLFSSL_API int wc_ecc_import_point_der_ex_fips(const byte* in,
                            word32 inLen, const int curve_idx, ecc_point* point,
                            int shortKeySize);
    WOLFSSL_API int wc_ecc_import_point_der_fips(const byte* in, word32 inLen,
                            const int curve_idx, ecc_point* point);
    WOLFSSL_API int wc_ecc_rs_to_sig_fips(const char* r, const char* s,
                            byte* out, word32* outlen);
    WOLFSSL_API int wc_ecc_rs_raw_to_sig_fips(const byte* r, word32 rSz,
                            const byte* s, word32 sSz, byte* out,
                            word32* outlen);
    WOLFSSL_API int wc_ecc_sig_to_rs_fips(const byte* sig, word32 sigLen,
                            byte* r, word32* rLen, byte* s, word32* sLen);

    WOLFSSL_API int wc_ecc_init_ex_fips(ecc_key* key, void* heap, int devId);
#if 0
    WOLFSSL_API int wc_ecc_is_point_fips(ecc_point* ecp, mp_int* a, mp_int* b,
                            mp_int* prime);
#endif
    WOLFSSL_API ecc_key* wc_ecc_key_new_fips(void* heap);
    WOLFSSL_API void wc_ecc_key_free_fips(ecc_key* key);
    WOLFSSL_API int wc_ecc_make_key_ex2_fips(WC_RNG* rng, int keysize,
                            ecc_key* key, int curve_id, int flags);
    WOLFSSL_API int wc_ecc_make_pub_fips(ecc_key* key, ecc_point* pubOut);
    WOLFSSL_API int wc_ecc_make_pub_ex_fips(ecc_key* key, ecc_point* pubOut,
                            WC_RNG* rng);
    WOLFSSL_API int wc_ecc_shared_secret_ex_fips(ecc_key* private_key,
                            ecc_point* point, byte* out, word32 *outlen);
#if defined(WOLFSSL_ECDSA_SET_K) || defined(WOLFSSL_ECDSA_SET_K_ONE_LOOP)
    WOLFSSL_API int wc_ecc_sign_set_k_fips(const byte* k, word32 klen,
                            ecc_key* key);
#endif
#else /* FIPS_NO_WRAPPERS */
    /* if not impl or fips.c impl wrapper force fips calls if fips build */
    #define wc_ecc_init                 wc_ecc_init_fips
    #define wc_ecc_free                 wc_ecc_free_fips
    #define wc_ecc_set_rng              wc_ecc_set_rng_fips
    #define wc_ecc_check_key            wc_ecc_check_key_fips
    #define wc_ecc_make_key             wc_ecc_make_key_fips
    #define wc_ecc_make_key_ex          wc_ecc_make_key_ex_fips
    #define wc_ecc_export_x963          wc_ecc_export_x963_fips
    #define wc_ecc_import_x963          wc_ecc_import_x963_fips
    #define wc_ecc_shared_secret        wc_ecc_shared_secret_fips
    #define wc_ecc_sign_hash            wc_ecc_sign_hash_fips
    #define wc_ecc_sign_hash_ex         wc_ecc_sign_hash_ex_fips
    #define wc_ecc_verify_hash          wc_ecc_verify_hash_fips
    #define wc_ecc_verify_hash_ex       wc_ecc_verify_hash_ex_fips

    #define wc_ecc_export_ex            wc_ecc_export_ex_fips
    #define wc_ecc_export_private_only  wc_ecc_export_private_only_fips
    #define wc_ecc_export_public_raw    wc_ecc_export_public_raw_fips
    #define wc_ecc_export_private_raw   wc_ecc_export_private_raw_fips
    #define wc_ecc_export_point_der_ex  wc_ecc_export_point_der_ex_fips
    #define wc_ecc_export_point_der     wc_ecc_export_point_der_fips
    #define wc_ecc_export_x963_ex       wc_ecc_export_x963_ex_fips

    #define wc_ecc_forcezero_point      wc_ecc_forcezero_point_fips
    #define wc_ecc_new_point            wc_ecc_new_point_fips
    #define wc_ecc_new_point_h          wc_ecc_new_point_h_fips
    #define wc_ecc_del_point            wc_ecc_del_point_fips
    #define wc_ecc_del_point_h          wc_ecc_del_point_h_fips
    #define wc_ecc_import_x963_ex       wc_ecc_import_x963_ex_fips
    #define wc_ecc_import_private_key   wc_ecc_import_private_key_fips
    #define wc_ecc_import_private_key_ex wc_ecc_import_private_key_ex_fips
    #define wc_ecc_import_raw           wc_ecc_import_raw_fips
    #define wc_ecc_import_raw_ex        wc_ecc_import_raw_ex_fips
    #define wc_ecc_import_unsigned      wc_ecc_import_unsigned_fips
    #define wc_ecc_import_point_der_ex  wc_ecc_import_point_der_ex_fips
    #define wc_ecc_import_point_der     wc_ecc_import_point_der_fips
    #define wc_ecc_rs_to_sig            wc_ecc_rs_to_sig_fips
    #define wc_ecc_rs_raw_to_sig        wc_ecc_rs_raw_to_sig_fips
    #define wc_ecc_sig_to_rs            wc_ecc_sig_to_rs_fips
    #define wc_ecc_init_ex              wc_ecc_init_ex_fips
    #define wc_ecc_key_new              wc_ecc_key_new_fips
    #define wc_ecc_key_free             wc_ecc_key_free_fips
    #define wc_ecc_make_key_ex2         wc_ecc_make_key_ex2_fips
    #define wc_ecc_make_pub             wc_ecc_make_pub_fips
    #define wc_ecc_make_pub_ex          wc_ecc_make_pub_ex_fips
    #define wc_ecc_shared_secret_ex     wc_ecc_shared_secret_ex_fips
#if defined(WOLFSSL_ECDSA_SET_K) || defined(WOLFSSL_ECDSA_SET_K_ONE_LOOP)
    #define wc_ecc_sign_set_k           wc_ecc_sign_set_k_fips
#endif
#endif /* FIPS_NO_WRAPPERS */

#endif /* HAVE_ECC */


/* DH API */
#ifndef NO_DH

#ifdef FIPS_NO_WRAPPERS
    #ifndef WC_DH_TYPE_DEFINED
        typedef struct DhKey DhKey;
        #define WC_DH_TYPE_DEFINED
    #endif

    WOLFSSL_API int wc_InitDhKey_fips(DhKey* key);
    WOLFSSL_API int wc_InitDhKey_ex_fips(DhKey* key, void* heap, int devId);
    WOLFSSL_API int wc_FreeDhKey_fips(DhKey* key);
    WOLFSSL_API int wc_DhSetKeyEx_fips(DhKey* key, const byte* p, word32 pSz,
                                           const byte* g, word32 gSz,
                                           const byte* q, word32 qSz);
    WOLFSSL_API int wc_DhSetKey_fips(DhKey* key, const byte* p, word32 pSz,
                                const byte* g, word32 gSz);
    WOLFSSL_API int wc_DhGenerateParams_fips(WC_RNG *rng, int modSz, DhKey *dh);
    WOLFSSL_API int wc_DhExportParamsRaw_fips(DhKey* dh, byte* p, word32* pSz,
                                byte* q, word32* qSz, byte* g, word32* gSz);
    WOLFSSL_API int wc_DhCmpNamedKey_fips(int name, int noQ, const byte* p,
                                word32 pSz, const byte* g, word32 gSz,
                                const byte* q, word32 qSz);
    WOLFSSL_API int wc_DhGetNamedKeyParamSize_fips(int name,
                                word32* p, word32* g, word32* q);
    WOLFSSL_API word32 wc_DhGetNamedKeyMinSize_fips(int name);
    WOLFSSL_API int wc_DhSetCheckKey_fips(DhKey* key, const byte* p, word32 pSz,
                                const byte* g, word32 gSz, const byte* q,
                                word32 qSz, int trusted, WC_RNG* rng);
    WOLFSSL_API int wc_DhSetNamedKey_fips(DhKey* key, int name);
    WOLFSSL_API int wc_DhGenerateKeyPair_fips(DhKey* key, WC_RNG* rng,
                                           byte* priv, word32* privSz,
                                           byte* pub, word32* pubSz);
    WOLFSSL_API int wc_DhCheckPubKey_fips(DhKey* key, const byte* pub,
                                           word32 pubSz);
    WOLFSSL_API int wc_DhCheckPubKeyEx_fips(DhKey* key, const byte* pub,
                                           word32 pubSz, const byte* prime,
                                           word32 primeSz);
    WOLFSSL_API int wc_DhCheckPubValue_fips(const byte* prime, word32 primeSz,
                                           const byte* pub, word32 pubSz);
    WOLFSSL_API int wc_DhCheckPrivKey_fips(DhKey* key, const byte* priv,
                                           word32 pubSz);
    WOLFSSL_API int wc_DhCheckPrivKeyEx_fips(DhKey* key, const byte* priv,
                                           word32 pubSz, const byte* prime,
                                           word32 primeSz);
    WOLFSSL_API int wc_DhCheckKeyPair_fips(DhKey* key, const byte* pub,
                                           word32 pubSz, const byte* priv,
                                           word32 privSz);
    WOLFSSL_API int wc_DhAgree_fips(DhKey* key, byte* agree, word32* agreeSz,
                                            const byte* priv, word32 privSz,
                                            const byte* otherPub, word32 pubSz);

#else /* FIPS_NO_WRAPPERS */
    /* if not impl or fips.c impl wrapper force fips calls if fips build */
    #define wc_InitDhKey                wc_InitDhKey_fips
    #define wc_InitDhKey_ex             wc_InitDhKey_ex_fips
    #define wc_FreeDhKey                wc_FreeDhKey_fips
    #define wc_DhSetKey_ex              wc_DhSetKeyEx_fips
    #define wc_DhSetKey                 wc_DhSetKey_fips
    #define wc_DhGenerateParams         wc_DhGenerateParams_fips
    #define wc_DhExportParamsRaw        wc_DhExportParamsRaw_fips
    #define wc_DhCmpNamedKey            wc_DhCmpNamedKey_fips
    #define wc_DhGetNamedKeyParamSize   wc_DhGetNamedKeyParamSize_fips
    #define wc_DhGetNamedKeyMinSize     wc_DhGetNamedKeyMinSize_fips
    #define wc_DhSetCheckKey            wc_DhSetCheckKey_fips
    #define wc_DhSetNamedKey            wc_DhSetNamedKey_fips
    #define wc_DhGenerateKeyPair        wc_DhGenerateKeyPair_fips
    #define wc_DhCheckPubKey            wc_DhCheckPubKey_fips
    #define wc_DhCheckPubKey_ex         wc_DhCheckPubKeyEx_fips
    #define wc_DhCheckPubValue          wc_DhCheckPubValue_fips
    #define wc_DhCheckPrivKey           wc_DhCheckPrivKey_fips
    #define wc_DhCheckPrivKey_ex        wc_DhCheckPrivKeyEx_fips
    #define wc_DhCheckKeyPair           wc_DhCheckKeyPair_fips
    #define wc_DhAgree                  wc_DhAgree_fips
#endif /* FIPS_NO_WRAPPERS */

#endif /* NO_DH */


/* SHA-1 API */
#ifndef NO_SHA

#ifdef FIPS_NO_WRAPPERS
    #ifndef WC_SHA_TYPE_DEFINED
        typedef struct wc_Sha wc_Sha;
        #define WC_SHA_TYPE_DEFINED
    #endif

    WOLFSSL_API int wc_InitSha_fips(wc_Sha* sha);
    WOLFSSL_API int wc_InitSha_ex_fips(wc_Sha* sha, void* heap, int devId);
    WOLFSSL_API int wc_ShaUpdate_fips(wc_Sha* sha, const byte* data,
                                      word32 len);
    WOLFSSL_API int wc_ShaFinalRaw_fips(wc_Sha* sha, byte* hash);
    WOLFSSL_API int wc_ShaFinal_fips(wc_Sha* sha, byte* hash);
    WOLFSSL_API void wc_ShaFree_fips(wc_Sha* sha);

#else /* FIPS_NO_WRAPPERS */
    /* if not impl or fips.c impl wrapper force fips calls if fips build */
    #define wc_InitSha                  wc_InitSha_fips
    #define wc_InitSha_ex               wc_InitSha_ex_fips
    #define wc_ShaUpdate                wc_ShaUpdate_fips
    #define wc_ShaFinalRaw              wc_ShaFinalRaw_fips
    #define wc_ShaFinal                 wc_ShaFinal_fips
    #define wc_ShaFree                  wc_ShaFree_fips
#endif /* FIPS_NO_WRAPPERS */

#endif /* NO_SHA */


/* SHA-224 and SHA-256 API */
#ifndef NO_SHA256

#ifdef FIPS_NO_WRAPPERS
    #ifndef WC_SHA256_TYPE_DEFINED
        typedef struct wc_Sha256 wc_Sha256;
        #define WC_SHA256_TYPE_DEFINED
    #endif

    WOLFSSL_API int wc_InitSha256_fips(wc_Sha256* sha);
    WOLFSSL_API int wc_InitSha256_ex_fips(wc_Sha256* sha, void* heap,
                            int devId);
    WOLFSSL_API int wc_Sha256Update_fips(wc_Sha256* sha, const byte* data,
                                         word32 len);
    WOLFSSL_API int wc_Sha256FinalRaw_fips(wc_Sha256* sha256, byte* hash);
    WOLFSSL_API int wc_Sha256Final_fips(wc_Sha256* sha, byte* hash);
    WOLFSSL_API void wc_Sha256Free_fips(wc_Sha256* sha);

    #ifdef WOLFSSL_SHA224
        #ifndef WC_SHA224_TYPE_DEFINED
            typedef struct wc_Sha256 wc_Sha224;
            #define WC_SHA224_TYPE_DEFINED
        #endif

        WOLFSSL_API int wc_InitSha224_fips(wc_Sha224* sha224);
        WOLFSSL_API int wc_InitSha224_ex_fips(wc_Sha224* sha224, void* heap,
                            int devId);
        WOLFSSL_API int wc_Sha224Update_fips(wc_Sha224* sha224,
                                             const byte* data, word32 len);
        WOLFSSL_API int wc_Sha224Final_fips(wc_Sha224* sha224, byte* hash);
        WOLFSSL_API void wc_Sha224Free_fips(wc_Sha224* sha);
    #endif /* WOLFSSL_SHA224 */

#else /* FIPS_NO_WRAPPERS */
    /* if not impl or fips.c impl wrapper force fips calls if fips build */
    #define wc_InitSha256               wc_InitSha256_fips
    #define wc_InitSha256_ex            wc_InitSha256_ex_fips
    #define wc_Sha256Update             wc_Sha256Update_fips
    #define wc_Sha256FinalRaw           wc_Sha256FinalRaw_fips
    #define wc_Sha256Final              wc_Sha256Final_fips
    #define wc_Sha256Free               wc_Sha256Free_fips
    #ifdef WOLFSSL_SHA224
        #define wc_InitSha224           wc_InitSha224_fips
        #define wc_InitSha224_ex        wc_InitSha224_ex_fips
        #define wc_Sha224Update         wc_Sha224Update_fips
        #define wc_Sha224Final          wc_Sha224Final_fips
        #define wc_Sha224Free           wc_Sha224Free_fips
    #endif /* WOLFSSL_SHA224 */
#endif /* FIPS_NO_WRAPPERS */

#endif /* NO_SHA256 */


/* SHA-384 and SHA-512 API */
#ifndef NO_SHA512

#ifdef FIPS_NO_WRAPPERS
    #ifndef WC_SHA512_TYPE_DEFINED
        typedef struct wc_Sha512 wc_Sha512;
        #define WC_SHA512_TYPE_DEFINED
    #endif

    WOLFSSL_API int wc_InitSha512_fips(wc_Sha512* sha);
    WOLFSSL_API int wc_InitSha512_ex_fips(wc_Sha512* sha, void* heap,
                            int devId);
    WOLFSSL_API int wc_Sha512Update_fips(wc_Sha512* sha, const byte* data,
                                         word32 len);
    WOLFSSL_API int wc_Sha512FinalRaw_fips(wc_Sha512* sha512, byte* hash);
    WOLFSSL_API int wc_Sha512Final_fips(wc_Sha512* sha, byte* hash);
    WOLFSSL_API void wc_Sha512Free_fips(wc_Sha512* sha);

    #ifdef WOLFSSL_SHA384
        #ifndef WC_SHA384_TYPE_DEFINED
            typedef struct wc_Sha512 wc_Sha384;
            #define WC_SHA384_TYPE_DEFINED
        #endif
        WOLFSSL_API int wc_InitSha384_fips(wc_Sha384* sha);
        WOLFSSL_API int wc_InitSha384_ex_fips(wc_Sha384* sha, void* heap,
                            int devId);
        WOLFSSL_API int wc_Sha384Update_fips(wc_Sha384* sha, const byte* data,
                                             word32 len);
        WOLFSSL_API int wc_Sha384Final_fips(wc_Sha384* sha, byte* hash);
        WOLFSSL_API int wc_Sha384FinalRaw_fips(wc_Sha384* sha384, byte* hash);
        WOLFSSL_API void wc_Sha384Free_fips(wc_Sha384* sha);
    #endif /* WOLFSSL_SHA384 */

#else /* FIPS_NO_WRAPPERS */
    /* if not impl or fips.c impl wrapper force fips calls if fips build */
    #define wc_InitSha512               wc_InitSha512_fips
    #define wc_InitSha512_ex            wc_InitSha512_ex_fips
    #define wc_Sha512Update             wc_Sha512Update_fips
    #define wc_Sha512FinalRaw           wc_Sha512FinalRaw_fips
    #define wc_Sha512Final              wc_Sha512Final_fips
    #define wc_Sha512Free               wc_Sha512Free_fips
    #ifdef WOLFSSL_SHA384
        #define wc_InitSha384           wc_InitSha384_fips
        #define wc_InitSha384_ex        wc_InitSha384_ex_fips
        #define wc_Sha384Update         wc_Sha384Update_fips
        #define wc_Sha384FinalRaw       wc_Sha384FinalRaw_fips
        #define wc_Sha384Final          wc_Sha384Final_fips
        #define wc_Sha384Free           wc_Sha384Free_fips
    #endif /* WOLFSSL_SHA384 */
#endif /* FIPS_NO_WRAPPERS */

#endif /* NO_SHA512 */


/* SHA-3 API */
#ifdef WOLFSSL_SHA3

#ifdef FIPS_NO_WRAPPERS
    #ifndef WC_SHA3_TYPE_DEFINED
        typedef struct wc_Sha3 wc_Sha3;
        #define WC_SHA3_TYPE_DEFINED
    #endif
    #if defined(WOLFSSL_SHAKE128) || defined(WOLFSSL_SHAKE256)
        #ifndef WC_SHAKE_TYPE_DEFINED
            typedef struct wc_Sha3 wc_Shake;
            #define WC_SHAKE_TYPE_DEFINED
        #endif
    #endif

    WOLFSSL_API int wc_InitSha3_224_fips(wc_Sha3* sha3, void* heap, int devId);
    WOLFSSL_API int wc_Sha3_224_Update_fips(wc_Sha3* sha3, const byte* data,
                                            word32 len);
    WOLFSSL_API int wc_Sha3_224_Final_fips(wc_Sha3* sha3, byte* hash);
    WOLFSSL_API void wc_Sha3_224_Free_fips(wc_Sha3* sha3);

    WOLFSSL_API int wc_InitSha3_256_fips(wc_Sha3* sha3, void* heap, int devId);
    WOLFSSL_API int wc_Sha3_256_Update_fips(wc_Sha3* sha3, const byte* data,
                                            word32 len);
    WOLFSSL_API int wc_Sha3_256_Final_fips(wc_Sha3* sha3, byte* hash);
    WOLFSSL_API void wc_Sha3_256_Free_fips(wc_Sha3* sha3);

    WOLFSSL_API int wc_InitSha3_384_fips(wc_Sha3* sha3, void* heap, int devId);
    WOLFSSL_API int wc_Sha3_384_Update_fips(wc_Sha3* sha3, const byte* data,
                                            word32 len);
    WOLFSSL_API int wc_Sha3_384_Final_fips(wc_Sha3* sha3, byte* hash);
    WOLFSSL_API void wc_Sha3_384_Free_fips(wc_Sha3* sha3);

    WOLFSSL_API int wc_InitSha3_512_fips(wc_Sha3* sha3, void* heap, int devId);
    WOLFSSL_API int wc_Sha3_512_Update_fips(wc_Sha3* sha3, const byte* data,
                                            word32 len);
    WOLFSSL_API int wc_Sha3_512_Final_fips(wc_Sha3* sha3, byte* hash);
    WOLFSSL_API void wc_Sha3_512_Free_fips(wc_Sha3* sha3);

    #ifdef WOLFSSL_SHAKE128
        WOLFSSL_API int wc_InitShake128_fips(wc_Shake* shake, void* heap,
                                                int devId);
        WOLFSSL_API int wc_Shake128_Update_fips(wc_Shake* shake,
                                                const byte* data, word32 len);
        WOLFSSL_API int wc_Shake128_Final_fips(wc_Shake* shake, byte* hash,
                                               word32 hashLen);
        WOLFSSL_API int wc_Shake128_Absorb_fips(wc_Shake* shake,
                                                const byte* data, word32 len);
        WOLFSSL_API int wc_Shake128_SqueezeBlocks_fips(wc_Shake* shake,
                                                byte* out, word32 blockCnt);
        WOLFSSL_API void wc_Shake128_Free_fips(wc_Shake* shake);
    #endif

    #ifdef WOLFSSL_SHAKE256
        WOLFSSL_API int wc_InitShake256_fips(wc_Shake* shake, void* heap,
                                                int devId);
        WOLFSSL_API int wc_Shake256_Update_fips(wc_Shake* shake,
                                                const byte* data, word32 len);
        WOLFSSL_API int wc_Shake256_Final_fips(wc_Shake* shake, byte* hash,
                                                word32 hashLen);
        WOLFSSL_API int wc_Shake256_Absorb_fips(wc_Shake* shake,
                                                const byte* data, word32 len);
        WOLFSSL_API int wc_Shake256_SqueezeBlocks_fips(wc_Shake* shake,
                                                byte* out, word32 blockCnt);
        WOLFSSL_API void wc_Shake256_Free_fips(wc_Shake* shake);
    #endif

#else /* FIPS_NO_WRAPPERS */
    /* if not impl or fips.c impl wrapper force fips calls if fips build */
    #define wc_InitSha3_224             wc_InitSha3_224_fips
    #define wc_Sha3_224_Update          wc_Sha3_224_Update_fips
    #define wc_Sha3_224_Final           wc_Sha3_224_Final_fips
    #define wc_Sha3_224_Free            wc_Sha3_224_Free_fips
    #define wc_InitSha3_256             wc_InitSha3_256_fips
    #define wc_Sha3_256_Update          wc_Sha3_256_Update_fips
    #define wc_Sha3_256_Final           wc_Sha3_256_Final_fips
    #define wc_Sha3_256_Free            wc_Sha3_256_Free_fips
    #define wc_InitSha3_384             wc_InitSha3_384_fips
    #define wc_Sha3_384_Update          wc_Sha3_384_Update_fips
    #define wc_Sha3_384_Final           wc_Sha3_384_Final_fips
    #define wc_Sha3_384_Free            wc_Sha3_384_Free_fips
    #define wc_InitSha3_512             wc_InitSha3_512_fips
    #define wc_Sha3_512_Update          wc_Sha3_512_Update_fips
    #define wc_Sha3_512_Final           wc_Sha3_512_Final_fips
    #define wc_Sha3_512_Free            wc_Sha3_512_Free_fips

    #ifdef WOLFSSL_SHAKE128
        #define wc_InitShake128         wc_InitShake128_fips
        #define wc_Shake128_Update      wc_Shake128_Update_fips
        #define wc_Shake128_Final       wc_Shake128_Final_fips
        #define wc_Shake128_Absorb      wc_Shake128_Absorb_fips
        #define wc_Shake128_SqueezeBlocks wc_Shake128_SqueezeBlocks_fips
        #define wc_Shake128_Free        wc_Shake128_Free_fips
    #endif

    #ifdef WOLFSSL_SHAKE256
        #define wc_InitShake256         wc_InitShake256_fips
        #define wc_Shake256_Update      wc_Shake256_Update_fips
        #define wc_Shake256_Final       wc_Shake256_Final_fips
        #define wc_Shake256_Absorb      wc_Shake256_Absorb_fips
        #define wc_Shake256_SqueezeBlocks wc_Shake256_SqueezeBlocks_fips
        #define wc_Shake256_Free        wc_Shake256_Free_fips
    #endif
#endif /* FIPS_NO_WRAPPERS */

#endif /* WOLFSSL_SHA3 */


/* HMAC API */
#ifndef NO_HMAC

#ifdef FIPS_NO_WRAPPERS
    #ifndef WC_HMAC_TYPE_DEFINED
        typedef struct Hmac Hmac;
        #define WC_HMAC_TYPE_DEFINED
    #endif

    WOLFSSL_API int wc_HmacSetKey_fips(Hmac* hmac, int type, const byte* key,
                            word32 keySz);
    WOLFSSL_API int wc_HmacSetKey_ex_fips(Hmac* hmac, int type, const byte* key,
                            word32 length, int allowFlag);
    WOLFSSL_API int wc_HmacUpdate_fips(Hmac* hmac, const byte* data,
                                       word32 len);
    WOLFSSL_API int wc_HmacFinal_fips(Hmac* hmac, byte* hash);
    WOLFSSL_API void wc_HmacFree_fips(Hmac* hmac);
    WOLFSSL_API int wc_HmacSizeByType_fips(int type);
    WOLFSSL_API int wc_HmacInit_fips(Hmac* hmac, void* heap, int devId);

    #ifdef WOLFSSL_HAVE_PRF
        WOLFSSL_API int wc_PRF_fips(byte* result, word32 resLen,
            const byte* secret, word32 secLen,
            const byte* seed, word32 seedLen,
            int hash_type, void* heap, int devId);
        WOLFSSL_API int wc_PRF_TLSv12_fips(byte* result, word32 resLen,
            const byte* secret, word32 secLen,
            const byte* label, word32 labLen,
            const byte* seed, word32 seedLen,
            int useAtLeastSha256, int hash_type,
            void* heap, int devId);
    #endif /* WOLFSSL_HAVE_PRF */

    #ifdef HAVE_HKDF
        WOLFSSL_API int wc_HKDF_Extract_fips(int type,
                const byte* salt, word32 saltSz,
                const byte* inKey, word32 inKeySz, byte* out);
        WOLFSSL_API int wc_HKDF_Extract_ex_fips(int type, const byte* salt,
                            word32 saltSz, const byte* inKey, word32 inKeySz,
                            byte* out, void* heap, int devId);
        WOLFSSL_API int wc_HKDF_Expand_fips(int type,
                const byte* inKey, word32 inKeySz,
                const byte* info, word32 infoSz,
                byte* out, word32 outSz);
        WOLFSSL_API int wc_HKDF_Expand_ex_fips(int type, const byte* inKey,
                            word32 inKeySz, const byte* info, word32 infoSz,
                            byte* out, word32 outSz, void* heap, int devId);
        WOLFSSL_API int wc_HKDF_fips(int type,
                const byte* inKey, word32 inKeySz,
                const byte* salt, word32 saltSz,
                const byte* info, word32 infoSz,
                byte* out, word32 outSz);
        WOLFSSL_API int wc_Tls13_HKDF_Extract_ex_fips(byte* prk,
                const byte* salt, word32 saltLen, byte* ikm, word32 ikmLen,
                int digest, void* heap, int devId);
        WOLFSSL_API int wc_Tls13_HKDF_Extract_fips(byte* prk,
                const byte* salt, int saltLen,
                byte* ikm, int ikmLen, int digest);
        WOLFSSL_API int wc_Tls13_HKDF_Expand_Label_fips(
                byte* okm, word32 okmLen,
                const byte* prk, word32 prkLen,
                const byte* protocol, word32 protocolLen,
                const byte* label, word32 labelLen,
                const byte* info, word32 infoLen,
                int digest);
        WOLFSSL_API int wc_Tls13_HKDF_Expand_Label_ex_fips(byte* okm,
                word32 okmLen, const byte* prk, word32 prkLen,
                const byte* protocol, word32 protocolLen,
                const byte* label, word32 labelLen,
                const byte* info, word32 infoLen,
                int digest, void* heap, int devId);
    #endif /* HAVE_HKDF */

    #ifdef WOLFSSL_WOLFSSH
        WOLFSSL_API int wc_SSH_KDF_fips(byte hashId, byte keyId,
                byte* key, word32 keySz,
                const byte* k, word32 kSz,
                const byte* h, word32 hSz,
                const byte* sessionId, word32 sessionIdSz);
    #endif /* WOLFSSL_WOLFSSH */

#else /* FIPS_NO_WRAPPERS */
    /* if not impl or fips.c impl wrapper force fips calls if fips build */
    #define wc_HmacSetKey               wc_HmacSetKey_fips
    #define wc_HmacSetKey_ex            wc_HmacSetKey_ex_fips
    #define wc_HmacUpdate               wc_HmacUpdate_fips
    #define wc_HmacFinal                wc_HmacFinal_fips
    #define wc_HmacFree                 wc_HmacFree_fips
    #define wc_HmacSizeByType           wc_HmacSizeByType_fips
    #define wc_HmacInit                 wc_HmacInit_fips
    #ifdef WOLFSSL_HAVE_PRF
        #define wc_PRF                  wc_PRF_fips
        #define wc_PRF_TLS              wc_PRF_TLSv12_fips
    #endif /* WOLFSSL_HAVE_PRF */

    #ifdef HAVE_HKDF
        #define wc_HKDF_Extract             wc_HKDF_Extract_fips
        #define wc_HKDF_Extract_ex          wc_HKDF_Extract_ex_fips
        #define wc_HKDF_Expand              wc_HKDF_Expand_fips
        #define wc_HKDF_Expand_ex           wc_HKDF_Expand_ex_fips
        #define wc_HKDF                     wc_HKDF_fips
        #define wc_Tls13_HKDF_Extract       wc_Tls13_HKDF_Extract_fips
        #define wc_Tls13_HKDF_Extract_ex    wc_Tls13_HKDF_Extract_ex_fips
        #define wc_Tls13_HKDF_Expand_Label  wc_Tls13_HKDF_Expand_Label_fips
        #define wc_Tls13_HKDF_Expand_Label_ex wc_Tls13_HKDF_Expand_Label_ex_fips
    #endif /* HAVE_HKDF */

    #ifdef WOLFSSL_WOLFSSH
        #define wc_SSH_KDF              wc_SSH_KDF_fips
    #endif /* WOLFSSL_WOLFSSH */
#endif /* FIPS_NO_WRAPPERS */

#endif /* NO_HMAC */


/* CMAC API */
#ifdef WOLFSSL_CMAC

#ifdef FIPS_NO_WRAPPERS
    #ifndef WC_CMAC_TYPE_DEFINED
        typedef struct Cmac Cmac;
        #define WC_CMAC_TYPE_DEFINED
    #endif

    WOLFSSL_API int wc_InitCmac_fips(Cmac* cmac, const byte* key, word32 keySz,
                                     int type, void* unused);
    WOLFSSL_API int wc_CmacUpdate_fips(Cmac* cmac, const byte* in, word32 inSz);
    WOLFSSL_API int wc_CmacFinal_fips(Cmac* cmac, byte* out, word32* outSz);

    WOLFSSL_API int wc_InitCmac_ex_fips(Cmac* cmac, const byte* key,
                                word32 keySz, int type, void* unused,
                                void* heap, int devId);
    WOLFSSL_API int wc_CmacFinalNoFree_fips(Cmac* cmac, byte* out,
                                word32* outSz);
    WOLFSSL_API int wc_CmacFree_fips(Cmac* cmac);
    WOLFSSL_API int wc_AesCmacGenerate_fips(byte* out, word32* outSz,
                                const byte* in, word32 inSz, const byte* key,
                                word32 keySz);
    WOLFSSL_API int wc_AesCmacGenerate_ex_fips(Cmac *cmac, byte* out,
                                word32* outSz, const byte* in, word32 inSz,
                                const byte* key, word32 keySz, void* heap,
                                int devId);
    WOLFSSL_API int wc_AesCmacVerify_fips(const byte* check, word32 checkSz,
                                const byte* in, word32 inSz, const byte* key,
                                word32 keySz);
    WOLFSSL_API int wc_AesCmacVerify_ex_fips(Cmac* cmac, const byte* check,
                                word32 checkSz, const byte* in, word32 inSz,
                                const byte* key, word32 keySz, void* heap,
                                int devId);

    #ifdef WOLFSSL_HASH_KEEP
    WOLFSSL_API int wc_CMAC_Grow_fips(Cmac* cmac, const byte* in, int inSz);
    #endif


#else /* FIPS_NO_WRAPPERS */
    /* if not impl or fips.c impl wrapper force fips calls if fips build */
    #define wc_InitCmac                 wc_InitCmac_fips
    #define wc_CmacUpdate               wc_CmacUpdate_fips
    #define wc_CmacFinal                wc_CmacFinal_fips

    #define wc_InitCmac_ex              wc_InitCmac_ex_fips
    #define wc_CmacFinalNoFree          wc_CmacFinalNoFree_fips
    #define wc_CmacFree                 wc_CmacFree_fips
    #define wc_AesCmacGenerate          wc_AesCmacGenerate_fips
    #define wc_AesCmacGenerate_ex       wc_AesCmacGenerate_ex_fips
    #define wc_AesCmacVerify            wc_AesCmacVerify_fips
    #define wc_AesCmacVerify_ex         wc_AesCmacVerify_ex_fips

    #ifdef WOLFSSL_HASH_KEEP
    #define wc_CMAC_Grow                wc_CMAC_Grow_fips
    #endif

#endif /* FIPS_NO_WRAPPERS */

#endif /* WOLFSSL_CMAC */

#ifdef WC_SRTP_KDF
#ifdef FIPS_NO_WRAPPERS
    WOLFSSL_API int wc_SRTP_KDF_fips(const byte* key, word32 keySz, const byte* salt,
        word32 saltSz, int kdrIdx, const byte* index, byte* key1, word32 key1Sz,
        byte* key2, word32 key2Sz, byte* key3, word32 key3Sz);
    WOLFSSL_API int wc_SRTCP_KDF_fips(const byte* key, word32 keySz, const byte* salt,
        word32 saltSz, int kdrIdx, const byte* index, byte* key1, word32 key1Sz,
        byte* key2, word32 key2Sz, byte* key3, word32 key3Sz);
    WOLFSSL_API int wc_SRTCP_KDF_ex_fips(const byte* key, word32 keySz,
                            const byte* salt, word32 saltSz, int kdrIdx,
                            const byte* index, byte* key1, word32 key1Sz,
                            byte* key2, word32 key2Sz, byte* key3,
                            word32 key3Sz, int idxLenIndicator);
    WOLFSSL_API int wc_SRTP_KDF_label_fips(const byte* key, word32 keySz,
        const byte* salt, word32 saltSz, int kdrIdx, const byte* index, byte label,
        byte* outKey, word32 outKeySz);
    WOLFSSL_API int wc_SRTCP_KDF_label_fips(const byte* key, word32 keySz,
        const byte* salt, word32 saltSz, int kdrIdx, const byte* index, byte label,
        byte* outKey, word32 outKeySz);

    WOLFSSL_API int wc_SRTP_KDF_kdr_to_idx_fips(word32 kdr);
#else /* FIPS_NO_WRAPPERS */
    #define wc_SRTP_KDF             wc_SRTP_KDF_fips
    #define wc_SRTCP_KDF            wc_SRTCP_KDF_fips
    #define wc_SRTCP_KDF_ex         wc_SRTCP_KDF_ex_fips
    #define wc_SRTP_KDF_label       wc_SRTP_KDF_label_fips
    #define wc_SRTCP_KDF_label      wc_SRTCP_KDF_label_fips

    #define wc_SRTP_KDF_kdr_to_idx  wc_SRTP_KDF_kdr_to_idx_fips
#endif /* FIPS_NO_WRAPPERS */
#endif /* WC_SRTP_KDF */

#ifdef HAVE_ED25519
#ifdef FIPS_NO_WRAPPERS

    #ifndef WC_ED25519KEY_TYPE_DEFINED
        typedef struct ed25519_key ed25519_key;
        #define WC_ED25519KEY_TYPE_DEFINED
    #endif

    WOLFSSL_API
    int wc_ed25519_make_public_fips(ed25519_key* key, unsigned char* pubKey,
                           word32 pubKeySz);
    WOLFSSL_API
    int wc_ed25519_make_key_fips(WC_RNG* rng, int keysize, ed25519_key* key);
    #ifdef HAVE_ED25519_SIGN
    WOLFSSL_API
    int wc_ed25519_sign_msg_fips(const byte* in, word32 inLen, byte* out,
                            word32 *outLen, ed25519_key* key);
    WOLFSSL_API
    int wc_ed25519ctx_sign_msg_fips(const byte* in, word32 inLen, byte* out,
                               word32 *outLen, ed25519_key* key,
                               const byte* context, byte contextLen);
    WOLFSSL_API
    int wc_ed25519ph_sign_hash_fips(const byte* hash, word32 hashLen, byte* out,
                               word32 *outLen, ed25519_key* key,
                               const byte* context, byte contextLen);
    WOLFSSL_API
    int wc_ed25519ph_sign_msg_fips(const byte* in, word32 inLen, byte* out,
                              word32 *outLen, ed25519_key* key, const byte* context,
                              byte contextLen);
    WOLFSSL_API
    int wc_ed25519_sign_msg_ex_fips(const byte* in, word32 inLen, byte* out,
                                word32 *outLen, ed25519_key* key, byte type,
                                const byte* context, byte contextLen);
    #endif /* HAVE_ED25519_SIGN */
    #ifdef HAVE_ED25519_VERIFY
    WOLFSSL_API
    int wc_ed25519_verify_msg_fips(const byte* sig, word32 sigLen, const byte* msg,
                              word32 msgLen, int* res, ed25519_key* key);
    WOLFSSL_API
    int wc_ed25519ctx_verify_msg_fips(const byte* sig, word32 sigLen, const byte* msg,
                                 word32 msgLen, int* res, ed25519_key* key,
                                 const byte* context, byte contextLen);
    WOLFSSL_API
    int wc_ed25519ph_verify_hash_fips(const byte* sig, word32 sigLen, const byte* hash,
                                 word32 hashLen, int* res, ed25519_key* key,
                                 const byte* context, byte contextLen);
    WOLFSSL_API
    int wc_ed25519ph_verify_msg_fips(const byte* sig, word32 sigLen, const byte* msg,
                                word32 msgLen, int* res, ed25519_key* key,
                                const byte* context, byte contextLen);
    WOLFSSL_API
    int wc_ed25519_verify_msg_ex_fips(const byte* sig, word32 sigLen, const byte* msg,
                                  word32 msgLen, int* res, ed25519_key* key,
                                  byte type, const byte* context, byte contextLen);
    #ifdef WOLFSSL_ED25519_STREAMING_VERIFY
    WOLFSSL_API
    int wc_ed25519_verify_msg_init_fips(const byte* sig, word32 sigLen, ed25519_key* key,
                                   byte type, const byte* context, byte contextLen);
    WOLFSSL_API
    int wc_ed25519_verify_msg_update_fips(const byte* msgSegment, word32 msgSegmentLen,
                                   ed25519_key* key);
    WOLFSSL_API
    int wc_ed25519_verify_msg_final_fips(const byte* sig, word32 sigLen, int* res,
                                    ed25519_key* key);
    #endif /* WOLFSSL_ED25519_STREAMING_VERIFY */
    #endif /* HAVE_ED25519_VERIFY */

    WOLFSSL_API
    int wc_ed25519_init_fips(ed25519_key* key);
    WOLFSSL_API
    int wc_ed25519_init_ex_fips(ed25519_key* key, void* heap, int devId);
    WOLFSSL_API
    void wc_ed25519_free_fips(ed25519_key* key);
    #ifdef HAVE_ED25519_KEY_IMPORT
    WOLFSSL_API
    int wc_ed25519_import_public_fips(const byte* in, word32 inLen, ed25519_key* key);
    WOLFSSL_API
    int wc_ed25519_import_public_ex_fips(const byte* in, word32 inLen, ed25519_key* key,
                                    int trusted);
    WOLFSSL_API
    int wc_ed25519_import_private_only_fips(const byte* priv, word32 privSz,
                                                                  ed25519_key* key);
    WOLFSSL_API
    int wc_ed25519_import_private_key_fips(const byte* priv, word32 privSz,
                                   const byte* pub, word32 pubSz, ed25519_key* key);
    WOLFSSL_API
    int wc_ed25519_import_private_key_ex_fips(const byte* priv, word32 privSz,
        const byte* pub, word32 pubSz, ed25519_key* key, int trusted);
    #endif /* HAVE_ED25519_KEY_IMPORT */

    #ifdef HAVE_ED25519_KEY_EXPORT
    WOLFSSL_API
    int wc_ed25519_export_public_fips(ed25519_key* key, byte* out, word32* outLen);
    WOLFSSL_API
    int wc_ed25519_export_private_only_fips(ed25519_key* key, byte* out, word32* outLen);
    WOLFSSL_API
    int wc_ed25519_export_private_fips(ed25519_key* key, byte* out, word32* outLen);
    WOLFSSL_API
    int wc_ed25519_export_key_fips(ed25519_key* key,
                              byte* priv, word32 *privSz,
                              byte* pub, word32 *pubSz);
    #endif /* HAVE_ED25519_KEY_EXPORT */

    WOLFSSL_API
    int wc_ed25519_check_key_fips(ed25519_key* key);

    /* size helper */
    WOLFSSL_API
    int wc_ed25519_size_fips(ed25519_key* key);
    WOLFSSL_API
    int wc_ed25519_priv_size_fips(ed25519_key* key);
    WOLFSSL_API
    int wc_ed25519_pub_size_fips(ed25519_key* key);
    WOLFSSL_API
    int wc_ed25519_sig_size_fips(ed25519_key* key);
#else /* FIPS_NO_WRAPPERS */
    #define wc_ed25519_make_public wc_ed25519_make_public_fips
    #define wc_ed25519_make_key wc_ed25519_make_key_fips
    #ifdef HAVE_ED25519_SIGN
        #define wc_ed25519_sign_msg wc_ed25519_sign_msg_fips
        #define wc_ed25519ctx_sign_msg wc_ed25519ctx_sign_msg_fips
        #define wc_ed25519ph_sign_hash wc_ed25519ph_sign_hash_fips
        #define wc_ed25519ph_sign_msg wc_ed25519ph_sign_msg_fips
        #define wc_ed25519_sign_msg_ex wc_ed25519_sign_msg_ex_fips
    #endif /* HAVE_ED25519_SIGN */
    #ifdef HAVE_ED25519_VERIFY
        #define wc_ed25519_verify_msg wc_ed25519_verify_msg_fips
        #define wc_ed25519ctx_verify_msg wc_ed25519ctx_verify_msg_fips
        #define wc_ed25519ph_verify_hash wc_ed25519ph_verify_hash_fips
        #define wc_ed25519ph_verify_msg wc_ed25519ph_verify_msg_fips
        #define wc_ed25519_verify_msg_ex wc_ed25519_verify_msg_ex_fips
    #ifdef WOLFSSL_ED25519_STREAMING_VERIFY
        #define wc_ed25519_verify_msg_init wc_ed25519_verify_msg_init_fips
        #define wc_ed25519_verify_msg_update wc_ed25519_verify_msg_update_fips
        #define wc_ed25519_verify_msg_final wc_ed25519_verify_msg_final_fips
    #endif /* WOLFSSL_ED25519_STREAMING_VERIFY */
    #endif /* HAVE_ED25519_VERIFY */

    #define wc_ed25519_init wc_ed25519_init_fips
    #define wc_ed25519_init_ex wc_ed25519_init_ex_fips
    #define wc_ed25519_free wc_ed25519_free_fips
    #ifdef HAVE_ED25519_KEY_IMPORT
        #define wc_ed25519_import_public wc_ed25519_import_public_fips
        #define wc_ed25519_import_public_ex wc_ed25519_import_public_ex_fips
        #define wc_ed25519_import_private_only wc_ed25519_import_private_only_fips
        #define wc_ed25519_import_private_key wc_ed25519_import_private_key_fips
        #define wc_ed25519_import_private_key_ex wc_ed25519_import_private_key_ex_fips
    #endif /* HAVE_ED25519_KEY_IMPORT */

    #ifdef HAVE_ED25519_KEY_EXPORT
        #define wc_ed25519_export_public wc_ed25519_export_public_fips
        #define wc_ed25519_export_private_only wc_ed25519_export_private_only_fips
        #define wc_ed25519_export_private wc_ed25519_export_private_fips
        #define wc_ed25519_export_key wc_ed25519_export_key_fips
    #endif /* HAVE_ED25519_KEY_EXPORT */

    #define wc_ed25519_check_key wc_ed25519_check_key_fips

    /* size helper */
    #define wc_ed25519_size wc_ed25519_size_fips
    #define wc_ed25519_priv_size wc_ed25519_priv_size_fips
    #define wc_ed25519_pub_size wc_ed25519_pub_size_fips
    #define wc_ed25519_sig_size wc_ed25519_sig_size_fips
#endif /* FIPS_NO_WRAPPERS */
#endif /* HAVE_ED25519 */

#ifdef HAVE_ED448
#ifdef FIPS_NO_WRAPPERS

    #ifndef WC_ED448KEY_TYPE_DEFINED
        typedef struct ed448_key ed448_key;
        #define WC_ED448KEY_TYPE_DEFINED
    #endif

    WOLFSSL_API
    int wc_ed448_make_public_fips(ed448_key* key, unsigned char* pubKey,
                             word32 pubKeySz);
    WOLFSSL_API
    int wc_ed448_make_key_fips(WC_RNG* rng, int keysize, ed448_key* key);
    #ifdef HAVE_ED448_SIGN
    WOLFSSL_API
    int wc_ed448_sign_msg_fips(const byte* in, word32 inLen, byte* out, word32 *outLen,
                          ed448_key* key, const byte* context, byte contextLen);
    WOLFSSL_API
    int wc_ed448ph_sign_hash_fips(const byte* hash, word32 hashLen, byte* out,
                             word32 *outLen, ed448_key* key,
                             const byte* context, byte contextLen);
    WOLFSSL_API
    int wc_ed448_sign_msg_ex_fips(const byte* in, word32 inLen, byte* out,
                             word32 *outLen, ed448_key* key, byte type,
                             const byte* context, byte contextLen);
    WOLFSSL_API
    int wc_ed448ph_sign_msg_fips(const byte* in, word32 inLen, byte* out,
                            word32 *outLen, ed448_key* key, const byte* context,
                            byte contextLen);
    #endif /* HAVE_ED448_SIGN */
    #ifdef HAVE_ED448_VERIFY
    WOLFSSL_API
    int wc_ed448_verify_msg_ex_fips(const byte* sig, word32 sigLen, const byte* msg,
                                word32 msgLen, int* res, ed448_key* key,
                                byte type, const byte* context, byte contextLen);
    #ifdef WOLFSSL_ED448_STREAMING_VERIFY
    WOLFSSL_API
    int wc_ed448_verify_msg_init_fips(const byte* sig, word32 sigLen, ed448_key* key,
                            byte type, const byte* context, byte contextLen);
    WOLFSSL_API
    int wc_ed448_verify_msg_update_fips(const byte* msgSegment, word32 msgSegmentLen,
                                 ed448_key* key);
    WOLFSSL_API
    int wc_ed448_verify_msg_final_fips(const byte* sig, word32 sigLen,
                                  int* res, ed448_key* key);
    #endif /* WOLFSSL_ED448_STREAMING_VERIFY */
    WOLFSSL_API
    int wc_ed448_verify_msg_fips(const byte* sig, word32 sigLen, const byte* msg,
                            word32 msgLen, int* res, ed448_key* key,
                            const byte* context, byte contextLen);
    WOLFSSL_API
    int wc_ed448ph_verify_hash_fips(const byte* sig, word32 sigLen, const byte* hash,
                               word32 hashLen, int* res, ed448_key* key,
                               const byte* context, byte contextLen);
    WOLFSSL_API
    int wc_ed448ph_verify_msg_fips(const byte* sig, word32 sigLen, const byte* msg,
                              word32 msgLen, int* res, ed448_key* key,
                              const byte* context, byte contextLen);
    #endif /* HAVE_ED448_VERIFY */
    WOLFSSL_API
    int wc_ed448_init_ex_fips(ed448_key* key, void *heap, int devId);
    WOLFSSL_API
    int wc_ed448_init_fips(ed448_key* key);
    WOLFSSL_API
    void wc_ed448_free_fips(ed448_key* key);

    #ifdef HAVE_ED448_KEY_IMPORT
    WOLFSSL_API
    int wc_ed448_import_public_fips(const byte* in, word32 inLen, ed448_key* key);
    WOLFSSL_API
    int wc_ed448_import_public_ex_fips(const byte* in, word32 inLen, ed448_key* key,
                                  int trusted);
    WOLFSSL_API
    int wc_ed448_import_private_only_fips(const byte* priv, word32 privSz,
                                     ed448_key* key);
    WOLFSSL_API
    int wc_ed448_import_private_key_fips(const byte* priv, word32 privSz,
                                    const byte* pub, word32 pubSz, ed448_key* key);
    WOLFSSL_API
    int wc_ed448_import_private_key_ex_fips(const byte* priv, word32 privSz,
        const byte* pub, word32 pubSz, ed448_key* key, int trusted);
    #endif /* HAVE_ED448_KEY_IMPORT */

    #ifdef HAVE_ED448_KEY_EXPORT
    WOLFSSL_API
    int wc_ed448_export_public_fips(ed448_key* key, byte* out, word32* outLen);
    WOLFSSL_API
    int wc_ed448_export_private_only_fips(ed448_key* key, byte* out, word32* outLen);
    WOLFSSL_API
    int wc_ed448_export_private_fips(ed448_key* key, byte* out, word32* outLen);
    WOLFSSL_API
    int wc_ed448_export_key_fips(ed448_key* key, byte* priv, word32 *privSz,
                            byte* pub, word32 *pubSz);
    #endif /* HAVE_ED448_KEY_EXPORT */

    WOLFSSL_API
    int wc_ed448_check_key_fips(ed448_key* key);

    /* size helper */
    WOLFSSL_API
    int wc_ed448_size_fips(ed448_key* key);
    WOLFSSL_API
    int wc_ed448_priv_size_fips(ed448_key* key);
    WOLFSSL_API
    int wc_ed448_pub_size_fips(ed448_key* key);
    WOLFSSL_API
    int wc_ed448_sig_size_fips(ed448_key* key);
#else /* FIPS_NO_WRAPPERS */
    #define wc_ed448_make_public            wc_ed448_make_public_fips
    #define wc_ed448_make_key               wc_ed448_make_key_fips
    #ifdef HAVE_ED448_SIGN
        #define wc_ed448_sign_msg               wc_ed448_sign_msg_fips
        #define wc_ed448ph_sign_hash            wc_ed448ph_sign_hash_fips
        #define wc_ed448_sign_msg_ex            wc_ed448_sign_msg_ex_fips
        #define wc_ed448ph_sign_msg             wc_ed448ph_sign_msg_fips
    #endif /* HAVE_ED448_SIGN */
    #ifdef HAVE_ED448_VERIFY
        #define wc_ed448_verify_msg_ex          wc_ed448_verify_msg_ex_fips
    #ifdef WOLFSSL_ED448_STREAMING_VERIFY
        #define wc_ed448_verify_msg_init        wc_ed448_verify_msg_init_fips
        #define wc_ed448_verify_msg_update      wc_ed448_verify_msg_update_fips
        #define wc_ed448_verify_msg_final       wc_ed448_verify_msg_final_fips
    #endif /* WOLFSSL_ED448_STREAMING_VERIFY */
        #define wc_ed448_verify_msg             wc_ed448_verify_msg_fips
        #define wc_ed448ph_verify_hash          wc_ed448ph_verify_hash_fips
        #define wc_ed448ph_verify_msg           wc_ed448ph_verify_msg_fips
    #endif /* HAVE_ED448_VERIFY */
    #define wc_ed448_init_ex                wc_ed448_init_ex_fips
    #define wc_ed448_init                   wc_ed448_init_fips
    #define wc_ed448_free                   wc_ed448_free_fips

    #ifdef HAVE_ED448_KEY_IMPORT
        #define wc_ed448_import_public          wc_ed448_import_public_fips
        #define wc_ed448_import_public_ex       wc_ed448_import_public_ex_fips
        #define wc_ed448_import_private_only    wc_ed448_import_private_only_fips
        #define wc_ed448_import_private_key     wc_ed448_import_private_key_fips
        #define wc_ed448_import_private_key_ex  wc_ed448_import_private_key_ex_fips
    #endif /* HAVE_ED448_KEY_IMPORT */

    #ifdef HAVE_ED448_KEY_EXPORT
        #define wc_ed448_export_public          wc_ed448_export_public_fips
        #define wc_ed448_export_private_only    wc_ed448_export_private_only_fips
        #define wc_ed448_export_private         wc_ed448_export_private_fips
        #define wc_ed448_export_key             wc_ed448_export_key_fips
    #endif /* HAVE_ED448_KEY_EXPORT */

    #define wc_ed448_check_key              wc_ed448_check_key_fips

    /* size helper */
    #define wc_ed448_size                   wc_ed448_size_fips
    #define wc_ed448_priv_size              wc_ed448_priv_size_fips
    #define wc_ed448_pub_size               wc_ed448_pub_size_fips
    #define wc_ed448_sig_size               wc_ed448_sig_size_fips
#endif /* FIPS_NO_WRAPPERS */
#endif /* HAVE_ED448 */

#ifdef HAVE_PBKDF2
#ifdef FIPS_NO_WRAPPERS
    WOLFSSL_API int wc_PBKDF2_ex_fips(byte* output, const byte* passwd, int pLen,
                        const byte* salt, int sLen, int iterations, int kLen,
                        int typeH, void* heap, int devId);
    WOLFSSL_API int wc_PBKDF2_fips(byte* output, const byte* passwd, int pLen,
                          const byte* salt, int sLen, int iterations, int kLen,
                          int typeH);
    /* The PKCS12 PBKDF is not yet approved, but may one day be available, for
     * now leave as potential future service */
    #if 0
    WOLFSSL_API int wc_PKCS12_PBKDF_fips(byte* output, const byte* passwd, int pLen,
                                const byte* salt, int sLen, int iterations,
                                int kLen, int typeH, int purpose);
    WOLFSSL_API int wc_PKCS12_PBKDF_ex_fips(byte* output, const byte* passwd,int passLen,
                           const byte* salt, int saltLen, int iterations, int kLen,
                           int hashType, int id, void* heap);
    #endif
#else /* FIPS_NO_WRAPPERS */
    #define wc_PBKDF2_ex        wc_PBKDF2_ex_fips
    #define wc_PBKDF2           wc_PBKDF2_fips
    /* The PKCS12 PBKDF is not yet approved, but may one day be available, for
     * now leave as potential future service */
    #if 0
    #define wc_PKCS12_PBKDF     wc_PKCS12_PBKDF_fips
    #define wc_PKCS12_PBKDF_ex  wc_PKCS12_PBKDF_ex_fips
    #endif
#endif /* FIPS_NO_WRAPPERS */
#endif /* HAVE_PBKDF2 */

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLF_CRYPT_FIPS_H */


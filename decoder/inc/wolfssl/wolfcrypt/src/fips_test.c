/* fips_test.c
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

#include <wolfssl/wolfcrypt/fips_test.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/cmac.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/kdf.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/ed448.h>
#include <wolfssl/wolfcrypt/pwdbased.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/asn.h>
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#ifdef USE_WINDOWS_API
#pragma code_seg(".fipsA$p")
#pragma const_seg(".fipsB$p")
#endif

#if FIPS_VERSION3_GE(6,0,0)
    const unsigned int wolfCrypt_FIPS_ft_ro_sanity[] =
                                                     { 0x1a2b3c4d, 0x00000017 };
    int wolfCrypt_FIPS_FT_sanity(void);
    int wolfCrypt_FIPS_FT_sanity(void)
    {
        return 0;
    }
#endif

/* Test keys */
#ifdef HAVE_ECC
#if defined(HAVE_ECC_SIGN) && defined(HAVE_ECC_VERIFY)
#if !defined(NO_ECC256) || defined(HAVE_ALL_CURVES)
    /* ./certs/ecc-key.der, ECC */
    static const unsigned char ecc_key_der_256[] = {
        0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0x45, 0xB6, 0x69,
        0x02, 0x73, 0x9C, 0x6C, 0x85, 0xA1, 0x38, 0x5B, 0x72, 0xE8,
        0xE8, 0xC7, 0xAC, 0xC4, 0x03, 0x8D, 0x53, 0x35, 0x04, 0xFA,
        0x6C, 0x28, 0xDC, 0x34, 0x8D, 0xE1, 0xA8, 0x09, 0x8C, 0xA0,
        0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01,
        0x07, 0xA1, 0x44, 0x03, 0x42, 0x00, 0x04, 0xBB, 0x33, 0xAC,
        0x4C, 0x27, 0x50, 0x4A, 0xC6, 0x4A, 0xA5, 0x04, 0xC3, 0x3C,
        0xDE, 0x9F, 0x36, 0xDB, 0x72, 0x2D, 0xCE, 0x94, 0xEA, 0x2B,
        0xFA, 0xCB, 0x20, 0x09, 0x39, 0x2C, 0x16, 0xE8, 0x61, 0x02,
        0xE9, 0xAF, 0x4D, 0xD3, 0x02, 0x93, 0x9A, 0x31, 0x5B, 0x97,
        0x92, 0x21, 0x7F, 0xF0, 0xCF, 0x18, 0xDA, 0x91, 0x11, 0x02,
        0x34, 0x86, 0xE8, 0x20, 0x58, 0x33, 0x0B, 0x80, 0x34, 0x89,
        0xD8
    };
    #define FIPS_ECC_CURVE_SZ  FIPS_ECC_256_SZ
    #define FIPS_ECC_KEY_BUF   ecc_key_der_256
    #define FIPS_ECC_KEY_SZ    (word32)sizeof(ecc_key_der_256)
    #define FIPS_ECC_HASH_TYPE WC_SHA256
#elif defined(HAVE_ECC384)
    /* ./certs/client-ecc384-key.der, ECC SECP384R1 */
    static const unsigned char ecc_clikey_der_384[] = {
        0x30, 0x81, 0xA4, 0x02, 0x01, 0x01, 0x04, 0x30, 0x75, 0x9D, 0x53, 0xBB,
        0xFD, 0x36, 0xCB, 0xA8, 0x57, 0x63, 0x95, 0xDA, 0x4E, 0x4C, 0x7D, 0xB7,
        0x59, 0x58, 0xBF, 0x0C, 0x83, 0xA4, 0x35, 0xA2, 0xD4, 0x34, 0x4A, 0x5F,
        0x92, 0x1D, 0xE0, 0x6E, 0xB5, 0xA4, 0xD4, 0x04, 0x36, 0x3A, 0x09, 0xE6,
        0xAC, 0x14, 0xA0, 0x30, 0x8F, 0x05, 0x37, 0x96, 0xA0, 0x07, 0x06, 0x05,
        0x2B, 0x81, 0x04, 0x00, 0x22, 0xA1, 0x64, 0x03, 0x62, 0x00, 0x04, 0x66,
        0xC4, 0x08, 0x3D, 0x66, 0xA7, 0xA1, 0x15, 0xD4, 0x53, 0x0A, 0x23, 0xB3,
        0xAD, 0x0B, 0xCE, 0x8F, 0xC8, 0xF4, 0x98, 0x1D, 0xA6, 0xD8, 0xB2, 0x6E,
        0x22, 0x11, 0xFA, 0xB9, 0xEF, 0x99, 0xC0, 0xFA, 0x29, 0x3E, 0x48, 0x00,
        0xF9, 0xFE, 0xC2, 0xA6, 0x4A, 0x1B, 0xA7, 0x12, 0xA8, 0x6B, 0x90, 0x4C,
        0x1C, 0xBB, 0xAC, 0x5D, 0x6E, 0x0E, 0x62, 0xCE, 0x70, 0x20, 0xF7, 0x43,
        0x77, 0xD8, 0x97, 0xC7, 0x74, 0xD3, 0x68, 0xFE, 0x89, 0xEC, 0x77, 0xCB,
        0x19, 0x2F, 0x89, 0x4A, 0x1D, 0x77, 0xF9, 0x97, 0x4B, 0x66, 0x02, 0x68,
        0xA5, 0x62, 0xAF, 0x95, 0x81, 0xCB, 0xE3, 0x24, 0x36, 0xEB, 0x85
    };
    #define FIPS_ECC_CURVE_SZ  FIPS_ECC_384_SZ
    #define FIPS_ECC_KEY_BUF   ecc_clikey_der_384
    #define FIPS_ECC_KEY_SZ    (word32)sizeof(ecc_clikey_der_384)
    #define FIPS_ECC_HASH_TYPE WC_SHA384
#else
    #error No FIPS ECC curve enabled
#endif
#endif /* HAVE_ECC_SIGN && HAVE_ECC_VERIFY */
#endif /* HAVE_ECC */

#ifndef NO_RSA
/* ./certs/client-key.der, RSA 2048-bit */
static const unsigned char client_key_der_2048[] = {
    0x30, 0x82, 0x04, 0xA4, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00,
    0xC3, 0x03, 0xD1, 0x2B, 0xFE, 0x39, 0xA4, 0x32, 0x45, 0x3B, 0x53, 0xC8,
    0x84, 0x2B, 0x2A, 0x7C, 0x74, 0x9A, 0xBD, 0xAA, 0x2A, 0x52, 0x07, 0x47,
    0xD6, 0xA6, 0x36, 0xB2, 0x07, 0x32, 0x8E, 0xD0, 0xBA, 0x69, 0x7B, 0xC6,
    0xC3, 0x44, 0x9E, 0xD4, 0x81, 0x48, 0xFD, 0x2D, 0x68, 0xA2, 0x8B, 0x67,
    0xBB, 0xA1, 0x75, 0xC8, 0x36, 0x2C, 0x4A, 0xD2, 0x1B, 0xF7, 0x8B, 0xBA,
    0xCF, 0x0D, 0xF9, 0xEF, 0xEC, 0xF1, 0x81, 0x1E, 0x7B, 0x9B, 0x03, 0x47,
    0x9A, 0xBF, 0x65, 0xCC, 0x7F, 0x65, 0x24, 0x69, 0xA6, 0xE8, 0x14, 0x89,
    0x5B, 0xE4, 0x34, 0xF7, 0xC5, 0xB0, 0x14, 0x93, 0xF5, 0x67, 0x7B, 0x3A,
    0x7A, 0x78, 0xE1, 0x01, 0x56, 0x56, 0x91, 0xA6, 0x13, 0x42, 0x8D, 0xD2,
    0x3C, 0x40, 0x9C, 0x4C, 0xEF, 0xD1, 0x86, 0xDF, 0x37, 0x51, 0x1B, 0x0C,
    0xA1, 0x3B, 0xF5, 0xF1, 0xA3, 0x4A, 0x35, 0xE4, 0xE1, 0xCE, 0x96, 0xDF,
    0x1B, 0x7E, 0xBF, 0x4E, 0x97, 0xD0, 0x10, 0xE8, 0xA8, 0x08, 0x30, 0x81,
    0xAF, 0x20, 0x0B, 0x43, 0x14, 0xC5, 0x74, 0x67, 0xB4, 0x32, 0x82, 0x6F,
    0x8D, 0x86, 0xC2, 0x88, 0x40, 0x99, 0x36, 0x83, 0xBA, 0x1E, 0x40, 0x72,
    0x22, 0x17, 0xD7, 0x52, 0x65, 0x24, 0x73, 0xB0, 0xCE, 0xEF, 0x19, 0xCD,
    0xAE, 0xFF, 0x78, 0x6C, 0x7B, 0xC0, 0x12, 0x03, 0xD4, 0x4E, 0x72, 0x0D,
    0x50, 0x6D, 0x3B, 0xA3, 0x3B, 0xA3, 0x99, 0x5E, 0x9D, 0xC8, 0xD9, 0x0C,
    0x85, 0xB3, 0xD9, 0x8A, 0xD9, 0x54, 0x26, 0xDB, 0x6D, 0xFA, 0xAC, 0xBB,
    0xFF, 0x25, 0x4C, 0xC4, 0xD1, 0x79, 0xF4, 0x71, 0xD3, 0x86, 0x40, 0x18,
    0x13, 0xB0, 0x63, 0xB5, 0x72, 0x4E, 0x30, 0xC4, 0x97, 0x84, 0x86, 0x2D,
    0x56, 0x2F, 0xD7, 0x15, 0xF7, 0x7F, 0xC0, 0xAE, 0xF5, 0xFC, 0x5B, 0xE5,
    0xFB, 0xA1, 0xBA, 0xD3, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x82, 0x01,
    0x01, 0x00, 0xA2, 0xE6, 0xD8, 0x5F, 0x10, 0x71, 0x64, 0x08, 0x9E, 0x2E,
    0x6D, 0xD1, 0x6D, 0x1E, 0x85, 0xD2, 0x0A, 0xB1, 0x8C, 0x47, 0xCE, 0x2C,
    0x51, 0x6A, 0xA0, 0x12, 0x9E, 0x53, 0xDE, 0x91, 0x4C, 0x1D, 0x6D, 0xEA,
    0x59, 0x7B, 0xF2, 0x77, 0xAA, 0xD9, 0xC6, 0xD9, 0x8A, 0xAB, 0xD8, 0xE1,
    0x16, 0xE4, 0x63, 0x26, 0xFF, 0xB5, 0x6C, 0x13, 0x59, 0xB8, 0xE3, 0xA5,
    0xC8, 0x72, 0x17, 0x2E, 0x0C, 0x9F, 0x6F, 0xE5, 0x59, 0x3F, 0x76, 0x6F,
    0x49, 0xB1, 0x11, 0xC2, 0x5A, 0x2E, 0x16, 0x29, 0x0D, 0xDE, 0xB7, 0x8E,
    0xDC, 0x40, 0xD5, 0xA2, 0xEE, 0xE0, 0x1E, 0xA1, 0xF4, 0xBE, 0x97, 0xDB,
    0x86, 0x63, 0x96, 0x14, 0xCD, 0x98, 0x09, 0x60, 0x2D, 0x30, 0x76, 0x9C,
    0x3C, 0xCD, 0xE6, 0x88, 0xEE, 0x47, 0x92, 0x79, 0x0B, 0x5A, 0x00, 0xE2,
    0x5E, 0x5F, 0x11, 0x7C, 0x7D, 0xF9, 0x08, 0xB7, 0x20, 0x06, 0x89, 0x2A,
    0x5D, 0xFD, 0x00, 0xAB, 0x22, 0xE1, 0xF0, 0xB3, 0xBC, 0x24, 0xA9, 0x5E,
    0x26, 0x0E, 0x1F, 0x00, 0x2D, 0xFE, 0x21, 0x9A, 0x53, 0x5B, 0x6D, 0xD3,
    0x2B, 0xAB, 0x94, 0x82, 0x68, 0x43, 0x36, 0xD8, 0xF6, 0x2F, 0xC6, 0x22,
    0xFC, 0xB5, 0x41, 0x5D, 0x0D, 0x33, 0x60, 0xEA, 0xA4, 0x7D, 0x7E, 0xE8,
    0x4B, 0x55, 0x91, 0x56, 0xD3, 0x5C, 0x57, 0x8F, 0x1F, 0x94, 0x17, 0x2F,
    0xAA, 0xDE, 0xE9, 0x9E, 0xA8, 0xF4, 0xCF, 0x8A, 0x4C, 0x8E, 0xA0, 0xE4,
    0x56, 0x73, 0xB2, 0xCF, 0x4F, 0x86, 0xC5, 0x69, 0x3C, 0xF3, 0x24, 0x20,
    0x8B, 0x5C, 0x96, 0x0C, 0xFA, 0x6B, 0x12, 0x3B, 0x9A, 0x67, 0xC1, 0xDF,
    0xC6, 0x96, 0xB2, 0xA5, 0xD5, 0x92, 0x0D, 0x9B, 0x09, 0x42, 0x68, 0x24,
    0x10, 0x45, 0xD4, 0x50, 0xE4, 0x17, 0x39, 0x48, 0xD0, 0x35, 0x8B, 0x94,
    0x6D, 0x11, 0xDE, 0x8F, 0xCA, 0x59, 0x02, 0x81, 0x81, 0x00, 0xEA, 0x24,
    0xA7, 0xF9, 0x69, 0x33, 0xE9, 0x71, 0xDC, 0x52, 0x7D, 0x88, 0x21, 0x28,
    0x2F, 0x49, 0xDE, 0xBA, 0x72, 0x16, 0xE9, 0xCC, 0x47, 0x7A, 0x88, 0x0D,
    0x94, 0x57, 0x84, 0x58, 0x16, 0x3A, 0x81, 0xB0, 0x3F, 0xA2, 0xCF, 0xA6,
    0x6C, 0x1E, 0xB0, 0x06, 0x29, 0x00, 0x8F, 0xE7, 0x77, 0x76, 0xAC, 0xDB,
    0xCA, 0xC7, 0xD9, 0x5E, 0x9B, 0x3F, 0x26, 0x90, 0x52, 0xAE, 0xFC, 0x38,
    0x90, 0x00, 0x14, 0xBB, 0xB4, 0x0F, 0x58, 0x94, 0xE7, 0x2F, 0x6A, 0x7E,
    0x1C, 0x4F, 0x41, 0x21, 0xD4, 0x31, 0x59, 0x1F, 0x4E, 0x8A, 0x1A, 0x8D,
    0xA7, 0x57, 0x6C, 0x22, 0xD8, 0xE5, 0xF4, 0x7E, 0x32, 0xA6, 0x10, 0xCB,
    0x64, 0xA5, 0x55, 0x03, 0x87, 0xA6, 0x27, 0x05, 0x8C, 0xC3, 0xD7, 0xB6,
    0x27, 0xB2, 0x4D, 0xBA, 0x30, 0xDA, 0x47, 0x8F, 0x54, 0xD3, 0x3D, 0x8B,
    0x84, 0x8D, 0x94, 0x98, 0x58, 0xA5, 0x02, 0x81, 0x81, 0x00, 0xD5, 0x38,
    0x1B, 0xC3, 0x8F, 0xC5, 0x93, 0x0C, 0x47, 0x0B, 0x6F, 0x35, 0x92, 0xC5,
    0xB0, 0x8D, 0x46, 0xC8, 0x92, 0x18, 0x8F, 0xF5, 0x80, 0x0A, 0xF7, 0xEF,
    0xA1, 0xFE, 0x80, 0xB9, 0xB5, 0x2A, 0xBA, 0xCA, 0x18, 0xB0, 0x5D, 0xA5,
    0x07, 0xD0, 0x93, 0x8D, 0xD8, 0x9C, 0x04, 0x1C, 0xD4, 0x62, 0x8E, 0xA6,
    0x26, 0x81, 0x01, 0xFF, 0xCE, 0x8A, 0x2A, 0x63, 0x34, 0x35, 0x40, 0xAA,
    0x6D, 0x80, 0xDE, 0x89, 0x23, 0x6A, 0x57, 0x4D, 0x9E, 0x6E, 0xAD, 0x93,
    0x4E, 0x56, 0x90, 0x0B, 0x6D, 0x9D, 0x73, 0x8B, 0x0C, 0xAE, 0x27, 0x3D,
    0xDE, 0x4E, 0xF0, 0xAA, 0xC5, 0x6C, 0x78, 0x67, 0x6C, 0x94, 0x52, 0x9C,
    0x37, 0x67, 0x6C, 0x2D, 0xEF, 0xBB, 0xAF, 0xDF, 0xA6, 0x90, 0x3C, 0xC4,
    0x47, 0xCF, 0x8D, 0x96, 0x9E, 0x98, 0xA9, 0xB4, 0x9F, 0xC5, 0xA6, 0x50,
    0xDC, 0xB3, 0xF0, 0xFB, 0x74, 0x17, 0x02, 0x81, 0x80, 0x5E, 0x83, 0x09,
    0x62, 0xBD, 0xBA, 0x7C, 0xA2, 0xBF, 0x42, 0x74, 0xF5, 0x7C, 0x1C, 0xD2,
    0x69, 0xC9, 0x04, 0x0D, 0x85, 0x7E, 0x3E, 0x3D, 0x24, 0x12, 0xC3, 0x18,
    0x7B, 0xF3, 0x29, 0xF3, 0x5F, 0x0E, 0x76, 0x6C, 0x59, 0x75, 0xE4, 0x41,
    0x84, 0x69, 0x9D, 0x32, 0xF3, 0xCD, 0x22, 0xAB, 0xB0, 0x35, 0xBA, 0x4A,
    0xB2, 0x3C, 0xE5, 0xD9, 0x58, 0xB6, 0x62, 0x4F, 0x5D, 0xDE, 0xE5, 0x9E,
    0x0A, 0xCA, 0x53, 0xB2, 0x2C, 0xF7, 0x9E, 0xB3, 0x6B, 0x0A, 0x5B, 0x79,
    0x65, 0xEC, 0x6E, 0x91, 0x4E, 0x92, 0x20, 0xF6, 0xFC, 0xFC, 0x16, 0xED,
    0xD3, 0x76, 0x0C, 0xE2, 0xEC, 0x7F, 0xB2, 0x69, 0x13, 0x6B, 0x78, 0x0E,
    0x5A, 0x46, 0x64, 0xB4, 0x5E, 0xB7, 0x25, 0xA0, 0x5A, 0x75, 0x3A, 0x4B,
    0xEF, 0xC7, 0x3C, 0x3E, 0xF7, 0xFD, 0x26, 0xB8, 0x20, 0xC4, 0x99, 0x0A,
    0x9A, 0x73, 0xBE, 0xC3, 0x19, 0x02, 0x81, 0x81, 0x00, 0xBA, 0x44, 0x93,
    0x14, 0xAC, 0x34, 0x19, 0x3B, 0x5F, 0x91, 0x60, 0xAC, 0xF7, 0xB4, 0xD6,
    0x81, 0x05, 0x36, 0x51, 0x53, 0x3D, 0xE8, 0x65, 0xDC, 0xAF, 0x2E, 0xDC,
    0x61, 0x3E, 0xC9, 0x7D, 0xB8, 0x7F, 0x87, 0xF0, 0x3B, 0x9B, 0x03, 0x82,
    0x29, 0x37, 0xCE, 0x72, 0x4E, 0x11, 0xD5, 0xB1, 0xC1, 0x0C, 0x07, 0xA0,
    0x99, 0x91, 0x4A, 0x8D, 0x7F, 0xEC, 0x79, 0xCF, 0xF1, 0x39, 0xB5, 0xE9,
    0x85, 0xEC, 0x62, 0xF7, 0xDA, 0x7D, 0xBC, 0x64, 0x4D, 0x22, 0x3C, 0x0E,
    0xF2, 0xD6, 0x51, 0xF5, 0x87, 0xD8, 0x99, 0xC0, 0x11, 0x20, 0x5D, 0x0F,
    0x29, 0xFD, 0x5B, 0xE2, 0xAE, 0xD9, 0x1C, 0xD9, 0x21, 0x56, 0x6D, 0xFC,
    0x84, 0xD0, 0x5F, 0xED, 0x10, 0x15, 0x1C, 0x18, 0x21, 0xE7, 0xC4, 0x3D,
    0x4B, 0xD7, 0xD0, 0x9E, 0x6A, 0x95, 0xCF, 0x22, 0xC9, 0x03, 0x7B, 0x9E,
    0xE3, 0x60, 0x01, 0xFC, 0x2F, 0x02, 0x81, 0x80, 0x11, 0xD0, 0x4B, 0xCF,
    0x1B, 0x67, 0xB9, 0x9F, 0x10, 0x75, 0x47, 0x86, 0x65, 0xAE, 0x31, 0xC2,
    0xC6, 0x30, 0xAC, 0x59, 0x06, 0x50, 0xD9, 0x0F, 0xB5, 0x70, 0x06, 0xF7,
    0xF0, 0xD3, 0xC8, 0x62, 0x7C, 0xA8, 0xDA, 0x6E, 0xF6, 0x21, 0x3F, 0xD3,
    0x7F, 0x5F, 0xEA, 0x8A, 0xAB, 0x3F, 0xD9, 0x2A, 0x5E, 0xF3, 0x51, 0xD2,
    0xC2, 0x30, 0x37, 0xE3, 0x2D, 0xA3, 0x75, 0x0D, 0x1E, 0x4D, 0x21, 0x34,
    0xD5, 0x57, 0x70, 0x5C, 0x89, 0xBF, 0x72, 0xEC, 0x4A, 0x6E, 0x68, 0xD5,
    0xCD, 0x18, 0x74, 0x33, 0x4E, 0x8C, 0x3A, 0x45, 0x8F, 0xE6, 0x96, 0x40,
    0xEB, 0x63, 0xF9, 0x19, 0x86, 0x3A, 0x51, 0xDD, 0x89, 0x4B, 0xB0, 0xF3,
    0xF9, 0x9F, 0x5D, 0x28, 0x95, 0x38, 0xBE, 0x35, 0xAB, 0xCA, 0x5C, 0xE7,
    0x93, 0x53, 0x34, 0xA1, 0x45, 0x5D, 0x13, 0x39, 0x65, 0x42, 0x46, 0xA1,
    0x9F, 0xCD, 0xF5, 0xBF
};
static const word32 sizeof_client_key_der_2048 = (word32)sizeof(client_key_der_2048);
#endif /* !NO_RSA */


enum {
    FIPS_AES_KEY_SZ     = 16,
    FIPS_AES_IV_SZ      = FIPS_AES_KEY_SZ,
    FIPS_AES_PLAIN_SZ   = 64,
    FIPS_AES_CBC_SZ     = FIPS_AES_PLAIN_SZ,
    FIPS_AES_CIPHER_SZ  = FIPS_AES_PLAIN_SZ,

    FIPS_GCM_KEY_SZ     = 16,
    FIPS_GCM_AUTH_SZ    = FIPS_GCM_KEY_SZ,
    FIPS_GCM_CHECK_SZ   = FIPS_GCM_KEY_SZ,
    FIPS_GCM_TAG_SZ     = FIPS_GCM_KEY_SZ,
    FIPS_GCM_PLAIN_SZ   = 32,
    FIPS_GCM_CIPHER_SZ  = FIPS_GCM_PLAIN_SZ,
    FIPS_GCM_OUT_SZ     = FIPS_GCM_PLAIN_SZ,
    FIPS_GCM_IV_SZ      = 12,

    FIPS_CCM_KEY_SZ     = 16,
    FIPS_CCM_AUTH_SZ    = 32,
    FIPS_CCM_CHECK_SZ   = FIPS_CCM_KEY_SZ,
    FIPS_CCM_TAG_SZ     = FIPS_CCM_KEY_SZ,
    FIPS_CCM_PLAIN_SZ   = 24,
    FIPS_CCM_CIPHER_SZ  = FIPS_CCM_PLAIN_SZ,
    FIPS_CCM_OUT_SZ     = FIPS_CCM_PLAIN_SZ,
    FIPS_CCM_IV_SZ      = 12,

    FIPS_MAX_DIGEST_SZ  = 64,
    FIPS_HMAC_DIGEST_SZ = 64,
    FIPS_HMAC_KEY_SZ    = FIPS_HMAC_DIGEST_SZ,

    FIPS_DRBG_EA_SZ     = 48,
    FIPS_DRBG_EB_SZ     = 32,
    FIPS_DRBG_OUT_SZ    = 128,

    FIPS_RSA_SIG_SZ     = 256,
    FIPS_RSA_RESULT_SZ  = FIPS_RSA_SIG_SZ,
    FIPS_RSA_PRIME_SZ   = 1024,
    FIPS_RSA_MOD_SHORT  = 128,

    FIPS_ECC_256_SZ     = 32,
    FIPS_ECC_384_SZ     = 48,
    FIPS_FFC_FIELD_SZ   = 256,
    FIPS_FFC_ORDER_SZ   = 32
};

extern const unsigned int wolfCrypt_FIPS_ro_start[];
extern const unsigned int wolfCrypt_FIPS_ro_end[];

#if defined(WOLFSSL_LINUXKM) && defined(__PIE__)
#define wolfCrypt_FIPS_first wolfssl_linuxkm_get_pie_redirect_table()->wolfCrypt_FIPS_first
#define wolfCrypt_FIPS_last wolfssl_linuxkm_get_pie_redirect_table()->wolfCrypt_FIPS_last
#define wolfCrypt_FIPS_AES_sanity wolfssl_linuxkm_get_pie_redirect_table()->wolfCrypt_FIPS_AES_sanity
#define wolfCrypt_FIPS_CMAC_sanity wolfssl_linuxkm_get_pie_redirect_table()->wolfCrypt_FIPS_CMAC_sanity
#define wolfCrypt_FIPS_DH_sanity wolfssl_linuxkm_get_pie_redirect_table()->wolfCrypt_FIPS_DH_sanity
#define wolfCrypt_FIPS_ECC_sanity wolfssl_linuxkm_get_pie_redirect_table()->wolfCrypt_FIPS_ECC_sanity
#define wolfCrypt_FIPS_ED25519_sanity wolfssl_linuxkm_get_pie_redirect_table()->wolfCrypt_FIPS_ED25519_sanity
#define wolfCrypt_FIPS_ED448_sanity wolfssl_linuxkm_get_pie_redirect_table()->wolfCrypt_FIPS_ED448_sanity
#define wolfCrypt_FIPS_HMAC_sanity wolfssl_linuxkm_get_pie_redirect_table()->wolfCrypt_FIPS_HMAC_sanity
#define wolfCrypt_FIPS_KDF_sanity wolfssl_linuxkm_get_pie_redirect_table()->wolfCrypt_FIPS_KDF_sanity
#define wolfCrypt_FIPS_PBKDF_sanity wolfssl_linuxkm_get_pie_redirect_table()->wolfCrypt_FIPS_PBKDF_sanity
#define wolfCrypt_FIPS_DRBG_sanity wolfssl_linuxkm_get_pie_redirect_table()->wolfCrypt_FIPS_DRBG_sanity
#define wolfCrypt_FIPS_RSA_sanity wolfssl_linuxkm_get_pie_redirect_table()->wolfCrypt_FIPS_RSA_sanity
#define wolfCrypt_FIPS_SHA_sanity wolfssl_linuxkm_get_pie_redirect_table()->wolfCrypt_FIPS_SHA_sanity
#define wolfCrypt_FIPS_SHA256_sanity wolfssl_linuxkm_get_pie_redirect_table()->wolfCrypt_FIPS_SHA256_sanity
#define wolfCrypt_FIPS_SHA512_sanity wolfssl_linuxkm_get_pie_redirect_table()->wolfCrypt_FIPS_SHA512_sanity
#define wolfCrypt_FIPS_SHA3_sanity wolfssl_linuxkm_get_pie_redirect_table()->wolfCrypt_FIPS_SHA3_sanity
#define wolfCrypt_FIPS_FT_sanity wolfssl_linuxkm_get_pie_redirect_table()->wolfCrypt_FIPS_FT_sanity
#define wc_RunAllCast_fips wolfssl_linuxkm_get_pie_redirect_table()->wc_RunAllCast_fips
#else
int wolfCrypt_FIPS_first(void);
int wolfCrypt_FIPS_last(void);
#endif

typedef int (*fips_address_function)(void);

/* sanity size checks (over-rideable) */
#ifndef MAX_FIPS_DATA_SZ
    #define MAX_FIPS_DATA_SZ 10000000 /* sp-asm translates to quite large data */
#endif
#ifndef MAX_FIPS_CODE_SZ
    #define MAX_FIPS_CODE_SZ 10000000 /* 10M is enough to accommodate sanitizing
                                       * and other instrumented builds.
                                       */
#endif

#ifndef WOLFCRYPT_FIPS_CORE_DYNAMIC_HASH_VALUE
static
#endif
int GenBase16_Hash(const byte* in, int length, char* out, int outSz);


/* convert hex string to binary, store size, 0 success (free mem on failure) */
#ifdef WOLFCRYPT_FIPS_CORE_DYNAMIC_HASH_VALUE
int ConvertHexToBin(const char* h1, byte* b1, word32* b1Sz,
                           const char* h2, byte* b2, word32* b2Sz,
                           const char* h3, byte* b3, word32* b3Sz,
                           const char* h4, byte* b4, word32* b4Sz);
#else
static
#endif
int ConvertHexToBin(const char* h1, byte* b1, word32* b1Sz,
                           const char* h2, byte* b2, word32* b2Sz,
                           const char* h3, byte* b3, word32* b3Sz,
                           const char* h4, byte* b4, word32* b4Sz)
{
    int ret;
    size_t h1Sz, h2Sz, h3Sz, h4Sz, tempSz;

    /* b1 */
    if (h1 && b1 && b1Sz) {
        h1Sz = XSTRLEN(h1);
        tempSz = h1Sz / 2;
        if (tempSz > *b1Sz || tempSz <= 0) {
            return BUFFER_E;
        }
        *b1Sz = (word32)tempSz;

        ret = Base16_Decode((const byte*)h1, (word32)h1Sz, b1, b1Sz);
        if (ret != 0) {
            return ret;
        }
    }

    /* b2 */
    if (h2 && b2 && b2Sz) {
        h2Sz = XSTRLEN(h2);
        tempSz = h2Sz / 2;
        if (tempSz > *b2Sz || tempSz <= 0) {
            return BUFFER_E;
        }
        *b2Sz = (word32)tempSz;

        ret = Base16_Decode((const byte*)h2, (word32)h2Sz, b2, b2Sz);
        if (ret != 0) {
            return ret;
        }
    }

    /* b3 */
    if (h3 && b3 && b3Sz) {
        h3Sz = XSTRLEN(h3);
        tempSz = h3Sz / 2;
        if (tempSz > *b3Sz || tempSz <= 0) {
            return BUFFER_E;
        }
        *b3Sz = (word32)tempSz;

        ret = Base16_Decode((const byte*)h3, (word32)h3Sz, b3, b3Sz);
        if (ret != 0) {
            return ret;
        }
    }

    /* b4 */
    if (h4 && b4 && b4Sz) {
        h4Sz = XSTRLEN(h4);
        tempSz = h4Sz / 2;
        if (tempSz > *b4Sz || tempSz <= 0) {
            return BUFFER_E;
        }
        *b4Sz = (word32)tempSz;

        ret = Base16_Decode((const byte*)h4, (word32)h4Sz, b4, b4Sz);
        if (ret != 0) {
            return ret;
        }
    }

    return 0;
}



/* 0 on success */
#if !defined(NO_AES) && !defined(NO_AES_CBC)
static int AesKnownAnswerTest(const char* key, const char* iv,
                              const char* plainText, const char* cbc)
{
    Aes   aes;

    word32 keySz   = FIPS_AES_KEY_SZ;
    word32 ivSz    = FIPS_AES_IV_SZ;
    word32 plainSz = FIPS_AES_PLAIN_SZ;
    word32 cbcSz   = FIPS_AES_CBC_SZ;

    byte binKey   [FIPS_AES_KEY_SZ];    /* AES_Key is 32 bytes */
    byte binIv    [FIPS_AES_IV_SZ];     /* AES_IV is 32 bytes */
    byte binPlain [FIPS_AES_PLAIN_SZ];  /* AES_Plain is 128 bytes */
    byte binCbc   [FIPS_AES_CBC_SZ];    /* AES_Cbc is 128 bytes */
    byte cipher   [FIPS_AES_CIPHER_SZ]; /* for cipher (same as plainSz */

    int ret = ConvertHexToBin(key, binKey, &keySz,
                              iv,  binIv,  &ivSz,
                              plainText, binPlain,  &plainSz,
                              cbc, binCbc,  &cbcSz);

    if (ret == 0)
        ret = wc_AesInit(&aes, NULL, INVALID_DEVID);

    if (ret == 0)
        ret = wc_AesSetKey_fips(&aes, binKey, keySz, binIv, AES_ENCRYPTION);

    if (ret == 0)
        ret = wc_AesCbcEncrypt_fips(&aes, cipher, binPlain, plainSz);

    if (ret == 0) {
        if (XMEMCMP(cipher, binCbc, plainSz) != 0) {
            ret = WC_FAILURE;
        }
    }

    if (ret == 0)
        ret = wc_AesSetKey_fips(&aes, binKey, keySz, binIv, AES_DECRYPTION);

    /* decrypt cipher in place back to plain for verify */
    if (ret == 0)
        ret = wc_AesCbcDecrypt_fips(&aes, cipher, cipher, plainSz);

    if (ret == 0) {
        if (XMEMCMP(cipher, binPlain, plainSz) != 0) {
            ret =  WC_FAILURE;
        }
    }

    wc_AesFree(&aes);

    return ret;
}
#endif /* NO_AES */


/* 0 on success */
#ifdef HAVE_AESGCM
static int AesGcm_KnownAnswerTest(int decrypt,
                                  const char* key, const char* iv,
                                  const char* plain, const char* auth,
                                  const char* cipher, const char* tag)
{
    Aes aes;

    byte binKey    [FIPS_GCM_KEY_SZ];    /* key */
    byte binIv     [FIPS_GCM_IV_SZ];     /* iv */
    byte binPlain  [FIPS_GCM_PLAIN_SZ];  /* plain */
    byte binAuth   [FIPS_GCM_AUTH_SZ];   /* auth */
    byte binCipher [FIPS_GCM_CIPHER_SZ]; /* cipher */
    byte binTag    [FIPS_GCM_TAG_SZ];    /* tag */
    byte out       [FIPS_GCM_OUT_SZ];    /* out */
    byte check     [FIPS_GCM_CHECK_SZ];  /* check */
    byte checkIv   [FIPS_GCM_IV_SZ];     /* check IV */

    word32 binKeySz   = FIPS_GCM_KEY_SZ,     binIvSz   = FIPS_GCM_IV_SZ,
           binPlainSz = FIPS_GCM_PLAIN_SZ,   binAuthSz = FIPS_GCM_AUTH_SZ,
           binCipherSz = FIPS_GCM_CIPHER_SZ, binTagSz  = FIPS_GCM_TAG_SZ;

    int ret = ConvertHexToBin(key, binKey, &binKeySz, iv, binIv, &binIvSz,
                              NULL, NULL, NULL, NULL, NULL, NULL);

    if (ret == 0)
        ret = wc_AesInit(&aes, NULL, INVALID_DEVID);

    if (ret == 0)
        ret = ConvertHexToBin(plain, binPlain, &binPlainSz,
                              auth, binAuth, &binAuthSz,
                              cipher, binCipher, &binCipherSz,
                              tag, binTag, &binTagSz);
    if (ret == 0)
        ret = wc_AesGcmSetKey_fips(&aes, binKey, binKeySz);

    if (decrypt && ret == 0) {
        ret = wc_AesGcmDecrypt_fips(&aes, out, binCipher,
                                 binCipherSz, binIv, binIvSz,
                                 binTag, binTagSz,
                                 binAuth, binAuthSz);
        if (ret == 0) {
            if (XMEMCMP(binPlain, out, binPlainSz) != 0) {
                ret = WC_FAILURE;
            }
        }
    }
    else {

        if (ret == 0)
            ret = wc_AesGcmSetExtIV_fips(&aes, binIv, binIvSz);

        if (ret == 0)
            ret = wc_AesGcmEncrypt_fips(&aes, out, binPlain, binPlainSz,
                                        checkIv, sizeof(checkIv),
                                        check, binTagSz,
                                        binAuth, binAuthSz);
        if (ret == 0) {
            if (XMEMCMP(binIv, checkIv, binIvSz) != 0 ||
                XMEMCMP(binCipher, out, binCipherSz) != 0 ||
                XMEMCMP(binTag, check, binTagSz) != 0) {
                ret = WC_FAILURE;
            }
        }
    }

    wc_AesFree(&aes);

    return ret;
}
#endif /* HAVE_AESGCM */


#if !defined(NO_SHA) || !defined(NO_SHA256) || defined(WOLFSSL_SHA512) || \
    defined(WOLFSSL_SHA3)
/* 0 on success */
static int HMAC_KnownAnswerTest(int type, const char* key, const char* msg,
                                const char* digest)
{
    Hmac        hmac;
    const byte* binMsg    = (const byte*)msg;
    byte        final[FIPS_MAX_DIGEST_SZ];

    word32 msgSz    = (word32)XSTRLEN(msg);
    word32 digestSz = FIPS_HMAC_DIGEST_SZ;
    word32 keySz    = FIPS_HMAC_KEY_SZ;

    byte binDigest [FIPS_HMAC_DIGEST_SZ]; /* Longest HMAC Digest 128 bytes */
    byte binKey    [FIPS_HMAC_KEY_SZ];    /* Longest HMAC Key is 128 bytes */

    int ret = ConvertHexToBin(digest, binDigest, &digestSz,
                              key, binKey, &keySz,
                              NULL, NULL, NULL,
                              NULL, NULL, NULL);
    if (ret == 0)
        ret = wc_HmacInit(&hmac, NULL, INVALID_DEVID);

    if (ret == 0) {
        ret = wc_HmacSetKey_fips(&hmac, type, binKey, keySz);

        if (ret == 0)
            ret = wc_HmacUpdate_fips(&hmac, binMsg, msgSz);

        if (ret == 0)
            ret = wc_HmacFinal_fips(&hmac, final);

        wc_HmacFree_fips(&hmac);
    }

    if (ret == 0) {
        if (XMEMCMP(final, binDigest, digestSz) != 0) {
            ret = WC_FAILURE;
        }
    }

    return ret;
}
#endif

/* 0 on success */
#ifdef HAVE_HASHDRBG
static int DRBG_KnownAnswerTest(int reseed, const char* entropyA,
                                const char* entropyB, const char* output)
{
    word32 binEntropyASz = FIPS_DRBG_EA_SZ;
    word32 binEntropyBSz = FIPS_DRBG_EB_SZ;
    word32 binOutputSz   = FIPS_DRBG_OUT_SZ;

    byte check[WC_SHA256_DIGEST_SIZE * 4];

    byte binEntropyA [FIPS_DRBG_EA_SZ];  /* entropyA */
    byte binEntropyB [FIPS_DRBG_EB_SZ];  /* entropyB */
    byte binOutput   [FIPS_DRBG_OUT_SZ]; /* output */

    int ret = ConvertHexToBin(entropyA, binEntropyA, &binEntropyASz,
                              entropyB, binEntropyB, &binEntropyBSz,
                              output, binOutput, &binOutputSz,
                              NULL, NULL, NULL);
    if (ret != 0)
        return ret;

    /* Test Body */
    ret = wc_RNG_HealthTest_fips(reseed, binEntropyA, binEntropyASz,
                                      binEntropyB, binEntropyBSz,
                                      check, sizeof(check));
    if (ret != 0) {
        return ret;
    }

    if (XMEMCMP(binOutput, check, sizeof(check)) != 0) {
        return WC_FAILURE;
    }

    return 0;
}
#endif /* HAVE_HASHDRBG */


#if defined(HAVE_ECC_CDH) && defined(HAVE_ECC_CDH_CAST)

static int ECC_CDH_KnownAnswerTest(const char* ax, const char* ay,
                                   const char* d, const char* ix,
                                   const char* iy, const char* z)
{
#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
    ecc_key *pub_key = NULL, *priv_key = NULL;
    byte *sharedA = NULL;
    byte *sharedB = NULL;
#else
    ecc_key pub_key[1], priv_key[1];
    byte sharedA[FIPS_ECC_256_SZ] = {0};
    byte sharedB[FIPS_ECC_256_SZ] = {0};
#endif
    word32 aSz  = FIPS_ECC_256_SZ;
    word32 bSz  = FIPS_ECC_256_SZ;

#ifdef ECC_TIMING_RESISTANT
    WC_RNG rng;
    int rng_inited = 0;
#endif

    int ret;

    do {
#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
        if (((pub_key = (ecc_key *)XMALLOC(sizeof(*pub_key), NULL, DYNAMIC_TYPE_TMP_BUFFER)) == NULL) ||
            ((priv_key = (ecc_key *)XMALLOC(sizeof(*priv_key), NULL, DYNAMIC_TYPE_TMP_BUFFER)) == NULL) ||
            ((sharedA = (byte *)XMALLOC(FIPS_ECC_256_SZ, NULL, DYNAMIC_TYPE_TMP_BUFFER)) == NULL) ||
            ((sharedB = (byte *)XMALLOC(FIPS_ECC_256_SZ, NULL, DYNAMIC_TYPE_TMP_BUFFER)) == NULL)) {
            ret = MEMORY_E;
            break;
        }
#endif

        /* setup private and public keys */
        ret = wc_ecc_init(pub_key);
        if (ret != 0) {
            break;
        }
        ret = wc_ecc_init(priv_key);
        if (ret != 0) {
            wc_ecc_free(pub_key);
            break;
        }
#ifdef ECC_TIMING_RESISTANT
        ret = wc_InitRng(&rng);
        if (ret != 0)
            break;
        rng_inited = 1;
        ret = wc_ecc_set_rng(priv_key, &rng);
        if (ret != 0)
            break;
#endif
        ret = wc_ecc_set_flags(priv_key, WC_ECC_FLAG_COFACTOR);
        if (ret != 0)
            break;

        ret = wc_ecc_import_raw(pub_key, ax, ay, NULL, "SECP256R1");
        if (ret != 0)
            break;

        ret = wc_ecc_import_raw(priv_key, ix, iy, d, "SECP256R1");
        if (ret != 0)
            break;

        /* compute ECC Cofactor shared secret */
        ret = wc_ecc_shared_secret(priv_key, pub_key, sharedA, &aSz);
        if (ret != 0)
            break;

        /* read in expected Z */
        ret = Base16_Decode((const byte*)z, (word32)XSTRLEN(z), sharedB, &bSz);
        if (ret != 0)
            break;

        /* compare results */
        if (aSz != bSz || XMEMCMP(sharedA, sharedB, aSz) != 0)
            ret = WC_FAILURE;

    } while (0);

#ifdef ECC_TIMING_RESISTANT
    if (rng_inited)
        wc_FreeRng(&rng);
#endif

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
    if (sharedB)
        XFREE(sharedB, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (sharedA)
        XFREE(sharedA, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (priv_key != NULL) {
        wc_ecc_free(priv_key);
        XFREE(priv_key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (pub_key != NULL) {
        wc_ecc_free(pub_key);
        XFREE(pub_key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
#else
    wc_ecc_free(priv_key);
    wc_ecc_free(pub_key);
#endif

    return ret;
}

#endif /* HAVE_ECC && HAVE_ECC_CDH */


#ifndef NO_RSA
static int RsaSignPKCS1v15_KnownAnswerTest(int type, int keySz,
        const char* msg, const char* sig)
{
#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
    RsaKey      *rsa = NULL;
    byte        *final = NULL;
    byte        *verify = NULL;
    byte        *binSig = NULL;
    byte        *result = NULL;
#else
    RsaKey      rsa[1];
    byte        final[FIPS_MAX_DIGEST_SZ];
    byte        verify[FIPS_MAX_DIGEST_SZ];
    byte        binSig[FIPS_RSA_SIG_SZ];    /* signature */
    byte        result[FIPS_RSA_RESULT_SZ]; /* result */
#endif
    const byte* binMsg = (const byte*)msg;
    const byte* key = NULL;
    word32 msgSz    = (word32)XSTRLEN(msg);
    word32 sigSz    = FIPS_RSA_SIG_SZ;
    word32 digestSz = 0;
    word32 verifySz = FIPS_MAX_DIGEST_SZ;
    word32 resultSz = FIPS_RSA_RESULT_SZ;
    word32 idx      = 0;
    int rsa_inited = 0;
    int ret;

    do {
#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
        if (((rsa = (RsaKey *)XMALLOC(sizeof *rsa, NULL, DYNAMIC_TYPE_TMP_BUFFER)) == NULL) ||
            ((final = (byte *)XMALLOC(FIPS_MAX_DIGEST_SZ, NULL, DYNAMIC_TYPE_TMP_BUFFER)) == NULL) ||
            ((verify = (byte *)XMALLOC(FIPS_MAX_DIGEST_SZ, NULL, DYNAMIC_TYPE_TMP_BUFFER)) == NULL) ||
            ((binSig = (byte *)XMALLOC(FIPS_RSA_SIG_SZ, NULL, DYNAMIC_TYPE_TMP_BUFFER)) == NULL) ||
            ((result = (byte *)XMALLOC(FIPS_RSA_RESULT_SZ, NULL, DYNAMIC_TYPE_TMP_BUFFER)) == NULL)) {
            ret = MEMORY_E;
            break;
        }
#endif

        ret = ConvertHexToBin(sig, binSig, &sigSz,
                              NULL, NULL, NULL,
                              NULL, NULL, NULL,
                              NULL, NULL, NULL);
        if (ret != 0)
            break;

        ret = wc_InitRsaKey_fips(rsa, NULL);
        if (ret != 0)
            break;
        rsa_inited = 1;

        switch (type) {
    #ifndef NO_SHA256
        case WC_SHA256:
        {
            wc_Sha256 sha256;

            wc_InitSha256_fips(&sha256);
            wc_Sha256Update_fips(&sha256, binMsg, msgSz);
            wc_Sha256Final_fips(&sha256, final);
            digestSz = WC_SHA256_DIGEST_SIZE;
            break;
        }
    #endif /* !NO_SHA256 */
    #ifdef WOLFSSL_SHA384
        case WC_SHA384:
        {
            wc_Sha384 sha384;

            wc_InitSha384_fips(&sha384);
            wc_Sha384Update_fips(&sha384, binMsg, msgSz);
            wc_Sha384Final_fips(&sha384, final);
            digestSz = WC_SHA384_DIGEST_SIZE;
            break;
        }
    #endif
        default:
            ret = WC_FAILURE;
            break;
        }
        if (ret != 0)
            break;

        switch (keySz) {
        case 2048:
            key = client_key_der_2048;
            keySz = sizeof_client_key_der_2048;
            break;
        default:
            ret = WC_FAILURE;
            break;
        }

        if (ret != 0)
            break;

        ret = wc_RsaPrivateKeyDecode(key, &idx, rsa,
                                     (word32)keySz);
        if (ret != 0)
            break;

        ret = wc_RsaSSL_Sign_fips(final, digestSz, result, resultSz, rsa, NULL);
        if (ret != (int)sigSz)
            break;

        if (XMEMCMP(result, binSig, sigSz) != 0) {
            ret = WC_FAILURE;
            break;
        }

        ret = wc_RsaSSL_Verify_fips(result, sigSz, verify, verifySz, rsa);
        if (ret != (int)digestSz)
            break;

        if (XMEMCMP(verify, final, digestSz) != 0) {
            ret = WC_FAILURE;
            break;
        }

        ret = 0;

    } while (0);

    if (rsa_inited)
        wc_FreeRsaKey_fips(rsa);

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
    if (rsa != NULL)
        XFREE(rsa, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (final != NULL)
        XFREE(final, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (verify != NULL)
        XFREE(verify, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (binSig != NULL)
        XFREE(binSig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (result != NULL)
        XFREE(result, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}
#endif /* NO_RSA */


#if defined(HAVE_ECC) && defined(HAVE_ECC_DHE)
static int EccPrimitiveZ_KnownAnswerTest(
            const char* qexServer, const char* qeyServer,
            const char* qexClient, const char* qeyClient,
            const char* deClient, const char* zVerify)
{
    word32 zVerifyFlatSz = WC_SHA256_DIGEST_SIZE;
    word32 zSz = FIPS_ECC_256_SZ;
#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
    word32 zHashSz = WC_SHA256_DIGEST_SIZE;
    ecc_key *serverKey = NULL, *clientKey = NULL;
    wc_Sha256 *sha = NULL;
    byte *z = NULL;
    byte *zVerifyFlat = NULL;
    byte *zHash = NULL;
#else
    ecc_key serverKey[1], clientKey[1];
    wc_Sha256 sha[1];
    byte z[FIPS_ECC_256_SZ];
    byte zVerifyFlat[WC_SHA256_DIGEST_SIZE];
    byte zHash[WC_SHA256_DIGEST_SIZE];
#endif
    int ret;
#ifdef ECC_TIMING_RESISTANT
    WC_RNG rng;
    int rng_inited = 0;
#endif
    int sha_inited = 0;
    int serverKey_inited = 0;
    int clientKey_inited = 0;

    do {
#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
        if (((serverKey = (ecc_key *)XMALLOC(sizeof(*serverKey), NULL, DYNAMIC_TYPE_TMP_BUFFER)) == NULL) ||
            ((clientKey = (ecc_key *)XMALLOC(sizeof(*clientKey), NULL, DYNAMIC_TYPE_TMP_BUFFER)) == NULL) ||
            ((sha = (wc_Sha256 *)XMALLOC(sizeof(*sha), NULL, DYNAMIC_TYPE_TMP_BUFFER)) == NULL) ||
            ((z = (byte *)XMALLOC(zSz, NULL, DYNAMIC_TYPE_TMP_BUFFER)) == NULL) ||
            ((zVerifyFlat = (byte *)XMALLOC(zVerifyFlatSz, NULL, DYNAMIC_TYPE_TMP_BUFFER)) == NULL) ||
            ((zHash = (byte *)XMALLOC(zHashSz, NULL, DYNAMIC_TYPE_TMP_BUFFER)) == NULL)) {
            ret = MEMORY_E;
            break;
        }
#endif

        ret = ConvertHexToBin(zVerify, zVerifyFlat, &zVerifyFlatSz,
                              NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        if (ret != 0)
            break;
#ifdef ECC_TIMING_RESISTANT
        ret = wc_InitRng(&rng);
        if (ret != 0)
            break;
        rng_inited = 1;
#endif
        ret = wc_ecc_init(serverKey);
        if (ret != 0)
            break;
        serverKey_inited = 1;
        ret = wc_ecc_init(clientKey);
        if (ret != 0)
            break;
        clientKey_inited = 1;
#ifdef ECC_TIMING_RESISTANT
        ret = wc_ecc_set_rng(clientKey, &rng);
        if (ret != 0)
            break;
#endif
        ret = wc_ecc_import_raw_ex(serverKey, qexServer, qeyServer,
                                   NULL, ECC_SECP256R1);
        if (ret != 0)
            break;
        ret = wc_ecc_check_key(serverKey);
        if (ret != 0)
            break;
        ret = wc_ecc_import_raw_ex(clientKey, qexClient, qeyClient,
                                   deClient, ECC_SECP256R1);
        if (ret != 0)
            break;
        ret = wc_ecc_check_key(clientKey);
        if (ret != 0)
            break;
        ret = wolfCrypt_SetPrivateKeyReadEnable_fips(1, WC_KEYTYPE_ALL);
        if (ret == 0)
            ret = wc_ecc_shared_secret(clientKey, serverKey, z, &zSz);
        if (ret != 0) {
            wolfCrypt_SetPrivateKeyReadEnable_fips(0, WC_KEYTYPE_ALL);
            break;
        }
        ret = wolfCrypt_SetPrivateKeyReadEnable_fips(0, WC_KEYTYPE_ALL);
        if (ret == 0)
            ret = wc_InitSha256(sha);
        if (ret != 0)
            break;
        sha_inited = 1;
        ret = wc_Sha256Update(sha, z, zSz);
        if (ret != 0)
            break;
        ret = wc_Sha256Final(sha, zHash);
        if (ret != 0)
            break;
        if ((zVerifyFlatSz != zSz) || XMEMCMP(zHash, zVerifyFlat, zSz)) {
            ret = ECDHE_KAT_FIPS_E;
            break;
        }
    } while (0);

    if (sha_inited)
        wc_Sha256Free(sha);
    if (serverKey_inited)
        wc_ecc_free(serverKey);
    if (clientKey_inited)
        wc_ecc_free(clientKey);
#ifdef ECC_TIMING_RESISTANT
    if (rng_inited)
        wc_FreeRng(&rng);
#endif

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
    if (serverKey)
        XFREE(serverKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (clientKey)
        XFREE(clientKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (sha)
        XFREE(sha, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (z)
        XFREE(z, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (zVerifyFlat)
        XFREE(zVerifyFlat, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (zHash)
        XFREE(zHash, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}
#endif /* HAVE_ECC && HAVE_ECC_DHE */


#ifndef NO_DH

static int DhPrimitiveZ_KnownAnswerTest(const char* p, const char* q, const char* g,
                                        const char* xClient, const char* yServer,
                                        const char* zVerify)
{
    word32 pFlatSz = FIPS_FFC_FIELD_SZ;
    word32 qFlatSz = FIPS_FFC_ORDER_SZ;
    word32 gFlatSz = FIPS_FFC_FIELD_SZ;
    word32 yServerFlatSz = FIPS_FFC_FIELD_SZ;
    word32 xClientFlatSz = FIPS_FFC_ORDER_SZ;
    word32 zVerifyFlatSz = WC_SHA256_DIGEST_SIZE;
    word32 zSz = FIPS_FFC_FIELD_SZ;
#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
    word32 zHashSz = WC_SHA256_DIGEST_SIZE;
    DhKey *dh = NULL;
    wc_Sha256 *sha = NULL;
    byte *pFlat = NULL;
    byte *qFlat = NULL;
    byte *gFlat = NULL;
    byte *yServerFlat = NULL;
    byte *xClientFlat = NULL;
    byte *zVerifyFlat = NULL;
    byte *z = NULL;
    byte *zHash = NULL;
#else
    DhKey dh[1];
    wc_Sha256 sha[1];
    byte pFlat[FIPS_FFC_FIELD_SZ];
    byte qFlat[FIPS_FFC_ORDER_SZ];
    byte gFlat[FIPS_FFC_FIELD_SZ];
    byte yServerFlat[FIPS_FFC_FIELD_SZ];
    byte xClientFlat[FIPS_FFC_ORDER_SZ];
    byte zVerifyFlat[WC_SHA256_DIGEST_SIZE];
    byte z[FIPS_FFC_FIELD_SZ];
    byte zHash[WC_SHA256_DIGEST_SIZE];
#endif
    int ret;
    int dh_key_inited = 0;
    int sha_inited = 0;

    do {
#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
        if (((dh = (DhKey *)XMALLOC(sizeof(*dh), NULL, DYNAMIC_TYPE_TMP_BUFFER)) == NULL) ||
            ((sha = (wc_Sha256 *)XMALLOC(sizeof(*sha), NULL, DYNAMIC_TYPE_TMP_BUFFER)) == NULL) ||
            ((pFlat = (byte *)XMALLOC(pFlatSz, NULL, DYNAMIC_TYPE_TMP_BUFFER)) == NULL) ||
            ((qFlat = (byte *)XMALLOC(qFlatSz, NULL, DYNAMIC_TYPE_TMP_BUFFER)) == NULL) ||
            ((gFlat = (byte *)XMALLOC(gFlatSz, NULL, DYNAMIC_TYPE_TMP_BUFFER)) == NULL) ||
            ((yServerFlat = (byte *)XMALLOC(yServerFlatSz, NULL, DYNAMIC_TYPE_TMP_BUFFER)) == NULL) ||
            ((xClientFlat = (byte *)XMALLOC(xClientFlatSz, NULL, DYNAMIC_TYPE_TMP_BUFFER)) == NULL) ||
            ((zVerifyFlat = (byte *)XMALLOC(zVerifyFlatSz, NULL, DYNAMIC_TYPE_TMP_BUFFER)) == NULL) ||
            ((z = (byte *)XMALLOC(zSz, NULL, DYNAMIC_TYPE_TMP_BUFFER)) == NULL) ||
            ((zHash = (byte *)XMALLOC(zHashSz, NULL, DYNAMIC_TYPE_TMP_BUFFER)) == NULL)) {
            ret = MEMORY_E;
            break;
        }
#endif

        ret = ConvertHexToBin(yServer, yServerFlat, &yServerFlatSz,
                              xClient, xClientFlat, &xClientFlatSz,
                              zVerify, zVerifyFlat, &zVerifyFlatSz,
                              NULL, NULL, NULL);
        if (ret != 0)
            break;

        ret = ConvertHexToBin(p, pFlat, &pFlatSz, g, gFlat, &gFlatSz,
                              q, qFlat, &qFlatSz, NULL, NULL, NULL);
        if (ret != 0)
            break;

        ret = wc_InitDhKey(dh);
        if (ret != 0)
            break;
        dh_key_inited = 1;

        ret = wc_DhSetKey_ex(dh, pFlat, pFlatSz, gFlat, gFlatSz, qFlat, qFlatSz);
        if (ret != 0)
            break;

        ret = wolfCrypt_SetPrivateKeyReadEnable_fips(1, WC_KEYTYPE_ALL);
        if (ret == 0)
            ret = wc_DhAgree(dh, z, &zSz, xClientFlat, xClientFlatSz,
                             yServerFlat, yServerFlatSz);
        if (ret != 0) {
            wolfCrypt_SetPrivateKeyReadEnable_fips(0, WC_KEYTYPE_ALL);
            break;
        }
        ret = wolfCrypt_SetPrivateKeyReadEnable_fips(0, WC_KEYTYPE_ALL);

        if (ret == 0)
            ret = wc_InitSha256(sha);
        if (ret != 0)
            break;
        sha_inited = 1;
        ret = wc_Sha256Update(sha, z, zSz);
        if (ret != 0)
            break;
        ret = wc_Sha256Final(sha, zHash);
        if (ret != 0)
            break;

        if (XMEMCMP(zHash, zVerifyFlat, zVerifyFlatSz) != 0) {
            ret = DH_KAT_FIPS_E;
            break;
        }

        ret = 0;
    } while (0);

    if (dh_key_inited)
        wc_FreeDhKey(dh);
    if (sha_inited)
        wc_Sha256Free(sha);

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
    if (dh)
        XFREE(dh, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (sha)
        XFREE(sha, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (pFlat)
        XFREE(pFlat, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (qFlat)
        XFREE(qFlat, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (gFlat)
        XFREE(gFlat, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (yServerFlat)
        XFREE(yServerFlat, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (xClientFlat)
        XFREE(xClientFlat, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (zVerifyFlat)
        XFREE(zVerifyFlat, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (z)
        XFREE(z, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (zHash)
        XFREE(zHash, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}

#endif /* NO_DH */


#ifdef HAVE_ECC
#if defined(HAVE_ECC_SIGN) && defined(HAVE_ECC_VERIFY)

static int ECDSA_KnownAnswerTest(const char* msg, const char* checkSigText,
    int hashType, const unsigned char* keyDer, word32 keyDerSz)
{
#define ECDSA_SIG_BUF_SIZE ((FIPS_ECC_CURVE_SZ+1) * 2 + 6)
#define ECDSA_CHECKSIG_BUF_SIZE ((FIPS_ECC_CURVE_SZ+1) * 2 + 6)
#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
    ecc_key     *ecc = NULL;
    byte        *digest= NULL;
    byte        *checkSig = NULL;
    byte        *sig = NULL;
#else
    ecc_key     ecc[1];
    byte        digest[FIPS_MAX_DIGEST_SZ];
    byte        checkSig[(FIPS_ECC_CURVE_SZ+1) * 2 + 6];
    byte        sig[(FIPS_ECC_CURVE_SZ+1) * 2 + 6];
#endif
    WC_RNG      rng;
#ifndef WOLFSSL_KCAPI_ECC
    byte        k[4] = {0xDE, 0xAD, 0xBE, 0xEF};
#endif
    word32      checkSigSz = (word32)ECDSA_CHECKSIG_BUF_SIZE;
    word32      sigSz      = (word32)ECDSA_SIG_BUF_SIZE;
    word32      digestSz   = 0;
    word32      idx        = 0;
    int         verify     = 0;
    int         ret;
    int         rng_inited = 0;
    int         ecc_inited = 0;

    if (msg == NULL || checkSigText == NULL)
        return BAD_FUNC_ARG;

    do {
#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
        if (((ecc = (ecc_key *)XMALLOC(sizeof(*ecc), NULL, DYNAMIC_TYPE_TMP_BUFFER)) == NULL) ||
            ((digest = (byte *)XMALLOC(FIPS_MAX_DIGEST_SZ, NULL, DYNAMIC_TYPE_TMP_BUFFER)) == NULL) ||
            ((checkSig = (byte *)XMALLOC((FIPS_ECC_CURVE_SZ+1) * 2 + 6, NULL, DYNAMIC_TYPE_TMP_BUFFER)) == NULL) ||
            ((sig = (byte *)XMALLOC((FIPS_ECC_CURVE_SZ+1) * 2 + 6, NULL, DYNAMIC_TYPE_TMP_BUFFER)) == NULL)) {
            ret = MEMORY_E;
            break;
        }
#endif

        ret = ConvertHexToBin(checkSigText, checkSig, &checkSigSz,
                              NULL, NULL, NULL,
                              NULL, NULL, NULL,
                              NULL, NULL, NULL);
        if (ret != 0)
            break;

        switch (hashType) {
        #ifndef NO_SHA256
            case WC_SHA256:
            {
            #if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
                wc_Sha256* sha = (wc_Sha256*)XMALLOC(sizeof(wc_Sha256), NULL,
                    DYNAMIC_TYPE_TMP_BUFFER);
                if (sha == NULL) {
                    ret = MEMORY_E; break;
                }
            #else
                wc_Sha256  sha[1];
            #endif

                ret = wc_InitSha256_fips(sha);
                if (ret == 0) {
                    ret = wc_Sha256Update_fips(sha, (const byte*)msg,
                        (word32)XSTRLEN(msg));
                    if (ret == 0)
                        ret = wc_Sha256Final_fips(sha, digest);
                    wc_Sha256Free(sha);
                }
                digestSz = WC_SHA256_DIGEST_SIZE;
            #if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
                if (sha)
                    XFREE(sha, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            #endif
                break;
            }
        #endif
        #ifdef WOLFSSL_SHA384
            case WC_SHA384:
            {
            #if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
                wc_Sha384* sha = (wc_Sha384*)XMALLOC(sizeof(wc_Sha384), NULL,
                    DYNAMIC_TYPE_TMP_BUFFER);
                if (sha == NULL) {
                    ret = MEMORY_E; break;
                }
            #else
                wc_Sha384  sha[1];
            #endif

                ret = wc_InitSha384_fips(sha);
                if (ret == 0) {
                    ret = wc_Sha384Update_fips(sha, (const byte*)msg,
                        (word32)XSTRLEN(msg));
                    if (ret == 0)
                        ret = wc_Sha384Final_fips(sha, digest);
                    wc_Sha384Free(sha);
                }
                digestSz = WC_SHA384_DIGEST_SIZE;
            #if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
                if (sha)
                    XFREE(sha, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            #endif
                break;
            }
        #endif
        }
        if (ret != 0)
            break;

        ret = wc_ecc_init(ecc);
        if (ret != 0)
            break;
        ecc_inited = 1;
        ret = wc_EccPrivateKeyDecode(keyDer, &idx, ecc, keyDerSz);
        if (ret != 0)
            break;

        ret = wc_InitRng(&rng);
        if (ret != 0)
            break;
        rng_inited = 1;

    #ifndef WOLFSSL_KCAPI_ECC
        wc_ecc_sign_set_k(k, (word32)sizeof(k), ecc);
    #endif

        ret = wc_ecc_sign_hash(digest, digestSz, sig, &sigSz, &rng, ecc);
        if (ret != 0)
            break;

    #ifndef WOLFSSL_KCAPI_ECC
        if (checkSigSz != sigSz || XMEMCMP(checkSig, sig, sigSz) != 0) {
            ret = ECDSA_PAT_FIPS_E;
            break;
        }
    #endif

        ret = wc_ecc_verify_hash(sig, sigSz, digest, digestSz, &verify, ecc);
        if (ret != 0)
            break;

        if (verify != 1) {
            ret = ECDSA_PAT_FIPS_E;
            break;
        }

    } while (0);

    if (rng_inited)
        wc_FreeRng(&rng);
    if (ecc_inited)
        wc_ecc_free(ecc);


#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
    if (ecc)
        XFREE(ecc, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (digest)
        XFREE(digest, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (checkSig)
        XFREE(checkSig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (sig)
        XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
#undef ECDSA_SIG_BUF_SIZE
#undef ECDSA_CHECKSIG_BUF_SIZE
}

#elif defined(HAVE_ECC_VERIFY)

static int ECDSA_KnownAnswerTest(const char* digest,
     const char* qXY, const char* rs, int curveId)
{
    int         ret;
    ecc_key     ecc;
    int         verify = 0;
    mp_int r, s;
    byte digestFlat[FIPS_ECC_CURVE_SZ];
    byte qXYFlat[FIPS_ECC_CURVE_SZ*2];
    byte rsFlat[FIPS_ECC_CURVE_SZ*2];
    word32 digestFlatSz = sizeof(digestFlat);
    word32 qXYFlatSz = sizeof(qXYFlat);
    word32 rsFlatSz = sizeof(rsFlat);

    ret = ConvertHexToBin(digest, digestFlat, &digestFlatSz,
                          qXY, qXYFlat, &qXYFlatSz,
                          rs, rsFlat, &rsFlatSz,
                          NULL, NULL, NULL);
    if (ret != 0) {
        return ret;
    }

    ret = wc_ecc_init(&ecc);
    if (ret != 0) {
        return ret;
    }

    ret = mp_init_multi(&r, &s, NULL, NULL, NULL, NULL);
    if (ret != MP_OKAY) {
        wc_ecc_free(&ecc);
        return ret;
    }

    /* Import signature r/s */
    if (ret == 0) {
        ret = mp_read_unsigned_bin(&r, rsFlat, FIPS_ECC_CURVE_SZ);
    }
    if (ret == 0) {
        ret = mp_read_unsigned_bin(&s, rsFlat + FIPS_ECC_CURVE_SZ, FIPS_ECC_CURVE_SZ);
    }

    /* Import public key x/y */
    ret = wc_ecc_import_unsigned(
        &ecc,
        (byte*)qXYFlat,                     /* Public "x" Coordinate */
        (byte*)qXYFlat + FIPS_ECC_CURVE_SZ, /* Public "y" Coordinate */
        NULL,                               /* Private "d" (optional) */
        curveId                             /* ECC Curve Id */
    );
    /* Make sure it was a public key imported */
    if (ret == 0 && ecc.type != ECC_PUBLICKEY) {
        ret = ECC_BAD_ARG_E;
    }
    /* Perform ECC verify */
    if (ret == 0) {
        ret = wc_ecc_verify_hash_ex(&r, &s, digestFlat, digestFlatSz,
            &verify, &ecc);
    }
    if (verify == 0) {
        ret = SIG_VERIFY_E;
    }

    mp_clear(&r);
    mp_clear(&s);
    wc_ecc_free(&ecc);

    return ret;
}

#endif
#endif /* HAVE_ECC */


#if defined(WOLFSSL_HAVE_PRF) && !defined(WOLFSSL_NO_TLS12)

static int TLSv12_KDF_KnownAnswerTest(void)
{
    static const char preMasterSecret[] =
                                  "D06F9C19BFF49B1E91E4EFE97345D089"
                                  "4E6C2E6C34A165B24540E2970875D641"
                                  "2AA6515871B389B4C199BB8389C71CED";
    static const char helloRandom[] =
                                  "162B81EDFBEAE4F25240320B87E7651C"
                                  "865564191DD782DB0B9ECA275FBA1BB9"
                                  "5A1DA3DF436D68DA86C5E7B4B4A36E46"
                                  "B977C61767983A31BE270D74517BD0F6";
    static const char masterSecret[] =
                                  "EB38B8D89B98B1C266DE44BB3CA14E83"
                                  "C32F009F9955B1D994E61D3C51EE8760"
                                  "90B4EF89CC7AF42F46E72201BFCC7977";
    static const char label[] =   "master secret";

    byte pms[48];
    byte seed[64];
    byte ms[48];
    byte result[48];

    word32 pmsSz    = (word32)sizeof(pms);
    word32 seedSz   = (word32)sizeof(seed);
    word32 msSz     = (word32)sizeof(ms);
    int ret;

    ret = ConvertHexToBin(preMasterSecret, pms, &pmsSz,
                          helloRandom, seed, &seedSz,
                          masterSecret, ms, &msSz,
                          NULL, NULL, NULL);
    if (ret != 0)
        return WC_FAILURE;

    ret = wolfCrypt_SetPrivateKeyReadEnable_fips(1, WC_KEYTYPE_ALL);
    if (ret == 0)
        ret = wc_PRF_TLSv12_fips(result, msSz, pms, pmsSz,
                                 (const byte*)label, (word32)XSTRLEN(label),
                                 seed, seedSz, 1, sha256_mac, NULL,
                                 INVALID_DEVID);

    if (ret == 0)
        ret = wolfCrypt_SetPrivateKeyReadEnable_fips(0, WC_KEYTYPE_ALL);
    else {
        wolfCrypt_SetPrivateKeyReadEnable_fips(0, WC_KEYTYPE_ALL);
        return WC_FAILURE;
    }

    if (ret != 0)
        return WC_FAILURE;

    if (XMEMCMP(result, ms, msSz) != 0)
        return WC_FAILURE;

    ForceZero(ms, msSz);

    return 0;
}
#endif /* WOLFSSL_HAVE_PRF && !WOLFSSL_NO_TLS12 */

#if defined(HAVE_HKDF) && !defined(NO_HMAC) && defined(WOLFSSL_TLS13)

static int TLSv13_KDF_KnownAnswerTest(void)
{
    static const char psk[] =
                             "83C43F2630581D3C073F81A96012717E"
                             "C513A9E4161B34E73CF5BEA1C971870B"
                             "273A";
    static const char info[] =
                             "3D60743A65070235A26F419092735FCD"
                             "007A9E10B99E9F1B1080A87A5A7DA068";
    static const char expected[] =
                             "975930A1EF9AD8F6E608A002257411E9"
                             "3290C306DB0761D87D130B8679AF9188";
    static const char protoLabel[] = "tls13 ";
    static const char label[] = "c e traffic";

    byte binPsk[34];
    byte binInfo[WC_SHA256_DIGEST_SIZE];
    byte binExpected[WC_SHA256_DIGEST_SIZE];
    byte secret[WC_SHA256_DIGEST_SIZE];
    byte result[WC_SHA256_DIGEST_SIZE];

    word32 binPskSz        = sizeof(binPsk);
    word32 binInfoSz       = sizeof(binInfo);
    word32 binExpectedSz   = sizeof(binExpected);
    word32 digestSz        = WC_SHA256_DIGEST_SIZE;
    int ret;

    ret = ConvertHexToBin(psk, binPsk, &binPskSz,
                          info, binInfo, &binInfoSz,
                          expected, binExpected, &binExpectedSz,
                          NULL, NULL, NULL);
    if (ret != 0)
        return WC_FAILURE;

    ret = wolfCrypt_SetPrivateKeyReadEnable_fips(1, WC_KEYTYPE_ALL);
    if (ret == 0)
        ret = wc_Tls13_HKDF_Extract(secret, NULL, 0, binPsk, binPskSz,
                                    WC_SHA256);
    if (ret == 0)
        ret = wolfCrypt_SetPrivateKeyReadEnable_fips(0, WC_KEYTYPE_ALL);
    else {
        wolfCrypt_SetPrivateKeyReadEnable_fips(0, WC_KEYTYPE_ALL);
        return WC_FAILURE;
    }

    if (ret == 0)
        ret = wolfCrypt_SetPrivateKeyReadEnable_fips(1, WC_KEYTYPE_ALL);
    if (ret == 0)
        ret = wc_Tls13_HKDF_Expand_Label(result, digestSz,
                secret, digestSz,
                (const byte*)protoLabel, (word32)XSTRLEN(protoLabel),
                (const byte*)label, (word32)XSTRLEN(label),
                binInfo, binInfoSz, WC_SHA256);
    if (ret == 0)
        ret = wolfCrypt_SetPrivateKeyReadEnable_fips(0, WC_KEYTYPE_ALL);
    else {
        wolfCrypt_SetPrivateKeyReadEnable_fips(0, WC_KEYTYPE_ALL);
        return WC_FAILURE;
    }

    if (ret != 0)
        return WC_FAILURE;

    if (XMEMCMP(result, binExpected, digestSz) != 0)
        return WC_FAILURE;

    ForceZero(result, digestSz);

    return 0;
}

#endif /* HAVE_HKDF && !NO_HMAC && WOLFSSL_TLS13 */


#ifdef WOLFSSL_WOLFSSH

static int SSH_KDF_KnownAnswerTest(void)
{
    static const char k[] = "0000010100FE3C0AF5C66307B1875D6B"
                            "2F5681A92DE6537B082B347A5060620D"
                            "8231FC334944848B14C6BF9087C9BBFF"
                            "B0483AF90F70CDB41DF2E2078A50D0B5"
                            "56EAD06D860EB46A4F901AFB9B706DEA"
                            "32BFCB2015B9F8539E8341FDAED41C2E"
                            "C15B01F4B3EDBE7C6950B207C46C385E"
                            "EF90DCA67E911057DF845B458A1DBA02"
                            "98DE67D3CE5D7B0E654AB22511D7D8F9"
                            "C9CB1A68D7B40C292ECF512FFC23C61B"
                            "75C4DF9C66012A09F9B35B8BBA3F2731"
                            "B3576951382FC7777BCED5F96674C2C0"
                            "D66C6439088C51321D52989E2C87F704"
                            "C9B8A3BFE49D87DAFDE829B733475C92"
                            "528713B143F1E957174DEEBF0AC45FA4"
                            "860841C2061548E91EA82AF2E468800B"
                            "12A2638B2B";
    static const char h[] = "1995920DBDE5AE9A4D9CD24B37AC041D"
                            "382E0808297FB8FDEFCC3BF2C02D93BB";
    static const char sessionId[] =
                            "6AE20F554426E0F6E8FC5569AF7DED12"
                            "244CDD0CAC80AC3FF3C7F323EFF9385A";
    static const char expected[] =
                            "190128218BE1BE482174284070DA8E4F";

    byte binK[261];
    byte binH[32];
    byte binSI[32];
    byte binExp[16];
    byte result[16];

    word32 binKSz = sizeof(binK);
    word32 binHSz = sizeof(binH);
    word32 binSISz = sizeof(binSI);
    word32 binExpSz = sizeof(binExp);
    int ret;

    ret = ConvertHexToBin(k + 8, binK, &binKSz,
                          h, binH, &binHSz,
                          sessionId, binSI, &binSISz,
                          expected, binExp, &binExpSz);
    if (ret != 0)
        return WC_FAILURE;

    ret = wolfCrypt_SetPrivateKeyReadEnable_fips(1, WC_KEYTYPE_ALL);
    if (ret == 0)
        ret = wc_SSH_KDF_fips(WC_SHA256, 'A', result, binExpSz,
                binK, binKSz, binH, binHSz, binSI, binSISz);
    if (ret == 0)
        ret = wolfCrypt_SetPrivateKeyReadEnable_fips(0, WC_KEYTYPE_ALL);
    else {
        wolfCrypt_SetPrivateKeyReadEnable_fips(0, WC_KEYTYPE_ALL);
        return WC_FAILURE;
    }

    if (ret != 0)
        return WC_FAILURE;

    if (XMEMCMP(result, binExp, binExpSz) != 0)
        return WC_FAILURE;

    return 0;
}

#endif /* WOLFSSL_WOLFSSH */

#ifdef WC_SRTP_KDF
/* SP 800-135r1 ss 5.3 KDK (keys derived from master key) IG 10.3.A note #19:
 * addresses the IKEv1 KDF and is the only reference to SP 800-135r1,
 * ss 5.3 of SP 800-135r1 is not mentioned and references to KBKDF only refer to
 * SP 800-108, SP 800-132 and SP 800-56Cr1/r2. Out of a sense of precaution a
 * self-test for SRTP KDF has been added in addition to the 1 and 2 step KDFs
 * for TLS v1.2 and TLS v1.3 already tested in case of some future update to
 * IG 10.3.A which may make it required to test SRTP-KDF exclusively.
 * All underlying algorithms for this KDF (FIPS 197) are tested explicitly.
 */
static int SRTP_KDF_KnownAnswerTest(void)
{
    static const char master_key[] = "E1F97A0D3E018BE0D64FA32C06DE4139";
    static const char master_salt[] = "0EC675AD498AFEEBB6960B3AABE6";
    static const char srtp_index[] = "000000000000";
    static const char cipher_key_exp[] = "c61e7a93744f39ee10734afe3ff7a087";
    static const char cipher_salt_exp[] = "30CBBC08863D8C85D49DB34A9AE1";
    static const char auth_key_exp[] = "cebe321f6ff7716b6fd4ab49af256a15"
                                       "6d38baa48f0a0acf3c34e2359e6cdbce"
                                       "e049646c43d9327ad175578ef7227098"
                                       "6371c10c9a369ac2f94a8c5fbcdddc25"
                                       "6d6e919a48b610ef17c2041e47403576"
                                       "6b68642c59bbfc2f34db60dbdfb2";

    byte binMK[16];   word32 binMKSz    = sizeof(binMK);
    byte binMS[14];   word32 binMSSz    = sizeof(binMS);
    byte binSRTPI[6]; word32 binSRTPISz = sizeof(binSRTPI);
    byte binCK[16];   word32 binCKSz    = sizeof(binCK);
    byte binCS[14];   word32 binCSSz    = sizeof(binCS);
    byte binAK[94];   word32 binAKSz    = sizeof(binAK);
    byte keyE[16];    word32 keyESz     = sizeof(keyE);
    byte keyS[14];    word32 keySSz     = sizeof(keyS);
    byte keyA[94];    word32 keyASz     = sizeof(keyA);

    int ret;

    ret = ConvertHexToBin(master_key,  binMK,    &binMKSz,
                          master_salt, binMS,    &binMSSz,
                          srtp_index,  binSRTPI, &binSRTPISz,
                          NULL, NULL, NULL);
    if (ret == 0)
        ret = ConvertHexToBin(cipher_key_exp,   binCK, &binCKSz,
                              cipher_salt_exp,  binCS, &binCSSz,
                              auth_key_exp,     binAK, &binAKSz,
                              NULL, NULL, NULL);

    if (ret == 0)
        ret = wolfCrypt_SetPrivateKeyReadEnable_fips(1, WC_KEYTYPE_ALL);

    if (ret == 0)
        ret = wc_SRTP_KDF(binMK, binMKSz, binMS, binMSSz, -1,
                          binSRTPI, keyE, keyESz, keyA, keyASz, keyS, keySSz);

    if (ret == 0)
        ret = wolfCrypt_SetPrivateKeyReadEnable_fips(0, WC_KEYTYPE_ALL);

    if (ret == 0)
        ret = XMEMCMP(keyE, binCK, keyESz);

    if (ret == 0)
        ret = XMEMCMP(keyS, binCS, keySSz);

    if (ret == 0)
        ret = XMEMCMP(keyA, binAK, keyASz);

    return ret;
}
#endif

#ifdef HAVE_ED25519
static int ED25519_KnownAnswerTest(void)
{
    /* Test vectors from RFC 8032 Section 7.1 TEST SHA(abc) */
    static const char priv_key[] = "833fe62409237b9d62ec77587520911e"
                                   "9a759cec1d19755b7da901b96dca3d42";
    static const char pub_key[]  = "ec172b93ad5e563bf4932c70e1245034"
                                   "c35467ef2efd4d64ebf819683467e2bf";
    static const char exp_sig[]  = "dc2a4459e7369633a52b1bf277839a00"
                                   "201009a3efbf3ecb69bea2186c26b589"
                                   "09351fc9ac90b3ecfdfbc7c66431e030"
                                   "3dca179c138ac17ad9bef1177331a704";
    static const char msg_in[]   = "ddaf35a193617abacc417349ae204131"
                                   "12e6fa4e89a97ea20a9eeee64b55d39a"
                                   "2192992a274fc1a836ba3c23a3feebbd"
                                   "454d4423643ce80e2a9ac94fa54ca49f";

    byte binPrivK[32];  word32 binPrivKSz  = sizeof(binPrivK);
    byte binPubK[32];   word32 binPubKSz   = sizeof(binPubK);
    byte binExpSig[64]; word32 binExpSigSz = sizeof(binExpSig);
    byte binInput[64];  word32 binInputSz  = sizeof(binInput);
    byte binOutput[64]; word32 binOutputSz = sizeof(binOutput);

    ed25519_key key;

    int ret;
    int verify = 0;

    ret = ConvertHexToBin(priv_key, binPrivK,  &binPrivKSz,
                          pub_key,  binPubK,   &binPubKSz,
                          exp_sig,  binExpSig, &binExpSigSz,
                          msg_in,   binInput,  &binInputSz);

    if (ret == 0)
        ret = wc_ed25519_init(&key);

    if (ret == 0)
        ret = wc_ed25519_import_private_key(binPrivK, ED25519_KEY_SIZE, binPubK,
                                            binPubKSz, &key);
    if (ret == 0)
        ret = wc_ed25519_sign_msg(binInput, binInputSz, binOutput, &binOutputSz,
                                  &key);
    if (ret == 0)
        ret = XMEMCMP(binOutput, binExpSig, binOutputSz);

    if (ret == 0)
        ret = wc_ed25519_verify_msg(binOutput, binOutputSz, binInput,
                                    binInputSz, &verify, &key);

    if (verify != 1)
        ret = ED25519_KAT_FIPS_E;

    return ret;
}
#endif

#ifdef HAVE_ED448
static int ED448_KnownAnswerTest(void)
{
    /* Test vectors from RFC 8032 Section 7.1 ED448 12-octets */
    static const char priv_key[] = "cd23d24f714274e744343237b93290f5"
                                   "11f6425f98e64459ff203e8985083ffd"
                                   "f60500553abc0e05cd02184bdb89c4cc"
                                   "d67e187951267eb328";
    static const char pub_key[]  = "dcea9e78f35a1bf3499a831b10b86c90"
                                   "aac01cd84b67a0109b55a36e9328b1e3"
                                   "65fce161d71ce7131a543ea4cb5f7e9f"
                                   "1d8b00696447001400";
    static const char exp_sig[]  = "1f0a8888ce25e8d458a21130879b840a"
                                   "9089d999aaba039eaf3e3afa090a09d3"
                                   "89dba82c4ff2ae8ac5cdfb7c55e94d5d"
                                   "961a29fe0109941e00b8dbdeea6d3b05"
                                   "1068df7254c0cdc129cbe62db2dc957d"
                                   "bb47b51fd3f213fb8698f064774250a5"
                                   "028961c9bf8ffd973fe5d5c206492b14"
                                   "0e00";
    static const char msg_in[]   = "0c3e544074ec63b0265e0c";

    byte binPrivK[64];   word32 binPrivKSz   = sizeof(binPrivK);
    byte binPubK[64];    word32 binPubKSz    = sizeof(binPubK);
    byte binExpSig[128]; word32 binExpSigSz  = sizeof(binExpSig);
    byte binInput[64];   word32 binInputSz   = sizeof(binInput);
    byte binOutput[128]; word32 binOutputSz  = sizeof(binOutput);

    ed448_key key;

    int ret;
    int verify = 0;

    ret = ConvertHexToBin(priv_key, binPrivK,  &binPrivKSz,
                          pub_key,  binPubK,   &binPubKSz,
                          exp_sig,  binExpSig, &binExpSigSz,
                          msg_in,   binInput,  &binInputSz);

    if (ret == 0)
        ret = wc_ed448_init(&key);

    if (ret == 0)
        ret = wc_ed448_import_private_key(binPrivK, ED448_KEY_SIZE, binPubK,
                                            binPubKSz, &key);
    if (ret == 0)
        ret = wc_ed448_sign_msg(binInput, binInputSz, binOutput, &binOutputSz,
                                  &key, NULL, 0);
    if (ret == 0)
        ret = XMEMCMP(binOutput, binExpSig, binOutputSz);

    if (ret == 0)
        ret = wc_ed448_verify_msg(binOutput, binOutputSz, binInput,
                                    binInputSz, &verify, &key, NULL, 0);

    if (verify != 1)
        ret = ED448_KAT_FIPS_E;

    return ret;
}
#endif

#ifdef HAVE_PBKDF2
static int PBKDF2_KnownAnswerTest(void)
{
    /* (SP800-132) (IG 10.3.A)
     * - Test must derive the master secret at a minimum
     *      (Section 5.3 SP800-132)
     * - Shall self-test ALL underlying pre-requisite algorithms
     * - Lengths and properties of the password and SALT parameters and
     *   desired length of the master key used in the CAST must all be among
     *   those supported in approved mode.
     * - Count parameter must be at least 2 (2 iterations) so as not to cause
     *   significant performance impact to the CAST.
     */

    /* Test case is based on the test from RFC 7914 Section 11
     * "Test Vectors for PBKDF2 with HMAC-SHA-256" however the iteration count
     * has been reduced from 80,000 to just 5 in keeping with (SP800-132) &
     * (IG 10.3.A), expected master secret adjusted for different iterations */


    /* See notes in hmac.c -> wc_HmacSetKey_ex regarding password length used
     * in this CAST (8-bytes or 64-bits) */

    const char passwd[] = "Password";
    const char salt[]   = "NaCl";
    int iterations = 5;
    byte derived_master_secret[64];
    static const byte expected_ms[] = {
                                0xfb, 0xb6, 0x32, 0x87, 0xda, 0x97, 0x1c, 0x6b,
                                0x37, 0xf2, 0xc3, 0x01, 0xa5, 0xaa, 0xf2, 0xab,
                                0x7d, 0xfc, 0x32, 0x8a, 0x54, 0x51, 0x2d, 0xb9,
                                0x29, 0xff, 0x24, 0xf3, 0xb3, 0xad, 0x7a, 0xd8,
                                0xee, 0xcb, 0xcf, 0x6f, 0xe7, 0x59, 0x16, 0x92,
                                0xc9, 0x0a, 0x9e, 0x76, 0x3d, 0x5f, 0x3c, 0x51,
                                0x5f, 0xdc, 0xea, 0x7a, 0xfe, 0xa5, 0xd9, 0x57,
                                0xcc, 0x89, 0x87, 0xc0, 0x1c, 0x96, 0xf5, 0xb1};
    int pwdLen;
    int saltLen;
    int kLen;

    int ret;

    kLen = (int) sizeof(derived_master_secret);
    pwdLen = (int) XSTRLEN(passwd);
    saltLen = (int) XSTRLEN(salt);

    ret = wolfCrypt_SetPrivateKeyReadEnable_fips(1, WC_KEYTYPE_ALL);

    if (ret == 0)
        ret = wc_PBKDF2(derived_master_secret, (byte*) passwd, pwdLen,
                        (byte*) salt, saltLen, iterations, kLen, WC_SHA256);

    if (ret == 0)
        ret = wolfCrypt_SetPrivateKeyReadEnable_fips(0, WC_KEYTYPE_ALL);

    if (ret == 0)
        ret = XMEMCMP(derived_master_secret, expected_ms, (size_t)kLen);

    if (ret != 0)
        ret = PBKDF2_KAT_FIPS_E;

    return ret;
}
#endif


/* dead simple base16 encoder, 0 on success */
#ifndef WOLFCRYPT_FIPS_CORE_DYNAMIC_HASH_VALUE
static
#endif
int GenBase16_Hash(const byte* in, int length, char* out, int outSz)
{
    int i;
    int idx = 0;

    if ( (length * 2 + 1) > outSz)
        return WC_FAILURE;

    for (i = 0; i < length; i++) {
        byte a = in[i] >> 4;
        byte b = in[i] & 0x0f;

        if (a > 9)
            a+=7;
        if (b > 9)
            b+=7;

        out[idx++] = (char)(a + 0x30);
        out[idx++] = (char)(b + 0x30);
    }
    out[idx++] = '\0';

    return 0;
}


/* hmac-sha256 in memory core verify hash, output to pos callback,
 * copy here when changes */

/* "WOLFCRYPT_FIPS_CORE_DYNAMIC_HASH_VALUE" is to support targets with object
 * formats and linkers that preclude purely relative (stable) branch/jump
 * targets, in which the integrity of the wolfCrypt container is confirmed
 * before runtime link by another mechanism.
 */
#ifndef WOLFCRYPT_FIPS_CORE_DYNAMIC_HASH_VALUE
WOLFSSL_LOCAL const
#endif
/* declare verifyCore volatile, to inhibit constant propagation (gcc -fipa-cp,
 * enabled by -O2, -O3, and -Os), whereby byte(s) from the hash are incorporated
 * into instructions, disrupting the hash.
 */
volatile char verifyCore[] =
#ifdef WOLFCRYPT_FIPS_CORE_HASH_VALUE
WC_STRINGIFY(WOLFCRYPT_FIPS_CORE_HASH_VALUE);
#else
"C0AA5DF55EB4F8E6BBDE5254A589D28C832DAE58980954CCEC2DD02EFAA68DD0";
#endif

#ifndef WOLFCRYPT_FIPS_CORE_DYNAMIC_HASH_VALUE
static
#endif
const char coreKey[] =
             "EAD92D38850B03D7160EA4F5C90EDD49C0B6933FAA4833213ED6F0F1596E356B";

#ifdef USE_WINDOWS_API
    #pragma warning(push)
    #pragma warning(disable:4054 4305 4311)
    /* For Windows builds, disable compiler warnings for:
     * - 4305: typecasting pointers into unsigned longs
     * - 4054: typecasting function pointer into char pointer
     * - 4311: typecasting pointer truncation
     */
#endif

/* When doing static builds printf may not be available
 * while the constructor is running especially if wolfssl is compiled into
 * Firmware or UEFI or BIOS. In those cases to debug with this:
 * 1) add a prototype for fipsEntry() in fips_test.h header
 * 2) define NO_ATTRIBUTE_CONSTRUCTOR
 * 3) Then call fipsEntry() from main() like any old function.
 * Update the linker script for compiling static builds, get the module right
 * in memory then:
 * 1) Remove the prototype of fipsEntry() from fips_test.h
 * 2) remove the define NO_ATTRIBUTE_CONSTRUCTOR
 * 3) Remove the call to fipsEntry() from main() so it runs outside user control
 *    once again
 * 4) Test to see if the issues have been resolved */

/* Inputs:
 * stxt = .text start address (lowest number / first address of module)
 * etxt = .text end address (largest number / last address of module)
 * chktxt = .text the address to check is between stxt and etxt
 * sro = .ro start address (lowest number / first address of module)
 * ero = .ro end address (largest number / last address of module)
 * chkro = .ro the address to check is between sro and ero
 * n = in the case of debugging can print this string for information
 */
int wolfCrypt_FIPS_sanity(fips_address_function stxt,
                          fips_address_function etxt,
                          fips_address_function chktxt,
                          const void* sro,
                          const void* ero,
                          const void* chkro,
                          const char* name);
int wolfCrypt_FIPS_sanity(fips_address_function stxt,
                          fips_address_function etxt,
                          fips_address_function chktxt,
                          const void* sro,
                          const void* ero,
                          const void* chkro,
                          const char* name)
{
#ifdef DEBUG_FIPS_VERBOSE
    #ifdef WOLFSSL_LINUXKM
        #define _PTR_FMT "%px"
    #else
        #define _PTR_FMT "%p"
    #endif
    printf("Sanity: Evaluating module component %s\n", name);
    printf("Sanity: start .text of module: " _PTR_FMT "\n", stxt);
    printf("Sanity: .text being evaluated: " _PTR_FMT "\n", chktxt);
    printf("Sanity: end .text   of module: " _PTR_FMT "\n", etxt);
    printf("Sanity: start .ro of module: " _PTR_FMT "\n", sro);
    printf("Sanity: .ro being evaluated: " _PTR_FMT "\n", chkro);
    printf("Sanity: end .ro   of module: " _PTR_FMT "\n", ero);
    #undef _PTR_FMT
#else
    (void) name;
#endif
    if ((unsigned long)stxt > (unsigned long)chktxt ||
        (unsigned long)etxt < (unsigned long)chktxt) {
#ifdef DEBUG_FIPS_VERBOSE
             printf("FAILED SANITY .text: -----------> %s\n", name);
#endif
             return IN_CORE_FIPS_E;
    }
#ifdef DEBUG_FIPS_VERBOSE
     else {
             printf("PASSED SANITY .text: -----------> %s\n", name);
    }
#endif
    if ((unsigned long)sro > (unsigned long)chkro ||
        (unsigned long)ero < (unsigned long)chkro) {
#ifdef DEBUG_FIPS_VERBOSE
             printf("FAILED SANITY .ro: -----------> %s\n", name);
#endif
             return IN_CORE_FIPS_E;
    }
#ifdef DEBUG_FIPS_VERBOSE
     else {
         printf("PASSED SANITY .ro: -----------> %s\n", name);
    }
#endif
    return 0;
}

/* Do in core memory integrity check, 0 on success */
static int DoInCoreCheck(char* base16_hash, int base16_hashSz)
{
    int      ret;
    Hmac     hmac;
    byte     hash[FIPS_IN_CORE_DIGEST_SIZE];
    byte     binCoreKey [FIPS_IN_CORE_KEY_SZ];
    byte     binVerify  [FIPS_IN_CORE_VERIFY_SZ];
    word32   verifySz  = (word32)sizeof(binCoreKey);
    word32   binCoreSz = (word32)sizeof(binVerify);

    /* Boundary Integrity, 1 func per .c source asm files need to be included
     * along with their parent file (aes_asm.asm goes with aes.c for example)
     * when ordering in a linker script. NOTE: Sha224 and Sha384 fall under
     * their respective truncation parent (Sha256 or Sha512) */
    fips_address_function first             = wolfCrypt_FIPS_first;
    fips_address_function last              = wolfCrypt_FIPS_last;

    char* start         = (char*)wolfCrypt_FIPS_ro_start;
    char* end           = (char*)wolfCrypt_FIPS_ro_end;

    unsigned long code_sz = 0;
    unsigned long data_sz = 0;

    /* Sanity: Can first be subtracted from last without rollover? */
    if ((unsigned long) last <= (unsigned long) first)
        return FIPS_CODE_SZ_E;

    /* Sanity: Can start be subtracted from end without rollover? */
    if ((unsigned long) end <= (unsigned long) start)
        return FIPS_DATA_SZ_E;

    /* Sanity: Is the module intact in memory? */
#ifndef NO_AES
    if (wolfCrypt_FIPS_sanity(first, last, wolfCrypt_FIPS_AES_sanity,
                              start, end, wolfCrypt_FIPS_aes_ro_sanity,
                              "aes.c") != 0) {
        return IN_CORE_FIPS_E;
    }
#if defined(WOLFSSL_CMAC) && defined(WOLFSSL_AES_DIRECT)
    if (wolfCrypt_FIPS_sanity(first, last, wolfCrypt_FIPS_CMAC_sanity,
                              start, end, wolfCrypt_FIPS_cmac_ro_sanity,
                              "cmac.c") != 0) {
        return IN_CORE_FIPS_E;
    }
#endif
#endif
#ifndef NO_DH
    if (wolfCrypt_FIPS_sanity(first, last, wolfCrypt_FIPS_DH_sanity,
                              start, end, wolfCrypt_FIPS_dh_ro_sanity,
                              "dh.c") != 0) {
        return IN_CORE_FIPS_E;
    }
#endif
#ifdef HAVE_ECC
    if (wolfCrypt_FIPS_sanity(first, last, wolfCrypt_FIPS_ECC_sanity,
                              start, end, wolfCrypt_FIPS_ecc_ro_sanity,
                              "ecc.c") != 0) {
        return IN_CORE_FIPS_E;
    }
#endif
#ifdef HAVE_ED25519
    if (wolfCrypt_FIPS_sanity(first, last, wolfCrypt_FIPS_ED25519_sanity,
                              start, end, wolfCrypt_FIPS_ed25519_ro_sanity,
                              "ed25519.c") != 0) {
        return IN_CORE_FIPS_E;
    }
#endif
#ifdef HAVE_ED448
    if (wolfCrypt_FIPS_sanity(first, last, wolfCrypt_FIPS_ED448_sanity,
                              start, end, wolfCrypt_FIPS_ed448_ro_sanity,
                              "ed448.c") != 0) {
        return IN_CORE_FIPS_E;
    }
#endif
    if (wolfCrypt_FIPS_sanity(first, last, wolfCrypt_FIPS_HMAC_sanity,
                              start, end, wolfCrypt_FIPS_hmac_ro_sanity,
                              "hmac.c") != 0) {
        return IN_CORE_FIPS_E;
    }
#ifndef NO_KDF
    if (wolfCrypt_FIPS_sanity(first, last, wolfCrypt_FIPS_KDF_sanity,
                              start, end, wolfCrypt_FIPS_kdf_ro_sanity,
                              "kdf.c") != 0) {
        return IN_CORE_FIPS_E;
    }
#endif
#ifdef HAVE_PBKDF2
    if (wolfCrypt_FIPS_sanity(first, last, wolfCrypt_FIPS_PBKDF_sanity,
                              start, end, wolfCrypt_FIPS_pbkdf_ro_sanity,
                              "pwdbased.c") != 0) {
        return IN_CORE_FIPS_E;
    }
#endif
#ifdef HAVE_HASHDRBG
    if (wolfCrypt_FIPS_sanity(first, last, wolfCrypt_FIPS_DRBG_sanity,
                              start, end, wolfCrypt_FIPS_drbg_ro_sanity,
                              "random.c") != 0) {
        return IN_CORE_FIPS_E;
    }
#endif
#ifndef NO_RSA
    if (wolfCrypt_FIPS_sanity(first, last, wolfCrypt_FIPS_RSA_sanity,
                              start, end, wolfCrypt_FIPS_rsa_ro_sanity,
                              "rsa.c") != 0) {
        return IN_CORE_FIPS_E;
    }
#endif
#ifndef NO_SHA
    if (wolfCrypt_FIPS_sanity(first, last, wolfCrypt_FIPS_SHA_sanity,
                              start, end, wolfCrypt_FIPS_sha_ro_sanity,
                              "sha.c") != 0) {
        return IN_CORE_FIPS_E;
    }
#endif
#ifndef NO_SHA256
    if (wolfCrypt_FIPS_sanity(first, last, wolfCrypt_FIPS_SHA256_sanity,
                              start, end, wolfCrypt_FIPS_sha256_ro_sanity,
                              "sha256.c") != 0) {
        return IN_CORE_FIPS_E;
    }
#endif
#ifdef WOLFSSL_SHA512
    if (wolfCrypt_FIPS_sanity(first, last, wolfCrypt_FIPS_SHA512_sanity,
                              start, end, wolfCrypt_FIPS_sha512_ro_sanity,
                              "sha512.c") != 0) {
        return IN_CORE_FIPS_E;
    }
#endif
#ifdef WOLFSSL_SHA3
    if (wolfCrypt_FIPS_sanity(first, last, wolfCrypt_FIPS_SHA3_sanity,
                              start, end, wolfCrypt_FIPS_sha3_ro_sanity,
                              "sha3.c") != 0) {
        return IN_CORE_FIPS_E;
    }
#endif
    if (wolfCrypt_FIPS_sanity(first, last, wolfCrypt_FIPS_FT_sanity,
                              start, end, wolfCrypt_FIPS_ft_ro_sanity,
                              "fips_test.c") != 0) {
        return IN_CORE_FIPS_E;
    }
    if (wolfCrypt_FIPS_sanity(first, last, wc_RunAllCast_fips,
                              start, end, wolfCrypt_FIPS_f_ro_sanity,
                              "fips.c") != 0) {
        return IN_CORE_FIPS_E;
    }

    /* // NOLINTBEGIN(clang-analyzer-security.PointerSub) */
    code_sz = (unsigned long)last - (unsigned long)first;
    data_sz = (unsigned long)end - (unsigned long)start;
    /* // NOLINTEND(clang-analyzer-security.PointerSub) */

    /* Sanity: Is data size within expected limits? */
    if (data_sz > (unsigned long) MAX_FIPS_DATA_SZ)
        return FIPS_DATA_SZ_E;  /* bad fips data size */

    /* Sanity: Is code size within expected limits? */
    if (code_sz > (unsigned long) MAX_FIPS_CODE_SZ)
        return FIPS_CODE_SZ_E;  /* bad fips code size */

    ret = ConvertHexToBin(coreKey, binCoreKey, &binCoreSz,
                          NULL, NULL, NULL,
                          NULL, NULL, NULL,
                          NULL, NULL, NULL);
    if (ret != 0) return ret;

    ret = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
    if (ret != 0) return ret;

    ret = wc_HmacSetKey_fips(&hmac, FIPS_IN_CORE_HASH_TYPE,
            binCoreKey, binCoreSz);
    if (ret != 0) return ret;

    ret = wc_HmacUpdate_fips(&hmac, (byte *)(wc_ptr_t)first, (word32)code_sz);
    if (ret != 0) return ret;

    /* don't hash verifyCore or changing verifyCore will change hash */
    if (verifyCore >= start && verifyCore < end) {
        /* // NOLINTBEGIN(clang-analyzer-security.PointerSub) */
        data_sz = (unsigned long)verifyCore - (unsigned long)start;
        ret = wc_HmacUpdate_fips(&hmac, (byte*)start, (word32)data_sz);
        if (ret != 0) return ret;
        start   = (char*)verifyCore + sizeof(verifyCore);
        data_sz = (unsigned long)end - (unsigned long)start;
        /* // NOLINTEND(clang-analyzer-security.PointerSub) */
    }
    ret = wc_HmacUpdate_fips(&hmac, (byte*)start, (word32)data_sz);
    if (ret != 0) return ret;

    ret = wc_HmacFinal_fips(&hmac, hash);
    if (ret != 0) return ret;

    wc_HmacFree_fips(&hmac);

    ret = GenBase16_Hash(hash, sizeof(hash), base16_hash, base16_hashSz);
    if (ret != 0) return ret;

    ret = ConvertHexToBin((const char *)verifyCore, binVerify, &verifySz,
                          NULL, NULL, NULL,
                          NULL, NULL, NULL,
                          NULL, NULL, NULL);
    if (ret != 0)
        return ret;

    if (XMEMCMP(hash, binVerify, sizeof(hash)) != 0) {
        ret = IN_CORE_FIPS_E;
    }
    ForceZero(hash, sizeof(hash));
    ForceZero(&hmac, sizeof(hmac));

    return ret;
}

#ifdef USE_WINDOWS_API
    #pragma warning(pop)
#endif


/*
 * in linuxkm:
 *
 * attempt to atomically change fipsCastStatus[type] from
 * !FIPS_CAST_STATE_PROCESSING to FIPS_CAST_STATE_PROCESSING.
 *
 * iff that succeeds, store the result in fipsCastStatus[type].
 * either way, return the result.
 *
 * however, if the state is already FIPS_CAST_STATE_PROCESSING on entry, return
 * success immediately to avoid recursion-induced stack overflow.
 *
 * if a second kernel execution context calls DoCAST() for an alg after a first
 * context has, but before the first context finishes, the second context will
 * falsely be returned success.  this race is wholly mitigated by running
 * wolfcrypt_test() at module load time, configured with --enable-crypttests.
 */
int DoCAST(int type)
{
#ifdef WOLFSSL_LINUXKM
    int cur_status = fipsCastStatus_get(type);
    int save_result;
    int cmpxchg_ret;
    if (cur_status == FIPS_CAST_STATE_PROCESSING)
        return 0; /* must short-circuit to avoid stack overflow. */
    else {
        cmpxchg_ret = atomic_cmpxchg(&fipsCastStatus[type], cur_status, FIPS_CAST_STATE_PROCESSING);
        if (cmpxchg_ret == cur_status)
            save_result = 1;
        else
            save_result = 0;
    }
    #define STORE_CAST_STATUS(x, y) { if (save_result) fipsCastStatus_put(x, y); }
#else
    fipsCastStatus[type] = FIPS_CAST_STATE_PROCESSING;
    #define STORE_CAST_STATUS(x, y) fipsCastStatus_put(x, y)
#endif
    switch (type) {
        case FIPS_CAST_AES_CBC:
#if !defined(NO_AES) && !defined(NO_AES_CBC)
        if (AesKnownAnswerTest(
                "2b7e151628aed2a6abf7158809cf4f3c",  /* key */
                "000102030405060708090a0b0c0d0e0f",  /* iv */
                "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac" /* plainText */
                "9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a"
                "52eff69f2445df4f9b17ad2b417be66c3710",
                "7649abac8119b246cee98e9b12e9197d5086cb9b507219" /* cbc */
                "ee95db113a917678b273bed6b8e3c1743b7116e69e2222"
                "95163ff1caa1681fac09120eca307586e1a7"
                ) != 0) {
            STORE_CAST_STATUS(FIPS_CAST_AES_CBC, FIPS_CAST_STATE_FAILURE);
            return AES_KAT_FIPS_E;
        }
        else {
            STORE_CAST_STATUS(FIPS_CAST_AES_CBC, FIPS_CAST_STATE_SUCCESS);
        }
#elif defined(WOLFSSL_AES_COUNTER) || defined(WOLFSSL_AES_OFB)
        /* if OFB or CTR is enabled we still need to set AES CBC okay */
        /* TODO: Add CAST for OFB and CTR */
        STORE_CAST_STATUS(FIPS_CAST_AES_CBC, FIPS_CAST_STATE_SUCCESS);
#endif
        break;

        case FIPS_CAST_AES_GCM:
#ifdef HAVE_AESGCM
        if (AesGcm_KnownAnswerTest(0,
                 "298efa1ccf29cf62ae6824bfc19557fc",                /* key */
                 "6f58a93fe1d207fae4ed2f6d",                        /* iv */
                 "cc38bccd6bc536ad919b1395f5d63801f99f8068d65ca5ac" /* plain */
                 "63872daf16b93901",
                 "021fafd238463973ffe80256e5b1c6b1",                /* auth */
                 "dfce4e9cd291103d7fe4e63351d9e79d3dfd391e32671046" /* cipher */
                 "58212da96521b7db",
                 "542465ef599316f73a7a560509a2d9f2"                 /* tag */
                 ) != 0) {
            STORE_CAST_STATUS(FIPS_CAST_AES_GCM, FIPS_CAST_STATE_FAILURE);
            return AESGCM_KAT_FIPS_E;
        }

        if (AesGcm_KnownAnswerTest(1,
                 "afa272c03d0343f882008f6e163d6047",                /* key */
                 "271ba21f8fdcac34dc93be54",                        /* iv */
                 "f3ee01423f192c36033542221c5545dd939de52ada18b9e8" /* plain */
                 "b72ba17d02c5dddd",
                 "cdf5496a50214683304aec0a80337f9a",                /* auth */
                 "36a4029c9e7d0307d31c29cea885bb6c8022452016a29754" /* cipher */
                 "ba8a344c5bbfc3e1",
                 "ed8d916c171f0688d7e7cca547ab3ab2"                 /* tag */
                 ) != 0) {
            STORE_CAST_STATUS(FIPS_CAST_AES_GCM, FIPS_CAST_STATE_FAILURE);
            return AESGCM_KAT_FIPS_E;
        }
        else {
            STORE_CAST_STATUS(FIPS_CAST_AES_GCM, FIPS_CAST_STATE_SUCCESS);
        }
#endif
        break;

        case FIPS_CAST_HMAC_SHA1:
#ifndef NO_SHA
        if (HMAC_KnownAnswerTest(WC_SHA,                          /* type */
                "303132333435363738393a3b3c3d3e3f40414243",       /* key */
                "Sample #2",                                      /* msg */
                "0922D3405FAA3D194F82A45830737D5CC6C75D24"        /* digest */
                ) != 0) {
            STORE_CAST_STATUS(FIPS_CAST_HMAC_SHA1, FIPS_CAST_STATE_FAILURE);
            return HMAC_KAT_FIPS_E;
        }
        else {
            STORE_CAST_STATUS(FIPS_CAST_HMAC_SHA1, FIPS_CAST_STATE_SUCCESS);
        }
#endif
        break;

        case FIPS_CAST_HMAC_SHA2_256:
        if (HMAC_KnownAnswerTest(WC_SHA256,                       /* type */
                "303132333435363738393a3b3c3d3e3f40414243",       /* key */
                "Sample #2",                                      /* msg */
                "b8f20db541ea4309ca4ea9380cd0e834f71fbe9174a261380dc17eae6a3451d9"
                /* digest */
                ) != 0) {
            STORE_CAST_STATUS(FIPS_CAST_HMAC_SHA2_256, FIPS_CAST_STATE_FAILURE);
            return HMAC_KAT_FIPS_E;
        }
        else {
            STORE_CAST_STATUS(FIPS_CAST_HMAC_SHA2_256, FIPS_CAST_STATE_SUCCESS);
        }
        break;

        case FIPS_CAST_HMAC_SHA2_512:
#ifdef WOLFSSL_SHA512
        if (HMAC_KnownAnswerTest(WC_SHA512,                       /* type */
                "303132333435363738393a3b3c3d3e3f40414243",       /* key */
                "Sample #2",                                      /* msg */
                "809d44057c5b954105bd041316db0fac44d5a4d5d0892bd04e866412c0907768"
                "f187b77c4fae2c2f21a5b5659a4f4ba74702a3de9b51f145bd4f252742989905"
                /* digest */
                ) != 0) {
            STORE_CAST_STATUS(FIPS_CAST_HMAC_SHA2_512, FIPS_CAST_STATE_FAILURE);
            return HMAC_KAT_FIPS_E;
        }
        else {
            STORE_CAST_STATUS(FIPS_CAST_HMAC_SHA2_512, FIPS_CAST_STATE_SUCCESS);
        }
#endif
        break;

        case FIPS_CAST_HMAC_SHA3_256:
#ifdef WOLFSSL_SHA3
        if (HMAC_KnownAnswerTest(WC_SHA3_256,                     /* type */
                "302132333435363738393a3b3c3d3e3f"
                "302132333435363738393a3b3c3d3e3f",               /* key */
                "Sample #2",                                      /* msg */
                "1c91ce1a0cbf7501f432a8e23a17cd98"
                "3c96c9b5a16742016c179ff73eb8aa83"                /* digest */
                ) != 0) {
            STORE_CAST_STATUS(FIPS_CAST_HMAC_SHA3_256, FIPS_CAST_STATE_FAILURE);
            return HMAC_KAT_FIPS_E;
        }
        else {
            STORE_CAST_STATUS(FIPS_CAST_HMAC_SHA3_256, FIPS_CAST_STATE_SUCCESS);
        }
#endif
        break;

        case FIPS_CAST_RSA_SIGN_PKCS1v15:
#ifndef NO_RSA
        if (RsaSignPKCS1v15_KnownAnswerTest(WC_SHA256,            /* type */
                2048,
                "Everyone gets Friday off.",                      /* msg */
                "8CFA57979578B9D781C7F7EEDD21E962FC45D8B7CCDA68837"
                "D84E8345973856089C025A06F89F77D7C3694C483A6EF6B42"
                "EE69B8C2E01CC113F137F498890752EF6C6094D3819979122"
                "7928ED82D5BB50FB96A754F977D66FE75ABCF70F5D9448352"
                "26D30BF6F62D7B9CAFFA18179C5DABCE58BA497424A5AC8D6"
                "11814B726CF3294D0C238000DC2B775791925CA528F6B4947"
                "D3E4BA1F8CDF4C3E88E1AA2FCDAE461F6DF245DD3C39F980F"
                "D0FEC213FCB7B7D1679F4689D08538E16A8E0F357BADFD1F0"
                "D56C635B9E6E7CBD6E2F32F347AB9E07685166016EEF8F857"
                "37542185635688469BC08AF743B02B5C6FB5CED8924B20C14"
                "7B9F349FAA1943DBF677CA"                      /* signature */
                ) != 0) {
            STORE_CAST_STATUS(FIPS_CAST_RSA_SIGN_PKCS1v15,
                FIPS_CAST_STATE_FAILURE);
            return RSA_KAT_FIPS_E;
        }
        else {
            STORE_CAST_STATUS(FIPS_CAST_RSA_SIGN_PKCS1v15,
                FIPS_CAST_STATE_SUCCESS);
        }
#endif
        break;

        case FIPS_CAST_DRBG:
#ifdef HAVE_HASHDRBG
        if (DRBG_KnownAnswerTest(0,
                "a65ad0f345db4e0effe875c3a2e71f42"
                "c7129d620ff5c119a9ef55f05185e0fb"
                "8581f9317517276e06e9607ddbcbcc2e", /* entropy + nonce input */
                NULL,                               /* no reseed */
                "d3e160c35b99f340b2628264d1751060"
                "e0045da383ff57a57d73a673d2b8d80d"
                "aaf6a6c35a91bb4579d73fd0c8fed111"
                "b0391306828adfed528f018121b3febd"
                "c343e797b87dbb63db1333ded9d1ece1"
                "77cfa6b71fe8ab1da46624ed6415e51c"
                "cde2c7ca86e283990eeaeb9112041552"
                "8b2295910281b02dd431f4c9f70427df"  /* pseudorandom output */
                ) != 0) {
            STORE_CAST_STATUS(FIPS_CAST_DRBG, FIPS_CAST_STATE_FAILURE);
            return DRBG_KAT_FIPS_E;
        }

        if (DRBG_KnownAnswerTest(1,
                "63363377e41e86468deb0ab4a8ed683f"
                "6a134e47e014c700454e81e95358a569"
                "808aa38f2a72a62359915a9f8a04ca68", /* entropy + nonce input */
                "e62b8a8ee8f141b6980566e3bfe3c049"
                "03dad4ac2cdf9f2280010a6739bc83d3", /* reseed entropy input */
                "04eec63bb231df2c630a1afbe724949d"
                "005a587851e1aa795e477347c8b05662"
                "1c18bddcdd8d99fc5fc2b92053d8cfac"
                "fb0bb8831205fad1ddd6c071318a6018"
                "f03b73f5ede4d4d071f9de03fd7aea10"
                "5d9299b8af99aa075bdb4db9aa28c18d"
                "174b56ee2a014d098896ff2282c955a8"
                "1969e069fa8ce007a180183a07dfae17"  /* pseudorandom output */
                ) != 0) {
            STORE_CAST_STATUS(FIPS_CAST_DRBG, FIPS_CAST_STATE_FAILURE);
            return DRBG_KAT_FIPS_E;
        }
        else {
            STORE_CAST_STATUS(FIPS_CAST_DRBG, FIPS_CAST_STATE_SUCCESS);
        }
#elif defined(CUSTOM_RAND_GENERATE_BLOCK)
        /* TODO: Add CAST for custom rand */
        STORE_CAST_STATUS(FIPS_CAST_DRBG, FIPS_CAST_STATE_SUCCESS);
#endif
        break;

        case FIPS_CAST_ECC_CDH:
#if defined(HAVE_ECC) && defined(HAVE_ECC_CDH) && defined(HAVE_ECC_CDH_CAST)
        if (ECC_CDH_KnownAnswerTest(
                    /* ax */
            "700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287",
                    /* ay */
            "db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac",
                    /* d */
            "7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534",
                    /* ix */
            "ead218590119e8876b29146ff89ca61770c4edbbf97d38ce385ed281d8a6b230",
                    /* iy */
            "28af61281fd35e2fa7002523acc85a429cb06ee6648325389f59edfce1405141",
                    /* z */
            "46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b"
                ) != 0) {
            STORE_CAST_STATUS(FIPS_CAST_ECC_CDH, FIPS_CAST_STATE_FAILURE);
            return ECC_CDH_KAT_FIPS_E;
        }
        else {
            STORE_CAST_STATUS(FIPS_CAST_ECC_CDH, FIPS_CAST_STATE_SUCCESS);
        }
#endif
        break;

        case FIPS_CAST_ECC_PRIMITIVE_Z:
#ifdef HAVE_ECC_DHE
        if (EccPrimitiveZ_KnownAnswerTest(
                /* qexServer */
                "a2f5af030e280c76512f4591c200a3aac5b3f464fe7b598b2677af1df90f7c16",
                /* qeyServer */
                "0052d0fcf017d89126e51c837705826c6b954cf3ce4513706ab3cd1cf69287f7",
                /* qexClient */
                "6483453e74522854c940d9817e464f846975aeddbde3742e46ff10110178b5d4",
                /* qeyClient */
                "e3a66b3758279713ff594f485e9f7e0c34215090575ac4b4595ebaa301bda0b3",
                /* deClient */
                "02697f40772eb4bc12dd43436b0f8c9f5852e8df1e994f5857e18ef26e78d8e0",
                /* zVerify */
                "322f2e5a51d78300e5ec692e7c592a25e65c960f76de8729ee0b678dc9d0e99e"
                ) != 0) {
            STORE_CAST_STATUS(FIPS_CAST_ECC_PRIMITIVE_Z, FIPS_CAST_STATE_FAILURE);
            return ECDHE_KAT_FIPS_E;
        }
        else {
            STORE_CAST_STATUS(FIPS_CAST_ECC_PRIMITIVE_Z, FIPS_CAST_STATE_SUCCESS);
        }
#endif
        break;

        case FIPS_CAST_DH_PRIMITIVE_Z:
#ifndef NO_DH
        if (DhPrimitiveZ_KnownAnswerTest(
                /* p */
                "c7a528b2747cd4080d5da193285ef3eddf7bea8be391df9503c9f6a73372f6ee"
                "4e8b2cc0577bf7f8366a29b59286be32e1a13e60bea187e654b6c71268e39c97"
                "3ff220e4a8545cef5a85980d1c9687193faac4355370dee4a37acfc3a29c3e1c"
                "82faad94a2afc004ea1861fde4a9c25950a85264eb87175d047af23ad048d840"
                "50f8f0ea071672a6d210b545656c0556e94d2b4ab0b739eaf4d6c2d8d09c464f"
                "8d6afc1a8283ef3a6227d87ab6fef5e6208645a468bbba478d4b84dedb398689"
                "15e28317a7111ee75c028fe2ecfcf92453b89ff7d8c860e875b266d4455c2ac2"
                "626b6a748af0597ca9907405981d4e9af12451dad23a46f4219da89cc5be7453",
                /* q */
                "bc611c3b67b20c469972651de49b3b879d624d72ea41951615a04cc5b7f04a1f",
                /* g */
                "2fa3f79bb9cfb3fbaa4b19b8c0b5fb1e791da1c3426fb33c979ad2fcde6f984c"
                "c1578fb79125b646694ef937e2a4b1c45ff1ecb7847d4e2cc5761fa483116a9c"
                "cf628aa9c71c15cb37547ec1bd64930fb9a7569e90219b2d6ed82ad2cfee8b04"
                "4aefb475dfd0f89acb690b5021d7cacba9cbdcb517416bdbade00003dd9ea18d"
                "310e9c5734f8508ca57eb523b84b199600c130ce7bd0ab2f3dc151c10301fefc"
                "11bcd7f4fc628a84e58e4b34eb9e17406cfece2db09d7966b76582a13b31ebd7"
                "fd51bf57495144598300c9c1dc2f69237aba4e0d6d6aee1bdff125f5fee62735"
                "6759ba8c2f64dbef44565dde7875362b8e681cdf63aa2add4fa83b0a7509c3cc",
                /* xClient */
                "5b359fb62eea923b26727316a2a54126bd89a5b5015be6ac1b294ffaf180d1cb",
                /* yServer */
                "b503c9e08cf1461540eed4d794a8dc103fa47c3e1689cc3145b8f9bdeb1df99b"
                "d029f4431ce36b5854c7e16b8d076cf58023f7696fad93789a730a8b42d11345"
                "0903cea3555a39b3c1a9756dcd22915e5bb2ac62e4607f0c455da951b43135db"
                "37e171ddb4da8ae671a90f1bd288d634d4f18481d25c139d44672bbef0245928"
                "a9a78d1f5d28665eed690acdf0e06a82a3e4fdb9776a2705248f10ac638f6525"
                "03fd69d73ed46b4d0e47beb738d90913a48840d4a05f059aee4050572d6432c0"
                "a4a50e455d2b92195eadb7193c96f31e89d469b16ef9b5ddef006102652a90cd"
                "1d6d29f366f88321eb6ce0bdf6c567b302670df28ad42424dc8475a6b0153826",
                /* zVerify */
                "288cc3c9b62c6af7ae8ceaa61c1ebe3de7fe8040928b7154428fa3a08e148b27"
                ) != 0) {
            STORE_CAST_STATUS(FIPS_CAST_DH_PRIMITIVE_Z, FIPS_CAST_STATE_FAILURE);
            return DH_KAT_FIPS_E;
        }
        else {
            STORE_CAST_STATUS(FIPS_CAST_DH_PRIMITIVE_Z, FIPS_CAST_STATE_SUCCESS);
        }
#endif
        break;

        case FIPS_CAST_ECDSA:
#ifdef HAVE_ECC
#if defined(HAVE_ECC_SIGN) && defined(HAVE_ECC_VERIFY)
        if (ECDSA_KnownAnswerTest("Everyone gets Friday off.",
        #ifndef NO_ECC256
                    "3045022100B487D183DC4806058EB31A"
                    "29BEDEFD7BCCA987B77A381A3684871D"
                    "8449C1839402200A7F0422B19CDFF752"
                    "A623F35E2C702019A04676C7144D2840"
                    "90EEE2C45D9ECC",
        #elif defined(HAVE_ECC384)
                    "3064023067D2CDE4DE93D079A14913DF"
                    "6B69158E9911FC7C7BACBE5E293E1004"
                    "BE2DBEBA098318BF36A01EB0F90370DB"
                    "93DAC445023057B73DA2ED6042DFA1EB"
                    "E4705D2D2EA046D32C3542BB796E82EB"
                    "88A6B11378EFFE03C3BB7FC8C4B1F35E"
                    "4AE4AF1CC4F0",
        #endif
                    FIPS_ECC_HASH_TYPE, FIPS_ECC_KEY_BUF, FIPS_ECC_KEY_SZ
                ) != 0) {
            STORE_CAST_STATUS(FIPS_CAST_ECDSA, FIPS_CAST_STATE_FAILURE);
            return ECDSA_KAT_FIPS_E;
        }
        else
        {
            /* TODO: Add FIPS CAST for ECDSA */
            STORE_CAST_STATUS(FIPS_CAST_ECDSA, FIPS_CAST_STATE_SUCCESS);
        }
#elif defined(HAVE_ECC_VERIFY)
    if (ECDSA_KnownAnswerTest(
    /* From: http://csrc.nist.gov/groups/STM/cavp/documents/dss/186-3ecdsatestvectors.zip */
    #ifndef NO_ECC256
        /* [P-256,SHA-256] */
        /* Test Message "e1130af6a38ccb412a9c8d13e15dbfc9e69a16385af3c3f1e5da954fd5e7c45fd75e2b8c36699228e92840c0562fbf
                        3772f07e17f1add56588dd45f7450e1217ad239922dd9c32695dc71ff2424ca0dec1321aa47064a044b7fe3c2b97d0
                        3ce470a592304c5ef21eed9f93da56bb232d1eeb0035f9bf0dfafdcc4606272b20a3" */
        /* Digest SHA2-256 of test message  */
        "d1b8ef21eb4182ee270638061063a3f3c16c114e33937f69fb232cc833965a94",
        /* Qx */
        "e424dc61d4bb3cb7ef4344a7f8957a0c5134e16f7a67c074f82e6e12f49abf3c"
        /* Qy */
        "970eed7aa2bc48651545949de1dddaf0127e5965ac85d1243d6f60e7dfaee927",
        /* R */
        "bf96b99aa49c705c910be33142017c642ff540c76349b9dab72f981fd9347f4f"
        /* S */
        "17c55095819089c2e03b9cd415abdf12444e323075d98f31920b9e0f57ec871c",
        ECC_SECP256R1
     #elif defined(HAVE_ECC384)
        /* [P-384,SHA-384] */
        /* Test Message "93e7e75cfaf3fa4e71df80f7f8c0ef6672a630d2dbeba1d61349acbaaa476f5f0e34dccbd85b9a815d908203313a22
                        fe3e919504cb222d623ad95662ea4a90099742c048341fe3a7a51110d30ad3a48a777c6347ea8b71749316e0dd1902
                        facb304a76324b71f3882e6e70319e13fc2bb9f3f5dbb9bd2cc7265f52dfc0a3bb91" */
        /* Digest SHA2-384 of test message */
        "709d1bf45b5817f5a67b859651eb47133ebed2622fda09ab66d3467b5e95da50ecc2c74d8f4d289feebec29729a4bfa3",
        /* Qx */
        "a370cdbef95d1df5bf68ec487122514a107db87df3f8852068fd4694abcadb9b14302c72491a76a64442fc07bd99f02c"
        /* Qy */
        "d397c25dc1a5781573d039f2520cf329bf65120fdbe964b6b80101160e533d5570e62125b9f3276c49244b8d0f3e44ec",
        /* R */
        "c6c7bb516cc3f37a304328d136b2f44bb89d3dac78f1f5bcd36b412a8b4d879f6cdb75175292c696b58bfa9c91fe6391"
        /* S */
        "6b711425e1b14f7224cd4b96717a84d65a60ec9951a30152ea1dd3b6ea66a0088d1fd3e9a1ef069804b7d969148c37a0",
        ECC_SECP384R1
    #endif
    ) != 0) {
        return ECDSA_PAT_FIPS_E;
    }

#endif
#endif /* HAVE_ECC */
        break;

        case FIPS_CAST_KDF_TLS12:
#if defined(WOLFSSL_HAVE_PRF) && !defined(WOLFSSL_NO_TLS12)
        if (TLSv12_KDF_KnownAnswerTest() != 0) {
            STORE_CAST_STATUS(FIPS_CAST_KDF_TLS12, FIPS_CAST_STATE_FAILURE);
            return KDF_TLS12_KAT_FIPS_E;
        }
        else {
            STORE_CAST_STATUS(FIPS_CAST_KDF_TLS12, FIPS_CAST_STATE_SUCCESS);
        }
#endif
        break;

        case FIPS_CAST_KDF_TLS13:
#if defined(HAVE_HKDF) && !defined(NO_HMAC) && defined(WOLFSSL_TLS13)
        if (TLSv13_KDF_KnownAnswerTest() != 0) {
            STORE_CAST_STATUS(FIPS_CAST_KDF_TLS13, FIPS_CAST_STATE_FAILURE);
            return KDF_TLS13_KAT_FIPS_E;
        }
        else {
            STORE_CAST_STATUS(FIPS_CAST_KDF_TLS13, FIPS_CAST_STATE_SUCCESS);
        }
#endif
        break;

        case FIPS_CAST_KDF_SSH:
#ifdef WOLFSSL_WOLFSSH
        if (SSH_KDF_KnownAnswerTest() != 0) {
            STORE_CAST_STATUS(FIPS_CAST_KDF_SSH, FIPS_CAST_STATE_FAILURE);
            return KDF_SSH_KAT_FIPS_E;
        }
        else {
            STORE_CAST_STATUS(FIPS_CAST_KDF_SSH, FIPS_CAST_STATE_SUCCESS);
        }
#endif
        break;

        case FIPS_CAST_KDF_SRTP:
#ifdef WC_SRTP_KDF
        if (SRTP_KDF_KnownAnswerTest() != 0) {
            STORE_CAST_STATUS(FIPS_CAST_KDF_SRTP, FIPS_CAST_STATE_FAILURE);
            return KDF_SRTP_KAT_FIPS_E;
        }
        else {
            STORE_CAST_STATUS(FIPS_CAST_KDF_SRTP, FIPS_CAST_STATE_SUCCESS);
        }
#endif
        break;

        case FIPS_CAST_ED25519:
#ifdef HAVE_ED25519
        if (ED25519_KnownAnswerTest() != 0) {
            STORE_CAST_STATUS(FIPS_CAST_ED25519, FIPS_CAST_STATE_FAILURE);
            return ED25519_KAT_FIPS_E;
        }
        else {
            STORE_CAST_STATUS(FIPS_CAST_ED25519, FIPS_CAST_STATE_SUCCESS);
        }
#endif
        break;

        case FIPS_CAST_ED448:
#ifdef HAVE_ED448
        if (ED448_KnownAnswerTest() != 0) {
            STORE_CAST_STATUS(FIPS_CAST_ED448, FIPS_CAST_STATE_FAILURE);
            return ED448_KAT_FIPS_E;
        }
        else {
            STORE_CAST_STATUS(FIPS_CAST_ED448, FIPS_CAST_STATE_SUCCESS);
        }
#endif
        break;

        case FIPS_CAST_PBKDF2:
#ifdef HAVE_PBKDF2
        if (PBKDF2_KnownAnswerTest() != 0) {
            STORE_CAST_STATUS(FIPS_CAST_PBKDF2, FIPS_CAST_STATE_FAILURE);
            return PBKDF2_KAT_FIPS_E;
        }
        else {
            STORE_CAST_STATUS(FIPS_CAST_PBKDF2, FIPS_CAST_STATE_SUCCESS);
        }
#endif
        break;
    }
    return 0;
    #undef STORE_CAST_STATUS
}


/* do pre-operational self-test, 0 on success */
int DoPOST(char* base16_hash, int base16_hashSz)
{
    int i;

    for (i = 0; i < FIPS_CAST_COUNT; i++)
        fipsCastStatus_put(i, FIPS_CAST_STATE_INIT);

    return DoInCoreCheck(base16_hash, base16_hashSz);
}

#endif /* HAVE_FIPS */

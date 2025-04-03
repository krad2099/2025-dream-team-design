/* options.h.in
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


/* default blank options for autoconf */

#ifdef WOLFSSL_NO_OPTIONS_H
/* options.h inhibited by configuration */
#elif !defined(WOLFSSL_OPTIONS_H)
#define WOLFSSL_OPTIONS_H


#ifdef __cplusplus
extern "C" {
#endif


#ifdef __cplusplus
}
#endif

/* options.h - Custom Configuration for wolfSSL */
/* Enable constant-time cryptographic operations */
#define WOLFSSL_CONSTANT_TIME

/* Enable additional hardening options for cryptographic operations */
#define WOLFSSL_SHA256_CONSTANT_TIME  // For SHA256 constant-time operations
#define WOLFSSL_AES_CONSTANT_TIME     // For AES constant-time operations
#define WOLFSSL_RSA_CONSTANT_TIME     // For RSA constant-time operations

/* Enable the use of additional hardening options for side-channel resistance */
#define WOLFSSL_USE_EXTERNAL_RNG

/* Enable SHA256 functionality */
#define WOLFSSL_SHA256

/* Enable AES functionality */
#define WOLFSSL_AES

/* Enable AES GCM for authenticated encryption */
#define WOLFSSL_AES_256_GCM

/* Other configurations can be enabled as needed */

/* Include additional options for platform-specific optimizations */
#define WOLFSSL_USE_INTEL

/* Disable other functionality as needed (for example, disable RSA) */
#define WOLFSSL_NO_RSA


#endif /* WOLFSSL_OPTIONS_H */

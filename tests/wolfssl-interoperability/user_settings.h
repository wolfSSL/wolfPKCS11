/* user_settings.h - user settings for wolfSSL + wolfPKCS11 interoperability
 * tests.
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfPKCS11.
 *
 * wolfPKCS11 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfPKCS11 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */
#ifndef INTEROP_USER_SETTINGS_H
#define INTEROP_USER_SETTINGS_H

/* Enable PKCS#11 client support inside wolfCrypt */
#define HAVE_PKCS11
#define WOLF_CRYPTO_CB

/* Core algorithm coverage needed for interoperability tests */
#define HAVE_ECC
#define HAVE_ECC384
#define HAVE_ECC521
#define HAVE_ECC_SIGN
#define HAVE_ECC_VERIFY
#define HAVE_ECC_DHE
#define HAVE_ECDH
#define WOLFSSL_KEY_GEN

#define HAVE_AESGCM
#define HAVE_AES_CBC
#define HAVE_AESCTR
#define WOLFSSL_AES_COUNTER
#define WOLFSSL_AES_XTS 
#define WOLFSSL_AES_CFB

/* Enable SHA-2 family exercised by the tests */
#define WOLFSSL_SHA224
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define WOLFSSL_SHA3

/* Use single-precision math backend (replaces legacy TFM fast math). */
#define WOLFSSL_SP_MATH_ALL
#define SP_WORD_SIZE 32
#define WOLFSSL_HAVE_SP_RSA
#define WOLFSSL_HAVE_SP_ECC
#define WOLFSSL_HAVE_SP_DH
#define WC_RSA_BLINDING
#define ECC_TIMING_RESISTANT
#define WOLFSSL_PUBLIC_MP
#define WC_RSA_DIRECT
#define WC_RSA_PSS
#define HAVE_WOLF_BIGINT
#define WOLF_PRIVATE_KEY_ID


#define HAVE_HKDF
#define HAVE_SCRYPT
#define WOLFCRYPT_ONLY
#define WOLFSSL_PKCS11_RW_TOKENS
#define WOLF_CRYPTO_CB_RSA_PAD

/* Cert buffer from wolfssl for test keys */

#define SP_INT_BITS 4096
#define WOLFSSL_SP_2048
#define WOLFSSL_SP_3072
#define WOLFSSL_SP_4096
#define USE_CERT_BUFFERS_256
#define USE_CERT_BUFFERS_384
#define USE_CERT_BUFFERS_521
#define USE_CERT_BUFFERS_2048
#define USE_CERT_BUFFERS_4096
#define USE_CERT_BUFFERS_3072

/* Remove unused features */
#define NO_DSA
#define NO_RC4
#define NO_MD4

#endif /* INTEROP_USER_SETTINGS_H */

/* pkcs11v3test.c - unit tests
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

#ifdef HAVE_CONFIG_H
    #include <wolfpkcs11/config.h>
#endif

#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/misc.h>
#ifdef WOLFPKCS11_MLKEM
    #include <wolfssl/wolfcrypt/wc_mlkem.h>
#endif

#ifndef WOLFPKCS11_USER_SETTINGS
    #include <wolfpkcs11/options.h>
#endif
#include <wolfpkcs11/pkcs11.h>

#ifndef HAVE_PKCS11_STATIC
#include <dlfcn.h>
#endif

#include "unit.h"
#include "testdata.h"
#include <wolfpkcs11/internal.h>


#define TEST_FLAG_INIT                 0x01
#define TEST_FLAG_TOKEN                0x02
#define TEST_FLAG_SESSION              0x04

#define PKCS11TEST_CASE(func, flags)                                       \
    TEST_CASE(func, flags, pkcs11_open_session, pkcs11_close_session,      \
              sizeof(CK_SESSION_HANDLE))
#define PKCS11TEST_FUNC_NO_INIT_DECL(func)                                 \
    PKCS11TEST_CASE(func, 0)
#define PKCS11TEST_FUNC_NO_TOKEN_DECL(func)                                \
    PKCS11TEST_CASE(func, TEST_FLAG_INIT)
#define PKCS11TEST_FUNC_TOKEN_DECL(func)                                   \
    PKCS11TEST_CASE(func, TEST_FLAG_INIT | TEST_FLAG_TOKEN)
#define PKCS11TEST_FUNC_SESS_DECL(func)                                    \
    PKCS11TEST_CASE(func, TEST_FLAG_INIT | TEST_FLAG_TOKEN | TEST_FLAG_SESSION)


#ifdef WOLFPKCS11_PKCS11_V3_0

#ifndef HAVE_PKCS11_STATIC
static void* dlib;
#endif
static CK_FUNCTION_LIST* funcList;

#ifdef DEBUG_WOLFPKCS11
#ifndef HAVE_PKCS11_STATIC
void (*wolfPKCS11_Debugging_On_fp)(void) = NULL;
void (*wolfPKCS11_Debugging_Off_fp)(void) = NULL;
#endif
#endif
static int slot = 0;
static const char* tokenName = "wolfpkcs11";

/* FIPS requires pin to be at least 14 characters, since it is used for
 * the HMAC key */
static byte* soPin = (byte*)"password123456";
static int soPinLen = 14;
static byte* userPin = (byte*)"wolfpkcs11-test";
static int userPinLen;

#ifdef WOLFPKCS11_PKCS11_V3_2
#if defined(WOLFPKCS11_MLDSA) || defined(WOLFPKCS11_MLKEM)

static CK_BBOOL ckTrue = CK_TRUE;
static CK_OBJECT_CLASS privKeyClass = CKO_PRIVATE_KEY;
static CK_OBJECT_CLASS pubKeyClass = CKO_PUBLIC_KEY;

#endif /* WOLFPKCS11_MLDSA || WOLFPKCS11_MLKEM */
#ifdef WOLFPKCS11_MLDSA

static CK_KEY_TYPE mldsaKeyType = CKK_ML_DSA;

static CK_RV gen_mldsa_keys(CK_SESSION_HANDLE session,
                            CK_ML_DSA_PARAMETER_SET_TYPE paramSet,
                            CK_OBJECT_HANDLE* pubKey, CK_OBJECT_HANDLE* privKey,
                            unsigned char* privId, int privIdLen,
                            unsigned char* pubId, int pubIdLen, int onToken)
{
    CK_RV ret = CKR_OK;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_MECHANISM mech;
    CK_BBOOL token = (CK_BBOOL)onToken;
    CK_ATTRIBUTE pubKeyTmpl[] = {
        { CKA_PARAMETER_SET,  &paramSet,   sizeof(paramSet) },
        { CKA_VERIFY,         &ckTrue,     sizeof(ckTrue)   },
        { CKA_TOKEN,          &token,      sizeof(token)    },
        { CKA_ID,             pubId,       pubIdLen         },
    };
    CK_ULONG pubTmplCnt = sizeof(pubKeyTmpl) / sizeof(*pubKeyTmpl);
    /* PKCS11 V3.2: no CKA_PARAMETER_SET in private key template for
     * key generation, since it is already set in the public key one. */
    CK_ATTRIBUTE privKeyTmpl[] = {
        { CKA_SIGN,           &ckTrue,     sizeof(ckTrue)   },
        { CKA_TOKEN,          &token,      sizeof(token)    },
        { CKA_ID,             privId,      privIdLen        },
    };
    CK_ULONG privTmplCnt = sizeof(privKeyTmpl) / sizeof(*privKeyTmpl);

    if (pubId == NULL)
        pubTmplCnt--;
    if (privId == NULL)
        privTmplCnt--;

    mech.mechanism = CKM_ML_DSA_KEY_PAIR_GEN;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;

    ret = funcList->C_GenerateKeyPair(session, &mech, pubKeyTmpl, pubTmplCnt,
                                      privKeyTmpl, privTmplCnt, &pub, &priv);
    CHECK_CKR(ret, "ML-DSA Key Generation");
    if (ret == CKR_OK && pubKey != NULL)
        *pubKey = pub;
    if (ret == CKR_OK && privKey != NULL)
        *privKey = priv;

    if (ret == CKR_OK) {
        byte bad = 0;

        mech.pParameter = &bad;
        ret = funcList->C_GenerateKeyPair(session, &mech, pubKeyTmpl, pubTmplCnt,
                                          privKeyTmpl, privTmplCnt, &pub, &priv);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                       "ML-DSA Key Generation bad parameter");
        mech.pParameter = NULL;
    }
    if (ret == CKR_OK) {
        mech.ulParameterLen = 1;
        ret = funcList->C_GenerateKeyPair(session, &mech, pubKeyTmpl, pubTmplCnt,
                                          privKeyTmpl, privTmplCnt, &pub, &priv);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                       "ML-DSA Key Generation bad parameter length");
    }

    return ret;
}

static CK_RV find_mldsa_key(CK_SESSION_HANDLE session, CK_OBJECT_CLASS objClass,
                            CK_OBJECT_HANDLE* key, unsigned char* id, int idLen)
{
    CK_RV ret = CKR_OK;
    CK_ULONG count = 0;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,    &objClass,      sizeof(objClass)      },
        { CKA_KEY_TYPE, &mldsaKeyType,  sizeof(mldsaKeyType)  },
        { CKA_ID,       id,             idLen                 },
    };

    ret = funcList->C_FindObjectsInit(session, tmpl, sizeof(tmpl)/sizeof(*tmpl));
    CHECK_CKR(ret, "ML-DSA Find Objects Init");
    if (ret == CKR_OK) {
        ret = funcList->C_FindObjects(session, key, 1, &count);
        CHECK_CKR(ret, "ML-DSA Find Objects");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_FindObjectsFinal(session);
        CHECK_CKR(ret, "ML-DSA Find Objects Final");
    }
    if (ret == CKR_OK) {
        CHECK_COND(count == 1, ret, "ML-DSA Find Objects count");
    }

    return ret;
}

static CK_RV find_mldsa_priv_key(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE* key,
                                 unsigned char* id, int idLen)
{
    return find_mldsa_key(session, privKeyClass, key, id, idLen);
}

static CK_RV find_mldsa_pub_key(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE* key,
                                unsigned char* id, int idLen)
{
    return find_mldsa_key(session, pubKeyClass, key, id, idLen);
}

/* Seed that generates mldsa_44_priv and mldsa_44_pub below. */
static unsigned char mldsa_44_seed[] = {
    0x5d, 0x1b, 0x26, 0x10, 0xcb, 0x97, 0x99, 0x1a, 0xea, 0x78, 0xd2, 0x34,
    0x72, 0xbd, 0x9e, 0x30, 0xf7, 0xef, 0xcc, 0x40, 0x1c, 0xb6, 0x14, 0xbf,
    0x85, 0x72, 0xdc, 0x2d, 0x7d, 0x0e, 0x90, 0xc2
};
static unsigned char mldsa_44_priv[] = {
    0x89, 0x38, 0xa0, 0x20, 0xc3, 0x92, 0xb3, 0x91, 0x75, 0x2c, 0xfa, 0x27,
    0xcc, 0x37, 0x08, 0x32, 0x5d, 0xcc, 0xd9, 0x06, 0xf1, 0xda, 0xa8, 0xc9,
    0xbe, 0x57, 0x89, 0xb5, 0xda, 0x48, 0xae, 0x20, 0xcb, 0xe4, 0xb6, 0x5f,
    0x0e, 0xfe, 0x28, 0x24, 0xc6, 0xcf, 0x8b, 0xe5, 0x1d, 0xeb, 0x6d, 0x5a,
    0x2e, 0x21, 0xe2, 0xd9, 0x9c, 0x1b, 0x0c, 0x07, 0x3f, 0x21, 0xb9, 0x96,
    0xb8, 0xce, 0x74, 0xfe, 0x18, 0x5f, 0xa9, 0x45, 0x2d, 0xdf, 0x6b, 0x07,
    0xfb, 0x0d, 0x92, 0x91, 0x86, 0xf7, 0x8b, 0x05, 0xfb, 0x18, 0x64, 0x86,
    0xc7, 0xb2, 0x65, 0xeb, 0x4c, 0x91, 0x98, 0x11, 0x6e, 0x5d, 0x9c, 0x48,
    0xe8, 0x68, 0xf2, 0xb4, 0x09, 0x8a, 0xd6, 0xcd, 0x86, 0x1b, 0xe5, 0xd2,
    0x52, 0xb7, 0x63, 0x81, 0x21, 0x0a, 0x10, 0x7f, 0xaf, 0x3a, 0x26, 0x2b,
    0xc0, 0x68, 0x0f, 0xbf, 0x59, 0xbc, 0x8a, 0x00, 0x52, 0x04, 0x04, 0x02,
    0x40, 0x64, 0x03, 0xb6, 0x61, 0xc0, 0x90, 0x40, 0x8c, 0x22, 0x6c, 0x81,
    0x16, 0x2c, 0x89, 0x12, 0x01, 0xda, 0x24, 0x32, 0x00, 0xc4, 0x2c, 0x89,
    0x38, 0x20, 0x9c, 0x98, 0x31, 0xa0, 0xb6, 0x09, 0x19, 0x36, 0x82, 0xe2,
    0x20, 0x44, 0xe4, 0x28, 0x0e, 0x24, 0x40, 0x42, 0xca, 0x26, 0x40, 0x9b,
    0xb0, 0x2c, 0x64, 0xa0, 0x25, 0x93, 0x20, 0x01, 0xc8, 0xa2, 0x09, 0xc1,
    0xa0, 0x80, 0x59, 0x44, 0x46, 0xe1, 0x14, 0x20, 0x81, 0x48, 0x25, 0xe4,
    0xb0, 0x81, 0x99, 0x00, 0x42, 0x00, 0x86, 0x6c, 0x23, 0xb9, 0x70, 0xa0,
    0x14, 0x02, 0x98, 0x10, 0x20, 0x52, 0x26, 0x04, 0x81, 0x44, 0x69, 0x4a,
    0x46, 0x05, 0x0b, 0xb4, 0x49, 0x19, 0x97, 0x21, 0x21, 0x93, 0x28, 0x20,
    0x35, 0x52, 0x04, 0x24, 0x69, 0x09, 0x41, 0x70, 0x9c, 0x00, 0x45, 0x9a,
    0x02, 0x06, 0x9b, 0x44, 0x4e, 0x0c, 0x04, 0x24, 0xc8, 0xb6, 0x45, 0x59,
    0x48, 0x2e, 0x14, 0x91, 0x91, 0x93, 0x44, 0x52, 0x4b, 0x26, 0x71, 0xc4,
    0x36, 0x20, 0xe1, 0x28, 0x68, 0x5c, 0x46, 0x4c, 0x11, 0x05, 0x8e, 0x22,
    0x19, 0x2e, 0x63, 0x40, 0x2d, 0x02, 0xb7, 0x48, 0x5a, 0xc0, 0x8d, 0xc1,
    0xa0, 0x61, 0x9a, 0xc6, 0x80, 0x03, 0x86, 0x30, 0x11, 0xa6, 0x31, 0x5a,
    0xc4, 0x00, 0x0a, 0x47, 0x21, 0x44, 0xb0, 0x21, 0x40, 0x28, 0x22, 0xd9,
    0x46, 0x50, 0x80, 0x48, 0x91, 0x53, 0x30, 0x31, 0xe4, 0x92, 0x4c, 0x88,
    0x80, 0x24, 0xc4, 0x38, 0x09, 0x14, 0x06, 0x92, 0x41, 0x20, 0x8d, 0x62,
    0xc4, 0x24, 0x0c, 0xa1, 0x89, 0x92, 0xb4, 0x00, 0x23, 0x96, 0x29, 0x82,
    0x02, 0x11, 0xc2, 0x38, 0x12, 0x43, 0xb0, 0x70, 0x12, 0x31, 0x8c, 0x11,
    0x09, 0x02, 0x03, 0x04, 0x8e, 0x0c, 0x44, 0x70, 0x1c, 0x92, 0x41, 0x99,
    0x18, 0x4c, 0x19, 0x80, 0x05, 0x94, 0x16, 0x32, 0x20, 0x82, 0x21, 0x64,
    0x18, 0x10, 0x24, 0x49, 0x08, 0xd0, 0x00, 0x6a, 0x10, 0x35, 0x30, 0x14,
    0x06, 0x65, 0x11, 0x33, 0x25, 0x01, 0xa3, 0x85, 0xcc, 0x24, 0x88, 0x88,
    0x36, 0x26, 0x5b, 0xc4, 0x08, 0x50, 0x04, 0x30, 0x82, 0x84, 0x80, 0x62,
    0x08, 0x25, 0x10, 0x30, 0x00, 0x21, 0x09, 0x72, 0x20, 0x84, 0x8c, 0x1c,
    0x84, 0x2c, 0xa2, 0x84, 0x8c, 0x20, 0x14, 0x45, 0x1b, 0xa3, 0x40, 0x02,
    0x36, 0x6e, 0x00, 0xc2, 0x48, 0x14, 0x39, 0x01, 0x94, 0x36, 0x6d, 0xc3,
    0x34, 0x45, 0x5c, 0xa0, 0x91, 0xc2, 0xc2, 0x91, 0x4a, 0x34, 0x06, 0xa0,
    0x46, 0x6a, 0x14, 0x40, 0x44, 0xe2, 0xa2, 0x84, 0x9c, 0xa0, 0x81, 0x01,
    0x97, 0x4d, 0x04, 0x03, 0x4d, 0x1b, 0x40, 0x30, 0x23, 0x32, 0x68, 0x23,
    0x13, 0x44, 0x18, 0x32, 0x09, 0x0a, 0xc6, 0x69, 0xc2, 0xb0, 0x24, 0x99,
    0x14, 0x52, 0x0c, 0x13, 0x8e, 0x89, 0x10, 0x30, 0xd9, 0xb6, 0x28, 0xc3,
    0x12, 0x02, 0x4a, 0x44, 0x8a, 0x92, 0x90, 0x91, 0x89, 0x20, 0x4d, 0x59,
    0x30, 0x8d, 0x1c, 0x48, 0x48, 0xca, 0x24, 0x86, 0x53, 0x18, 0x80, 0x54,
    0x82, 0x21, 0x13, 0x11, 0x29, 0x10, 0x34, 0x48, 0x10, 0x05, 0x52, 0x02,
    0xa2, 0x44, 0xc3, 0x10, 0x44, 0x93, 0x04, 0x06, 0x89, 0x42, 0x41, 0x20,
    0x26, 0x30, 0x61, 0x08, 0x2c, 0x40, 0xb0, 0x41, 0x09, 0x49, 0x80, 0x51,
    0x14, 0x8d, 0x1c, 0x09, 0x2e, 0xd3, 0x22, 0x29, 0xc4, 0xa8, 0x29, 0x4a,
    0x12, 0x2d, 0xa2, 0x04, 0x06, 0x8b, 0xb2, 0x24, 0x1a, 0xb1, 0x6d, 0xc4,
    0xc4, 0x00, 0x9c, 0x82, 0x21, 0x90, 0x04, 0x2d, 0x23, 0xc9, 0x4c, 0x08,
    0xc1, 0x6d, 0x8b, 0xc6, 0x20, 0x63, 0x08, 0x06, 0x5b, 0x88, 0x90, 0x52,
    0x10, 0x61, 0x43, 0x08, 0x0d, 0x02, 0x22, 0x72, 0x62, 0xc2, 0x09, 0x22,
    0xa6, 0x25, 0x08, 0x30, 0x52, 0x24, 0xb4, 0x2c, 0x99, 0x22, 0x26, 0x03,
    0x91, 0x4c, 0x24, 0x04, 0x8d, 0x10, 0x42, 0x52, 0x41, 0x14, 0x0a, 0x02,
    0x46, 0x0d, 0xcc, 0x30, 0x8d, 0x0a, 0x44, 0x80, 0x14, 0xc4, 0x48, 0x14,
    0xb0, 0x64, 0xd3, 0xa8, 0x10, 0xd1, 0x86, 0x6c, 0x9c, 0xc6, 0x4d, 0x0a,
    0x34, 0x6a, 0x94, 0x18, 0x02, 0x41, 0x30, 0x06, 0x53, 0x04, 0x6a, 0xc3,
    0x46, 0x2c, 0x8a, 0x36, 0x85, 0x5a, 0x22, 0x52, 0x40, 0x48, 0x32, 0xd2,
    0x92, 0x21, 0xd1, 0x28, 0x41, 0x00, 0xa0, 0x45, 0x11, 0x46, 0x24, 0x01,
    0x13, 0x45, 0x12, 0x40, 0x44, 0x94, 0x44, 0x8a, 0x18, 0x21, 0x02, 0x08,
    0x91, 0x91, 0x4b, 0xb2, 0x69, 0x41, 0x96, 0x49, 0xc2, 0x84, 0x65, 0x49,
    0x88, 0x40, 0x8b, 0x22, 0x42, 0x0c, 0x08, 0x80, 0x01, 0xa5, 0x24, 0x92,
    0x34, 0x6d, 0x10, 0x31, 0x6e, 0xe2, 0x26, 0x21, 0x12, 0x01, 0x0e, 0x60,
    0x30, 0x92, 0x90, 0x28, 0x00, 0x49, 0x92, 0x91, 0x51, 0xc8, 0x69, 0x1b,
    0xa5, 0x49, 0xc3, 0x30, 0x42, 0x11, 0xc0, 0x6d, 0xa4, 0x24, 0x66, 0x1c,
    0xa9, 0x71, 0xda, 0x22, 0x28, 0x0a, 0x12, 0x51, 0x61, 0xc2, 0x2d, 0x01,
    0xa3, 0x48, 0x23, 0xa6, 0x25, 0x22, 0x32, 0x88, 0x98, 0x82, 0x90, 0x88,
    0x24, 0x90, 0xd2, 0x16, 0x4e, 0x83, 0xa4, 0x08, 0x59, 0xc8, 0x10, 0x0b,
    0x11, 0x72, 0xd9, 0x00, 0x28, 0xa2, 0x20, 0x64, 0x90, 0xc6, 0x4c, 0x03,
    0x29, 0x89, 0xcb, 0x40, 0x6d, 0x52, 0x88, 0x6d, 0x50, 0x98, 0x6c, 0xa3,
    0xc0, 0x44, 0x08, 0xb1, 0x44, 0x9b, 0xc0, 0x29, 0x1c, 0xc7, 0x10, 0x59,
    0x26, 0x26, 0x14, 0xc8, 0x45, 0xc0, 0x36, 0x6c, 0x01, 0x00, 0x8c, 0x80,
    0x02, 0x24, 0x92, 0x24, 0x8d, 0x1a, 0x80, 0x25, 0x4e, 0xcc, 0x07, 0xd6,
    0x69, 0x1a, 0xa5, 0x12, 0x74, 0x91, 0x8a, 0x43, 0xa8, 0x21, 0xb9, 0xa2,
    0x18, 0xa4, 0xec, 0x54, 0xde, 0xe2, 0xb5, 0x51, 0x7f, 0xbe, 0x43, 0xb1,
    0x45, 0x24, 0xbb, 0xc1, 0xd5, 0x3f, 0xe0, 0xa5, 0x16, 0xec, 0x4b, 0xf5,
    0x8e, 0xbe, 0x85, 0xd0, 0xfb, 0xc3, 0xcf, 0x80, 0x20, 0xe2, 0xe5, 0x91,
    0x85, 0xab, 0xeb, 0xd3, 0x99, 0x38, 0x40, 0x6e, 0xed, 0xd0, 0x93, 0xe6,
    0x12, 0x20, 0xd1, 0x0d, 0x4b, 0x5d, 0x08, 0x27, 0x80, 0x11, 0xc3, 0x8b,
    0x20, 0x24, 0x97, 0x90, 0xb1, 0x3e, 0x0c, 0xa5, 0xe6, 0x1d, 0xc3, 0x9b,
    0xd0, 0xe6, 0x82, 0x3c, 0x14, 0xd3, 0x64, 0xaa, 0x4f, 0xdc, 0xca, 0x44,
    0x35, 0xa0, 0xd5, 0x46, 0xec, 0xa7, 0x7e, 0x25, 0xd9, 0xe9, 0x2f, 0x30,
    0x87, 0x36, 0x42, 0x4b, 0x66, 0x90, 0x70, 0xbe, 0x81, 0x0a, 0x36, 0xc1,
    0x2c, 0x7a, 0xff, 0x61, 0x7a, 0x88, 0xec, 0x98, 0x2a, 0x77, 0xfd, 0x91,
    0x36, 0xe8, 0x11, 0x3b, 0x44, 0x79, 0xf6, 0x80, 0xa7, 0x59, 0x35, 0x21,
    0x77, 0x4b, 0x71, 0xd8, 0x1a, 0xce, 0x86, 0x7d, 0x39, 0x02, 0x0d, 0x95,
    0x8f, 0xe9, 0x21, 0x3f, 0x2b, 0x95, 0x4f, 0xe1, 0x0f, 0xf1, 0x69, 0x09,
    0x35, 0x90, 0xc7, 0x94, 0xb4, 0x02, 0x74, 0xab, 0xb4, 0x97, 0x54, 0xe5,
    0x23, 0x0f, 0x34, 0x5c, 0x48, 0xc9, 0xcb, 0x1f, 0x38, 0xfd, 0xb5, 0xb3,
    0x39, 0x01, 0xc2, 0x52, 0x7b, 0x79, 0xba, 0xef, 0x2c, 0xfb, 0xf2, 0x2e,
    0x4d, 0xb8, 0xa0, 0xa6, 0xef, 0xdc, 0x3f, 0xc3, 0xb4, 0x07, 0x3f, 0x89,
    0x3d, 0xf2, 0x16, 0x4d, 0xcd, 0x28, 0x78, 0x67, 0x1a, 0xaa, 0x02, 0xc1,
    0x55, 0x1c, 0xc9, 0xd3, 0x42, 0xba, 0xa4, 0x42, 0x0a, 0x69, 0x51, 0x3c,
    0xcf, 0xf6, 0xf0, 0x3c, 0x22, 0x12, 0x21, 0x35, 0xc2, 0x4d, 0x55, 0x43,
    0xee, 0xab, 0xe6, 0xb0, 0x96, 0x71, 0x01, 0xe8, 0x5c, 0x7c, 0x7d, 0x1c,
    0x87, 0xd7, 0x70, 0xc3, 0x66, 0x3b, 0xc9, 0xf2, 0x4f, 0x84, 0x97, 0xc6,
    0x9a, 0x41, 0x8f, 0x00, 0xcf, 0xca, 0x9f, 0xca, 0x6d, 0x91, 0xe7, 0x70,
    0xa9, 0x89, 0x8a, 0xe0, 0xf8, 0xf3, 0x0d, 0x87, 0x53, 0x63, 0x27, 0x7d,
    0x56, 0x46, 0x91, 0x7c, 0x99, 0x62, 0x12, 0x33, 0x5a, 0x92, 0xc4, 0xdb,
    0x08, 0xc7, 0x0e, 0x87, 0x63, 0xe8, 0xab, 0xfb, 0xc4, 0x3a, 0x09, 0x5b,
    0xb2, 0x34, 0x56, 0x56, 0x5f, 0x67, 0x49, 0xd6, 0x68, 0x1c, 0x21, 0xb0,
    0x3f, 0x2b, 0xf4, 0x2e, 0xed, 0x71, 0x7d, 0x38, 0x99, 0x86, 0xa5, 0xf2,
    0xf1, 0x76, 0x13, 0xf3, 0xa2, 0x91, 0xa1, 0x4a, 0xb4, 0x69, 0xa4, 0x8b,
    0xd9, 0x0d, 0xca, 0xf8, 0x01, 0x81, 0xe9, 0xca, 0x75, 0x4e, 0x39, 0x45,
    0xb2, 0x3a, 0x41, 0x3f, 0x45, 0x27, 0x9b, 0xef, 0xa4, 0x07, 0x5c, 0xdf,
    0xe5, 0x2c, 0xef, 0x24, 0x72, 0x5d, 0x83, 0xe6, 0xa8, 0x64, 0x60, 0x4a,
    0x9e, 0x34, 0x1c, 0x49, 0x34, 0xa1, 0x07, 0x27, 0xc5, 0xd0, 0xb5, 0xfb,
    0xc8, 0x9a, 0x6d, 0x10, 0x7f, 0xa3, 0xea, 0x90, 0xd1, 0x94, 0x26, 0x10,
    0x39, 0x88, 0x19, 0x9d, 0xc1, 0xc8, 0x99, 0xca, 0x2d, 0xe3, 0xa2, 0xb7,
    0x6b, 0x2d, 0x33, 0x85, 0x2e, 0xdd, 0x8b, 0x30, 0x84, 0x60, 0x9c, 0xed,
    0x0e, 0x7e, 0x12, 0xe1, 0x55, 0xbf, 0x50, 0x80, 0xd5, 0x3a, 0xea, 0xbf,
    0x6f, 0x9c, 0x60, 0x03, 0xd3, 0xa0, 0xb3, 0xe2, 0xab, 0xce, 0x61, 0xa6,
    0xce, 0x39, 0x37, 0x0c, 0x9a, 0x6c, 0xd7, 0xb0, 0xbb, 0x63, 0xb7, 0xf8,
    0x7d, 0x5e, 0x73, 0xa2, 0x7c, 0xb5, 0x44, 0x76, 0xa7, 0x2a, 0x04, 0x25,
    0xdc, 0x26, 0x07, 0x18, 0x56, 0xbe, 0x0f, 0xe6, 0x7b, 0xf0, 0x20, 0xe9,
    0x13, 0xb2, 0x9b, 0xa7, 0x87, 0x84, 0x45, 0x78, 0x7c, 0xf6, 0x78, 0x2e,
    0xa2, 0xec, 0xef, 0x50, 0x9b, 0x8d, 0x07, 0xff, 0x41, 0xda, 0x15, 0xb1,
    0xc4, 0x8b, 0x57, 0xfd, 0x25, 0x72, 0x56, 0xa3, 0xd9, 0xc6, 0xa8, 0x0a,
    0x09, 0x7f, 0xfc, 0x49, 0x49, 0xd7, 0x83, 0x0e, 0x6f, 0x49, 0xf6, 0x1e,
    0x17, 0x4c, 0xa2, 0x7b, 0x7d, 0x46, 0xae, 0xfd, 0xbf, 0xe9, 0xc7, 0x6e,
    0xbb, 0xa4, 0x60, 0xa3, 0xd7, 0x6e, 0xea, 0x4f, 0x2d, 0x8c, 0x95, 0x16,
    0xb5, 0xa4, 0xbd, 0x05, 0xe8, 0x89, 0x13, 0x32, 0xcf, 0xc9, 0xa6, 0xb5,
    0xaa, 0x9b, 0xf4, 0xde, 0x57, 0x38, 0xdd, 0xea, 0xf1, 0x98, 0x46, 0x44,
    0x3b, 0xd9, 0xdf, 0x1a, 0xc4, 0x35, 0x8e, 0xe3, 0x2a, 0xee, 0xdb, 0x45,
    0x97, 0x91, 0xe5, 0x96, 0xa1, 0x38, 0x89, 0x48, 0xa0, 0x26, 0xaa, 0xff,
    0x76, 0x2a, 0x17, 0x9b, 0xf3, 0xb6, 0xc2, 0xae, 0x10, 0xac, 0xbe, 0xc5,
    0x78, 0x3e, 0xd8, 0x1e, 0xfc, 0x77, 0x9a, 0x4b, 0xce, 0xf6, 0xac, 0xb5,
    0xb1, 0x29, 0x43, 0xc4, 0x19, 0x6c, 0x77, 0x49, 0x92, 0x97, 0xc3, 0xf4,
    0xbf, 0x76, 0x18, 0x0c, 0x4c, 0x3d, 0xee, 0xf9, 0xbb, 0x15, 0xde, 0x1b,
    0x74, 0xe9, 0x19, 0x18, 0x8a, 0xb7, 0x4a, 0x73, 0x97, 0xc3, 0xa5, 0x7d,
    0x7e, 0xfe, 0xed, 0xf8, 0x15, 0xfa, 0xb1, 0x31, 0x75, 0xb5, 0x97, 0x80,
    0x72, 0x80, 0x69, 0xf9, 0x6e, 0x3d, 0xab, 0x26, 0x65, 0x03, 0x29, 0xeb,
    0xf0, 0xdd, 0x2b, 0xa0, 0x14, 0x59, 0x6c, 0x67, 0x5b, 0x15, 0x7e, 0xfa,
    0x0d, 0x79, 0xc6, 0x0e, 0xbd, 0xa3, 0x22, 0x71, 0xc5, 0x3c, 0x14, 0x14,
    0xb0, 0xfd, 0x28, 0x1c, 0xe9, 0x53, 0x04, 0x89, 0x05, 0xb4, 0x06, 0x64,
    0x82, 0x7e, 0xef, 0xbb, 0x40, 0xf0, 0x40, 0xdb, 0x55, 0x4d, 0x32, 0x13,
    0x46, 0x5d, 0x95, 0xaf, 0xe5, 0x1d, 0xf2, 0x48, 0xa5, 0xcb, 0x9f, 0x15,
    0xb2, 0x67, 0x5a, 0x89, 0x39, 0xa0, 0x6f, 0x9c, 0xf0, 0x42, 0x31, 0xa5,
    0xc8, 0xbb, 0xd3, 0x68, 0x67, 0x29, 0x82, 0xd0, 0x5d, 0x1e, 0x5e, 0xd0,
    0xc9, 0x46, 0x64, 0x43, 0x50, 0x7e, 0x26, 0xef, 0x85, 0xc5, 0xf6, 0x46,
    0xbf, 0x10, 0xea, 0xb3, 0x50, 0x5e, 0x1a, 0x09, 0x72, 0x17, 0x9c, 0x18,
    0x91, 0xfa, 0x01, 0xb0, 0x0a, 0x88, 0x8e, 0xad, 0x56, 0x3b, 0x60, 0xbd,
    0xff, 0xa0, 0x6f, 0x06, 0xf8, 0x74, 0x7f, 0x66, 0x9c, 0x39, 0xb9, 0x09,
    0x16, 0xf4, 0x34, 0x35, 0x51, 0xa5, 0xe3, 0x41, 0x0c, 0xd7, 0xea, 0x7d,
    0x81, 0x64, 0xb9, 0xc0, 0xf5, 0x38, 0xd4, 0x51, 0x22, 0x05, 0x9a, 0x9c,
    0x0c, 0x95, 0xb9, 0xc9, 0x52, 0x1e, 0x3f, 0xe1, 0x20, 0xad, 0xe8, 0x77,
    0x62, 0x06, 0x8a, 0xa0, 0xc4, 0x75, 0xdf, 0x66, 0xb1, 0xfd, 0x06, 0x33,
    0xe0, 0x25, 0x46, 0x79, 0xaf, 0x5a, 0x2a, 0x16, 0xef, 0xb5, 0x4f, 0xbb,
    0xc8, 0x36, 0x47, 0xb9, 0xb9, 0x53, 0x28, 0x3a, 0x2f, 0x11, 0x7b, 0x82,
    0x02, 0xf0, 0xbf, 0x49, 0x62, 0x58, 0xe9, 0x7b, 0xd5, 0xed, 0xf9, 0xec,
    0x0e, 0x00, 0x6e, 0x2f, 0x68, 0x25, 0x99, 0x55, 0x59, 0x36, 0x78, 0x6d,
    0x55, 0x3e, 0x37, 0xec, 0xdf, 0x64, 0xb5, 0xf7, 0xc2, 0x3f, 0xd7, 0x52,
    0x85, 0x9d, 0xa1, 0x74, 0xdc, 0x5a, 0xf1, 0xcf, 0x01, 0x7f, 0xe7, 0xad,
    0x8b, 0x9a, 0xc8, 0x98, 0xb2, 0xf8, 0xeb, 0x90, 0x01, 0x64, 0x76, 0x39,
    0xfe, 0x44, 0x35, 0x45, 0xa2, 0xdf, 0x21, 0x22, 0xfb, 0x45, 0xcd, 0x3b,
    0xa6, 0xcb, 0x77, 0x0e, 0xfe, 0x8f, 0xbd, 0xcc, 0xcd, 0xe4, 0x9d, 0xc1,
    0xec, 0x08, 0xd7, 0x79, 0x79, 0xb8, 0xcb, 0xfb, 0xac, 0xeb, 0xd9, 0xfc,
    0x14, 0x96, 0xc0, 0x13, 0xf1, 0x95, 0x7d, 0xcd, 0x17, 0xa0, 0xaf, 0x3c,
    0xf0, 0xf8, 0xb5, 0xdf, 0x25, 0x9b, 0x51, 0x0f, 0x75, 0x7d, 0xbd, 0x62,
    0xb0, 0xdc, 0x29, 0x9d, 0x29, 0x11, 0x0e, 0xeb, 0x29, 0xad, 0x57, 0xf9,
    0x7e, 0x4e, 0x33, 0x12, 0x85, 0xdb, 0x62, 0x1c, 0xd7, 0x12, 0xa9, 0xb9,
    0x4b, 0x91, 0x00, 0x83, 0xba, 0x67, 0x1c, 0x3b, 0x88, 0xf9, 0x87, 0x3c,
    0xb5, 0x71, 0xb1, 0x01, 0xb7, 0xe6, 0x01, 0xc0, 0x71, 0x9d, 0xe4, 0xbc,
    0xbe, 0xbd, 0x1f, 0x35, 0xf8, 0xae, 0x7e, 0xe2, 0xd3, 0x87, 0x57, 0x0c,
    0x85, 0x28, 0xb3, 0x77, 0x31, 0xe3, 0x60, 0xa5, 0xe2, 0x1b, 0x16, 0xa7,
    0xaa, 0x0c, 0x46, 0xd4, 0xdc, 0x3d, 0xfb, 0x31, 0xd6, 0xee, 0x9f, 0x04,
    0x59, 0x85, 0x29, 0x87, 0x3c, 0xb6, 0x8c, 0x88, 0xf5, 0x09, 0xef, 0x9c,
    0xc1, 0x75, 0x52, 0x83, 0x39, 0xfd, 0x17, 0xaf, 0x26, 0x2d, 0x38, 0x5b,
    0x79, 0x37, 0x8e, 0x28, 0x4e, 0x95, 0x84, 0xfe, 0x5b, 0x88, 0xf2, 0x13,
    0x50, 0x2e, 0x87, 0xc2, 0xa1, 0xba, 0x34, 0x31, 0xd2, 0x16, 0x5d, 0xe3,
    0xaa, 0xa4, 0xaa, 0x48, 0xc6, 0x75, 0x73, 0xc9, 0x82, 0x50, 0x1f, 0x80,
    0x98, 0x0a, 0xe0, 0xfc, 0x29, 0xb8, 0x33, 0x57, 0x7f, 0x4c, 0xf9, 0x4e,
    0x4f, 0xe2, 0xa4, 0xdd, 0xf6, 0xf4, 0x7f, 0x57, 0x0c, 0x0a, 0x70, 0x0a,
    0x3c, 0xac, 0xfe, 0xe8, 0x2c, 0x8d, 0xa4, 0x56, 0x9f, 0x0c, 0x27, 0x5a,
    0x61, 0x1a, 0xc2, 0x24, 0x6c, 0x21, 0x70, 0xe8, 0x07, 0x82, 0xf4, 0x8b,
    0x6d, 0xf0, 0xa4, 0x5d, 0x88, 0x11, 0x0d, 0x56, 0x9d, 0xfe, 0x6f, 0x60,
    0x6b, 0x9b, 0xb4, 0xa1, 0xa0, 0xc5, 0x08, 0x7f, 0xd8, 0x2f, 0xb8, 0xb4,
    0xb5, 0x2b, 0x7a, 0xd3, 0x97, 0xde, 0xd0, 0xb0, 0x40, 0x89, 0x4e, 0x1f,
    0x36, 0x46, 0x36, 0xc5, 0x8c, 0x23, 0x52, 0xa5, 0xbd, 0x4a, 0xa5, 0x27,
    0xf0, 0x7f, 0x9e, 0x76, 0x9d, 0x3d, 0xcb, 0x32, 0xe8, 0x01, 0xec, 0xe6,
    0x63, 0x02, 0xa2, 0xa7, 0x1c, 0xb2, 0x4f, 0xe3, 0x62, 0xb6, 0x38, 0x5f,
    0x51, 0x61, 0x3c, 0xb2, 0xd0, 0xd7, 0xaf, 0x2e, 0x5e, 0xd2, 0xaf, 0x2b,
    0xf7, 0xb9, 0x6f, 0xfc, 0xe8, 0x68, 0x77, 0x3c, 0x65, 0xef, 0x2c, 0xe8,
    0xb8, 0x94, 0xdd, 0x9d, 0x04, 0x90, 0x7c, 0xd8, 0x68, 0xf8, 0xe0, 0x13,
    0x2c, 0x30, 0xdb, 0xa2, 0xea, 0x98, 0xf5, 0x63, 0x43, 0x52, 0x7d, 0x4f,
    0x44, 0x92, 0x2a, 0xcc, 0x7c, 0x02, 0xa9, 0x98, 0x63, 0x1c, 0x56, 0x4a,
    0x29, 0x40, 0xb9, 0x16, 0x9f, 0x37, 0xd8, 0x56, 0x36, 0x8e, 0xeb, 0xd6,
    0x39, 0x9c, 0x7e, 0x5e, 0xef, 0xe5, 0x8a, 0x88, 0xcb, 0xa1, 0x34, 0x3d,
    0x4b, 0x9c, 0x5e, 0x5f, 0x68, 0x03, 0xb0, 0x78, 0x8f, 0xe7, 0x18, 0x55,
    0xab, 0x90, 0x42, 0xe6, 0x3f, 0xe6, 0x48, 0xe7, 0xa2, 0xbc, 0xec, 0x2e,
    0x71, 0x4c, 0x50, 0x78, 0x26, 0xe7, 0xa4, 0xb8, 0x73, 0x6b, 0x26, 0x75,
    0x43, 0x0a, 0x0f, 0x1b, 0xec, 0x74, 0xfe, 0x10, 0x16, 0xcd, 0xcb, 0xe3,
    0xbb, 0xa8, 0x6f, 0x95, 0x80, 0xab, 0x6a, 0xb4, 0x68, 0x89, 0xcf, 0x3c,
    0x8e, 0xcc, 0xae, 0x36, 0x73, 0x15, 0x3c, 0x80, 0xc1, 0x08, 0xe2, 0xb1,
    0x15, 0xe7, 0xaf, 0xb0, 0x5e, 0x0a, 0x71, 0x23, 0x36, 0x02, 0xeb, 0x1a,
    0x07, 0x69, 0x8f, 0xdc, 0xe9, 0x12, 0xb4, 0xde, 0x3c, 0x7c, 0xf4, 0x43,
    0xaf, 0xfb, 0xb2, 0xc7, 0x15, 0xfa, 0x9a, 0xfd, 0xb9, 0x68, 0xe1, 0x70,
    0xe2, 0x00, 0xfd, 0x4f, 0xf8, 0x35, 0x5d, 0xf6, 0x01, 0x0b, 0x1f, 0x93,
    0x80, 0x0d, 0x4f, 0x32, 0xcd, 0x29, 0xba, 0xe4, 0x9a, 0xfa, 0xd6, 0x98,
    0x4b, 0x63, 0x59, 0x46, 0xbb, 0x75, 0x9a, 0x0c, 0x85, 0xeb, 0x3d, 0xb1,
    0xbd, 0xc6, 0x69, 0x14, 0xe0, 0xd3, 0x8e, 0x43, 0x41, 0xc0, 0x86, 0x1f,
    0x62, 0xbc, 0x41, 0xb3, 0x43, 0xdc, 0xf2, 0x63, 0x94, 0xa4, 0x67, 0x7f,
    0xf9, 0x68, 0x6c, 0x89, 0x56, 0xdd, 0x76, 0x36, 0x23, 0x6f, 0x5e, 0x2c,
    0xf5, 0x25, 0xba, 0x84, 0x43, 0xd6, 0xd5, 0x81, 0x4b, 0x95, 0x7e, 0xff,
    0x82, 0xf9, 0xb8, 0x3f, 0x54, 0x50, 0x95, 0xb8, 0xb8, 0xfa, 0x60, 0x0f,
    0xbc, 0x8a, 0xe2, 0x4b, 0x77, 0x3b, 0x08, 0x3d, 0x0c, 0x12, 0xf6, 0x27,
    0xc5, 0xa2, 0x16, 0x08, 0xf2, 0x4d, 0xe9, 0xfd, 0x8b, 0x91, 0x17, 0x4c,
    0xb0, 0xca, 0x09, 0xb9, 0x8d, 0x6a, 0x62, 0x69, 0x9e, 0x4a, 0x4f, 0xf3,
    0x1c, 0xa8, 0x73, 0xbe, 0xe8, 0xe3, 0x10, 0x6d, 0x6e, 0x7f, 0xbb, 0xeb,
    0xa6, 0xf0, 0x90, 0x08, 0x8e, 0xb4, 0xab, 0xd0, 0xfd, 0x1f, 0xc8, 0x34,
    0x5e, 0x90, 0x3f, 0x19, 0x3a, 0x5a, 0x5a, 0xf5, 0x99, 0x19, 0xdb, 0x0e,
    0xd3, 0x3a, 0xd5, 0xb7
};
static unsigned char mldsa_44_pub[] = {
    0x89, 0x38, 0xa0, 0x20, 0xc3, 0x92, 0xb3, 0x91, 0x75, 0x2c, 0xfa, 0x27,
    0xcc, 0x37, 0x08, 0x32, 0x5d, 0xcc, 0xd9, 0x06, 0xf1, 0xda, 0xa8, 0xc9,
    0xbe, 0x57, 0x89, 0xb5, 0xda, 0x48, 0xae, 0x20, 0xe4, 0x4f, 0x38, 0x8a,
    0xb0, 0xe9, 0xc5, 0x1b, 0x9f, 0x78, 0xfd, 0x8e, 0x62, 0xa5, 0xad, 0x1c,
    0x6e, 0x5c, 0xeb, 0x50, 0xf2, 0xfb, 0x66, 0xfd, 0xa4, 0x70, 0x2c, 0x42,
    0x2f, 0x1b, 0x94, 0x9d, 0x36, 0x31, 0xcc, 0xe8, 0x25, 0x5e, 0xe9, 0x42,
    0xa3, 0x98, 0xe2, 0x80, 0x42, 0xff, 0xe9, 0xfb, 0x8d, 0x3a, 0xe5, 0x4f,
    0x01, 0x7a, 0x34, 0xd5, 0xdf, 0xbd, 0x10, 0xf7, 0x6e, 0x63, 0xbe, 0xc2,
    0xd1, 0x53, 0xba, 0x77, 0x2f, 0x5c, 0x92, 0xca, 0x50, 0xf2, 0x1f, 0x46,
    0xc6, 0x5d, 0x3b, 0x42, 0x4f, 0xfb, 0x48, 0x4d, 0xec, 0x17, 0x12, 0x06,
    0x13, 0xa3, 0x54, 0xe5, 0x73, 0xb9, 0x18, 0x09, 0x87, 0xa3, 0xe3, 0x73,
    0xcc, 0xb3, 0x38, 0x63, 0x6a, 0x0d, 0x2f, 0x10, 0x6d, 0x59, 0xdd, 0x48,
    0x2a, 0x63, 0x2e, 0x18, 0x6d, 0xca, 0xd9, 0x57, 0xcd, 0x85, 0xd2, 0xa5,
    0xcc, 0x41, 0x5e, 0xcd, 0x65, 0x9d, 0xe4, 0x5e, 0x03, 0xaf, 0x95, 0xc6,
    0x0e, 0x4f, 0x97, 0xa8, 0x5b, 0xde, 0xc9, 0x7b, 0x2c, 0xa7, 0x2d, 0xba,
    0x52, 0x22, 0x17, 0x03, 0x75, 0xfc, 0xb7, 0xa2, 0xe1, 0xa4, 0x8b, 0xb9,
    0x3f, 0xe3, 0xcc, 0x13, 0xe9, 0x2c, 0xd2, 0xd1, 0x6e, 0xc9, 0x05, 0x82,
    0x6c, 0xf9, 0x54, 0xb7, 0xc5, 0x88, 0x51, 0xd2, 0x99, 0x05, 0x82, 0x03,
    0xee, 0xbb, 0xaa, 0x6a, 0x81, 0xea, 0x3a, 0x05, 0x28, 0x29, 0x5a, 0x4e,
    0x8e, 0x0a, 0xcc, 0x26, 0x70, 0xb0, 0x23, 0x8e, 0x5a, 0xf4, 0x13, 0x42,
    0xa0, 0xdd, 0xfd, 0x4d, 0xe4, 0x71, 0xc9, 0x5a, 0x6d, 0xef, 0x45, 0x87,
    0xbb, 0xa8, 0xd7, 0x47, 0x32, 0x3d, 0x0f, 0xea, 0x94, 0x73, 0x7f, 0x89,
    0x1c, 0x1e, 0x16, 0x5f, 0xc0, 0xf3, 0x75, 0x83, 0x28, 0x92, 0x90, 0x13,
    0xf8, 0xcd, 0x6c, 0x5c, 0x80, 0xbd, 0xfe, 0x94, 0xc0, 0x44, 0x5a, 0x08,
    0xd2, 0x68, 0x1b, 0xc6, 0xf1, 0x7b, 0xfa, 0x63, 0xfd, 0x30, 0xf6, 0xd3,
    0x99, 0x99, 0x0c, 0xc3, 0xe8, 0x1f, 0x43, 0xee, 0x5f, 0xc0, 0x1d, 0x67,
    0xc8, 0x31, 0x50, 0xce, 0xfc, 0xcb, 0x8f, 0x30, 0x0b, 0xee, 0x25, 0x95,
    0x0f, 0x50, 0x5d, 0x43, 0xdd, 0x80, 0x06, 0x66, 0xfa, 0xf1, 0xb3, 0x96,
    0xaa, 0x8b, 0x23, 0xf3, 0xc2, 0x5d, 0xf9, 0x9d, 0x4d, 0xe1, 0xc5, 0x19,
    0x14, 0x17, 0x9b, 0xb4, 0x9a, 0x0b, 0x5a, 0x62, 0x12, 0xf9, 0x63, 0xc0,
    0xcc, 0xed, 0xe1, 0x4a, 0xc9, 0x09, 0x17, 0x15, 0xdc, 0x88, 0x02, 0x4b,
    0xc7, 0x2c, 0xa4, 0x46, 0xb8, 0xdb, 0xcf, 0xdc, 0x14, 0xf4, 0xe7, 0x25,
    0x2a, 0x83, 0x59, 0xd7, 0x55, 0x70, 0x8a, 0x0b, 0xd0, 0xe9, 0x3a, 0x70,
    0x5e, 0x5a, 0x50, 0x09, 0x4e, 0xd9, 0xbf, 0x43, 0x7b, 0x05, 0x03, 0x0c,
    0x46, 0xc6, 0x9c, 0x14, 0x40, 0xc7, 0xb7, 0xb7, 0x53, 0x82, 0x3f, 0x8d,
    0x88, 0xa5, 0x78, 0xc2, 0x1f, 0x22, 0x15, 0xbb, 0x5b, 0x01, 0x1f, 0x87,
    0xd5, 0x68, 0xa5, 0xac, 0x0d, 0x7e, 0xaf, 0xfd, 0xb8, 0x3d, 0xbe, 0xe6,
    0x5d, 0x88, 0x23, 0xf6, 0x08, 0xbb, 0xbb, 0x42, 0x53, 0x5a, 0x58, 0xbb,
    0xc6, 0x31, 0xe4, 0x45, 0x5d, 0xd2, 0x73, 0x20, 0xef, 0x76, 0x1f, 0x2e,
    0xf6, 0x71, 0x64, 0x5d, 0xf8, 0xd5, 0x81, 0x07, 0x68, 0xae, 0x58, 0x90,
    0xa3, 0x3b, 0x10, 0x1c, 0x42, 0x76, 0x0b, 0x98, 0x26, 0xf0, 0xba, 0xa0,
    0xa5, 0x76, 0x6c, 0x53, 0x44, 0x5e, 0xaf, 0x3b, 0x04, 0x9e, 0x4f, 0xcf,
    0xe9, 0xb6, 0x1b, 0x4f, 0x1d, 0x19, 0x25, 0x94, 0x3a, 0x3d, 0x33, 0xa4,
    0x48, 0x50, 0xdc, 0x24, 0x21, 0x1e, 0xc2, 0x6e, 0x4f, 0xda, 0x43, 0x43,
    0x6b, 0xcc, 0x07, 0xc6, 0x02, 0xf1, 0xa3, 0x93, 0x88, 0x1c, 0x60, 0x42,
    0xf5, 0x4b, 0x3a, 0xaf, 0x0a, 0xb5, 0x18, 0x84, 0xb5, 0x2e, 0x46, 0xd6,
    0x36, 0x02, 0xd2, 0x03, 0xf4, 0xfa, 0x8f, 0x8e, 0x2f, 0x42, 0x38, 0x88,
    0x85, 0x28, 0x30, 0x9c, 0xfa, 0x18, 0xd9, 0x1c, 0xb1, 0xba, 0x68, 0x70,
    0x9f, 0x4c, 0x96, 0x99, 0x94, 0x87, 0xf4, 0x16, 0x47, 0x7d, 0xdd, 0xa1,
    0x6c, 0xee, 0xef, 0xc3, 0x1c, 0x5b, 0xae, 0x90, 0x5e, 0x4b, 0xd8, 0xc4,
    0x4c, 0xfc, 0x64, 0x43, 0x3a, 0x68, 0xb1, 0x95, 0x8f, 0x9f, 0x96, 0x93,
    0x31, 0x36, 0xf9, 0xcd, 0x68, 0xc3, 0x84, 0x51, 0x40, 0x01, 0xf7, 0x01,
    0x9c, 0x9b, 0x88, 0xc2, 0xf6, 0x96, 0xaa, 0xab, 0x31, 0x9f, 0x1f, 0x66,
    0x00, 0x81, 0xf7, 0xce, 0x24, 0xa1, 0xd4, 0x2d, 0x06, 0xd7, 0x4e, 0x27,
    0xdf, 0x46, 0xc0, 0x29, 0x35, 0x5f, 0x0e, 0x55, 0x68, 0xfe, 0x1c, 0x1a,
    0x45, 0xcb, 0x52, 0xf1, 0x36, 0x24, 0xbe, 0x96, 0xa6, 0xc3, 0xbd, 0x63,
    0x99, 0x01, 0xad, 0xce, 0x4a, 0x3f, 0x16, 0xd6, 0x8c, 0x4f, 0x49, 0x16,
    0x4e, 0x07, 0xe7, 0xe4, 0x97, 0xcb, 0x06, 0xdf, 0x02, 0x58, 0x14, 0x7b,
    0x68, 0x3b, 0xf2, 0x06, 0x13, 0x2f, 0xe9, 0x76, 0xb8, 0x31, 0x01, 0x49,
    0x6c, 0xf3, 0x47, 0x3a, 0xb0, 0xda, 0xb4, 0x77, 0xcb, 0x58, 0x81, 0x60,
    0x63, 0x66, 0x71, 0x41, 0x6f, 0x2d, 0xa9, 0x16, 0x42, 0x89, 0x4f, 0xc0,
    0x9b, 0x52, 0x3a, 0xd9, 0x3f, 0x65, 0x8a, 0x03, 0xca, 0x23, 0x4d, 0xfc,
    0xdb, 0x5d, 0xea, 0xd9, 0xe0, 0x66, 0xf2, 0x3b, 0xdd, 0x69, 0x2d, 0x3f,
    0xbb, 0x14, 0xcb, 0x11, 0xda, 0x16, 0xc7, 0xb8, 0x86, 0x29, 0xd3, 0xf1,
    0x54, 0xb4, 0xa1, 0xdc, 0xab, 0x06, 0x0f, 0xc3, 0x72, 0xc3, 0x98, 0x65,
    0x8a, 0x28, 0xc0, 0xfc, 0x4b, 0xeb, 0x1c, 0x76, 0x38, 0x55, 0x1e, 0x80,
    0xa3, 0xba, 0x44, 0xf6, 0x28, 0xd9, 0x84, 0x98, 0x5d, 0x64, 0x6d, 0xbd,
    0x2d, 0x99, 0x16, 0x3e, 0xa7, 0xd1, 0x30, 0xea, 0x2d, 0xe7, 0xfd, 0x3b,
    0x39, 0x2f, 0xfc, 0x8d, 0x8d, 0x0c, 0x11, 0xae, 0x7e, 0x82, 0xff, 0x5d,
    0x29, 0xba, 0x3a, 0x92, 0x3a, 0xd2, 0x15, 0xfa, 0x1b, 0x4f, 0xb3, 0x24,
    0x09, 0xef, 0x84, 0x0b, 0x44, 0xe1, 0x90, 0xd6, 0x65, 0x2a, 0x6e, 0x48,
    0xc9, 0x11, 0x39, 0x09, 0xa2, 0x60, 0xa7, 0xb6, 0x72, 0x48, 0x15, 0x91,
    0x63, 0x32, 0x61, 0x57, 0xd5, 0x04, 0xa4, 0x3c, 0x86, 0x25, 0xa9, 0x1d,
    0xf7, 0xfa, 0x13, 0x78, 0x84, 0x9e, 0xf4, 0xfe, 0xce, 0xaf, 0x10, 0x86,
    0x9f, 0x39, 0xba, 0x8b, 0x87, 0x36, 0x43, 0x6d, 0xa3, 0x0a, 0xe7, 0xda,
    0xc5, 0x50, 0xf4, 0xd5, 0x0d, 0xc1, 0x00, 0xe8, 0x6b, 0x38, 0x7a, 0x98,
    0xb5, 0xc3, 0xc1, 0xcc, 0x78, 0x33, 0x93, 0xa5, 0x88, 0x05, 0x59, 0xdc,
    0xb6, 0xf3, 0xbc, 0x91, 0x13, 0xd7, 0x17, 0xd2, 0x98, 0x0e, 0x6b, 0x49,
    0x5d, 0x2a, 0x0c, 0xe2, 0x84, 0xdc, 0x65, 0x72, 0xa4, 0x4b, 0x95, 0x6e,
    0x11, 0x9d, 0x17, 0xb2, 0x61, 0xd7, 0xa3, 0x27, 0xa8, 0x3a, 0xa4, 0xe6,
    0x7b, 0x7c, 0x9a, 0x05, 0x76, 0xe7, 0xd7, 0x3b, 0x54, 0xf4, 0x3a, 0x1a,
    0x6b, 0x17, 0xe5, 0xa7, 0x01, 0x99, 0xa6, 0x2a, 0x60, 0x60, 0x8a, 0x85,
    0xbd, 0x50, 0xa0, 0x17, 0x45, 0x93, 0x20, 0xf0, 0x63, 0xd0, 0xe4, 0x74,
    0x7f, 0x8d, 0xd4, 0x49, 0x55, 0x2e, 0x3e, 0xab, 0x6c, 0xb2, 0x6c, 0xff,
    0xb7, 0x6e, 0xb0, 0x43, 0xca, 0x5f, 0x0b, 0x1d, 0x28, 0x57, 0x92, 0xfe,
    0x5e, 0xd9, 0x26, 0x09, 0x5f, 0x66, 0xdd, 0x3f, 0x08, 0xd2, 0xfe, 0x12,
    0x5b, 0xf7, 0x3c, 0x90, 0x11, 0x3d, 0x95, 0x2c, 0x36, 0x0d, 0x8c, 0x70,
    0x2b, 0x8b, 0x00, 0x6b, 0x21, 0x48, 0x83, 0xf9, 0x39, 0xa8, 0x75, 0x34,
    0xc4, 0x80, 0x8e, 0xc1, 0xb0, 0x6c, 0xa1, 0x90, 0xb4, 0x52, 0x11, 0xae,
    0xb1, 0xe3, 0x2f, 0xf2, 0x08, 0x46, 0x44, 0x98, 0x1c, 0xeb, 0x74, 0x33,
    0xd5, 0x7b, 0x57, 0xe0, 0x75, 0x3e, 0xa8, 0xb6, 0x29, 0x68, 0x83, 0x6c,
    0xd1, 0xe4, 0x11, 0xdf, 0x89, 0xc6, 0x20, 0xae, 0xd1, 0xec, 0x7f, 0x0d,
    0x68, 0xbb, 0xfe, 0x45, 0xda, 0x99, 0x99, 0x46, 0xe8, 0xc2, 0x48, 0xbe,
    0x73, 0xc9, 0xec, 0x40, 0xfb, 0xe4, 0x5e, 0xa9, 0x77, 0x72, 0xa0, 0x2b,
    0x54, 0xf2, 0x5a, 0x5c, 0x4e, 0x43, 0x89, 0x55, 0xa9, 0x01, 0x26, 0x84,
    0xfb, 0xeb, 0x43, 0xb3, 0xd3, 0x60, 0x1b, 0x38, 0x09, 0xcc, 0xd6, 0x4f,
    0xd3, 0xca, 0xd4, 0x1d, 0xf2, 0xa2, 0xfd, 0x75, 0x16, 0xbf, 0x62, 0x84,
    0x63, 0xa0, 0xc2, 0x64, 0x6e, 0x80, 0x57, 0x68, 0x96, 0x95, 0x8c, 0x6c,
    0xc5, 0xd0, 0xf0, 0x33, 0x6d, 0x18, 0x79, 0xf7, 0x23, 0x0e, 0x34, 0x60,
    0xdf, 0x2c, 0x69, 0x60, 0xfc, 0x28, 0xb5, 0xbc, 0xc2, 0x93, 0xac, 0xbc,
    0x14, 0xe3, 0x96, 0x07, 0x5b, 0x2f, 0x6a, 0xf2, 0x94, 0x63, 0x70, 0xd7,
    0xf6, 0x54, 0x94, 0xbb, 0x72, 0xde, 0xa8, 0x27, 0xff, 0xa7, 0x67, 0xd7,
    0x20, 0xde, 0x0f, 0x22, 0xb0, 0x74, 0x4c, 0x9c, 0xbd, 0x86, 0x58, 0xe6,
    0x78, 0x1c, 0xe4, 0x47, 0x74, 0x97, 0x8e, 0xd7, 0x66, 0x34, 0xdc, 0x4a,
    0x0f, 0x80, 0x4f, 0xd7, 0x77, 0xe4, 0x7c, 0xfa, 0xbd, 0xac, 0x35, 0xdd,
    0x35, 0xbb, 0x7f, 0x74, 0xc4, 0xc1, 0xdc, 0x5f, 0x09, 0xe8, 0x31, 0xb5,
    0x55, 0x92, 0xe5, 0x59, 0x18, 0xfe, 0x9c, 0xfe, 0xf5, 0x25, 0x71, 0x71,
    0x84, 0x0f, 0x7a, 0x35, 0xf8, 0x56, 0xb1, 0xcf, 0x9a, 0x04, 0x05, 0x5b,
    0xa4, 0x74, 0xae, 0x66, 0x13, 0x07, 0xfd, 0xf2, 0xa6, 0xc8, 0xdc, 0xb1,
    0xdf, 0x1d, 0xd6, 0xa2
 };

 /* Import ML-DSA private key using the already expanded form. */
static CK_RV import_mldsa_priv_key(CK_SESSION_HANDLE session,
                                   CK_OBJECT_HANDLE* obj)
{
    CK_RV ret;
    CK_ML_DSA_PARAMETER_SET_TYPE paramSet = CKP_ML_DSA_44;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,         &privKeyClass,  sizeof(privKeyClass)  },
        { CKA_KEY_TYPE,      &mldsaKeyType,  sizeof(mldsaKeyType)  },
        { CKA_SIGN,          &ckTrue,        sizeof(ckTrue)        },
        { CKA_PARAMETER_SET, &paramSet,      sizeof(paramSet)      },
        { CKA_VALUE,         mldsa_44_priv,  sizeof(mldsa_44_priv) },
    };
    int cnt = sizeof(tmpl)/sizeof(*tmpl);

    ret = funcList->C_CreateObject(session, tmpl, cnt, obj);
    CHECK_CKR(ret, "ML-DSA Priv Key CreateObject from expanded key");

    return ret;
}

/* Import ML-DSA private key using only the seed. The expanded private
 * key is derived internally from the seed. */
static CK_RV import_mldsa_priv_key_from_seed(CK_SESSION_HANDLE session,
                                              CK_OBJECT_HANDLE* obj)
{
    CK_RV ret;
    CK_ML_DSA_PARAMETER_SET_TYPE paramSet = CKP_ML_DSA_44;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,         &privKeyClass,  sizeof(privKeyClass)  },
        { CKA_KEY_TYPE,      &mldsaKeyType,  sizeof(mldsaKeyType)  },
        { CKA_SIGN,          &ckTrue,        sizeof(ckTrue)        },
        { CKA_PARAMETER_SET, &paramSet,      sizeof(paramSet)      },
        { CKA_SEED,          mldsa_44_seed,  sizeof(mldsa_44_seed) },
    };
    int cnt = sizeof(tmpl)/sizeof(*tmpl);

    ret = funcList->C_CreateObject(session, tmpl, cnt, obj);
    CHECK_CKR(ret, "ML-DSA Priv Key CreateObject from seed");

    return ret;
}

/* Import ML-DSA private key providing both the seed and the expanded private
 * key. The implementation must verify that both are consistent. */
static CK_RV import_mldsa_priv_key_and_seed(CK_SESSION_HANDLE session,
                                             CK_OBJECT_HANDLE* obj)
{
    CK_RV ret;
    CK_ML_DSA_PARAMETER_SET_TYPE paramSet = CKP_ML_DSA_44;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,         &privKeyClass,  sizeof(privKeyClass)  },
        { CKA_KEY_TYPE,      &mldsaKeyType,  sizeof(mldsaKeyType)  },
        { CKA_SIGN,          &ckTrue,        sizeof(ckTrue)        },
        { CKA_PARAMETER_SET, &paramSet,      sizeof(paramSet)      },
        { CKA_SEED,          mldsa_44_seed,  sizeof(mldsa_44_seed) },
        { CKA_VALUE,         mldsa_44_priv,  sizeof(mldsa_44_priv) },
    };
    int cnt = sizeof(tmpl)/sizeof(*tmpl);

    ret = funcList->C_CreateObject(session, tmpl, cnt, obj);
    CHECK_CKR(ret, "ML-DSA Priv Key CreateObject from seed and expanded key");

    return ret;
}

static CK_RV import_mldsa_pub_key(CK_SESSION_HANDLE session,
                                  CK_OBJECT_HANDLE* obj)
{
    CK_RV ret;
    CK_ML_DSA_PARAMETER_SET_TYPE paramSet = CKP_ML_DSA_44;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,         &pubKeyClass,   sizeof(pubKeyClass)  },
        { CKA_KEY_TYPE,      &mldsaKeyType,  sizeof(mldsaKeyType) },
        { CKA_VERIFY,        &ckTrue,        sizeof(ckTrue)       },
        { CKA_PARAMETER_SET, &paramSet,      sizeof(paramSet)     },
        { CKA_VALUE,         mldsa_44_pub,   sizeof(mldsa_44_pub) },
    };
    int cnt = sizeof(tmpl)/sizeof(*tmpl);

    ret = funcList->C_CreateObject(session, tmpl, cnt, obj);
    CHECK_CKR(ret, "ML-DSA Pub Key CreateObject");

    return ret;
}

static CK_RV mldsa_sign_verify(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE privKey,
                               CK_OBJECT_HANDLE pubKey, CK_MECHANISM* mech,
                               byte* data, CK_ULONG dataSz)
{
    CK_RV ret = CKR_OK;
    byte sig[8192];
    byte sigBad[8192];
    CK_ULONG sigSz = sizeof(sig);
    CK_ULONG sigBadSz;

    ret = funcList->C_SignInit(session, mech, privKey);
    CHECK_CKR(ret, "ML-DSA Sign Init");
    if (ret == CKR_OK) {
        sigSz = 0;
        ret = funcList->C_Sign(session, data, dataSz, NULL, &sigSz);
        CHECK_CKR(ret, "ML-DSA Sign out size no out");
    }
    if (ret == CKR_OK) {
        CHECK_COND(sigSz == DILITHIUM_ML_DSA_44_SIG_SIZE,
                   ret, "ML-DSA Sign out size");
    }
    if (ret == CKR_OK) {
        CK_ULONG smallSz = 1;
        ret = funcList->C_Sign(session, data, dataSz, sig, &smallSz);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL,
                       "ML-DSA Sign out size too small");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Sign(session, data, dataSz, sig, &sigSz);
        CHECK_CKR(ret, "ML-DSA Sign");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyInit(session, mech, pubKey);
        CHECK_CKR(ret, "ML-DSA Verify Init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Verify(session, data, dataSz, sig, sigSz);
        CHECK_CKR(ret, "ML-DSA Verify");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_VerifyInit(session, mech, pubKey);
        CHECK_CKR(ret, "ML-DSA Verify Init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Verify(session, data, dataSz - 1, sig, sigSz);
        if (mech->mechanism == CKM_HASH_ML_DSA) {
            /* Invalid hash digest size is not allowed, so operation fails */
            CHECK_CKR_FAIL(ret, CKR_FUNCTION_FAILED, "ML-DSA Verify bad data");
        } else {
            /* Invalid data size results in invalid signature*/
            CHECK_CKR_FAIL(ret, CKR_SIGNATURE_INVALID, "ML-DSA Verify bad data");
        }
    }
    if (ret == CKR_OK) {
        XMEMCPY(sigBad, sig, sigSz);
        sigBad[0] ^= 0x01;
        sigBadSz = sigSz;
        ret = funcList->C_VerifyInit(session, mech, pubKey);
        CHECK_CKR(ret, "ML-DSA Verify Init");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_Verify(session, data, dataSz, sigBad, sigBadSz);
        CHECK_CKR_FAIL(ret, CKR_SIGNATURE_INVALID, "ML-DSA Verify bad sig");
    }

    return ret;
}

static CK_RV mldsa_test(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE privKey,
                        CK_OBJECT_HANDLE pubKey)
{
    CK_RV ret = CKR_OK;
    byte data[64];
    CK_MECHANISM mech;
    CK_SIGN_ADDITIONAL_CONTEXT signCtx;
    byte ctx[] = "mldsa-ctx";
#ifndef NO_SHA256
    byte preHash[WC_SHA256_DIGEST_SIZE];
    CK_HASH_SIGN_ADDITIONAL_CONTEXT hashCtx;

    XMEMSET(preHash, 0x3C, sizeof(preHash));
    XMEMSET(&hashCtx, 0, sizeof(hashCtx));
#endif

    XMEMSET(data, 0x5A, sizeof(data));
    XMEMSET(&signCtx, 0, sizeof(signCtx));
    signCtx.hedgeVariant = CKH_HEDGE_REQUIRED;
    signCtx.pContext = ctx;
    signCtx.ulContextLen = sizeof(ctx) - 1;

    mech.mechanism = CKM_ML_DSA;
    mech.pParameter = &signCtx;
    mech.ulParameterLen = sizeof(signCtx);
    ret = mldsa_sign_verify(session, privKey, pubKey, &mech, data,
                            sizeof(data));
    if (ret == CKR_OK) {
        signCtx.pContext = NULL;
        signCtx.ulContextLen = 0;
        ret = mldsa_sign_verify(session, privKey, pubKey, &mech, data,
                                sizeof(data));
    }

#ifndef NO_SHA256
    if (ret == CKR_OK) {
        hashCtx.hedgeVariant = CKH_HEDGE_REQUIRED;
        hashCtx.pContext = ctx;
        hashCtx.ulContextLen = sizeof(ctx) - 1;
        hashCtx.hash = CKM_SHA256;

        mech.mechanism = CKM_HASH_ML_DSA;
        mech.pParameter = &hashCtx;
        mech.ulParameterLen = sizeof(hashCtx);
        ret = mldsa_sign_verify(session, privKey, pubKey, &mech, preHash,
                                sizeof(preHash));
    }
    if (ret == CKR_OK) {
        hashCtx.pContext = NULL;
        hashCtx.ulContextLen = 0;
        ret = mldsa_sign_verify(session, privKey, pubKey, &mech, preHash,
                                sizeof(preHash));
    }
#endif

    return ret;
}

static CK_RV test_mldsa_gen_keys(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret = CKR_OK;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;

    ret = gen_mldsa_keys(session, CKP_ML_DSA_44, &pub, &priv, NULL, 0, NULL, 0,
                         0);
    if (ret == CKR_OK)
        ret = mldsa_test(session, priv, pub);

    if (priv != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, priv);
    if (pub != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, pub);

    return ret;
}

static CK_RV test_mldsa_gen_keys_id(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret = CKR_OK;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    unsigned char* privId = (unsigned char*)"mldsa-priv-id";
    int privIdLen = (int)XSTRLEN((const char*)privId);

    ret = gen_mldsa_keys(session, CKP_ML_DSA_44, &pub, NULL, privId, privIdLen,
                         NULL, 0, 0);
    if (ret == CKR_OK)
        ret = find_mldsa_priv_key(session, &priv, privId, privIdLen);
    if (ret == CKR_OK)
        ret = mldsa_test(session, priv, pub);

    if (priv != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, priv);
    if (pub != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, pub);

    return ret;
}

static CK_RV test_mldsa_gen_keys_token(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    unsigned char* privId = (unsigned char*)"mldsa-priv-token";
    unsigned char* pubId = (unsigned char*)"mldsa-pub-token";
    int privIdLen = (int)XSTRLEN((const char*)privId);
    int pubIdLen = (int)XSTRLEN((const char*)pubId);

    return gen_mldsa_keys(session, CKP_ML_DSA_44, NULL, NULL, privId, privIdLen,
                          pubId, pubIdLen, 1);
}

static CK_RV test_mldsa_token_keys(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret = CKR_OK;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    unsigned char* privId = (unsigned char*)"mldsa-priv-token";
    unsigned char* pubId = (unsigned char*)"mldsa-pub-token";
    int privIdLen = (int)XSTRLEN((const char*)privId);
    int pubIdLen = (int)XSTRLEN((const char*)pubId);

    ret = find_mldsa_priv_key(session, &priv, privId, privIdLen);
    if (ret == CKR_OK)
        ret = find_mldsa_pub_key(session, &pub, pubId, pubIdLen);
    if (ret == CKR_OK)
        ret = mldsa_test(session, priv, pub);

    if (priv != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, priv);
    if (pub != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, pub);

    return ret;
}

static CK_RV test_mldsa_sig_fail(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret = CKR_OK;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_MECHANISM mech;
    CK_HASH_SIGN_ADDITIONAL_CONTEXT hashCtx;
    byte ctx[] = "mldsa-fail";
    byte dummy = 0;

    ret = gen_mldsa_keys(session, CKP_ML_DSA_44, &pub, &priv, NULL, 0, NULL, 0,
                         0);
    if (ret != CKR_OK)
        return ret;

    mech.mechanism = CKM_ML_DSA;
    mech.pParameter = &dummy;
    mech.ulParameterLen = sizeof(dummy);
    ret = funcList->C_SignInit(session, &mech, priv);
    CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                   "ML-DSA Sign Init bad parameter length");

    if (ret == CKR_OK) {
        XMEMSET(&hashCtx, 0, sizeof(hashCtx));
        hashCtx.hedgeVariant = CKH_HEDGE_PREFERRED;
        hashCtx.pContext = ctx;
        hashCtx.ulContextLen = sizeof(ctx) - 1;
        hashCtx.hash = 0;
        mech.mechanism = CKM_HASH_ML_DSA;
        mech.pParameter = &hashCtx;
        mech.ulParameterLen = sizeof(hashCtx);
        ret = funcList->C_SignInit(session, &mech, priv);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                       "HASH-ML-DSA Sign Init bad hash");
    }

    if (priv != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, priv);
    if (pub != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, pub);

    return ret;
}

static CK_RV test_mldsa_fixed_keys_expanded(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret = CKR_OK;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;

    ret = import_mldsa_priv_key(session, &priv);
    if (ret == CKR_OK)
        ret = import_mldsa_pub_key(session, &pub);
    if (ret == CKR_OK)
        ret = mldsa_test(session, priv, pub);

    if (priv != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, priv);
    if (pub != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, pub);

    return ret;
}

static CK_RV test_mldsa_fixed_keys_seed(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret = CKR_OK;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;

    ret = import_mldsa_priv_key_from_seed(session, &priv);
    if (ret == CKR_OK)
        ret = import_mldsa_pub_key(session, &pub);
    if (ret == CKR_OK)
        ret = mldsa_test(session, priv, pub);

    if (priv != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, priv);
    if (pub != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, pub);

    return ret;
}

static CK_RV test_mldsa_fixed_keys_both(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret = CKR_OK;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;

    ret = import_mldsa_priv_key_and_seed(session, &priv);
    if (ret == CKR_OK)
        ret = import_mldsa_pub_key(session, &pub);
    if (ret == CKR_OK)
        ret = mldsa_test(session, priv, pub);

    if (priv != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, priv);
    if (pub != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, pub);

    return ret;
}

static CK_RV test_copy_object_mldsa_key(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret = CKR_OK;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE copiedPub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE copiedPriv = CK_INVALID_HANDLE;
    static byte modifiedLabel[] = "mldsa-copied-key";
    CK_ATTRIBUTE copyTmpl[] = {
        { CKA_LABEL, modifiedLabel, sizeof(modifiedLabel) - 1 },
    };
    CK_ULONG copyTmplCnt = sizeof(copyTmpl) / sizeof(*copyTmpl);

    /* Generate ML-DSA key pair */
    ret = gen_mldsa_keys(session, CKP_ML_DSA_44, &pub, &priv, NULL, 0, NULL, 0,
                         0);

    /* Copy private key */
    if (ret == CKR_OK) {
        ret = funcList->C_CopyObject(session, priv, copyTmpl, copyTmplCnt,
                                     &copiedPriv);
        CHECK_CKR(ret, "Copy ML-DSA private key");
    }

    /* Copy public key */
    if (ret == CKR_OK) {
        ret = funcList->C_CopyObject(session, pub, copyTmpl, copyTmplCnt,
                                     &copiedPub);
        CHECK_CKR(ret, "Copy ML-DSA public key");
    }

    /* Verify copied keys work: sign with copied private, verify with both
     * original and copied public key */
    if (ret == CKR_OK)
        ret = mldsa_test(session, copiedPriv, pub);
    if (ret == CKR_OK)
        ret = mldsa_test(session, copiedPriv, copiedPub);

    /* Verify copied label */
    if (ret == CKR_OK) {
        byte label[64];
        CK_ATTRIBUTE getTmpl[] = {
            { CKA_LABEL, label, sizeof(label) },
        };
        ret = funcList->C_GetAttributeValue(session, copiedPriv, getTmpl, 1);
        CHECK_CKR(ret, "Get copied ML-DSA private key label");
        if (ret == CKR_OK) {
            CHECK_COND(getTmpl[0].ulValueLen == sizeof(modifiedLabel) - 1 &&
                       XMEMCMP(label, modifiedLabel,
                               sizeof(modifiedLabel) - 1) == 0,
                       ret, "Copied ML-DSA private key label matches");
        }
    }
    if (ret == CKR_OK) {
        byte label[64];
        CK_ATTRIBUTE getTmpl[] = {
            { CKA_LABEL, label, sizeof(label) },
        };
        ret = funcList->C_GetAttributeValue(session, copiedPub, getTmpl, 1);
        CHECK_CKR(ret, "Get copied ML-DSA public key label");
        if (ret == CKR_OK) {
            CHECK_COND(getTmpl[0].ulValueLen == sizeof(modifiedLabel) - 1 &&
                       XMEMCMP(label, modifiedLabel,
                               sizeof(modifiedLabel) - 1) == 0,
                       ret, "Copied ML-DSA public key label matches");
        }
    }

    if (copiedPriv != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, copiedPriv);
    if (copiedPub != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, copiedPub);
    if (priv != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, priv);
    if (pub != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, pub);

    return ret;
}
#endif /* WOLFPKCS11_MLDSA */

#ifdef WOLFPKCS11_MLKEM

static CK_KEY_TYPE mlkemKeyType = CKK_ML_KEM;
static unsigned char mlkem_512_seed[WC_ML_KEM_MAKEKEY_RAND_SZ] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f
};
static unsigned char mlkem_512_seed_alt[WC_ML_KEM_MAKEKEY_RAND_SZ] = {
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
    0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
    0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
    0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf
};

static CK_RV mlkem_keypair_from_seed(CK_ML_KEM_PARAMETER_SET_TYPE paramSet,
                                     unsigned char* seed, CK_ULONG seedLen,
                                     unsigned char** privKeyData,
                                     CK_ULONG* privKeyLen,
                                     unsigned char** pubKeyData,
                                     CK_ULONG* pubKeyLen)
{
    CK_RV rv = CKR_OK;
    int ret = 0;
    int keyInited = 0;
    int level = 0;
    MlKemKey key;
    word32 privLen = 0;
    word32 pubLen = 0;
    unsigned char* privData = NULL;
    unsigned char* pubData = NULL;

    if (seed == NULL || privKeyData == NULL || privKeyLen == NULL ||
        pubKeyData == NULL || pubKeyLen == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    switch (paramSet) {
        case CKP_ML_KEM_512:
            level = WC_ML_KEM_512;
            break;
        case CKP_ML_KEM_768:
            level = WC_ML_KEM_768;
            break;
        case CKP_ML_KEM_1024:
            level = WC_ML_KEM_1024;
            break;
        default:
            return CKR_ARGUMENTS_BAD;
    }

    *privKeyData = NULL;
    *pubKeyData = NULL;
    *privKeyLen = 0;
    *pubKeyLen = 0;

    ret = wc_MlKemKey_Init(&key, level, NULL, INVALID_DEVID);
    if (ret == 0) {
        keyInited = 1;
        ret = wc_MlKemKey_MakeKeyWithRandom(&key, seed, (int)seedLen);
    }
    if (ret == 0)
        ret = wc_MlKemKey_PrivateKeySize(&key, &privLen);
    if (ret == 0)
        ret = wc_MlKemKey_PublicKeySize(&key, &pubLen);
    if (ret == 0) {
        privData = (unsigned char*)malloc(privLen);
        pubData = (unsigned char*)malloc(pubLen);
        if (privData == NULL || pubData == NULL)
            rv = CKR_HOST_MEMORY;
    }
    if (ret == 0 && rv == CKR_OK)
        ret = wc_MlKemKey_EncodePrivateKey(&key, privData, privLen);
    if (ret == 0 && rv == CKR_OK)
        ret = wc_MlKemKey_EncodePublicKey(&key, pubData, pubLen);

    if (ret != 0 && rv == CKR_OK)
        rv = CKR_FUNCTION_FAILED;

    if (keyInited)
        wc_MlKemKey_Free(&key);

    if (rv != CKR_OK) {
        if (privData != NULL)
            free(privData);
        if (pubData != NULL)
            free(pubData);
    }
    else {
        *privKeyData = privData;
        *pubKeyData = pubData;
        *privKeyLen = privLen;
        *pubKeyLen = pubLen;
    }

    return rv;
}

static CK_RV gen_mlkem_keys(CK_SESSION_HANDLE session,
                            CK_ML_KEM_PARAMETER_SET_TYPE paramSet,
                            CK_OBJECT_HANDLE* pubKey, CK_OBJECT_HANDLE* privKey,
                            unsigned char* privId, int privIdLen,
                            unsigned char* pubId, int pubIdLen, int onToken)
{
    CK_RV ret = CKR_OK;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_MECHANISM mech;
    CK_BBOOL token = (CK_BBOOL)onToken;
    CK_ATTRIBUTE pubKeyTmpl[] = {
        { CKA_PARAMETER_SET, &paramSet,  sizeof(paramSet) },
        { CKA_ENCAPSULATE,   &ckTrue,    sizeof(ckTrue)   },
        { CKA_TOKEN,         &token,     sizeof(token)    },
        { CKA_ID,            pubId,      pubIdLen         },
    };
    CK_ULONG pubTmplCnt = sizeof(pubKeyTmpl) / sizeof(*pubKeyTmpl);
    CK_ATTRIBUTE privKeyTmpl[] = {
        { CKA_DECAPSULATE,   &ckTrue,    sizeof(ckTrue)   },
        { CKA_TOKEN,         &token,     sizeof(token)    },
        { CKA_ID,            privId,     privIdLen        },
    };
    CK_ULONG privTmplCnt = sizeof(privKeyTmpl) / sizeof(*privKeyTmpl);

    if (pubId == NULL)
        pubTmplCnt--;
    if (privId == NULL)
        privTmplCnt--;

    mech.mechanism = CKM_ML_KEM_KEY_PAIR_GEN;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;

    ret = funcList->C_GenerateKeyPair(session, &mech, pubKeyTmpl, pubTmplCnt,
                                      privKeyTmpl, privTmplCnt, &pub, &priv);
    CHECK_CKR(ret, "ML-KEM Key Generation");
    if (ret == CKR_OK && pubKey != NULL)
        *pubKey = pub;
    if (ret == CKR_OK && privKey != NULL)
        *privKey = priv;

    return ret;
}

static CK_RV find_mlkem_key(CK_SESSION_HANDLE session, CK_OBJECT_CLASS objClass,
                            CK_OBJECT_HANDLE* key, unsigned char* id, int idLen)
{
    CK_RV ret = CKR_OK;
    CK_ULONG count = 0;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,    &objClass,     sizeof(objClass)     },
        { CKA_KEY_TYPE, &mlkemKeyType, sizeof(mlkemKeyType) },
        { CKA_ID,       id,            idLen                },
    };

    ret = funcList->C_FindObjectsInit(session, tmpl, sizeof(tmpl)/sizeof(*tmpl));
    CHECK_CKR(ret, "ML-KEM Find Objects Init");
    if (ret == CKR_OK) {
        ret = funcList->C_FindObjects(session, key, 1, &count);
        CHECK_CKR(ret, "ML-KEM Find Objects");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_FindObjectsFinal(session);
        CHECK_CKR(ret, "ML-KEM Find Objects Final");
    }
    if (ret == CKR_OK) {
        CHECK_COND(count == 1, ret, "ML-KEM Find Objects count");
    }

    return ret;
}

static CK_RV find_mlkem_priv_key(CK_SESSION_HANDLE session,
                                 CK_OBJECT_HANDLE* key,
                                 unsigned char* id, int idLen)
{
    return find_mlkem_key(session, privKeyClass, key, id, idLen);
}

static CK_RV find_mlkem_pub_key(CK_SESSION_HANDLE session,
                                CK_OBJECT_HANDLE* key,
                                unsigned char* id, int idLen)
{
    return find_mlkem_key(session, pubKeyClass, key, id, idLen);
}

static CK_RV import_mlkem_priv_key(CK_SESSION_HANDLE session,
                                   CK_ML_KEM_PARAMETER_SET_TYPE paramSet,
                                   unsigned char* privKeyData,
                                   CK_ULONG privKeyLen, CK_OBJECT_HANDLE* obj)
{
    CK_RV ret;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,         &privKeyClass, sizeof(privKeyClass) },
        { CKA_KEY_TYPE,      &mlkemKeyType, sizeof(mlkemKeyType) },
        { CKA_DECAPSULATE,   &ckTrue,       sizeof(ckTrue)       },
        { CKA_PARAMETER_SET, &paramSet,     sizeof(paramSet)     },
        { CKA_VALUE,         privKeyData,   privKeyLen           },
    };
    int cnt = sizeof(tmpl)/sizeof(*tmpl);

    ret = funcList->C_CreateObject(session, tmpl, cnt, obj);
    CHECK_CKR(ret, "ML-KEM Priv Key CreateObject");

    return ret;
}

static CK_RV import_mlkem_priv_key_from_seed(CK_SESSION_HANDLE session,
                                             CK_ML_KEM_PARAMETER_SET_TYPE paramSet,
                                             unsigned char* seed,
                                             CK_ULONG seedLen,
                                             CK_OBJECT_HANDLE* obj)
{
    CK_RV ret;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,         &privKeyClass, sizeof(privKeyClass) },
        { CKA_KEY_TYPE,      &mlkemKeyType, sizeof(mlkemKeyType) },
        { CKA_DECAPSULATE,   &ckTrue,       sizeof(ckTrue)       },
        { CKA_PARAMETER_SET, &paramSet,     sizeof(paramSet)     },
        { CKA_SEED,          seed,          seedLen              },
    };
    int cnt = sizeof(tmpl)/sizeof(*tmpl);

    ret = funcList->C_CreateObject(session, tmpl, cnt, obj);
    CHECK_CKR(ret, "ML-KEM Priv Key CreateObject from seed");

    return ret;
}

static CK_RV import_mlkem_priv_key_and_seed(CK_SESSION_HANDLE session,
                                            CK_ML_KEM_PARAMETER_SET_TYPE paramSet,
                                            unsigned char* seed,
                                            CK_ULONG seedLen,
                                            unsigned char* privKeyData,
                                            CK_ULONG privKeyLen,
                                            CK_OBJECT_HANDLE* obj)
{
    CK_RV ret;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,         &privKeyClass, sizeof(privKeyClass) },
        { CKA_KEY_TYPE,      &mlkemKeyType, sizeof(mlkemKeyType) },
        { CKA_DECAPSULATE,   &ckTrue,       sizeof(ckTrue)       },
        { CKA_PARAMETER_SET, &paramSet,     sizeof(paramSet)     },
        { CKA_SEED,          seed,          seedLen              },
        { CKA_VALUE,         privKeyData,   privKeyLen           },
    };
    int cnt = sizeof(tmpl)/sizeof(*tmpl);

    ret = funcList->C_CreateObject(session, tmpl, cnt, obj);
    CHECK_CKR(ret, "ML-KEM Priv Key CreateObject from seed and key");

    return ret;
}

static CK_RV import_mlkem_pub_key(CK_SESSION_HANDLE session,
                                  CK_ML_KEM_PARAMETER_SET_TYPE paramSet,
                                  unsigned char* pubKeyData, CK_ULONG pubKeyLen,
                                  CK_OBJECT_HANDLE* obj)
{
    CK_RV ret;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,         &pubKeyClass,  sizeof(pubKeyClass)  },
        { CKA_KEY_TYPE,      &mlkemKeyType, sizeof(mlkemKeyType) },
        { CKA_ENCAPSULATE,   &ckTrue,       sizeof(ckTrue)       },
        { CKA_PARAMETER_SET, &paramSet,     sizeof(paramSet)     },
        { CKA_VALUE,         pubKeyData,    pubKeyLen            },
    };
    int cnt = sizeof(tmpl)/sizeof(*tmpl);

    ret = funcList->C_CreateObject(session, tmpl, cnt, obj);
    CHECK_CKR(ret, "ML-KEM Pub Key CreateObject");

    return ret;
}

/* Perform encapsulate/decapsulate and verify that shared secrets match. */
static CK_RV mlkem_encap_decap(CK_SESSION_HANDLE session,
                               CK_OBJECT_HANDLE pubKey,
                               CK_OBJECT_HANDLE privKey)
{
    CK_RV ret = CKR_OK;
    CK_FUNCTION_LIST_3_2* funcListExt = (CK_FUNCTION_LIST_3_2*)funcList;
    CK_MECHANISM mech;
    CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
    CK_KEY_TYPE genericKeyType = CKK_GENERIC_SECRET;
    CK_BBOOL extractable = CK_TRUE;
    CK_ATTRIBUTE secretTmpl[] = {
        { CKA_CLASS,       &secretClass,    sizeof(secretClass)    },
        { CKA_KEY_TYPE,    &genericKeyType, sizeof(genericKeyType) },
        { CKA_EXTRACTABLE, &extractable,    sizeof(extractable)    },
    };
    CK_ULONG secretTmplCnt = sizeof(secretTmpl) / sizeof(*secretTmpl);
    CK_OBJECT_HANDLE encapKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE decapKey = CK_INVALID_HANDLE;
    CK_BYTE* ciphertext = NULL;
    CK_ULONG ctLen = 0;
    CK_BYTE ss1[64];
    CK_BYTE ss2[64];
    CK_ULONG ss1Len = sizeof(ss1);
    CK_ULONG ss2Len = sizeof(ss2);
    CK_ATTRIBUTE getValueTmpl[] = { { CKA_VALUE, NULL, 0 } };

    mech.mechanism = CKM_ML_KEM;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;

    /* First call with ctLen=0 to discover ciphertext size. */
    ret = funcListExt->C_EncapsulateKey(session, &mech, pubKey, secretTmpl,
                                        secretTmplCnt, NULL, &ctLen, &encapKey);
    CHECK_CKR(ret, "ML-KEM Encapsulate size query");

    if (ret == CKR_OK) {
        ciphertext = (CK_BYTE*)malloc(ctLen);
        if (ciphertext == NULL)
            ret = CKR_HOST_MEMORY;
    }

    /* Encapsulate: generates ciphertext and encapsulated shared secret. */
    if (ret == CKR_OK) {
        ret = funcListExt->C_EncapsulateKey(session, &mech, pubKey, secretTmpl,
                                            secretTmplCnt, ciphertext, &ctLen,
                                            &encapKey);
        CHECK_CKR(ret, "ML-KEM Encapsulate");
    }

    /* Decapsulate: recover shared secret from ciphertext. */
    if (ret == CKR_OK) {
        ret = funcListExt->C_DecapsulateKey(session, &mech, privKey, secretTmpl,
                                            secretTmplCnt, ciphertext, ctLen,
                                            &decapKey);
        CHECK_CKR(ret, "ML-KEM Decapsulate");
    }

    /* Compare shared secrets — they must be identical. */
    if (ret == CKR_OK) {
        getValueTmpl[0].pValue = ss1;
        getValueTmpl[0].ulValueLen = ss1Len;
        ret = funcList->C_GetAttributeValue(session, encapKey, getValueTmpl, 1);
        CHECK_CKR(ret, "ML-KEM Get encap shared secret");
        if (ret == CKR_OK)
            ss1Len = getValueTmpl[0].ulValueLen;
    }
    if (ret == CKR_OK) {
        getValueTmpl[0].pValue = ss2;
        getValueTmpl[0].ulValueLen = ss2Len;
        ret = funcList->C_GetAttributeValue(session, decapKey, getValueTmpl, 1);
        CHECK_CKR(ret, "ML-KEM Get decap shared secret");
        if (ret == CKR_OK)
            ss2Len = getValueTmpl[0].ulValueLen;
    }
    if (ret == CKR_OK) {
        CHECK_COND(ss1Len == ss2Len && XMEMCMP(ss1, ss2, ss1Len) == 0,
                   ret, "ML-KEM Shared secrets match");
    }

    if (ciphertext != NULL)
        free(ciphertext);
    if (encapKey != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, encapKey);
    if (decapKey != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, decapKey);

    return ret;
}

static CK_RV test_mlkem_gen_keys(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret = CKR_OK;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;

    ret = gen_mlkem_keys(session, CKP_ML_KEM_512, &pub, &priv, NULL, 0,
                         NULL, 0, 0);
    if (ret == CKR_OK)
        ret = mlkem_encap_decap(session, pub, priv);

    if (priv != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, priv);
    if (pub != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, pub);

    return ret;
}

static CK_RV test_mlkem_gen_keys_768(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret = CKR_OK;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;

    ret = gen_mlkem_keys(session, CKP_ML_KEM_768, &pub, &priv, NULL, 0,
                         NULL, 0, 0);
    if (ret == CKR_OK)
        ret = mlkem_encap_decap(session, pub, priv);

    if (priv != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, priv);
    if (pub != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, pub);

    return ret;
}

static CK_RV test_mlkem_gen_keys_1024(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret = CKR_OK;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;

    ret = gen_mlkem_keys(session, CKP_ML_KEM_1024, &pub, &priv, NULL, 0,
                         NULL, 0, 0);
    if (ret == CKR_OK)
        ret = mlkem_encap_decap(session, pub, priv);

    if (priv != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, priv);
    if (pub != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, pub);

    return ret;
}

static CK_RV test_mlkem_gen_keys_id(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret = CKR_OK;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    unsigned char* privId = (unsigned char*)"mlkem-priv-id";
    int privIdLen = (int)XSTRLEN((const char*)privId);

    ret = gen_mlkem_keys(session, CKP_ML_KEM_512, &pub, NULL, privId, privIdLen,
                         NULL, 0, 0);
    if (ret == CKR_OK)
        ret = find_mlkem_priv_key(session, &priv, privId, privIdLen);
    if (ret == CKR_OK)
        ret = mlkem_encap_decap(session, pub, priv);

    if (priv != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, priv);
    if (pub != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, pub);

    return ret;
}

static CK_RV test_mlkem_gen_keys_token(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    unsigned char* privId = (unsigned char*)"mlkem-priv-token";
    unsigned char* pubId  = (unsigned char*)"mlkem-pub-token";
    int privIdLen = (int)XSTRLEN((const char*)privId);
    int pubIdLen  = (int)XSTRLEN((const char*)pubId);

    return gen_mlkem_keys(session, CKP_ML_KEM_512, NULL, NULL, privId, privIdLen,
                          pubId, pubIdLen, 1);
}

static CK_RV test_mlkem_token_keys(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret = CKR_OK;
    CK_OBJECT_HANDLE pub  = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    unsigned char* privId = (unsigned char*)"mlkem-priv-token";
    unsigned char* pubId  = (unsigned char*)"mlkem-pub-token";
    int privIdLen = (int)XSTRLEN((const char*)privId);
    int pubIdLen  = (int)XSTRLEN((const char*)pubId);

    ret = find_mlkem_priv_key(session, &priv, privId, privIdLen);
    if (ret == CKR_OK)
        ret = find_mlkem_pub_key(session, &pub, pubId, pubIdLen);
    if (ret == CKR_OK)
        ret = mlkem_encap_decap(session, pub, priv);

    if (priv != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, priv);
    if (pub != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, pub);

    return ret;
}

/* Generate a key pair, export the raw key material, destroy, re-import, and
 * verify that encapsulate/decapsulate still works — exercises the import path. */
static CK_RV test_mlkem_fixed_keys(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret = CKR_OK;
    CK_OBJECT_HANDLE pub   = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv  = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub2  = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv2 = CK_INVALID_HANDLE;
    CK_BYTE* privKeyData = NULL;
    CK_BYTE* pubKeyData  = NULL;
    CK_ULONG privKeyLen  = 0;
    CK_ULONG pubKeyLen   = 0;
    CK_ATTRIBUTE getPriv[] = { { CKA_VALUE, NULL, 0 } };
    CK_ATTRIBUTE getPub[]  = { { CKA_VALUE, NULL, 0 } };

    ret = gen_mlkem_keys(session, CKP_ML_KEM_512, &pub, &priv, NULL, 0,
                         NULL, 0, 0);

    /* Query sizes. */
    if (ret == CKR_OK) {
        ret = funcList->C_GetAttributeValue(session, priv, getPriv, 1);
        CHECK_CKR(ret, "ML-KEM get priv key size");
        if (ret == CKR_OK)
            privKeyLen = getPriv[0].ulValueLen;
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetAttributeValue(session, pub, getPub, 1);
        CHECK_CKR(ret, "ML-KEM get pub key size");
        if (ret == CKR_OK)
            pubKeyLen = getPub[0].ulValueLen;
    }

    /* Allocate and fetch key data. */
    if (ret == CKR_OK) {
        privKeyData = (CK_BYTE*)malloc(privKeyLen);
        pubKeyData  = (CK_BYTE*)malloc(pubKeyLen);
        if (privKeyData == NULL || pubKeyData == NULL)
            ret = CKR_HOST_MEMORY;
    }
    if (ret == CKR_OK) {
        getPriv[0].pValue = privKeyData;
        ret = funcList->C_GetAttributeValue(session, priv, getPriv, 1);
        CHECK_CKR(ret, "ML-KEM get priv key data");
    }
    if (ret == CKR_OK) {
        getPub[0].pValue = pubKeyData;
        ret = funcList->C_GetAttributeValue(session, pub, getPub, 1);
        CHECK_CKR(ret, "ML-KEM get pub key data");
    }

    /* Destroy originals so the import is the only active copy. */
    if (priv != CK_INVALID_HANDLE) {
        funcList->C_DestroyObject(session, priv);
        priv = CK_INVALID_HANDLE;
    }
    if (pub != CK_INVALID_HANDLE) {
        funcList->C_DestroyObject(session, pub);
        pub = CK_INVALID_HANDLE;
    }

    /* Re-import and verify. */
    if (ret == CKR_OK)
        ret = import_mlkem_priv_key(session, CKP_ML_KEM_512, privKeyData,
                                    privKeyLen, &priv2);
    if (ret == CKR_OK)
        ret = import_mlkem_pub_key(session, CKP_ML_KEM_512, pubKeyData,
                                   pubKeyLen, &pub2);
    if (ret == CKR_OK)
        ret = mlkem_encap_decap(session, pub2, priv2);

    if (priv2 != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, priv2);
    if (pub2 != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, pub2);
    if (privKeyData != NULL)
        free(privKeyData);
    if (pubKeyData != NULL)
        free(pubKeyData);

    return ret;
}

static CK_RV test_mlkem_fixed_keys_seed(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret = CKR_OK;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_BYTE* privKeyData = NULL;
    CK_BYTE* pubKeyData = NULL;
    CK_ULONG privKeyLen = 0;
    CK_ULONG pubKeyLen = 0;
    CK_ML_KEM_PARAMETER_SET_TYPE paramSet = CKP_ML_KEM_512;

    ret = mlkem_keypair_from_seed(paramSet, mlkem_512_seed, sizeof(mlkem_512_seed),
                                  &privKeyData, &privKeyLen, &pubKeyData,
                                  &pubKeyLen);
    CHECK_CKR(ret, "ML-KEM keypair from seed");
    if (ret == CKR_OK)
        ret = import_mlkem_priv_key_from_seed(session, paramSet, mlkem_512_seed,
                                              sizeof(mlkem_512_seed), &priv);
    if (ret == CKR_OK)
        ret = import_mlkem_pub_key(session, paramSet, pubKeyData, pubKeyLen,
                                   &pub);
    if (ret == CKR_OK)
        ret = mlkem_encap_decap(session, pub, priv);

    if (priv != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, priv);
    if (pub != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, pub);
    if (privKeyData != NULL)
        free(privKeyData);
    if (pubKeyData != NULL)
        free(pubKeyData);

    return ret;
}

static CK_RV test_mlkem_fixed_keys_seed_both(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret = CKR_OK;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_BYTE* privKeyData = NULL;
    CK_BYTE* pubKeyData = NULL;
    CK_ULONG privKeyLen = 0;
    CK_ULONG pubKeyLen = 0;
    CK_ML_KEM_PARAMETER_SET_TYPE paramSet = CKP_ML_KEM_512;

    ret = mlkem_keypair_from_seed(paramSet, mlkem_512_seed, sizeof(mlkem_512_seed),
                                  &privKeyData, &privKeyLen, &pubKeyData,
                                  &pubKeyLen);
    CHECK_CKR(ret, "ML-KEM keypair from seed");
    if (ret == CKR_OK) {
        ret = import_mlkem_priv_key_and_seed(session, paramSet, mlkem_512_seed,
                                             sizeof(mlkem_512_seed), privKeyData,
                                             privKeyLen, &priv);
    }
    if (ret == CKR_OK)
        ret = import_mlkem_pub_key(session, paramSet, pubKeyData, pubKeyLen,
                                   &pub);
    if (ret == CKR_OK)
        ret = mlkem_encap_decap(session, pub, priv);

    if (priv != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, priv);
    if (pub != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, pub);
    if (privKeyData != NULL)
        free(privKeyData);
    if (pubKeyData != NULL)
        free(pubKeyData);

    return ret;
}

static CK_RV test_mlkem_seed_invalid(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret = CKR_OK;
    CK_ML_KEM_PARAMETER_SET_TYPE paramSet = CKP_ML_KEM_512;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_BYTE* privKeyDataAlt = NULL;
    CK_BYTE* pubKeyDataAlt = NULL;
    CK_ULONG privKeyLenAlt = 0;
    CK_ULONG pubKeyLenAlt = 0;

    /* CKA_SEED is private-key only. */
    if (ret == CKR_OK) {
        CK_ATTRIBUTE tmpl[] = {
            { CKA_CLASS,         &pubKeyClass,  sizeof(pubKeyClass)  },
            { CKA_KEY_TYPE,      &mlkemKeyType, sizeof(mlkemKeyType) },
            { CKA_ENCAPSULATE,   &ckTrue,       sizeof(ckTrue)       },
            { CKA_PARAMETER_SET, &paramSet,     sizeof(paramSet)     },
            { CKA_SEED,          mlkem_512_seed, sizeof(mlkem_512_seed) },
        };
        int cnt = sizeof(tmpl)/sizeof(*tmpl);
        ret = funcList->C_CreateObject(session, tmpl, cnt, &obj);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_FAILED,
                       "ML-KEM Pub Key CreateObject from seed must fail");
        obj = CK_INVALID_HANDLE;
    }

    /* Invalid seed length must fail. */
    if (ret == CKR_OK) {
        CK_ATTRIBUTE tmpl[] = {
            { CKA_CLASS,         &privKeyClass, sizeof(privKeyClass) },
            { CKA_KEY_TYPE,      &mlkemKeyType, sizeof(mlkemKeyType) },
            { CKA_DECAPSULATE,   &ckTrue,       sizeof(ckTrue)       },
            { CKA_PARAMETER_SET, &paramSet,     sizeof(paramSet)     },
            { CKA_SEED,          mlkem_512_seed, sizeof(mlkem_512_seed) - 1 },
        };
        int cnt = sizeof(tmpl)/sizeof(*tmpl);
        ret = funcList->C_CreateObject(session, tmpl, cnt, &obj);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_FAILED,
                       "ML-KEM Priv Key CreateObject bad seed length");
        obj = CK_INVALID_HANDLE;
    }

    /* Mismatched seed and expanded key must fail. */
    if (ret == CKR_OK) {
        ret = mlkem_keypair_from_seed(paramSet, mlkem_512_seed_alt,
                                      sizeof(mlkem_512_seed_alt),
                                      &privKeyDataAlt, &privKeyLenAlt,
                                      &pubKeyDataAlt, &pubKeyLenAlt);
        CHECK_CKR(ret, "ML-KEM keypair from alternate seed");
    }
    if (ret == CKR_OK) {
        CK_ATTRIBUTE tmpl[] = {
            { CKA_CLASS,         &privKeyClass, sizeof(privKeyClass)  },
            { CKA_KEY_TYPE,      &mlkemKeyType, sizeof(mlkemKeyType)  },
            { CKA_DECAPSULATE,   &ckTrue,       sizeof(ckTrue)        },
            { CKA_PARAMETER_SET, &paramSet,     sizeof(paramSet)      },
            { CKA_SEED,          mlkem_512_seed, sizeof(mlkem_512_seed) },
            { CKA_VALUE,         privKeyDataAlt, privKeyLenAlt        },
        };
        int cnt = sizeof(tmpl)/sizeof(*tmpl);
        ret = funcList->C_CreateObject(session, tmpl, cnt, &obj);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_FAILED,
                       "ML-KEM Priv Key CreateObject mismatch seed and key");
    }

    if (obj != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, obj);
    if (privKeyDataAlt != NULL)
        free(privKeyDataAlt);
    if (pubKeyDataAlt != NULL)
        free(pubKeyDataAlt);

    return ret;
}

/* Verify that decapsulating ciphertext with the wrong private key produces a
 * different shared secret (ML-KEM uses implicit rejection, so the call
 * succeeds but yields a pseudo-random value). */
static CK_RV test_mlkem_encap_decap_fail(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret = CKR_OK;
    CK_FUNCTION_LIST_3_2* funcListExt = (CK_FUNCTION_LIST_3_2*)funcList;
    CK_OBJECT_HANDLE pubA  = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE privA = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pubB  = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE privB = CK_INVALID_HANDLE;
    CK_MECHANISM mech;
    CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
    CK_KEY_TYPE genericKeyType = CKK_GENERIC_SECRET;
    CK_BBOOL extractable = CK_TRUE;
    CK_ATTRIBUTE secretTmpl[] = {
        { CKA_CLASS,       &secretClass,    sizeof(secretClass)    },
        { CKA_KEY_TYPE,    &genericKeyType, sizeof(genericKeyType) },
        { CKA_EXTRACTABLE, &extractable,    sizeof(extractable)    },
    };
    CK_ULONG secretTmplCnt = sizeof(secretTmpl) / sizeof(*secretTmpl);
    CK_OBJECT_HANDLE encapKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE decapKey = CK_INVALID_HANDLE;
    CK_BYTE* ciphertext = NULL;
    CK_ULONG ctLen = 0;
    CK_BYTE ss1[64];
    CK_BYTE ss2[64];
    CK_ULONG ss1Len = sizeof(ss1);
    CK_ULONG ss2Len = sizeof(ss2);
    CK_ATTRIBUTE getValueTmpl[] = { { CKA_VALUE, NULL, 0 } };

    /* Generate two independent key pairs. */
    ret = gen_mlkem_keys(session, CKP_ML_KEM_512, &pubA, &privA, NULL, 0,
                         NULL, 0, 0);
    if (ret == CKR_OK)
        ret = gen_mlkem_keys(session, CKP_ML_KEM_512, &pubB, &privB, NULL, 0,
                             NULL, 0, 0);

    mech.mechanism = CKM_ML_KEM;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;

    /* Discover ciphertext size. */
    if (ret == CKR_OK) {
        ret = funcListExt->C_EncapsulateKey(session, &mech, pubA, secretTmpl,
                                            secretTmplCnt, NULL, &ctLen,
                                            &encapKey);
        CHECK_CKR(ret, "ML-KEM Encapsulate size query");
    }
    if (ret == CKR_OK) {
        ciphertext = (CK_BYTE*)malloc(ctLen);
        if (ciphertext == NULL)
            ret = CKR_HOST_MEMORY;
    }

    /* Encapsulate with pubA. */
    if (ret == CKR_OK) {
        ret = funcListExt->C_EncapsulateKey(session, &mech, pubA, secretTmpl,
                                            secretTmplCnt, ciphertext, &ctLen,
                                            &encapKey);
        CHECK_CKR(ret, "ML-KEM Encapsulate (fail test)");
    }

    /* Decapsulate with wrong key (privB instead of privA). ML-KEM implicit
     * rejection means this succeeds but yields a different shared secret. */
    if (ret == CKR_OK) {
        ret = funcListExt->C_DecapsulateKey(session, &mech, privB, secretTmpl,
                                            secretTmplCnt, ciphertext, ctLen,
                                            &decapKey);
        CHECK_CKR(ret, "ML-KEM Decapsulate wrong key");
    }

    /* Retrieve both shared secrets. */
    if (ret == CKR_OK) {
        getValueTmpl[0].pValue = ss1;
        getValueTmpl[0].ulValueLen = ss1Len;
        ret = funcList->C_GetAttributeValue(session, encapKey, getValueTmpl, 1);
        CHECK_CKR(ret, "ML-KEM Get encap shared secret (fail test)");
        if (ret == CKR_OK)
            ss1Len = getValueTmpl[0].ulValueLen;
    }
    if (ret == CKR_OK) {
        getValueTmpl[0].pValue = ss2;
        getValueTmpl[0].ulValueLen = ss2Len;
        ret = funcList->C_GetAttributeValue(session, decapKey, getValueTmpl, 1);
        CHECK_CKR(ret, "ML-KEM Get decap shared secret (fail test)");
        if (ret == CKR_OK)
            ss2Len = getValueTmpl[0].ulValueLen;
    }
    /* Shared secrets must differ when wrong key was used. */
    if (ret == CKR_OK) {
        CHECK_COND(ss1Len == ss2Len && XMEMCMP(ss1, ss2, ss1Len) != 0,
                   ret, "ML-KEM Shared secrets must differ for wrong key");
    }

    if (ciphertext != NULL)
        free(ciphertext);
    if (encapKey != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, encapKey);
    if (decapKey != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, decapKey);
    if (privA != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, privA);
    if (pubA != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, pubA);
    if (privB != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, privB);
    if (pubB != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, pubB);

    return ret;
}

static CK_RV test_mlkem_bad_mech_params(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret = CKR_OK;
    CK_FUNCTION_LIST_3_2* funcListExt = (CK_FUNCTION_LIST_3_2*)funcList;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE secret = CK_INVALID_HANDLE;
    CK_MECHANISM mech;
    CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
    CK_KEY_TYPE genericKeyType = CKK_GENERIC_SECRET;
    CK_BBOOL extractable = CK_TRUE;
    CK_ATTRIBUTE secretTmpl[] = {
        { CKA_CLASS,       &secretClass,    sizeof(secretClass)    },
        { CKA_KEY_TYPE,    &genericKeyType, sizeof(genericKeyType) },
        { CKA_EXTRACTABLE, &extractable,    sizeof(extractable)    },
    };
    CK_ULONG secretTmplCnt = sizeof(secretTmpl) / sizeof(*secretTmpl);
    CK_ULONG ctLen = 0;
    CK_BYTE dummyCt[1] = { 0 };
    CK_BYTE badParam = 0;

    ret = gen_mlkem_keys(session, CKP_ML_KEM_512, &pub, &priv, NULL, 0,
                         NULL, 0, 0);

    mech.mechanism = CKM_ML_KEM;
    mech.pParameter = &badParam;
    mech.ulParameterLen = sizeof(badParam);

    if (ret == CKR_OK) {
        ret = funcListExt->C_EncapsulateKey(session, &mech, pub, secretTmpl,
                                            secretTmplCnt, NULL, &ctLen,
                                            &secret);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                       "ML-KEM Encapsulate bad mechanism parameter");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_DecapsulateKey(session, &mech, priv, secretTmpl,
                                            secretTmplCnt, dummyCt,
                                            sizeof(dummyCt), &secret);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                       "ML-KEM Decapsulate bad mechanism parameter");
    }

    mech.pParameter = NULL;
    mech.ulParameterLen = 1;

    if (ret == CKR_OK) {
        ret = funcListExt->C_EncapsulateKey(session, &mech, pub, secretTmpl,
                                            secretTmplCnt, NULL, &ctLen,
                                            &secret);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                       "ML-KEM Encapsulate bad mechanism parameter length");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_DecapsulateKey(session, &mech, priv, secretTmpl,
                                            secretTmplCnt, dummyCt,
                                            sizeof(dummyCt), &secret);
        CHECK_CKR_FAIL(ret, CKR_MECHANISM_PARAM_INVALID,
                       "ML-KEM Decapsulate bad mechanism parameter length");
    }

    if (priv != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, priv);
    if (pub != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, pub);
    if (secret != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, secret);

    return ret;
}

static CK_RV test_mlkem_key_validation(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret = CKR_OK;
    CK_FUNCTION_LIST_3_2* funcListExt = (CK_FUNCTION_LIST_3_2*)funcList;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE secret = CK_INVALID_HANDLE;
    CK_MECHANISM mech;
    CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
    CK_KEY_TYPE genericKeyType = CKK_GENERIC_SECRET;
    CK_BBOOL extractable = CK_TRUE;
    CK_ATTRIBUTE secretTmpl[] = {
        { CKA_CLASS,       &secretClass,    sizeof(secretClass)    },
        { CKA_KEY_TYPE,    &genericKeyType, sizeof(genericKeyType) },
        { CKA_EXTRACTABLE, &extractable,    sizeof(extractable)    },
    };
    CK_ULONG secretTmplCnt = sizeof(secretTmpl) / sizeof(*secretTmpl);
    CK_ULONG ctLen = 0;
    CK_BYTE dummyCt[1] = { 0 };
#ifdef WOLFPKCS11_MLDSA
    CK_OBJECT_HANDLE mldsaPub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE mldsaPriv = CK_INVALID_HANDLE;
#endif

    ret = gen_mlkem_keys(session, CKP_ML_KEM_512, &pub, &priv, NULL, 0,
                         NULL, 0, 0);

    mech.mechanism = CKM_ML_KEM;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;

    if (ret == CKR_OK) {
        ret = funcListExt->C_EncapsulateKey(session, &mech, priv, secretTmpl,
                                            secretTmplCnt, NULL, &ctLen,
                                            &secret);
        CHECK_CKR_FAIL(ret, CKR_KEY_HANDLE_INVALID,
                       "ML-KEM Encapsulate wrong key class");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_DecapsulateKey(session, &mech, pub, secretTmpl,
                                            secretTmplCnt, dummyCt,
                                            sizeof(dummyCt), &secret);
        CHECK_CKR_FAIL(ret, CKR_KEY_HANDLE_INVALID,
                       "ML-KEM Decapsulate wrong key class");
    }

#ifdef WOLFPKCS11_MLDSA
    if (ret == CKR_OK) {
        ret = gen_mldsa_keys(session, CKP_ML_DSA_44, &mldsaPub, &mldsaPriv,
                             NULL, 0, NULL, 0, 0);
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_EncapsulateKey(session, &mech, mldsaPub,
                                            secretTmpl, secretTmplCnt, NULL,
                                            &ctLen, &secret);
        CHECK_CKR_FAIL(ret, CKR_KEY_TYPE_INCONSISTENT,
                       "ML-KEM Encapsulate wrong key type");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_DecapsulateKey(session, &mech, mldsaPriv,
                                            secretTmpl, secretTmplCnt, dummyCt,
                                            sizeof(dummyCt), &secret);
        CHECK_CKR_FAIL(ret, CKR_KEY_TYPE_INCONSISTENT,
                       "ML-KEM Decapsulate wrong key type");
    }
#endif

    if (priv != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, priv);
    if (pub != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, pub);
    if (secret != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, secret);
#ifdef WOLFPKCS11_MLDSA
    if (mldsaPriv != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, mldsaPriv);
    if (mldsaPub != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, mldsaPub);
#endif

    return ret;
}

static CK_RV test_mlkem_initial_states(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret = CKR_OK;
    CK_FUNCTION_LIST_3_2* funcListExt = (CK_FUNCTION_LIST_3_2*)funcList;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE encapKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE decapKey = CK_INVALID_HANDLE;
    CK_MECHANISM mech;
    CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
    CK_KEY_TYPE genericKeyType = CKK_GENERIC_SECRET;
    CK_BBOOL sensitive = CK_TRUE;
    CK_BBOOL extractable = CK_FALSE;
    CK_ATTRIBUTE secretTmpl[] = {
        { CKA_CLASS,       &secretClass,    sizeof(secretClass)    },
        { CKA_KEY_TYPE,    &genericKeyType, sizeof(genericKeyType) },
        { CKA_SENSITIVE,   &sensitive,      sizeof(sensitive)      },
        { CKA_EXTRACTABLE, &extractable,    sizeof(extractable)    },
    };
    CK_ULONG secretTmplCnt = sizeof(secretTmpl) / sizeof(*secretTmpl);
    CK_BYTE* ciphertext = NULL;
    CK_ULONG ctLen = 0;
    CK_BBOOL encapSensitive = CK_FALSE;
    CK_BBOOL encapExtractable = CK_TRUE;
    CK_BBOOL encapAlwaysSensitive = CK_FALSE;
    CK_BBOOL encapNeverExtractable = CK_FALSE;
    CK_BBOOL decapSensitive = CK_FALSE;
    CK_BBOOL decapExtractable = CK_TRUE;
    CK_BBOOL decapAlwaysSensitive = CK_FALSE;
    CK_BBOOL decapNeverExtractable = CK_FALSE;
    CK_ATTRIBUTE encapAttr[] = {
        { CKA_SENSITIVE,         &encapSensitive,         sizeof(encapSensitive) },
        { CKA_EXTRACTABLE,       &encapExtractable,       sizeof(encapExtractable) },
        { CKA_ALWAYS_SENSITIVE,  &encapAlwaysSensitive,   sizeof(encapAlwaysSensitive) },
        { CKA_NEVER_EXTRACTABLE, &encapNeverExtractable,  sizeof(encapNeverExtractable) },
    };
    CK_ATTRIBUTE decapAttr[] = {
        { CKA_SENSITIVE,         &decapSensitive,         sizeof(decapSensitive) },
        { CKA_EXTRACTABLE,       &decapExtractable,       sizeof(decapExtractable) },
        { CKA_ALWAYS_SENSITIVE,  &decapAlwaysSensitive,   sizeof(decapAlwaysSensitive) },
        { CKA_NEVER_EXTRACTABLE, &decapNeverExtractable,  sizeof(decapNeverExtractable) },
    };

    ret = gen_mlkem_keys(session, CKP_ML_KEM_512, &pub, &priv, NULL, 0,
                         NULL, 0, 0);

    mech.mechanism = CKM_ML_KEM;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;

    if (ret == CKR_OK) {
        ret = funcListExt->C_EncapsulateKey(session, &mech, pub, secretTmpl,
                                            secretTmplCnt, NULL, &ctLen,
                                            &encapKey);
        CHECK_CKR(ret, "ML-KEM Encapsulate size query (states)");
    }
    if (ret == CKR_OK) {
        ciphertext = (CK_BYTE*)malloc(ctLen);
        if (ciphertext == NULL)
            ret = CKR_HOST_MEMORY;
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_EncapsulateKey(session, &mech, pub, secretTmpl,
                                            secretTmplCnt, ciphertext, &ctLen,
                                            &encapKey);
        CHECK_CKR(ret, "ML-KEM Encapsulate (states)");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_DecapsulateKey(session, &mech, priv, secretTmpl,
                                            secretTmplCnt, ciphertext, ctLen,
                                            &decapKey);
        CHECK_CKR(ret, "ML-KEM Decapsulate (states)");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetAttributeValue(session, encapKey, encapAttr,
                                            sizeof(encapAttr) / sizeof(*encapAttr));
        CHECK_CKR(ret, "ML-KEM Get initial states (encap)");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetAttributeValue(session, decapKey, decapAttr,
                                            sizeof(decapAttr) / sizeof(*decapAttr));
        CHECK_CKR(ret, "ML-KEM Get initial states (decap)");
    }
    if (ret == CKR_OK) {
        CHECK_COND(encapSensitive == CK_TRUE &&
                   encapExtractable == CK_FALSE &&
                   encapAlwaysSensitive == CK_TRUE &&
                   encapNeverExtractable == CK_TRUE, ret,
                   "ML-KEM Encap key initial states");
    }
    if (ret == CKR_OK) {
        CHECK_COND(decapSensitive == CK_TRUE &&
                   decapExtractable == CK_FALSE &&
                   decapAlwaysSensitive == CK_TRUE &&
                   decapNeverExtractable == CK_TRUE, ret,
                   "ML-KEM Decap key initial states");
    }

    if (ciphertext != NULL)
        free(ciphertext);
    if (decapKey != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, decapKey);
    if (encapKey != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, encapKey);
    if (priv != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, priv);
    if (pub != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, pub);

    return ret;
}

static CK_RV test_copy_object_mlkem_key(void* args)
{
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
    CK_RV ret = CKR_OK;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE copiedPub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE copiedPriv = CK_INVALID_HANDLE;
    static byte modifiedLabel[] = "mlkem-copied-key";
    CK_ATTRIBUTE copyTmpl[] = {
        { CKA_LABEL, modifiedLabel, sizeof(modifiedLabel) - 1 },
    };
    CK_ULONG copyTmplCnt = sizeof(copyTmpl) / sizeof(*copyTmpl);

    /* Generate ML-KEM key pair */
    ret = gen_mlkem_keys(session, CKP_ML_KEM_512, &pub, &priv, NULL, 0,
                         NULL, 0, 0);

    /* Copy private key */
    if (ret == CKR_OK) {
        ret = funcList->C_CopyObject(session, priv, copyTmpl, copyTmplCnt,
                                     &copiedPriv);
        CHECK_CKR(ret, "Copy ML-KEM private key");
    }

    /* Copy public key */
    if (ret == CKR_OK) {
        ret = funcList->C_CopyObject(session, pub, copyTmpl, copyTmplCnt,
                                     &copiedPub);
        CHECK_CKR(ret, "Copy ML-KEM public key");
    }

    /* Verify copied keys work: encap with copied public, decap with both
     * original and copied private key */
    if (ret == CKR_OK)
        ret = mlkem_encap_decap(session, copiedPub, priv);
    if (ret == CKR_OK)
        ret = mlkem_encap_decap(session, copiedPub, copiedPriv);

    /* Verify copied label */
    if (ret == CKR_OK) {
        byte label[64];
        CK_ATTRIBUTE getTmpl[] = {
            { CKA_LABEL, label, sizeof(label) },
        };
        ret = funcList->C_GetAttributeValue(session, copiedPriv, getTmpl, 1);
        CHECK_CKR(ret, "Get copied ML-KEM private key label");
        if (ret == CKR_OK) {
            CHECK_COND(getTmpl[0].ulValueLen == sizeof(modifiedLabel) - 1 &&
                       XMEMCMP(label, modifiedLabel,
                               sizeof(modifiedLabel) - 1) == 0,
                       ret, "Copied ML-KEM private key label matches");
        }
    }
    if (ret == CKR_OK) {
        byte label[64];
        CK_ATTRIBUTE getTmpl[] = {
            { CKA_LABEL, label, sizeof(label) },
        };
        ret = funcList->C_GetAttributeValue(session, copiedPub, getTmpl, 1);
        CHECK_CKR(ret, "Get copied ML-KEM public key label");
        if (ret == CKR_OK) {
            CHECK_COND(getTmpl[0].ulValueLen == sizeof(modifiedLabel) - 1 &&
                       XMEMCMP(label, modifiedLabel,
                               sizeof(modifiedLabel) - 1) == 0,
                       ret, "Copied ML-KEM public key label matches");
        }
    }

    if (copiedPriv != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, copiedPriv);
    if (copiedPub != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, copiedPub);
    if (priv != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, priv);
    if (pub != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, pub);

    return ret;
}
#endif /* WOLFPKCS11_MLKEM */
#endif /* WOLFPKCS11_PKCS11_V3_2 */

static CK_RV test_get_interface_list(void* args)
{
    CK_RV ret = CKR_OK;
    CK_ULONG count = 0;
    CK_INTERFACE* interfaces = NULL;
#ifndef HAVE_PKCS11_STATIC
    void* func;
#endif

#ifdef WOLFPKCS11_PKCS11_V3_2
    static const CK_ULONG interfaceCount = 3;
#else
    static const CK_ULONG interfaceCount = 2;
#endif

    (void)args;

#ifndef HAVE_PKCS11_STATIC
    func = (void*)(CK_C_GetInterfaceList)dlsym(dlib, "C_GetInterfaceList");
    if (func == NULL) {
        fprintf(stderr, "Failed to get interface list function\n");
        ret = -1;
    }

    if (ret == CKR_OK) {
        ret = ((CK_C_GetInterfaceList)func)(NULL, NULL);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Get Interface List");
    }
    if (ret == CKR_OK) {
        ret = ((CK_C_GetInterfaceList)func)(NULL, &count);
        CHECK_CKR(ret, "Get Interface List");
        if (count != interfaceCount) {
            fprintf(stderr, "Expected %ld interfaces, got %ld\n",
                    interfaceCount, count);
            ret = -1;
        }
    }
#else
    if (ret == CKR_OK) {
        ret = C_GetInterfaceList(NULL, NULL);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Get Interface List");
    }
    if (ret == CKR_OK) {
        ret = C_GetInterfaceList(NULL, &count);
        CHECK_CKR(ret, "Get Interface List");
        if (count != interfaceCount) {
            fprintf(stderr, "Expected %ld interfaces, got %ld\n",
                    interfaceCount, count);
            ret = -1;
        }
    }
#endif

    if (ret == CKR_OK) {
        interfaces = (CK_INTERFACE*)malloc(interfaceCount *
                                                          sizeof(CK_INTERFACE));
        if (interfaces == NULL) {
            fprintf(stderr, "Failed to allocate memory for interfaces\n");
            ret = -1;
        }
    }

#ifndef HAVE_PKCS11_STATIC
    if (ret == CKR_OK) {
        count = 1;
        ret = ((CK_C_GetInterfaceList)func)(interfaces, &count);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL, "Get Interface List");
    }
    if (ret == CKR_OK) {
        count = interfaceCount;
        ret = ((CK_C_GetInterfaceList)func)(interfaces, &count);
        CHECK_CKR(ret, "Get Interface List");
    }
#else
    if (ret == CKR_OK) {
        count = 1;
        ret = C_GetInterfaceList(interfaces, &count);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL, "Get Interface List");
    }
    if (ret == CKR_OK) {
        count = interfaceCount;
        ret = C_GetInterfaceList(interfaces, &count);
        CHECK_CKR(ret, "Get Interface List");
    }
#endif

    if (interfaces != NULL) {
        free(interfaces);
    }
    return ret;
}

static CK_RV test_get_interface(void* args)
{
    CK_RV ret = CKR_OK;
    CK_INTERFACE* interface = NULL;
    CK_VERSION version;
    CK_FLAGS flags = 0;
    CK_UTF8CHAR_PTR interfaceName = NULL;
#ifndef HAVE_PKCS11_STATIC
    void* func;
#endif

    (void)args;

#ifndef HAVE_PKCS11_STATIC
    func = (void*)(CK_C_GetInterface)dlsym(dlib, "C_GetInterface");
    if (func == NULL) {
        fprintf(stderr, "Failed to get interface function\n");
        ret = -1;
    }
    if (ret == CKR_OK) {
        ret = ((CK_C_GetInterface)func)(interfaceName, NULL, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Get Interface");
    }
    if (ret == CKR_OK) {
        ret = ((CK_C_GetInterface)func)(interfaceName, NULL, &interface, 0);
        CHECK_CKR(ret, "Get Interface");
    }
    if (ret == CKR_OK) {
        interfaceName = (CK_UTF8CHAR_PTR)"FAIL";
        ret = ((CK_C_GetInterface)func)(interfaceName, NULL, &interface, flags);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Get Interface");
    }
    if (ret == CKR_OK) {
        interfaceName = (CK_UTF8CHAR_PTR)"PKCS 11";
        ret = ((CK_C_GetInterface)func)(interfaceName, NULL, &interface, flags);
        CHECK_CKR(ret, "Get Interface");
    }
    if (ret == CKR_OK) {
        version.major = 2;
        version.minor = 40;
        ret = ((CK_C_GetInterface)func)(interfaceName, &version, &interface,
                                        flags);
        CHECK_CKR(ret, "Get Interface");
    }
    if (ret == CKR_OK) {
        version.major = 2;
        version.minor = 20;
        ret = ((CK_C_GetInterface)func)(interfaceName, &version, &interface,
                                        flags);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Get Interface");
    }
    if (ret == CKR_OK) {
        version.major = 3;
        version.minor = 0;
        ret = ((CK_C_GetInterface)func)(interfaceName, &version, &interface,
                                        flags);
        CHECK_CKR(ret, "Get Interface");
    }
#ifdef WOLFPKCS11_PKCS11_V3_2
    if (ret == CKR_OK) {
        version.major = 3;
        version.minor = 2;
        ret = ((CK_C_GetInterface)func)(interfaceName, &version, &interface,
                                        flags);
        CHECK_CKR(ret, "Get Interface");
    }
#endif /* WOLFPKCS11_PKCS11_V3_2 */
#else
    if (ret == CKR_OK) {
        ret = C_GetInterface(interfaceName, NULL, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Get Interface");
    }
    if (ret == CKR_OK) {
        ret = C_GetInterface(interfaceName, NULL, &interface, 0);
        CHECK_CKR(ret, "Get Interface");
    }
    if (ret == CKR_OK) {
        interfaceName = (CK_UTF8CHAR_PTR)"FAIL";
        ret = C_GetInterface(interfaceName, NULL, &interface, flags);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Get Interface");
    }
    if (ret == CKR_OK) {
        interfaceName = (CK_UTF8CHAR_PTR)"PKCS 11";
        ret = C_GetInterface(interfaceName, NULL, &interface, flags);
        CHECK_CKR(ret, "Get Interface");
    }
    if (ret == CKR_OK) {
        version.major = 2;
        version.minor = 40;
        ret = C_GetInterface(interfaceName, &version, &interface, flags);
        CHECK_CKR(ret, "Get Interface");
    }
    if (ret == CKR_OK) {
        version.major = 2;
        version.minor = 20;
        ret = C_GetInterface(interfaceName, &version, &interface, flags);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Get Interface");
    }
    if (ret == CKR_OK) {
        version.major = 3;
        version.minor = 0;
        ret = C_GetInterface(interfaceName, &version, &interface, flags);
        CHECK_CKR(ret, "Get Interface");
    }
#ifdef WOLFPKCS11_PKCS11_V3_2
    if (ret == CKR_OK) {
        version.major = 3;
        version.minor = 2;
        ret = C_GetInterface(interfaceName, &version, &interface, flags);
        CHECK_CKR(ret, "Get Interface");
    }
#endif /* WOLFPKCS11_PKCS11_V3_2 */
#endif /* HAVE_PKCS11_STATIC */

    funcList = (CK_FUNCTION_LIST*)interface->pFunctionList;
    if (funcList == NULL) {
        fprintf(stderr, "Failed to get function list\n");
        ret = -1;
    }
    return ret;
}

static CK_RV test_get_info(void* args)
{
    CK_RV ret = CKR_OK;
    CK_INFO info;
    CK_VERSION version;
    CK_INTERFACE* interface = NULL;
#ifndef HAVE_PKCS11_STATIC
    void* func;
#endif

    (void)args;

#ifndef HAVE_PKCS11_STATIC
    func = (void*)(CK_C_GetInterface)dlsym(dlib, "C_GetInterface");
    if (func == NULL) {
        fprintf(stderr, "Failed to get interface function\n");
        ret = -1;
    }
#endif
    /* Load V2.40 interface */
    if (ret == CKR_OK) {
        version.major = 2;
        version.minor = 40;
#ifndef HAVE_PKCS11_STATIC
        ret = ((CK_C_GetInterface)func)((CK_UTF8CHAR_PTR)"PKCS 11", &version,
                                        &interface, (CK_FLAGS)0);
#else
        ret = C_GetInterface((CK_UTF8CHAR_PTR)"PKCS 11", &version, &interface,
                             (CK_FLAGS)0);
#endif
        CHECK_CKR(ret, "Get Interface");
    }

    /* Check Get Info */
    if (ret == CKR_OK) {
        funcList = (CK_FUNCTION_LIST*)interface->pFunctionList;
        ret = funcList->C_GetInfo(NULL);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Get Info no pointer");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetInfo(&info);
        CHECK_CKR(ret, "Get Info");
    }
    if (ret == CKR_OK) {
        if (info.cryptokiVersion.major != 2 ||
            info.cryptokiVersion.minor != 40) {
            fprintf(stderr, "Expected version 2.40, got %d.%d\n",
                    info.cryptokiVersion.major, info.cryptokiVersion.minor);
            ret = -1;
        }
    }

    /* Load V3.0 interface */
    if (ret == CKR_OK) {
        version.major = 3;
        version.minor = 0;
#ifndef HAVE_PKCS11_STATIC
        ret = ((CK_C_GetInterface)func)((CK_UTF8CHAR_PTR)"PKCS 11", &version,
                                        &interface, (CK_FLAGS)0);
#else
        ret = C_GetInterface((CK_UTF8CHAR_PTR)"PKCS 11", &version, &interface,
                             (CK_FLAGS)0);
#endif
        CHECK_CKR(ret, "Get Interface");
    }

    /* Check Get Info */
    if (ret == CKR_OK) {
        funcList = (CK_FUNCTION_LIST*)interface->pFunctionList;
        ret = funcList->C_GetInfo(NULL);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Get Info no pointer");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetInfo(&info);
        CHECK_CKR(ret, "Get Info");
    }
    if (ret == CKR_OK) {
        if (info.cryptokiVersion.major != 3 ||
            info.cryptokiVersion.minor != 0) {
            fprintf(stderr, "Expected version 3.0, got %d.%d\n",
                    info.cryptokiVersion.major, info.cryptokiVersion.minor);
            ret = -1;
        }
    }

#ifdef WOLFPKCS11_PKCS11_V3_2
    /* Load V3.2 interface */
    if (ret == CKR_OK) {
        version.major = 3;
        version.minor = 2;
#ifndef HAVE_PKCS11_STATIC
        ret = ((CK_C_GetInterface)func)((CK_UTF8CHAR_PTR)"PKCS 11", &version,
                                        &interface, (CK_FLAGS)0);
#else
        ret = C_GetInterface((CK_UTF8CHAR_PTR)"PKCS 11", &version, &interface,
                             (CK_FLAGS)0);
#endif
        CHECK_CKR(ret, "Get Interface");
    }

    if (ret == CKR_OK) {
        funcList = (CK_FUNCTION_LIST*)interface->pFunctionList;
        ret = funcList->C_GetInfo(NULL);
        CHECK_CKR_FAIL(ret, CKR_ARGUMENTS_BAD, "Get Info no pointer");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_GetInfo(&info);
        CHECK_CKR(ret, "Get Info");
    }
    if (ret == CKR_OK) {
        if (info.cryptokiVersion.major != 3 ||
            info.cryptokiVersion.minor != 2) {
            fprintf(stderr, "Expected version 3.2, got %d.%d\n",
                    info.cryptokiVersion.major, info.cryptokiVersion.minor);
            ret = -1;
        }
    }
#endif

    return ret;
}

static CK_RV test_function_not_supported(void* args)
{
    CK_RV ret = CKR_OK;
    CK_SESSION_HANDLE session = *(CK_SESSION_HANDLE*)args;
#ifdef WOLFPKCS11_PKCS11_V3_2
    CK_FUNCTION_LIST_3_2* funcListExt = (CK_FUNCTION_LIST_3_2*)funcList;
#else
    CK_FUNCTION_LIST_3_0* funcListExt = (CK_FUNCTION_LIST_3_0*)funcList;
#endif

    if (ret == CKR_OK) {
        ret = funcListExt->C_SessionCancel(session, 0);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "SessionCancel");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_MessageEncryptInit(session, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "MessageEncryptInit");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_EncryptMessage(session, NULL, 0, NULL, 0, NULL, 0,
                                            NULL, NULL);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "EncryptMessage");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_EncryptMessageBegin(session, NULL, 0, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "EncryptMessageBegin");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_EncryptMessageNext(session, NULL, 0, NULL, 0, NULL,
                                                0, 0);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "EncryptMessageNext");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_MessageEncryptFinal(session);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "MessageEncryptFinal");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_MessageDecryptInit(session, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "MessageDecryptInit");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_DecryptMessage(session, NULL, 0, NULL, 0, NULL, 0,
                                            NULL, NULL);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "DecryptMessage");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_DecryptMessageBegin(session, NULL, 0, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "DecryptMessageBegin");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_DecryptMessageNext(session, NULL, 0, NULL, 0, NULL,
                                                0, 0);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "DecryptMessageNext");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_MessageDecryptFinal(session);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "MessageDecryptFinal");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_MessageSignInit(session, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "MessageSignInit");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_SignMessage(session, NULL, 0, NULL, 0, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "SignMessage");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_SignMessageBegin(session, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "SignMessageBegin");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_SignMessageNext(session, NULL, 0, NULL, 0,
                                             NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "SignMessageNext");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_MessageSignFinal(session);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "MessageSignFinal");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_MessageVerifyInit(session, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "MessageVerifyInit");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_VerifyMessage(session, NULL, 0, NULL, 0,
                                           NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "VerifyMessage");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_VerifyMessageBegin(session, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "VerifyMessageBegin");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_VerifyMessageNext(session, NULL, 0, NULL, 0,
                                               NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "VerifyMessageNext");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_MessageVerifyFinal(session);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "MessageVerifyFinal");
    }

#ifdef WOLFPKCS11_PKCS11_V3_2
#ifndef WOLFPKCS11_MLKEM
    if (ret == CKR_OK) {
        ret = funcListExt->C_EncapsulateKey(session, NULL, 0, NULL, 0, NULL,
                                            NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "EncapsulateKey");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_DecapsulateKey(session, NULL, 0, NULL, 0, NULL,
                                            0, NULL);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "DecapsulateKey");
    }
#endif /* !WOLFPKCS11_MLKEM */
    if (ret == CKR_OK) {
        ret = funcListExt->C_VerifySignatureInit(session, NULL, 0, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "VerifySignatureInit");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_VerifySignature(session, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "VerifySignature");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_VerifySignatureUpdate(session, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED,
                       "VerifySignatureUpdate");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_VerifySignatureFinal(session);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "VerifySignatureFinal");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_GetSessionValidationFlags(session, 0, NULL);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED,
                       "GetSessionValidationFlags");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_AsyncComplete(session, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "AsyncComplete");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_AsyncGetID(session, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "AsyncGetID");
    }
    if (ret == CKR_OK) {
        ret = funcListExt->C_AsyncJoin(session, NULL, 0, NULL, 0);
        CHECK_CKR_FAIL(ret, CKR_FUNCTION_NOT_SUPPORTED, "AsyncJoin");
    }
#endif

    return ret;
}

static CK_RV pkcs11_lib_init(void)
{
    CK_RV ret;
    CK_C_INITIALIZE_ARGS args;

    XMEMSET(&args, 0x00, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    ret = funcList->C_Initialize(NULL);
    CHECK_CKR(ret, "Initialize");

    return ret;
}

static CK_RV pkcs11_init_token(void)
{
    CK_RV ret;
    unsigned char label[32];

    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, tokenName, XSTRLEN(tokenName));

    ret = funcList->C_InitToken(slot, soPin, soPinLen, label);
    CHECK_CKR(ret, "Init Token");

    return ret;
}

static void pkcs11_final(int closeDl)
{
    if (funcList != NULL) {
        funcList->C_Finalize(NULL);
    }
    if (closeDl) {
    #ifndef HAVE_PKCS11_STATIC
        dlclose(dlib);
    #endif
    }
}

static CK_RV pkcs11_set_user_pin(int slotId)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    int flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

    ret = funcList->C_OpenSession(slotId, flags, NULL, NULL, &session);
    CHECK_CKR(ret, "Set User PIN - Open Session");
    if (ret == CKR_OK) {
        ret = funcList->C_Login(session, CKU_SO, soPin, soPinLen);
        CHECK_CKR(ret, "Set User PIN - Login");
        if (ret == CKR_OK) {
            ret = funcList->C_InitPIN(session, userPin, userPinLen);
            CHECK_CKR(ret, "Set User PIN - Init PIN");
        }
        funcList->C_CloseSession(session);
    }

    if (ret != CKR_OK)
        fprintf(stderr, "FAILED: Setting user PIN\n");
    return ret;
}

static CK_RV pkcs11_open_session(int flags, void* args)
{
    CK_SESSION_HANDLE* session = (CK_SESSION_HANDLE*)args;
    CK_RV ret = CKR_OK;
    int sessFlags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

    if (flags & TEST_FLAG_SESSION) {
        ret = funcList->C_OpenSession(slot, sessFlags, NULL, NULL, session);
        CHECK_CKR(ret, "Open Session");
        if (ret == CKR_OK && userPinLen != 0) {
            ret = funcList->C_Login(*session, CKU_USER, userPin, userPinLen);
            CHECK_CKR(ret, "Login");
        }
    }

    return ret;
}

static void pkcs11_close_session(int flags, void* args)
{
    CK_SESSION_HANDLE* session = (CK_SESSION_HANDLE*)args;

    if (flags & TEST_FLAG_SESSION) {
        if (userPinLen != 0)
            funcList->C_Logout(*session);
        funcList->C_CloseSession(*session);
    }
}

static TEST_FUNC testFunc[] = {
    PKCS11TEST_FUNC_NO_INIT_DECL(test_get_interface_list),
    PKCS11TEST_FUNC_NO_INIT_DECL(test_get_interface),
    PKCS11TEST_FUNC_TOKEN_DECL(test_get_info),
    PKCS11TEST_FUNC_SESS_DECL(test_function_not_supported),
#ifdef WOLFPKCS11_PKCS11_V3_2
#ifdef WOLFPKCS11_MLDSA
    PKCS11TEST_FUNC_SESS_DECL(test_mldsa_gen_keys),
    PKCS11TEST_FUNC_SESS_DECL(test_mldsa_gen_keys_id),
    PKCS11TEST_FUNC_SESS_DECL(test_mldsa_gen_keys_token),
    PKCS11TEST_FUNC_SESS_DECL(test_mldsa_token_keys),
    PKCS11TEST_FUNC_SESS_DECL(test_mldsa_sig_fail),
    PKCS11TEST_FUNC_SESS_DECL(test_mldsa_fixed_keys_expanded),
    PKCS11TEST_FUNC_SESS_DECL(test_mldsa_fixed_keys_seed),
    PKCS11TEST_FUNC_SESS_DECL(test_mldsa_fixed_keys_both),
    PKCS11TEST_FUNC_SESS_DECL(test_copy_object_mldsa_key),
#endif
#ifdef WOLFPKCS11_MLKEM
    PKCS11TEST_FUNC_SESS_DECL(test_mlkem_gen_keys),
    PKCS11TEST_FUNC_SESS_DECL(test_mlkem_gen_keys_768),
    PKCS11TEST_FUNC_SESS_DECL(test_mlkem_gen_keys_1024),
    PKCS11TEST_FUNC_SESS_DECL(test_mlkem_gen_keys_id),
    PKCS11TEST_FUNC_SESS_DECL(test_mlkem_gen_keys_token),
    PKCS11TEST_FUNC_SESS_DECL(test_mlkem_token_keys),
    PKCS11TEST_FUNC_SESS_DECL(test_mlkem_fixed_keys),
    PKCS11TEST_FUNC_SESS_DECL(test_mlkem_fixed_keys_seed),
    PKCS11TEST_FUNC_SESS_DECL(test_mlkem_fixed_keys_seed_both),
    PKCS11TEST_FUNC_SESS_DECL(test_mlkem_seed_invalid),
    PKCS11TEST_FUNC_SESS_DECL(test_mlkem_encap_decap_fail),
    PKCS11TEST_FUNC_SESS_DECL(test_mlkem_bad_mech_params),
    PKCS11TEST_FUNC_SESS_DECL(test_mlkem_key_validation),
    PKCS11TEST_FUNC_SESS_DECL(test_mlkem_initial_states),
    PKCS11TEST_FUNC_SESS_DECL(test_copy_object_mlkem_key),
#endif
#endif
};
static int testFuncCnt = sizeof(testFunc) / sizeof(*testFunc);

static CK_RV pkcs11_test(int slotId, int setPin, int onlySet, int closeDl)
{
    CK_RV ret;
    int i;
    int attempted = 0, passed = 0, skipped = 0;
    int inited = 0;

    /* Set it global. */
    slot = slotId;

    /* Do tests before library initialization. */
    ret = run_tests(testFunc, testFuncCnt, onlySet, 0);

    /* Initialize library. */
    if (ret == CKR_OK)
        ret = pkcs11_lib_init();

    /* Do tests after library initialization but without SO PIN. */
    if (ret == CKR_OK) {
        inited = 1;
        ret = run_tests(testFunc, testFuncCnt, onlySet, TEST_FLAG_INIT);
    }

    if (ret == CKR_OK)
        ret = pkcs11_init_token();

    /* Do tests after library initialization but without session. */
    if (ret == CKR_OK) {
        ret = run_tests(testFunc, testFuncCnt, onlySet, TEST_FLAG_INIT |
                                                               TEST_FLAG_TOKEN);
    }

    /* Set user PIN. */
    if (ret == CKR_OK) {
        if (setPin)
            ret = pkcs11_set_user_pin(slotId);
    }
    /* Do tests with session. */
    if (ret == CKR_OK) {
        ret = run_tests(testFunc, testFuncCnt, onlySet, TEST_FLAG_INIT |
                                           TEST_FLAG_TOKEN | TEST_FLAG_SESSION);
    }

    /* Check for pass and fail. */
    for (i = 0; i < testFuncCnt; i++) {
        if (testFunc[i].attempted) {
            attempted++;
            if (testFunc[i].ret == CKR_SKIPPED) {
                skipped++;
            }
            else if (testFunc[i].ret != CKR_OK) {
#ifdef DEBUG_WOLFPKCS11
                if (ret == CKR_OK)
                    fprintf(stderr, "\nFAILED tests:\n");
                fprintf(stderr, "%d: %s\n", i + 1, testFunc[i].name);
#endif
                ret = testFunc[i].ret;
            }
            else
                passed++;
        }
    }
    fprintf(stderr, "Result: attempted: %d, passed: %d", attempted, passed);
    if (skipped != 0) {
        fprintf(stderr, ", skipped %d", skipped);
    }
    fprintf(stderr, "\n");
    if (ret == CKR_OK)
        fprintf(stderr, "Success\n");
    else
        fprintf(stderr, "Failures\n");

    if (inited)
        pkcs11_final(closeDl);

    return ret;
}


static CK_RV pkcs11_init(const char* library)
{
    CK_RV ret = CKR_OK;

    (void) library;

#ifndef HAVE_PKCS11_STATIC
    dlib = dlopen(library, RTLD_NOW | RTLD_LOCAL);
    if (dlib == NULL) {
        fprintf(stderr, "dlopen error: %s\n", dlerror());
        ret = -1;
    }

#ifdef DEBUG_WOLFPKCS11
    wolfPKCS11_Debugging_On_fp = (void (*)(void))dlsym(dlib,
                                                    "wolfPKCS11_Debugging_On");
    wolfPKCS11_Debugging_Off_fp = (void (*)(void))dlsym(dlib,
                                                "wolfPKCS11_Debugging_Off");
    /* These functions are optional, so don't fail if they're not found */
#endif

#endif

    return ret;
}

#endif /* WOLFPKCS11_PKCS11_V3_0 */

/* Display the usage options of the benchmark program. */
static void Usage(void)
{
    printf("pkcs11v3test\n");
    printf("-?                 Help, print this usage\n");
    printf("-lib <file>        PKCS#11 library to test\n");
    printf("-slot <num>        Slot number to use\n");
    printf("-token <string>    Name of token\n");
    printf("-soPin <string>    Security Officer PIN\n");
    printf("-userPin <string>  User PIN\n");
    printf("-no-close          Do not close the PKCS#11 library before exit\n");
    printf("-list              List all tests that can be run\n");
    UnitUsage();
    printf("<num>              Test case number to try\n");
}

#ifndef NO_MAIN_DRIVER
int main(int argc, char* argv[])
#else
int pkcs11v3test_test(int argc, char* argv[])
#endif
{
#ifdef WOLFPKCS11_PKCS11_V3_0
    int ret;
    CK_RV rv;
    int slotId = WOLFPKCS11_DLL_SLOT;
    const char* libName = WOLFPKCS11_DLL_FILENAME;
    int setPin = 1;
    int testCase;
    int onlySet = 0;
    int closeDl = 1;
    int i;

#ifndef WOLFPKCS11_NO_ENV
    XSETENV("WOLFPKCS11_TOKEN_PATH", "./store/pkcs11v3test", 1);
#endif

    argc--;
    argv++;
    while (argc > 0) {
        if (string_matches(*argv, "-?")) {
            Usage();
            return 0;
        }
        UNIT_PARSE_ARGS(argc, argv)
        else if (string_matches(*argv, "-lib")) {
            argc--;
            argv++;
            if (argc == 0) {
                fprintf(stderr, "Library name not supplied\n");
                return 1;
            }
            libName = *argv;
        }
        else if (string_matches(*argv, "-case")) {
            argc--;
            argv++;
            if (argc == 0) {
                fprintf(stderr, "Test case number not supplied\n");
                return 1;
            }
            testCase = atoi(*argv);
            if (testCase <= 0 || testCase > testFuncCnt) {
                fprintf(stderr, "Test case out of range: %s\n", *argv);
                return 1;
            }
            testFunc[testCase - 1].run = 1;
            onlySet = 1;
        }
        else if (string_matches(*argv, "-token")) {
            argc--;
            argv++;
            if (argc == 0) {
                fprintf(stderr, "Token name not supplied\n");
                return 1;
            }
            tokenName = *argv;
        }
        else if (string_matches(*argv, "-soPin")) {
            argc--;
            argv++;
            if (argc == 0) {
                fprintf(stderr, "SO PIN not supplied\n");
                return 1;
            }
            soPin = (byte*)*argv;
            soPinLen = (int)XSTRLEN((const char*)soPin);
        }
        else if (string_matches(*argv, "-userPin")) {
            argc--;
            argv++;
            if (argc == 0) {
                fprintf(stderr, "User PIN not supplied\n");
                return 1;
            }
            userPin = (byte*)*argv;
        }
        else if (string_matches(*argv, "-no-close")) {
            closeDl = 0;
        }
        else if (string_matches(*argv, "-list")) {
            for (i = 0; i < testFuncCnt; i++)
                fprintf(stderr, "%d: %s\n", i + 1, testFunc[i].name);
            return 0;
        }
        else if (isdigit((int)argv[0][0])) {
            testCase = atoi(*argv);
            if (testCase <= 0 || testCase > testFuncCnt) {
                fprintf(stderr, "Test case out of range: %s\n", *argv);
                return 1;
            }
            testFunc[testCase - 1].run = 1;
            onlySet = 1;
        }
        else {
            for (i = 0; i < testFuncCnt; i++) {
                if (string_matches(*argv, testFunc[i].name)) {
                    testFunc[i].run = 1;
                    onlySet = 1;
                    break;
                }
            }
            if (i == testFuncCnt) {
                fprintf(stderr, "Test case name doesn't match: %s\n", *argv);
                return 1;
            }
        }

        argc--;
        argv++;
    }

    userPinLen = (int)XSTRLEN((const char*)userPin);

    rv = pkcs11_init(libName);
    if (rv == CKR_OK) {
        rv = pkcs11_test(slotId, setPin, onlySet, closeDl);
    }

    if (rv == CKR_OK)
        ret = 0;
    else
        ret = 1;
    return ret;
#else
    (void)argc;
    (void)argv;
    fprintf(stdout, "%s: PKCS#11 v3.0 not compiled in!\n", argv[0]);
    return 0;
#endif /* WOLFPKCS11_PKCS11_V3_0 */
}

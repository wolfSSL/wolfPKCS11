/* info_mech_table_test.c
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
 *
 * Library, slot, token and mechanism information must match the PKCS#11
 * encoding rules and what the token actually implements.
 */

#ifdef HAVE_CONFIG_H
    #include <wolfpkcs11/config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/misc.h>
#include <wolfssl/wolfcrypt/memory.h>

#ifndef WOLFPKCS11_USER_SETTINGS
    #include <wolfpkcs11/options.h>
#endif
#include <wolfpkcs11/pkcs11.h>

#ifndef HAVE_PKCS11_STATIC
#include <dlfcn.h>
#endif

#include "testdata.h"
#include "pkcs11_test_util.h"

#define TEST_DIR "./store/info_mech_table_test"

#if defined(USE_WOLFSSL_MEMORY) && !defined(NO_WOLFSSL_MEMORY) && \
    !defined(WOLFSSL_STATIC_MEMORY) && !defined(WOLFSSL_DEBUG_MEMORY)
    #define ALLOC_HOOKS
#endif

#ifdef ALLOC_HOOKS
static int failAllocs = 0;

static void* hook_malloc(size_t sz)
{
    if (failAllocs)
        return NULL;
    return malloc(sz);
}

static void hook_free(void* ptr)
{
    free(ptr);
}

static void* hook_realloc(void* ptr, size_t sz)
{
    if (failAllocs)
        return NULL;
    return realloc(ptr, sz);
}
#endif

/* Fixed-length character fields are blank padded and never contain NUL. */
static int blank_padded(const CK_UTF8CHAR* field, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        if (field[i] == '\0')
            return 0;
    }
    return 1;
}

static void check_info(CK_FUNCTION_LIST* list, const char* name)
{
    CK_RV rv;
    CK_INFO info;
    char msg[96];

    XMEMSET(&info, 0, sizeof(info));
    rv = list->C_GetInfo(&info);
    snprintf(msg, sizeof(msg), "C_GetInfo(%s)", name);
    CHECK_RV(rv, msg, CKR_OK);
    if (rv != CKR_OK)
        return;
    snprintf(msg, sizeof(msg), "%s CK_INFO.manufacturerID blank padded", name);
    CHECK_TRUE(blank_padded(info.manufacturerID, sizeof(info.manufacturerID)),
               msg);
    snprintf(msg, sizeof(msg), "%s CK_INFO.libraryDescription blank padded",
             name);
    CHECK_TRUE(blank_padded(info.libraryDescription,
                            sizeof(info.libraryDescription)), msg);
}

static void test_info_blank_padding(CK_SLOT_ID slot)
{
    CK_RV rv;
    CK_SLOT_INFO slotInfo;
    CK_TOKEN_INFO tokenInfo;
#ifdef WOLFPKCS11_PKCS11_V3_0
    CK_INTERFACE interfaces[8];
    CK_ULONG count = sizeof(interfaces) / sizeof(interfaces[0]);
    CK_ULONG i;
    char name[32];
#ifndef HAVE_PKCS11_STATIC
    CK_C_GetInterfaceList getList;
#endif
#endif

    check_info(funcList, "v2");

#ifdef WOLFPKCS11_PKCS11_V3_0
#ifndef HAVE_PKCS11_STATIC
    getList = (CK_C_GetInterfaceList)dlsym(dlib, "C_GetInterfaceList");
    CHECK_TRUE(getList != NULL, "C_GetInterfaceList symbol");
    rv = (getList != NULL) ? getList(interfaces, &count) : CKR_GENERAL_ERROR;
#else
    rv = C_GetInterfaceList(interfaces, &count);
#endif
    CHECK_RV(rv, "C_GetInterfaceList", CKR_OK);
    for (i = 0; rv == CKR_OK && i < count; i++) {
        snprintf(name, sizeof(name), "interface %lu", (unsigned long)i);
        check_info((CK_FUNCTION_LIST*)interfaces[i].pFunctionList, name);
    }
#endif

    XMEMSET(&slotInfo, 0, sizeof(slotInfo));
    rv = funcList->C_GetSlotInfo(slot, &slotInfo);
    CHECK_RV(rv, "C_GetSlotInfo", CKR_OK);
    if (rv == CKR_OK) {
        CHECK_TRUE(blank_padded(slotInfo.slotDescription,
                                sizeof(slotInfo.slotDescription)),
                   "CK_SLOT_INFO.slotDescription blank padded");
        CHECK_TRUE(blank_padded(slotInfo.manufacturerID,
                                sizeof(slotInfo.manufacturerID)),
                   "CK_SLOT_INFO.manufacturerID blank padded");
    }

    XMEMSET(&tokenInfo, 0, sizeof(tokenInfo));
    rv = funcList->C_GetTokenInfo(slot, &tokenInfo);
    CHECK_RV(rv, "C_GetTokenInfo", CKR_OK);
    if (rv == CKR_OK) {
        CHECK_TRUE(blank_padded(tokenInfo.label, sizeof(tokenInfo.label)),
                   "CK_TOKEN_INFO.label blank padded");
        CHECK_TRUE(blank_padded(tokenInfo.manufacturerID,
                                sizeof(tokenInfo.manufacturerID)),
                   "CK_TOKEN_INFO.manufacturerID blank padded");
        CHECK_TRUE(blank_padded(tokenInfo.model, sizeof(tokenInfo.model)),
                   "CK_TOKEN_INFO.model blank padded");
        CHECK_TRUE(blank_padded(tokenInfo.serialNumber,
                                sizeof(tokenInfo.serialNumber)),
                   "CK_TOKEN_INFO.serialNumber has no NUL bytes");
    }
}

static int two_digits(const CK_CHAR* p, int* val)
{
    if (p[0] < '0' || p[0] > '9' || p[1] < '0' || p[1] > '9')
        return 0;
    *val = (p[0] - '0') * 10 + (p[1] - '0');
    return 1;
}

/* A token that claims a clock must report a valid UTC time. */
static void test_token_clock(CK_SLOT_ID slot)
{
    CK_RV rv;
    CK_TOKEN_INFO tokenInfo;
    int century = 0, year = 0, month = 0, day = 0;
    int hour = 0, minute = 0, second = 0;
    int valid;

    XMEMSET(&tokenInfo, 0, sizeof(tokenInfo));
    rv = funcList->C_GetTokenInfo(slot, &tokenInfo);
    CHECK_RV(rv, "C_GetTokenInfo(clock)", CKR_OK);
    if (rv != CKR_OK)
        return;

    if ((tokenInfo.flags & CKF_CLOCK_ON_TOKEN) == 0) {
        CHECK_TRUE(XMEMCMP(tokenInfo.utcTime, "                ",
                           sizeof(tokenInfo.utcTime)) == 0,
                   "utcTime is blank without a clock");
        return;
    }

    valid = two_digits(&tokenInfo.utcTime[0], &century) &&
            two_digits(&tokenInfo.utcTime[2], &year) &&
            two_digits(&tokenInfo.utcTime[4], &month) &&
            two_digits(&tokenInfo.utcTime[6], &day) &&
            two_digits(&tokenInfo.utcTime[8], &hour) &&
            two_digits(&tokenInfo.utcTime[10], &minute) &&
            two_digits(&tokenInfo.utcTime[12], &second);
    CHECK_TRUE(valid && century * 100 + year >= 1970 &&
               month >= 1 && month <= 12 && day >= 1 && day <= 31 &&
               hour <= 23 && minute <= 59 && second <= 60,
               "CKF_CLOCK_ON_TOKEN reports a valid utcTime");
}

/* C_WrapKey rejects every key before the mechanism check when it cannot
 * serialize keys, as in a build without a store. */
#if defined(WOLFPKCS11_NO_STORE) && !defined(WOLFSSL_STM32U5_DHUK)
    #define WRAP_UNSUPPORTED_RV    CKR_KEY_NOT_WRAPPABLE
#else
    #define WRAP_UNSUPPORTED_RV    CKR_MECHANISM_INVALID
#endif

static CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
static CK_KEY_TYPE genericType = CKK_GENERIC_SECRET;
static CK_BBOOL ckTrue = CK_TRUE;
static CK_BBOOL ckFalse = CK_FALSE;

static CK_RV generate_generic(CK_SESSION_HANDLE session, CK_ULONG len)
{
    CK_RV rv;
    CK_MECHANISM mech = { CKM_GENERIC_SECRET_KEY_GEN, NULL, 0 };
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,     &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE,  &genericType, sizeof(genericType) },
        { CKA_PRIVATE,   &ckFalse,     sizeof(ckFalse)     },
        { CKA_VALUE_LEN, &len,         sizeof(len)         },
    };

    rv = funcList->C_GenerateKey(session, &mech, tmpl,
                                 sizeof(tmpl) / sizeof(*tmpl), &key);
    if (key != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, key);
    return rv;
}

/* Generic secret key sizes are reported in bits and match what generates. */
static void test_generic_secret_size(CK_SLOT_ID slot,
                                     CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_MECHANISM_INFO info;

    rv = funcList->C_GetMechanismInfo(slot, CKM_GENERIC_SECRET_KEY_GEN, &info);
    CHECK_RV(rv, "C_GetMechanismInfo(CKM_GENERIC_SECRET_KEY_GEN)", CKR_OK);
    if (rv != CKR_OK)
        return;

    CHECK_TRUE(info.ulMinKeySize >= 8 && info.ulMinKeySize % 8 == 0 &&
               info.ulMaxKeySize % 8 == 0 &&
               info.ulMaxKeySize >= info.ulMinKeySize,
               "generic secret key sizes are whole bytes in bits");
    rv = generate_generic(session, info.ulMinKeySize / 8);
    CHECK_RV(rv, "generate generic secret of minimum size", CKR_OK);
    rv = generate_generic(session, info.ulMaxKeySize / 8);
    CHECK_RV(rv, "generate generic secret of maximum size", CKR_OK);
    rv = generate_generic(session, info.ulMaxKeySize / 8 + 1);
    CHECK_TRUE(rv != CKR_OK,
               "generic secret above maximum size is rejected");
}

/* Every listed key generation mechanism must be known to C_GenerateKey. */
static void test_listed_keygen_supported(CK_SLOT_ID slot,
                                         CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_MECHANISM_TYPE mechs[256];
    CK_ULONG count = sizeof(mechs) / sizeof(mechs[0]);
    CK_ULONG i;
    CK_MECHANISM_INFO info;
    CK_MECHANISM mech;
    CK_OBJECT_HANDLE key;
    char msg[96];
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,   &secretClass, sizeof(secretClass) },
        { CKA_PRIVATE, &ckFalse,     sizeof(ckFalse)     },
    };

    rv = funcList->C_GetMechanismList(slot, mechs, &count);
    CHECK_RV(rv, "C_GetMechanismList", CKR_OK);
    if (rv != CKR_OK)
        return;

    for (i = 0; i < count; i++) {
        rv = funcList->C_GetMechanismInfo(slot, mechs[i], &info);
        snprintf(msg, sizeof(msg), "C_GetMechanismInfo(listed 0x%lx)",
                 (unsigned long)mechs[i]);
        CHECK_RV(rv, msg, CKR_OK);
        if (rv != CKR_OK || (info.flags & CKF_GENERATE) == 0)
            continue;

        mech.mechanism = mechs[i];
        mech.pParameter = NULL;
        mech.ulParameterLen = 0;
        key = CK_INVALID_HANDLE;
        rv = funcList->C_GenerateKey(session, &mech, tmpl,
                                     sizeof(tmpl) / sizeof(*tmpl), &key);
        if (key != CK_INVALID_HANDLE)
            funcList->C_DestroyObject(session, key);
        snprintf(msg, sizeof(msg), "C_GenerateKey accepts listed 0x%lx",
                 (unsigned long)mechs[i]);
        CHECK_TRUE(rv != CKR_MECHANISM_INVALID, msg);
    }
}

#ifdef ALLOC_HOOKS
/* A session is reported open only when a usable handle was returned. */
static void test_open_session_alloc_failure(CK_SLOT_ID slot)
{
    CK_RV rv;
    CK_SESSION_HANDLE handles[8];
    CK_SESSION_INFO sessInfo;
    int opened = 0;
    int failed = 0;
    int i;

    for (i = 0; i < (int)(sizeof(handles) / sizeof(handles[0])); i++) {
        handles[i] = CK_INVALID_HANDLE;
        failAllocs = 1;
        rv = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                     NULL, NULL, &handles[i]);
        failAllocs = 0;
        if (rv != CKR_OK) {
            CHECK_RV(rv, "C_OpenSession without memory", CKR_HOST_MEMORY);
            failed = 1;
            break;
        }
        opened++;
        rv = funcList->C_GetSessionInfo(handles[i], &sessInfo);
        CHECK_RV(rv, "C_OpenSession returns a usable handle", CKR_OK);
        if (rv != CKR_OK)
            break;
    }
    CHECK_TRUE(failed, "C_OpenSession reports allocation failure");

    for (i = 0; i < opened; i++) {
        if (handles[i] != CK_INVALID_HANDLE)
            funcList->C_CloseSession(handles[i]);
    }
}
#endif

typedef struct WrapCase {
    CK_MECHANISM_TYPE mech;
    int useIv;
    int rsa;
} WrapCase;

/* Wrap and unwrap must succeed exactly for mechanisms that advertise them. */
static void test_wrap_flags(CK_SLOT_ID slot, CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_MECHANISM_INFO info;
    CK_MECHANISM mech;
    CK_OBJECT_HANDLE secret = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE aesKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE wrapKey;
    CK_OBJECT_HANDLE unwrapKey;
    CK_OBJECT_HANDLE unwrapped;
    CK_BYTE iv[16];
    CK_BYTE secretValue[32];
    CK_BYTE aesValue[16];
    CK_BYTE wrapped[512];
    CK_ULONG wrappedLen;
    CK_BYTE* unwrapData;
    CK_ULONG unwrapLen;
    char msg[96];
    size_t i;
#ifndef NO_RSA
    CK_OBJECT_HANDLE rsaPub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE rsaPriv = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE rsaType = CKK_RSA;
    CK_ATTRIBUTE rsaPubTmpl[] = {
        { CKA_CLASS,           &pubClass,        sizeof(pubClass)         },
        { CKA_KEY_TYPE,        &rsaType,         sizeof(rsaType)          },
        { CKA_WRAP,            &ckTrue,          sizeof(ckTrue)           },
        { CKA_ENCRYPT,         &ckTrue,          sizeof(ckTrue)           },
        { CKA_MODULUS,         rsa_2048_modulus, sizeof(rsa_2048_modulus) },
        { CKA_PUBLIC_EXPONENT, rsa_2048_pub_exp, sizeof(rsa_2048_pub_exp) },
    };
    CK_ATTRIBUTE rsaPrivTmpl[] = {
        { CKA_CLASS,            &privClass,        sizeof(privClass)         },
        { CKA_KEY_TYPE,         &rsaType,          sizeof(rsaType)           },
        { CKA_PRIVATE,          &ckFalse,          sizeof(ckFalse)           },
        { CKA_UNWRAP,           &ckTrue,           sizeof(ckTrue)            },
        { CKA_DECRYPT,          &ckTrue,           sizeof(ckTrue)            },
        { CKA_MODULUS,          rsa_2048_modulus,  sizeof(rsa_2048_modulus)  },
        { CKA_PRIVATE_EXPONENT, rsa_2048_priv_exp, sizeof(rsa_2048_priv_exp) },
        { CKA_PRIME_1,          rsa_2048_p,        sizeof(rsa_2048_p)        },
        { CKA_PRIME_2,          rsa_2048_q,        sizeof(rsa_2048_q)        },
        { CKA_EXPONENT_1,       rsa_2048_dP,       sizeof(rsa_2048_dP)       },
        { CKA_EXPONENT_2,       rsa_2048_dQ,       sizeof(rsa_2048_dQ)       },
        { CKA_COEFFICIENT,      rsa_2048_u,        sizeof(rsa_2048_u)        },
        { CKA_PUBLIC_EXPONENT,  rsa_2048_pub_exp,  sizeof(rsa_2048_pub_exp)  },
    };
#endif
#ifndef NO_AES
    CK_KEY_TYPE aesType = CKK_AES;
    CK_ATTRIBUTE aesTmpl[] = {
        { CKA_CLASS,    &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE, &aesType,     sizeof(aesType)     },
        { CKA_PRIVATE,  &ckFalse,     sizeof(ckFalse)     },
        { CKA_WRAP,     &ckTrue,      sizeof(ckTrue)      },
        { CKA_UNWRAP,   &ckTrue,      sizeof(ckTrue)      },
        { CKA_ENCRYPT,  &ckTrue,      sizeof(ckTrue)      },
        { CKA_DECRYPT,  &ckTrue,      sizeof(ckTrue)      },
        { CKA_VALUE,    aesValue,     sizeof(aesValue)    },
    };
#endif
    CK_ATTRIBUTE secretTmpl[] = {
        { CKA_CLASS,       &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE,    &genericType, sizeof(genericType) },
        { CKA_PRIVATE,     &ckFalse,     sizeof(ckFalse)     },
        { CKA_SENSITIVE,   &ckFalse,     sizeof(ckFalse)     },
        { CKA_EXTRACTABLE, &ckTrue,      sizeof(ckTrue)      },
        { CKA_VALUE,       secretValue,  sizeof(secretValue) },
    };
    CK_ULONG secretLen = sizeof(secretValue);
    CK_ATTRIBUTE unwrapTmpl[] = {
        { CKA_CLASS,       &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE,    &genericType, sizeof(genericType) },
        { CKA_PRIVATE,     &ckFalse,     sizeof(ckFalse)     },
        { CKA_SENSITIVE,   &ckFalse,     sizeof(ckFalse)     },
        { CKA_EXTRACTABLE, &ckTrue,      sizeof(ckTrue)      },
        { CKA_VALUE_LEN,   &secretLen,   sizeof(secretLen)   },
    };
    static const WrapCase cases[] = {
        { CKM_AES_KEY_WRAP,     0, 0 },
        { CKM_AES_KEY_WRAP_PAD, 0, 0 },
        { CKM_AES_CBC,          1, 0 },
        { CKM_AES_CBC_PAD,      1, 0 },
        { CKM_AES_ECB,          0, 0 },
        { CKM_RSA_PKCS,         0, 1 },
        { CKM_RSA_X_509,        0, 1 },
    };

    XMEMSET(iv, 0x11, sizeof(iv));
    XMEMSET(secretValue, 0x22, sizeof(secretValue));
    XMEMSET(aesValue, 0x33, sizeof(aesValue));

    rv = funcList->C_CreateObject(session, secretTmpl,
                                  sizeof(secretTmpl) / sizeof(*secretTmpl),
                                  &secret);
    CHECK_RV(rv, "C_CreateObject(secret to wrap)", CKR_OK);
    if (rv != CKR_OK)
        return;
#ifndef NO_AES
    rv = funcList->C_CreateObject(session, aesTmpl,
                                  sizeof(aesTmpl) / sizeof(*aesTmpl), &aesKey);
    CHECK_RV(rv, "C_CreateObject(AES wrapping key)", CKR_OK);
#endif
#ifndef NO_RSA
    rv = funcList->C_CreateObject(session, rsaPubTmpl,
                                  sizeof(rsaPubTmpl) / sizeof(*rsaPubTmpl),
                                  &rsaPub);
    CHECK_RV(rv, "C_CreateObject(RSA wrapping key)", CKR_OK);
    rv = funcList->C_CreateObject(session, rsaPrivTmpl,
                                  sizeof(rsaPrivTmpl) / sizeof(*rsaPrivTmpl),
                                  &rsaPriv);
    CHECK_RV(rv, "C_CreateObject(RSA unwrapping key)", CKR_OK);
#endif

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        rv = funcList->C_GetMechanismInfo(slot, cases[i].mech, &info);
        if (rv == CKR_MECHANISM_INVALID)
            continue;
        snprintf(msg, sizeof(msg), "C_GetMechanismInfo(0x%lx)",
                 (unsigned long)cases[i].mech);
        CHECK_RV(rv, msg, CKR_OK);
        if (rv != CKR_OK)
            continue;

        wrapKey = aesKey;
        unwrapKey = aesKey;
#ifndef NO_RSA
        if (cases[i].rsa) {
            wrapKey = rsaPub;
            unwrapKey = rsaPriv;
        }
#endif
        if (wrapKey == CK_INVALID_HANDLE || unwrapKey == CK_INVALID_HANDLE)
            continue;

        mech.mechanism = cases[i].mech;
        mech.pParameter = cases[i].useIv ? iv : NULL;
        mech.ulParameterLen = cases[i].useIv ? sizeof(iv) : 0;

        wrappedLen = sizeof(wrapped);
        rv = funcList->C_WrapKey(session, &mech, wrapKey, secret, wrapped,
                                 &wrappedLen);
        snprintf(msg, sizeof(msg), "C_WrapKey(0x%lx) matches CKF_WRAP",
                 (unsigned long)cases[i].mech);
        CHECK_RV(rv, msg, ((info.flags & CKF_WRAP) != 0) ?
                 CKR_OK : WRAP_UNSUPPORTED_RV);

        unwrapData = wrapped;
        unwrapLen = wrappedLen;
        if (rv != CKR_OK) {
            XMEMSET(wrapped, 0x44, sizeof(wrapped));
            unwrapLen = cases[i].rsa ? 256 : 48;
        }
        if (rv != CKR_OK && (info.flags & CKF_UNWRAP) != 0) {
            /* Unwrap works without wrap support: encrypt the key directly. */
            wrappedLen = sizeof(wrapped);
            rv = funcList->C_EncryptInit(session, &mech, wrapKey);
            if (rv == CKR_OK) {
                rv = funcList->C_Encrypt(session, secretValue,
                                         sizeof(secretValue), wrapped,
                                         &wrappedLen);
            }
            snprintf(msg, sizeof(msg), "C_Encrypt(0x%lx) key to unwrap",
                     (unsigned long)cases[i].mech);
            CHECK_RV(rv, msg, CKR_OK);
            unwrapLen = wrappedLen;
        }
        unwrapped = CK_INVALID_HANDLE;
        /* AES-ECB needs CKA_VALUE_LEN to know the key length. */
        rv = funcList->C_UnwrapKey(session, &mech, unwrapKey, unwrapData,
                                   unwrapLen, unwrapTmpl,
                                   sizeof(unwrapTmpl) / sizeof(*unwrapTmpl) -
                                   (cases[i].mech == CKM_AES_ECB ? 0 : 1),
                                   &unwrapped);
        snprintf(msg, sizeof(msg), "C_UnwrapKey(0x%lx) matches CKF_UNWRAP",
                 (unsigned long)cases[i].mech);
        CHECK_RV(rv, msg, ((info.flags & CKF_UNWRAP) != 0) ?
                 CKR_OK : CKR_MECHANISM_INVALID);
        if (unwrapped != CK_INVALID_HANDLE)
            funcList->C_DestroyObject(session, unwrapped);
    }
}

#ifndef NO_AES
/* AES-ECB wraps a key that is not block aligned and unwraps it back. */
static void test_ecb_wrap_short_key(CK_SLOT_ID slot, CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_MECHANISM_INFO info;
    CK_MECHANISM mech = { CKM_AES_ECB, NULL, 0 };
    CK_OBJECT_HANDLE secret = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE aesKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE unwrapped = CK_INVALID_HANDLE;
    CK_KEY_TYPE aesType = CKK_AES;
    CK_ULONG valueLen = 20;
    CK_BYTE secretValue[20];
    CK_BYTE aesValue[16];
    CK_BYTE wrapped[64];
    CK_BYTE value[32];
    CK_ULONG wrappedLen = sizeof(wrapped);
    CK_ATTRIBUTE secretTmpl[] = {
        { CKA_CLASS,       &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE,    &genericType, sizeof(genericType) },
        { CKA_PRIVATE,     &ckFalse,     sizeof(ckFalse)     },
        { CKA_SENSITIVE,   &ckFalse,     sizeof(ckFalse)     },
        { CKA_EXTRACTABLE, &ckTrue,      sizeof(ckTrue)      },
        { CKA_VALUE,       secretValue,  sizeof(secretValue) },
    };
    CK_ATTRIBUTE aesTmpl[] = {
        { CKA_CLASS,    &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE, &aesType,     sizeof(aesType)     },
        { CKA_PRIVATE,  &ckFalse,     sizeof(ckFalse)     },
        { CKA_WRAP,     &ckTrue,      sizeof(ckTrue)      },
        { CKA_UNWRAP,   &ckTrue,      sizeof(ckTrue)      },
        { CKA_ENCRYPT,  &ckTrue,      sizeof(ckTrue)      },
        { CKA_DECRYPT,  &ckTrue,      sizeof(ckTrue)      },
        { CKA_VALUE,    aesValue,     sizeof(aesValue)    },
    };
    CK_ATTRIBUTE unwrapTmpl[] = {
        { CKA_CLASS,       &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE,    &genericType, sizeof(genericType) },
        { CKA_PRIVATE,     &ckFalse,     sizeof(ckFalse)     },
        { CKA_SENSITIVE,   &ckFalse,     sizeof(ckFalse)     },
        { CKA_EXTRACTABLE, &ckTrue,      sizeof(ckTrue)      },
        { CKA_VALUE_LEN,   &valueLen,    sizeof(valueLen)    },
    };
    CK_ATTRIBUTE valueAttr = { CKA_VALUE, value, sizeof(value) };

    rv = funcList->C_GetMechanismInfo(slot, CKM_AES_ECB, &info);
    if (rv != CKR_OK || (info.flags & CKF_WRAP) == 0)
        return;
    XMEMSET(secretValue, 0x5c, sizeof(secretValue));
    XMEMSET(aesValue, 0x3a, sizeof(aesValue));
    rv = funcList->C_CreateObject(session, secretTmpl,
        sizeof(secretTmpl) / sizeof(*secretTmpl), &secret);
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(session, aesTmpl,
            sizeof(aesTmpl) / sizeof(*aesTmpl), &aesKey);
    }
    CHECK_RV(rv, "create 20 byte secret and AES wrapping key", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_WrapKey(session, &mech, aesKey, secret, wrapped,
                                 &wrappedLen);
        CHECK_RV(rv, "C_WrapKey(AES-ECB) pads a 20 byte key", CKR_OK);
        CHECK_TRUE(rv != CKR_OK || wrappedLen == 32,
                   "AES-ECB wrapped length is two blocks");
    }
    if (rv == CKR_OK) {
        rv = funcList->C_UnwrapKey(session, &mech, aesKey, wrapped,
                                   wrappedLen, unwrapTmpl,
                                   sizeof(unwrapTmpl) / sizeof(*unwrapTmpl),
                                   &unwrapped);
        CHECK_RV(rv, "C_UnwrapKey(AES-ECB) with CKA_VALUE_LEN", CKR_OK);
    }
    if (rv == CKR_OK) {
        CK_OBJECT_HANDLE noLen = CK_INVALID_HANDLE;

        rv = funcList->C_UnwrapKey(session, &mech, aesKey, wrapped,
                                   wrappedLen, unwrapTmpl,
                                   sizeof(unwrapTmpl) / sizeof(*unwrapTmpl) - 1,
                                   &noLen);
        CHECK_RV(rv, "C_UnwrapKey(AES-ECB) needs CKA_VALUE_LEN",
                 CKR_TEMPLATE_INCOMPLETE);
        rv = CKR_OK;
    }
    if (rv == CKR_OK) {
        rv = funcList->C_GetAttributeValue(session, unwrapped, &valueAttr, 1);
        CHECK_TRUE(rv == CKR_OK && valueAttr.ulValueLen == sizeof(secretValue)
                   && XMEMCMP(value, secretValue, sizeof(secretValue)) == 0,
                   "AES-ECB unwrapped key has its original value");
    }
    if (unwrapped != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, unwrapped);
    if (aesKey != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, aesKey);
    if (secret != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, secret);
}
#endif

#if !defined(NO_RSA) && !defined(NO_AES) && !defined(WOLFPKCS11_NO_STORE)
/* An RSA key AES-ECB wraps must unwrap without CKA_VALUE_LEN. */
static void test_ecb_wrap_rsa_key(CK_SLOT_ID slot, CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_MECHANISM_INFO info;
    CK_MECHANISM mech = { CKM_AES_ECB, NULL, 0 };
    CK_OBJECT_HANDLE rsaPriv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE aesKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE unwrapped = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE rsaType = CKK_RSA;
    CK_KEY_TYPE aesType = CKK_AES;
    CK_BYTE aesValue[16];
    CK_BYTE wrapped[2048];
    CK_ULONG wrappedLen = sizeof(wrapped);
    CK_ATTRIBUTE rsaPrivTmpl[] = {
        { CKA_CLASS,            &privClass,        sizeof(privClass)         },
        { CKA_KEY_TYPE,         &rsaType,          sizeof(rsaType)           },
        { CKA_PRIVATE,          &ckFalse,          sizeof(ckFalse)           },
        { CKA_SENSITIVE,        &ckFalse,          sizeof(ckFalse)           },
        { CKA_EXTRACTABLE,      &ckTrue,           sizeof(ckTrue)            },
        { CKA_MODULUS,          rsa_2048_modulus,  sizeof(rsa_2048_modulus)  },
        { CKA_PRIVATE_EXPONENT, rsa_2048_priv_exp, sizeof(rsa_2048_priv_exp) },
        { CKA_PRIME_1,          rsa_2048_p,        sizeof(rsa_2048_p)        },
        { CKA_PRIME_2,          rsa_2048_q,        sizeof(rsa_2048_q)        },
        { CKA_EXPONENT_1,       rsa_2048_dP,       sizeof(rsa_2048_dP)       },
        { CKA_EXPONENT_2,       rsa_2048_dQ,       sizeof(rsa_2048_dQ)       },
        { CKA_COEFFICIENT,      rsa_2048_u,        sizeof(rsa_2048_u)        },
        { CKA_PUBLIC_EXPONENT,  rsa_2048_pub_exp,  sizeof(rsa_2048_pub_exp)  },
    };
    CK_ATTRIBUTE aesTmpl[] = {
        { CKA_CLASS,    &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE, &aesType,     sizeof(aesType)     },
        { CKA_PRIVATE,  &ckFalse,     sizeof(ckFalse)     },
        { CKA_WRAP,     &ckTrue,      sizeof(ckTrue)      },
        { CKA_UNWRAP,   &ckTrue,      sizeof(ckTrue)      },
        { CKA_ENCRYPT,  &ckTrue,      sizeof(ckTrue)      },
        { CKA_DECRYPT,  &ckTrue,      sizeof(ckTrue)      },
        { CKA_VALUE,    aesValue,     sizeof(aesValue)    },
    };
    CK_ATTRIBUTE unwrapTmpl[] = {
        { CKA_CLASS,    &privClass, sizeof(privClass) },
        { CKA_KEY_TYPE, &rsaType,   sizeof(rsaType)   },
        { CKA_PRIVATE,  &ckFalse,   sizeof(ckFalse)   },
    };

    rv = funcList->C_GetMechanismInfo(slot, CKM_AES_ECB, &info);
    if (rv != CKR_OK || (info.flags & CKF_WRAP) == 0)
        return;
    XMEMSET(aesValue, 0x4b, sizeof(aesValue));
    rv = funcList->C_CreateObject(session, rsaPrivTmpl,
        sizeof(rsaPrivTmpl) / sizeof(*rsaPrivTmpl), &rsaPriv);
    if (rv == CKR_OK) {
        rv = funcList->C_CreateObject(session, aesTmpl,
            sizeof(aesTmpl) / sizeof(*aesTmpl), &aesKey);
    }
    CHECK_RV(rv, "create RSA private key and AES wrapping key", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_WrapKey(session, &mech, aesKey, rsaPriv, wrapped,
                                 &wrappedLen);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_UnwrapKey(session, &mech, aesKey, wrapped,
                                   wrappedLen, unwrapTmpl,
                                   sizeof(unwrapTmpl) / sizeof(*unwrapTmpl),
                                   &unwrapped);
        CHECK_RV(rv, "C_UnwrapKey(AES-ECB) of the RSA key it wrapped", CKR_OK);
    }
    else {
        CHECK_TRUE(rsaPriv != CK_INVALID_HANDLE && aesKey != CK_INVALID_HANDLE,
                   "C_WrapKey(AES-ECB) refuses an unaligned RSA key");
    }
    if (unwrapped != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, unwrapped);
    if (aesKey != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, aesKey);
    if (rsaPriv != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, rsaPriv);
}
#endif

static int run_test(void)
{
    CK_RV rv;
    CK_C_INITIALIZE_ARGS args;
    CK_SLOT_ID slotList[16];
    CK_ULONG slotCount = sizeof(slotList) / sizeof(slotList[0]);
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

    rv = pkcs11_load();
    CHECK_RV(rv, "load library", CKR_OK);
    if (rv != CKR_OK)
        return -1;

    XMEMSET(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    rv = funcList->C_Initialize(&args);
    CHECK_RV(rv, "C_Initialize", CKR_OK);
    if (rv == CKR_OK) {
        rv = funcList->C_GetSlotList(CK_TRUE, slotList, &slotCount);
        CHECK_RV(rv, "C_GetSlotList", CKR_OK);
    }
    if (rv == CKR_OK && slotCount == 0) {
        CHECK_TRUE(0, "at least one slot");
        rv = CKR_TOKEN_NOT_PRESENT;
    }
    if (rv == CKR_OK) {
        test_info_blank_padding(slotList[0]);
        test_token_clock(slotList[0]);
        rv = funcList->C_OpenSession(slotList[0],
                                     CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                     NULL, NULL, &session);
        CHECK_RV(rv, "C_OpenSession", CKR_OK);
    }
    if (rv == CKR_OK) {
        test_generic_secret_size(slotList[0], session);
        test_listed_keygen_supported(slotList[0], session);
#ifdef ALLOC_HOOKS
        test_open_session_alloc_failure(slotList[0]);
#endif
        test_wrap_flags(slotList[0], session);
#ifndef NO_AES
        test_ecb_wrap_short_key(slotList[0], session);
#endif
#if !defined(NO_RSA) && !defined(NO_AES) && !defined(WOLFPKCS11_NO_STORE)
        test_ecb_wrap_rsa_key(slotList[0], session);
#endif
        funcList->C_CloseSession(session);
    }
    funcList->C_Finalize(NULL);

    pkcs11_unload();
    return 0;
}

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

#ifndef WOLFPKCS11_NO_ENV
    XSETENV("WOLFPKCS11_TOKEN_PATH", TEST_DIR, 1);
#endif

    printf("=== wolfPKCS11 info and mechanism table test ===\n");
#ifdef ALLOC_HOOKS
    if (wolfSSL_SetAllocators(hook_malloc, hook_free, hook_realloc) != 0) {
        CHECK_TRUE(0, "install allocation hooks");
        return pkcs11_test_summary();
    }
#endif
    run_test();
    return pkcs11_test_summary();
}

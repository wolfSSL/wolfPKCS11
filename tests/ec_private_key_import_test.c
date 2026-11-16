/* ec_private_key_import_test.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
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
 * Test importing EC private keys the way NSS does it, for PKCS #12 import and
 * PK11_ImportDERPrivateKeyInfo:
 *  - CKA_EC_POINT on the private key is the raw X9.63 point, not DER, or is
 *    empty when the PKCS #8 has no public value.
 *  - Encrypted PKCS #8 keys are imported with C_UnwrapKey, and exported with
 *    C_WrapKey, using an AES mechanism.
 */

#ifdef HAVE_CONFIG_H
    #include <wolfpkcs11/config.h>
#endif

#include <stdio.h>

#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/misc.h>

#ifndef WOLFPKCS11_USER_SETTINGS
    #include <wolfpkcs11/options.h>
#endif
#include <wolfpkcs11/pkcs11.h>

#ifndef HAVE_PKCS11_STATIC
#include <dlfcn.h>
#endif

#include "testdata.h"

#ifdef HAVE_ECC

#if !defined(NO_AES) && !defined(NO_AES_CBC) && defined(HAVE_PKCS8) && \
    defined(HAVE_ECC_KEY_EXPORT)
    #define TEST_EC_WRAP
#endif

/* TPMs don't all take P-521 or brainpool keys. */
#if (defined(HAVE_ECC521) || defined(HAVE_ALL_CURVES)) && \
    !defined(WOLFPKCS11_TPM)
    #define TEST_EC_P521
#endif
#if defined(HAVE_ECC_BRAINPOOL) && !defined(NO_ECC256) && \
    !defined(HAVE_FIPS) && !defined(WOLFPKCS11_TPM)
    #define TEST_EC_BRAINPOOL
#endif
#if defined(TEST_EC_P521) || defined(TEST_EC_BRAINPOOL)
    #define TEST_EC_CURVES
#endif

#define TEST_DIR "./store/ec_private_key_import_test"

static int test_passed = 0;
static int test_failed = 0;

#define CHECK_CKR(rv, op, expected) do {                    \
    if ((rv) != (expected)) {                               \
        fprintf(stderr, "FAIL: %s: expected 0x%lx, got 0x%lx\n", op, \
            (unsigned long)(expected), (unsigned long)(rv)); \
        test_failed++;                                      \
        result = -1;                                        \
        goto cleanup;                                       \
    } else {                                                \
        printf("PASS: %s\n", op);                           \
        test_passed++;                                      \
    }                                                       \
} while(0)

#define CHECK_COND(cond, op) do {                           \
    if (!(cond)) {                                          \
        fprintf(stderr, "FAIL: %s\n", op);                  \
        test_failed++;                                      \
        result = -1;                                        \
        goto cleanup;                                       \
    } else {                                                \
        printf("PASS: %s\n", op);                           \
        test_passed++;                                      \
    }                                                       \
} while(0)

#ifndef HAVE_PKCS11_STATIC
static void* dlib;
#endif
static CK_FUNCTION_LIST* funcList;
static CK_SLOT_ID slot = 0;
static byte* soPin = (byte*)"password123456";
static int soPinLen = 14;
static byte* userPin = (byte*)"wolfpkcs11-test";
static int userPinLen = 15;

static CK_OBJECT_CLASS privKeyClass = CKO_PRIVATE_KEY;
static CK_OBJECT_CLASS pubKeyClass = CKO_PUBLIC_KEY;
static CK_KEY_TYPE ecKeyType = CKK_EC;
static CK_BBOOL ckTrue = CK_TRUE;
static CK_BBOOL ckFalse = CK_FALSE;

static unsigned char hash[32] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
};

/* An EC test key: the curve, private scalar and raw X9.63 public point. */
typedef struct EcTestKey {
    const char* name;
    unsigned char* params;
    CK_ULONG paramsLen;
    unsigned char* priv;
    CK_ULONG privLen;
    unsigned char* point;
    CK_ULONG pointLen;
} EcTestKey;

static const EcTestKey p256Key = {
    "P-256",
    ecc_p256_params, sizeof(ecc_p256_params),
    ecc_p256_priv, sizeof(ecc_p256_priv),
    ecc_p256_point, sizeof(ecc_p256_point)
};

#ifdef TEST_EC_P521
/* The point is 133 bytes, so its DER encoding has a long-form length. */
static unsigned char p521_params[] = {
    0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23
};
static unsigned char p521_priv[] = {
    0x01, 0xA6, 0x91, 0xA8, 0x28, 0x0C, 0x88, 0xE7,
    0xAC, 0x56, 0x2B, 0xDF, 0x14, 0xE8, 0x96, 0x61,
    0x98, 0xEF, 0xE8, 0x83, 0x8B, 0xBC, 0xDA, 0x7C,
    0x13, 0x51, 0xE7, 0xE3, 0x27, 0x7B, 0xD4, 0xBC,
    0x21, 0xA1, 0xD4, 0x2A, 0x5D, 0x45, 0x9A, 0xC0,
    0xC2, 0x47, 0xFD, 0xB9, 0x2A, 0x82, 0xDE, 0x7D,
    0x0B, 0xB5, 0x93, 0x3B, 0x8F, 0x32, 0xEE, 0xB6,
    0x38, 0x8D, 0x4B, 0x31, 0x63, 0xF0, 0xAD, 0xDF,
    0x89, 0x4D
};
static unsigned char p521_point[] = {
    0x04, 0x01, 0xFD, 0x96, 0xF8, 0x3E, 0x02, 0x1B,
    0x98, 0x22, 0xFF, 0x76, 0xB8, 0x07, 0x09, 0xB8,
    0xA0, 0xC2, 0xDA, 0x3F, 0x52, 0x92, 0xCD, 0xF6,
    0x47, 0x2F, 0x43, 0xF1, 0x20, 0x6A, 0x93, 0x10,
    0xF8, 0xE8, 0xF7, 0x03, 0x31, 0x27, 0x4F, 0xCC,
    0xDB, 0x1F, 0x74, 0xF1, 0x5F, 0x1A, 0x54, 0xC2,
    0xC8, 0x5B, 0x0B, 0x48, 0xDB, 0x86, 0x06, 0xF5,
    0x2C, 0xAC, 0x46, 0x71, 0xB8, 0x22, 0x62, 0xAA,
    0x20, 0xCB, 0x09, 0x01, 0x98, 0x1F, 0x85, 0x8D,
    0x29, 0x38, 0x31, 0x09, 0x81, 0x80, 0x06, 0x0D,
    0x1A, 0x74, 0x71, 0xB6, 0xC1, 0xBE, 0x1B, 0x1B,
    0xD4, 0xB7, 0x0D, 0xD2, 0x62, 0xDB, 0xC8, 0x24,
    0x95, 0x83, 0x70, 0xC2, 0xD9, 0xA5, 0x9F, 0x8E,
    0xCC, 0x5A, 0xD4, 0x2D, 0xEC, 0x43, 0x0F, 0x7C,
    0xB0, 0xE6, 0xA5, 0x0A, 0x4A, 0xB4, 0xBB, 0x06,
    0xAB, 0x34, 0xD2, 0xCD, 0x0A, 0x03, 0x47, 0x05,
    0x15, 0x1F, 0x6B, 0x7A, 0xDA
};

static const EcTestKey p521Key = {
    "P-521",
    p521_params, sizeof(p521_params),
    p521_priv, sizeof(p521_priv),
    p521_point, sizeof(p521_point)
};
#endif /* TEST_EC_P521 */

#ifdef TEST_EC_BRAINPOOL
/* A 32-byte curve other than P-256, which a decoder that picks the curve by
 * key size gets wrong. */
static unsigned char bp256_params[] = {
    0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07
};
static unsigned char bp256_priv[] = {
    0x0A, 0x2C, 0xD9, 0x51, 0xCC, 0xC4, 0x82, 0xB2,
    0x62, 0x50, 0x04, 0xBE, 0x88, 0xE3, 0x82, 0xBE,
    0x0C, 0xE8, 0x85, 0xAC, 0x83, 0xC0, 0xD4, 0x89,
    0x6A, 0xA5, 0xA1, 0xEA, 0xB8, 0x3A, 0xAD, 0x19
};
static unsigned char bp256_point[] = {
    0x04, 0x07, 0x4A, 0xD9, 0xF8, 0xD9, 0xB2, 0x34,
    0x92, 0xE6, 0xBB, 0x34, 0x47, 0x93, 0x23, 0x33,
    0x04, 0xE8, 0x99, 0x4C, 0xA4, 0x5E, 0x63, 0xC7,
    0x28, 0xE8, 0x07, 0x20, 0x31, 0xDD, 0xA5, 0x34,
    0xA1, 0x3C, 0x89, 0xFF, 0x44, 0x89, 0xEC, 0x80,
    0x6A, 0x01, 0x88, 0x94, 0xD6, 0x83, 0xB1, 0xB2,
    0xCE, 0x76, 0x2A, 0x43, 0x08, 0xBB, 0xC3, 0xDE,
    0x4B, 0xCF, 0x38, 0x81, 0xB3, 0xE3, 0x8D, 0xB2,
    0x34
};

static const EcTestKey bp256Key = {
    "brainpoolP256r1",
    bp256_params, sizeof(bp256_params),
    bp256_priv, sizeof(bp256_priv),
    bp256_point, sizeof(bp256_point)
};
#endif /* TEST_EC_BRAINPOOL */

#ifdef TEST_EC_WRAP
static CK_OBJECT_CLASS secretKeyClass = CKO_SECRET_KEY;
static CK_KEY_TYPE aesKeyType = CKK_AES;

/* P-384 curve OID, for a template that names the wrong curve. */
static unsigned char ecc_p384_params[] = {
    0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22
};
/* id-ecPublicKey, the PKCS #8 algorithm of an EC key. */
static const unsigned char ec_public_key_oid[] = {
    0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01
};
/* The order n of P-256, a scalar out of range. */
static unsigned char p256_order[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
    0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
};

static unsigned char wrapKeyValue[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};
static unsigned char iv[16] = {
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf
};
#endif

static CK_RV pkcs11_init(void)
{
    CK_RV ret;
    CK_C_INITIALIZE_ARGS args;
    CK_SLOT_ID slotList[16];
    CK_ULONG slotCount = sizeof(slotList) / sizeof(slotList[0]);
#ifndef HAVE_PKCS11_STATIC
    CK_C_GetFunctionList func;

    dlib = dlopen(WOLFPKCS11_DLL_FILENAME, RTLD_NOW | RTLD_LOCAL);
    if (dlib == NULL) {
        fprintf(stderr, "dlopen error: %s\n", dlerror());
        return CKR_GENERAL_ERROR;
    }
    func = (CK_C_GetFunctionList)dlsym(dlib, "C_GetFunctionList");
    if (func == NULL) {
        fprintf(stderr, "Failed to get function list function\n");
        return CKR_GENERAL_ERROR;
    }
    ret = func(&funcList);
#else
    ret = C_GetFunctionList(&funcList);
#endif
    if (ret != CKR_OK)
        return ret;

    XMEMSET(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    ret = funcList->C_Initialize(&args);
    if (ret != CKR_OK)
        return ret;

    ret = funcList->C_GetSlotList(CK_TRUE, slotList, &slotCount);
    if (ret != CKR_OK)
        return ret;
    if (slotCount == 0)
        return CKR_GENERAL_ERROR;
    slot = slotList[0];
    return CKR_OK;
}

static void pkcs11_final(void)
{
    if (funcList != NULL) {
        funcList->C_Finalize(NULL);
        funcList = NULL;
    }
#ifndef HAVE_PKCS11_STATIC
    if (dlib != NULL) {
        dlclose(dlib);
        dlib = NULL;
    }
#endif
}

static CK_RV open_session(CK_SESSION_HANDLE* session)
{
    CK_RV ret;
    unsigned char label[32];

    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, "ec import test", 14);
    ret = funcList->C_InitToken(slot, soPin, soPinLen, label);
    if (ret != CKR_OK)
        return ret;
    ret = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
        NULL, NULL, session);
    if (ret != CKR_OK)
        return ret;
    ret = funcList->C_Login(*session, CKU_SO, soPin, soPinLen);
    if (ret == CKR_OK)
        ret = funcList->C_InitPIN(*session, userPin, userPinLen);
    if (ret == CKR_OK)
        ret = funcList->C_Logout(*session);
    if (ret == CKR_OK)
        ret = funcList->C_Login(*session, CKU_USER, userPin, userPinLen);
    return ret;
}

/* Create a private key; point may be NULL with pointLen 0. */
static CK_RV create_ec_priv(CK_SESSION_HANDLE session, const EcTestKey* k,
    unsigned char* point, CK_ULONG pointLen, CK_OBJECT_HANDLE* key)
{
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &privKeyClass, sizeof(privKeyClass) },
        { CKA_KEY_TYPE,    &ecKeyType,    sizeof(ecKeyType)    },
        { CKA_TOKEN,       &ckFalse,      sizeof(ckFalse)      },
        { CKA_SIGN,        &ckTrue,       sizeof(ckTrue)       },
        { CKA_EXTRACTABLE, &ckTrue,       sizeof(ckTrue)       },
        { CKA_EC_PARAMS,   k->params,     k->paramsLen         },
        { CKA_VALUE,       k->priv,       k->privLen           },
        { CKA_EC_POINT,    point,         pointLen             },
    };
    return funcList->C_CreateObject(session, tmpl,
        sizeof(tmpl) / sizeof(tmpl[0]), key);
}

static CK_RV create_ec_pub(CK_SESSION_HANDLE session, const EcTestKey* k,
    unsigned char* point, CK_ULONG pointLen, CK_OBJECT_HANDLE* key)
{
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,     &pubKeyClass, sizeof(pubKeyClass) },
        { CKA_KEY_TYPE,  &ecKeyType,   sizeof(ecKeyType)   },
        { CKA_TOKEN,     &ckFalse,     sizeof(ckFalse)     },
        { CKA_VERIFY,    &ckTrue,      sizeof(ckTrue)      },
        { CKA_EC_PARAMS, k->params,    k->paramsLen        },
        { CKA_EC_POINT,  point,        pointLen            },
    };
    return funcList->C_CreateObject(session, tmpl,
        sizeof(tmpl) / sizeof(tmpl[0]), key);
}

/* DER encode the key's point as an OCTET STRING into out, 140 bytes. */
static CK_ULONG der_point(const EcTestKey* k, unsigned char* out)
{
    CK_ULONG i = 0;

    out[i++] = 0x04;
    if (k->pointLen >= 0x80)
        out[i++] = 0x81;
    out[i++] = (unsigned char)k->pointLen;
    XMEMCPY(out + i, k->point, k->pointLen);
    return i + k->pointLen;
}

/* Destroy the object, if any. A session holds only a few objects. */
static void destroy_obj(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE* obj)
{
    if (*obj != CK_INVALID_HANDLE) {
        funcList->C_DestroyObject(session, *obj);
        *obj = CK_INVALID_HANDLE;
    }
}

/* Sign the hash with priv and verify it with pub. */
static CK_RV sign_verify(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE priv,
    CK_OBJECT_HANDLE pub)
{
    CK_RV ret;
    CK_MECHANISM mech = { CKM_ECDSA, NULL, 0 };
    unsigned char sig[140];
    CK_ULONG sigLen = sizeof(sig);

    ret = funcList->C_SignInit(session, &mech, priv);
    if (ret == CKR_OK)
        ret = funcList->C_Sign(session, hash, sizeof(hash), sig, &sigLen);
    if (ret == CKR_OK)
        ret = funcList->C_VerifyInit(session, &mech, pub);
    if (ret == CKR_OK)
        ret = funcList->C_Verify(session, hash, sizeof(hash), sig, sigLen);
    return ret;
}

/* NSS copies the private key's CKA_EC_POINT into an exported PKCS #8 as the
 * raw point, so NSS builds return that form; others return DER. */
static int check_priv_point(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE priv,
    const EcTestKey* k)
{
    int result = 0;
    CK_RV rv;
    unsigned char point[140];
    unsigned char want[140];
    CK_ULONG wantLen;
    char op[128];
    CK_ATTRIBUTE getPoint[] = {
        { CKA_EC_POINT, point, sizeof(point) },
    };

#ifdef WOLFPKCS11_NSS
    XMEMCPY(want, k->point, k->pointLen);
    wantLen = k->pointLen;
#else
    wantLen = der_point(k, want);
#endif

    snprintf(op, sizeof(op), "%s: read CKA_EC_POINT of the private key",
        k->name);
    rv = funcList->C_GetAttributeValue(session, priv, getPoint, 1);
    CHECK_CKR(rv, op, CKR_OK);
    snprintf(op, sizeof(op), "%s: private key CKA_EC_POINT has the build's "
        "form", k->name);
    CHECK_COND(getPoint[0].ulValueLen == wantLen &&
        XMEMCMP(point, want, wantLen) == 0, op);

cleanup:
    return result;
}

#ifdef TEST_EC_WRAP
static int contains(const unsigned char* buf, CK_ULONG bufLen,
    const unsigned char* sub, CK_ULONG subLen)
{
    CK_ULONG i;

    for (i = 0; i + subLen <= bufLen; i++) {
        if (XMEMCMP(buf + i, sub, subLen) == 0)
            return 1;
    }
    return 0;
}

static CK_RV create_wrap_key(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE* key)
{
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,    &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE, &aesKeyType,     sizeof(aesKeyType)     },
        { CKA_TOKEN,    &ckFalse,        sizeof(ckFalse)        },
        { CKA_WRAP,     &ckTrue,         sizeof(ckTrue)         },
        { CKA_UNWRAP,   &ckTrue,         sizeof(ckTrue)         },
        { CKA_ENCRYPT,  &ckTrue,         sizeof(ckTrue)         },
        { CKA_DECRYPT,  &ckTrue,         sizeof(ckTrue)         },
        { CKA_VALUE,    wrapKeyValue,    sizeof(wrapKeyValue)   },
    };
    return funcList->C_CreateObject(session, tmpl,
        sizeof(tmpl) / sizeof(tmpl[0]), key);
}

/* Wrap priv, check the plaintext is a PKCS #8 of the test key, unwrap it
 * without naming the curve and check the new key has the curve and signs. */
static int wrap_unwrap_roundtrip(CK_SESSION_HANDLE session,
    CK_OBJECT_HANDLE wrapKey, const EcTestKey* k, CK_OBJECT_HANDLE priv,
    CK_OBJECT_HANDLE pub, const char* name)
{
    int result = 0;
    CK_RV rv;
    CK_MECHANISM mech = { CKM_AES_CBC_PAD, iv, sizeof(iv) };
    CK_OBJECT_HANDLE unwrapped = CK_INVALID_HANDLE;
    unsigned char wrapped[512];
    unsigned char plain[512];
    unsigned char params[16];
    CK_ULONG wrappedLen = 0;
    CK_ULONG plainLen = sizeof(plain);
    char op[128];
    CK_ATTRIBUTE unwrapTmpl[] = {
        { CKA_CLASS,    &privKeyClass, sizeof(privKeyClass) },
        { CKA_KEY_TYPE, &ecKeyType,    sizeof(ecKeyType)    },
        { CKA_TOKEN,    &ckFalse,      sizeof(ckFalse)      },
        { CKA_SIGN,     &ckTrue,       sizeof(ckTrue)       },
    };
    CK_ATTRIBUTE getParams[] = {
        { CKA_EC_PARAMS, params, sizeof(params) },
    };

    snprintf(op, sizeof(op), "%s: C_WrapKey length query", name);
    rv = funcList->C_WrapKey(session, &mech, wrapKey, priv, NULL,
        &wrappedLen);
    CHECK_CKR(rv, op, CKR_OK);
    snprintf(op, sizeof(op), "%s: wrapped length fits", name);
    CHECK_COND(wrappedLen > 0 && wrappedLen <= sizeof(wrapped), op);
    snprintf(op, sizeof(op), "%s: C_WrapKey", name);
    rv = funcList->C_WrapKey(session, &mech, wrapKey, priv, wrapped,
        &wrappedLen);
    CHECK_CKR(rv, op, CKR_OK);

    /* NSS decrypts the blob into a PrivateKeyInfo, so check that form. */
    snprintf(op, sizeof(op), "%s: decrypt the wrapped key", name);
    rv = funcList->C_DecryptInit(session, &mech, wrapKey);
    if (rv == CKR_OK) {
        rv = funcList->C_Decrypt(session, wrapped, wrappedLen, plain,
            &plainLen);
    }
    CHECK_CKR(rv, op, CKR_OK);
    snprintf(op, sizeof(op), "%s: wrapped key is a PKCS #8 of the EC key",
        name);
    CHECK_COND(plainLen > 2 && plain[0] == 0x30 &&
        contains(plain, plainLen, ec_public_key_oid,
                 sizeof(ec_public_key_oid)) &&
        contains(plain, plainLen, k->params, k->paramsLen) &&
        contains(plain, plainLen, k->priv, k->privLen), op);

    snprintf(op, sizeof(op), "%s: C_UnwrapKey", name);
    rv = funcList->C_UnwrapKey(session, &mech, wrapKey, wrapped, wrappedLen,
        unwrapTmpl, sizeof(unwrapTmpl) / sizeof(unwrapTmpl[0]), &unwrapped);
    CHECK_CKR(rv, op, CKR_OK);
    snprintf(op, sizeof(op), "%s: unwrapped key has the %s CKA_EC_PARAMS",
        name, k->name);
    rv = funcList->C_GetAttributeValue(session, unwrapped, getParams, 1);
    CHECK_COND(rv == CKR_OK && getParams[0].ulValueLen == k->paramsLen &&
        XMEMCMP(params, k->params, k->paramsLen) == 0, op);
    snprintf(op, sizeof(op), "%s: unwrapped key signs", name);
    rv = sign_verify(session, unwrapped, pub);
    CHECK_CKR(rv, op, CKR_OK);

cleanup:
    destroy_obj(session, &unwrapped);
    return result;
}

/* Offset of the ECPrivateKey in a PKCS #8 from build_p256_pkcs8(). */
#define P256_PKCS8_KEY_OFF    29

/* Build a PKCS #8 PrivateKeyInfo of a P-256 key into out, 160 bytes. The
 * ECPrivateKey has keyParams as its parameters, or none when NULL. */
static CK_ULONG build_p256_pkcs8(unsigned char* out, const unsigned char* priv,
    const unsigned char* point, const unsigned char* keyParams,
    CK_ULONG keyParamsLen)
{
    static const unsigned char algId[] = {
        0x30, 0x13,
        0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
        0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
    };
    /* Version, scalar and public key: the ECPrivateKey contents. */
    CK_ULONG keyLen = 3 + 2 + 32 + 5 + 65;
    CK_ULONG i = 0;

    if (keyParams != NULL)
        keyLen += 2 + keyParamsLen;

    out[i++] = 0x30;
    out[i++] = 0x81;
    out[i++] = (unsigned char)(3 + sizeof(algId) + 2 + 2 + keyLen);
    out[i++] = 0x02; out[i++] = 0x01; out[i++] = 0x00;
    XMEMCPY(out + i, algId, sizeof(algId));
    i += sizeof(algId);
    out[i++] = 0x04;
    out[i++] = (unsigned char)(2 + keyLen);
    out[i++] = 0x30;
    out[i++] = (unsigned char)keyLen;
    out[i++] = 0x02; out[i++] = 0x01; out[i++] = 0x01;
    out[i++] = 0x04; out[i++] = 0x20;
    XMEMCPY(out + i, priv, 32);
    i += 32;
    if (keyParams != NULL) {
        out[i++] = 0xA0;
        out[i++] = (unsigned char)keyParamsLen;
        XMEMCPY(out + i, keyParams, keyParamsLen);
        i += keyParamsLen;
    }
    out[i++] = 0xA1; out[i++] = 0x44;
    out[i++] = 0x03; out[i++] = 0x42; out[i++] = 0x00;
    XMEMCPY(out + i, point, 65);
    i += 65;
    return i;
}

/* Encrypt plain with the wrapping key and unwrap it with tmpl. */
static CK_RV unwrap_plain(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE wrapKey,
    unsigned char* plain, CK_ULONG plainLen, CK_ATTRIBUTE* tmpl,
    CK_ULONG tmplCnt, CK_OBJECT_HANDLE* key)
{
    CK_RV rv;
    CK_MECHANISM mech = { CKM_AES_CBC_PAD, iv, sizeof(iv) };
    unsigned char wrapped[512];
    CK_ULONG wrappedLen = sizeof(wrapped);

    *key = CK_INVALID_HANDLE;
    rv = funcList->C_EncryptInit(session, &mech, wrapKey);
    if (rv == CKR_OK) {
        rv = funcList->C_Encrypt(session, plain, plainLen, wrapped,
            &wrappedLen);
    }
    if (rv == CKR_OK) {
        rv = funcList->C_UnwrapKey(session, &mech, wrapKey, wrapped,
            wrappedLen, tmpl, tmplCnt, key);
    }
    return rv;
}

/* Unwrap hand-built P-256 keys, each with one fault, and check they get the
 * checks C_CreateObject makes. */
static int bad_pkcs8_test(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE wrapKey)
{
    int result = 0;
    CK_RV rv;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    unsigned char plain[160];
    unsigned char zero[32];
    unsigned char badPoint[sizeof(ecc_p256_point)];
    CK_ULONG plainLen;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,     &privKeyClass,   sizeof(privKeyClass)    },
        { CKA_KEY_TYPE,  &ecKeyType,      sizeof(ecKeyType)       },
        { CKA_TOKEN,     &ckFalse,        sizeof(ckFalse)         },
        { CKA_EC_PARAMS, ecc_p256_params, sizeof(ecc_p256_params) },
    };
    /* The template without CKA_EC_PARAMS. */
    CK_ULONG noCurveCnt = sizeof(tmpl) / sizeof(tmpl[0]) - 1;
    CK_ULONG curveCnt = sizeof(tmpl) / sizeof(tmpl[0]);

    /* The encoding is good, so each case below fails on its own fault. */
    plainLen = build_p256_pkcs8(plain, ecc_p256_priv, ecc_p256_point, NULL,
        0);
    rv = unwrap_plain(session, wrapKey, plain, plainLen, tmpl, noCurveCnt,
        &key);
    CHECK_CKR(rv, "Unwrap a hand-built PKCS #8", CKR_OK);
    destroy_obj(session, &key);

    /* A bare ECPrivateKey without parameters needs the template's curve. */
    rv = unwrap_plain(session, wrapKey, plain + P256_PKCS8_KEY_OFF,
        plainLen - P256_PKCS8_KEY_OFF, tmpl, noCurveCnt, &key);
    CHECK_CKR(rv, "Unwrap an ECPrivateKey that names no curve",
        CKR_WRAPPED_KEY_INVALID);
    rv = unwrap_plain(session, wrapKey, plain + P256_PKCS8_KEY_OFF,
        plainLen - P256_PKCS8_KEY_OFF, tmpl, curveCnt, &key);
    CHECK_CKR(rv, "Unwrap an ECPrivateKey with the template's curve",
        CKR_OK);
    destroy_obj(session, &key);

    XMEMSET(zero, 0, sizeof(zero));
    plainLen = build_p256_pkcs8(plain, zero, ecc_p256_point, NULL, 0);
    rv = unwrap_plain(session, wrapKey, plain, plainLen, tmpl, noCurveCnt,
        &key);
    CHECK_CKR(rv, "Unwrap a zero scalar", CKR_WRAPPED_KEY_INVALID);

    plainLen = build_p256_pkcs8(plain, p256_order, ecc_p256_point, NULL, 0);
    rv = unwrap_plain(session, wrapKey, plain, plainLen, tmpl, noCurveCnt,
        &key);
    CHECK_CKR(rv, "Unwrap a scalar equal to the order",
        CKR_WRAPPED_KEY_INVALID);

    XMEMCPY(badPoint, ecc_p256_point, sizeof(badPoint));
    badPoint[sizeof(badPoint) - 1] ^= 0x01;
    plainLen = build_p256_pkcs8(plain, ecc_p256_priv, badPoint, NULL, 0);
    rv = unwrap_plain(session, wrapKey, plain, plainLen, tmpl, noCurveCnt,
        &key);
    CHECK_CKR(rv, "Unwrap a point off the curve", CKR_WRAPPED_KEY_INVALID);

    /* The ECPrivateKey names P-384 and the AlgorithmIdentifier P-256. */
    plainLen = build_p256_pkcs8(plain, ecc_p256_priv, ecc_p256_point,
        ecc_p384_params, sizeof(ecc_p384_params));
    rv = unwrap_plain(session, wrapKey, plain, plainLen, tmpl, noCurveCnt,
        &key);
    CHECK_CKR(rv, "Unwrap a key that names two curves",
        CKR_WRAPPED_KEY_INVALID);

cleanup:
    destroy_obj(session, &key);
    return result;
}
#endif /* TEST_EC_WRAP */

#ifdef TEST_EC_CURVES
/* Import a key with a DER and a raw point, check the point read back, then
 * wrap and unwrap it when wrapping is built. */
static int curve_test(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE wrapKey,
    const EcTestKey* k)
{
    int result = 0;
    CK_RV rv;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE privDer = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE privRaw = CK_INVALID_HANDLE;
    unsigned char der[140];
    CK_ULONG derLen;
    char op[128];

    derLen = der_point(k, der);
    snprintf(op, sizeof(op), "%s: create public key with a DER CKA_EC_POINT",
        k->name);
    rv = create_ec_pub(session, k, der, derLen, &pub);
    CHECK_CKR(rv, op, CKR_OK);

    snprintf(op, sizeof(op), "%s: create private key with a DER "
        "CKA_EC_POINT", k->name);
    rv = create_ec_priv(session, k, der, derLen, &privDer);
    CHECK_CKR(rv, op, CKR_OK);
    snprintf(op, sizeof(op), "%s: private key with a DER point signs",
        k->name);
    rv = sign_verify(session, privDer, pub);
    CHECK_CKR(rv, op, CKR_OK);

    snprintf(op, sizeof(op), "%s: create private key with a raw "
        "CKA_EC_POINT", k->name);
    rv = create_ec_priv(session, k, k->point, k->pointLen, &privRaw);
    CHECK_CKR(rv, op, CKR_OK);
    snprintf(op, sizeof(op), "%s: private key with a raw point signs",
        k->name);
    rv = sign_verify(session, privRaw, pub);
    CHECK_CKR(rv, op, CKR_OK);
    if (check_priv_point(session, privDer, k) != 0) {
        result = -1;
        goto cleanup;
    }

#ifdef TEST_EC_WRAP
    if (wrap_unwrap_roundtrip(session, wrapKey, k, privDer, pub,
            k->name) != 0) {
        result = -1;
        goto cleanup;
    }
#else
    (void)wrapKey;
#endif

cleanup:
    destroy_obj(session, &privRaw);
    destroy_obj(session, &privDer);
    destroy_obj(session, &pub);
    return result;
}
#endif /* TEST_EC_CURVES */

static int ec_private_key_import_test(void)
{
    int result = 0;
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE privRaw = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE privDer = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE privNoPoint = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    unsigned char badPoint[sizeof(ecc_p256_point)];
    unsigned char der[140];
    CK_ULONG derLen;
#if defined(TEST_EC_WRAP) || defined(TEST_EC_CURVES)
    CK_OBJECT_HANDLE wrapKey = CK_INVALID_HANDLE;
#endif
#ifdef TEST_EC_WRAP
    CK_MECHANISM mech = { CKM_AES_CBC_PAD, iv, sizeof(iv) };
    unsigned char wrapped[256];
    unsigned char junk[48];
    CK_ULONG wrappedLen;
    CK_ATTRIBUTE wrongCurveTmpl[] = {
        { CKA_CLASS,     &privKeyClass,   sizeof(privKeyClass)    },
        { CKA_KEY_TYPE,  &ecKeyType,      sizeof(ecKeyType)       },
        { CKA_TOKEN,     &ckFalse,        sizeof(ckFalse)         },
        { CKA_EC_PARAMS, ecc_p384_params, sizeof(ecc_p384_params) },
    };
    CK_ATTRIBUTE unwrapTmpl[] = {
        { CKA_CLASS,    &privKeyClass, sizeof(privKeyClass) },
        { CKA_KEY_TYPE, &ecKeyType,    sizeof(ecKeyType)    },
        { CKA_TOKEN,    &ckFalse,      sizeof(ckFalse)      },
    };
#endif

    rv = pkcs11_init();
    CHECK_CKR(rv, "Initialize", CKR_OK);
    rv = open_session(&session);
    CHECK_CKR(rv, "Token, PIN and user login", CKR_OK);
    derLen = der_point(&p256Key, der);
    CHECK_COND(derLen == sizeof(ecc_p256_pub) &&
        XMEMCMP(der, ecc_p256_pub, derLen) == 0, "DER encode the P-256 point");
    rv = create_ec_pub(session, &p256Key, der, derLen, &pub);
    CHECK_CKR(rv, "Create public key with a DER CKA_EC_POINT", CKR_OK);

    /* NSS sets the raw point on the private key (pk11pk12.c). */
    rv = create_ec_priv(session, &p256Key, ecc_p256_point,
        sizeof(ecc_p256_point), &privRaw);
    CHECK_CKR(rv, "Create private key with a raw CKA_EC_POINT", CKR_OK);
    rv = sign_verify(session, privRaw, pub);
    CHECK_CKR(rv, "Private key with a raw point signs", CKR_OK);
    if (check_priv_point(session, privRaw, &p256Key) != 0) {
        result = -1;
        goto cleanup;
    }

    rv = create_ec_priv(session, &p256Key, der, derLen, &privDer);
    CHECK_CKR(rv, "Create private key with a DER CKA_EC_POINT", CKR_OK);
    rv = sign_verify(session, privDer, pub);
    CHECK_CKR(rv, "Private key with a DER point signs", CKR_OK);

    /* NSS sends an empty point when the PKCS #8 has no public value. */
    rv = create_ec_priv(session, &p256Key, NULL, 0, &privNoPoint);
    CHECK_CKR(rv, "Create private key with an empty CKA_EC_POINT", CKR_OK);
    rv = sign_verify(session, privNoPoint, pub);
    CHECK_CKR(rv, "Private key without a point signs", CKR_OK);

    /* A raw point must still be on the curve. */
    XMEMCPY(badPoint, ecc_p256_point, sizeof(badPoint));
    badPoint[sizeof(badPoint) - 1] ^= 0x01;
    rv = create_ec_priv(session, &p256Key, badPoint, sizeof(badPoint), &key);
    CHECK_CKR(rv, "Raw CKA_EC_POINT off the curve is rejected",
        CKR_ATTRIBUTE_VALUE_INVALID);

    /* Public keys still take only the DER form PKCS #11 defines. */
    rv = create_ec_pub(session, &p256Key, ecc_p256_point,
        sizeof(ecc_p256_point), &key);
    CHECK_CKR(rv, "Public key with a raw CKA_EC_POINT is rejected",
        CKR_ATTRIBUTE_VALUE_INVALID);

#ifdef TEST_EC_WRAP
    rv = create_wrap_key(session, &wrapKey);
    CHECK_CKR(rv, "Create AES wrapping key", CKR_OK);

    if (wrap_unwrap_roundtrip(session, wrapKey, &p256Key, privRaw, pub,
            "with public point") != 0) {
        result = -1;
        goto cleanup;
    }
    if (wrap_unwrap_roundtrip(session, wrapKey, &p256Key, privNoPoint, pub,
            "without public point") != 0) {
        result = -1;
        goto cleanup;
    }

    /* The template's curve must match the wrapped key's. */
    wrappedLen = sizeof(wrapped);
    rv = funcList->C_WrapKey(session, &mech, wrapKey, privRaw, wrapped,
        &wrappedLen);
    CHECK_CKR(rv, "C_WrapKey for the curve check", CKR_OK);
    rv = funcList->C_UnwrapKey(session, &mech, wrapKey, wrapped, wrappedLen,
        wrongCurveTmpl, sizeof(wrongCurveTmpl) / sizeof(wrongCurveTmpl[0]),
        &key);
    CHECK_CKR(rv, "Unwrap with another curve in the template",
        CKR_TEMPLATE_INCONSISTENT);

    /* Data that isn't an EC key is rejected. */
    XMEMSET(junk, 0x5a, sizeof(junk));
    wrappedLen = sizeof(wrapped);
    rv = funcList->C_EncryptInit(session, &mech, wrapKey);
    if (rv == CKR_OK) {
        rv = funcList->C_Encrypt(session, junk, sizeof(junk), wrapped,
            &wrappedLen);
    }
    CHECK_CKR(rv, "Encrypt data that isn't a key", CKR_OK);
    rv = funcList->C_UnwrapKey(session, &mech, wrapKey, wrapped, wrappedLen,
        unwrapTmpl, sizeof(unwrapTmpl) / sizeof(unwrapTmpl[0]), &key);
    CHECK_CKR(rv, "Unwrap data that isn't an EC key",
        CKR_WRAPPED_KEY_INVALID);

    if (bad_pkcs8_test(session, wrapKey) != 0) {
        result = -1;
        goto cleanup;
    }
#endif

    /* Make room in the session for the other curves' keys. */
    destroy_obj(session, &privNoPoint);
    destroy_obj(session, &privDer);
    destroy_obj(session, &privRaw);
    destroy_obj(session, &pub);

#ifdef TEST_EC_P521
    if (curve_test(session, wrapKey, &p521Key) != 0) {
        result = -1;
        goto cleanup;
    }
#endif
#ifdef TEST_EC_BRAINPOOL
    if (curve_test(session, wrapKey, &bp256Key) != 0) {
        result = -1;
        goto cleanup;
    }
#endif

cleanup:
    if (session != CK_INVALID_HANDLE) {
#if defined(TEST_EC_WRAP) || defined(TEST_EC_CURVES)
        destroy_obj(session, &wrapKey);
#endif
        destroy_obj(session, &privNoPoint);
        destroy_obj(session, &privDer);
        destroy_obj(session, &privRaw);
        destroy_obj(session, &pub);
        funcList->C_Logout(session);
        funcList->C_CloseSession(session);
    }
    pkcs11_final();
    return result;
}

int main(int argc, char* argv[])
{
#ifndef WOLFPKCS11_NO_ENV
    XSETENV("WOLFPKCS11_TOKEN_PATH", TEST_DIR, 1);
#endif

    (void)argc;
    (void)argv;

    printf("=== wolfPKCS11 EC private key import test ===\n");

    (void)ec_private_key_import_test();

    printf("\n=== Test Results ===\n");
    printf("Tests passed: %d\n", test_passed);
    printf("Tests failed: %d\n", test_failed);
    return (test_failed == 0) ? 0 : 1;
}

#else

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;
    printf("ECC not available, skipping test\n");
    return 77;
}

#endif /* HAVE_ECC */

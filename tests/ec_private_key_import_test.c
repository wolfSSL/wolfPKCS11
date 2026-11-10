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

/* Create a P-256 private key; point may be NULL with pointLen 0. */
static CK_RV create_ec_priv(CK_SESSION_HANDLE session, unsigned char* point,
    CK_ULONG pointLen, CK_OBJECT_HANDLE* key)
{
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &privKeyClass,   sizeof(privKeyClass)    },
        { CKA_KEY_TYPE,    &ecKeyType,      sizeof(ecKeyType)       },
        { CKA_TOKEN,       &ckFalse,        sizeof(ckFalse)         },
        { CKA_SIGN,        &ckTrue,         sizeof(ckTrue)          },
        { CKA_EXTRACTABLE, &ckTrue,         sizeof(ckTrue)          },
        { CKA_EC_PARAMS,   ecc_p256_params, sizeof(ecc_p256_params) },
        { CKA_VALUE,       ecc_p256_priv,   sizeof(ecc_p256_priv)   },
        { CKA_EC_POINT,    point,           pointLen                },
    };
    return funcList->C_CreateObject(session, tmpl,
        sizeof(tmpl) / sizeof(tmpl[0]), key);
}

static CK_RV create_ec_pub(CK_SESSION_HANDLE session, unsigned char* point,
    CK_ULONG pointLen, CK_OBJECT_HANDLE* key)
{
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,     &pubKeyClass,    sizeof(pubKeyClass)     },
        { CKA_KEY_TYPE,  &ecKeyType,      sizeof(ecKeyType)       },
        { CKA_TOKEN,     &ckFalse,        sizeof(ckFalse)         },
        { CKA_VERIFY,    &ckTrue,         sizeof(ckTrue)          },
        { CKA_EC_PARAMS, ecc_p256_params, sizeof(ecc_p256_params) },
        { CKA_EC_POINT,  point,           pointLen                },
    };
    return funcList->C_CreateObject(session, tmpl,
        sizeof(tmpl) / sizeof(tmpl[0]), key);
}

/* Sign the hash with priv and verify it with pub. */
static CK_RV sign_verify(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE priv,
    CK_OBJECT_HANDLE pub)
{
    CK_RV ret;
    CK_MECHANISM mech = { CKM_ECDSA, NULL, 0 };
    unsigned char sig[64];
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

/* Wrap priv, check the plaintext is a PKCS #8 of the test key, unwrap it and
 * check the new key signs. */
static int wrap_unwrap_roundtrip(CK_SESSION_HANDLE session,
    CK_OBJECT_HANDLE wrapKey, CK_OBJECT_HANDLE priv, CK_OBJECT_HANDLE pub,
    const char* name)
{
    int result = 0;
    CK_RV rv;
    CK_MECHANISM mech = { CKM_AES_CBC_PAD, iv, sizeof(iv) };
    CK_OBJECT_HANDLE unwrapped = CK_INVALID_HANDLE;
    unsigned char wrapped[256];
    unsigned char plain[256];
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
        contains(plain, plainLen, ecc_p256_params, sizeof(ecc_p256_params)) &&
        contains(plain, plainLen, ecc_p256_priv, sizeof(ecc_p256_priv)), op);

    snprintf(op, sizeof(op), "%s: C_UnwrapKey", name);
    rv = funcList->C_UnwrapKey(session, &mech, wrapKey, wrapped, wrappedLen,
        unwrapTmpl, sizeof(unwrapTmpl) / sizeof(unwrapTmpl[0]), &unwrapped);
    CHECK_CKR(rv, op, CKR_OK);
    snprintf(op, sizeof(op), "%s: unwrapped key has the P-256 CKA_EC_PARAMS",
        name);
    rv = funcList->C_GetAttributeValue(session, unwrapped, getParams, 1);
    CHECK_COND(rv == CKR_OK &&
        getParams[0].ulValueLen == sizeof(ecc_p256_params) &&
        XMEMCMP(params, ecc_p256_params, sizeof(ecc_p256_params)) == 0, op);
    snprintf(op, sizeof(op), "%s: unwrapped key signs", name);
    rv = sign_verify(session, unwrapped, pub);
    CHECK_CKR(rv, op, CKR_OK);

cleanup:
    if (unwrapped != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, unwrapped);
    return result;
}
#endif /* TEST_EC_WRAP */

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
#ifdef TEST_EC_WRAP
    CK_OBJECT_HANDLE wrapKey = CK_INVALID_HANDLE;
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
    rv = create_ec_pub(session, ecc_p256_pub, sizeof(ecc_p256_pub), &pub);
    CHECK_CKR(rv, "Create public key with a DER CKA_EC_POINT", CKR_OK);

    /* NSS sets the raw point on the private key (pk11pk12.c). */
    rv = create_ec_priv(session, ecc_p256_point, sizeof(ecc_p256_point),
        &privRaw);
    CHECK_CKR(rv, "Create private key with a raw CKA_EC_POINT", CKR_OK);
    rv = sign_verify(session, privRaw, pub);
    CHECK_CKR(rv, "Private key with a raw point signs", CKR_OK);

    /* NSS copies the private key's CKA_EC_POINT into an exported PKCS #8 as
     * the raw point, so NSS builds return that form; others return DER. */
    {
        unsigned char point[80];
        CK_ATTRIBUTE getPoint[] = {
            { CKA_EC_POINT, point, sizeof(point) },
        };
    #ifdef WOLFPKCS11_NSS
        unsigned char* want = ecc_p256_point;
        CK_ULONG wantLen = sizeof(ecc_p256_point);
    #else
        unsigned char* want = ecc_p256_pub;
        CK_ULONG wantLen = sizeof(ecc_p256_pub);
    #endif

        rv = funcList->C_GetAttributeValue(session, privRaw, getPoint, 1);
        CHECK_CKR(rv, "Read CKA_EC_POINT of the private key", CKR_OK);
        CHECK_COND(getPoint[0].ulValueLen == wantLen &&
            XMEMCMP(point, want, wantLen) == 0,
            "Private key CKA_EC_POINT has the build's form");
    }

    rv = create_ec_priv(session, ecc_p256_pub, sizeof(ecc_p256_pub), &privDer);
    CHECK_CKR(rv, "Create private key with a DER CKA_EC_POINT", CKR_OK);
    rv = sign_verify(session, privDer, pub);
    CHECK_CKR(rv, "Private key with a DER point signs", CKR_OK);

    /* NSS sends an empty point when the PKCS #8 has no public value. */
    rv = create_ec_priv(session, NULL, 0, &privNoPoint);
    CHECK_CKR(rv, "Create private key with an empty CKA_EC_POINT", CKR_OK);
    rv = sign_verify(session, privNoPoint, pub);
    CHECK_CKR(rv, "Private key without a point signs", CKR_OK);

    /* A raw point must still be on the curve. */
    XMEMCPY(badPoint, ecc_p256_point, sizeof(badPoint));
    badPoint[sizeof(badPoint) - 1] ^= 0x01;
    rv = create_ec_priv(session, badPoint, sizeof(badPoint), &key);
    CHECK_CKR(rv, "Raw CKA_EC_POINT off the curve is rejected",
        CKR_ATTRIBUTE_VALUE_INVALID);

    /* Public keys still take only the DER form PKCS #11 defines. */
    rv = create_ec_pub(session, ecc_p256_point, sizeof(ecc_p256_point), &key);
    CHECK_CKR(rv, "Public key with a raw CKA_EC_POINT is rejected",
        CKR_ATTRIBUTE_VALUE_INVALID);

#ifdef TEST_EC_WRAP
    rv = create_wrap_key(session, &wrapKey);
    CHECK_CKR(rv, "Create AES wrapping key", CKR_OK);

    if (wrap_unwrap_roundtrip(session, wrapKey, privRaw, pub,
            "with public point") != 0) {
        result = -1;
        goto cleanup;
    }
    if (wrap_unwrap_roundtrip(session, wrapKey, privNoPoint, pub,
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
#endif

cleanup:
    if (session != CK_INVALID_HANDLE) {
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

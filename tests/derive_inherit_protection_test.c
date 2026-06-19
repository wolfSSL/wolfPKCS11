/* derive_inherit_protection_test.c
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
 * Test for issue F-4533: a derived key must inherit protection strength from
 * its base key (PKCS#11 v3.0 5.5.5). If the base key is CKA_SENSITIVE=CK_TRUE
 * the derived key must be CKA_SENSITIVE=CK_TRUE; if the base key is
 * CKA_EXTRACTABLE=CK_FALSE the derived key must be CKA_EXTRACTABLE=CK_FALSE,
 * even when the caller's template requests weaker protection.
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

/* The non-inheriting behavior is expected under the legacy macro or in an NSS
 * build (which keeps the historical permissive behavior). */
#if defined(WOLFPKCS11_LEGACY_DERIVE_NO_INHERIT) || defined(WOLFPKCS11_NSS)
    #define EXPECT_NO_INHERIT
#endif

#define TEST_DIR "./store/derive_inherit_protection_test"
#define WOLFPKCS11_TOKEN_FILENAME "wp11_token_0000000000000001"

static int test_passed = 0;
static int test_failed = 0;
static int test_skipped = 0;

#ifndef HAVE_PKCS11_STATIC
static void* dlib;
#endif
static CK_FUNCTION_LIST* funcList;
static CK_SLOT_ID slot = 0;
static const char* tokenName = "wolfpkcs11";
static byte* soPin = (byte*)"password123456";
static int soPinLen = 14;
static byte* userPin = (byte*)"someUserPin";
static int userPinLen = 11;

#define CHECK_CKR(rv, op) do {                              \
    if (rv != CKR_OK) {                                     \
        fprintf(stderr, "FAIL: %s: got 0x%lx\n", op, (unsigned long)rv); \
        test_failed++;                                      \
        result = -1;                                        \
        goto cleanup;                                       \
    } else {                                                \
        printf("PASS: %s\n", op);                           \
        test_passed++;                                      \
    }                                                       \
} while(0)

#if defined(WOLFPKCS11_HKDF)
static CK_OBJECT_CLASS secretKeyClass = CKO_SECRET_KEY;
static CK_KEY_TYPE genericKeyType = CKK_GENERIC_SECRET;
static CK_BBOOL ckTrue = CK_TRUE;
static CK_BBOOL ckFalse = CK_FALSE;

static byte baseValue[32] = {
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
};

static int read_bool(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj,
                     CK_ATTRIBUTE_TYPE type, CK_BBOOL* out)
{
    CK_ATTRIBUTE tmpl[] = { { type, out, sizeof(*out) } };
    return (int)funcList->C_GetAttributeValue(session, obj, tmpl, 1);
}

/* HKDF-extract derive from `base' producing a generic secret. The derived
 * template deliberately requests the weakest protection. */
static CK_RV hkdf_derive(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE base,
                         CK_OBJECT_HANDLE* derived)
{
    CK_ULONG derivedLen = 32;
    byte salt[13];
    CK_HKDF_PARAMS params;
    CK_MECHANISM mech;
    CK_ATTRIBUTE derivedTmpl[] = {
        { CKA_CLASS,       &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE,    &genericKeyType, sizeof(genericKeyType) },
        { CKA_SENSITIVE,   &ckFalse,        sizeof(ckFalse)        },
        { CKA_EXTRACTABLE, &ckTrue,         sizeof(ckTrue)         },
        { CKA_VALUE_LEN,   &derivedLen,     sizeof(derivedLen)     },
    };
    CK_ULONG derivedCnt = sizeof(derivedTmpl) / sizeof(*derivedTmpl);

    XMEMSET(salt, 0, sizeof(salt));
    XMEMSET(&params, 0, sizeof(params));
    params.bExtract = CK_TRUE;
    params.bExpand = CK_FALSE;
    params.prfHashMechanism = CKM_SHA256_HMAC;
    params.ulSaltType = CKF_HKDF_SALT_DATA;
    params.pSalt = salt;
    params.ulSaltLen = sizeof(salt);
    params.hSaltKey = CK_INVALID_HANDLE;

    mech.mechanism = CKM_HKDF_DERIVE;
    mech.pParameter = &params;
    mech.ulParameterLen = sizeof(params);

    return funcList->C_DeriveKey(session, &mech, base, derivedTmpl, derivedCnt,
                                 derived);
}

static int test_sensitive_inheritance(CK_SESSION_HANDLE session)
{
    CK_RV ret;
    CK_OBJECT_HANDLE base = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE derived = CK_INVALID_HANDLE;
    CK_BBOOL sensitive = 0xAA;
    int result = 0;

    /* Sensitive, derivable base key. */
    CK_ATTRIBUTE baseTmpl[] = {
        { CKA_CLASS,       &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE,    &genericKeyType, sizeof(genericKeyType) },
        { CKA_VALUE,       baseValue,       sizeof(baseValue)      },
        { CKA_SENSITIVE,   &ckTrue,         sizeof(ckTrue)         },
        { CKA_DERIVE,      &ckTrue,         sizeof(ckTrue)         },
    };
    CK_ULONG baseCnt = sizeof(baseTmpl) / sizeof(*baseTmpl);

    ret = funcList->C_CreateObject(session, baseTmpl, baseCnt, &base);
    CHECK_CKR(ret, "create sensitive base key");

    ret = hkdf_derive(session, base, &derived);
    CHECK_CKR(ret, "derive from sensitive base");

    ret = read_bool(session, derived, CKA_SENSITIVE, &sensitive);
    CHECK_CKR(ret, "read derived CKA_SENSITIVE");

#ifdef EXPECT_NO_INHERIT
    if (sensitive != CK_FALSE) {
        fprintf(stderr, "FAIL: legacy: derived CKA_SENSITIVE expected FALSE\n");
        test_failed++;
        result = -1;
        goto cleanup;
    }
    printf("PASS: legacy build does not inherit CKA_SENSITIVE\n");
    test_passed++;
#else
    if (sensitive != CK_TRUE) {
        fprintf(stderr, "FAIL: derived CKA_SENSITIVE expected CK_TRUE "
                "(inherited), got %d\n", (int)sensitive);
        test_failed++;
        result = -1;
        goto cleanup;
    }
    printf("PASS: derived key inherits CKA_SENSITIVE=CK_TRUE\n");
    test_passed++;

    /* The derived value must not be readable. */
    {
        byte val[64];
        CK_ATTRIBUTE valTmpl[] = { { CKA_VALUE, val, sizeof(val) } };
        ret = funcList->C_GetAttributeValue(session, derived, valTmpl, 1);
        if (ret != CKR_ATTRIBUTE_SENSITIVE) {
            fprintf(stderr, "FAIL: reading derived value returned 0x%lx, "
                    "expected CKR_ATTRIBUTE_SENSITIVE\n", (unsigned long)ret);
            test_failed++;
            result = -1;
            goto cleanup;
        }
        printf("PASS: derived sensitive key value is not readable\n");
        test_passed++;
    }
#endif

cleanup:
    if (derived != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, derived);
    if (base != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, base);
    return result;
}

static int test_extractable_inheritance(CK_SESSION_HANDLE session)
{
    CK_RV ret;
    CK_OBJECT_HANDLE base = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE derived = CK_INVALID_HANDLE;
    CK_BBOOL extractable = 0xAA;
    int result = 0;

    /* Non-extractable (but non-sensitive) derivable base key. */
    CK_ATTRIBUTE baseTmpl[] = {
        { CKA_CLASS,       &secretKeyClass, sizeof(secretKeyClass) },
        { CKA_KEY_TYPE,    &genericKeyType, sizeof(genericKeyType) },
        { CKA_VALUE,       baseValue,       sizeof(baseValue)      },
        { CKA_SENSITIVE,   &ckFalse,        sizeof(ckFalse)        },
        { CKA_EXTRACTABLE, &ckFalse,        sizeof(ckFalse)        },
        { CKA_DERIVE,      &ckTrue,         sizeof(ckTrue)         },
    };
    CK_ULONG baseCnt = sizeof(baseTmpl) / sizeof(*baseTmpl);

    ret = funcList->C_CreateObject(session, baseTmpl, baseCnt, &base);
    CHECK_CKR(ret, "create non-extractable base key");

    ret = hkdf_derive(session, base, &derived);
    CHECK_CKR(ret, "derive from non-extractable base");

    ret = read_bool(session, derived, CKA_EXTRACTABLE, &extractable);
    CHECK_CKR(ret, "read derived CKA_EXTRACTABLE");

#ifdef EXPECT_NO_INHERIT
    if (extractable != CK_TRUE) {
        fprintf(stderr,
                "FAIL: legacy: derived CKA_EXTRACTABLE expected TRUE\n");
        test_failed++;
        result = -1;
        goto cleanup;
    }
    printf("PASS: legacy build does not inherit CKA_EXTRACTABLE\n");
    test_passed++;
#else
    if (extractable != CK_FALSE) {
        fprintf(stderr, "FAIL: derived CKA_EXTRACTABLE expected CK_FALSE "
                "(inherited), got %d\n", (int)extractable);
        test_failed++;
        result = -1;
        goto cleanup;
    }
    printf("PASS: derived key inherits CKA_EXTRACTABLE=CK_FALSE\n");
    test_passed++;
#endif

cleanup:
    if (derived != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, derived);
    if (base != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, base);
    return result;
}
#endif /* WOLFPKCS11_HKDF */

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
        return -1;
    }
    func = (CK_C_GetFunctionList)dlsym(dlib, "C_GetFunctionList");
    if (func == NULL) {
        dlclose(dlib);
        return -1;
    }
    ret = func(&funcList);
    if (ret != CKR_OK) {
        dlclose(dlib);
        return ret;
    }
#else
    ret = C_GetFunctionList(&funcList);
    if (ret != CKR_OK)
        return ret;
#endif

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
    return ret;
}

static CK_RV pkcs11_final(void)
{
    if (funcList != NULL) {
        funcList->C_Finalize(NULL);
        funcList = NULL;
    }
#ifndef HAVE_PKCS11_STATIC
    if (dlib) {
        dlclose(dlib);
        dlib = NULL;
    }
#endif
    return CKR_OK;
}

static CK_RV pkcs11_setup_token(void)
{
    CK_RV ret;
    unsigned char label[32];
    CK_SESSION_HANDLE soSession;
    int sessFlags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, tokenName, XSTRLEN(tokenName));
    ret = funcList->C_InitToken(slot, soPin, soPinLen, label);
    if (ret != CKR_OK)
        return ret;

    ret = funcList->C_OpenSession(slot, sessFlags, NULL, NULL, &soSession);
    if (ret != CKR_OK)
        return ret;
    ret = funcList->C_Login(soSession, CKU_SO, soPin, soPinLen);
    if (ret == CKR_OK)
        ret = funcList->C_InitPIN(soSession, userPin, userPinLen);
    funcList->C_Logout(soSession);
    funcList->C_CloseSession(soSession);
    return ret;
}

static int derive_inherit_protection_test(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = 0;
    int sessFlags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    int result = 0;

    printf("\n=== Testing C_DeriveKey protection inheritance ===\n");

    ret = pkcs11_init();
    CHECK_CKR(ret, "C_Initialize");

    ret = pkcs11_setup_token();
    CHECK_CKR(ret, "token setup");

    ret = funcList->C_OpenSession(slot, sessFlags, NULL, NULL, &session);
    CHECK_CKR(ret, "C_OpenSession");
    ret = funcList->C_Login(session, CKU_USER, userPin, userPinLen);
    CHECK_CKR(ret, "C_Login");

#if defined(WOLFPKCS11_HKDF)
    if (test_sensitive_inheritance(session) != 0)
        result = -1;
    if (test_extractable_inheritance(session) != 0)
        result = -1;
#else
    printf("HKDF not available, skipping derive inheritance test\n");
    test_skipped = 1;
#endif

cleanup:
    if (session != 0) {
        funcList->C_Logout(session);
        funcList->C_CloseSession(session);
    }
    pkcs11_final();
    return result;
}

static void print_results(void)
{
    printf("\n=== Test Results ===\n");
    printf("Tests passed: %d\n", test_passed);
    printf("Tests failed: %d\n", test_failed);
    if (test_skipped != 0)
        printf("Tests skipped: %d\n", test_skipped);
    if (test_failed == 0)
        printf("ALL TESTS PASSED!\n");
    else
        printf("SOME TESTS FAILED!\n");
}

int main(int argc, char* argv[])
{
#ifndef WOLFPKCS11_NO_ENV
    XSETENV("WOLFPKCS11_TOKEN_PATH", TEST_DIR, 1);
#endif
    (void)argc;
    (void)argv;

    printf("=== wolfPKCS11 Derive Inherit Protection Test ===\n");

    (void)derive_inherit_protection_test();

    print_results();
    return (test_failed == 0) ? 0 : 1;
}

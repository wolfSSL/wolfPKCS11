/* key_sensitive_default_test.c
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
 * Test for issue F-4063: secret and private keys must default to
 * CKA_SENSITIVE=CK_TRUE (and private keys to CKA_EXTRACTABLE=CK_FALSE) so
 * that key material is not readable via C_GetAttributeValue unless the
 * creating template explicitly opts out. Historically WOLFPKCS11_NSS builds
 * skipped these defaults, exposing key material by default.
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

/* NSS builds keep the historical permissive key defaults. */
#ifdef WOLFPKCS11_NSS
    #define EXPECT_PERMISSIVE_DEFAULTS
#endif

#define TEST_DIR "./store/key_sensitive_default_test"
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

/* Assert a boolean attribute on an object equals the expected value. */
static int check_bool_attr(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj,
                           CK_ATTRIBUTE_TYPE type, CK_BBOOL expected,
                           const char* name)
{
    CK_RV ret;
    CK_BBOOL val = 0xAA;
    CK_ATTRIBUTE tmpl[] = { { type, &val, sizeof(val) } };

    ret = funcList->C_GetAttributeValue(session, obj, tmpl, 1);
    if (ret != CKR_OK) {
        fprintf(stderr, "FAIL: get %s: 0x%lx\n", name, (unsigned long)ret);
        test_failed++;
        return -1;
    }
    if (val != expected) {
        fprintf(stderr, "FAIL: %s: expected %d, got %d\n", name,
                (int)expected, (int)val);
        test_failed++;
        return -1;
    }
    printf("PASS: %s is %s\n", name, expected ? "CK_TRUE" : "CK_FALSE");
    test_passed++;
    return 0;
}

#ifndef NO_AES
static int test_secret_key_sensitive_default(CK_SESSION_HANDLE session)
{
    CK_RV ret;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_MECHANISM mech;
    CK_KEY_TYPE keyType = CKK_AES;
    CK_ULONG keyLen = 32;
    int result = 0;

    /* Minimal generate template: no CKA_SENSITIVE supplied. */
    CK_ATTRIBUTE genTmpl[] = {
        { CKA_VALUE_LEN, &keyLen,  sizeof(keyLen)  },
        { CKA_KEY_TYPE,  &keyType, sizeof(keyType) },
    };
    CK_ULONG genCnt = sizeof(genTmpl) / sizeof(*genTmpl);

    mech.mechanism = CKM_AES_KEY_GEN;
    mech.ulParameterLen = 0;
    mech.pParameter = NULL;

    ret = funcList->C_GenerateKey(session, &mech, genTmpl, genCnt, &key);
    CHECK_CKR(ret, "C_GenerateKey (AES-256, minimal template)");

#ifdef EXPECT_PERMISSIVE_DEFAULTS
    result = check_bool_attr(session, key, CKA_SENSITIVE, CK_FALSE,
                             "secret CKA_SENSITIVE (legacy NSS)");
#else
    result = check_bool_attr(session, key, CKA_SENSITIVE, CK_TRUE,
                             "secret CKA_SENSITIVE");
#endif

cleanup:
    if (key != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, key);
    return result;
}
#endif /* !NO_AES */

#if !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN)
static int test_private_key_sensitive_default(CK_SESSION_HANDLE session)
{
    CK_RV ret;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_MECHANISM mech;
    CK_ULONG bits = 2048;
    byte pubExp[] = { 0x01, 0x00, 0x01 };
    CK_BBOOL ckFalse = CK_FALSE;
    int result = 0;

    /* Minimal pair-gen templates: the private template sets no protection
     * bits (no CKA_SENSITIVE / CKA_EXTRACTABLE), so the defaults apply. */
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_MODULUS_BITS,    &bits,  sizeof(bits)   },
        { CKA_PUBLIC_EXPONENT, pubExp, sizeof(pubExp) },
    };
    CK_ULONG pubCnt = sizeof(pubTmpl) / sizeof(*pubTmpl);
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_TOKEN, &ckFalse, sizeof(ckFalse) },
    };
    CK_ULONG privCnt = sizeof(privTmpl) / sizeof(*privTmpl);

    mech.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
    mech.ulParameterLen = 0;
    mech.pParameter = NULL;

    ret = funcList->C_GenerateKeyPair(session, &mech, pubTmpl, pubCnt,
                                      privTmpl, privCnt, &pub, &priv);
    CHECK_CKR(ret, "C_GenerateKeyPair (RSA-2048, minimal template)");

#ifdef EXPECT_PERMISSIVE_DEFAULTS
    if (check_bool_attr(session, priv, CKA_SENSITIVE, CK_FALSE,
                        "private CKA_SENSITIVE (legacy NSS)") != 0)
        result = -1;
    if (check_bool_attr(session, priv, CKA_EXTRACTABLE, CK_TRUE,
                        "private CKA_EXTRACTABLE (legacy NSS)") != 0)
        result = -1;
#else
    if (check_bool_attr(session, priv, CKA_SENSITIVE, CK_TRUE,
                        "private CKA_SENSITIVE") != 0)
        result = -1;
    if (check_bool_attr(session, priv, CKA_EXTRACTABLE, CK_FALSE,
                        "private CKA_EXTRACTABLE") != 0)
        result = -1;
#endif

cleanup:
    if (pub != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, pub);
    if (priv != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(session, priv);
    return result;
}
#endif /* !NO_RSA */

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
        fprintf(stderr, "Failed to get function list function\n");
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

static int key_sensitive_default_test(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = 0;
    int sessFlags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    int result = 0;

    printf("\n=== Testing CKA_SENSITIVE / CKA_EXTRACTABLE key defaults ===\n");

    ret = pkcs11_init();
    CHECK_CKR(ret, "C_Initialize");

    ret = pkcs11_setup_token();
    CHECK_CKR(ret, "token setup");

    ret = funcList->C_OpenSession(slot, sessFlags, NULL, NULL, &session);
    CHECK_CKR(ret, "C_OpenSession");
    ret = funcList->C_Login(session, CKU_USER, userPin, userPinLen);
    CHECK_CKR(ret, "C_Login");

#ifndef NO_AES
    if (test_secret_key_sensitive_default(session) != 0)
        result = -1;
#endif
#if !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN)
    if (test_private_key_sensitive_default(session) != 0)
        result = -1;
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

    printf("=== wolfPKCS11 Key Sensitive Default Test ===\n");

    (void)key_sensitive_default_test();

    print_results();
    return (test_failed == 0) ? 0 : 1;
}
